// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Cloud Files API (cldapi.dll — the OneDrive driver's user-mode side)
//! as the shell uses it (commit 39b). Every `unsafe` block of the shell is
//! here, each as small as the call it makes; the provider (provider.rs)
//! sees safe functions over paths and byte slices.
//!
//! ```text
//! register    the folder becomes a sync root: placeholders appear as files with
//!             their size and times, the bytes fetched only when read (PARTIAL
//!             hydration — a range read of a 255 GiB image fetches that range)
//! connect     the callbacks: FETCH_DATA (fill a range), NOTIFY_DELETE and
//!             NOTIFY_RENAME (allowed or refused — the server decides)
//! placeholder created MARK_IN_SYNC with an identity blob (names.rs › identity);
//!             updated, converted, dehydrated through a handle opened with an
//!             oplock — an application holding the file open makes those wait
//! ```

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::path::Path;

use windows::core::{GUID, HSTRING, PCWSTR};
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::Storage::CloudFilters::*;
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO};

pub use windows::Win32::Foundation::{STATUS_ACCESS_DENIED, STATUS_CLOUD_FILE_ACCESS_DENIED, STATUS_CLOUD_FILE_IN_USE, STATUS_CLOUD_FILE_NOT_IN_SYNC, STATUS_CLOUD_FILE_READ_ONLY_VOLUME, STATUS_CLOUD_FILE_UNSUCCESSFUL, STATUS_SUCCESS};

/// Gorani's provider id (a fixed GUID: the platform groups sync roots by it).
const PROVIDER_ID: GUID = GUID::from_u128(0x6f72_616e_692d_4739_9b0a_c0ff_ee5e_c0de);

pub type Result<T> = windows::core::Result<T>;

/// Make `root` a sync root (again, with UPDATE, if it already is one).
pub fn register(root: &Path, area: &str) -> Result<()> {
	let name = HSTRING::from("Gorani");
	let version = HSTRING::from(env!("CARGO_PKG_VERSION"));
	let sync_identity = format!("gorani:{area}").into_bytes();
	let root_identity = crate::names::identity("", 0);
	let registration = CF_SYNC_REGISTRATION {
		StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
		ProviderName: PCWSTR(name.as_ptr()),
		ProviderVersion: PCWSTR(version.as_ptr()),
		SyncRootIdentity: sync_identity.as_ptr() as *const c_void,
		SyncRootIdentityLength: sync_identity.len() as u32,
		FileIdentity: root_identity.as_ptr() as *const c_void,
		FileIdentityLength: root_identity.len() as u32,
		ProviderId: PROVIDER_ID,
	};
	let policies = CF_SYNC_POLICIES {
		StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
		Hydration: CF_HYDRATION_POLICY { Primary: CF_HYDRATION_POLICY_PARTIAL, Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE },
		Population: CF_POPULATION_POLICY { Primary: CF_POPULATION_POLICY_ALWAYS_FULL, Modifier: CF_POPULATION_POLICY_MODIFIER_NONE },
		InSync: CF_INSYNC_POLICY_TRACK_ALL,
		HardLink: CF_HARDLINK_POLICY_NONE,
		PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
	};
	let path = HSTRING::from(root);
	let flags = CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT;
	// SAFETY: every pointer refers to a local that outlives the call.
	unsafe { CfRegisterSyncRoot(&path, &registration, &policies, flags) }.or_else(|_| unsafe { CfRegisterSyncRoot(&path, &registration, &policies, flags | CF_REGISTER_FLAG_UPDATE) })
}

pub fn unregister(root: &Path) -> Result<()> {
	// SAFETY: a path string that outlives the call.
	unsafe { CfUnregisterSyncRoot(&HSTRING::from(root)) }
}

/// The callback table handed to `connect`: it must outlive the connection
/// (a static), and ends with a NONE entry.
pub struct Callbacks {
	pub fetch_data: unsafe extern "system" fn(*const CF_CALLBACK_INFO, *const CF_CALLBACK_PARAMETERS),
	pub notify_delete: unsafe extern "system" fn(*const CF_CALLBACK_INFO, *const CF_CALLBACK_PARAMETERS),
	pub notify_rename: unsafe extern "system" fn(*const CF_CALLBACK_INFO, *const CF_CALLBACK_PARAMETERS),
}

pub struct Connection {
	key: CF_CONNECTION_KEY,
	// (Kept alive for as long as the platform may call through it.)
	_table: Box<[CF_CALLBACK_REGISTRATION; 4]>,
}

impl Connection {
	pub fn key(&self) -> CF_CONNECTION_KEY {
		self.key
	}
}

/// Connect: from here the platform calls `cb` on its own threads, with
/// `context` (the provider) in every callback's info.
pub fn connect(root: &Path, cb: Callbacks, context: *const c_void) -> Result<Connection> {
	let table = Box::new([
		CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_FETCH_DATA, Callback: Some(cb.fetch_data) },
		CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NOTIFY_DELETE, Callback: Some(cb.notify_delete) },
		CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NOTIFY_RENAME, Callback: Some(cb.notify_rename) },
		CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None },
	]);
	// SAFETY: the table is boxed and kept in the Connection; the context
	// pointer is the caller's to keep valid until `disconnect`.
	let key = unsafe { CfConnectSyncRoot(&HSTRING::from(root), table.as_ptr(), Some(context), CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH) }?;
	Ok(Connection { key, _table: table })
}

pub fn disconnect(c: Connection) -> Result<()> {
	// SAFETY: a key the platform gave us.
	unsafe { CfDisconnectSyncRoot(c.key) }
}

/// What a placeholder is made with.
pub struct NewPlaceholder<'a> {
	pub name: &'a str,
	pub dir: bool,
	pub size: u64,
	pub modified: u64,
	pub identity: Vec<u8>,
	pub read_only: bool,
}

fn basic_info(dir: bool, modified: u64, read_only: bool) -> FILE_BASIC_INFO {
	let t = crate::names::filetime(modified);
	let mut attrs = if dir { FILE_ATTRIBUTE_DIRECTORY.0 } else { FILE_ATTRIBUTE_NORMAL.0 };
	if read_only && !dir {
		attrs |= FILE_ATTRIBUTE_READONLY.0;
	}
	FILE_BASIC_INFO { CreationTime: t, LastAccessTime: t, LastWriteTime: t, ChangeTime: t, FileAttributes: attrs }
}

/// Create placeholders in `dir` (an existing folder in the sync root), in
/// sync, with their identities. Returns each one's result.
pub fn create_placeholders(dir: &Path, items: &[NewPlaceholder]) -> Vec<Result<()>> {
	if items.is_empty() {
		return Vec::new();
	}
	let names: Vec<HSTRING> = items.iter().map(|i| HSTRING::from(i.name)).collect();
	let mut infos: Vec<CF_PLACEHOLDER_CREATE_INFO> = items
		.iter()
		.zip(&names)
		.map(|(i, n)| CF_PLACEHOLDER_CREATE_INFO {
			RelativeFileName: PCWSTR(n.as_ptr()),
			FsMetadata: CF_FS_METADATA { BasicInfo: basic_info(i.dir, i.modified, i.read_only), FileSize: if i.dir { 0 } else { i.size as i64 } },
			FileIdentity: i.identity.as_ptr() as *const c_void,
			FileIdentityLength: i.identity.len() as u32,
			Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC | if i.dir { CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION } else { CF_PLACEHOLDER_CREATE_FLAG_NONE },
			Result: windows::core::HRESULT(0),
			CreateUsn: 0,
		})
		.collect();
	let mut done = 0u32;
	// SAFETY: names and identities outlive the call; the array is ours.
	let all = unsafe { CfCreatePlaceholders(&HSTRING::from(dir), &mut infos, CF_CREATE_FLAG_NONE, Some(&mut done)) };
	infos.iter().map(|i| if all.is_ok() || i.Result.is_ok() { i.Result.ok() } else { all.clone() }).collect()
}

/// A handle opened through the platform (with an oplock): an application
/// holding the file open makes an exclusive open fail rather than letting
/// a placeholder change under it. Closed when dropped.
pub struct Handle(HANDLE);

impl Handle {
	pub fn open(path: &Path, write: bool) -> Result<Self> {
		let flags = if write { CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS } else { CF_OPEN_FILE_FLAG_NONE };
		// SAFETY: a path string that outlives the call.
		let h = unsafe { CfOpenFileWithOplock(&HSTRING::from(path), flags) }?;
		Ok(Self(h))
	}

	fn win32(&self) -> HANDLE {
		// SAFETY: a protected handle this struct owns.
		unsafe { CfGetWin32HandleFromProtectedHandle(self.0) }
	}
}

impl Drop for Handle {
	fn drop(&mut self) {
		// SAFETY: closed once, here.
		unsafe { CfCloseHandle(self.0) }
	}
}

/// A placeholder's state: in sync or not, and its identity blob.
pub struct Info {
	pub in_sync: bool,
	pub identity: Vec<u8>,
}

/// None when the file is not a placeholder (a file the member just made).
pub fn info(path: &Path) -> Option<Info> {
	let h = Handle::open(path, false).ok()?;
	let mut buf = vec![0u8; size_of::<CF_PLACEHOLDER_BASIC_INFO>() + 4096];
	let mut got = 0u32;
	// SAFETY: the buffer is large enough for the struct and the largest identity.
	unsafe { CfGetPlaceholderInfo(h.win32(), CF_PLACEHOLDER_INFO_BASIC, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, Some(&mut got)) }.ok()?;
	// SAFETY: the platform wrote a CF_PLACEHOLDER_BASIC_INFO at the start.
	let basic = unsafe { &*(buf.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO) };
	let at = offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
	let len = (basic.FileIdentityLength as usize).min(buf.len() - at);
	Some(Info { in_sync: basic.InSyncState == CF_IN_SYNC_STATE_IN_SYNC, identity: buf[at..at + len].to_vec() })
}

/// Point a placeholder at a new identity (a new version), optionally with
/// new metadata and its local bytes dropped, and mark it in sync.
pub fn update(path: &Path, identity: &[u8], meta: Option<(bool, u64, u64, bool)>, dehydrate: bool) -> Result<()> {
	let h = Handle::open(path, true)?;
	let md = meta.map(|(dir, size, modified, ro)| CF_FS_METADATA { BasicInfo: basic_info(dir, modified, ro), FileSize: size as i64 });
	let mut flags = CF_UPDATE_FLAG_MARK_IN_SYNC;
	if dehydrate {
		flags |= CF_UPDATE_FLAG_DEHYDRATE;
	}
	// SAFETY: the metadata and identity outlive the call.
	unsafe { CfUpdatePlaceholder(h.win32(), md.as_ref().map(|m| m as *const _), Some(identity.as_ptr() as *const c_void), identity.len() as u32, None, flags, None, None) }
}

/// A file or folder the member made becomes a placeholder, in sync.
pub fn convert(path: &Path, identity: &[u8]) -> Result<()> {
	let h = Handle::open(path, true)?;
	// SAFETY: the identity outlives the call.
	unsafe { CfConvertToPlaceholder(h.win32(), Some(identity.as_ptr() as *const c_void), identity.len() as u32, CF_CONVERT_FLAG_MARK_IN_SYNC, None, None) }
}

/// Drop a placeholder's local bytes (it stays listed, its bytes on the server).
pub fn dehydrate(path: &Path) -> Result<()> {
	let h = Handle::open(path, true)?;
	// SAFETY: a handle we own; the whole file.
	unsafe { CfDehydratePlaceholder(h.win32(), 0, -1, CF_DEHYDRATE_FLAG_NONE, None) }
}

/// A placeholder stops being one (its bytes stay, as a plain local file).
pub fn revert(path: &Path) -> Result<()> {
	let h = Handle::open(path, true)?;
	// SAFETY: a handle we own.
	unsafe { CfRevertPlaceholder(h.win32(), CF_REVERT_FLAG_NONE, None) }
}

/// Mark a placeholder in sync without changing anything else (a folder
/// whose attributes or times were touched).
pub fn mark_in_sync(path: &Path) -> Result<()> {
	let h = Handle::open(path, true)?;
	// SAFETY: a handle we own.
	unsafe { CfSetInSyncState(h.win32(), CF_IN_SYNC_STATE_IN_SYNC, CF_SET_IN_SYNC_FLAG_NONE, None) }
}

// ── answering a callback ─────────────────────────────────────────────

fn op_info(info: &CF_CALLBACK_INFO, kind: CF_OPERATION_TYPE) -> CF_OPERATION_INFO {
	CF_OPERATION_INFO { StructSize: size_of::<CF_OPERATION_INFO>() as u32, Type: kind, ConnectionKey: info.ConnectionKey, TransferKey: info.TransferKey, CorrelationVector: info.CorrelationVector, SyncStatus: std::ptr::null(), RequestKey: info.RequestKey }
}

/// `CF_SIZE_OF_OP_PARAM(field)`: the header and the one member used.
const fn param_size<T>() -> u32 {
	(offset_of!(CF_OPERATION_PARAMETERS, Anonymous) + size_of::<T>()) as u32
}

/// Hand the platform `data` for the range at `offset` of the file a
/// FETCH_DATA callback asked for (or `status` to fail the rest of it).
pub fn transfer(info: &CF_CALLBACK_INFO, offset: u64, data: &[u8], status: NTSTATUS) -> Result<()> {
	let op = op_info(info, CF_OPERATION_TYPE_TRANSFER_DATA);
	let mut p = CF_OPERATION_PARAMETERS {
		ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_0>(),
		Anonymous: CF_OPERATION_PARAMETERS_0 { TransferData: CF_OPERATION_PARAMETERS_0_0 { Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CompletionStatus: status, Buffer: data.as_ptr() as *const c_void, Offset: offset as i64, Length: data.len() as i64 } },
	};
	// SAFETY: the buffer outlives the call; info is the callback's own.
	unsafe { CfExecute(&op, &mut p) }
}

pub fn ack_delete(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
	let op = op_info(info, CF_OPERATION_TYPE_ACK_DELETE);
	let mut p = CF_OPERATION_PARAMETERS { ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_7>(), Anonymous: CF_OPERATION_PARAMETERS_0 { AckDelete: CF_OPERATION_PARAMETERS_0_7 { Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE, CompletionStatus: status } } };
	// SAFETY: info is the callback's own.
	unsafe { CfExecute(&op, &mut p) }
}

pub fn ack_rename(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
	let op = op_info(info, CF_OPERATION_TYPE_ACK_RENAME);
	let mut p = CF_OPERATION_PARAMETERS { ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_6>(), Anonymous: CF_OPERATION_PARAMETERS_0 { AckRename: CF_OPERATION_PARAMETERS_0_6 { Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE, CompletionStatus: status } } };
	// SAFETY: info is the callback's own.
	unsafe { CfExecute(&op, &mut p) }
}

/// A wide string the platform handed us, as a Rust string.
pub fn wide(p: PCWSTR) -> String {
	if p.is_null() {
		return String::new();
	}
	// SAFETY: the platform's NUL-terminated string, valid during the callback.
	unsafe { p.to_string() }.unwrap_or_default()
}

/// The identity blob a callback carries.
pub fn identity_of(info: &CF_CALLBACK_INFO) -> Vec<u8> {
	if info.FileIdentity.is_null() || info.FileIdentityLength == 0 {
		return Vec::new();
	}
	// SAFETY: the platform's buffer of that length, valid during the callback.
	unsafe { std::slice::from_raw_parts(info.FileIdentity as *const u8, info.FileIdentityLength as usize) }.to_vec()
}
