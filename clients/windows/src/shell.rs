// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Explorer's side of the folder (commit 39e, docs/DESKTOP.md › 39e). A
//! sync root registered through the shell's StorageProviderSyncRootManager
//! (rather than only cldapi's CfRegisterSyncRoot) is what Explorer shows as
//! a provider: its own entry in the navigation pane, named for the area,
//! the Status column's cloud and tick per file, "Always keep on this device"
//! and "Free up space" in the context menu — and a custom state for what
//! deserves one: a malware sample says so beside its name.
//!
//! Where the shell will not register it (a Server SKU without the desktop
//! experience, a policy), the plain cldapi registration (cf.rs) still makes
//! it a working folder; the shell only adds what Explorer shows. Which one
//! a folder got is said once at start.
//!
//! The id Explorer groups roots by is `Gorani!<the user's SID>!<area>` —
//! the shape the platform documents (provider ! user ! account).

use std::path::Path;

use windows::core::{HSTRING, PWSTR};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Provider::*;
use windows::Storage::{StorageFile, StorageFolder};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The custom state a malware sample shows (Explorer's Status column).
const SAMPLE_STATE: i32 = 1;
/// The folder's icon in the navigation pane (shell32's closed folder) —
/// until the installer gives the program one of its own (39f).
const FOLDER_ICON: &str = "%SystemRoot%\\System32\\shell32.dll,-4";
/// A sample's state icon (user32's standard warning sign).
const WARNING_ICON: &str = "%SystemRoot%\\System32\\user32.dll,-101";
/// What the in-sync state tracks, in the shell's documented bits: times and
/// the hidden and system attributes of files and folders — not read-only,
/// which the shell sets itself (cf.rs › register says why).
const IN_SYNC: u32 = 0x1 | 0x4 | 0x8 | 0x10 | 0x40 | 0x80 | 0x100 | 0x200;

pub enum Registration {
	/// Explorer knows it as a provider's folder.
	Shell { id: String },
	/// cldapi only: the folder works, Explorer shows less — and why.
	Plain { why: String },
}

fn text(e: windows::core::Error) -> String {
	format!("{} (0x{:08x})", e.message(), e.code().0)
}

/// This user's SID, as text (S-1-5-21-…).
fn user_sid() -> Result<String, String> {
	let mut token = HANDLE::default();
	// SAFETY: our own process's token, queried; closed below.
	unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(text)?;
	let mut len = 0u32;
	// SAFETY: a size query (it fails with "insufficient buffer" and says how much).
	let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
	// (u64s: TOKEN_USER holds pointers, and must be aligned for them.)
	let mut buf = vec![0u64; (len as usize).div_ceil(8)];
	// SAFETY: a buffer of at least `len` bytes.
	let r = unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut _), len, &mut len) };
	// SAFETY: the handle opened above, closed once.
	let _ = unsafe { CloseHandle(token) };
	r.map_err(text)?;
	// SAFETY: the call wrote a TOKEN_USER at the buffer's start.
	let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
	let mut s = PWSTR::null();
	// SAFETY: the SID inside our buffer; the string is LocalAlloc'd, freed below.
	unsafe { ConvertSidToStringSidW(user.User.Sid, &mut s) }.map_err(text)?;
	// SAFETY: a NUL-terminated string the call made.
	let out = unsafe { s.to_string() }.unwrap_or_default();
	// SAFETY: freed once.
	unsafe { LocalFree(Some(HLOCAL(s.0 as *mut _))) };
	Ok(out)
}

/// The id Explorer knows this area's folder by.
pub fn sync_root_id(area: &str) -> Result<String, String> {
	// ("!" separates the parts; an area name never needs one.)
	let account: String = area.chars().map(|c| if c == '!' || c.is_control() { '_' } else { c }).collect();
	Ok(format!("Gorani!{}!{account}", user_sid()?))
}

/// Register `root` with the shell — or say why not (the caller then
/// registers it with cldapi alone).
pub fn register(root: &Path, area: &str, read_only: bool) -> Registration {
	match register_shell(root, area, read_only) {
		Ok(id) => Registration::Shell { id },
		Err(why) => Registration::Plain { why },
	}
}

fn register_shell(root: &Path, area: &str, read_only: bool) -> Result<String, String> {
	if !StorageProviderSyncRootManager::IsSupported().unwrap_or(false) {
		return Err("this Windows has no shell sync-root support".into());
	}
	let id = sync_root_id(area)?;
	let info = StorageProviderSyncRootInfo::new().map_err(text)?;
	let folder = StorageFolder::GetFolderFromPathAsync(&HSTRING::from(root)).and_then(|op| op.get()).map_err(text)?;
	let name = if read_only { format!("Gorani — {area} (read-only)") } else { format!("Gorani — {area}") };
	let defs = StorageProviderItemPropertyDefinition::new().map_err(text)?;
	defs.SetId(SAMPLE_STATE).map_err(text)?;
	defs.SetDisplayNameResource(&HSTRING::from("Malware sample")).map_err(text)?;
	(|| -> windows::core::Result<()> {
		info.SetId(&HSTRING::from(id.as_str()))?;
		info.SetPath(&folder)?;
		info.SetDisplayNameResource(&HSTRING::from(name.as_str()))?;
		info.SetIconResource(&HSTRING::from(FOLDER_ICON))?;
		// The same policies cf.rs › register gives cldapi.
		info.SetHydrationPolicy(StorageProviderHydrationPolicy::Partial)?;
		info.SetHydrationPolicyModifier(StorageProviderHydrationPolicyModifier::None)?;
		info.SetPopulationPolicy(StorageProviderPopulationPolicy::AlwaysFull)?;
		info.SetInSyncPolicy(StorageProviderInSyncPolicy(IN_SYNC))?;
		info.SetHardlinkPolicy(StorageProviderHardlinkPolicy::None)?;
		info.SetShowSiblingsAsGroup(false)?;
		info.SetVersion(&HSTRING::from(env!("CARGO_PKG_VERSION")))?;
		info.SetProtectionMode(StorageProviderProtectionMode::Unknown)?;
		info.SetAllowPinning(true)?;
		info.SetContext(&CryptographicBuffer::CreateFromByteArray(format!("gorani:{area}").as_bytes())?)?;
		info.StorageProviderItemPropertyDefinitions()?.Append(&defs)?;
		StorageProviderSyncRootManager::Register(&info)
	})()
	.map_err(text)?;
	Ok(id)
}

/// The shell's id for the folder, if the shell registered it (ours).
pub fn registered_id(root: &Path) -> Option<String> {
	let folder = StorageFolder::GetFolderFromPathAsync(&HSTRING::from(root)).and_then(|op| op.get()).ok()?;
	let id = StorageProviderSyncRootManager::GetSyncRootInformationForFolder(&folder).and_then(|i| i.Id()).ok()?.to_string();
	id.starts_with("Gorani!").then_some(id)
}

/// The folder stops being a Gorani folder — the shell's registration if it
/// has one, cldapi's otherwise.
pub fn unregister(root: &Path) -> Result<(), String> {
	if let Some(id) = registered_id(root) {
		return StorageProviderSyncRootManager::Unregister(&HSTRING::from(id.as_str())).map_err(text);
	}
	crate::cf::unregister(root).map_err(text)
}

/// Show a malware sample's state beside its name. (Written through the
/// shell's property store; the caller marks the placeholder in sync after.)
pub fn mark_sample(path: &Path) -> Result<(), String> {
	let file = StorageFile::GetFileFromPathAsync(&HSTRING::from(path)).and_then(|op| op.get()).map_err(text)?;
	let state = StorageProviderItemProperty::new().map_err(text)?;
	state.SetId(SAMPLE_STATE).map_err(text)?;
	state.SetValue(&HSTRING::from("Malware sample — never opened raw")).map_err(text)?;
	state.SetIconResource(&HSTRING::from(WARNING_ICON)).map_err(text)?;
	let list = windows_collections::IIterable::<StorageProviderItemProperty>::from(vec![Some(state)]);
	StorageProviderItemProperties::SetAsync(&file, &list).and_then(|op| op.get()).map_err(text)
}
