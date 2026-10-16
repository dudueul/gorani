// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The replica (commit 39a, docs/DESKTOP.md › 39): what a shell that keeps
//! REAL files on disk needs from the core — Windows' Cloud Files API (a
//! placeholder per item, hydrated on first read) and macOS' File Provider
//! (the system's own replicated folder). The Linux shell answers each
//! system call itself (FUSE) and uses the engine's inodes; these two are
//! told about ITEMS, by a stable identifier, and hand back paths:
//!
//! ```text
//! items      the area's tree by server id (the top is ""), names opened in their places —
//!            one that does not open is shown "⚠ unverified ‹id›", never as what it claims
//! read       bytes of ONE version: a placeholder made for version N is never filled with
//!            N+1's (its size and its signed hash are N's) — a sample never, evidence only
//!            once it checked out against its uploader's signed hash
//! create     a new file from a local path: whole up to 48 MiB, GC01 frames above (to
//! save       255 GiB); a new version after the one the placeholder holds. If the file moved
//!            on meanwhile, the bytes become "name (conflict …)" beside it — nothing lost
//! changes    `diff(before, after)`: what to add, move, refresh or remove, parents first
//! ```
//!
//! Two implementations of `Remote`: `HttpRemote` (the engine, the server)
//! and `MemRemote` (in memory — what each platform's own smoke test drives,
//! so a Windows or macOS runner proves the platform layer without a
//! server; the server side is proven on Linux, `api:replica`). And one
//! JSON protocol over either (`dispatch`): the CLI's `replica` command
//! speaks it on stdin/stdout, the macOS bridge across its C interface.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::api::UploadFields;
use crate::engine::{Engine, FsError, Kind, WRITE_LIMIT};
use crate::transfer::{self, hex, Journal};
use crate::Error;

/// One file or folder, as a replicating shell sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
	/// The server's id — stable across renames and moves.
	pub id: String,
	/// The folder's id; "" for the area's top.
	pub parent: String,
	/// As shown: sanitised, unique within its folder.
	pub name: String,
	pub kind: Kind,
	pub size: u64,
	/// The content version (files; 0 for folders): a change means new bytes.
	pub version: i64,
	/// Seconds since the epoch.
	pub modified: u64,
	/// A malware sample (D8): listed, never readable raw.
	pub sample: bool,
	/// False when the name did not open in its place (O6).
	pub name_verified: bool,
}

/// What saving a new version came to.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum Saved {
	/// The file's next version.
	Version { item: Item },
	/// Someone else saved first: their version stands, these bytes are a
	/// new file beside it (`copy`).
	Conflict { copy: Item },
}

/// The server, as a replicating shell needs it.
pub trait Remote {
	/// The area's name (`<member>` or `case:<id>`).
	fn area(&self) -> String;
	/// Why nothing may be written here (evidence; a read grant), or None.
	fn read_only(&self) -> Option<String>;
	/// Has anything changed since the last call? (The first call: yes.)
	fn poll(&mut self) -> Result<bool, Error>;
	/// The tree as the server has it now.
	fn items(&mut self) -> Result<Vec<Item>, Error>;
	/// `len` bytes of version `version` of `id`, from `offset` (fewer at the end).
	fn read(&mut self, id: &str, version: i64, offset: u64, len: u64) -> Result<Vec<u8>, FsError>;
	/// A new file in folder `parent` ("" for the top), its bytes from `path`.
	fn create_file(&mut self, parent: &str, name: &str, path: &Path) -> Result<Item, FsError>;
	/// The version after `base` of `id`, its bytes from `path`.
	fn save_version(&mut self, id: &str, base: i64, path: &Path) -> Result<Saved, FsError>;
	fn mkdir(&mut self, parent: &str, name: &str) -> Result<Item, FsError>;
	/// Rename and/or move (`new_parent` "" for the top).
	fn rename(&mut self, id: &str, new_parent: &str, new_name: &str) -> Result<(), FsError>;
	/// To the Trash (a folder: only when empty).
	fn trash(&mut self, id: &str) -> Result<(), FsError>;
}

// ── what changed ─────────────────────────────────────────────────────

/// One difference between two listings, for a shell to apply.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "camelCase")]
pub enum Change {
	Added { item: Item },
	/// Its folder or name changed (and maybe more: a `Content` follows if so).
	Moved { before: Item, item: Item },
	/// New bytes (a new version): a hydrated copy is stale.
	Content { item: Item },
	/// Only its metadata (modified time, the sample mark).
	Meta { item: Item },
	Removed { item: Item },
}

/// The changes from `before` to `after`, in an order that can be applied
/// as it comes: additions and moves parents first, removals children
/// first.
pub fn diff(before: &[Item], after: &[Item]) -> Vec<Change> {
	let old: HashMap<&str, &Item> = before.iter().map(|i| (i.id.as_str(), i)).collect();
	let new: HashMap<&str, &Item> = after.iter().map(|i| (i.id.as_str(), i)).collect();
	let depth = |items: &HashMap<&str, &Item>, i: &Item| {
		let (mut d, mut at) = (0usize, i.parent.as_str());
		while !at.is_empty() && d < 4096 {
			d += 1;
			at = items.get(at).map(|p| p.parent.as_str()).unwrap_or("");
		}
		d
	};
	let mut adds: Vec<(usize, Change)> = Vec::new();
	let mut removes: Vec<(usize, Change)> = Vec::new();
	for i in after {
		match old.get(i.id.as_str()) {
			None => adds.push((depth(&new, i), Change::Added { item: i.clone() })),
			Some(o) => {
				if o.parent != i.parent || o.name != i.name {
					adds.push((depth(&new, i), Change::Moved { before: (*o).clone(), item: i.clone() }));
				}
				if o.kind == Kind::File && (o.version != i.version || o.size != i.size) {
					adds.push((depth(&new, i) + 1, Change::Content { item: i.clone() }));
				} else if o.modified != i.modified || o.sample != i.sample || o.name_verified != i.name_verified {
					adds.push((depth(&new, i) + 1, Change::Meta { item: i.clone() }));
				}
			}
		}
	}
	for o in before {
		if !new.contains_key(o.id.as_str()) {
			removes.push((depth(&old, o), Change::Removed { item: o.clone() }));
		}
	}
	adds.sort_by_key(|(d, _)| *d);
	removes.sort_by_key(|(d, _)| std::cmp::Reverse(*d));
	removes.into_iter().chain(adds).map(|(_, c)| c).collect()
}

/// Item ids by their folder, children sorted by name — a shell's walk order.
pub fn by_folder(items: &[Item]) -> BTreeMap<String, Vec<Item>> {
	let mut out: BTreeMap<String, Vec<Item>> = BTreeMap::new();
	for i in items {
		out.entry(i.parent.clone()).or_default().push(i.clone());
	}
	for v in out.values_mut() {
		v.sort_by(|a, b| a.name.cmp(&b.name));
	}
	out
}

// ── the server ───────────────────────────────────────────────────────

/// `Remote` over the engine: the server, the area's key, the same naming,
/// sample and evidence rules as the Linux mount.
pub struct HttpRemote {
	engine: Engine,
	journal: Journal,
	member: String,
}

impl HttpRemote {
	/// `journal_dir`: where a large upload's progress is kept (sealed
	/// fields only), so a stopped one can be told apart from a new one.
	pub fn new(engine: Engine, member: &str, journal_dir: PathBuf) -> Self {
		Self { engine, journal: Journal::new(journal_dir), member: member.into() }
	}

	pub fn engine(&mut self) -> &mut Engine {
		&mut self.engine
	}

	fn writable(&self) -> Result<(), FsError> {
		match self.engine.read_only() {
			Some(why) => Err(FsError::ReadOnly(why.to_string())),
			None => Ok(()),
		}
	}

	fn item(&mut self, id: &str) -> Result<Item, FsError> {
		self.engine.relist_now()?;
		self.engine.items().into_iter().find(|i| i.id == id).ok_or(FsError::NotFound)
	}

	/// Seal and send `path`: a new file (`base` None) or the version after
	/// `base`. Whole up to WRITE_LIMIT — read once, hashed and sealed from
	/// the same buffer; GC01 frames above, re-hashed as they are sealed.
	fn send(&mut self, id: &str, base: Option<i64>, parent: &str, name: &str, path: &Path) -> Result<(), FsError> {
		let size = std::fs::metadata(path).map_err(|e| FsError::Io(e.to_string()))?.len();
		let ck = gorani_formats::formats::new_content_key();
		let key = gorani_formats::formats::import_content_key(&ck);
		let area = self.engine.area();
		let folder = (!parent.is_empty()).then(|| parent.to_string());
		if size <= WRITE_LIMIT {
			let plain = Zeroizing::new(std::fs::read(path).map_err(|e| FsError::Io(e.to_string()))?);
			let sha256 = hex(&<sha2::Sha256 as sha2::Digest>::digest(&plain[..]));
			let sealed = gorani_formats::formats::seal_with(&key, &plain);
			let client = self.engine.client();
			match base {
				None => {
					if let Some(note) = area.duplicate_note(client, name, plain.len() as u64, &sha256) {
						eprintln!("gorani: {note}");
					}
					let mut form = area.new_file_fields(id, name, &ck, plain.len() as u64, &sha256, None)?;
					if let Some(f) = &folder {
						form.push(("folder_id".into(), f.clone()));
					}
					client.upload_whole(&UploadFields { form }, &sealed)?;
				}
				Some(base) => {
					let form = area.version_fields(id, base, &ck, plain.len() as u64, &sha256)?;
					client.upload_version(id, &UploadFields { form }, &sealed)?;
				}
			}
			return Ok(());
		}
		let chunk = gorani_formats::chunked::chunk_for(size).ok_or(FsError::TooBig)?;
		let (sha256, hashed) = transfer::sha256_file(path)?;
		if hashed != size {
			return Err(FsError::Io("the file changed while it was being read".into()));
		}
		let mut fields = match base {
			None => {
				if let Some(note) = area.duplicate_note(self.engine.client(), name, size, &sha256) {
					eprintln!("gorani: {note}");
				}
				let mut f = area.new_file_fields(id, name, &ck, size, &sha256, None)?;
				if let Some(p) = &folder {
					f.push(("folder_id".into(), p.clone()));
				}
				f
			}
			// (The upload names the file at its start — `fileId`; the
			// completion carries base_version, as the browser's does.)
			Some(base) => area.version_fields(id, base, &ck, size, &sha256)?,
		};
		fields.push(("chunk".into(), chunk.to_string()));
		// (A replica re-sends a stopped upload from the start: the journal
		// only keeps two runs from mixing, it does not resume — yet.)
		let jkey = Journal::key_for(&self.member, &area.name, &format!("{id}:{}", base.unwrap_or(0)), size, 0, &sha256);
		self.journal.delete(&jkey);
		transfer::push_frames(self.engine.client(), &self.journal, &jkey, path, &key, &self.member, id, chunk, size, fields, None, Some(&sha256), |_, _| {})?;
		Ok(())
	}
}

impl Remote for HttpRemote {
	fn area(&self) -> String {
		self.engine.area().name.clone()
	}

	fn read_only(&self) -> Option<String> {
		self.engine.read_only().map(str::to_string)
	}

	fn poll(&mut self) -> Result<bool, Error> {
		self.engine.refresh()
	}

	fn items(&mut self) -> Result<Vec<Item>, Error> {
		Ok(self.engine.items())
	}

	fn read(&mut self, id: &str, version: i64, offset: u64, len: u64) -> Result<Vec<u8>, FsError> {
		if self.engine.ino_of(id).is_none() {
			self.engine.relist_now()?;
		}
		self.engine.read_at(id, version, offset, len)
	}

	fn create_file(&mut self, parent: &str, name: &str, path: &Path) -> Result<Item, FsError> {
		self.writable()?;
		check_name(name)?;
		let id = crate::new_item_id();
		self.send(&id, None, parent, name, path)?;
		self.item(&id)
	}

	fn save_version(&mut self, id: &str, base: i64, path: &Path) -> Result<Saved, FsError> {
		self.writable()?;
		match self.send(id, Some(base), "", "", path) {
			Ok(()) => Ok(Saved::Version { item: self.item(id)? }),
			Err(FsError::Exists) => {
				// Someone saved first (409): their version stays; these bytes
				// become a new file beside it — nothing is overwritten or lost.
				let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
				let current = self.item(id)?;
				let copy_id = crate::new_item_id();
				let name = crate::engine::conflict_name(&current.name, now);
				self.send(&copy_id, None, &current.parent, &name, path)?;
				Ok(Saved::Conflict { copy: self.item(&copy_id)? })
			}
			Err(e) => Err(e),
		}
	}

	fn mkdir(&mut self, parent: &str, name: &str) -> Result<Item, FsError> {
		self.writable()?;
		let p = self.engine.ino_of(parent).ok_or(FsError::NotFound)?;
		let ino = self.engine.mkdir(p, name)?;
		let id = self.engine.id_of(ino).unwrap_or_default();
		self.item(&id)
	}

	fn rename(&mut self, id: &str, new_parent: &str, new_name: &str) -> Result<(), FsError> {
		self.writable()?;
		let ino = self.engine.ino_of(id).ok_or(FsError::NotFound)?;
		let node = self.engine.node(ino).ok_or(FsError::NotFound)?.clone();
		let np = self.engine.ino_of(new_parent).ok_or(FsError::NotFound)?;
		self.engine.rename(node.parent, &node.name, np, new_name)
	}

	fn trash(&mut self, id: &str) -> Result<(), FsError> {
		self.writable()?;
		let ino = self.engine.ino_of(id).ok_or(FsError::NotFound)?;
		let node = self.engine.node(ino).ok_or(FsError::NotFound)?.clone();
		match node.kind {
			Kind::File => self.engine.unlink(node.parent, &node.name),
			Kind::Dir => self.engine.rmdir(node.parent, &node.name),
		}
	}
}

/// Open a replica over the server, as every shell does: the profile
/// `gorani-sync setup` wrote, unlocked with THIS computer's enrolled copy
/// (or a typed secret), the area opened (a case's key only through a
/// signature the member can check), the root dropped from memory once the
/// area's key is open, and the tree read once.
pub fn connect(profile_path: &Path, case: Option<&str>, secret: Option<&str>, dev_email: Option<&str>, accept_unverified: bool) -> Result<HttpRemote, Error> {
	let mut profile = crate::session::load_profile(profile_path)?;
	if let Some(e) = dev_email {
		profile.dev_email = Some(e.to_string());
	}
	let sess = match secret {
		Some(s) => crate::session::unlock(&profile, s)?,
		None if crate::session::has_device_copy(&profile) => crate::session::unlock_device(&profile)?,
		None => return Err(Error::Config("this profile has no enrolled device copy — run gorani-sync setup, or give the secret".into())),
	};
	let member = profile.member.clone();
	let client = crate::api::Client::new(profile.clone());
	let area = crate::area::open_area(&client, &sess, &member, case)?;
	let name = area.name.clone();
	drop(sess);
	let mut engine = Engine::new(crate::api::Client::new(profile).in_area(&name), area, accept_unverified);
	engine.refresh()?;
	Ok(HttpRemote::new(engine, &member, profile_path.with_extension("uploads")))
}

fn check_name(name: &str) -> Result<(), FsError> {
	if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') || name.contains('\0') {
		return Err(FsError::Denied("not a usable name".into()));
	}
	Ok(())
}

// ── in memory ────────────────────────────────────────────────────────

/// A `Remote` in memory: what each platform's own test drives (a Windows
/// or macOS runner proves its placeholder layer without a server). It
/// keeps the rules that matter to a shell — versions, conflicts, samples,
/// read-only areas, empty-folder trashing — and nothing of the crypto,
/// which is the server side's and proven there.
#[derive(Default)]
pub struct MemRemote {
	pub area: String,
	pub read_only: Option<String>,
	items: BTreeMap<String, Item>,
	bytes: HashMap<(String, i64), Vec<u8>>,
	changed: bool,
	next: u64,
	clock: u64,
}

impl MemRemote {
	pub fn new(area: &str) -> Self {
		Self { area: area.into(), changed: true, clock: 1_760_000_000, ..Default::default() }
	}

	fn fresh_id(&mut self) -> String {
		self.next += 1;
		format!("mem{:06}", self.next)
	}

	fn tick(&mut self) -> u64 {
		self.clock += 1;
		self.clock
	}

	/// Put a file there as if someone else uploaded it (tests).
	pub fn put(&mut self, parent: &str, name: &str, bytes: &[u8]) -> Item {
		let id = self.fresh_id();
		let modified = self.tick();
		let item = Item { id: id.clone(), parent: parent.into(), name: name.into(), kind: Kind::File, size: bytes.len() as u64, version: 1, modified, sample: false, name_verified: true };
		self.bytes.insert((id.clone(), 1), bytes.to_vec());
		self.items.insert(id, item.clone());
		self.changed = true;
		item
	}

	/// A folder made elsewhere (tests).
	pub fn put_dir(&mut self, parent: &str, name: &str) -> Item {
		let id = self.fresh_id();
		let modified = self.tick();
		let item = Item { id: id.clone(), parent: parent.into(), name: name.into(), kind: Kind::Dir, size: 0, version: 0, modified, sample: false, name_verified: true };
		self.items.insert(id, item.clone());
		self.changed = true;
		item
	}

	/// A new version saved elsewhere (tests: the cause of a conflict).
	pub fn edit(&mut self, id: &str, bytes: &[u8]) -> Option<Item> {
		let modified = self.tick();
		let it = self.items.get_mut(id)?;
		it.version += 1;
		it.size = bytes.len() as u64;
		it.modified = modified;
		let item = it.clone();
		self.bytes.insert((id.into(), item.version), bytes.to_vec());
		self.changed = true;
		Some(item)
	}

	/// Mark a file a malware sample (tests).
	pub fn mark_sample(&mut self, id: &str) {
		if let Some(i) = self.items.get_mut(id) {
			i.sample = true;
			self.changed = true;
		}
	}

	/// Moved or removed elsewhere (tests).
	pub fn move_to(&mut self, id: &str, parent: &str, name: &str) {
		if let Some(i) = self.items.get_mut(id) {
			i.parent = parent.into();
			i.name = name.into();
			self.changed = true;
		}
	}

	pub fn remove(&mut self, id: &str) {
		self.items.remove(id);
		self.changed = true;
	}

	/// The current bytes of a file (tests check what a shell sent).
	pub fn content(&self, id: &str) -> Option<Vec<u8>> {
		let it = self.items.get(id)?;
		self.bytes.get(&(id.to_string(), it.version)).cloned()
	}

	pub fn find(&self, parent: &str, name: &str) -> Option<Item> {
		self.items.values().find(|i| i.parent == parent && i.name == name).cloned()
	}

	fn writable(&self) -> Result<(), FsError> {
		match &self.read_only {
			Some(why) => Err(FsError::ReadOnly(why.clone())),
			None => Ok(()),
		}
	}

	fn parent_ok(&self, parent: &str) -> Result<(), FsError> {
		if parent.is_empty() || self.items.get(parent).is_some_and(|p| p.kind == Kind::Dir) {
			Ok(())
		} else {
			Err(FsError::NotFound)
		}
	}

	fn name_free(&self, parent: &str, name: &str, except: Option<&str>) -> Result<(), FsError> {
		check_name(name)?;
		if self.items.values().any(|i| i.parent == parent && i.name == name && Some(i.id.as_str()) != except) {
			return Err(FsError::Exists);
		}
		Ok(())
	}
}

impl Remote for MemRemote {
	fn area(&self) -> String {
		self.area.clone()
	}

	fn read_only(&self) -> Option<String> {
		self.read_only.clone()
	}

	fn poll(&mut self) -> Result<bool, Error> {
		Ok(std::mem::replace(&mut self.changed, false))
	}

	fn items(&mut self) -> Result<Vec<Item>, Error> {
		Ok(self.items.values().cloned().collect())
	}

	fn read(&mut self, id: &str, version: i64, offset: u64, len: u64) -> Result<Vec<u8>, FsError> {
		let it = self.items.get(id).ok_or(FsError::NotFound)?;
		if it.kind == Kind::Dir {
			return Err(FsError::IsDir);
		}
		if it.sample {
			return Err(FsError::Denied("a malware sample is never readable raw".into()));
		}
		if it.version != version {
			return Err(FsError::Io(format!("changed on the server (version {}, not {version})", it.version)));
		}
		let b = self.bytes.get(&(id.to_string(), version)).ok_or(FsError::NotFound)?;
		let from = (offset as usize).min(b.len());
		Ok(b[from..(from + len as usize).min(b.len())].to_vec())
	}

	fn create_file(&mut self, parent: &str, name: &str, path: &Path) -> Result<Item, FsError> {
		self.writable()?;
		self.parent_ok(parent)?;
		self.name_free(parent, name, None)?;
		let bytes = std::fs::read(path).map_err(|e| FsError::Io(e.to_string()))?;
		Ok(self.put(parent, name, &bytes))
	}

	fn save_version(&mut self, id: &str, base: i64, path: &Path) -> Result<Saved, FsError> {
		self.writable()?;
		let bytes = std::fs::read(path).map_err(|e| FsError::Io(e.to_string()))?;
		let it = self.items.get(id).ok_or(FsError::NotFound)?.clone();
		if it.version != base {
			let name = crate::engine::conflict_name(&it.name, self.clock);
			let copy = self.put(&it.parent, &name, &bytes);
			return Ok(Saved::Conflict { copy });
		}
		Ok(Saved::Version { item: self.edit(id, &bytes).ok_or(FsError::NotFound)? })
	}

	fn mkdir(&mut self, parent: &str, name: &str) -> Result<Item, FsError> {
		self.writable()?;
		self.parent_ok(parent)?;
		self.name_free(parent, name, None)?;
		Ok(self.put_dir(parent, name))
	}

	fn rename(&mut self, id: &str, new_parent: &str, new_name: &str) -> Result<(), FsError> {
		self.writable()?;
		self.parent_ok(new_parent)?;
		if !self.items.contains_key(id) {
			return Err(FsError::NotFound);
		}
		self.name_free(new_parent, new_name, Some(id))?;
		let mut at = new_parent.to_string();
		while !at.is_empty() {
			if at == id {
				return Err(FsError::Denied("a folder cannot move into itself".into()));
			}
			at = self.items.get(&at).map(|p| p.parent.clone()).unwrap_or_default();
		}
		self.move_to(id, new_parent, new_name);
		Ok(())
	}

	fn trash(&mut self, id: &str) -> Result<(), FsError> {
		self.writable()?;
		let it = self.items.get(id).ok_or(FsError::NotFound)?;
		if it.kind == Kind::Dir && self.items.values().any(|c| c.parent == id) {
			return Err(FsError::NotEmpty);
		}
		self.remove(id);
		Ok(())
	}
}

/// One version's whole plaintext into a new file at `path`, a window at a
/// time (a 255 GiB file never in memory) — what a shell that is handed
/// contents as a FILE needs (macOS File Provider's fetchContents). On Unix
/// the file is created 0600; on any refusal it is removed.
pub fn download(remote: &mut dyn Remote, id: &str, version: i64, path: &Path) -> Result<u64, FsError> {
	use std::io::Write;
	const WINDOW: u64 = 8 * 1024 * 1024;
	let mut o = std::fs::OpenOptions::new();
	o.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		o.mode(0o600);
	}
	let mut f = o.open(path).map_err(|e| FsError::Io(format!("{}: {e}", path.display())))?;
	let mut at = 0u64;
	let r = (|| loop {
		let b = remote.read(id, version, at, WINDOW)?;
		f.write_all(&b).map_err(|e| FsError::Io(e.to_string()))?;
		at += b.len() as u64;
		if (b.len() as u64) < WINDOW {
			f.sync_all().map_err(|e| FsError::Io(e.to_string()))?;
			return Ok(at);
		}
	})();
	if r.is_err() {
		let _ = std::fs::remove_file(path);
	}
	r
}

// ── one protocol over either ─────────────────────────────────────────

/// A short code for an error, for a shell to map to its platform's.
pub fn error_code(e: &FsError) -> &'static str {
	match e {
		FsError::NotFound => "not_found",
		FsError::Exists => "exists",
		FsError::NotEmpty => "not_empty",
		FsError::NotDir => "not_dir",
		FsError::IsDir => "is_dir",
		FsError::Denied(_) => "denied",
		FsError::ReadOnly(_) => "read_only",
		FsError::TooBig => "too_big",
		FsError::Io(_) => "io",
	}
}

/// One request, one answer — JSON, over any `Remote`:
///
/// ```text
/// { "op": "poll" }                                       → { "changed": bool }
/// { "op": "items" }                                      → { "items": [Item], "readOnly": why|null, "area": name }
/// { "op": "read", "id", "version", "offset", "len" }     → { "data": base64 }
/// { "op": "download", "id", "version", "path" }          → { "size": n } (the whole version, into a new file)
/// { "op": "create", "parent", "name", "path" }           → { "item": Item }
/// { "op": "save", "id", "base", "path" }                 → { "outcome": "version", "item" } | { "outcome": "conflict", "copy" }
/// { "op": "mkdir", "parent", "name" }                    → { "item": Item }
/// { "op": "rename", "id", "parent", "name" }             → {}
/// { "op": "trash", "id" }                                → {}
/// any refusal                                            → { "error": message, "code": not_found|exists|… }
/// ```
pub fn dispatch(remote: &mut dyn Remote, req: &Value) -> Value {
	let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
	let n = |k: &str| req.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
	let fs = |r: Result<Value, FsError>| r.unwrap_or_else(|e| json!({ "error": e.to_string(), "code": error_code(&e) }));
	let core = |r: Result<Value, Error>| r.unwrap_or_else(|e| json!({ "error": e.to_string(), "code": "io" }));
	match s("op").as_str() {
		"poll" => core(remote.poll().map(|c| json!({ "changed": c }))),
		"items" => core(remote.items().map(|i| json!({ "items": i, "readOnly": remote.read_only(), "area": remote.area() }))),
		"read" => fs(remote.read(&s("id"), n("version"), n("offset").max(0) as u64, n("len").max(0) as u64).map(|b| {
			use base64::Engine as _;
			json!({ "data": base64::engine::general_purpose::STANDARD.encode(b) })
		})),
		"download" => fs(download(remote, &s("id"), n("version"), Path::new(&s("path"))).map(|n| json!({ "size": n }))),
		"create" => fs(remote.create_file(&s("parent"), &s("name"), Path::new(&s("path"))).map(|i| json!({ "item": i }))),
		"save" => fs(remote.save_version(&s("id"), n("base"), Path::new(&s("path"))).map(|o| serde_json::to_value(o).unwrap_or_default())),
		"mkdir" => fs(remote.mkdir(&s("parent"), &s("name")).map(|i| json!({ "item": i }))),
		"rename" => fs(remote.rename(&s("id"), &s("parent"), &s("name")).map(|()| json!({}))),
		"trash" => fs(remote.trash(&s("id")).map(|()| json!({}))),
		other => json!({ "error": format!("no such op: {other}"), "code": "denied" }),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn file(id: &str, parent: &str, name: &str, version: i64) -> Item {
		Item { id: id.into(), parent: parent.into(), name: name.into(), kind: Kind::File, size: 10, version, modified: 1, sample: false, name_verified: true }
	}
	fn dir(id: &str, parent: &str, name: &str) -> Item {
		Item { id: id.into(), parent: parent.into(), name: name.into(), kind: Kind::Dir, size: 0, version: 0, modified: 1, sample: false, name_verified: true }
	}

	#[test]
	fn a_diff_adds_parents_first_and_removes_children_first() {
		let before = vec![dir("d1", "", "old"), file("f1", "d1", "a.txt", 1), file("f2", "", "b.txt", 1)];
		let after = vec![dir("d2", "", "new"), dir("d3", "d2", "sub"), file("f3", "d3", "c.txt", 1), file("f2", "d2", "b2.txt", 2)];
		let c = diff(&before, &after);
		let pos = |pred: &dyn Fn(&Change) -> bool| c.iter().position(|x| pred(x)).expect("present");
		assert!(pos(&|x| matches!(x, Change::Removed { item } if item.id == "f1")) < pos(&|x| matches!(x, Change::Removed { item } if item.id == "d1")), "a file goes before its folder");
		assert!(pos(&|x| matches!(x, Change::Added { item } if item.id == "d2")) < pos(&|x| matches!(x, Change::Added { item } if item.id == "d3")));
		assert!(pos(&|x| matches!(x, Change::Added { item } if item.id == "d3")) < pos(&|x| matches!(x, Change::Added { item } if item.id == "f3")));
		assert!(pos(&|x| matches!(x, Change::Moved { item, .. } if item.id == "f2")) < pos(&|x| matches!(x, Change::Content { item } if item.id == "f2")), "moved, then refreshed");
		assert!(c.iter().all(|x| !matches!(x, Change::Removed { item } if item.id == "f2")));
		assert!(diff(&after, &after).is_empty(), "nothing changed, nothing to do");
	}

	#[test]
	fn the_memory_remote_keeps_the_rules_a_shell_relies_on() {
		let dir_ = std::env::temp_dir().join(format!("gorani-replica-{}", crate::new_item_id()));
		std::fs::create_dir_all(&dir_).unwrap();
		let p = dir_.join("x");
		std::fs::write(&p, b"first").unwrap();
		let mut m = MemRemote::new("ana");
		assert!(m.poll().unwrap() && !m.poll().unwrap(), "the first poll says so, the next only after a change");
		let f = m.create_file("", "x.txt", &p).unwrap();
		assert!(matches!(m.create_file("", "x.txt", &p), Err(FsError::Exists)));
		assert_eq!(m.read(&f.id, 1, 1, 3).unwrap(), b"irs");
		std::fs::write(&p, b"second").unwrap();
		let Saved::Version { item } = m.save_version(&f.id, 1, &p).unwrap() else { panic!("a version") };
		assert_eq!(item.version, 2);
		assert!(matches!(m.read(&f.id, 1, 0, 10), Err(FsError::Io(_))), "an old version is not served as the new one");
		m.edit(&f.id, b"theirs");
		let Saved::Conflict { copy } = m.save_version(&f.id, 2, &p).unwrap() else { panic!("a conflict") };
		assert!(copy.name.starts_with("x (conflict ") && copy.name.ends_with(".txt"));
		assert_eq!(m.content(&f.id).unwrap(), b"theirs", "their version stands");
		let d = m.mkdir("", "docs").unwrap();
		m.rename(&f.id, &d.id, "y.txt").unwrap();
		assert!(matches!(m.trash(&d.id), Err(FsError::NotEmpty)));
		assert!(matches!(m.rename(&d.id, &d.id, "loop"), Err(FsError::Denied(_))));
		m.mark_sample(&copy.id);
		assert!(matches!(m.read(&copy.id, 1, 0, 1), Err(FsError::Denied(_))));
		m.read_only = Some("evidence".into());
		assert!(matches!(m.mkdir("", "nope"), Err(FsError::ReadOnly(_))));
		std::fs::remove_dir_all(&dir_).ok();
	}

	#[test]
	fn the_protocol_answers_in_json_and_names_its_refusals() {
		let mut m = MemRemote::new("ana");
		let f = m.put("", "a.txt", b"hello");
		let r = dispatch(&mut m, &json!({ "op": "read", "id": f.id, "version": 1, "offset": 1, "len": 3 }));
		assert_eq!(r["data"], "ZWxs");
		let r = dispatch(&mut m, &json!({ "op": "trash", "id": "nope" }));
		assert_eq!(r["code"], "not_found");
		let r = dispatch(&mut m, &json!({ "op": "items" }));
		assert_eq!(r["items"][0]["name"], "a.txt");
		assert_eq!(r["items"][0]["kind"], "file");
		assert_eq!(dispatch(&mut m, &json!({ "op": "bogus" }))["code"], "denied");
		let big = m.put("", "big.bin", &vec![7u8; 9 * 1024 * 1024 + 5]);
		let to = std::env::temp_dir().join(format!("gorani-dl-{}", crate::new_item_id()));
		assert_eq!(dispatch(&mut m, &json!({ "op": "download", "id": big.id, "version": 1, "path": to.to_string_lossy() }))["size"], 9 * 1024 * 1024 + 5);
		assert_eq!(std::fs::read(&to).unwrap().len(), 9 * 1024 * 1024 + 5);
		assert_eq!(dispatch(&mut m, &json!({ "op": "download", "id": big.id, "version": 1, "path": to.to_string_lossy() }))["code"], "io", "never over an existing file");
		std::fs::remove_file(&to).ok();
	}
}

/// A shell calls its remote from the platform's own threads (Cloud Files
/// callbacks; File Provider's queues): both remotes cross threads.
#[allow(dead_code)]
fn remotes_are_send() {
	fn send<T: Send>() {}
	send::<HttpRemote>();
	send::<MemRemote>();
}
