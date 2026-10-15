// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Windows sync provider (commit 39b, docs/DESKTOP.md › 39b): one
//! folder, one area, over any `Remote` — the server (the CLI) or memory
//! (the smoke test, tests/cloud.rs).
//!
//! ```text
//! the server → the folder   a placeholder per item (its size, times, identity; no bytes);
//!                           moved, renamed, refreshed (dehydrated: new bytes are fetched
//!                           on the next read) or removed as the listing says — never one
//!                           the member changed and has not sent (that one waits, or is
//!                           kept as a local copy: nothing is lost)
//! a read                    FETCH_DATA: the range asked, of the placeholder's own
//!                           version, 4 MiB at a time; a sample refused, evidence only
//!                           once checked (the engine's rules)
//! the folder → the server   deletes and renames: allowed only once the server agreed
//!                           (NOTIFY_*); new files and folders and saves: seen by the
//!                           watcher, sent once the writer let go, then made placeholders
//!                           in sync. A save the server refuses as stale becomes a
//!                           conflict copy beside the other version
//! stop                      what was hydrated is dehydrated — plaintext leaves the
//!                           disk with the shell (unless --keep-local)
//! ```
//!
//! Locks: the remote and the state are each held only for a call, never
//! across a file-system operation — our own deletes and renames come back
//! as callbacks on the platform's threads, and must not wait for us.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use gorani_client_core::engine::{FsError, Kind};
use gorani_client_core::replica::{Item, Remote, Saved};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Storage::CloudFilters::{CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS, CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE, CF_CALLBACK_DELETE_FLAG_IS_UNDELETE};

use crate::cf;
use crate::names::{self, identity, key, layout, local_name, parse_identity};

/// How much a FETCH_DATA answers at once (a multiple of 4 KiB, as the
/// platform requires of every transfer but the last).
const CHUNK: u64 = 4 * 1024 * 1024;
/// A local change is looked at once nothing has touched it for this long.
const SETTLE: Duration = Duration::from_millis(1500);

pub struct Options {
	/// Ask the server for changes this often; None: only when told (tests).
	pub poll: Option<Duration>,
	/// Leave hydrated files on disk when the shell stops.
	pub keep_local: bool,
	pub verbose: bool,
}

/// What the shell knows of an item it has a placeholder for.
#[derive(Clone, Debug)]
struct Known {
	id: String,
	rel: PathBuf,
	kind: Kind,
	version: i64,
	size: u64,
	/// None when learnt from the disk (the next listing says).
	modified: Option<u64>,
	sample: bool,
}

#[derive(Default)]
struct State {
	known: HashMap<String, Known>,
	by_path: HashMap<String, String>,
}

impl State {
	fn insert(&mut self, k: Known) {
		if let Some(old) = self.known.get(&k.id) {
			self.by_path.remove(&key(&old.rel));
		}
		self.by_path.insert(key(&k.rel), k.id.clone());
		self.known.insert(k.id.clone(), k);
	}

	fn remove(&mut self, id: &str) {
		if let Some(k) = self.known.remove(id) {
			self.by_path.remove(&key(&k.rel));
			// (A folder's children go with it.)
			let prefix = format!("{}\\", key(&k.rel));
			let kids: Vec<String> = self.known.values().filter(|c| key(&c.rel).starts_with(&prefix)).map(|c| c.id.clone()).collect();
			for c in kids {
				if let Some(ck) = self.known.remove(&c) {
					self.by_path.remove(&key(&ck.rel));
				}
			}
		}
	}

	/// A rename or move: the item and, for a folder, everything under it.
	fn moved(&mut self, id: &str, to: &Path) {
		let Some(k) = self.known.get(id).cloned() else { return };
		let (from, prefix) = (k.rel.clone(), format!("{}\\", key(&k.rel)));
		let under: Vec<Known> = self.known.values().filter(|c| key(&c.rel).starts_with(&prefix)).cloned().collect();
		self.insert(Known { rel: to.to_path_buf(), ..k });
		for mut c in under {
			let rest = c.rel.strip_prefix(&from).map(Path::to_path_buf).unwrap_or_default();
			c.rel = to.join(rest);
			self.insert(c);
		}
	}

	fn id_at(&self, rel: &Path) -> Option<String> {
		if rel.as_os_str().is_empty() {
			return Some(String::new());
		}
		self.by_path.get(&key(rel)).cloned()
	}
}

pub struct Provider {
	root: PathBuf,
	/// The root as the platform writes paths in callbacks (no drive), folded,
	/// and how many characters it has unfolded.
	root_vol: String,
	root_chars: usize,
	remote: Arc<Mutex<dyn Remote + Send>>,
	read_only: Option<String>,
	state: Mutex<State>,
	/// Our own deletes and renames, by folded volume path: their callbacks are
	/// acknowledged without asking the server again.
	self_ops: Mutex<HashSet<String>>,
	pending: Mutex<BTreeMap<PathBuf, Instant>>,
	stop: AtomicBool,
	verbose: bool,
	warned: Mutex<HashSet<String>>,
}

/// A path as callbacks name it: without `\\?\` and the drive.
fn vol_raw(p: &str) -> String {
	let s = p.replace('/', "\\");
	let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
	let s = if s.as_bytes().get(1) == Some(&b':') { s[2..].to_string() } else { s };
	s.trim_end_matches('\\').to_string()
}

/// The same, folded for comparisons.
fn vol(p: &Path) -> String {
	names::fold(&vol_raw(&p.to_string_lossy()))
}

fn status_of(e: &FsError) -> NTSTATUS {
	match e {
		FsError::Denied(_) => cf::STATUS_CLOUD_FILE_ACCESS_DENIED,
		FsError::ReadOnly(_) => cf::STATUS_CLOUD_FILE_READ_ONLY_VOLUME,
		FsError::Io(_) => cf::STATUS_CLOUD_FILE_NOT_IN_SYNC,
		_ => cf::STATUS_CLOUD_FILE_UNSUCCESSFUL,
	}
}

impl Provider {
	fn log(&self, msg: &str) {
		if self.verbose {
			eprintln!("gorani-cloud: {msg}");
		}
	}

	fn warn_once(&self, what: &str, msg: &str) {
		if self.warned.lock().expect("lock").insert(what.to_string()) {
			eprintln!("gorani-cloud: {msg}");
		}
	}

	/// Run `f` as one of our own operations on `paths`.
	fn ours<T>(&self, paths: &[&Path], f: impl FnOnce() -> T) -> T {
		let keys: Vec<String> = paths.iter().map(|p| vol(p)).collect();
		self.self_ops.lock().expect("lock").extend(keys.iter().cloned());
		let out = f();
		let mut s = self.self_ops.lock().expect("lock");
		for k in &keys {
			s.remove(k);
		}
		out
	}

	/// A callback's volume path, relative to the root — None when outside it.
	fn rel_of(&self, raw: &str) -> Option<PathBuf> {
		let head: String = raw.chars().take(self.root_chars).collect();
		if names::fold(&head) != self.root_vol {
			return None;
		}
		let tail: String = raw.chars().skip(self.root_chars).collect();
		if !tail.is_empty() && !tail.starts_with('\\') {
			return None;
		}
		Some(PathBuf::from(tail.trim_start_matches('\\')))
	}

	pub fn note(&self, rel: PathBuf) {
		self.pending.lock().expect("lock").insert(rel, Instant::now());
	}

	// ── the server → the folder ────────────────────────────────────────

	/// Ask the server; apply what changed. `force`: list even if the feed
	/// says nothing changed (the first run, a test).
	pub fn sync_remote(&self, force: bool) -> Result<(), String> {
		let items = {
			let mut r = self.remote.lock().expect("lock");
			let changed = r.poll().map_err(|e| e.to_string())?;
			if !changed && !force {
				return Ok(());
			}
			r.items().map_err(|e| e.to_string())?
		};
		self.apply(&items);
		Ok(())
	}

	fn apply(&self, items: &[Item]) {
		let want = layout(items);
		let by_id: HashMap<&str, &Item> = items.iter().map(|i| (i.id.as_str(), i)).collect();
		// 1. Gone from the server: deepest first.
		let mut gone: Vec<Known> = self.state.lock().expect("lock").known.values().filter(|k| !by_id.contains_key(k.id.as_str())).cloned().collect();
		gone.sort_by_key(|k| std::cmp::Reverse(k.rel.components().count()));
		for k in gone {
			self.remove_local(&k);
		}
		// 2. New and moved: shallowest first, folders before files, retried
		// while a parent is still on its way.
		let mut todo: Vec<&Item> = items.iter().collect();
		todo.sort_by_key(|i| (want[&i.id].components().count(), i.kind != Kind::Dir));
		for _pass in 0..8 {
			let mut later = Vec::new();
			for i in todo {
				let target = &want[&i.id];
				let known = self.state.lock().expect("lock").known.get(&i.id).cloned();
				let parent = target.parent().map(Path::to_path_buf).unwrap_or_default();
				if !parent.as_os_str().is_empty() && !self.root.join(&parent).is_dir() {
					later.push(i);
					continue;
				}
				match known {
					Some(k) if key(&k.rel) != key(target) => self.move_local(&k, target),
					Some(_) => {}
					None => self.add_local(i, target),
				}
			}
			if later.is_empty() {
				break;
			}
			todo = later;
		}
		// 3. New bytes, new metadata.
		for i in items {
			let Some(k) = self.state.lock().expect("lock").known.get(&i.id).cloned() else { continue };
			if i.kind == Kind::File && (k.version != i.version || k.size != i.size) {
				self.refresh_local(&k, i);
			} else if k.modified.is_some_and(|m| m != i.modified) || k.sample != i.sample {
				self.retag_local(&k, i);
			} else if k.modified.is_none() {
				self.state.lock().expect("lock").insert(Known { modified: Some(i.modified), sample: i.sample, ..k });
			}
		}
	}

	fn read_only_item(&self, i: &Item) -> bool {
		self.read_only.is_some() || i.sample
	}

	fn add_local(&self, i: &Item, rel: &Path) {
		let full = self.root.join(rel);
		if full.exists() {
			// Something of the member's own is there: theirs stays, ours waits.
			self.warn_once(&format!("taken:{}", key(rel)), &format!("{} is the member's own file; the server's item of that name is not placed until it moves", rel.display()));
			return;
		}
		let name = rel.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
		let ph = cf::NewPlaceholder { name: &name, dir: i.kind == Kind::Dir, size: i.size, modified: i.modified, identity: identity(&i.id, i.version), read_only: self.read_only_item(i) };
		let dir = full.parent().map(Path::to_path_buf).unwrap_or_else(|| self.root.clone());
		match cf::create_placeholders(&dir, &[ph]).into_iter().next() {
			Some(Ok(())) => {
				self.log(&format!("placed {}", rel.display()));
				self.state.lock().expect("lock").insert(Known { id: i.id.clone(), rel: rel.to_path_buf(), kind: i.kind, version: i.version, size: i.size, modified: Some(i.modified), sample: i.sample });
			}
			Some(Err(e)) => self.warn_once(&format!("place:{}", i.id), &format!("could not place {}: {e}", rel.display())),
			None => {}
		}
	}

	fn move_local(&self, k: &Known, to: &Path) {
		let (from, dest) = (self.root.join(&k.rel), self.root.join(to));
		if dest.exists() {
			self.warn_once(&format!("taken:{}", key(to)), &format!("{} is taken; {} stays where it is", to.display(), k.rel.display()));
			return;
		}
		match self.ours(&[&from], || std::fs::rename(&from, &dest)) {
			Ok(()) => {
				self.log(&format!("moved {} → {}", k.rel.display(), to.display()));
				self.state.lock().expect("lock").moved(&k.id, to);
			}
			Err(e) => self.log(&format!("could not move {}: {e}", k.rel.display())),
		}
	}

	fn remove_local(&self, k: &Known) {
		let full = self.root.join(&k.rel);
		let info = cf::info(&full);
		let sent = info.as_ref().is_some_and(|i| i.in_sync);
		let result = match k.kind {
			Kind::Dir => self.ours(&[&full], || std::fs::remove_dir(&full)),
			Kind::File if sent => self.ours(&[&full], || std::fs::remove_file(&full)),
			Kind::File => {
				// The member changed it and it was removed elsewhere: their
				// bytes stay, as a file of their own, sent again as new.
				let kept = full.with_file_name(format!("{} (removed elsewhere)", local_name(&full.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())));
				let r = self.ours(&[&full], || std::fs::rename(&full, &kept)).and_then(|()| cf::revert(&kept).map_err(|e| std::io::Error::other(e.to_string())));
				if r.is_ok() {
					self.note(kept.strip_prefix(&self.root).map(Path::to_path_buf).unwrap_or_default());
				}
				r
			}
		};
		match result {
			Ok(()) => self.log(&format!("removed {}", k.rel.display())),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
			Err(e) => {
				// A folder still holding the member's own files: it stops
				// being ours, and they are sent from there.
				if k.kind == Kind::Dir {
					let _ = cf::revert(&full);
					self.note(k.rel.clone());
				}
				self.log(&format!("kept {} ({e})", k.rel.display()));
			}
		}
		self.state.lock().expect("lock").remove(&k.id);
	}

	fn refresh_local(&self, k: &Known, i: &Item) {
		let full = self.root.join(&k.rel);
		match cf::info(&full) {
			Some(info) if info.in_sync => match cf::update(&full, &identity(&i.id, i.version), Some((false, i.size, i.modified, self.read_only_item(i))), true) {
				Ok(()) => {
					self.log(&format!("{} is version {} now", k.rel.display(), i.version));
					self.state.lock().expect("lock").insert(Known { version: i.version, size: i.size, modified: Some(i.modified), sample: i.sample, ..k.clone() });
				}
				// In use: the next round tries again.
				Err(e) => self.log(&format!("{} is busy ({e}); later", k.rel.display())),
			},
			// The member's own unsent change: their save comes first (and
			// makes a conflict copy if it is stale).
			_ => {}
		}
	}

	fn retag_local(&self, k: &Known, i: &Item) {
		let full = self.root.join(&k.rel);
		if cf::update(&full, &identity(&i.id, k.version), Some((k.kind == Kind::Dir, k.size, i.modified, self.read_only_item(i))), i.sample && !k.sample).is_ok() {
			self.state.lock().expect("lock").insert(Known { modified: Some(i.modified), sample: i.sample, ..k.clone() });
		}
	}

	// ── the folder → the server ────────────────────────────────────────

	/// Look at what changed locally — `all`: now, not only what settled.
	pub fn sync_local(&self, all: bool) {
		let now = Instant::now();
		let due: Vec<PathBuf> = {
			let p = self.pending.lock().expect("lock");
			p.iter().filter(|(_, t)| all || now.duration_since(**t) >= SETTLE).map(|(r, _)| r.clone()).collect()
		};
		let mut due = due;
		// Folders before what is in them.
		due.sort_by_key(|r| r.components().count());
		for rel in due {
			self.pending.lock().expect("lock").remove(&rel);
			if rel.as_os_str().is_empty() {
				// (The watcher lost events: everything is looked at again.)
				self.scan(&self.root.clone(), true);
				continue;
			}
			match self.local(&rel) {
				Ok(true) => {}
				Ok(false) => self.note(rel),
				Err(e) => {
					self.warn_once(&format!("local:{}", key(&rel)), &format!("{}: {e}", rel.display()));
					self.note(rel);
				}
			}
		}
	}

	/// One local path, looked at: Ok(true) done, Ok(false) not yet (in use,
	/// its folder not sent yet).
	fn local(&self, rel: &Path) -> Result<bool, String> {
		let full = self.root.join(rel);
		let Ok(meta) = std::fs::symlink_metadata(&full) else { return Ok(true) };
		let name = rel.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
		if names::ignored(&name) || meta.file_type().is_symlink() {
			return Ok(true);
		}
		let parent = rel.parent().map(Path::to_path_buf).unwrap_or_default();
		let parent_id = self.state.lock().expect("lock").id_at(&parent);
		let fs = |e: FsError| e.to_string();
		match cf::info(&full) {
			None => {
				if let Some(why) = &self.read_only {
					self.warn_once(&format!("ro:{}", key(rel)), &format!("{} stays on this computer only — {why}", rel.display()));
					return Ok(true);
				}
				let Some(pid) = parent_id else { return Ok(false) };
				if meta.is_dir() {
					let item = self.remote.lock().expect("lock").mkdir(&pid, &name).map_err(fs)?;
					cf::convert(&full, &identity(&item.id, 0)).map_err(|e| e.to_string())?;
					self.state.lock().expect("lock").insert(Known { id: item.id.clone(), rel: rel.to_path_buf(), kind: Kind::Dir, version: 0, size: 0, modified: Some(item.modified), sample: false });
					self.log(&format!("sent folder {}", rel.display()));
					if let Ok(entries) = std::fs::read_dir(&full) {
						for e in entries.flatten() {
							self.note(rel.join(e.file_name()));
						}
					}
				} else {
					if in_use(&full) {
						return Ok(false);
					}
					let item = self.remote.lock().expect("lock").create_file(&pid, &name, &full).map_err(fs)?;
					cf::convert(&full, &identity(&item.id, item.version)).map_err(|e| e.to_string())?;
					self.state.lock().expect("lock").insert(Known { id: item.id.clone(), rel: rel.to_path_buf(), kind: Kind::File, version: item.version, size: item.size, modified: Some(item.modified), sample: false });
					self.log(&format!("sent {}", rel.display()));
				}
				Ok(true)
			}
			Some(info) if info.in_sync => Ok(true),
			Some(info) => {
				if meta.is_dir() {
					let _ = cf::mark_in_sync(&full);
					return Ok(true);
				}
				let Some((id, base)) = parse_identity(&info.identity) else { return Ok(true) };
				if let Some(why) = &self.read_only {
					self.warn_once(&format!("ro:{}", key(rel)), &format!("{} was changed here and is not sent — {why}", rel.display()));
					return Ok(true);
				}
				if in_use(&full) {
					return Ok(false);
				}
				let saved = self.remote.lock().expect("lock").save_version(&id, base, &full).map_err(fs)?;
				match saved {
					Saved::Version { item } => {
						cf::update(&full, &identity(&item.id, item.version), None, false).map_err(|e| e.to_string())?;
						let k = self.state.lock().expect("lock").known.get(&id).cloned();
						if let Some(k) = k {
							self.state.lock().expect("lock").insert(Known { version: item.version, size: item.size, modified: Some(item.modified), ..k });
						}
						self.log(&format!("sent {} as version {}", rel.display(), item.version));
					}
					Saved::Conflict { copy } => {
						// These bytes are the copy now; the other version's
						// placeholder comes back at the name on the next sync.
						let copy_rel = rel.with_file_name(local_name(&copy.name));
						let dest = self.root.join(&copy_rel);
						self.ours(&[&full], || std::fs::rename(&full, &dest)).map_err(|e| e.to_string())?;
						cf::update(&dest, &identity(&copy.id, copy.version), None, false).map_err(|e| e.to_string())?;
						let mut st = self.state.lock().expect("lock");
						st.remove(&id);
						st.insert(Known { id: copy.id.clone(), rel: copy_rel.clone(), kind: Kind::File, version: copy.version, size: copy.size, modified: Some(copy.modified), sample: false });
						drop(st);
						eprintln!("gorani-cloud: {} changed elsewhere meanwhile — your bytes are saved as “{}”", rel.display(), copy_rel.display());
						self.sync_remote(true)?;
					}
				}
				Ok(true)
			}
		}
	}

	/// What is on disk already: placeholders become known (their identity
	/// says which item, which version); everything else is looked at as new.
	fn scan(&self, dir: &Path, queue_all: bool) {
		let Ok(entries) = std::fs::read_dir(dir) else { return };
		for e in entries.flatten() {
			let full = e.path();
			let rel = full.strip_prefix(&self.root).map(Path::to_path_buf).unwrap_or_default();
			let Ok(meta) = e.metadata() else { continue };
			match cf::info(&full).and_then(|i| parse_identity(&i.identity).map(|(id, v)| (i.in_sync, id, v))) {
				Some((in_sync, id, version)) => {
					let kind = if meta.is_dir() { Kind::Dir } else { Kind::File };
					self.state.lock().expect("lock").insert(Known { id, rel: rel.clone(), kind, version, size: if meta.is_dir() { 0 } else { meta.len() }, modified: None, sample: false });
					if !in_sync || queue_all {
						self.note(rel.clone());
					}
				}
				None => self.note(rel.clone()),
			}
			if meta.is_dir() {
				self.scan(&full, queue_all);
			}
		}
	}

	/// Drop the local bytes of everything sent (the shell is stopping).
	fn dehydrate_all(&self) {
		let files: Vec<PathBuf> = self.state.lock().expect("lock").known.values().filter(|k| k.kind == Kind::File).map(|k| self.root.join(&k.rel)).collect();
		for f in files {
			if cf::info(&f).is_some_and(|i| i.in_sync) {
				if let Err(e) = cf::dehydrate(&f) {
					self.log(&format!("{} kept on disk ({e})", f.display()));
				}
			}
		}
	}
}

/// Is a writer still holding it? (Opened with no sharing: fails while any
/// other handle is open.)
fn in_use(p: &Path) -> bool {
	use std::os::windows::fs::OpenOptionsExt;
	std::fs::OpenOptions::new().read(true).share_mode(0).open(p).is_err()
}

// ── the callbacks ────────────────────────────────────────────────────

/// SAFETY (all three): the platform calls these with valid pointers, and
/// `CallbackContext` is the `Provider` we connected with, kept alive by
/// `Running` until after the disconnect.
unsafe fn provider<'a>(info: *const CF_CALLBACK_INFO) -> (&'a CF_CALLBACK_INFO, &'a Provider) {
	let info = unsafe { &*info };
	(info, unsafe { &*(info.CallbackContext as *const Provider) })
}

unsafe extern "system" fn on_fetch_data(info: *const CF_CALLBACK_INFO, params: *const CF_CALLBACK_PARAMETERS) {
	let (info, p) = unsafe { provider(info) };
	let fd = unsafe { (*params).Anonymous.FetchData };
	let start = fd.RequiredFileOffset.max(0) as u64;
	let size = info.FileSize.max(0) as u64;
	let end = (start + fd.RequiredLength.max(0) as u64).min(size);
	let fail = |at: u64, status: NTSTATUS| {
		if let Err(e) = cf::fail_transfer(info, at, end.saturating_sub(at).max(1), status) {
			p.log(&format!("could not fail the fetch at {at}: {e}"));
		}
	};
	let Some((id, version)) = parse_identity(&cf::identity_of(info)) else {
		fail(start, cf::STATUS_CLOUD_FILE_UNSUCCESSFUL);
		return;
	};
	p.log(&format!("fetch {id} v{version} [{start}, {end})"));
	let mut at = start;
	while at < end {
		let want = CHUNK.min(end - at);
		let got = p.remote.lock().expect("lock").read(&id, version, at, want);
		match got {
			Ok(data) if data.len() as u64 == want || (at + data.len() as u64 == size && !data.is_empty()) => {
				if let Err(e) = cf::transfer(info, at, &data) {
					p.log(&format!("transfer of {id} at {at} failed: {e}"));
					return;
				}
				at += data.len() as u64;
			}
			Ok(_) => return fail(at, cf::STATUS_CLOUD_FILE_UNSUCCESSFUL),
			Err(e) => {
				p.warn_once(&format!("read:{id}"), &format!("{id}: {e}"));
				return fail(at, status_of(&e));
			}
		}
	}
}

unsafe extern "system" fn on_delete(info: *const CF_CALLBACK_INFO, params: *const CF_CALLBACK_PARAMETERS) {
	let (info, p) = unsafe { provider(info) };
	let flags = unsafe { (*params).Anonymous.Delete.Flags };
	let path = vol(Path::new(&cf::wide(info.NormalizedPath)));
	p.log(&format!("delete {}", cf::wide(info.NormalizedPath)));
	if p.self_ops.lock().expect("lock").contains(&path) || (flags.0 & CF_CALLBACK_DELETE_FLAG_IS_UNDELETE.0) != 0 {
		let _ = cf::ack_delete(info, cf::STATUS_SUCCESS);
		return;
	}
	if p.read_only.is_some() {
		let _ = cf::ack_delete(info, cf::STATUS_CLOUD_FILE_READ_ONLY_VOLUME);
		return;
	}
	let status = match parse_identity(&cf::identity_of(info)) {
		Some((id, _)) if !id.is_empty() => match p.remote.lock().expect("lock").trash(&id) {
			Ok(()) | Err(FsError::NotFound) => {
				p.state.lock().expect("lock").remove(&id);
				p.log(&format!("trashed {id}"));
				cf::STATUS_SUCCESS
			}
			Err(e) => {
				p.warn_once(&format!("del:{id}"), &format!("the server did not take the delete: {e}"));
				status_of(&e)
			}
		},
		_ => cf::STATUS_SUCCESS,
	};
	if let Err(e) = cf::ack_delete(info, status) {
		p.log(&format!("could not answer the delete: {e}"));
	}
}

unsafe extern "system" fn on_rename(info: *const CF_CALLBACK_INFO, params: *const CF_CALLBACK_PARAMETERS) {
	let (info, p) = unsafe { provider(info) };
	let rename = unsafe { (*params).Anonymous.Rename };
	let source = vol(Path::new(&cf::wide(info.NormalizedPath)));
	p.log(&format!("rename {} → {}", cf::wide(info.NormalizedPath), cf::wide(rename.TargetPath)));
	if p.self_ops.lock().expect("lock").contains(&source) {
		let _ = cf::ack_rename(info, cf::STATUS_SUCCESS);
		return;
	}
	if p.read_only.is_some() {
		let _ = cf::ack_rename(info, cf::STATUS_CLOUD_FILE_READ_ONLY_VOLUME);
		return;
	}
	let Some((id, _)) = parse_identity(&cf::identity_of(info)).filter(|(id, _)| !id.is_empty()) else {
		let _ = cf::ack_rename(info, cf::STATUS_SUCCESS);
		return;
	};
	let target_raw = vol_raw(&cf::wide(rename.TargetPath));
	let status = if (rename.Flags.0 & CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE.0) == 0 {
		// Out of the folder (the Recycle Bin, elsewhere): gone from the area.
		match p.remote.lock().expect("lock").trash(&id) {
			Ok(()) | Err(FsError::NotFound) => {
				p.state.lock().expect("lock").remove(&id);
				cf::STATUS_SUCCESS
			}
			Err(e) => status_of(&e),
		}
	} else {
		let rel = p.rel_of(&target_raw);
		match rel {
			Some(rel) if !rel.as_os_str().is_empty() => {
				let parent = rel.parent().map(Path::to_path_buf).unwrap_or_default();
				let name = rel.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
				let pid = p.state.lock().expect("lock").id_at(&parent);
				match pid {
					// Into a folder of the member's own, not sent yet: not now.
					None => cf::STATUS_CLOUD_FILE_NOT_IN_SYNC,
					Some(pid) => match p.remote.lock().expect("lock").rename(&id, &pid, &name) {
						Ok(()) => {
							p.state.lock().expect("lock").moved(&id, &rel);
							p.log(&format!("renamed {id} → {}", rel.display()));
							cf::STATUS_SUCCESS
						}
						Err(e) => {
							p.warn_once(&format!("mv:{id}"), &format!("the server did not take the rename: {e}"));
							status_of(&e)
						}
					},
				}
			}
			_ => cf::STATUS_CLOUD_FILE_UNSUCCESSFUL,
		}
	};
	if let Err(e) = cf::ack_rename(info, status) {
		p.log(&format!("could not answer the rename: {e}"));
	}
}

// ── running it ───────────────────────────────────────────────────────

pub struct Running {
	provider: Arc<Provider>,
	connection: Option<cf::Connection>,
	watcher: Option<crate::watch::Watcher>,
	poller: Option<JoinHandle<()>>,
	keep_local: bool,
}

/// Make `root` the area's sync root and start serving it.
pub fn start(root: &Path, remote: Arc<Mutex<dyn Remote + Send>>, opts: Options) -> Result<Running, String> {
	std::fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
	let root = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
	let (area, read_only) = {
		let r = remote.lock().expect("lock");
		(r.area(), r.read_only())
	};
	cf::register(&root, &area).map_err(|e| format!("could not make {} a sync root: {e}", root.display()))?;
	let provider = Arc::new(Provider {
		root_vol: vol(&root),
		root_chars: vol_raw(&root.to_string_lossy()).chars().count(),
		root: root.clone(),
		remote,
		read_only,
		state: Mutex::new(State::default()),
		self_ops: Mutex::new(HashSet::new()),
		pending: Mutex::new(BTreeMap::new()),
		stop: AtomicBool::new(false),
		verbose: opts.verbose,
		warned: Mutex::new(HashSet::new()),
	});
	provider.scan(&root, false);
	let connection = cf::connect(&root, cf::Callbacks { fetch_data: on_fetch_data, notify_delete: on_delete, notify_rename: on_rename }, Arc::as_ptr(&provider) as *const c_void).map_err(|e| format!("could not connect the sync root: {e}"))?;
	provider.sync_remote(true)?;
	let p = provider.clone();
	let watcher = crate::watch::Watcher::start(&root, move |rel| p.note(rel)).map_err(|e| format!("could not watch {}: {e}", root.display()))?;
	let poller = opts.poll.map(|every| {
		let p = provider.clone();
		std::thread::spawn(move || {
			let mut last = Instant::now();
			while !p.stop.load(Ordering::SeqCst) {
				std::thread::sleep(Duration::from_millis(250));
				p.sync_local(false);
				if last.elapsed() >= every {
					if let Err(e) = p.sync_remote(false) {
						p.warn_once("poll", &format!("the server: {e}"));
					}
					last = Instant::now();
				}
			}
		})
	});
	Ok(Running { provider, connection: Some(connection), watcher: Some(watcher), poller, keep_local: opts.keep_local })
}

impl Running {
	pub fn root(&self) -> &Path {
		&self.provider.root
	}

	/// The server's changes, now (tests; a poll does the same).
	pub fn sync_remote(&self) -> Result<(), String> {
		self.provider.sync_remote(true)
	}

	/// The member's changes, now — whether they settled or not.
	pub fn sync_local(&self) {
		self.provider.sync_local(true)
	}

	/// Send what is left, drop the plaintext (unless kept), disconnect.
	pub fn stop(mut self) {
		self.provider.stop.store(true, Ordering::SeqCst);
		if let Some(t) = self.poller.take() {
			let _ = t.join();
		}
		if let Some(w) = self.watcher.take() {
			w.stop();
		}
		self.provider.sync_local(true);
		if !self.keep_local {
			self.provider.dehydrate_all();
		}
		if let Some(c) = self.connection.take() {
			let _ = cf::disconnect(c);
		}
	}
}

impl Drop for Running {
	fn drop(&mut self) {
		if let Some(c) = self.connection.take() {
			let _ = cf::disconnect(c);
		}
	}
}
