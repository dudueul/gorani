// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The sync engine (commit 33d, docs/DESKTOP.md) — what every shell mounts.
//! Platform-neutral: inodes, names, reads, writes and the server, with no
//! FUSE, Cloud Files or File Provider in sight. `clients/linux` adapts it to
//! FUSE; the Windows and macOS shells will adapt the same calls.
//!
//! ```text
//! the tree   files/list (paged) is the state; the change feed only says
//!            "something changed since cursor N" — the journal is pruned
//!            after its retention, so it cannot rebuild a tree from 0
//! names      opened in the place their row names (O6); one that does not
//!            open is shown as "⚠ unverified ‹id›", never as what it claims
//! read       chunked: only the GC01 frames the range touches, by Range;
//!            whole: fetched once, opened, held in a bounded cache
//! evidence   every file checked against its uploader's signed hash when it
//!            is opened (chunked ones streamed through once): a mismatch or
//!            a bad record refuses the open, unverified evidence too unless
//!            the mount was started with --accept-unverified. Mounted
//!            read-only: an evidence item needs its intake record, which a
//!            file system cannot ask for (gorani-sync push --case does)
//! write      buffered in memory (≤ 48 MiB — no plaintext spool on disk),
//!            sealed and sent on close: a new file, or a new version after
//!            the one that was opened (base_version). If the file moved on
//!            meanwhile, the bytes become "name (conflict …)" beside it —
//!            nothing is overwritten, nothing is lost
//! ```
//!
//! Honest limits, for now: no local cache on disk (so nothing at rest to
//! encrypt — GL1 arrives with an offline cache), files above 48 MiB are
//! read-only through the mount (`gorani-sync push` sends them), and a
//! rename over an existing file trashes the old one rather than making the
//! moved bytes its new version.

use std::collections::{BTreeMap, HashMap};

use gorani_formats::chunked;
use gorani_formats::placed::Place;
use zeroize::Zeroizing;

use crate::api::{Client, UploadFields};
use crate::area::Area;
use crate::cases::HashCheck;
use crate::transfer::hex;
use crate::Error;

/// The root directory's inode (FUSE's FUSE_ROOT_ID).
pub const ROOT: u64 = 1;
/// The largest file the mount writes (the CLI's whole-upload limit).
pub const WRITE_LIMIT: u64 = 48 * 1024 * 1024;
/// Plaintext of whole files held in memory, at most.
const CACHE_LIMIT: usize = 256 * 1024 * 1024;

/// What a file-system call can answer — each shell maps it to its platform's
/// code (FUSE: an errno).
#[derive(Debug)]
pub enum FsError {
	NotFound,
	Exists,
	NotEmpty,
	NotDir,
	IsDir,
	/// Refused, and why (a sample, unverified evidence, the server's 403).
	Denied(String),
	/// The area does not take writes here (evidence, a read grant).
	ReadOnly(String),
	TooBig,
	Io(String),
}

impl FsError {
	/// The POSIX errno (Linux values).
	pub fn errno(&self) -> i32 {
		match self {
			FsError::NotFound => 2,
			FsError::Exists => 17,
			FsError::NotEmpty => 39,
			FsError::NotDir => 20,
			FsError::IsDir => 21,
			FsError::Denied(_) => 13,
			FsError::ReadOnly(_) => 30,
			FsError::TooBig => 27,
			FsError::Io(_) => 5,
		}
	}
}

impl std::fmt::Display for FsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			FsError::NotFound => write!(f, "no such file or folder"),
			FsError::Exists => write!(f, "already exists"),
			FsError::NotEmpty => write!(f, "the folder is not empty"),
			FsError::NotDir => write!(f, "not a folder"),
			FsError::IsDir => write!(f, "a folder"),
			FsError::Denied(why) | FsError::ReadOnly(why) | FsError::Io(why) => write!(f, "{why}"),
			FsError::TooBig => write!(f, "larger than the mount writes ({} MiB) — use gorani-sync push", WRITE_LIMIT >> 20),
		}
	}
}

impl From<Error> for FsError {
	fn from(e: Error) -> Self {
		match e {
			Error::Http(403, body) => FsError::Denied(format!("the server refused: {body}")),
			Error::Http(404, _) => FsError::NotFound,
			Error::Http(409, _) => FsError::Exists,
			other => FsError::Io(other.to_string()),
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
	Dir,
	File,
}

/// One entry of the tree.
#[derive(Debug, Clone)]
pub struct Node {
	pub ino: u64,
	pub parent: u64,
	/// As shown: sanitised, and unique within its folder.
	pub name: String,
	pub kind: Kind,
	/// The server's id (the root has none).
	pub id: Option<String>,
	pub size: u64,
	pub version: i64,
	/// Seconds since the epoch.
	pub modified: u64,
	pub sample: bool,
	/// Created here, not yet sent (it lives until its handle is closed).
	pub local: bool,
}

/// A content key and what is needed to read one version.
struct Meta {
	version: i64,
	key: Zeroizing<[u8; 32]>,
	chunk: Option<u64>,
	size: u64,
}

struct Handle {
	ino: u64,
	/// The bytes being written (in memory only), and whether they changed.
	buf: Option<Zeroizing<Vec<u8>>>,
	dirty: bool,
	/// The version this handle's bytes follow (None: a new file).
	base: Option<i64>,
}

pub struct Engine {
	client: Client,
	area: Area,
	nodes: BTreeMap<u64, Node>,
	by_id: HashMap<String, u64>,
	next_ino: u64,
	cursor: u64,
	listed: bool,
	meta: HashMap<String, Meta>,
	/// Whole files' plaintext, oldest first (bounded by CACHE_LIMIT).
	cache: Vec<(String, i64, Zeroizing<Vec<u8>>)>,
	/// Evidence verdicts, per (file, version): Ok, or why it is refused.
	verdicts: HashMap<(String, i64), Result<(), String>>,
	handles: HashMap<u64, Handle>,
	next_fh: u64,
	accept_unverified: bool,
	read_only: Option<String>,
}

impl Engine {
	/// An engine over `area`. A read-only reason makes every write answer
	/// it (evidence is always read-only here; a read grant can be told).
	pub fn new(client: Client, area: Area, accept_unverified: bool) -> Self {
		let read_grant = area.case.as_ref().and_then(|c| c.grant.as_ref()).is_some_and(|g| g.permission == "read");
		let read_only = if area.is_evidence() {
			Some("an evidence case is read-only through the mount — an item needs its intake record: gorani-sync push --case … --source … --collector … --method … --collected-at …".to_string())
		} else if read_grant {
			// (The server refuses the writes anyway; saying so at mount time
			// beats a refusal at every save.)
			Some("your grant on this case is read-only".to_string())
		} else {
			None
		};
		let mut nodes = BTreeMap::new();
		nodes.insert(ROOT, Node { ino: ROOT, parent: ROOT, name: String::new(), kind: Kind::Dir, id: None, size: 0, version: 0, modified: 0, sample: false, local: false });
		Self { client, area, nodes, by_id: HashMap::new(), next_ino: ROOT + 1, cursor: 0, listed: false, meta: HashMap::new(), cache: Vec::new(), verdicts: HashMap::new(), handles: HashMap::new(), next_fh: 1, accept_unverified, read_only }
	}

	pub fn area(&self) -> &Area {
		&self.area
	}

	pub fn read_only(&self) -> Option<&str> {
		self.read_only.as_deref()
	}

	pub fn client(&self) -> &Client {
		&self.client
	}

	/// The inode of a server id (the root's id is "").
	pub fn ino_of(&self, id: &str) -> Option<u64> {
		if id.is_empty() {
			return Some(ROOT);
		}
		self.by_id.get(id).copied().filter(|i| self.nodes.contains_key(i))
	}

	/// The server id of an inode ("" for the root).
	pub fn id_of(&self, ino: u64) -> Option<String> {
		if ino == ROOT {
			return Some(String::new());
		}
		self.nodes.get(&ino).and_then(|n| n.id.clone())
	}

	/// What the server has — the tree, by id, for a shell that keeps
	/// placeholders (replica.rs). Files created here and not yet sent are
	/// left out: they are the shell's, not the server's.
	pub fn items(&self) -> Vec<crate::replica::Item> {
		self.nodes
			.values()
			.filter(|n| n.ino != ROOT && !n.local)
			.map(|n| crate::replica::Item {
				id: n.id.clone().unwrap_or_default(),
				parent: self.id_of(n.parent).unwrap_or_default(),
				name: n.name.clone(),
				kind: n.kind,
				size: n.size,
				version: n.version,
				modified: n.modified,
				sample: n.sample,
				name_verified: !n.name.starts_with("⚠ unverified ‹"),
			})
			.collect()
	}

	/// `len` bytes of `id` from `offset`, but only of `version`: a shell
	/// that put a placeholder down for version N must not be handed N+1's
	/// bytes (its size and its hash are N's). The same rules as `read` — a
	/// sample is refused, evidence is checked before a byte is served.
	pub fn read_at(&mut self, id: &str, version: i64, offset: u64, len: u64) -> Result<Vec<u8>, FsError> {
		let (current, chunk, size) = {
			let m = self.meta_of(id)?;
			(m.version, m.chunk, m.size)
		};
		if current != version {
			return Err(FsError::Io(format!("changed on the server (version {current}, not {version}) — the placeholder is updated on the next refresh")));
		}
		if offset >= size || len == 0 {
			return Ok(Vec::new());
		}
		let len = len.min(size - offset);
		let key = Zeroizing::new(*self.meta[id].key);
		match chunk {
			Some(chunk) => {
				let span = chunked::frames_for(offset, len, size, chunk);
				let bytes = self.client.fetch(id, Some(version as u64), Some((span.start, span.end)))?;
				let plain = chunked::open_span(&key, &bytes, span, size, chunk).map_err(|_| FsError::Io("content (altered, reordered or cut short)".into()))?;
				let from = (offset - span.first * chunk) as usize;
				Ok(plain[from..(from + len as usize).min(plain.len())].to_vec())
			}
			None => {
				let plain = self.whole(id, version, &key)?;
				Ok(plain[offset as usize..(offset + len) as usize].to_vec())
			}
		}
	}

	/// After an upload made elsewhere (replica.rs): the tree is read again.
	pub fn relist_now(&mut self) -> Result<(), Error> {
		self.relist()
	}

	// ── the tree ──────────────────────────────────────────────────────

	/// Bring the tree up to date: the feed is asked whether anything
	/// changed since the cursor; if so (or the first time), the listing is
	/// read again. Returns whether it was.
	pub fn refresh(&mut self) -> Result<bool, Error> {
		let mut changed = !self.listed;
		loop {
			let (cursor, more, changes) = self.client.changes_page(self.cursor, 5000)?;
			changed |= !changes.is_empty();
			self.cursor = cursor;
			if !more {
				break;
			}
		}
		if changed {
			self.relist()?;
		}
		Ok(changed)
	}

	fn ino_for(&mut self, id: &str) -> u64 {
		if let Some(i) = self.by_id.get(id) {
			return *i;
		}
		let i = self.next_ino;
		self.next_ino += 1;
		self.by_id.insert(id.to_string(), i);
		i
	}

	fn relist(&mut self) -> Result<(), Error> {
		let mut files = Vec::new();
		let mut folders = Vec::new();
		let mut offset = 0u64;
		loop {
			let page = self.client.list(offset, 1000)?;
			if offset == 0 {
				folders = page["folders"].as_array().cloned().unwrap_or_default();
			}
			let got = page["files"].as_array().cloned().unwrap_or_default();
			offset += got.len() as u64;
			let done = got.is_empty() || offset >= page["total"].as_u64().unwrap_or(0);
			files.extend(got);
			if done {
				break;
			}
		}
		// Everything not created here and still unsent is rebuilt from the listing.
		let local: Vec<Node> = self.nodes.values().filter(|n| n.local).cloned().collect();
		let root = self.nodes[&ROOT].clone();
		let mut nodes: BTreeMap<u64, Node> = BTreeMap::new();
		nodes.insert(ROOT, root);
		let mut folder_parent: Vec<(u64, Option<String>)> = Vec::new();
		folders.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
		for f in &folders {
			let Some(id) = f["id"].as_str() else { continue };
			let ino = self.ino_for(id);
			let name = self.area.open(&Place::folder_name(&self.area.name, id), f["name"].as_str().unwrap_or_default());
			nodes.insert(ino, Node { ino, parent: ROOT, name: shown(name, id), kind: Kind::Dir, id: Some(id.into()), size: 0, version: 0, modified: iso_seconds(f["updatedAt"].as_str().unwrap_or_default()), sample: false, local: false });
			folder_parent.push((ino, f["parent"].as_str().map(str::to_string)));
		}
		for (ino, parent) in folder_parent {
			// A parent missing from the listing (trashed with its children
			// still live, or never there) puts the folder at the top.
			let p = parent.and_then(|p| self.by_id.get(&p).copied()).filter(|p| nodes.get(p).is_some_and(|n| n.kind == Kind::Dir) && *p != ino).unwrap_or(ROOT);
			nodes.get_mut(&ino).expect("inserted").parent = p;
		}
		// (A folder whose parents loop back on themselves goes to the top too.)
		let dirs: Vec<u64> = nodes.values().filter(|n| n.kind == Kind::Dir && n.ino != ROOT).map(|n| n.ino).collect();
		for d in dirs {
			let mut seen = vec![d];
			let mut at = nodes[&d].parent;
			while at != ROOT {
				if seen.contains(&at) {
					nodes.get_mut(&d).expect("dir").parent = ROOT;
					break;
				}
				seen.push(at);
				at = nodes[&at].parent;
			}
		}
		for f in &files {
			let Some(id) = f["id"].as_str() else { continue };
			let ino = self.ino_for(id);
			let parent = f["folder"].as_str().and_then(|p| self.by_id.get(p).copied()).filter(|p| nodes.get(p).is_some_and(|n| n.kind == Kind::Dir)).unwrap_or(ROOT);
			let name = self.area.open(&Place::file_name(&self.area.name, id), f["name"].as_str().unwrap_or_default());
			let version = f["version"].as_i64().unwrap_or(1);
			let size = f["size"].as_u64().or_else(|| f["size"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
			// The file's own modified date where its uploader kept it (39y), else
			// when it reached the server.
			let modified = f["modified"].as_str().and_then(|m| self.area.open_modified(id, version, m)).unwrap_or_else(|| iso_seconds(f["updatedAt"].as_str().unwrap_or_default()));
			nodes.insert(ino, Node { ino, parent, name: shown(name, id), kind: Kind::File, id: Some(id.into()), size, version, modified, sample: f["sample"].as_bool() == Some(true), local: false });
		}
		for n in local {
			if !nodes.contains_key(&n.ino) && nodes.contains_key(&n.parent) {
				nodes.insert(n.ino, n);
			}
		}
		// One name per folder: the first (by inode, i.e. first seen) keeps it,
		// a later namesake is shown with its id.
		let mut taken: HashMap<(u64, String), u64> = HashMap::new();
		for n in nodes.values_mut().filter(|n| n.ino != ROOT) {
			let key = (n.parent, n.name.clone());
			if taken.contains_key(&key) {
				let id = n.id.clone().unwrap_or_default();
				n.name = format!("{} ({})", n.name, &id[..id.len().min(8)]);
			}
			taken.insert((n.parent, n.name.clone()), n.ino);
		}
		// What changed version is read afresh.
		self.meta.retain(|id, m| self.by_id.get(id).and_then(|i| nodes.get(i)).is_some_and(|n| n.version == m.version));
		self.cache.retain(|(id, v, _)| self.by_id.get(id).and_then(|i| nodes.get(i)).is_some_and(|n| n.version == *v));
		self.nodes = nodes;
		self.listed = true;
		Ok(())
	}

	pub fn node(&self, ino: u64) -> Option<&Node> {
		self.nodes.get(&ino)
	}

	pub fn lookup(&self, parent: u64, name: &str) -> Option<&Node> {
		self.nodes.values().find(|n| n.parent == parent && n.ino != ROOT && n.name == name)
	}

	/// A folder's entries, by name.
	pub fn children(&self, ino: u64) -> Result<Vec<&Node>, FsError> {
		match self.nodes.get(&ino) {
			None => Err(FsError::NotFound),
			Some(n) if n.kind != Kind::Dir => Err(FsError::NotDir),
			Some(_) => {
				let mut out: Vec<&Node> = self.nodes.values().filter(|n| n.parent == ino && n.ino != ROOT).collect();
				out.sort_by(|a, b| a.name.cmp(&b.name));
				Ok(out)
			}
		}
	}

	/// The node at a `/`-separated path (the scripted shell and tests).
	pub fn resolve(&self, path: &str) -> Option<&Node> {
		let mut at = self.nodes.get(&ROOT)?;
		for part in path.split('/').filter(|p| !p.is_empty()) {
			at = self.lookup(at.ino, part)?;
		}
		Some(at)
	}

	// ── reading ───────────────────────────────────────────────────────

	fn meta_of(&mut self, id: &str) -> Result<&Meta, FsError> {
		if !self.meta.contains_key(id) {
			let keys = self.client.keys(&[id.to_string()])?;
			let k = &keys["keys"][id];
			let version = k["version"].as_i64().filter(|v| *v >= 1).ok_or(FsError::NotFound)?;
			// A malware sample never reaches a program raw (D8): not through a
			// mount either. Either mark counts — the flag or the sealed type.
			let typed = self.area.open(&Place::file_type(&self.area.name, id, version), k["type"].as_str().unwrap_or_default()).is_some_and(|t| t.starts_with("application/x-gorani-sample"));
			if k["sample"].as_bool() == Some(true) || typed {
				return Err(FsError::Denied("a malware sample is never readable raw — download it zipped from the web app (password: infected)".into()));
			}
			let key = Zeroizing::new(self.area.content_key(id, version, k["key"].as_str().unwrap_or_default())?);
			let size = k["size"].as_u64().ok_or(FsError::Io("the server did not say the file's size".into()))?;
			let chunk = k["chunk"].as_u64().filter(|c| *c > 0);
			if self.area.is_evidence() {
				self.verdict(id, version, &key, chunk, size, k["hash"].as_str())?;
			}
			self.meta.insert(id.to_string(), Meta { version, key, chunk, size });
		}
		Ok(&self.meta[id])
	}

	/// An evidence file is checked against its uploader's signed hash before
	/// a byte of it is served — whole, or streamed through once if chunked.
	fn verdict(&mut self, id: &str, version: i64, key: &[u8; 32], chunk: Option<u64>, size: u64, hash: Option<&str>) -> Result<(), FsError> {
		if let Some(v) = self.verdicts.get(&(id.to_string(), version)) {
			return v.clone().map_err(FsError::Denied);
		}
		let sha256 = match chunk {
			Some(chunk) => {
				use sha2::Digest;
				let mut h = sha2::Sha256::new();
				let frame = chunk + chunked::FRAME_OVERHEAD;
				let (count, sealed) = (chunked::frame_count(size, chunk), chunked::sealed_size(size, chunk));
				let per = ((32u64 << 20) / frame).max(1);
				let mut i = 0;
				while i < count {
					let n = per.min(count - i);
					let span = chunked::FrameSpan { first: i, last: i + n - 1, start: i * frame, end: ((i + n) * frame).min(sealed) };
					let bytes = self.client.fetch(id, Some(version as u64), Some((span.start, span.end)))?;
					h.update(&chunked::open_span(key, &bytes, span, size, chunk).map_err(|_| FsError::Io("content (altered, reordered or cut short)".into()))?[..]);
					i += n;
				}
				hex(&h.finalize())
			}
			None => {
				let plain = self.whole(id, version, key)?;
				hex(&<sha2::Sha256 as sha2::Digest>::digest(&plain[..]))
			}
		};
		let check = self.area.check_hash(id, version as u64, hash, &sha256, size).unwrap_or(HashCheck::Unsigned);
		let v = match &check {
			HashCheck::Verified { .. } => Ok(()),
			HashCheck::Untrusted { .. } | HashCheck::Unsigned if self.accept_unverified => Ok(()),
			_ => Err(check.describe()),
		};
		eprintln!("gorani-mount: {id} v{version}: {}", check.describe());
		self.verdicts.insert((id.to_string(), version), v.clone());
		v.map_err(FsError::Denied)
	}

	/// A whole (not chunked) version's plaintext, from the cache or fetched.
	fn whole(&mut self, id: &str, version: i64, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, FsError> {
		if let Some((_, _, p)) = self.cache.iter().find(|(i, v, _)| i == id && *v == version) {
			return Ok(p.clone());
		}
		let sealed = self.client.fetch(id, Some(version as u64), None)?;
		let plain = gorani_formats::formats::open_with(key, &sealed).map_err(|_| FsError::Io("content does not open with its key".into()))?;
		let mut held: usize = self.cache.iter().map(|(_, _, p)| p.len()).sum();
		while held + plain.len() > CACHE_LIMIT && !self.cache.is_empty() {
			held -= self.cache.remove(0).2.len();
		}
		if plain.len() <= CACHE_LIMIT {
			self.cache.push((id.to_string(), version, plain.clone()));
		}
		Ok(plain)
	}

	/// Open a file; `write` asks for its bytes to be editable (then held in
	/// memory, ≤ WRITE_LIMIT), `truncate` starts them empty. Returns a handle.
	pub fn open(&mut self, ino: u64, write: bool, truncate: bool) -> Result<u64, FsError> {
		let node = self.nodes.get(&ino).ok_or(FsError::NotFound)?.clone();
		if node.kind == Kind::Dir {
			return Err(FsError::IsDir);
		}
		let mut handle = Handle { ino, buf: None, dirty: false, base: (!node.local).then_some(node.version) };
		if write {
			if let Some(why) = &self.read_only {
				return Err(FsError::ReadOnly(why.clone()));
			}
			let id = node.id.clone().unwrap_or_default();
			let buf = if truncate || node.local {
				Zeroizing::new(Vec::new())
			} else if node.size > WRITE_LIMIT {
				return Err(FsError::TooBig);
			} else {
				Zeroizing::new(self.read_all(&id)?.to_vec())
			};
			handle.dirty = truncate && node.size > 0;
			handle.buf = Some(buf);
		} else if !node.local {
			// Evidence is judged here, at open — not at the first read.
			self.meta_of(node.id.as_deref().unwrap_or_default())?;
		}
		let fh = self.next_fh;
		self.next_fh += 1;
		self.handles.insert(fh, handle);
		if truncate {
			if let Some(n) = self.nodes.get_mut(&ino) {
				n.size = 0;
			}
		}
		Ok(fh)
	}

	fn read_all(&mut self, id: &str) -> Result<Zeroizing<Vec<u8>>, FsError> {
		let (version, chunk, size) = {
			let m = self.meta_of(id)?;
			(m.version, m.chunk, m.size)
		};
		let key = Zeroizing::new(*self.meta[id].key);
		match chunk {
			Some(c) => {
				let bytes = self.client.fetch(id, Some(version as u64), None)?;
				let plain = chunked::open_chunked(&key, &bytes, c).map_err(|_| FsError::Io("content (altered, reordered or cut short)".into()))?;
				if plain.len() as u64 != size {
					return Err(FsError::Io("content size does not match the file's size".into()));
				}
				Ok(plain)
			}
			None => self.whole(id, version, &key),
		}
	}

	/// `len` bytes from `offset` (fewer at the end of the file).
	pub fn read(&mut self, fh: u64, offset: u64, len: u32) -> Result<Vec<u8>, FsError> {
		let h = self.handles.get(&fh).ok_or(FsError::NotFound)?;
		if let Some(buf) = &h.buf {
			let from = (offset as usize).min(buf.len());
			return Ok(buf[from..(from + len as usize).min(buf.len())].to_vec());
		}
		let id = self.nodes.get(&h.ino).and_then(|n| n.id.clone()).ok_or(FsError::NotFound)?;
		let (version, chunk, size) = {
			let m = self.meta_of(&id)?;
			(m.version, m.chunk, m.size)
		};
		if offset >= size || len == 0 {
			return Ok(Vec::new());
		}
		let len = (len as u64).min(size - offset);
		let key = Zeroizing::new(*self.meta[&id].key);
		match chunk {
			Some(chunk) => {
				// Only the frames this range touches, each opened in its place.
				let span = chunked::frames_for(offset, len, size, chunk);
				let bytes = self.client.fetch(&id, Some(version as u64), Some((span.start, span.end)))?;
				let plain = chunked::open_span(&key, &bytes, span, size, chunk).map_err(|_| FsError::Io("content (altered, reordered or cut short)".into()))?;
				let from = (offset - span.first * chunk) as usize;
				Ok(plain[from..(from + len as usize).min(plain.len())].to_vec())
			}
			None => {
				let plain = self.whole(&id, version, &key)?;
				Ok(plain[offset as usize..(offset + len) as usize].to_vec())
			}
		}
	}

	// ── writing ───────────────────────────────────────────────────────

	fn writable(&self) -> Result<(), FsError> {
		match &self.read_only {
			Some(why) => Err(FsError::ReadOnly(why.clone())),
			None => Ok(()),
		}
	}

	fn check_new_name(&self, parent: u64, name: &str) -> Result<(), FsError> {
		match self.nodes.get(&parent) {
			None => return Err(FsError::NotFound),
			Some(p) if p.kind != Kind::Dir => return Err(FsError::NotDir),
			_ => {}
		}
		if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
			return Err(FsError::Denied("not a usable name".into()));
		}
		if self.lookup(parent, name).is_some() {
			return Err(FsError::Exists);
		}
		Ok(())
	}

	/// A new, empty file; it reaches the server when its handle is flushed.
	pub fn create(&mut self, parent: u64, name: &str) -> Result<(u64, u64), FsError> {
		self.writable()?;
		self.check_new_name(parent, name)?;
		let id = crate::new_item_id();
		let ino = self.ino_for(&id);
		self.nodes.insert(ino, Node { ino, parent, name: name.into(), kind: Kind::File, id: Some(id), size: 0, version: 0, modified: now_secs(), sample: false, local: true });
		let fh = self.next_fh;
		self.next_fh += 1;
		self.handles.insert(fh, Handle { ino, buf: Some(Zeroizing::new(Vec::new())), dirty: true, base: None });
		Ok((ino, fh))
	}

	pub fn write(&mut self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, FsError> {
		let h = self.handles.get_mut(&fh).ok_or(FsError::NotFound)?;
		let buf = h.buf.as_mut().ok_or(FsError::Denied("opened for reading".into()))?;
		let end = offset + data.len() as u64;
		if end > WRITE_LIMIT {
			return Err(FsError::TooBig);
		}
		if buf.len() < end as usize {
			buf.resize(end as usize, 0);
		}
		buf[offset as usize..end as usize].copy_from_slice(data);
		h.dirty = true;
		let (ino, size) = (h.ino, buf.len() as u64);
		if let Some(n) = self.nodes.get_mut(&ino) {
			n.size = size;
			n.modified = now_secs();
		}
		Ok(data.len() as u32)
	}

	/// Truncate or extend. With a handle, its buffer; without, the file is
	/// opened, changed and closed (a new version) in one step.
	pub fn set_size(&mut self, ino: u64, fh: Option<u64>, size: u64) -> Result<(), FsError> {
		if size > WRITE_LIMIT {
			return Err(FsError::TooBig);
		}
		let fh = match fh.filter(|f| self.handles.get(f).is_some_and(|h| h.buf.is_some())) {
			Some(f) => f,
			None => {
				let f = self.open(ino, true, size == 0)?;
				let r = self.set_size(ino, Some(f), size).and_then(|()| self.flush(f));
				self.release(f);
				return r;
			}
		};
		let h = self.handles.get_mut(&fh).expect("checked");
		let buf = h.buf.as_mut().expect("checked");
		if buf.len() as u64 != size {
			buf.resize(size as usize, 0);
			h.dirty = true;
		}
		if let Some(n) = self.nodes.get_mut(&ino) {
			n.size = size;
		}
		Ok(())
	}

	/// Send a handle's bytes if they changed: sealed under a fresh content
	/// key, as a new file or as the version after the one that was opened.
	pub fn flush(&mut self, fh: u64) -> Result<(), FsError> {
		let Some(h) = self.handles.get(&fh) else { return Ok(()) };
		if !h.dirty {
			return Ok(());
		}
		let (ino, base) = (h.ino, h.base);
		let plain = h.buf.clone().unwrap_or_default();
		let node = self.nodes.get(&ino).ok_or(FsError::NotFound)?.clone();
		let id = node.id.clone().unwrap_or_default();
		let sha256 = hex(&<sha2::Sha256 as sha2::Digest>::digest(&plain[..]));
		let ck = gorani_formats::formats::new_content_key();
		let sealed = gorani_formats::formats::seal_with(&gorani_formats::formats::import_content_key(&ck), &plain);
		let folder = self.nodes.get(&node.parent).and_then(|p| p.id.clone());
		match base {
			None => {
				// A copy of something already here (commit 39n): said, not
				// refused — the mount must keep what was put into it.
				if let Some(note) = self.area.duplicate_note(&self.client, &node.name, plain.len() as u64, &sha256) {
					eprintln!("gorani-mount: {note}");
				}
				let mut form = self.area.new_file_fields(&id, &node.name, &ck, plain.len() as u64, &sha256, None)?;
				if let Some(f) = &folder {
					form.push(("folder_id".into(), f.clone()));
				}
				// (When it was last written here — the mount's own mtime, 39y.)
				form.extend(self.area.modified_field(&id, 1, node.modified)?);
				self.client.upload_whole(&UploadFields { form }, &sealed)?;
				if let Some(n) = self.nodes.get_mut(&ino) {
					n.local = false;
					n.version = 1;
				}
				if let Some(h) = self.handles.get_mut(&fh) {
					h.base = Some(1);
				}
			}
			Some(base) => {
				let mut form = self.area.version_fields(&id, base, &ck, plain.len() as u64, &sha256)?;
				form.extend(self.area.modified_field(&id, base + 1, node.modified)?);
				match self.client.upload_version(&id, &UploadFields { form }, &sealed) {
					Ok(_) => {
						if let Some(n) = self.nodes.get_mut(&ino) {
							n.version = base + 1;
						}
						if let Some(h) = self.handles.get_mut(&fh) {
							h.base = Some(base + 1);
						}
						self.meta.remove(&id);
					}
					Err(Error::Http(409, _)) => {
						// Someone else saved first. Their version stays; these
						// bytes become a new file beside it — nothing is lost.
						let copy_id = crate::new_item_id();
						let copy_name = conflict_name(&node.name, now_secs());
						let ck2 = gorani_formats::formats::new_content_key();
						let sealed2 = gorani_formats::formats::seal_with(&gorani_formats::formats::import_content_key(&ck2), &plain);
						let mut form = self.area.new_file_fields(&copy_id, &copy_name, &ck2, plain.len() as u64, &sha256, None)?;
						if let Some(f) = &folder {
							form.push(("folder_id".into(), f.clone()));
						}
						form.extend(self.area.modified_field(&copy_id, 1, node.modified)?);
						self.client.upload_whole(&UploadFields { form }, &sealed2)?;
						eprintln!("gorani-mount: {} changed elsewhere while it was open — your bytes were saved as “{copy_name}”", node.name);
						if let Some(h) = self.handles.get_mut(&fh) {
							h.dirty = false;
						}
						self.relist()?;
						return Ok(());
					}
					Err(e) => return Err(e.into()),
				}
			}
		}
		if let Some(h) = self.handles.get_mut(&fh) {
			h.dirty = false;
		}
		Ok(())
	}

	/// The handle is gone (its last flush already ran). A file created here
	/// and never sent stays local only as long as a handle holds it.
	pub fn release(&mut self, fh: u64) {
		if let Some(h) = self.handles.remove(&fh) {
			let ino = h.ino;
			if self.nodes.get(&ino).is_some_and(|n| n.local) && !self.handles.values().any(|o| o.ino == ino) {
				self.nodes.remove(&ino);
			}
		}
	}

	/// A file to the Trash.
	pub fn unlink(&mut self, parent: u64, name: &str) -> Result<(), FsError> {
		self.writable()?;
		let n = self.lookup(parent, name).ok_or(FsError::NotFound)?.clone();
		if n.kind == Kind::Dir {
			return Err(FsError::IsDir);
		}
		if !n.local {
			self.client.trash_file(n.id.as_deref().unwrap_or_default())?;
		}
		self.nodes.remove(&n.ino);
		Ok(())
	}

	/// A new folder: its id chosen here, its name sealed into a place naming it.
	pub fn mkdir(&mut self, parent: u64, name: &str) -> Result<u64, FsError> {
		self.writable()?;
		self.check_new_name(parent, name)?;
		let id = crate::new_item_id();
		let sealed = self.area.seal(&Place::folder_name(&self.area.name, &id), name)?;
		let parent_id = self.nodes[&parent].id.clone();
		self.client.create_folder(&id, &sealed, parent_id.as_deref())?;
		let ino = self.ino_for(&id);
		self.nodes.insert(ino, Node { ino, parent, name: name.into(), kind: Kind::Dir, id: Some(id), size: 0, version: 0, modified: now_secs(), sample: false, local: false });
		Ok(ino)
	}

	pub fn rmdir(&mut self, parent: u64, name: &str) -> Result<(), FsError> {
		self.writable()?;
		let n = self.lookup(parent, name).ok_or(FsError::NotFound)?.clone();
		if n.kind != Kind::Dir {
			return Err(FsError::NotDir);
		}
		if self.nodes.values().any(|c| c.parent == n.ino && c.ino != ROOT) {
			return Err(FsError::NotEmpty);
		}
		self.client.trash_folder(n.id.as_deref().unwrap_or_default())?;
		self.nodes.remove(&n.ino);
		Ok(())
	}

	/// Rename and/or move. Onto an existing FILE, that file goes to the
	/// Trash first (what an editor's save-by-rename expects); onto a folder,
	/// refused.
	pub fn rename(&mut self, parent: u64, name: &str, new_parent: u64, new_name: &str) -> Result<(), FsError> {
		self.writable()?;
		let n = self.lookup(parent, name).ok_or(FsError::NotFound)?.clone();
		if let Some(t) = self.lookup(new_parent, new_name).cloned() {
			if t.ino == n.ino {
				return Ok(());
			}
			if t.kind == Kind::Dir || n.kind == Kind::Dir {
				return Err(FsError::Exists);
			}
			self.unlink(new_parent, new_name)?;
		}
		self.check_new_name(new_parent, new_name)?;
		if n.kind == Kind::Dir {
			let mut at = new_parent;
			while at != ROOT {
				if at == n.ino {
					return Err(FsError::Denied("a folder cannot move into itself".into()));
				}
				at = self.nodes[&at].parent;
			}
		}
		let id = n.id.clone().unwrap_or_default();
		let target = self.nodes[&new_parent].id.clone();
		if !n.local {
			match n.kind {
				Kind::File => {
					let sealed = self.area.seal(&Place::file_name(&self.area.name, &id), new_name)?;
					self.client.patch_file(&id, serde_json::json!({ "name": sealed, "folderId": target }))?;
				}
				Kind::Dir => {
					let sealed = self.area.seal(&Place::folder_name(&self.area.name, &id), new_name)?;
					self.client.patch_folder(&id, serde_json::json!({ "name": sealed, "parentId": target }))?;
				}
			}
		}
		let node = self.nodes.get_mut(&n.ino).expect("looked up");
		node.parent = new_parent;
		node.name = new_name.into();
		Ok(())
	}
}

/// A name as shown: what opened, made safe for a path — or, when it did
/// not open in its place, a marker with the id (never what it claims).
fn shown(opened: Option<String>, id: &str) -> String {
	match opened {
		Some(n) if !n.is_empty() && n != "." && n != ".." => n.replace('/', "∕").replace('\0', "␀"),
		Some(_) => format!("‹{id}›"),
		None => format!("⚠ unverified ‹{id}›"),
	}
}

/// "report.docx" → "report (conflict 2026-10-14 093005).docx".
pub(crate) fn conflict_name(name: &str, now: u64) -> String {
	let (days, secs) = ((now / 86_400) as i64, now % 86_400);
	let (y, m, d) = civil_from_days(days);
	let stamp = format!("{y:04}-{m:02}-{d:02} {:02}{:02}{:02}", secs / 3600, secs / 60 % 60, secs % 60);
	match name.rfind('.').filter(|i| *i > 0) {
		Some(i) => format!("{} (conflict {stamp}){}", &name[..i], &name[i..]),
		None => format!("{name} (conflict {stamp})"),
	}
}

fn now_secs() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Seconds since the epoch of `YYYY-MM-DDTHH:MM:SS…` (UTC); 0 if unreadable.
pub(crate) fn iso_seconds(s: &str) -> u64 {
	let n = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<i64>().ok());
	let (Some(y), Some(m), Some(d)) = (n(0, 4), n(5, 7), n(8, 10)) else { return 0 };
	let (h, mi, se) = (n(11, 13).unwrap_or(0), n(14, 16).unwrap_or(0), n(17, 19).unwrap_or(0));
	let days = days_from_civil(y, m, d);
	(days * 86_400 + h * 3600 + mi * 60 + se).max(0) as u64
}

/// Seconds since the epoch as ISO 8601 UTC — what the browser's
/// `Date.toISOString` writes, so a date sealed here reads the same there
/// (39y: a file's original modified date).
pub(crate) fn iso_of(secs: u64) -> String {
	let days = (secs / 86_400) as i64;
	let rest = secs % 86_400;
	let (y, m, d) = civil_from_days(days);
	format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

// Howard Hinnant's civil-calendar algorithms (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
	let y = if m <= 2 { y - 1 } else { y };
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
	let z = z + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	(yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn names_are_shown_safely_and_an_unopened_one_never_as_what_it_claims() {
		assert_eq!(shown(Some("notes.txt".into()), "abc"), "notes.txt");
		assert_eq!(shown(Some("a/b".into()), "abc"), "a∕b", "no slash reaches a path");
		assert_eq!(shown(Some("..".into()), "abc"), "‹abc›");
		assert_eq!(shown(None, "abc"), "⚠ unverified ‹abc›");
	}

	#[test]
	fn a_conflict_copy_keeps_the_extension_and_says_when() {
		let t = iso_seconds("2026-10-14T09:30:05.250Z");
		assert_eq!(conflict_name("report.docx", t), "report (conflict 2026-10-14 093005).docx");
		assert_eq!(conflict_name("Makefile", t), "Makefile (conflict 2026-10-14 093005)");
		assert_eq!(conflict_name(".bashrc", t), ".bashrc (conflict 2026-10-14 093005)");
		assert_eq!(iso_seconds("1970-01-01T00:00:00Z"), 0);
		assert_eq!(iso_seconds("2000-03-01T00:00:00Z"), 951_868_800);
		assert_eq!(iso_seconds("garbage"), 0);
	}

	#[test]
	fn a_modified_date_is_written_as_the_browser_writes_it_and_reads_back() {
		// (39y: a desktop seals its mtime in the format Date.toISOString
		// writes, so either side opens what the other sealed.)
		assert_eq!(iso_of(0), "1970-01-01T00:00:00.000Z");
		assert_eq!(iso_of(951_868_800), "2000-03-01T00:00:00.000Z");
		assert_eq!(iso_of(1_760_000_000), "2025-10-09T08:53:20.000Z");
		for secs in [1, 59, 86_399, 86_400, 951_868_799, 1_760_000_000, 4_102_444_800] {
			assert_eq!(iso_seconds(&iso_of(secs)), secs, "{secs} round-trips");
		}
	}
}
