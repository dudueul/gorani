// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Large files from the command line (D12 in the client, commit 33b,
//! docs/DESKTOP.md) — the same contract the browser speaks
//! (docs/LARGE-FILES.md), from a disk instead of a tab:
//!
//! ```text
//! push  SHA-256 in one streamed pass → plan (chunk_for(size)) → each GC01 frame read,
//!       sealed and PUT (three tries for the network's sake, none for a refusal),
//!       journalled → complete → the journal entry goes
//! pull  frame windows (≈ 32 MiB) by Range → each frame opened in its place →
//!       written to <out>.part, hashed → size checked → renamed onto <out>
//! ```
//!
//! Memory is one window, whatever the file. The journal (one JSON file per
//! unfinished upload, next to the profile) holds only what the server
//! already has — ids, the object key, sealed fields — keyed by a hash of
//! the member, the area (their own, or a case — commit 33c), the file's
//! name, size, modified time and SHA-256: no file name in the clear, and a
//! different file, or the same file bound for another area, never matches.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::api::{Client, UploadFields};
use crate::Error;

/// One window of ciphertext fetched (and held) at a time when pulling.
const WINDOW: u64 = 32 * 1024 * 1024;

pub fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file in one streamed pass (8 MiB reads), and its length.
pub fn sha256_file(path: &Path) -> Result<(String, u64), Error> {
	let mut f = std::fs::File::open(path)?;
	let mut h = Sha256::new();
	let mut buf = vec![0u8; 8 * 1024 * 1024];
	let mut size = 0u64;
	loop {
		let n = f.read(&mut buf)?;
		if n == 0 {
			break;
		}
		h.update(&buf[..n]);
		size += n as u64;
	}
	Ok((hex(&h.finalize()), size))
}

/// An unfinished upload, as the journal keeps it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadRecord {
	pub member: String,
	/// Where it is going: `<member>` or `case:<id>` (commit 33c).
	#[serde(default)]
	pub area: String,
	pub file_id: String,
	pub upload_id: String,
	pub object_key: String,
	pub chunk: u64,
	pub size: u64,
	/// The completion's form fields (every one sealed or public).
	pub fields: Vec<(String, String)>,
	pub parts: Vec<(u64, String)>,
	pub started_at: u64,
}

/// The on-disk journal of unfinished uploads.
pub struct Journal {
	dir: PathBuf,
}

impl Journal {
	pub fn new(dir: PathBuf) -> Self {
		Self { dir }
	}

	/// The key for one file: no name in the clear, and only the same bytes,
	/// bound for the same area, match.
	pub fn key_for(member: &str, area: &str, name: &str, size: u64, modified: u64, sha256: &str) -> String {
		let mut h = Sha256::new();
		for part in ["gorani-upload-v2", member, area, name, &size.to_string(), &modified.to_string(), sha256] {
			h.update((part.len() as u32).to_be_bytes());
			h.update(part.as_bytes());
		}
		hex(&h.finalize())
	}

	fn path(&self, key: &str) -> PathBuf {
		self.dir.join(format!("{key}.json"))
	}

	pub fn get(&self, key: &str) -> Option<UploadRecord> {
		std::fs::read(self.path(key)).ok().and_then(|b| serde_json::from_slice(&b).ok())
	}

	pub fn put(&self, key: &str, rec: &UploadRecord) -> Result<(), Error> {
		std::fs::create_dir_all(&self.dir)?;
		// Write-then-rename: a crash mid-write leaves the previous record, never half of one.
		let tmp = self.dir.join(format!("{key}.json.tmp"));
		std::fs::write(&tmp, serde_json::to_vec(rec).map_err(|e| Error::Config(e.to_string()))?)?;
		std::fs::rename(&tmp, self.path(key))?;
		Ok(())
	}

	pub fn delete(&self, key: &str) {
		let _ = std::fs::remove_file(self.path(key));
	}
}

/// Push a file as GC01 frames (D12), journalled so it can resume.
/// `resume`: the record of the same file's stopped upload — the frames
/// from its first missing part on are sealed with the SAME key and sent
/// under the SAME upload. Fields carrying `base_version` make it a new
/// VERSION of `file_id` (commit 39a). `expect`: the SHA-256 the fields
/// sign — the bytes are hashed again as they are sealed, and a file that
/// changed since it was hashed is never completed (its signature would
/// vouch for other bytes). Returns the completed file row.
#[allow(clippy::too_many_arguments)]
pub fn push_frames(client: &Client, journal: &Journal, journal_key: &str, path: &Path, key: &[u8; 32], member: &str, file_id: &str, chunk: u64, size: u64, fields: Vec<(String, String)>, resume: Option<UploadRecord>, expect: Option<&str>, mut progress: impl FnMut(u64, u64)) -> Result<serde_json::Value, Error> {
	let area = client.area().to_string();
	let count = gorani_formats::chunked::frame_count(size, chunk);
	let existing = fields.iter().any(|(k, _)| k == "base_version");
	let mut rec = match resume {
		Some(r) => r,
		None => {
			let (upload_id, object_key, parts) = client.upload_start_for(size, chunk, file_id, existing)?;
			if parts != count {
				return Err(Error::Config(format!("the server planned {parts} parts for {count} frames")));
			}
			let r = UploadRecord { member: member.into(), area, file_id: file_id.into(), upload_id, object_key, chunk, size, fields, parts: vec![], started_at: now_secs() };
			journal.put(journal_key, &r)?;
			r
		}
	};
	let mut f = std::fs::File::open(path)?;
	let first = rec.parts.len() as u64;
	let mut h = expect.map(|_| <sha2::Sha256 as sha2::Digest>::new());
	let mut buf = vec![0u8; chunk as usize];
	if let Some(h) = h.as_mut() {
		// (A resumed upload hashes the frames already sent too, from disk.)
		for i in 0..first {
			let want = if i == count - 1 { (size - i * chunk) as usize } else { chunk as usize };
			f.read_exact(&mut buf[..want])?;
			sha2::Digest::update(h, &buf[..want]);
		}
	}
	{
		use std::io::Seek;
		f.seek(std::io::SeekFrom::Start(first * chunk))?;
	}
	for i in first..count {
		let want = if i == count - 1 { (size - i * chunk) as usize } else { chunk as usize };
		f.read_exact(&mut buf[..want])?;
		if let Some(h) = h.as_mut() {
			sha2::Digest::update(h, &buf[..want]);
		}
		let frame = gorani_formats::chunked::seal_chunk(key, &buf[..want], i, i == count - 1);
		test_fault(i)?;
		let etag = client.upload_part(&rec.upload_id, &rec.object_key, i + 1, &frame)?;
		rec.parts.push((i + 1, etag));
		journal.put(journal_key, &rec)?;
		progress(i + 1, count);
	}
	if let (Some(h), Some(want)) = (h, expect) {
		if hex(&sha2::Digest::finalize(h)) != want {
			journal.delete(journal_key);
			return Err(Error::Config("the file changed while it was being sent — nothing was completed; send it again".into()));
		}
	}
	let parts: Vec<serde_json::Value> = rec.parts.iter().map(|(n, e)| serde_json::json!({ "partNumber": n, "etag": e })).collect();
	let mut form: Vec<(String, String)> = rec.fields.iter().filter(|(k, _)| k != "file_id").cloned().collect();
	form.push(("key".into(), rec.object_key.clone()));
	form.push(("parts".into(), serde_json::Value::Array(parts).to_string()));
	let row = client.upload_complete(&rec.upload_id, &UploadFields { form })?;
	journal.delete(journal_key);
	Ok(row)
}

/// (Debug builds only) Stop after this many parts — how the live test
/// proves a resume without pulling the network cable.
fn test_fault(i: u64) -> Result<(), Error> {
	#[cfg(debug_assertions)]
	if let Some(n) = std::env::var("GORANI_TEST_STOP_AFTER_PARTS").ok().and_then(|v| v.parse::<u64>().ok()) {
		if i == n {
			return Err(Error::Config(format!("test: stopped after {n} parts")));
		}
	}
	let _ = i;
	Ok(())
}

fn now_secs() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Pull a chunked version to `out`, a window of frames at a time: each
/// frame opened in its place (a reordered, altered or truncated object
/// fails), the plaintext written to `<out>.part` and hashed, the size
/// checked, then `judge` asked about the SHA-256 (the uploader's signed
/// hash — commit 33c), and only then renamed onto `out`. Returns the
/// plaintext's SHA-256. On any refusal, `<out>.part` is removed.
#[allow(clippy::too_many_arguments)]
pub fn pull_frames(client: &Client, id: &str, version: u64, key: &[u8; 32], chunk: u64, size: u64, out: &Path, judge: impl FnOnce(&str) -> Result<(), Error>) -> Result<String, Error> {
	let count = gorani_formats::chunked::frame_count(size, chunk);
	let frame = chunk + gorani_formats::chunked::FRAME_OVERHEAD;
	let sealed = gorani_formats::chunked::sealed_size(size, chunk);
	let per = (WINDOW / frame).max(1);
	let part = out.with_extension(format!("{}part", out.extension().map(|e| format!("{}.", e.to_string_lossy())).unwrap_or_default()));
	let mut w = std::io::BufWriter::new(std::fs::File::create(&part)?);
	let mut h = Sha256::new();
	let mut written = 0u64;
	let result = (|| -> Result<(), Error> {
		let mut i = 0;
		while i < count {
			let n = per.min(count - i);
			let (start, end) = (i * frame, ((i + n) * frame).min(sealed));
			let bytes = client.fetch(id, Some(version), Some((start, end)))?;
			if bytes.len() as u64 != end - start {
				return Err(Error::Open("the server answered a different span than asked"));
			}
			for k in 0..n {
				let at = (k * frame) as usize;
				let to = (((k + 1) * frame) as usize).min(bytes.len());
				let idx = i + k;
				let plain = gorani_formats::chunked::open_chunk(key, &bytes[at..to], idx, idx == count - 1).map_err(|_| Error::Open("content (altered, reordered or cut short)"))?;
				h.update(&plain[..]);
				w.write_all(&plain)?;
				written += plain.len() as u64;
			}
			i += n;
		}
		w.flush()?;
		if written != size {
			return Err(Error::Open("content size does not match the file's size"));
		}
		Ok(())
	})();
	let sha256 = hex(&h.finalize());
	drop(w);
	if let Err(e) = result.and_then(|()| judge(&sha256)) {
		let _ = std::fs::remove_file(&part);
		return Err(e);
	}
	std::fs::rename(&part, out)?;
	Ok(sha256)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_journal_key_names_no_file_and_only_the_same_bytes_match() {
		let k = Journal::key_for("jinu", "jinu", "disk.E01", 10, 1_700_000_000, "ab");
		assert_eq!(k.len(), 64);
		assert!(!k.contains("disk"), "no name in the clear");
		assert_ne!(k, Journal::key_for("jinu", "jinu", "disk.E01", 10, 1_700_000_000, "ac"), "other bytes, another key");
		assert_ne!(k, Journal::key_for("jinu", "case:ir-7", "disk.E01", 10, 1_700_000_000, "ab"), "the same file bound for a case: another upload");
		assert_ne!(k, Journal::key_for("jinu", "jinu", "disk.E0", 110, 1_700_000_000, "ab"), "length-prefixed: fields cannot slide");
	}

	#[test]
	fn the_journal_round_trips_and_forgets() {
		let dir = std::env::temp_dir().join(format!("gorani-journal-{}", std::process::id()));
		let j = Journal::new(dir.clone());
		let rec = UploadRecord { member: "jinu".into(), area: "jinu".into(), file_id: "f".into(), upload_id: "u".into(), object_key: "files/jinu/f/u-1".into(), chunk: 8, size: 20, fields: vec![("name".into(), "GV04:x".into())], parts: vec![(1, "\"e1\"".into())], started_at: 1 };
		j.put("k", &rec).unwrap();
		assert_eq!(j.get("k").unwrap().parts, rec.parts);
		j.delete("k");
		assert!(j.get("k").is_none());
		let _ = std::fs::remove_dir_all(dir);
	}
}
