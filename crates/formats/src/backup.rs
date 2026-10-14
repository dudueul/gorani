// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's backup design (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The `.gbak` backup container (GB2): one encrypted file per backup, whose
//! file key exists only in the owner's downloaded key file (sealed into the
//! header to the backup PUBLIC key — the server can write backups and never
//! open them).
//!
//! ```text
//! "GBAK2\n" ‖ headerLen (4 BE) ‖ header JSON ‖ segment 0 ‖ segment 1 ‖ … ‖ final segment
//! header JSON = { format: "gorani-backup", v: 2, stamp, kind, keyId, wrapped, seg, alg }
//! wrapped     = GV03 text: the 32-byte file key sealed to the backup public key
//! H           = SHA-256(everything before segment 0: magic ‖ headerLen ‖ header)
//! segment i   = nonce (12: 0x00000000 ‖ i, u64 BE) ‖ AES-256-GCM(fileKey, slice, AAD_i) ‖ tag (16)
//! AAD_i       = "GBAK2" ‖ '2' ‖ 'A' ‖ final (1) ‖ i (8 BE) ‖ H (32)
//! ```
//!
//! The plaintext stream inside the segments is the entry sequence the job
//! wrote: per entry, `jsonLen (4 BE) ‖ row JSON ‖ objectLen (8 BE) ‖ object
//! bytes` — the rows are metadata the server already holds; the objects are
//! the SEALED originals (GV02/GC1), so the backup is sealed twice over and
//! the restore replays them verbatim.
//!
//! Counter nonces under one file key can never repeat; segment numbers and
//! finality are authenticated, so segments cannot be reordered, dropped,
//! duplicated or the file cut short without opening failing.
//!
//! # What GB2 fixed (commit 25, docs/SECURITY-REVIEW.md › O7)
//!
//! GB1 authenticated the segments but not the HEADER — and the header is
//! what a restore believes: `stamp` (which night), `kind`. Anyone holding the
//! bytes could relabel last month's backup as last night's, and an operator
//! restoring "yesterday" would roll the store back a month without a single
//! check failing. GB2 hashes everything before the first segment into every
//! segment's AAD: change one header byte and nothing opens.
//!
//! Two reader gaps closed with it: a container cut down to its header (zero
//! segments) parsed as a valid EMPTY backup — the writer always emits a
//! final segment, so the reader now requires one; and the stored nonce's
//! first four bytes were never compared (the reader rebuilt the nonce from
//! the counter), so they were free for anyone to change — every byte of a
//! container is now either authenticated or checked.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

pub const MAGIC: &[u8; 6] = b"GBAK2\n";
pub const SEG_SIZE: usize = 1024 * 1024;
const TAG_LEN: usize = 16;

/// A fresh per-backup file key (wiped when dropped).
pub type FileKey = Zeroizing<[u8; 32]>;

pub fn new_file_key() -> FileKey {
	let mut k = Zeroizing::new([0u8; 32]);
	OsRng.fill_bytes(k.as_mut());
	k
}

fn aad(seg: u64, final_seg: bool, header_hash: &[u8; 32]) -> [u8; 48] {
	let mut a = [0u8; 48];
	a[..5].copy_from_slice(b"GBAK2");
	a[5] = b'2'; // container version, inside the AAD like the magic
	a[6] = b'A'; // domain separator: the segment stream (not the header)
	a[7] = final_seg as u8;
	a[8..16].copy_from_slice(&seg.to_be_bytes());
	a[16..48].copy_from_slice(header_hash);
	a
}

fn nonce_bytes(seg: u64) -> [u8; 12] {
	let mut n = [0u8; 12];
	n[4..12].copy_from_slice(&seg.to_be_bytes());
	n
}

fn aes(key: &[u8; 32]) -> Aes256Gcm {
	Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

/// Streaming writer: `start` emits the container's prefix (magic, header
/// length, header) and remembers its hash; `write` turns plaintext into
/// segments; `finish` emits the last one. The writer owns the prefix on
/// purpose — the hash it binds is of exactly the bytes it wrote.
pub struct BackupWriter {
	key: FileKey,
	header_hash: [u8; 32],
	seg: u64,
	buf: Vec<u8>,
	/// Plaintext bytes already emitted (segments before the current buffer).
	pub written: u64,
}

impl BackupWriter {
	/// Begin a container: the prefix goes into `out`. The header JSON carries
	/// the sealed file key (which only the owner's key file can open).
	pub fn start(key: FileKey, header_json: &[u8], out: &mut Vec<u8>) -> Self {
		let at = out.len();
		out.extend_from_slice(MAGIC);
		out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
		out.extend_from_slice(header_json);
		let header_hash: [u8; 32] = Sha256::digest(&out[at..]).into();
		Self { key, header_hash, seg: 0, buf: Vec::new(), written: 0 }
	}

	/// Push plaintext in; GB2 segment bytes come out.
	pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
		self.buf.extend_from_slice(data);
		while self.buf.len() >= SEG_SIZE {
			let slice: Vec<u8> = self.buf.drain(..SEG_SIZE).collect();
			self.emit(&slice, false, out);
		}
	}

	/// Flush the remainder as the final segment (an empty stream still
	/// emits one empty final segment — the container is never ambiguous).
	pub fn finish(&mut self, out: &mut Vec<u8>) {
		let slice: Vec<u8> = std::mem::take(&mut self.buf);
		self.emit(&slice, true, out);
	}

	fn emit(&mut self, slice: &[u8], final_seg: bool, out: &mut Vec<u8>) {
		// The counter nonce rides IN the segment (the reader verifies all of it).
		let n = nonce_bytes(self.seg);
		let ct = aes(&self.key)
			.encrypt(&Nonce::from(n), Payload { msg: slice, aad: &aad(self.seg, final_seg, &self.header_hash) })
			.expect("AES-GCM encrypt");
		out.extend_from_slice(&n);
		out.extend_from_slice(&ct);
		self.seg += 1;
		self.written += slice.len() as u64;
	}
}

/// One decrypted entry from a parsed backup: the row JSON and the sealed
/// object bytes that follow it.
pub struct BackupEntry {
	pub json: Vec<u8>,
	pub object: Vec<u8>,
}

/// Parse a complete .gbak: verify the container, decrypt every segment,
/// walk the entry stream. Tampering anywhere fails (GCM) — including
/// reordered or cut-off segments (the AAD binds positions and finality).
pub struct BackupReader<'a> {
	key: &'a FileKey,
	bytes: &'a [u8],
	header: Vec<u8>,
	header_hash: [u8; 32],
}

impl<'a> BackupReader<'a> {
	pub fn parse(key: &'a FileKey, bytes: &'a [u8]) -> Result<(Self, usize), Error> {
		if bytes.len() < MAGIC.len() + 4 || &bytes[..MAGIC.len()] != MAGIC {
			return Err(Error::Format("not a gorani backup"));
		}
		let len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
		let at = MAGIC.len() + 4;
		if bytes.len() < at + len {
			return Err(Error::Format("backup header is cut short"));
		}
		let header = bytes[at..at + len].to_vec();
		// The header is trusted only once a segment opens under its hash —
		// callers read it here, but nothing in it is proven until entries().
		let header_hash: [u8; 32] = Sha256::digest(&bytes[..at + len]).into();
		Ok((Self { key, bytes, header, header_hash }, at + len))
	}

	/// The header bytes. Unproven until `entries` succeeds (its hash is in
	/// every segment's AAD) — read it, but act on it only after that.
	pub fn header(&self) -> &[u8] {
		&self.header
	}

	/// Decrypt the segment stream into the plaintext entry sequence.
	pub fn entries(&self) -> Result<Vec<BackupEntry>, Error> {
		let at = MAGIC.len() + 4 + self.header.len();
		let stream = self.decrypt_stream(&self.bytes[at..])?;
		let mut entries = Vec::new();
		let mut cursor = 0usize;
		while cursor + 4 <= stream.len() {
			let json_len = u32::from_be_bytes([stream[cursor], stream[cursor + 1], stream[cursor + 2], stream[cursor + 3]]) as usize;
			cursor += 4;
			if cursor + json_len > stream.len() {
				return Err(Error::Format("backup entry JSON is cut short"));
			}
			let json = stream[cursor..cursor + json_len].to_vec();
			cursor += json_len;
			if cursor + 8 > stream.len() {
				return Err(Error::Format("backup entry object length is cut short"));
			}
			let obj_len = u64::from_be_bytes(stream[cursor..cursor + 8].try_into().expect("8 bytes")) as usize;
			cursor += 8;
			if cursor + obj_len > stream.len() {
				return Err(Error::Format("backup entry object is cut short"));
			}
			let object = stream[cursor..cursor + obj_len].to_vec();
			cursor += obj_len;
			entries.push(BackupEntry { json, object });
		}
		if cursor != stream.len() {
			return Err(Error::Format("backup stream has trailing bytes"));
		}
		Ok(entries)
	}

	/// Decrypt the segment chain: each 12+slice+16 block per the counter.
	fn decrypt_stream(&self, segments: &[u8]) -> Result<Vec<u8>, Error> {
		// A container cut down to its header is not an empty backup: the
		// writer always emits a final segment (GB1 accepted zero — O7).
		if segments.is_empty() {
			return Err(Error::Format("backup has no segments (cut short after the header)"));
		}
		let mut out = Vec::with_capacity(segments.len());
		let mut seg: u64 = 0;
		let mut at = 0usize;
		while at < segments.len() {
			if at + 12 > segments.len() {
				return Err(Error::Format("backup segment nonce is cut short"));
			}
			// All twelve stored bytes must be the counter nonce (GB1 compared
			// the last eight and rebuilt the rest, leaving four bytes free to
			// change). The segment number in it doubles as the reorder check.
			if segments[at..at + 12] != nonce_bytes(seg) {
				return Err(Error::Format("backup segments are out of order (or a nonce was altered)"));
			}
			// Segment length: SEG_SIZE payload until the final one, which is
			// whatever remains (>= 0 + tag). We discover finality by length
			// relative to the stream end: the last segment's tag ends the file.
			let remaining = segments.len() - at;
			// On-disk segment = nonce(12) ‖ payload ‖ tag(16). Full segments
			// carry exactly SEG_SIZE payload; the final one is the remainder.
			let (payload_len, final_seg) = if remaining <= 12 + SEG_SIZE + TAG_LEN {
				(remaining - 12 - TAG_LEN, true)
			} else {
				(SEG_SIZE, false)
			};
			if at + 12 + payload_len + TAG_LEN > segments.len() {
				return Err(Error::Format("backup segment is cut short"));
			}
			let plain = aes(self.key)
				.decrypt(
					&Nonce::from(nonce_bytes(seg)),
					// aes-gcm wants ciphertext ‖ tag — the tag trails the payload.
					Payload {
						msg: &segments[at + 12..at + 12 + payload_len + TAG_LEN],
						aad: &aad(seg, final_seg, &self.header_hash),
					},
				)
				.map_err(|_e| {
					#[cfg(test)]
					eprintln!("decrypt seg {seg} failed: payload_len {payload_len} final {final_seg} remaining {remaining}");
					Error::Open("wrong backup key, or the backup (header or segments) was altered")
				})?;
			out.extend_from_slice(&plain);
			at += 12 + payload_len + TAG_LEN;
			seg += 1;
			if final_seg && at != segments.len() {
				return Err(Error::Format("backup has bytes after the final segment"));
			}
		}
		Ok(out)
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	use crate::formats::{self, VaultPrivateKey, VaultPublicKey};

	fn keypair() -> (Vec<u8>, VaultPublicKey) {
		let (bundle, public) = crate::unlock::generate_hybrid().unwrap();
		(bundle.to_vec(), public)
	}

	#[test]
	fn round_trip_and_tamper() {
		let (bundle, public) = keypair();
		let file_key = new_file_key();
		let wrapped = formats::seal_text(&public, base64_of(file_key.as_ref()).as_str());
		let header = format!(r#"{{"format":"gorani-backup","v":2,"stamp":"20261014T020000Z","wrapped":"{wrapped}"}}"#);

		let mut out = vec![];
		let mut w = BackupWriter::start(file_key.clone(), header.as_bytes(), &mut out);
		let entries: Vec<Vec<u8>> = vec![vec![b'a'; 100], vec![b'b'; SEG_SIZE + 50], vec![b'c'; 3]];
		for e in &entries {
			w.write(&(e.len() as u32).to_be_bytes(), &mut out);
			w.write(e, &mut out);
			w.write(&0u64.to_be_bytes(), &mut out);
		}
		w.finish(&mut out);

		// Open with the file key (as the owner's key file would, after
		// unwrapping it from `wrapped` with the backup private half).
		let (reader, _) = BackupReader::parse(&file_key, &out).unwrap();
		let parsed: serde_json::Value = serde_json::from_slice(reader.header()).unwrap();
		assert_eq!(parsed["format"], "gorani-backup");
		let got = reader.entries().unwrap();
		assert_eq!(got.len(), 3);
		assert_eq!(got[0].json, vec![b'a'; 100], "the row JSON rides in the stream");
		assert_eq!(got[1].json.len(), SEG_SIZE + 50);
		assert_eq!(got[2].json, vec![b'c'; 3]);
		assert!(got.iter().all(|e| e.object.is_empty()), "this test wrote rows only");

		// The file key must be unwrappable from `wrapped` by the private half.
		let priv_key = VaultPrivateKey::from_bytes(&bundle).unwrap();
		let reopened = formats::open_text(&priv_key, &parsed["wrapped"].as_str().unwrap()).unwrap();
		assert_eq!(reopened.as_str(), base64_of(file_key.as_ref()).as_str());

		// Tamper: any changed byte fails.
		let mut bad = out.clone();
		let mid = bad.len() / 2;
		bad[mid] ^= 0x40;
		assert!(BackupReader::parse(&file_key, &bad).and_then(|(_, _)| Ok(())).is_err() || {
			match BackupReader::parse(&file_key, &bad) {
				Ok((r, _)) => r.entries().is_err(),
				Err(_) => true,
			}
		});
		// Truncation fails.
		assert!(BackupReader::parse(&file_key, &out[..out.len() - 40])
			.map(|(r, _)| r.entries().is_err())
			.unwrap_or(true));
		// Reordering the two halves fails (counter nonces + finality).
		let (a, b) = out.split_at(out.len() / 2);
		let swapped = [b, a].concat();
		assert!(BackupReader::parse(&file_key, &swapped)
			.map(|(r, _)| r.entries().is_err())
			.unwrap_or(true));

		// O7 (GB2): the header is authenticated. Relabel the stamp — same
		// length, still valid JSON — and nothing opens.
		let mut relabelled = out.clone();
		let at = relabelled.windows(16).position(|w| w == b"20261014T020000Z").expect("the stamp is in the header");
		relabelled[at..at + 16].copy_from_slice(b"20261113T020000Z");
		let (r, _) = BackupReader::parse(&file_key, &relabelled).unwrap();
		assert!(r.entries().is_err(), "a relabelled header fails every segment");
		// …a container cut down to its header is not an empty backup…
		let header_end = MAGIC.len() + 4 + header.len();
		let (r, _) = BackupReader::parse(&file_key, &out[..header_end]).unwrap();
		assert!(r.entries().is_err(), "zero segments is a truncation, not an empty backup");
		// …and every nonce byte is checked, not just the counter.
		let mut nonce_bit = out.clone();
		nonce_bit[header_end] ^= 0x01;
		let (r, _) = BackupReader::parse(&file_key, &nonce_bit).unwrap();
		assert!(r.entries().is_err(), "the nonce's zero prefix is checked");
		// An honestly EMPTY backup (no entries) still round-trips: one empty final segment.
		let mut empty = vec![];
		let mut w = BackupWriter::start(file_key.clone(), header.as_bytes(), &mut empty);
		w.finish(&mut empty);
		let (r, _) = BackupReader::parse(&file_key, &empty).unwrap();
		assert!(r.entries().unwrap().is_empty());
	}

	fn base64_of(b: &[u8]) -> String {
		use base64::Engine;
		base64::engine::general_purpose::STANDARD.encode(b)
	}
}
