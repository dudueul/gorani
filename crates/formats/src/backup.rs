// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's backup design (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The `.gbak` backup container (GB1): one encrypted file per backup, whose
//! file key exists only in the owner's downloaded key file (sealed into the
//! header to the backup PUBLIC key — the server can write backups and never
//! open them).
//!
//! ```text
//! "GBAK1\n" ‖ headerLen (4 BE) ‖ header JSON ‖ segment 0 ‖ segment 1 ‖ … ‖ final segment
//! header JSON = { format: "gorani-backup", v: 1, stamp, kind, keyId, wrapped, seg, alg, count }
//! wrapped     = GV03 text: the 32-byte file key sealed to the backup public key
//! segment i   = nonce (12: 0x00000000 ‖ i, u64 BE) ‖ AES-256-GCM(fileKey, slice, AAD) ‖ tag (16)
//! AAD_i       = "GBAK1" ‖ i (8 BE) ‖ final (1)
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

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::Error;

pub const MAGIC: &[u8; 6] = b"GBAK1\n";
pub const SEG_SIZE: usize = 1024 * 1024;
const TAG_LEN: usize = 16;

/// A fresh per-backup file key (wiped when dropped).
pub type FileKey = Zeroizing<[u8; 32]>;

pub fn new_file_key() -> FileKey {
	let mut k = Zeroizing::new([0u8; 32]);
	OsRng.fill_bytes(k.as_mut());
	k
}

fn aad(seg: u64, final_seg: bool) -> [u8; 16] {
	let mut a = [0u8; 16];
	a[..5].copy_from_slice(b"GBAK1");
	a[5] = b'1'; // container version, inside the AAD like the magic
	a[6] = b'A'; // domain separator: the segment stream (not the header)
	a[7] = final_seg as u8;
	a[8..16].copy_from_slice(&seg.to_be_bytes());
	a
}

fn nonce(seg: u64) -> Nonce<aes_gcm::aead::consts::U12> {
	let mut n = [0u8; 12];
	n[4..12].copy_from_slice(&seg.to_be_bytes());
	Nonce::from(n)
}

fn aes(key: &[u8; 32]) -> Aes256Gcm {
	Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

/// Streaming writer: feed plaintext, collect GB1 bytes; `finish` emits the
/// last segment. The caller assembles the header JSON (it includes the
/// sealed file key, which only the owner's key file can open).
pub struct BackupWriter {
	key: FileKey,
	seg: u64,
	buf: Vec<u8>,
	/// Bytes already emitted (segments before the current buffer).
	pub written: u64,
}

impl BackupWriter {
	pub fn new(key: FileKey) -> Self {
		Self { key, seg: 0, buf: Vec::new(), written: 0 }
	}

	/// Push plaintext in; GB1 segment bytes come out.
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
		// The counter nonce rides IN the segment (the reader verifies it).
		let mut block = [0u8; 12];
		block[4..12].copy_from_slice(&self.seg.to_be_bytes());
		let ct = aes(&self.key)
			.encrypt(&nonce(self.seg), Payload { msg: slice, aad: &aad(self.seg, final_seg) })
			.expect("AES-GCM encrypt");
		out.extend_from_slice(&block);
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
		Ok((Self { key, bytes, header }, at + len))
	}

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
		let mut out = Vec::with_capacity(segments.len());
		let mut seg: u64 = 0;
		let mut at = 0usize;
		while at < segments.len() {
			if at + 12 > segments.len() {
				return Err(Error::Format("backup segment nonce is cut short"));
			}
			// The nonce carries the segment number too; a mismatch is a reorder.
			let claimed = u64::from_be_bytes(segments[at + 4..at + 12].try_into().expect("8 bytes"));
			if claimed != seg {
				return Err(Error::Format("backup segments are out of order"));
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
					&nonce(seg),
					// aes-gcm wants ciphertext ‖ tag — the tag trails the payload.
					Payload {
						msg: &segments[at + 12..at + 12 + payload_len + TAG_LEN],
						aad: &aad(seg, final_seg),
					},
				)
				.map_err(|e| {
					#[cfg(test)]
					eprintln!("decrypt seg {seg} failed: payload_len {payload_len} final {final_seg} remaining {remaining}");
					Error::Open("wrong backup key or corrupted backup")
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
		let header = format!(r#"{{"format":"gorani-backup","v":1,"wrapped":"{wrapped}"}}"#);

		let mut w = BackupWriter::new(file_key.clone());
		let mut out = vec![];
		out.extend_from_slice(MAGIC);
		out.extend_from_slice(&(header.len() as u32).to_be_bytes());
		out.extend_from_slice(header.as_bytes());
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
	}

	fn base64_of(b: &[u8]) -> String {
		use base64::Engine;
		base64::engine::general_purpose::STANDARD.encode(b)
	}
}
