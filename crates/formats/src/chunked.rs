// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! Chunked files (GC01, docs/ENCRYPTION.md): a file too large for one request
//! is sealed in chunks of `chunk` bytes, each its own AES-256-GCM frame under
//! the file version's content key, uploaded one frame per multipart part.
//! Every frame binds its position and whether it is the last (as AAD), so
//! frames cannot be reordered, dropped, repeated or the file cut short
//! without opening failing:
//!
//! ```text
//! object  = frame 0 ‖ frame 1 ‖ … ‖ frame n−1   (every frame but the last exactly chunk + 28 bytes)
//! frame i = nonce (12, random) ‖ AES-256-GCM(content key, chunk i, AAD) ‖ tag (16)
//! AAD     = "GC01" ‖ i (8 bytes, big-endian) ‖ final (1 byte: 1 for the last frame, else 0)
//! ```
//!
//! Because every frame stands alone, any byte range of the file can be
//! fetched and opened without the rest: what lets the file explorer and the
//! video player open a large file on demand, part by part. An empty file is
//! one empty final frame.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::Error;

pub const MAGIC: &[u8; 4] = b"GC01";
const TAG_LEN: usize = 16;
pub const FRAME_OVERHEAD: u64 = 28;
/// Plain bytes per frame (and per uploaded part, which S3 wants at least 5 MiB and uniform).
pub const DEFAULT_CHUNK: u64 = 8 * 1024 * 1024;

pub fn frame_count(size: u64, chunk: u64) -> u64 {
	size.div_ceil(chunk).max(1)
}

/// The stored object's size for a plain size.
pub fn sealed_size(size: u64, chunk: u64) -> u64 {
	size + frame_count(size, chunk) * FRAME_OVERHEAD
}

fn aad(i: u64, last: bool) -> [u8; 13] {
	let mut a = [0u8; 13];
	a[..4].copy_from_slice(MAGIC);
	a[4..12].copy_from_slice(&i.to_be_bytes());
	a[12] = last as u8;
	a
}

pub fn seal_chunk(key: &[u8; 32], plain: &[u8], i: u64, last: bool) -> Vec<u8> {
	let mut nonce = [0u8; 12];
	OsRng.fill_bytes(&mut nonce);
	let ct = Aes256Gcm::new_from_slice(key).expect("32-byte key").encrypt(&Nonce::from(nonce), Payload { msg: plain, aad: &aad(i, last) }).expect("AES-GCM");
	[nonce.as_slice(), &ct].concat()
}

/// Open one frame from its parts (nonce + body + AAD already assembled) —
/// what the client's streaming path uses after fetching a ciphertext span.
pub fn open_chunk_frame(key: &[u8; 32], nonce: &[u8], body: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
	if body.len() < TAG_LEN {
		return Err(Error::Format("a chunk is too short"));
	}
	let mut iv = [0u8; 12];
	iv.copy_from_slice(&nonce[..12]);
	Aes256Gcm::new_from_slice(key)
		.expect("32-byte key")
		.decrypt(&Nonce::from(iv), Payload { msg: &body[..body.len() - TAG_LEN], aad })
		.map(Zeroizing::new)
		.map_err(|_| Error::Open("a chunk: wrong key, or the file was altered, reordered or cut short"))
}

pub fn open_chunk(key: &[u8; 32], frame: &[u8], i: u64, last: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
	if (frame.len() as u64) < FRAME_OVERHEAD {
		return Err(Error::Format("a chunk is too short"));
	}
	let mut nonce = [0u8; 12];
	nonce.copy_from_slice(&frame[..12]);
	Aes256Gcm::new_from_slice(key)
		.expect("32-byte key")
		.decrypt(&Nonce::from(nonce), Payload { msg: &frame[12..], aad: &aad(i, last) })
		.map(Zeroizing::new)
		.map_err(|_| Error::Open("a chunk: wrong key, or the file was altered, reordered or cut short"))
}

/// Where a plain byte range lies in the stored object: the frames that hold it (first..=last) and their byte span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSpan {
	pub first: u64,
	pub last: u64,
	pub start: u64,
	pub end: u64,
}

/// The frames holding plain bytes `offset .. offset + len` of a file of `size` bytes (`len` 0 still names one frame).
pub fn frames_for(offset: u64, len: u64, size: u64, chunk: u64) -> FrameSpan {
	let n = frame_count(size, chunk);
	let first = (offset / chunk).min(n - 1);
	let last = ((offset + len.max(1) - 1) / chunk).min(n - 1);
	let frame = chunk + FRAME_OVERHEAD;
	let end = (last * frame + frame).min(sealed_size(size, chunk));
	FrameSpan { first, last, start: first * frame, end }
}

/// Open the frames of a span (as fetched: `bytes` = the stored bytes from `span.start` to `span.end`).
pub fn open_span(key: &[u8; 32], bytes: &[u8], span: FrameSpan, size: u64, chunk: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
	let n = frame_count(size, chunk);
	let frame = (chunk + FRAME_OVERHEAD) as usize;
	let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
	for (k, i) in (span.first..=span.last).enumerate() {
		let from = k * frame;
		let to = (from + frame).min(bytes.len());
		if from >= bytes.len() {
			return Err(Error::Format("the file was cut short"));
		}
		out.extend_from_slice(&open_chunk(key, &bytes[from..to], i, i == n - 1)?);
	}
	Ok(out)
}

/// A whole chunked object, opened.
pub fn open_chunked(key: &[u8; 32], sealed: &[u8], chunk: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
	let frame = chunk + FRAME_OVERHEAD;
	let n = (sealed.len() as u64).div_ceil(frame).max(1);
	let size = sealed.len() as u64 - n * FRAME_OVERHEAD;
	open_span(key, sealed, FrameSpan { first: 0, last: n - 1, start: 0, end: sealed.len() as u64 }, size, chunk)
}