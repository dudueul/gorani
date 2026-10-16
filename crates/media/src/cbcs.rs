// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `cbcs` protection: the encryption FairPlay plays (commit 40a, docs/DRM.md).
//!
//! A protected copy is the same fMP4 the in-page player builds (an init
//! segment, then moof + mdat segments of about four seconds, made by
//! crate::moov_builder and crate::moof_builder), with three changes:
//!
//! 1. **The samples are encrypted**, AES-128 in CBC mode, the way ISO/IEC
//!    23001-7 §10.4 defines the `cbcs` scheme:
//!    - **video**: each slice's header stays clear (crate::nal finds where
//!      it ends); after it, one 16-byte block in every ten is encrypted
//!      (the 1:9 pattern); everything that is not a slice — parameter sets,
//!      SEI — stays clear. The IV restarts at the constant IV for every
//!      slice (every *subsample*), and a trailing partial block is clear.
//!    - **audio**: every whole 16-byte block of each sample, in one CBC
//!      chain from the constant IV; the last partial block is clear.
//!
//!    Encryption never changes a size, so the timing and sizes the index
//!    computed stay right.
//! 2. **The init says so.** Each sample entry is renamed (`avc1` → `encv`,
//!    `mp4a` → `enca`) and gains a `sinf`: the original name (`frma`), the
//!    scheme (`schm` = `cbcs` 1.0), and in `schi/tenc` the key id, the
//!    pattern and the constant IV. A player that meets `encv` asks its DRM
//!    for the key with that id.
//! 3. **Each video fragment carries its subsample map** (`senc`, with
//!    `saiz`/`saio` pointing at it): which bytes of each sample are clear
//!    and which are protected. Audio needs none — the whole sample is
//!    protected, which `tenc` already says.
//!
//! This is the layout Shaka Packager and Bento4 write for FairPlay and
//! Widevine alike; ffmpeg's `-decryption_key` reads it too, which is how
//! the tests check every frame of a protected copy against the original.
//!
//! # What is protected
//!
//! FairPlay plays H.264 and HEVC video with AAC, AC-3 or E-AC-3 audio. A
//! track in any other codec (VP9, AV1, Opus, FLAC…) is refused here with
//! that said, rather than left clear: a protected copy with a clear track
//! is not protected.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};

use crate::bytes::ByteWriter;
use crate::error::{CoreError, Result};
use crate::moof_builder::{build_segment, segment_runs_of};
use crate::moov_builder::{build_init_segment_with, decode_stsd};
use crate::nal::{hevc_nal_header, parse_avcc, parse_hvcc, split_nals, AvcParams, HevcParams};
use crate::sample_entry::find_child_box;
use crate::schema::{MediaIndex, Segment, Track, TrackType};

/// The 1:9 pattern of `cbcs` video: one block encrypted, nine skipped.
pub const VIDEO_CRYPT_BLOCKS: u8 = 1;
pub const VIDEO_SKIP_BLOCKS: u8 = 9;

/// What a copy is locked with: the content key, its id (what the player
/// asks the license server for — and what `tenc` names), and the constant
/// IV every sample starts from.
#[derive(Clone)]
pub struct Protection {
	pub key: [u8; 16],
	pub kid: [u8; 16],
	pub iv: [u8; 16],
}

impl std::fmt::Debug for Protection {
	/// The key is never printed — not in a panic, not in a log.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Protection").field("kid", &self.kid).finish_non_exhaustive()
	}
}

fn refused(msg: impl Into<String>) -> CoreError {
	CoreError::Refused(msg.into())
}

enum Kind {
	Avc { length_size: usize, params: AvcParams },
	Hevc { length_size: usize, params: HevcParams },
	Audio,
}

struct TrackState {
	id: u32,
	kind: Kind,
}

/// Packages one video's protected copy, segment by segment, in order.
/// Stateful only for the parameter sets a stream sends in band (`avc3`,
/// `hev1`, or an encoder that repeats them at keyframes): a later slice
/// may refer to a PPS an earlier sample carried.
pub struct Packager {
	cipher: Aes128,
	protection: Protection,
	tracks: Vec<TrackState>,
}

impl Packager {
	/// Check every track can be protected, and read the parameter sets of
	/// the video's sample entry.
	pub fn new(idx: &MediaIndex, protection: &Protection) -> Result<Packager> {
		let mut tracks = Vec::with_capacity(idx.tracks.len());
		for t in &idx.tracks {
			tracks.push(TrackState { id: t.id, kind: kind_of(t)? });
		}
		if !tracks.iter().any(|t| !matches!(t.kind, Kind::Audio)) {
			return Err(refused("this file has no video track to protect"));
		}
		Ok(Packager { cipher: cipher_of(&protection.key), protection: protection.clone(), tracks })
	}

	/// The protected init segment: the same moov, each sample entry marked
	/// encrypted with this copy's key id and IV.
	pub fn init(&self, idx: &MediaIndex) -> Result<Vec<u8>> {
		build_init_segment_with(idx, &|t, entry| protect_entry(&entry, t.track_type == TrackType::Video, &self.protection))
	}

	/// Protected segment `n`: `payloads` as crate::moof_builder takes them
	/// (each track's sample bytes, in the segment's track order).
	pub fn segment(&mut self, idx: &MediaIndex, seg: &Segment, n: usize, payloads: Vec<Vec<u8>>) -> Result<Vec<u8>> {
		let mut runs = segment_runs_of(idx, seg, n)?;
		if payloads.len() != runs.len() {
			return Err(CoreError::Parse(format!("segment {n}: {} payloads for {} runs", payloads.len(), runs.len())));
		}
		for (run, payload) in runs.iter_mut().zip(payloads) {
			if payload.len() != run.payload_len() {
				return Err(CoreError::Parse(format!("segment {n}, track {}: {} bytes for {} described", run.track_id, payload.len(), run.payload_len())));
			}
			run.payload = payload;
			let state = self.tracks.iter_mut().find(|t| t.id == run.track_id).ok_or(CoreError::TrackNotFound(run.track_id))?;
			let mut at = 0usize;
			let mut maps = Vec::with_capacity(run.samples.len());
			for s in &run.samples {
				let sample = &mut run.payload[at..at + s.size as usize];
				match &mut state.kind {
					Kind::Audio => encrypt_whole(&self.cipher, &self.protection.iv, sample),
					video => {
						let map = subsample_map(video, sample)?;
						encrypt_subsamples(&self.cipher, &self.protection.iv, sample, &map)?;
						maps.push(map);
					}
				}
				at += s.size as usize;
			}
			if !matches!(state.kind, Kind::Audio) {
				run.subsamples = Some(maps);
			}
		}
		build_segment(&runs, n as u32 + 1)
	}
}

/// How a track is protected, from its sample entry — or why it cannot be.
fn kind_of(t: &Track) -> Result<Kind> {
	let entry = decode_stsd(t)?;
	let fourcc: [u8; 4] = entry[4..8].try_into().map_err(|_| CoreError::Parse("short sample entry".into()))?;
	let name = String::from_utf8_lossy(&fourcc).into_owned();
	match &fourcc {
		b"encv" | b"enca" => Err(refused("this video is already encrypted")),
		b"avc1" | b"avc2" | b"avc3" | b"avc4" => {
			let (avcc, _) = find_child_box(&entry, b"avcC").ok_or_else(|| refused("this H.264 track has no avcC"))?;
			let (length_size, params) = parse_avcc(avcc)?;
			Ok(Kind::Avc { length_size, params })
		}
		b"hvc1" | b"hev1" | b"dvh1" | b"dvhe" => {
			let (hvcc, _) = find_child_box(&entry, b"hvcC").ok_or_else(|| refused("this HEVC track has no hvcC"))?;
			let (length_size, params) = parse_hvcc(hvcc)?;
			Ok(Kind::Hevc { length_size, params })
		}
		b"ac-3" | b"ec-3" => Ok(Kind::Audio),
		b"mp4a" if t.codec_string.starts_with("mp4a.40") => Ok(Kind::Audio),
		_ => Err(refused(format!(
			"FairPlay plays H.264 or HEVC video with AAC, AC-3 or E-AC-3 audio; this file has {} ({name}) — convert it first",
			t.codec_string
		))),
	}
}

/// A (clear, protected) pair, split where the clear part outgrows the
/// 16-bit field it is written in.
fn push_subsample(map: &mut Vec<(u16, u32)>, mut clear: usize, protected: usize) -> Result<()> {
	while clear > u16::MAX as usize {
		map.push((u16::MAX, 0));
		clear -= u16::MAX as usize;
	}
	let protected = u32::try_from(protected).map_err(|_| CoreError::Parse("a NAL unit over 4 GiB".into()))?;
	map.push((clear as u16, protected));
	Ok(())
}

/// One video sample's subsample map: a subsample per slice, whose clear
/// part is everything since the previous slice (length fields, parameter
/// sets, SEI) plus this slice's header; its protected part, the slice data.
fn subsample_map(kind: &mut Kind, sample: &[u8]) -> Result<Vec<(u16, u32)>> {
	let length_size = match kind {
		Kind::Avc { length_size, .. } | Kind::Hevc { length_size, .. } => *length_size,
		Kind::Audio => unreachable!("audio has no subsamples"),
	};
	let mut map = Vec::new();
	let mut pending = 0usize;
	for (start, len) in split_nals(sample, length_size)? {
		let nal = &sample[start..start + len];
		let header = match kind {
			Kind::Avc { params, .. } => match nal[0] & 0x1f {
				1 | 5 => Some(params.slice_header_len(nal)?),
				7 | 8 => {
					params.add(nal)?;
					None
				}
				2..=4 => return Err(refused("this H.264 video uses data partitioning (Extended profile) — it cannot be protected")),
				20 | 21 => return Err(refused("this H.264 video is SVC, MVC or 3D — it cannot be protected")),
				_ => None,
			},
			Kind::Hevc { params, .. } => {
				let (ty, _) = hevc_nal_header(nal)?;
				match ty {
					0..=9 | 16..=21 => Some(params.slice_header_len(nal)?),
					10..=15 | 22..=31 => return Err(refused(format!("this HEVC video has a slice of reserved type {ty} — it cannot be protected"))),
					33 | 34 => {
						params.add(nal)?;
						None
					}
					_ => {
						params.add(nal)?; // refuses a parameter set of a second layer
						None
					}
				}
			}
			Kind::Audio => unreachable!(),
		};
		match header {
			Some(h) => {
				let h = h.min(len);
				push_subsample(&mut map, pending + length_size + h, len - h)?;
				pending = 0;
			}
			None => pending += length_size + len,
		}
	}
	if pending > 0 || map.is_empty() {
		push_subsample(&mut map, pending, 0)?;
	}
	Ok(map)
}

fn cipher_of(key: &[u8; 16]) -> Aes128 {
	Aes128::new_from_slice(key).expect("a 16-byte key")
}

/// One CBC step: XOR with the chain, encrypt, and the result is the chain.
fn cbc_block(cipher: &Aes128, chain: &mut [u8; 16], block: &mut [u8]) {
	let mut b = Block::default();
	for (i, x) in b.iter_mut().enumerate() {
		*x = block[i] ^ chain[i];
	}
	cipher.encrypt_block(&mut b);
	block.copy_from_slice(&b);
	chain.copy_from_slice(&b);
}

/// Audio: every whole block of the sample, one chain from the IV.
fn encrypt_whole(cipher: &Aes128, iv: &[u8; 16], sample: &mut [u8]) {
	let mut chain = *iv;
	for block in sample.chunks_exact_mut(16) {
		cbc_block(cipher, &mut chain, block);
	}
}

/// Video: per subsample, skip the clear bytes, then the 1:9 pattern over
/// the protected bytes with the chain restarted at the IV.
fn encrypt_subsamples(cipher: &Aes128, iv: &[u8; 16], sample: &mut [u8], map: &[(u16, u32)]) -> Result<()> {
	let mut at = 0usize;
	for &(clear, protected) in map {
		at += usize::from(clear);
		let end = at + protected as usize;
		if end > sample.len() {
			return Err(CoreError::Parse("a subsample runs past its sample".into()));
		}
		encrypt_pattern(cipher, iv, &mut sample[at..end]);
		at = end;
	}
	if at != sample.len() {
		return Err(CoreError::Parse("a subsample map does not cover its sample".into()));
	}
	Ok(())
}

/// The 1:9 pattern over one protected range (ISO/IEC 23001-7 §9.6): one
/// block encrypted, then nine (or what is left) skipped; a range whose
/// remainder is shorter than a block leaves that remainder clear.
pub fn encrypt_pattern(cipher: &Aes128, iv: &[u8; 16], data: &mut [u8]) {
	let mut chain = *iv;
	let mut at = 0usize;
	while data.len() - at >= 16 {
		for _ in 0..VIDEO_CRYPT_BLOCKS {
			if data.len() - at < 16 {
				return;
			}
			cbc_block(cipher, &mut chain, &mut data[at..at + 16]);
			at += 16;
		}
		at += (16 * usize::from(VIDEO_SKIP_BLOCKS)).min(data.len() - at);
	}
}

/// Where a sample entry's child boxes begin: after the fixed fields of a
/// visual entry, or of a sound entry of its version (0, 1, or QuickTime's 2).
fn children_start(entry: &[u8], is_video: bool) -> Result<usize> {
	if is_video {
		return Ok(86);
	}
	let version = entry.get(16..18).map(|v| u16::from_be_bytes([v[0], v[1]])).ok_or_else(|| CoreError::Parse("short sound entry".into()))?;
	match version {
		0 => Ok(36),
		1 => Ok(52),
		2 => Ok(72),
		v => Err(refused(format!("a sound sample entry of version {v}"))),
	}
}

/// The `sinf` that marks an entry `cbcs`-protected (ISO/IEC 23001-7 §8).
fn sinf(original: &[u8; 4], is_video: bool, p: &Protection) -> Result<Vec<u8>> {
	let mut w = ByteWriter::new();
	let sinf = w.open_box(b"sinf");
	let frma = w.open_box(b"frma");
	w.bytes(original);
	w.close_box(frma)?;
	let schm = w.open_box(b"schm");
	w.u32(0);
	w.bytes(b"cbcs");
	w.u32(0x0001_0000); // version 1.0
	w.close_box(schm)?;
	let schi = w.open_box(b"schi");
	let tenc = w.open_box(b"tenc");
	w.u32(0x0100_0000); // version 1: the pattern fields are meaningful
	w.u8(0);
	// Video: 1:9. Audio: 0:0, which with no subsamples means every whole
	// block (the same encryption as 1:0, written the way Bento4 does; a
	// player that wanted 1:0 needs only this byte changed, not the copy
	// encrypted again).
	w.u8(if is_video { (VIDEO_CRYPT_BLOCKS << 4) | VIDEO_SKIP_BLOCKS } else { 0 });
	w.u8(1); // default_isProtected
	w.u8(0); // default_Per_Sample_IV_Size: none, the constant IV below
	w.bytes(&p.kid);
	w.u8(16); // default_constant_IV_size
	w.bytes(&p.iv);
	w.close_box(tenc)?;
	w.close_box(schi)?;
	w.close_box(sinf)?;
	Ok(w.into_vec())
}

/// A sample entry marked protected: renamed `encv`/`enca`, with a `sinf`
/// added after its last child box (before any trailing terminator a
/// QuickTime writer left).
pub fn protect_entry(entry: &[u8], is_video: bool, p: &Protection) -> Result<Vec<u8>> {
	let original: [u8; 4] = entry.get(4..8).and_then(|f| f.try_into().ok()).ok_or_else(|| CoreError::Parse("short sample entry".into()))?;
	let start = children_start(entry, is_video)?;
	let mut end = start;
	while end + 8 <= entry.len() {
		let size = u32::from_be_bytes(entry[end..end + 4].try_into().unwrap()) as usize;
		if size < 8 || end + size > entry.len() {
			break;
		}
		end += size;
	}
	let sinf = sinf(&original, is_video, p)?;
	let mut out = Vec::with_capacity(entry.len() + sinf.len());
	out.extend_from_slice(&entry[..end]);
	out.extend_from_slice(&sinf);
	out.extend_from_slice(&entry[end..]);
	let size = u32::try_from(out.len()).map_err(|_| CoreError::Parse("sample entry over 4 GiB".into()))?;
	out[0..4].copy_from_slice(&size.to_be_bytes());
	out[4..8].copy_from_slice(if is_video { b"encv" } else { b"enca" });
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;
	use aes::cipher::BlockDecrypt;

	fn protection() -> Protection {
		Protection { key: [7; 16], kid: [0x11; 16], iv: [0x22; 16] }
	}

	fn cbc_decrypt_block(cipher: &Aes128, chain: &mut [u8; 16], block: &mut [u8]) {
		let saved: [u8; 16] = block.try_into().unwrap();
		let mut b = Block::default();
		b.copy_from_slice(block);
		cipher.decrypt_block(&mut b);
		for (i, x) in block.iter_mut().enumerate() {
			*x = b[i] ^ chain[i];
		}
		*chain = saved;
	}

	#[test]
	fn the_pattern_encrypts_one_block_in_ten() {
		let p = protection();
		let cipher = cipher_of(&p.key);
		let plain: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
		let mut data = plain.clone();
		encrypt_pattern(&cipher, &p.iv, &mut data);
		// blocks 0 and 10 (bytes 0..16 and 160..176) change; 176..336 is the
		// skip; 320..336 would be block 20 but 400−320 = 80 ≥ 16, so it changes too
		for (i, (a, b)) in plain.chunks(16).zip(data.chunks(16)).enumerate() {
			assert_eq!(a != b, i % 10 == 0 && b.len() == 16, "block {i}");
		}
		// and the encrypted blocks are ONE chain from the IV
		let mut chain = p.iv;
		for i in [0usize, 10, 20] {
			let mut block = data[i * 16..i * 16 + 16].to_vec();
			cbc_decrypt_block(&cipher, &mut chain, &mut block);
			assert_eq!(block, plain[i * 16..i * 16 + 16]);
		}
	}

	#[test]
	fn a_short_tail_stays_clear() {
		let p = protection();
		let cipher = cipher_of(&p.key);
		let mut data = [9u8; 15];
		encrypt_pattern(&cipher, &p.iv, &mut data);
		assert_eq!(data, [9u8; 15], "less than a block is never encrypted");
		let mut audio = [9u8; 40];
		encrypt_whole(&cipher, &p.iv, &mut audio);
		assert_ne!(audio[..32], [9u8; 32]);
		assert_eq!(audio[32..], [9u8; 8], "audio's partial last block is clear");
	}

	#[test]
	fn each_subsample_restarts_at_the_iv() {
		let p = protection();
		let cipher = cipher_of(&p.key);
		let mut sample = vec![5u8; 2 * (4 + 32)];
		encrypt_subsamples(&cipher, &p.iv, &mut sample, &[(4, 32), (4, 32)]).unwrap();
		assert_eq!(sample[..4], [5, 5, 5, 5]);
		assert_eq!(sample[4..20], sample[40..56], "the same plaintext from the same IV: the chain restarted");
		assert!(encrypt_subsamples(&cipher, &p.iv, &mut sample, &[(4, 32)]).is_err(), "a map must cover its sample");
	}

	#[test]
	fn a_protected_entry_names_its_scheme_key_and_original() {
		let file = crate::testmp4::regular_two_track();
		let (h, moov) = crate::moov::find_moov(&file, 0).unwrap();
		let tracks = crate::moov::parse_tracks(&moov, h.content_start).unwrap();
		let p = protection();
		for t in &tracks {
			let entry = &t.sample_entry;
			let is_video = t.track_type == TrackType::Video;
			let out = protect_entry(entry, is_video, &p).unwrap();
			let parsed = crate::sample_entry::parse_sample_entry(&out).unwrap();
			assert!(parsed.encrypted);
			assert_eq!(parsed.scheme, Some(*b"cbcs"));
			let before = crate::sample_entry::parse_sample_entry(entry).unwrap();
			assert_eq!(parsed.codec_string, before.codec_string, "the codec string still describes the decoded stream");
			let (sinf, _) = find_child_box(&out, b"sinf").unwrap();
			let at = sinf.windows(4).position(|w| w == b"tenc").unwrap() + 4;
			let tenc = &sinf[at..];
			assert_eq!(tenc[5], if is_video { 0x19 } else { 0 }, "the pattern");
			assert_eq!(&tenc[8..24], &p.kid);
			assert_eq!(tenc[24], 16);
			assert_eq!(&tenc[25..41], &p.iv);
		}
	}

	#[test]
	fn the_key_is_never_printed() {
		let shown = format!("{:?}", protection());
		assert!(!shown.contains("7, 7"), "{shown}");
	}
}
