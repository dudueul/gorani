// Copyright 2026- Seongwoo Hong. All rights reserved.

//! gorani-media-wasm — the browser's door into `gorani-media` (commit 39p,
//! docs/VIDEO.md).
//!
//! The browser holds the plaintext (it decrypted the GC01 frames itself);
//! this turns a regular MP4's `moov` into an index, and the index plus the
//! sample bytes of segment N into fMP4 the page appends to Media Source
//! Extensions. It never sees a key and never asks for bytes on its own: the
//! page reads what [`core::plan`] says, decrypting frame by frame, and hands
//! the bytes back.
//!
//! The boundary, without wasm-bindgen:
//!
//! - `gm_alloc(len)` / `gm_free(ptr, len)` — memory the page writes inputs to;
//! - every call returns an `i32`: ≥ 0 is success (or a handle), < 0 an error
//!   whose message, `{"error": …}`, waits in the result slot;
//! - the result slot (`gm_out_ptr` / `gm_out_len`, then `gm_out_free`) holds
//!   the last call's bytes or JSON — WebAssembly here is single-threaded;
//! - an index stays inside, behind a handle (`gm_drop` frees it): a long
//!   film's sample tables are not shipped across as JSON for every segment.
//!
//! `u64` arguments arrive from JavaScript as BigInt, so offsets past 4 GiB
//! stay exact. The release profile aborts on panic: a bad file traps the
//! instance (the page catches it and starts a fresh one) — it never
//! returns a half-built segment.

use std::cell::RefCell;

use gorani_media::schema::MediaIndex;

/// The safe core — what the C ABI below wraps, and what the tests call.
pub mod core {
	use gorani_media::boxes::parse_top_header;
	use gorani_media::index_builder::BuildOptions;
	use gorani_media::indexer::index_moov_box;
	use gorani_media::moof_builder::build_segment_with;
	use gorani_media::moov_builder::build_init_segment;
	use gorani_media::readplan::{concat_ranges, plan_reads, segment_ranges, DEFAULT_MAX_BLOCK, DEFAULT_MAX_GAP};
	use gorani_media::schema::{ByteRange, MediaIndex, SourceInfo, TrackType};
	use serde_json::{json, Value};

	/// A top-level box header (8 or 16 bytes) at `offset` of a file of
	/// `size`: what the page needs to walk to the `moov`.
	pub fn top_header(hdr: &[u8], offset: u64, size: u64) -> Result<Value, String> {
		let b = parse_top_header(hdr, offset, size).map_err(|e| e.to_string())?;
		Ok(json!({ "type": String::from_utf8_lossy(&b.box_type), "offset": b.offset, "size": b.size, "headerLen": b.header_len }))
	}

	/// Index a regular MP4 from its whole `moov` box (header included), at
	/// absolute offset `moov_abs`. Segments are cut on keyframes, aiming at
	/// `target_ms` (≥ 500).
	pub fn index_moov(moov: Vec<u8>, moov_abs: u64, file_size: u64, target_ms: u32) -> Result<MediaIndex, String> {
		let source = SourceInfo { key: String::new(), size: file_size, etag: None };
		let opts = BuildOptions { target_segment_ms: u64::from(target_ms.max(500)) };
		index_moov_box(source, moov, moov_abs, &opts).map_err(|e| e.to_string())
	}

	/// What the page shows and seeks by: duration, the MSE codec string,
	/// each track, and every segment's start and length in seconds.
	pub fn summary(idx: &MediaIndex) -> Value {
		let ts = f64::from(idx.primary_timescale().max(1));
		json!({
			"durationMs": idx.duration_ms,
			"codecs": idx.codec_string(),
			"tracks": idx.tracks.iter().map(|t| json!({
				"id": t.id,
				"type": if t.track_type == TrackType::Video { "video" } else { "audio" },
				"codec": t.codec_string,
				"width": t.width,
				"height": t.height,
			})).collect::<Vec<_>>(),
			"segments": idx.segments.iter().map(|s| json!([s.start_dts as f64 / ts, s.duration as f64 / ts])).collect::<Vec<_>>(),
			"warnings": idx.compat_warnings(),
		})
	}

	/// The plaintext byte blocks segment `n` needs — coalesced, so audio and
	/// video interleaved in the file usually come in one read.
	pub fn plan(idx: &MediaIndex, n: usize) -> Result<Vec<ByteRange>, String> {
		let seg = idx.segments.get(n).ok_or_else(|| format!("no segment {n} (of {})", idx.segments.len()))?;
		Ok(plan_reads(&segment_ranges(seg), DEFAULT_MAX_GAP, DEFAULT_MAX_BLOCK))
	}

	/// Segment `n` (moof + mdat), from the blocks of [`plan`] joined in
	/// order. A block of the wrong total length is refused, not guessed at.
	pub fn segment(idx: &MediaIndex, n: usize, joined: &[u8]) -> Result<Vec<u8>, String> {
		let seg = idx.segments.get(n).ok_or_else(|| format!("no segment {n} (of {})", idx.segments.len()))?;
		let blocks = plan(idx, n)?;
		let want: u64 = blocks.iter().map(|b| b.length).sum();
		if want != joined.len() as u64 {
			return Err(format!("segment {n}: {} bytes given for {want} planned", joined.len()));
		}
		let mut at = 0usize;
		let mut owned = Vec::with_capacity(blocks.len());
		for b in blocks {
			let len = b.length as usize;
			owned.push((b, joined[at..at + len].to_vec()));
			at += len;
		}
		let payloads = seg
			.tracks
			.iter()
			.map(|st| concat_ranges(&owned, &st.byte_ranges).ok_or_else(|| format!("segment {n}: the plan does not cover a track's samples")))
			.collect::<Result<Vec<_>, _>>()?;
		build_segment_with(idx, seg, n, payloads).map_err(|e| e.to_string())
	}

	/// The fMP4 init segment (ftyp + moov with empty tables and mvex).
	pub fn init(idx: &MediaIndex) -> Result<Vec<u8>, String> {
		build_init_segment(idx).map_err(|e| e.to_string())
	}

	/// Plan as JSON: `[[offset, length], …]`.
	pub fn plan_json(idx: &MediaIndex, n: usize) -> Result<Value, String> {
		Ok(Value::Array(plan(idx, n)?.into_iter().map(|b| json!([b.offset, b.length])).collect()))
	}
}

thread_local! {
	static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
	static INDEXES: RefCell<Vec<Option<MediaIndex>>> = const { RefCell::new(Vec::new()) };
}

fn put(bytes: Vec<u8>) {
	OUT.with(|o| *o.borrow_mut() = bytes);
}

fn fail(message: impl std::fmt::Display) -> i32 {
	put(serde_json::json!({ "error": message.to_string() }).to_string().into_bytes());
	-1
}

fn answer(r: Result<Vec<u8>, String>) -> i32 {
	match r {
		Ok(bytes) => {
			put(bytes);
			0
		}
		Err(e) => fail(e),
	}
}

fn with_index<T>(h: i32, f: impl FnOnce(&MediaIndex) -> T) -> Result<T, String> {
	INDEXES.with(|ix| {
		let ix = ix.borrow();
		let idx = usize::try_from(h).ok().and_then(|i| ix.get(i)).and_then(Option::as_ref).ok_or_else(|| format!("no index {h}"))?;
		Ok(f(idx))
	})
}

/// # Safety
/// Only called by the page; the memory is freed with `gm_free(ptr, len)`.
#[no_mangle]
pub extern "C" fn gm_alloc(len: usize) -> *mut u8 {
	let mut v = Vec::<u8>::with_capacity(len.max(1));
	let p = v.as_mut_ptr();
	std::mem::forget(v);
	p
}

/// # Safety
/// `ptr`/`len` from `gm_alloc(len)`, not yet freed or handed to `gm_index_moov`.
#[no_mangle]
pub unsafe extern "C" fn gm_free(ptr: *mut u8, len: usize) {
	if !ptr.is_null() {
		drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
	}
}

#[no_mangle]
pub extern "C" fn gm_out_ptr() -> *const u8 {
	OUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn gm_out_len() -> usize {
	OUT.with(|o| o.borrow().len())
}

#[no_mangle]
pub extern "C" fn gm_out_free() {
	OUT.with(|o| *o.borrow_mut() = Vec::new());
}

/// # Safety
/// `p` points at `n` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn gm_top_header(p: *const u8, n: usize, offset: u64, size: u64) -> i32 {
	let hdr = std::slice::from_raw_parts(p, n);
	answer(core::top_header(hdr, offset, size).map(|v| v.to_string().into_bytes()))
}

/// Index the moov at `p` (`n` bytes, from `gm_alloc(n)` — ownership passes
/// here, no copy) and keep it: returns its handle; the result slot holds
/// its summary.
///
/// # Safety
/// `p`/`n` from `gm_alloc(n)`, filled, and not freed afterwards.
#[no_mangle]
pub unsafe extern "C" fn gm_index_moov(p: *mut u8, n: usize, moov_abs: u64, file_size: u64, target_ms: u32) -> i32 {
	let moov = Vec::from_raw_parts(p, n, n.max(1));
	match core::index_moov(moov, moov_abs, file_size, target_ms) {
		Ok(idx) => {
			put(core::summary(&idx).to_string().into_bytes());
			INDEXES.with(|ix| {
				let mut ix = ix.borrow_mut();
				ix.push(Some(idx));
				(ix.len() - 1) as i32
			})
		}
		Err(e) => fail(e),
	}
}

#[no_mangle]
pub extern "C" fn gm_drop(h: i32) {
	INDEXES.with(|ix| {
		if let Some(slot) = usize::try_from(h).ok().and_then(|i| ix.borrow_mut().get_mut(i).map(Option::take)) {
			drop(slot);
		}
	});
}

#[no_mangle]
pub extern "C" fn gm_init(h: i32) -> i32 {
	answer(with_index(h, core::init).and_then(|r| r))
}

#[no_mangle]
pub extern "C" fn gm_plan(h: i32, n: u32) -> i32 {
	answer(with_index(h, |idx| core::plan_json(idx, n as usize)).and_then(|r| r).map(|v| v.to_string().into_bytes()))
}

/// # Safety
/// `p` points at `len` readable bytes: segment `n`'s planned blocks, joined.
#[no_mangle]
pub unsafe extern "C" fn gm_segment(h: i32, n: u32, p: *const u8, len: usize) -> i32 {
	let joined = std::slice::from_raw_parts(p, len);
	answer(with_index(h, |idx| core::segment(idx, n as usize, joined)).and_then(|r| r))
}

#[cfg(test)]
mod tests {
	use super::core;
	use gorani_media::testmp4;

	/// The page's whole path, natively: walk the top boxes, index the moov,
	/// plan each segment, cut the planned blocks out of the file, build the
	/// segment — and a wrong-length input is refused.
	#[test]
	fn the_pages_path_end_to_end() {
		let file = testmp4::regular_two_track();
		let mut at = 0u64;
		let mut moov = None;
		while at < file.len() as u64 {
			let h = core::top_header(&file[at as usize..(at as usize + 16).min(file.len())], at, file.len() as u64).unwrap();
			let (ty, size) = (h["type"].as_str().unwrap().to_string(), h["size"].as_u64().unwrap());
			if ty == "moov" {
				moov = Some((at, size));
			}
			at += size;
		}
		let (moov_at, moov_size) = moov.expect("a moov");
		let idx = core::index_moov(file[moov_at as usize..(moov_at + moov_size) as usize].to_vec(), moov_at, file.len() as u64, 2000).unwrap();
		let summary = core::summary(&idx);
		assert!(summary["codecs"].as_str().unwrap().contains("avc1"), "{summary}");
		assert!(!idx.segments.is_empty());
		let init = core::init(&idx).unwrap();
		assert_eq!(&init[4..8], b"ftyp");
		for n in 0..idx.segments.len() {
			let joined: Vec<u8> = core::plan(&idx, n).unwrap().iter().flat_map(|b| file[b.offset as usize..(b.offset + b.length) as usize].to_vec()).collect();
			let seg = core::segment(&idx, n, &joined).unwrap();
			assert_eq!(&seg[4..8], b"moof", "segment {n} starts with its moof");
			assert!(core::segment(&idx, n, &joined[1..]).is_err(), "a short input is refused");
		}
	}
}
