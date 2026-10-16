// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Source indexing — the shared heart of the admin panel and the CLI.
//!
//! # Why this module is pure (no I/O, no worker deps)
//!
//! Indexing a source MP4 has exactly three ingredients:
//!   1. the *header bytes* of the file (ftyp + moov, possibly in a tail
//!      region for moov-at-end files),
//!   2. the source's total size and key (identity),
//!   3. segment-duration preferences.
//!
//! Everything else — where the bytes come from (local file, R2 ranged read)
//! and where the index goes (stdout, local path, R2 PUT) — is the caller's
//! business. Keeping this module pure lets:
//!   * the CLI index local files,
//!   * the admin panel index uploads by issuing a handful of ranged R2
//!     reads (never mdat!),
//!   * both share ONE parser (single source of truth, single test gate).
//!
//! # Two strategies
//!
//! * **head/tail buffers** (`index_bytes`): read the first `HEAD_MAX` bytes
//!   and, if no moov is there, the last `TAIL_MAX` bytes. Right for files up
//!   to the head budget (moov anywhere) — one or two reads.
//! * **lazy box walk** (`index_lazy`): for anything larger. Reads 16-byte
//!   box headers, skips `mdat` payloads analytically, fetches only `moov`
//!   and each `moof`. A 5GB fragmented file costs a few thousand tiny reads
//!   and a few MB of memory; `mdat` bytes are never read.

use crate::boxes::{fragment_end, parse_top_header, TopBox};
use crate::error::{CoreError, Result};
use crate::index_builder::BuildOptions;
use crate::parse_frag::{build_fragmented_index, build_fragmented_index_from_moofs, RemoteMoof};
use crate::schema::{MediaIndex, SourceInfo};

/// Which parts of a source object must be fetched to index it.
///
/// Both lengths are capped so a pathological file can never make the worker
/// buffer its whole body. `head` normally contains ftyp+moov (faststart or
/// fragmented sources); `tail` catches plain ffmpeg layout (moov at end).
/// Callers may fetch both and pass whichever produced a parseable moov.
#[derive(Debug, Clone, Copy)]
pub struct FetchRanges {
    /// bytes to read from offset 0 (may be less than source size)
    pub head_len: u64,
    /// bytes to read from (size - tail_len) — read ONLY if head lacks a moov
    pub tail_len: u64,
}

pub const HEAD_MAX: u64 = 64 * 1024 * 1024;
pub const TAIL_MAX: u64 = 32 * 1024 * 1024;

/// moov boxes larger than this are refused (memory safety: the worker holds
/// a JS copy and a wasm copy of it inside a 128MB isolate). Regular long
/// videos land in single-digit MB; 32MB is ~1.3M samples, i.e. >15h at
/// 24fps. Larger sources are indexed offline with the CLI.
pub const MOOV_MAX: u64 = 32 * 1024 * 1024;
/// per-moof fetch cap (a moof is header metadata only; >16MB is corruption)
pub const MOOF_MAX: u64 = 16 * 1024 * 1024;
/// fragment count cap (protects against corrupt/hostile inputs)
pub const MAX_MOOFS: usize = 20_000;
/// top-level box cap for the lazy walk
pub const MAX_TOP_BOXES: usize = 100_000;

/// Compute the ranges to fetch for a source of `size` bytes.
/// Small files: the whole file fits in the head (tail not needed).
pub fn head_and_tail_ranges(size: u64) -> FetchRanges {
    let head = size.min(HEAD_MAX);
    let tail = if size > head { size.min(TAIL_MAX) } else { 0 };
    FetchRanges {
        head_len: head,
        tail_len: tail,
    }
}

/// Index one source from its header bytes.
///
/// # Arguments
/// * `source` — identity (R2 key, size, optional etag) stored in the index
/// * `head` — buffer with the file's first `head_len` bytes
/// * `head_base` — absolute offset of `head`[0] (0 in practice)
/// * `tail` — optional `(buffer, base)` with the file's LAST bytes
///   (base = size - len); used when moov sits at the end
/// * `opts` — segment-duration target
///
/// Dispatch logic:
///
/// * If a trak with real samples parses → **regular source (Case B)**:
///   full sample-table index with cut points; the worker assembles segments.
/// * Otherwise → **fragmented source (Case A)**: `moof` walk via
///   `build_fragmented_index`, which also records `moov_range` so the worker
///   can serve `/init` as a direct ranged GET of the source moov.
pub fn index_bytes(
    source: SourceInfo,
    head: &[u8],
    head_base: u64,
    tail: Option<(&[u8], u64)>,
    opts: &BuildOptions,
) -> Result<MediaIndex> {
    // ── Step 1: locate moov in head, else in tail ────────────────────────
    let (moov_h, moov, moov_buf, moov_base) = if let Ok((h, m)) =
        crate::moov::find_moov(head, head_base)
    {
        (h, m, head, head_base)
    } else if let Some((t, tb)) = tail {
        let (h, m) = crate::moov::find_moov(t, tb)
            .map_err(|_| CoreError::Parse("no moov found in head or tail (not an MP4?)".into()))?;
        (h, m, t, tb)
    } else {
        return Err(CoreError::Parse(
            "no moov found in head (not an MP4?)".into(),
        ));
    };
    if moov_h.end() > moov_base + moov_buf.len() as u64 {
        return Err(CoreError::Parse(format!(
            "moov ({} bytes at {}) extends beyond the fetched bytes — index with the lazy walker",
            moov_h.size, moov_h.start
        )));
    }

    // ── Step 2: try the regular (sample-table) interpretation ────────────
    let tracks = crate::moov::parse_tracks_served(&moov, moov_h.content_start)?;
    if !tracks.is_empty() && tracks.iter().any(|t| !t.samples.is_empty()) {
        let movie_ts = crate::moov::parse_mvhd_pub(&moov, moov_h.content_start)?;
        return crate::index_builder::build_index(source, tracks, movie_ts, opts);
    }

    // ── Step 3: fragmented interpretation (Case A) ───────────────────────
    build_fragmented_index(source, moov_buf, moov_base, opts)
}

/// Index a REGULAR source from its complete `moov` box (header + children)
/// held in an owned buffer, without copying the box a second time — the
/// worker's memory-lean path. `moov_abs` is the box's absolute file offset.
/// Fails for fragmented sources (no samples); use the moof path for those.
pub fn index_moov_box(
    source: SourceInfo,
    mut moov_box: Vec<u8>,
    moov_abs: u64,
    opts: &BuildOptions,
) -> Result<MediaIndex> {
    let hdr = parse_top_header(&moov_box, moov_abs, u64::MAX)?;
    if &hdr.box_type != b"moov" {
        return Err(CoreError::Parse("buffer is not a moov box".into()));
    }
    let hl = hdr.header_len as usize;
    if moov_box.len() < hl {
        return Err(CoreError::Parse("moov shorter than its header".into()));
    }
    moov_box.drain(..hl);
    let content_start = moov_abs + hl as u64;
    let movie_ts = crate::moov::parse_mvhd_pub(&moov_box, content_start)?;
    let tracks = crate::moov::parse_tracks_served(&moov_box, content_start)?;
    drop(moov_box);
    if tracks.is_empty() || tracks.iter().all(|t| t.samples.is_empty()) {
        return Err(CoreError::Parse(
            "moov has no sample tables (fragmented source?)".into(),
        ));
    }
    crate::index_builder::build_index(source, tracks, movie_ts, opts)
}

/// Byte-range source for the lazy walker (a local file, a remote object…).
pub trait RangeReader {
    fn read_range(&mut self, offset: u64, length: u64) -> Result<Vec<u8>>;
}

impl<F: FnMut(u64, u64) -> Result<Vec<u8>>> RangeReader for F {
    fn read_range(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        self(offset, length)
    }
}

/// Outcome of the lazy walk: the top-level layout plus the metadata boxes
/// that were fetched along the way (moof bytes are read together with their
/// header so a fragmented file costs ONE read per fragment, not two).
pub struct LazyWalk {
    pub boxes: Vec<TopBox>,
    pub moofs: Vec<(usize, Vec<u8>)>, // (index into boxes, full moof bytes)
}

/// Walk the top-level box structure with tiny ranged reads, fetching every
/// `moof` box body on the way (bounded by `MOOF_MAX`).
pub fn walk_top_boxes(reader: &mut dyn RangeReader, size: u64) -> Result<LazyWalk> {
    let mut boxes = Vec::new();
    let mut moofs = Vec::new();
    let mut off = 0u64;
    let mut pending: Option<Vec<u8>> = None; // header bytes already fetched
    while off + 8 <= size {
        let hdr = match pending.take() {
            Some(h) => h,
            None => reader.read_range(off, 16.min(size - off))?,
        };
        let b = parse_top_header(&hdr, off, size)?;
        if &b.box_type == b"moof" {
            if b.size > MOOF_MAX {
                return Err(CoreError::Parse(format!(
                    "moof at {} is {} bytes (>{MOOF_MAX} cap) — corrupt or exotic",
                    b.offset, b.size
                )));
            }
            // one read: the whole moof plus the next box's header
            let want = (b.size + 16).min(size - off);
            let bytes = reader.read_range(off, want)?;
            if (bytes.len() as u64) < b.size {
                return Err(CoreError::Eof {
                    offset: off,
                    needed: b.size as usize,
                });
            }
            let rest = bytes[b.size as usize..].to_vec();
            moofs.push((boxes.len(), bytes[..b.size as usize].to_vec()));
            if rest.len() >= 8 {
                pending = Some(rest);
            }
            if moofs.len() > MAX_MOOFS {
                return Err(CoreError::Parse(format!("more than {MAX_MOOFS} fragments")));
            }
        }
        off = b.end();
        boxes.push(b);
        if boxes.len() > MAX_TOP_BOXES {
            return Err(CoreError::Parse(
                "box walk aborted: too many top-level boxes (corrupt file?)".into(),
            ));
        }
    }
    Ok(LazyWalk { boxes, moofs })
}

/// Index an object of ANY size through a `RangeReader`. Reads only box
/// headers, the `moov`, and each `moof`.
pub fn index_lazy(
    source: SourceInfo,
    reader: &mut dyn RangeReader,
    opts: &BuildOptions,
) -> Result<MediaIndex> {
    let size = source.size;
    let walk = walk_top_boxes(reader, size)?;
    let moov = walk
        .boxes
        .iter()
        .find(|b| &b.box_type == b"moov")
        .copied()
        .ok_or_else(|| CoreError::Parse("no moov box found (not an MP4?)".into()))?;
    if moov.size > MOOV_MAX {
        return Err(CoreError::Parse(format!(
            "moov is {} bytes (>{MOOV_MAX} cap)",
            moov.size
        )));
    }
    let moov_bytes = reader.read_range(moov.offset, moov.size)?;

    if walk.moofs.is_empty() {
        // Regular source: the moov alone is sufficient — stco/co64 offsets
        // are absolute file offsets, independent of where it was fetched.
        return index_moov_box(source, moov_bytes, moov.offset, opts);
    }

    let moofs: Vec<RemoteMoof> = walk
        .moofs
        .iter()
        .map(|(i, bytes)| RemoteMoof {
            abs_start: walk.boxes[*i].offset,
            abs_end: fragment_end(&walk.boxes, *i, size),
            bytes: bytes.clone(),
        })
        .collect();
    build_fragmented_index_from_moofs(source, &moov_bytes, moov.offset, &moofs, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SourceKind;

    /// Index all real fixtures through the PURE entry point — exactly what
    /// the admin panel does with R2 ranged reads.
    #[test]
    fn indexes_all_real_fixtures() {
        if !std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/output/fixtures-real")).exists() {
            eprintln!("SKIP: run scripts/gen_fixtures.sh first");
            return;
        }
        for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/output/fixtures-real")).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().map(|e| e != "mp4").unwrap_or(true) {
                continue;
            }
            let src = std::fs::read(&p).unwrap();
            let size = src.len() as u64;
            let ranges = head_and_tail_ranges(size);
            let head = &src[..ranges.head_len as usize];
            let tail = if ranges.tail_len > 0 {
                Some((
                    &src[(size - ranges.tail_len) as usize..],
                    size - ranges.tail_len,
                ))
            } else {
                None
            };
            let idx = index_bytes(
                SourceInfo {
                    key: p.file_name().unwrap().to_string_lossy().to_string(),
                    size,
                    etag: None,
                },
                head,
                0,
                tail,
                &BuildOptions::default(),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            assert!(idx.duration_ms > 0, "{}: zero duration", p.display());
            assert!(!idx.segments.is_empty(), "{}: no segments", p.display());

            // the lazy walker must produce the SAME index from ranged reads
            let mut reader = |off: u64, len: u64| -> Result<Vec<u8>> {
                let end = (off + len).min(size) as usize;
                Ok(src[off as usize..end].to_vec())
            };
            let lazy = index_lazy(
                SourceInfo {
                    key: p.file_name().unwrap().to_string_lossy().to_string(),
                    size,
                    etag: None,
                },
                &mut reader,
                &BuildOptions::default(),
            )
            .unwrap_or_else(|e| panic!("lazy {}: {e}", p.display()));
            assert_eq!(lazy, idx, "{}: lazy index differs", p.display());

            // the worker's in-place moov path must agree for regular sources
            if idx.kind == SourceKind::Regular {
                let (h, _) = crate::moov::find_moov(&src, 0).unwrap();
                let moov_box = src[h.start as usize..h.end() as usize].to_vec();
                let leaned = index_moov_box(
                    SourceInfo {
                        key: p.file_name().unwrap().to_string_lossy().to_string(),
                        size,
                        etag: None,
                    },
                    moov_box,
                    h.start,
                    &BuildOptions::default(),
                )
                .unwrap_or_else(|e| panic!("moov-box {}: {e}", p.display()));
                assert_eq!(leaned, idx, "{}: moov-box index differs", p.display());
            }
        }
    }

    /// The moov-box path refuses non-moov buffers and fragmented moovs.
    #[test]
    fn moov_box_path_rejects_wrong_input() {
        let f = crate::testmp4::fragmented_two_track(2);
        let (h, _) = crate::moov::find_moov(&f, 0).unwrap();
        let moov_box = f[h.start as usize..h.end() as usize].to_vec();
        let src = SourceInfo {
            key: "f.mp4".into(),
            size: f.len() as u64,
            etag: None,
        };
        assert!(index_moov_box(src.clone(), moov_box, h.start, &Default::default()).is_err());
        assert!(index_moov_box(src, f[..32].to_vec(), 0, &Default::default()).is_err());
    }

    /// moov-at-end sources must be indexed from the TAIL buffer only —
    /// the head (mdat start) contains no moov.
    #[test]
    fn indexes_moov_at_end_via_tail() {
        if !std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/output/fixtures-real/moovend_heavy.mp4")).exists() {
            eprintln!("SKIP: fixtures missing");
            return;
        }
        let src = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/output/fixtures-real/moovend_heavy.mp4")).unwrap();
        let size = src.len() as u64;
        let head = &src[..65536.min(src.len())];
        let tail_len = 32768.min(src.len());
        let tail_base = size - tail_len as u64;
        assert!(
            crate::moov::find_moov(head, 0).is_err(),
            "fixture should have moov at end"
        );
        let tail = &src[tail_base as usize..];
        let idx = index_bytes(
            SourceInfo {
                key: "m.mp4".into(),
                size,
                etag: None,
            },
            head,
            0,
            Some((tail, tail_base)),
            &BuildOptions::default(),
        )
        .unwrap();
        assert!(idx.duration_ms > 29_000 && idx.duration_ms < 31_000);
        assert_eq!(idx.kind, SourceKind::Regular);
    }

    /// Garbage input must produce a clean error, never a panic (admin panel
    /// feeds arbitrary uploaded bytes here).
    #[test]
    fn rejects_garbage() {
        let err = index_bytes(
            SourceInfo {
                key: "g".into(),
                size: 16,
                etag: None,
            },
            &[0u8; 16],
            0,
            None,
            &BuildOptions::default(),
        );
        assert!(err.is_err());
        let mut reader = |_o: u64, len: u64| -> Result<Vec<u8>> { Ok(vec![0u8; len as usize]) };
        assert!(index_lazy(
            SourceInfo {
                key: "g".into(),
                size: 64,
                etag: None
            },
            &mut reader,
            &Default::default()
        )
        .is_err());
    }

    /// Fragmented source indexed through the pure entry point must produce
    /// kind=Fragmented with a usable moov_range for the /init route.
    #[test]
    fn fragmented_gets_moov_range() {
        if !std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/output/fixtures-real/fragmented.mp4")).exists() {
            eprintln!("SKIP: fixtures missing");
            return;
        }
        let src = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/output/fixtures-real/fragmented.mp4")).unwrap();
        let ranges = head_and_tail_ranges(src.len() as u64);
        let idx = index_bytes(
            SourceInfo {
                key: "f.mp4".into(),
                size: src.len() as u64,
                etag: None,
            },
            &src[..ranges.head_len as usize],
            0,
            None,
            &BuildOptions::default(),
        )
        .unwrap();
        assert_eq!(idx.kind, SourceKind::Fragmented);
        let mr = idx.moov_range.expect("moov_range recorded");
        assert_eq!(mr.offset, 28); // right after ftyp (28 bytes in fixtures)
        assert!(mr.length > 0);
    }

    /// The lazy walker on the synthetic fragmented fixture: one read per
    /// fragment (moof + next header), no mdat bytes.
    #[test]
    fn lazy_walk_reads_only_metadata() {
        let src = crate::testmp4::fragmented_two_track(4);
        let size = src.len() as u64;
        let mut reads: Vec<(u64, u64)> = Vec::new();
        let mut reader = |off: u64, len: u64| -> Result<Vec<u8>> {
            reads.push((off, len));
            let end = (off + len).min(size) as usize;
            Ok(src[off as usize..end].to_vec())
        };
        let idx = index_lazy(
            SourceInfo {
                key: "f.mp4".into(),
                size,
                etag: None,
            },
            &mut reader,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(idx.kind, SourceKind::Fragmented);
        assert_eq!(idx.segments.len(), 4);
        let total: u64 = reads.iter().map(|(_, l)| *l).sum();
        assert!(total < size / 2, "read {total} of {size} bytes");
        // the walk is: ftyp hdr, moov hdr, moov body, then per fragment a
        // header read + one body read (which also yields the mdat header)
        assert!(reads.len() <= 3 + 2 * 4, "{} reads", reads.len());
    }
}
