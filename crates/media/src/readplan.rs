// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Read planning for Case B segment assembly.
//!
//! A regular MP4 interleaves audio and video chunks, so one segment's
//! samples for one track sit in many small file regions — and the "gaps"
//! between a video track's regions are exactly the audio regions we also
//! need for the same segment. Issuing one ranged read per region (dozens
//! per segment) costs a storage roundtrip each; instead we take the UNION
//! of every track's ranges, coalesce neighbours whose gap is below a
//! threshold, and read a handful of large blocks — usually exactly one.
//!
//! The functions here are pure so the policy is unit-tested on the host;
//! the worker only does the async reads.

use crate::schema::{ByteRange, Segment};

/// Bytes of unwanted data we accept fetching to save one roundtrip. Storage
/// roundtrips cost tens of milliseconds; 1MB of extra transfer at the edge
/// costs far less.
pub const DEFAULT_MAX_GAP: u64 = 1024 * 1024;
/// Largest single block we are willing to buffer at once.
pub const DEFAULT_MAX_BLOCK: u64 = 64 * 1024 * 1024;

/// Union of all ranges a segment needs, sorted by offset (unmerged).
pub fn segment_ranges(seg: &Segment) -> Vec<ByteRange> {
    let mut all: Vec<ByteRange> = seg
        .tracks
        .iter()
        .flat_map(|t| t.byte_ranges.iter().copied())
        .filter(|r| r.length > 0)
        .collect();
    all.sort_by_key(|r| (r.offset, r.length));
    all
}

/// Coalesce sorted ranges into read blocks. Adjacent or overlapping ranges
/// always merge; ranges separated by a gap merge when the gap is at most
/// `max_gap` and the merged block stays within `max_block`.
pub fn plan_reads(wanted: &[ByteRange], max_gap: u64, max_block: u64) -> Vec<ByteRange> {
    let mut sorted: Vec<ByteRange> = wanted.iter().copied().filter(|r| r.length > 0).collect();
    sorted.sort_by_key(|r| (r.offset, r.length));
    let mut out: Vec<ByteRange> = Vec::new();
    for r in sorted {
        match out.last_mut() {
            Some(b)
                if r.offset <= b.end() + max_gap
                    && r.end().max(b.end()) - b.offset <= max_block =>
            {
                b.length = r.end().max(b.end()) - b.offset;
            }
            _ => out.push(r),
        }
    }
    out
}

/// Slice a wanted range out of fetched blocks. Returns None when no single
/// block fully contains it (cannot happen for blocks produced by
/// `plan_reads` from the same wanted list, but callers stay defensive).
pub fn slice_range(blocks: &[(ByteRange, Vec<u8>)], want: ByteRange) -> Option<&[u8]> {
    for (b, data) in blocks {
        if want.offset >= b.offset && want.end() <= b.end() {
            let start = (want.offset - b.offset) as usize;
            let end = start + want.length as usize;
            return data.get(start..end);
        }
    }
    None
}

/// Concatenate a track's ranges (in order) from fetched blocks.
pub fn concat_ranges(blocks: &[(ByteRange, Vec<u8>)], ranges: &[ByteRange]) -> Option<Vec<u8>> {
    let total: usize = ranges.iter().map(|r| r.length as usize).sum();
    let mut out = Vec::with_capacity(total);
    for r in ranges {
        out.extend_from_slice(slice_range(blocks, *r)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(o: u64, l: u64) -> ByteRange {
        ByteRange {
            offset: o,
            length: l,
        }
    }

    #[test]
    fn interleaved_tracks_collapse_to_one_block() {
        // video ranges with audio in the gaps
        let video = [r(0, 100), r(150, 100), r(300, 100)];
        let audio = [r(100, 50), r(250, 50)];
        let mut all: Vec<ByteRange> = video.iter().chain(audio.iter()).copied().collect();
        all.reverse();
        let plan = plan_reads(&all, 0, u64::MAX);
        assert_eq!(plan, vec![r(0, 400)]);
    }

    #[test]
    fn gaps_respect_threshold_and_block_cap() {
        let all = [r(0, 100), r(200, 100), r(10_000, 100)];
        assert_eq!(
            plan_reads(&all, 100, u64::MAX),
            vec![r(0, 300), r(10_000, 100)]
        );
        assert_eq!(
            plan_reads(&all, 50, u64::MAX),
            vec![r(0, 100), r(200, 100), r(10_000, 100)]
        );
        // block cap prevents merging even with a tiny gap
        assert_eq!(
            plan_reads(&[r(0, 100), r(100, 100)], 0, 150),
            vec![r(0, 100), r(100, 100)]
        );
        // overlapping ranges merge
        assert_eq!(
            plan_reads(&[r(0, 100), r(50, 100)], 0, u64::MAX),
            vec![r(0, 150)]
        );
    }

    #[test]
    fn slicing_reproduces_track_payloads() {
        let data: Vec<u8> = (0..=255u8).collect();
        let blocks = vec![(r(0, 256), data.clone())];
        let video = [r(0, 4), r(8, 4)];
        assert_eq!(
            concat_ranges(&blocks, &video).unwrap(),
            vec![0, 1, 2, 3, 8, 9, 10, 11]
        );
        assert!(slice_range(&blocks, r(250, 10)).is_none());
        let two = vec![
            (r(0, 8), data[..8].to_vec()),
            (r(100, 8), data[100..108].to_vec()),
        ];
        assert_eq!(
            concat_ranges(&two, &[r(4, 4), r(100, 2)]).unwrap(),
            vec![4, 5, 6, 7, 100, 101]
        );
    }
}
