// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Split index layout: a small **header** plus **sample-run shards**.
//!
//! # Why
//!
//! A classic `index.json` carries every sample of every segment. For a
//! feature-length title that is 15–40MB of JSON and 20–50MB once parsed —
//! and the worker used to load, parse and memoize the whole document to
//! serve *one* 6-second segment, inside a 128MB isolate. Splitting makes
//! the per-request cost independent of the title's length:
//!
//! * the **header** is the `MediaIndex` with every `segments[i].tracks`
//!   emptied (≈60 bytes per segment) — everything playlists, MPDs and init
//!   segments need;
//! * the **shards** (`RunsShard`) hold the runs of `shard_segments`
//!   consecutive segments each (≈1MB for 64 six-second segments), and a
//!   media-segment request loads exactly one.
//!
//! # Keys
//!
//! Shard `k` of the index at `KEY.json` lives at `KEY.runs.{id}.{k}.json`
//! (a flat sibling, so every backend — R2 prefixes, S3, Box folders —
//! can hold it). The `id` is minted per build and stored in the header, so
//! shards from an earlier build can never be mixed with a newer header;
//! stale shards are garbage, deleted best-effort after a re-index.
//!
//! Classic single-document indexes stay valid: `runs` is absent and the
//! runs are inline. `merge_shards` turns a header + shards back into one.

use crate::error::{CoreError, Result};
use crate::schema::{MediaIndex, RunsLayout, RunsShard, Segment};

/// Default segments per shard: 64 × 6s ≈ 6.4 minutes of content, ~1MB of
/// JSON for typical H.264 + AAC.
pub const DEFAULT_SHARD_SEGMENTS: u32 = 64;

/// Split a full index into its header and shards. Nothing is copied: the
/// segment runs are moved out of the index into the shards.
pub fn split_index(
    mut idx: MediaIndex,
    shard_segments: u32,
    id: &str,
) -> (MediaIndex, Vec<RunsShard>) {
    let per = shard_segments.max(1) as usize;
    idx.media_bytes = Some(idx.media_bytes());
    let mut shards = Vec::with_capacity(idx.segments.len().div_ceil(per));
    for (k, chunk) in idx.segments.chunks_mut(per).enumerate() {
        let segments = chunk
            .iter_mut()
            .map(|s| Segment {
                start_dts: s.start_dts,
                duration: s.duration,
                tracks: std::mem::take(&mut s.tracks),
                fragment_range: s.fragment_range,
            })
            .collect();
        shards.push(RunsShard {
            version: idx.version,
            first_segment: (k * per) as u32,
            segments,
        });
    }
    idx.runs = Some(RunsLayout {
        shard_segments: per as u32,
        id: id.to_string(),
    });
    (idx, shards)
}

fn stem(index_key: &str) -> &str {
    index_key.strip_suffix(".json").unwrap_or(index_key)
}

/// Storage key of shard `k` for the index stored at `index_key`.
pub fn shard_key(index_key: &str, id: &str, k: u32) -> String {
    format!("{}.runs.{id}.{k}.json", stem(index_key))
}

/// Key prefix shared by every shard of every build of this index — list it
/// to find stale shards after a re-index.
pub fn shard_prefix(index_key: &str) -> String {
    format!("{}.runs.", stem(index_key))
}

/// `(shard, offset within shard)` of segment `n`; `None` for a classic index.
pub fn shard_of(idx: &MediaIndex, n: usize) -> Option<(u32, usize)> {
    let per = idx.runs.as_ref()?.shard_segments.max(1) as usize;
    Some(((n / per) as u32, n % per))
}

/// Number of shards a split header expects (0 for a classic index).
pub fn shard_count(idx: &MediaIndex) -> u32 {
    match idx.runs.as_ref() {
        Some(r) => idx
            .segments
            .len()
            .div_ceil(r.shard_segments.max(1) as usize) as u32,
        None => 0,
    }
}

/// Verify that `shard` is shard `k` of `header`: right position, right
/// segment count, timing identical to the header's.
pub fn check_shard(header: &MediaIndex, k: u32, shard: &RunsShard) -> Result<()> {
    let Some(r) = header.runs.as_ref() else {
        return Err(CoreError::Parse("index is not split".into()));
    };
    let per = r.shard_segments.max(1) as usize;
    let first = k as usize * per;
    if shard.first_segment as usize != first {
        return Err(CoreError::Parse(format!(
            "shard {k} starts at segment {} (expected {first})",
            shard.first_segment
        )));
    }
    let expected = header.segments.len().saturating_sub(first).min(per);
    if shard.segments.len() != expected {
        return Err(CoreError::Parse(format!(
            "shard {k} has {} segments (expected {expected})",
            shard.segments.len()
        )));
    }
    for (i, s) in shard.segments.iter().enumerate() {
        let h = &header.segments[first + i];
        if s.start_dts != h.start_dts || s.duration != h.duration {
            return Err(CoreError::Parse(format!(
                "shard {k} segment {} timing differs from the header (stale shard?)",
                first + i
            )));
        }
    }
    Ok(())
}

/// Rebuild a classic single-document index from a header and ALL its
/// shards (any order).
pub fn merge_shards(mut header: MediaIndex, mut shards: Vec<RunsShard>) -> Result<MediaIndex> {
    let expected = shard_count(&header);
    if shards.len() as u32 != expected {
        return Err(CoreError::Parse(format!(
            "have {} shards, header expects {expected}",
            shards.len()
        )));
    }
    shards.sort_by_key(|s| s.first_segment);
    for (k, shard) in shards.iter().enumerate() {
        check_shard(&header, k as u32, shard)?;
    }
    for shard in shards {
        let first = shard.first_segment as usize;
        for (i, s) in shard.segments.into_iter().enumerate() {
            header.segments[first + i].tracks = s.tracks;
        }
    }
    header.runs = None;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_builder::BuildOptions;
    use crate::schema::SourceInfo;

    fn fixture_index() -> MediaIndex {
        let f = crate::testmp4::regular_two_track();
        let (moov_h, moov) = crate::moov::find_moov(&f, 0).unwrap();
        let tracks = crate::moov::parse_tracks(&moov, moov_h.content_start).unwrap();
        crate::index_builder::build_index(
            SourceInfo {
                key: "t.mp4".into(),
                size: f.len() as u64,
                etag: None,
            },
            tracks,
            1000,
            &BuildOptions {
                target_segment_ms: 500,
            },
        )
        .unwrap()
    }

    #[test]
    fn split_and_merge_round_trip() {
        let full = fixture_index();
        assert!(
            full.segments.len() >= 3,
            "fixture must span several segments"
        );
        let (header, shards) = split_index(full.clone(), 2, "abc");
        assert!(header.is_split());
        assert_eq!(header.segments.len(), full.segments.len());
        assert!(header.segments.iter().all(|s| s.tracks.is_empty()));
        assert_eq!(header.media_bytes(), full.media_bytes());
        assert_eq!(header.estimated_bitrate(), full.estimated_bitrate());
        assert_eq!(shards.len() as u32, shard_count(&header));
        assert_eq!(shard_count(&header), full.segments.len().div_ceil(2) as u32);
        for (k, sh) in shards.iter().enumerate() {
            check_shard(&header, k as u32, sh).unwrap();
        }
        assert_eq!(shard_of(&header, 5), Some((2, 1)));
        assert_eq!(shard_of(&full, 5), None);
        // JSON round trip of both halves, then merge back (shuffled)
        let header2: MediaIndex =
            serde_json::from_slice(&serde_json::to_vec(&header).unwrap()).unwrap();
        let mut shards2: Vec<RunsShard> = shards
            .iter()
            .map(|s| serde_json::from_slice(&serde_json::to_vec(s).unwrap()).unwrap())
            .collect();
        shards2.reverse();
        let merged = merge_shards(header2, shards2).unwrap();
        let mut full_with_mb = full.clone();
        full_with_mb.media_bytes = Some(full.media_bytes());
        assert_eq!(merged, full_with_mb);
    }

    #[test]
    fn stale_or_misplaced_shards_are_rejected() {
        let full = fixture_index();
        let (header, shards) = split_index(full, 2, "abc");
        // wrong position
        assert!(check_shard(&header, 1, &shards[0]).is_err());
        // timing mismatch (a shard from another build)
        let mut stale = shards[0].clone();
        stale.segments[0].duration += 1;
        assert!(check_shard(&header, 0, &stale).is_err());
        // missing shard
        assert!(merge_shards(header.clone(), shards[1..].to_vec()).is_err());
    }

    #[test]
    fn shard_keys_are_flat_siblings() {
        assert_eq!(
            shard_key("movie/1080p.index.json", "ab12", 3),
            "movie/1080p.index.runs.ab12.3.json"
        );
        assert_eq!(
            shard_key("movie/index.json", "x", 0),
            "movie/index.runs.x.0.json"
        );
        assert_eq!(
            shard_key("box:123:1080p.index.json", "x", 0),
            "box:123:1080p.index.runs.x.0.json"
        );
        assert_eq!(
            shard_prefix("movie/1080p.index.json"),
            "movie/1080p.index.runs."
        );
    }
}
