// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Builds `MediaIndex` from parsed tracks: segment cut points + compact
//! per-segment sample runs.

use crate::error::{CoreError, Result};
use crate::moov::ParsedTrack;
use crate::schema::*;
use crate::tables::Sample;

const DEFAULT_SEGMENT_MS: u64 = 6000;

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub target_segment_ms: u64,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            target_segment_ms: DEFAULT_SEGMENT_MS,
        }
    }
}

/// Cumulative dts, len = n+1 (cum[0]=0).
pub fn cumulative_dts(samples: &[Sample]) -> Vec<i64> {
    let mut cum = Vec::with_capacity(samples.len() + 1);
    let mut acc: i64 = 0;
    cum.push(0);
    for s in samples {
        acc += s.duration as i64;
        cum.push(acc);
    }
    cum
}

fn delta_encode(values: &[i64]) -> Vec<i64> {
    let mut out = Vec::with_capacity(values.len());
    let mut prev: Option<i64> = None;
    for v in values {
        match prev {
            None => out.push(*v),
            Some(p) => out.push(*v - p),
        }
        prev = Some(*v);
    }
    out
}

fn delta_encode_sizes(sizes: &[u32]) -> (Option<u32>, Option<Vec<i64>>) {
    if sizes.is_empty() {
        return (None, None);
    }
    let first = sizes[0];
    if sizes.iter().all(|s| *s == first) {
        return (Some(first), None);
    }
    let v: Vec<i64> = sizes.iter().map(|s| *s as i64).collect();
    (None, Some(delta_encode(&v)))
}

/// Segment sample indices into cut points aligned to keyframes.
/// Returns indices: 0 = c0 < c1 < ... < n.
///
/// Every cut lands on a keyframe. When the target duration is reached but
/// no later keyframe exists (a long trailing GOP), the current segment is
/// extended to the end of the track rather than cut on a non-keyframe —
/// a segment that starts on a P/B frame cannot be decoded standalone.
fn cut_points(samples: &[Sample], target_dts: i64) -> Vec<usize> {
    let cum = cumulative_dts(samples);
    let n = samples.len();
    let has_kf = samples.iter().any(|s| s.keyframe);
    let mut cuts: Vec<usize> = vec![0];
    let mut i = 0usize;
    while i < n {
        let seg_start = cum[i];
        let mut j = i;
        while j < n && cum[j + 1] - seg_start < target_dts {
            j += 1;
        }
        if j >= n {
            break;
        }
        let mut cut = j + 1;
        if has_kf {
            let mut k = cut;
            while k < n && !samples[k].keyframe {
                k += 1;
            }
            cut = k; // == n when no later keyframe exists → final segment
        }
        if cut >= n {
            break;
        }
        cuts.push(cut);
        i = cut;
    }
    if *cuts.last().unwrap_or(&0) != n {
        cuts.push(n);
    }
    cuts
}

/// Merge consecutive samples into contiguous byte ranges.
///
/// WHY this exists: for Case B (regular MP4 sources) the worker must fetch the
/// *raw sample bytes* of one track's portion of a segment from R2 using ranged
/// reads. Within an ISO-BMFF chunk, samples are contiguous, but real muxers
/// interleave audio chunks between video chunks, so the video samples of one
/// segment are typically spread over several non-adjacent file regions.
/// Storing one `[offset..offset+total]` range per track is therefore wrong for
/// any real-world file — ffmpeg, for example, writes interleaved chunks.
///
/// This function walks the segment's samples in order and coalesces samples
/// whose file offsets are adjacent (next.offset == prev.offset + prev.size)
/// into one `ByteRange`. The result is 1 range for perfectly packed files
/// (our synthetic fixtures) and several ranges for interleaved files
/// (typically one per GOP-sized chunk). The worker reads the union of all
/// ranges (see `readplan`) and slices each track's payload out in order,
/// which reproduces the exact sample byte stream for the `mdat`.
fn merge_ranges(samples: &[Sample]) -> Vec<ByteRange> {
    let mut out: Vec<ByteRange> = Vec::new();
    for s in samples {
        match out.last_mut() {
            Some(r) if r.offset + r.length == s.offset => r.length += s.size as u64,
            _ => out.push(ByteRange {
                offset: s.offset,
                length: s.size as u64,
            }),
        }
    }
    out
}

/// Build the compact per-segment description for samples `[from, to)` of one
/// track. Everything here is *delta-encoded* so the index.json stays small:
/// sizes/durations/CTS offsets are stored as first-value-or-run + deltas and
/// are re-expanded by `moof_builder::expand_track_run` at serve time.
fn segment_run(track: &ParsedTrack, cum: &[i64], from: usize, to: usize) -> SegmentTrack {
    let samples = &track.samples[from..to];

    let sizes: Vec<u32> = samples.iter().map(|s| s.size).collect();
    let (uniform, size_deltas) = delta_encode_sizes(&sizes);

    // Composition offsets (cts - dts) per sample — needed for B-frame video.
    // Stored raw (as in the source); the segment builder applies the
    // edit-list shift at serve time.
    let cts: Vec<i64> = samples.iter().map(|s| s.cts_delta as i64).collect();
    let cts_deltas = if cts.iter().all(|c| *c == 0) {
        Vec::new()
    } else {
        delta_encode(&cts)
    };

    let durs: Vec<i64> = samples.iter().map(|s| s.duration as i64).collect();
    let (uniform_dur, dur_deltas) = if durs.iter().all(|d| *d == durs[0]) {
        (Some(durs[0] as u32), None)
    } else {
        (None, Some(delta_encode(&durs)))
    };

    // Additional sync samples inside the segment (video only; sample 0 is
    // implicitly a sync sample because cuts land on keyframes).
    let sync_samples: Vec<u32> = if track.track_type == TrackType::Video {
        samples
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, s)| s.keyframe)
            .map(|(i, _)| i as u32)
            .collect()
    } else {
        Vec::new()
    };

    SegmentTrack {
        track_id: track.id,
        first_sample: from as u32,
        sample_count: (to - from) as u32,
        first_sample_duration: uniform_dur.unwrap_or(samples[0].duration),
        duration: samples.iter().map(|s| s.duration as u64).sum(),
        start_dts: Some(cum[from]),
        cts_deltas,
        uniform_sample_size: uniform,
        sample_size_deltas: size_deltas,
        sample_duration_deltas: dur_deltas,
        sync_samples,
        first_sample_offset: samples[0].offset,
        byte_ranges: merge_ranges(samples),
    }
}

/// Map a primary-track cut time (in primary timescale) to the sample index of
/// another track whose cumulative dts (in its own timescale) first reaches it.
fn map_cut(other_cum: &[i64], other_ts: u32, primary_ts: u32, primary_cut_dts: i64) -> usize {
    if other_cum.len() <= 1 {
        return 0;
    }
    // integer rescale (no f64 rounding drift on long assets)
    let target = ((primary_cut_dts as i128 * other_ts as i128) / primary_ts as i128) as i64;
    match other_cum.binary_search(&target) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    }
}

/// What `select_served` needs to know about a track — available from the
/// trak headers alone, before any sample table is expanded.
#[derive(Debug, Clone, Copy)]
pub struct TrackFacts<'a> {
    pub track_type: TrackType,
    pub samples: usize,
    /// RFC 6381 codec string (`sample_entry::parse_sample_entry`)
    pub codec: &'a str,
}

/// Which tracks are served, primary first. The primary is the video track
/// with the most samples (or, without video, the longest track), followed
/// by at most ONE audio track: players cannot consume several audio tracks
/// muxed into a single CMAF segment (MSE exposes one audio track per
/// SourceBuffer), so secondary video and additional audio tracks are
/// dropped — publish them as separate audio renditions instead. Among the
/// audio tracks the one browsers can actually decode wins (AAC-LC over
/// Dolby Digital over AAC Main …, see `compat::support_tier`), earliest in
/// file order on ties. Tracks without samples are never selected. Shared
/// with `moov::parse_tracks_served` so the parser can skip the sample
/// tables of tracks that won't be served.
pub fn select_served(tracks: &[TrackFacts]) -> Vec<usize> {
    let Some(primary) = tracks
        .iter()
        .enumerate()
        .filter(|(_, t)| t.samples > 0)
        .max_by_key(|(_, t)| ((t.track_type == TrackType::Video) as u8, t.samples))
        .map(|(i, _)| i)
    else {
        return Vec::new();
    };
    let mut order = vec![primary];
    if tracks[primary].track_type == TrackType::Video {
        let audio = tracks
            .iter()
            .enumerate()
            .filter(|(_, t)| t.track_type == TrackType::Audio && t.samples > 0)
            .min_by_key(|(i, t)| (crate::compat::support_tier(t.codec), *i))
            .map(|(i, _)| i);
        if let Some(a) = audio {
            order.push(a);
        }
    }
    order
}

/// Build the full index for a regular MP4.
pub fn build_index(
    source: SourceInfo,
    tracks: Vec<ParsedTrack>,
    movie_timescale: u32,
    opts: &BuildOptions,
) -> Result<MediaIndex> {
    let facts: Vec<TrackFacts> = tracks
        .iter()
        .map(|t| TrackFacts {
            track_type: t.track_type,
            samples: t.samples.len(),
            codec: &t.codec_string,
        })
        .collect();
    let order = select_served(&facts);
    if order.is_empty() {
        return Err(CoreError::Parse(if tracks.is_empty() {
            "no tracks".into()
        } else {
            "no track has samples".into()
        }));
    }
    for &ti in &order {
        let t = &tracks[ti];
        if t.sample_entry.is_empty() {
            return Err(CoreError::Parse("missing sample entry".into()));
        }
        if t.timescale == 0 {
            return Err(CoreError::Parse(format!("track {} has timescale 0", t.id)));
        }
    }

    let primary_idx = order[0];
    let primary_ts = tracks[primary_idx].timescale;
    let target_dts = (opts.target_segment_ms.max(500) as i128 * primary_ts as i128 / 1000) as i64;
    let cuts = cut_points(&tracks[primary_idx].samples, target_dts);

    // cumulative dts (8 bytes/sample) — served tracks only
    let cums: Vec<Vec<i64>> = tracks
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if order.contains(&i) {
                cumulative_dts(&t.samples)
            } else {
                Vec::new()
            }
        })
        .collect();

    let mut segments = Vec::with_capacity(cuts.len() - 1);
    for w in 0..cuts.len() - 1 {
        let a = cuts[w];
        let b = cuts[w + 1];
        if b <= a {
            continue;
        }
        let mut seg_tracks = Vec::new();
        for &ti in &order {
            let t = &tracks[ti];
            let (from, to) = if ti == primary_idx {
                (a, b)
            } else {
                let from = map_cut(&cums[ti], t.timescale, primary_ts, cums[primary_idx][a]);
                let to = if w + 1 < cuts.len() - 1 {
                    map_cut(&cums[ti], t.timescale, primary_ts, cums[primary_idx][b])
                } else {
                    t.samples.len()
                };
                (from, to)
            };
            if from >= t.samples.len() || to <= from {
                continue;
            }
            seg_tracks.push(segment_run(t, &cums[ti], from, to.min(t.samples.len())));
        }
        if seg_tracks.is_empty() {
            continue;
        }
        let primary_dur = seg_tracks
            .iter()
            .find(|st| st.track_id == tracks[primary_idx].id)
            .map(|st| st.duration)
            .unwrap_or(0);
        segments.push(Segment {
            start_dts: cums[primary_idx][a],
            duration: primary_dur,
            tracks: seg_tracks,
            fragment_range: None,
        });
    }

    if segments.is_empty() {
        return Err(CoreError::Parse("no segments produced".into()));
    }

    let primary = &tracks[primary_idx];
    let total_dts = *cums[primary_idx].last().unwrap();
    let duration_ms = (total_dts as u128 * 1000 / primary.timescale as u128) as u64;

    let mut schema_tracks = Vec::with_capacity(tracks.len());
    // same order as the segment runs: primary first
    for &ti in &order {
        let t = &tracks[ti];
        schema_tracks.push(Track {
            id: t.id,
            track_type: t.track_type,
            codec_string: t.codec_string.clone(),
            timescale: t.timescale,
            duration: t.duration.max(*cums[ti].last().unwrap() as u64),
            base_dts: 0,
            edit_media_time: t.edit_media_time,
            width: t.width,
            height: t.height,
            stsd_b64: b64_encode(&t.sample_entry),
            trex: None,
            movie_timescale,
        });
    }

    Ok(MediaIndex {
        version: INDEX_VERSION,
        source,
        kind: SourceKind::Regular,
        primary_track_id: primary.id,
        tracks: schema_tracks,
        duration_ms,
        segments,
        sidx_range: None,
        moov_range: None,
        runs: None,
        media_bytes: None,
    })
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Public helpers shared with the fragmented-index builder.
pub fn delta_encode_pub(values: &[i64]) -> Vec<i64> {
    delta_encode(values)
}

pub fn uniform_of(sizes: &[u32]) -> Option<u32> {
    if sizes.is_empty() {
        return None;
    }
    let first = sizes[0];
    if sizes.iter().all(|s| *s == first) {
        Some(first)
    } else {
        None
    }
}

pub fn deltas_of(sizes: &[u32]) -> Option<Vec<i64>> {
    if uniform_of(sizes).is_some() || sizes.is_empty() {
        return None;
    }
    let v: Vec<i64> = sizes.iter().map(|s| *s as i64).collect();
    Some(delta_encode(&v))
}

pub fn b64_encode_pub(data: &[u8]) -> String {
    b64_encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(dur: u32, size: u32, off: u64, kf: bool) -> Sample {
        Sample {
            offset: off,
            size,
            duration: dur,
            cts_delta: 0,
            keyframe: kf,
        }
    }

    #[test]
    fn cuts_align_to_keyframes() {
        // 30 samples of 3000 dts, target 9000 (3 samples); keyframes at 0, 12, 24
        let mut samples = Vec::new();
        for i in 0..30 {
            samples.push(sample(3000, 100, (i * 100) as u64, i % 12 == 0));
        }
        let cuts = cut_points(&samples, 9000);
        assert_eq!(cuts, vec![0, 12, 24, 30]);
    }

    #[test]
    fn cuts_all_keyframes_when_no_kf_info() {
        let samples: Vec<Sample> = (0..10).map(|i| sample(1000, 10, i as u64, false)).collect();
        let cuts = cut_points(&samples, 3000);
        assert_eq!(cuts, vec![0, 3, 6, 9, 10]);
    }

    /// A long trailing GOP must be absorbed into the last segment — never
    /// cut on a non-keyframe.
    #[test]
    fn cuts_never_land_on_non_keyframes() {
        let mut samples = Vec::new();
        for i in 0..40 {
            samples.push(sample(1000, 10, i as u64, i == 0 || i == 10));
        }
        let cuts = cut_points(&samples, 5000);
        assert_eq!(cuts, vec![0, 10, 40]);
        for c in &cuts[..cuts.len() - 1] {
            assert!(samples[*c].keyframe);
        }
    }

    #[test]
    fn served_audio_prefers_what_browsers_decode() {
        let t = |track_type, samples, codec| TrackFacts {
            track_type,
            samples,
            codec,
        };
        // Dolby Digital first in file order, AAC-LC second → AAC-LC is served
        let tracks = [
            t(TrackType::Video, 100, "avc1.64001E"),
            t(TrackType::Audio, 200, "ac-3"),
            t(TrackType::Audio, 200, "mp4a.40.2"),
        ];
        assert_eq!(select_served(&tracks), vec![0, 2]);
        // equal tiers → earliest wins; empty tracks never selected
        let tracks = [
            t(TrackType::Audio, 0, "mp4a.40.2"),
            t(TrackType::Video, 100, "avc1.64001E"),
            t(TrackType::Audio, 200, "mp4a.40.2"),
            t(TrackType::Audio, 200, "mp4a.40.5"),
        ];
        assert_eq!(select_served(&tracks), vec![1, 2]);
        // audio-only: the longest track is primary, nothing else
        let tracks = [
            t(TrackType::Audio, 10, "ac-3"),
            t(TrackType::Audio, 20, "mp4a.40.2"),
        ];
        assert_eq!(select_served(&tracks), vec![1]);
    }

    #[test]
    fn delta_encoding() {
        assert_eq!(delta_encode(&[5, 5, 8]), vec![5, 0, 3]);
        assert_eq!(delta_encode_sizes(&[10, 10, 10]).0, Some(10));
        assert_eq!(delta_encode_sizes(&[10, 12, 10]).1, Some(vec![10, 2, -2]));
    }

    #[test]
    fn map_cut_rescales_exactly() {
        // audio cum in 48000 ts, primary 90000 ts: cut at 6s = 540000 → 288000
        let cum: Vec<i64> = (0..=300).map(|i| i * 1024).collect();
        let i = map_cut(&cum, 48000, 90000, 540_000);
        assert!(cum[i] <= 288_000 && cum[i + 1] > 288_000);
    }

    #[test]
    fn segment_runs_carry_exact_start_and_sync_samples() {
        let f = crate::testmp4::regular_two_track();
        let (moov_h, moov) = crate::moov::find_moov(&f, 0).unwrap();
        let tracks = crate::moov::parse_tracks(&moov, moov_h.content_start).unwrap();
        let idx = build_index(
            SourceInfo {
                key: "t.mp4".into(),
                size: f.len() as u64,
                etag: None,
            },
            tracks,
            1000,
            &BuildOptions {
                target_segment_ms: 1500,
            },
        )
        .unwrap();
        // video first, then audio, in every segment
        for seg in &idx.segments {
            assert_eq!(seg.tracks[0].track_id, idx.primary_track_id);
        }
        // fixture keyframes every 12 samples; segments cut at 24 → one extra sync at 12
        assert_eq!(idx.segments[0].tracks[0].sync_samples, vec![12]);
        assert!(idx.segments[0].tracks[1].sync_samples.is_empty());
        // exact audio start dts chains across segments
        let a0 = &idx.segments[0].tracks[1];
        let a1 = &idx.segments[1].tracks[1];
        assert_eq!(a0.start_dts, Some(0));
        assert_eq!(a1.start_dts, Some(a0.duration as i64));
    }
}
