// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Case B media segments: builds moof(traf/trun per track) + mdat from a
//! MediaIndex segment. The caller supplies each track's payload bytes.

use crate::bytes::ByteWriter;
use crate::error::{CoreError, Result};
use crate::schema::*;

/// `sample_depends_on = 2` (does not depend on others), sync sample.
pub const FLAG_SYNC: u32 = 0x0200_0000;
/// `sample_depends_on = 1`, `sample_is_non_sync_sample = 1`.
pub const FLAG_NON_SYNC: u32 = 0x0101_0000;

#[derive(Debug, Clone)]
pub struct Sample2 {
    pub size: u32,
    pub duration: u32,
    pub cts_delta: i64,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct TrackRun {
    pub track_id: u32,
    pub is_video: bool,
    pub base_dts: i64,
    pub samples: Vec<Sample2>,
    pub payload: Vec<u8>,
}

impl TrackRun {
    pub fn payload_len(&self) -> usize {
        self.samples.iter().map(|s| s.size as usize).sum()
    }
}

pub(crate) fn decode_deltas(d: &[i64]) -> Vec<i64> {
    let mut out = Vec::with_capacity(d.len());
    let mut acc: i64 = 0;
    for (i, v) in d.iter().enumerate() {
        acc = if i == 0 { *v } else { acc + *v };
        out.push(acc);
    }
    out
}

/// EXACT decode time of `st`'s first sample in segment `n`, in the track's
/// own timescale — the value `tfdt` must carry.
///
/// Newer indexes record it (`start_dts`). Older ones don't; for the primary
/// track it equals the segment's `start_dts`, and for any other track it is
/// the sum of that track's durations over all previous segments — runs are
/// contiguous by construction, so this reconstruction is exact.
pub fn track_start_dts(idx: &MediaIndex, n: usize, st: &SegmentTrack) -> i64 {
    if let Some(s) = st.start_dts {
        return s;
    }
    let Some(seg) = idx.segments.get(n) else {
        return 0;
    };
    if st.track_id == idx.primary_track_id {
        return seg.start_dts;
    }
    idx.segments[..n]
        .iter()
        .flat_map(|s| s.tracks.iter())
        .filter(|t| t.track_id == st.track_id)
        .map(|t| t.duration as i64)
        .sum()
}

/// Expand an index SegmentTrack into concrete samples (payload excluded).
pub fn expand_track_run(idx: &MediaIndex, st: &SegmentTrack, base_dts: i64) -> Result<TrackRun> {
    let n = st.sample_count as usize;
    let sizes: Vec<u32> = match (st.uniform_sample_size, &st.sample_size_deltas) {
        (Some(u), _) => vec![u; n],
        (None, Some(d)) => decode_deltas(d).iter().map(|v| *v as u32).collect(),
        (None, None) => return Err(CoreError::Parse("no sizes in SegmentTrack".into())),
    };
    let durs: Vec<u32> = match (&st.sample_duration_deltas, st.first_sample_duration) {
        (Some(d), _) => decode_deltas(d).iter().map(|v| *v as u32).collect(),
        (None, d) => vec![d; n],
    };
    let track = idx.track(st.track_id);
    let is_video = track
        .map(|t| t.track_type == TrackType::Video)
        .unwrap_or(false);
    // Composition offsets: the source's ctts values minus the edit-list
    // media_time, so presentation starts at t=0 without shipping an `elst`
    // (trun v1 carries the resulting negative offsets). Tracks without
    // composition offsets (audio) are left untouched — ffmpeg's fragmented
    // muxer makes the same choice for AAC priming.
    let mut cts: Vec<i64> = decode_deltas(&st.cts_deltas);
    if !cts.is_empty() && cts.iter().any(|c| *c != 0) {
        let shift = track.map(|t| t.edit_media_time).unwrap_or(0);
        for c in cts.iter_mut() {
            *c -= shift;
        }
    }
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let size = *sizes
            .get(i)
            .ok_or_else(|| CoreError::Parse("size list short".into()))?;
        let duration = *durs
            .get(i)
            .ok_or_else(|| CoreError::Parse("duration list short".into()))?;
        let cts_delta = cts.get(i).copied().unwrap_or(0);
        let flags = if !is_video || i == 0 || st.sync_samples.contains(&(i as u32)) {
            FLAG_SYNC
        } else {
            FLAG_NON_SYNC
        };
        samples.push(Sample2 {
            size,
            duration,
            cts_delta,
            flags,
        });
    }
    Ok(TrackRun {
        track_id: st.track_id,
        is_video,
        base_dts,
        samples,
        payload: Vec::new(),
    })
}

/// All runs of segment `n` (video first, as stored), payloads empty.
/// For a split index (`idx.is_split()`) the header carries no runs — use
/// `segment_runs_of` with the segment loaded from its shard.
pub fn segment_runs(idx: &MediaIndex, n: usize) -> Result<Vec<TrackRun>> {
    let seg = idx
        .segments
        .get(n)
        .ok_or(CoreError::SegmentOutOfRange(n, idx.segments.len()))?;
    if seg.tracks.is_empty() && idx.is_split() {
        return Err(CoreError::Parse(format!(
            "segment {n}: runs live in shard {} of a split index",
            crate::split::shard_of(idx, n).map(|(k, _)| k).unwrap_or(0)
        )));
    }
    segment_runs_of(idx, seg, n)
}

/// Runs of `seg`, which is segment `n` of `idx` — `seg` may come from the
/// index itself or from a shard of a split index (the header supplies the
/// tracks and, for legacy indexes without `start_dts`, the prior segments).
pub fn segment_runs_of(idx: &MediaIndex, seg: &Segment, n: usize) -> Result<Vec<TrackRun>> {
    let mut runs = Vec::with_capacity(seg.tracks.len());
    for st in &seg.tracks {
        if idx.track(st.track_id).is_none() {
            continue;
        }
        let base = track_start_dts(idx, n, st);
        runs.push(expand_track_run(idx, st, base)?);
    }
    Ok(runs)
}

/// Slice payload bytes for a run out of the source buffer (contiguous).
pub fn attach_payload(mut run: TrackRun, first_offset: u64, source: &[u8]) -> Result<TrackRun> {
    let total = run.payload_len();
    let start = first_offset as usize;
    if start + total > source.len() {
        return Err(CoreError::Parse("payload out of bounds".into()));
    }
    run.payload = source[start..start + total].to_vec();
    Ok(run)
}

/// Build one media segment: `moof + mdat`, in the given track order.
///
/// # What the output looks like
///
/// ```text
/// moof
///   mfhd  (sequence number = segment index + 1)
///   traf ── one per track ──────────────────────────────
///     tfhd  flags = default-base-is-moof | sample-description-index
///           (+ default-sample-flags when the run's tail is uniform)
///     tfdt  baseMediaDecodeTime (v1, 64-bit) = this track's start dts
///     trun  v0/v1, flags = data-offset + per-sample duration + size
///           (+ first-sample-flags | per-sample flags, + composition
///           offsets when the track has any)
///   traf (audio) ...
/// mdat
///   [track0 payload bytes][track1 payload bytes]...
/// ```
///
/// The key invariant: each `trun.data_offset` (signed, relative to the moof
/// start because `default-base-is-moof` is set) points at its track's payload
/// inside the single shared `mdat`. Video first, then audio — the muxer
/// semantics follow the traf order, so `runs` MUST be ordered video-first
/// when both tracks are present (the index already orders them that way).
///
/// # Sample flags
///
/// Audio samples are all sync samples. Video sample 0 is a sync sample
/// (segments are cut on keyframes) and so is every index listed in the
/// index's `sync_samples`. Flags are written the compact way: a uniform
/// tail goes into `tfhd.default_sample_flags` with sample 0 in the trun's
/// `first_sample_flags`; anything irregular falls back to per-sample flags.
///
/// # CTS (composition time) and B-frames
///
/// H.264 with B-frames stores presentation order ≠ decode order. The run
/// carries per-sample `cts_delta` (cts − dts, already shifted by the edit
/// list); when any is non-zero we set the `0x800` trun flag and emit a
/// `version 1` trun whose composition offsets are SIGNED — that is how CMAF
/// packagers express "frame 0 presents at t=0" without an edit list.
pub fn build_segment(runs: &[TrackRun], sequence: u32) -> Result<Vec<u8>> {
    for run in runs {
        if run.payload.len() != run.payload_len() {
            return Err(CoreError::Parse(format!(
                "track {}: payload is {} bytes, samples describe {}",
                run.track_id,
                run.payload.len(),
                run.payload_len()
            )));
        }
    }
    let mut w = ByteWriter::new();
    let moof = w.open_box(b"moof");
    let h = w.open_box(b"mfhd");
    w.u32(0);
    w.u32(sequence);
    w.close_box(h)?;
    // (run index, position of its trun.data_offset field) for emitted trafs
    let mut emitted: Vec<(usize, usize)> = Vec::new();
    for (ri, run) in runs.iter().enumerate() {
        if run.samples.is_empty() {
            continue;
        }
        let first_flags = run.samples[0].flags;
        let tail_flags = run.samples.get(1).map(|s| s.flags).unwrap_or(first_flags);
        let uniform_tail = run.samples[1..].iter().all(|s| s.flags == tail_flags);

        let traf = w.open_box(b"traf");
        let th = w.open_box(b"tfhd");
        // 0x020000 default-base-is-moof, 0x02 sample-description-index,
        // 0x20 default-sample-flags
        let tfhd_flags = 0x020002 | if uniform_tail { 0x20 } else { 0 };
        w.u32(tfhd_flags);
        w.u32(run.track_id);
        w.u32(1); // sample description index
        if uniform_tail {
            w.u32(tail_flags);
        }
        w.close_box(th)?;

        let td = w.open_box(b"tfdt");
        w.u32(0x01000000);
        w.u64(run.base_dts.max(0) as u64);
        w.close_box(td)?;

        let has_cts = run.samples.iter().any(|s| s.cts_delta != 0);
        let per_sample_flags = !uniform_tail;
        let first_sample_flags = uniform_tail && first_flags != tail_flags;
        let mut flags: u32 = 0x000301; // data-offset + duration + size
        if has_cts {
            flags |= 0x000800;
        }
        if per_sample_flags {
            flags |= 0x000400;
        }
        if first_sample_flags {
            flags |= 0x000004;
        }
        let version: u32 = if has_cts { 1 } else { 0 };
        let tr = w.open_box(b"trun");
        w.u32((version << 24) | flags);
        w.u32(run.samples.len() as u32);
        let doff_pos = w.len();
        w.i32(0); // data_offset, patched below
        if first_sample_flags {
            w.u32(first_flags);
        }
        for s in &run.samples {
            w.u32(s.duration);
            w.u32(s.size);
            if per_sample_flags {
                w.u32(s.flags);
            }
            if has_cts {
                w.i32(s.cts_delta as i32);
            }
        }
        w.close_box(tr)?;
        w.close_box(traf)?;
        emitted.push((ri, doff_pos));
    }
    w.close_box(moof)?;

    // mdat: one concatenated payload per emitted track, in traf order. Each
    // trun's data_offset points at its track's payload start, relative to
    // the moof box start (which is offset 0 of this buffer).
    let mdat = w.open_box(b"mdat");
    let mut payload_off = w.len() as i64;
    for (ri, pos) in emitted {
        let run = &runs[ri];
        w.buf[pos..pos + 4].copy_from_slice(&(payload_off as i32).to_be_bytes());
        w.bytes(&run.payload);
        payload_off += run.payload.len() as i64;
    }
    w.close_box(mdat)?;
    Ok(w.into_vec())
}

/// Build segment `n` of `idx` from per-track payloads supplied in the same
/// order as `segment_runs(idx, n)` returns them. The one-stop entry point
/// the worker, the tests and the examples all share.
pub fn build_segment_from_index(
    idx: &MediaIndex,
    n: usize,
    payloads: Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    let seg = idx
        .segments
        .get(n)
        .ok_or(CoreError::SegmentOutOfRange(n, idx.segments.len()))?;
    if seg.tracks.is_empty() && idx.is_split() {
        return Err(CoreError::Parse(format!(
            "segment {n}: runs live in a shard — use build_segment_with"
        )));
    }
    build_segment_with(idx, seg, n, payloads)
}

/// Same as `build_segment_from_index` with the segment supplied explicitly
/// — the worker's entry point for split indexes (header + one shard).
pub fn build_segment_with(
    idx: &MediaIndex,
    seg: &Segment,
    n: usize,
    payloads: Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut runs = segment_runs_of(idx, seg, n)?;
    if payloads.len() != runs.len() {
        return Err(CoreError::Parse(format!(
            "segment {n}: {} payloads for {} runs",
            payloads.len(),
            runs.len()
        )));
    }
    for (run, payload) in runs.iter_mut().zip(payloads) {
        run.payload = payload;
    }
    build_segment(&runs, n as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_builder::{build_index, BuildOptions};
    use crate::moov::find_moov;
    use crate::schema::SourceInfo;

    fn two_segment_index() -> (MediaIndex, Vec<u8>) {
        let f = crate::testmp4::regular_two_track();
        let (moov_h, moov) = find_moov(&f, 0).unwrap();
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
        (idx, f)
    }

    fn payloads_for(idx: &MediaIndex, n: usize, f: &[u8]) -> Vec<Vec<u8>> {
        idx.segments[n]
            .tracks
            .iter()
            .map(|st| {
                st.byte_ranges
                    .iter()
                    .flat_map(|r| {
                        f[r.offset as usize..(r.offset + r.length) as usize]
                            .iter()
                            .copied()
                    })
                    .collect()
            })
            .collect()
    }

    fn parse_moof_of(bytes: &[u8]) -> Vec<crate::parse_frag::FragTrack> {
        let mut moof_h: Option<crate::boxes::BoxHeader> = None;
        crate::boxes::walk_top_level(bytes, 0, |h| {
            if &h.box_type == b"moof" {
                moof_h = Some(h);
                return false;
            }
            true
        })
        .unwrap();
        let moof_h = moof_h.unwrap();
        let moof = crate::boxes::content_of(bytes, 0, &moof_h).to_vec();
        crate::parse_frag::parse_moof(
            &moof,
            moof_h.content_start,
            moof_h.start,
            &Default::default(),
        )
        .unwrap()
    }

    #[test]
    fn segment_roundtrip_parses_back() {
        let (idx, f) = two_segment_index();
        let seg = &idx.segments[1];
        let bytes = build_segment_from_index(&idx, 1, payloads_for(&idx, 1, &f)).unwrap();
        let tracks = parse_moof_of(&bytes);
        assert_eq!(tracks.len(), 2);
        let v = tracks.iter().find(|t| t.track_id == 1).unwrap();
        let st_v = seg.tracks.iter().find(|st| st.track_id == 1).unwrap();
        assert_eq!(v.samples.len(), st_v.sample_count as usize);
        assert_eq!(v.base_dts, seg.start_dts);
        let a = tracks.iter().find(|t| t.track_id == 2).unwrap();
        let st_a = seg.tracks.iter().find(|st| st.track_id == 2).unwrap();
        assert_eq!(a.samples.len(), st_a.sample_count as usize);
        // audio tfdt is the EXACT audio start (previous segment's duration),
        // not the video dts re-labelled in the audio timescale
        assert_eq!(a.base_dts, idx.segments[0].tracks[1].duration as i64);
        // sample offsets point inside the mdat and cover the payloads exactly
        let video_bytes: u64 = v.samples.iter().map(|s| s.size as u64).sum();
        assert_eq!(a.samples[0].offset, v.samples[0].offset + video_bytes);
        assert_eq!(
            a.samples.last().unwrap().offset + a.samples.last().unwrap().size as u64,
            bytes.len() as u64
        );
        // mfhd sequence = n + 1
        assert_eq!(&bytes[20..24], &2u32.to_be_bytes());
    }

    #[test]
    fn sync_flags_and_trun_versions() {
        let (idx, f) = two_segment_index();
        let bytes = build_segment_from_index(&idx, 0, payloads_for(&idx, 0, &f)).unwrap();
        // fixture video has a constant ctts offset (30 ticks) and an edit
        // media_time of 0 → trun version 1 with the raw offsets
        let tracks = parse_moof_of(&bytes);
        let v = tracks.iter().find(|t| t.track_id == 1).unwrap();
        assert!(v.samples.iter().all(|s| s.cts_delta == 30));
        // keyframe at index 12 inside the segment → per-sample flags path
        let st = &idx.segments[0].tracks[0];
        let run = expand_track_run(&idx, st, 0).unwrap();
        assert_eq!(run.samples[0].flags, FLAG_SYNC);
        assert_eq!(run.samples[1].flags, FLAG_NON_SYNC);
        assert_eq!(run.samples[12].flags, FLAG_SYNC);
        // audio: everything sync
        let ra = expand_track_run(&idx, &idx.segments[0].tracks[1], 0).unwrap();
        assert!(ra.samples.iter().all(|s| s.flags == FLAG_SYNC));
    }

    #[test]
    fn edit_list_shift_produces_negative_offsets() {
        let (mut idx, _f) = two_segment_index();
        idx.tracks[0].edit_media_time = 30;
        let run = expand_track_run(&idx, &idx.segments[0].tracks[0], 0).unwrap();
        assert!(run.samples.iter().all(|s| s.cts_delta == 0));
        idx.tracks[0].edit_media_time = 60;
        let run = expand_track_run(&idx, &idx.segments[0].tracks[0], 0).unwrap();
        assert!(run.samples.iter().all(|s| s.cts_delta == -30));
        // and build_segment writes them as v1 signed offsets
        let mut runs = vec![run];
        runs[0].payload = vec![0u8; runs[0].payload_len()];
        let bytes = build_segment(&runs, 1).unwrap();
        let t = parse_moof_of(&bytes);
        assert_eq!(t[0].samples[0].cts_delta, -30);
    }

    #[test]
    fn payload_mismatch_is_rejected() {
        let (idx, f) = two_segment_index();
        let mut p = payloads_for(&idx, 0, &f);
        p[0].pop();
        assert!(build_segment_from_index(&idx, 0, p).is_err());
        assert!(build_segment_from_index(&idx, 99, vec![]).is_err());
    }

    #[test]
    fn legacy_index_reconstructs_audio_start() {
        let (mut idx, _) = two_segment_index();
        for seg in idx.segments.iter_mut() {
            for st in seg.tracks.iter_mut() {
                st.start_dts = None;
            }
        }
        let a1 = &idx.segments[1].tracks[1];
        assert_eq!(
            track_start_dts(&idx, 1, a1),
            idx.segments[0].tracks[1].duration as i64
        );
        let v1 = &idx.segments[1].tracks[0];
        assert_eq!(track_start_dts(&idx, 1, v1), idx.segments[1].start_dts);
    }
}
