// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Fragmented MP4 (moof-driven) scanner → MediaIndex.

use crate::boxes::{fragment_end, TopBox};
use crate::bytes::ByteReader;
use crate::error::{CoreError, Result};
use crate::sample_entry::parse_sample_entry;
use crate::schema::*;

pub struct FragSample {
    pub offset: u64,
    pub size: u32,
    pub duration: u32,
    pub cts_delta: i64,
}

pub struct FragTrack {
    pub track_id: u32,
    pub base_dts: i64,
    pub samples: Vec<FragSample>,
}

pub struct Fragment {
    pub moof_start: u64,
    /// absolute end of the fragment (start of the next non-mdat box)
    pub end: u64,
    pub tracks: Vec<FragTrack>,
}

fn walk_traf(
    traf: &[u8],
    traf_start: u64,
    moof_start: u64,
    trex: &std::collections::HashMap<u32, TrexDefaults>,
) -> Result<Vec<FragTrack>> {
    use crate::boxes::find_child;

    // tfhd
    let (_th, tfhd) = find_child(traf, traf_start, b"tfhd")?
        .ok_or_else(|| CoreError::Parse("traf missing tfhd".into()))?;
    let mut r = ByteReader::new(tfhd);
    let vf = r.u32()?;
    let flags = vf & 0xFFFFFF;
    let track_id = r.u32()?;
    let mut base_data_offset: Option<u64> = None;
    if flags & 0x000001 != 0 {
        base_data_offset = Some(r.u64()?);
    }
    if flags & 0x000002 != 0 {
        r.skip(4); // sample_description_index
    }
    let mut default_dur = trex
        .get(&track_id)
        .map(|t| t.default_sample_duration)
        .unwrap_or(0);
    let mut default_size = trex
        .get(&track_id)
        .map(|t| t.default_sample_size)
        .unwrap_or(0);
    let mut default_flags = trex
        .get(&track_id)
        .map(|t| t.default_sample_flags)
        .unwrap_or(0);
    if flags & 0x000008 != 0 {
        default_dur = r.u32()?;
    }
    if flags & 0x000010 != 0 {
        default_size = r.u32()?;
    }
    if flags & 0x000020 != 0 {
        default_flags = r.u32()?;
    }
    // default-base-is-moof (0x20000) or no explicit base → moof start
    let base = base_data_offset.unwrap_or(moof_start);

    // tfdt
    let mut base_dts: i64 = 0;
    if let Some((_dh, tfdt)) = find_child(traf, traf_start, b"tfdt")? {
        let mut r = ByteReader::new(tfdt);
        let version = r.u8()?;
        r.skip(3);
        base_dts = if version == 1 {
            r.u64()? as i64
        } else {
            r.u32()? as i64
        };
    }

    // truns — a traf may carry several; they are consecutive in the mdat
    // and each normally has its own data_offset. Without one, samples
    // continue right after the previous run.
    let mut samples: Vec<FragSample> = Vec::new();
    let mut running_off: u64 = base;
    let mut err: Option<CoreError> = None;
    crate::boxes::walk_children(traf, traf_start, |h| {
        if &h.box_type == b"trun" {
            let rel = (h.content_start - traf_start) as usize;
            let end_rel = ((h.end() - traf_start) as usize).min(traf.len());
            let content = &traf[rel..end_rel];
            match parse_trun(
                content,
                base,
                running_off,
                default_dur,
                default_size,
                default_flags,
            ) {
                Ok((s, next)) => {
                    samples.extend(s);
                    running_off = next;
                }
                Err(e) => {
                    err = Some(e);
                    return false;
                }
            }
        }
        true
    })?;
    if let Some(e) = err {
        return Err(e);
    }

    Ok(vec![FragTrack {
        track_id,
        base_dts,
        samples,
    }])
}

/// Returns the samples and the offset right after the last one.
fn parse_trun(
    content: &[u8],
    base: u64,
    continue_off: u64,
    default_dur: u32,
    default_size: u32,
    default_flags: u32,
) -> Result<(Vec<FragSample>, u64)> {
    let mut r = ByteReader::new(content);
    let vf = r.u32()?;
    let flags = vf & 0xFFFFFF;
    let count = r.u32()?;
    let data_offset: Option<i32> = if flags & 0x000001 != 0 {
        Some(r.i32()?)
    } else {
        None
    };
    let mut first_flags: Option<u32> = None;
    if flags & 0x000004 != 0 {
        first_flags = Some(r.u32()?);
    }
    let per_dur = flags & 0x000100 != 0;
    let per_size = flags & 0x000200 != 0;
    let per_flags = flags & 0x000400 != 0;
    let per_cts = flags & 0x000800 != 0;
    let entry = 4 * (per_dur as usize + per_size as usize + per_flags as usize + per_cts as usize);
    if entry > 0 && (count as usize).saturating_mul(entry) > r.remaining() {
        return Err(CoreError::Parse(format!(
            "trun: {count} samples exceed box size"
        )));
    }
    if count as usize > crate::tables::MAX_SAMPLES {
        return Err(CoreError::Parse("trun: sample count exceeds cap".into()));
    }

    let mut out = Vec::with_capacity(count as usize);
    let mut running_off: i64 = match data_offset {
        Some(d) => base as i64 + d as i64,
        None => continue_off as i64,
    };
    for i in 0..count {
        let dur = if per_dur { r.u32()? } else { default_dur };
        let size = if per_size { r.u32()? } else { default_size };
        let _fl = if i == 0 {
            if let Some(ff) = first_flags {
                ff
            } else if per_flags {
                r.u32()?
            } else {
                default_flags
            }
        } else if per_flags {
            r.u32()?
        } else {
            default_flags
        };
        let cts = if per_cts { r.i32()? as i64 } else { 0 };
        out.push(FragSample {
            offset: running_off.max(0) as u64,
            size,
            duration: dur,
            cts_delta: cts,
        });
        running_off += size as i64;
    }
    Ok((out, running_off.max(0) as u64))
}

/// Extract trex defaults per track from a moov content slice.
pub fn parse_trex(
    moov: &[u8],
    moov_start: u64,
) -> Result<std::collections::HashMap<u32, TrexDefaults>> {
    use crate::boxes::find_child;
    let mut map = std::collections::HashMap::new();
    if let Some((mvex_h, mvex)) = find_child(moov, moov_start, b"mvex")? {
        crate::boxes::walk_children(mvex, mvex_h.content_start, |h| {
            if &h.box_type == b"trex" {
                let rel = (h.content_start - mvex_h.content_start) as usize;
                let end = ((h.end() - mvex_h.content_start) as usize).min(mvex.len());
                let c = &mvex[rel..end];
                let mut r = ByteReader::new(c);
                if let (Ok(_vf), Ok(track_id), Ok(desc), Ok(dur), Ok(size), Ok(flags)) =
                    (r.u32(), r.u32(), r.u32(), r.u32(), r.u32(), r.u32())
                {
                    map.insert(
                        track_id,
                        TrexDefaults {
                            default_sample_description_index: desc.max(1),
                            default_sample_duration: dur,
                            default_sample_size: size,
                            default_sample_flags: flags,
                        },
                    );
                }
            }
            true
        })?;
    }
    Ok(map)
}

/// Parse one moof (content + absolute start) into per-track sample lists.
pub fn parse_moof(
    moof_content: &[u8],
    content_start: u64,
    moof_box_start: u64,
    trex: &std::collections::HashMap<u32, TrexDefaults>,
) -> Result<Vec<FragTrack>> {
    use crate::boxes::walk_children;
    let mut tracks = Vec::new();
    walk_children(moof_content, content_start, |h| {
        if &h.box_type == b"traf" {
            let rel = (h.content_start - content_start) as usize;
            let end = ((h.end() - content_start) as usize).min(moof_content.len());
            let content = &moof_content[rel..end];
            if let Ok(mut t) = walk_traf(content, h.content_start, moof_box_start, trex) {
                tracks.append(&mut t);
            }
        }
        true
    })?;
    if tracks.is_empty() {
        return Err(CoreError::Parse("moof has no traf".into()));
    }
    Ok(tracks)
}

// ---------------------------------------------------------------------------
// Track skeletons (fragmented sources have empty sample tables)
// ---------------------------------------------------------------------------

pub struct TrackSkeleton {
    pub id: u32,
    pub track_type: TrackType,
    pub codec_string: String,
    pub timescale: u32,
    pub duration: u64,
    pub width: u16,
    pub height: u16,
    pub stsd_entry: Vec<u8>,
}

pub fn parse_track_skeletons(moov: &[u8], moov_start: u64) -> Result<Vec<TrackSkeleton>> {
    let mut out = Vec::new();
    crate::boxes::walk_children(moov, moov_start, |h| {
        if &h.box_type == b"trak" {
            let rel = (h.content_start - moov_start) as usize;
            let end = ((h.end() - moov_start) as usize).min(moov.len());
            if rel <= end {
                if let Ok(sk) = parse_trak_skeleton(&moov[rel..end], h.content_start) {
                    out.push(sk);
                }
            }
        }
        true
    })?;
    if out.is_empty() {
        return Err(CoreError::Parse("no track skeletons in moov".into()));
    }
    Ok(out)
}

fn parse_trak_skeleton(trak: &[u8], trak_start: u64) -> Result<TrackSkeleton> {
    use crate::boxes::find_child;

    let (_h, tkhd) = find_child(trak, trak_start, b"tkhd")?
        .ok_or_else(|| CoreError::Parse("trak missing tkhd".into()))?;
    let mut r = ByteReader::new(tkhd);
    let version = r.u8()?;
    r.skip(3);
    r.skip(if version == 0 { 8 } else { 16 });
    let id = r.u32()?;

    let (mh, mdia) = find_child(trak, trak_start, b"mdia")?
        .ok_or_else(|| CoreError::Parse("trak missing mdia".into()))?;
    let (timescale, duration) = {
        let (_h2, mdhd) = find_child(mdia, mh.content_start, b"mdhd")?
            .ok_or_else(|| CoreError::Parse("mdia missing mdhd".into()))?;
        let mut r = ByteReader::new(mdhd);
        let version = r.u8()?;
        r.skip(3);
        r.skip(if version == 0 { 8 } else { 16 });
        let ts = r.u32()?;
        let dur = if version == 0 {
            r.u32()? as u64
        } else {
            r.u64()?
        };
        if ts == 0 {
            return Err(CoreError::Parse("mdhd timescale is 0".into()));
        }
        (ts, dur)
    };
    let track_type = {
        let (_h2, hdlr) = find_child(mdia, mh.content_start, b"hdlr")?
            .ok_or_else(|| CoreError::Parse("mdia missing hdlr".into()))?;
        let mut r = ByteReader::new(hdlr);
        r.skip(8);
        let handler = r.u32()?;
        match &handler.to_be_bytes() {
            b"vide" => TrackType::Video,
            b"soun" => TrackType::Audio,
            _ => return Err(CoreError::Unsupported("fragmented handler".into())),
        }
    };
    let (entry, codec) = {
        let (m_h, minf) = find_child(mdia, mh.content_start, b"minf")?
            .ok_or_else(|| CoreError::Parse("mdia missing minf".into()))?;
        let (s_h, stbl) = find_child(minf, m_h.content_start, b"stbl")?
            .ok_or_else(|| CoreError::Parse("minf missing stbl".into()))?;
        let (_d_h, stsd) = find_child(stbl, s_h.content_start, b"stsd")?
            .ok_or_else(|| CoreError::Parse("stbl missing stsd".into()))?;
        let mut r = ByteReader::new(stsd);
        r.skip(4);
        let _count = r.u32()?;
        let esize = r.u32()? as usize;
        if esize < 8 || 8 + esize > stsd.len() {
            return Err(CoreError::Parse("bad stsd entry".into()));
        }
        let entry = &stsd[8..8 + esize];
        let se = parse_sample_entry(entry)?;
        (entry.to_vec(), se.codec_string)
    };
    let (width, height) = tkhd_dims(tkhd);
    Ok(TrackSkeleton {
        id,
        track_type,
        codec_string: codec,
        timescale,
        duration,
        width,
        height,
        stsd_entry: entry,
    })
}

fn tkhd_dims(tkhd: &[u8]) -> (u16, u16) {
    let mut r = ByteReader::new(tkhd);
    let version = r.u8().unwrap_or(0);
    r.skip(3);
    r.skip(if version == 0 { 8 } else { 16 }); // creation + modification
    r.skip(4); // track_ID
    r.skip(4); // reserved
    r.skip(if version == 0 { 4 } else { 8 }); // duration
    r.skip(8); // reserved[2]
    r.skip(2 + 2 + 2 + 2 + 36); // layer, alt group, volume, reserved, matrix
    let w = (r.u32().unwrap_or(0) >> 16) as u16;
    let h = (r.u32().unwrap_or(0) >> 16) as u16;
    (w, h)
}

/// Build the fragmented MediaIndex from a buffer covering the whole header
/// region (ftyp+moov+mvex) and ALL fragments' moof boxes. Every moof must be
/// fully inside `buf` (mdat payloads may extend past it); objects larger
/// than the caller's read budget go through `indexer::index_lazy` instead.
pub fn build_fragmented_index(
    source: SourceInfo,
    buf: &[u8],
    buf_base: u64,
    _opts: &crate::index_builder::BuildOptions,
) -> Result<MediaIndex> {
    use crate::boxes::walk_top_level;

    let (moov_h, moov) = crate::moov::find_moov(buf, buf_base)?;
    let movie_timescale = crate::moov::parse_mvhd_pub(&moov, moov_h.content_start).unwrap_or(1000);
    let trex = parse_trex(&moov, moov_h.content_start)?;
    let skeletons = parse_track_skeletons(&moov, moov_h.content_start)?;

    // top-level layout (headers only) — mdat payloads may run past the buffer
    let mut boxes: Vec<TopBox> = Vec::new();
    walk_top_level(buf, buf_base, |h| {
        boxes.push(TopBox {
            offset: h.start,
            box_type: h.box_type,
            size: h.size,
            header_len: (h.content_start - h.start) as u8,
        });
        true
    })?;
    let buf_end = buf_base + buf.len() as u64;
    let moof_idx: Vec<usize> = boxes
        .iter()
        .enumerate()
        .filter(|(_, b)| &b.box_type == b"moof")
        .map(|(i, _)| i)
        .collect();
    if moof_idx.is_empty() {
        return Err(CoreError::Parse("no fragments found".into()));
    }

    let mut fragments: Vec<Fragment> = Vec::with_capacity(moof_idx.len());
    for i in moof_idx {
        let b = boxes[i];
        if b.end() > buf_end {
            return Err(CoreError::Parse(format!(
                "moof at {} extends beyond the fetched bytes — index with the lazy walker",
                b.offset
            )));
        }
        let rel = (b.offset + b.header_len as u64 - buf_base) as usize;
        let end_rel = (b.end() - buf_base) as usize;
        let content = &buf[rel..end_rel];
        let tracks = parse_moof(content, b.offset + b.header_len as u64, b.offset, &trex)?;
        fragments.push(Fragment {
            moof_start: b.offset,
            end: fragment_end(&boxes, i, source.size),
            tracks,
        });
    }

    assemble_fragment_index(
        source,
        &trex,
        &skeletons,
        fragments,
        movie_timescale,
        moov_h,
    )
}

/// Shared tail of both fragmented builders: turns parsed fragments into the
/// final `MediaIndex` (segments with compact runs, per-track totals, moov
/// range). Used by:
///   * `build_fragmented_index` — whole-buffer path (CLI, small uploads)
///   * `build_fragmented_index_from_moofs` — lazy ranged-read path (worker
///     and CLI indexing of files larger than the read budget)
fn assemble_fragment_index(
    source: SourceInfo,
    trex: &std::collections::HashMap<u32, TrexDefaults>,
    skeletons: &[TrackSkeleton],
    fragments: Vec<Fragment>,
    movie_timescale: u32,
    moov_header: crate::boxes::BoxHeader,
) -> Result<MediaIndex> {
    let primary_id = primary_track_id(skeletons);
    let mut segments = Vec::with_capacity(fragments.len());
    for f in &fragments {
        let mut seg_tracks = Vec::new();
        let mut start_dts: Option<i64> = None;
        let mut seg_dur: Option<u64> = None;
        for ft in &f.tracks {
            if ft.samples.is_empty() {
                continue;
            }
            let sizes: Vec<u32> = ft.samples.iter().map(|s| s.size).collect();
            let cts: Vec<i64> = ft.samples.iter().map(|s| s.cts_delta).collect();
            let durs: Vec<u32> = ft.samples.iter().map(|s| s.duration).collect();
            let dur_total: u64 = durs.iter().map(|d| *d as u64).sum();
            let uniform_dur = crate::index_builder::uniform_of(&durs);
            seg_tracks.push(SegmentTrack {
                track_id: ft.track_id,
                first_sample: 0,
                sample_count: ft.samples.len() as u32,
                first_sample_duration: uniform_dur.unwrap_or(ft.samples[0].duration),
                duration: dur_total,
                start_dts: Some(ft.base_dts),
                cts_deltas: if cts.iter().all(|c| *c == 0) {
                    Vec::new()
                } else {
                    crate::index_builder::delta_encode_pub(&cts)
                },
                uniform_sample_size: crate::index_builder::uniform_of(&sizes),
                sample_size_deltas: crate::index_builder::deltas_of(&sizes),
                sample_duration_deltas: if uniform_dur.is_some() {
                    None
                } else {
                    Some(crate::index_builder::delta_encode_pub(
                        &durs.iter().map(|d| *d as i64).collect::<Vec<_>>(),
                    ))
                },
                sync_samples: Vec::new(),
                first_sample_offset: ft.samples[0].offset,
                byte_ranges: Vec::new(),
            });
            if ft.track_id == primary_id || start_dts.is_none() {
                start_dts = Some(ft.base_dts);
                seg_dur = Some(dur_total);
            }
        }
        if seg_tracks.is_empty() {
            continue;
        }
        segments.push(Segment {
            start_dts: start_dts.unwrap_or(0),
            duration: seg_dur.unwrap_or(0),
            tracks: seg_tracks,
            fragment_range: Some(ByteRange {
                offset: f.moof_start,
                length: f.end.min(source.size).saturating_sub(f.moof_start),
            }),
        });
    }

    if segments.is_empty() {
        return Err(CoreError::Parse("no fragments parsed".into()));
    }

    let primary = &skeletons[primary_index(skeletons)];

    // fragmented sources often carry duration=0 in mdhd (empty_moov) —
    // derive per-track totals from the fragment runs instead
    let mut totals: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    for seg in &segments {
        for st in &seg.tracks {
            *totals.entry(st.track_id).or_insert(0) += st.duration;
        }
    }
    let track_duration =
        |id: u32, mdhd: u64| -> u64 { totals.get(&id).copied().unwrap_or(0).max(mdhd) };

    let primary_total = track_duration(primary.id, primary.duration);
    let duration_ms = (primary_total as u128 * 1000 / primary.timescale.max(1) as u128) as u64;

    let schema_tracks: Vec<Track> = skeletons
        .iter()
        .map(|s| Track {
            id: s.id,
            track_type: s.track_type,
            codec_string: s.codec_string.clone(),
            timescale: s.timescale,
            duration: track_duration(s.id, s.duration),
            base_dts: 0,
            edit_media_time: 0,
            width: s.width,
            height: s.height,
            stsd_b64: crate::index_builder::b64_encode_pub(&s.stsd_entry),
            trex: trex.get(&s.id).copied(),
            movie_timescale,
        })
        .collect();

    Ok(MediaIndex {
        version: INDEX_VERSION,
        source,
        kind: SourceKind::Fragmented,
        primary_track_id: primary_id,
        tracks: schema_tracks,
        duration_ms,
        segments,
        sidx_range: None,
        moov_range: Some(ByteRange {
            offset: moov_header.start,
            length: moov_header.size,
        }),
        runs: None,
        media_bytes: None,
    })
}

/// Metadata for one remotely-fetched moof box. `abs_end` bounds the
/// fragment: the start of the next non-mdat top-level box after this moof,
/// i.e. fragment_range = [abs_start, abs_end).
#[derive(Debug, Clone)]
pub struct RemoteMoof {
    pub abs_start: u64,
    pub abs_end: u64,
    /// the complete moof box bytes (header + children)
    pub bytes: Vec<u8>,
}

/// Incremental fragmented-index builder for objects too large to read into
/// memory: the caller fetches the moov and each moof with ranged reads and
/// hands them over here; sample data (mdat) is NEVER touched. Sample byte
/// offsets inside each moof remain ABSOLUTE because `parse_moof` anchors
/// trun data_offsets at the moof's true file offset, not a buffer position.
pub fn build_fragmented_index_from_moofs(
    source: SourceInfo,
    moov_box: &[u8], // complete moov box bytes (header + children)
    moov_abs: u64,
    moofs: &[RemoteMoof],
    _opts: &crate::index_builder::BuildOptions,
) -> Result<MediaIndex> {
    if moofs.is_empty() {
        return Err(CoreError::Parse("no fragments found".into()));
    }
    let (moov_h, moov) = crate::moov::find_moov(moov_box, moov_abs)?;
    let movie_timescale = crate::moov::parse_mvhd_pub(&moov, moov_h.content_start).unwrap_or(1000);
    let trex = parse_trex(&moov, moov_h.content_start)?;
    let skeletons = parse_track_skeletons(&moov, moov_h.content_start)?;

    let mut fragments: Vec<Fragment> = Vec::with_capacity(moofs.len());
    for m in moofs {
        let hdr = crate::boxes::parse_top_header(&m.bytes, m.abs_start, u64::MAX)?;
        let hl = hdr.header_len as usize;
        if m.bytes.len() < hl {
            return Err(CoreError::Parse("moof shorter than its header".into()));
        }
        let tracks = parse_moof(&m.bytes[hl..], m.abs_start + hl as u64, m.abs_start, &trex)?;
        fragments.push(Fragment {
            moof_start: m.abs_start,
            end: m.abs_end,
            tracks,
        });
    }

    assemble_fragment_index(
        source,
        &trex,
        &skeletons,
        fragments,
        movie_timescale,
        moov_h,
    )
}

fn primary_index(skeletons: &[TrackSkeleton]) -> usize {
    skeletons
        .iter()
        .position(|s| s.track_type == TrackType::Video)
        .unwrap_or(0)
}

fn primary_track_id(skeletons: &[TrackSkeleton]) -> u32 {
    skeletons[primary_index(skeletons)].id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::ByteWriter;

    /// A trailing `mfra` (ffmpeg writes one) must not end up inside the last
    /// fragment's byte range.
    #[test]
    fn last_fragment_excludes_trailing_boxes() {
        let mut f = crate::testmp4::fragmented_two_track(3);
        let file_len = f.len() as u64;
        let mut w = ByteWriter::new();
        let m = w.open_box(b"mfra");
        w.zeros(24);
        w.close_box(m).unwrap();
        f.extend_from_slice(w.as_slice());
        let idx = build_fragmented_index(
            SourceInfo {
                key: "f.mp4".into(),
                size: f.len() as u64,
                etag: None,
            },
            &f,
            0,
            &Default::default(),
        )
        .unwrap();
        let last = idx.segments.last().unwrap().fragment_range.unwrap();
        assert_eq!(last.end(), file_len);
        // per-track exact start dts recorded from tfdt
        let a = &idx.segments[1].tracks[1];
        assert_eq!(a.start_dts, Some(96 * 1024));
        assert_eq!(idx.segments[1].start_dts, 24 * 100);
        assert_eq!(idx.tracks[0].movie_timescale, 1000);
    }

    #[test]
    fn multiple_truns_per_traf_are_all_read() {
        // build a traf with two truns of 2 samples each (default size/dur from tfhd)
        let mut w = ByteWriter::new();
        let traf = w.open_box(b"traf");
        let th = w.open_box(b"tfhd");
        w.u32(0x020018); // default-base-is-moof + default dur + default size
        w.u32(1);
        w.u32(100);
        w.u32(64);
        w.close_box(th).unwrap();
        for k in 0..2 {
            let tr = w.open_box(b"trun");
            w.u32(0x000001); // data offset only
            w.u32(2);
            w.i32(1000 + k * 128);
            w.close_box(tr).unwrap();
        }
        w.close_box(traf).unwrap();
        let bytes = w.into_vec();
        let content = &bytes[8..];
        let tracks = walk_traf(content, 8, 0, &Default::default()).unwrap();
        assert_eq!(tracks[0].samples.len(), 4);
        assert_eq!(tracks[0].samples[2].offset, 1128);
        assert_eq!(tracks[0].samples[3].offset, 1192);
    }
}
