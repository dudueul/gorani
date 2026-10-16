// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! moov container walking: mvhd, trak, mdia/minf/stbl assembly into ParsedTrack.

use crate::boxes::{find_child, BoxHeader, MOOV};
use crate::bytes::ByteReader;
use crate::error::{CoreError, Result};
use crate::sample_entry::{parse_sample_entry, SampleEntry};
use crate::schema::TrackType;
use crate::tables::{expand_sample_tables, Sample, SampleTables, SizeTable};

pub struct ParsedTrack {
    pub id: u32,
    pub track_type: TrackType,
    pub codec_string: String,
    pub timescale: u32,
    pub duration: u64,
    /// `media_time` of the first non-empty edit (0 when the track has no
    /// edit list). See `schema::Track::edit_media_time`.
    pub edit_media_time: i64,
    pub width: u16,
    pub height: u16,
    pub sample_entry: Vec<u8>,
    pub samples: Vec<Sample>,
}

/// Locate the moov box in `buf` (whose first byte sits at absolute
/// `buf_base`).
///
/// # Two scan modes
///
/// * `buf_base == 0`: a clean top-level box walk is reliable — box sizes
///   chain correctly from the file start.
/// * Mid-file buffers (the admin panel's *tail* read of a moov-at-end file),
///   or a file whose top-level chain is broken by trailing garbage: we scan
///   for the byte pattern `[u32 size]["moov"]` and VERIFY each candidate by
///   walking its children and requiring an `mvhd` — a false positive inside
///   media bytes is ~2^-32 per position and is rejected by the verification.
pub fn find_moov(buf: &[u8], buf_base: u64) -> Result<(BoxHeader, Vec<u8>)> {
    if buf_base == 0 {
        if let Some(h) = walk_for_moov(buf, buf_base) {
            return Ok(extract_moov(buf, buf_base, h));
        }
    }
    let h = scan_for_moov(buf, buf_base)?;
    Ok(extract_moov(buf, buf_base, h))
}

/// walk-based moov finder used when the buffer starts at a box boundary
fn walk_for_moov(buf: &[u8], buf_base: u64) -> Option<BoxHeader> {
    let mut found = None;
    let _ = crate::boxes::walk_top_level(buf, buf_base, |h| {
        if &h.box_type == MOOV {
            found = Some(h);
            return false;
        }
        true
    });
    found
}

/// Linear scan for a verified `moov` header anywhere in the buffer.
fn scan_for_moov(buf: &[u8], buf_base: u64) -> Result<BoxHeader> {
    let mut i = 0usize;
    while i + 8 <= buf.len() {
        if &buf[i + 4..i + 8] == MOOV {
            let size32 = u32::from_be_bytes(buf[i..i + 4].try_into().unwrap()) as u64;
            let (size, hdr) = if size32 == 1 && i + 16 <= buf.len() {
                (
                    u64::from_be_bytes(buf[i + 8..i + 16].try_into().unwrap()),
                    16u64,
                )
            } else {
                (size32, 8u64)
            };
            // plausible: at least a header plus one child header
            if size >= hdr + 8 {
                let abs = buf_base + i as u64;
                let h = BoxHeader {
                    box_type: *MOOV,
                    start: abs,
                    content_start: abs + hdr,
                    size,
                };
                if verify_moov(buf, buf_base, &h) {
                    return Ok(h);
                }
            }
        }
        i += 1;
    }
    Err(CoreError::Parse("no moov box found".into()))
}

/// A candidate moov is real when its children chain cleanly and include an
/// `mvhd`. Truncated moovs (extending past the buffer) still verify — the
/// caller decides whether the slice it gets is enough.
fn verify_moov(buf: &[u8], buf_base: u64, h: &BoxHeader) -> bool {
    let rel = (h.content_start - buf_base) as usize;
    let end = ((h.end() - buf_base) as usize).min(buf.len());
    if rel > end {
        return false;
    }
    let content = &buf[rel..end];
    let mut has_mvhd = false;
    let ok = crate::boxes::walk_top_level(content, h.content_start, |c| {
        if &c.box_type == b"mvhd" {
            has_mvhd = true;
        }
        true
    })
    .is_ok();
    ok && has_mvhd
}

/// Slice the moov children out of the buffer once its header is located.
fn extract_moov(buf: &[u8], buf_base: u64, h: BoxHeader) -> (BoxHeader, Vec<u8>) {
    let rel = (h.content_start - buf_base) as usize;
    let end = ((h.end() - buf_base) as usize).min(buf.len());
    (h, buf[rel..end].to_vec())
}

pub fn parse_mvhd(content: &[u8]) -> Result<u32> {
    let mut r = ByteReader::new(content);
    let version = r.u8()?;
    r.skip(3);
    r.skip(if version == 0 { 8 } else { 16 });
    let ts = r.u32()?;
    if ts == 0 {
        return Err(CoreError::Parse("mvhd timescale is 0".into()));
    }
    Ok(ts)
}

fn parse_tkhd(content: &[u8]) -> Result<(u32, u16, u16)> {
    let mut r = ByteReader::new(content);
    let version = r.u8()?;
    r.skip(3);
    r.skip(if version == 0 { 8 } else { 16 }); // creation+modification
    let id = r.u32()?;
    r.skip(4);
    r.skip(if version == 0 { 4 } else { 8 }); // duration
    r.skip(8); // reserved
    r.skip(2); // layer
    r.skip(2); // alternate group
    r.skip(2); // volume
    r.skip(2); // reserved
    r.skip(36); // matrix
    let width = (r.u32()? >> 16) as u16;
    let height = (r.u32()? >> 16) as u16;
    Ok((id, width, height))
}

fn parse_mdhd(content: &[u8]) -> Result<(u32, u64)> {
    let mut r = ByteReader::new(content);
    let version = r.u8()?;
    r.skip(3);
    r.skip(if version == 0 { 8 } else { 16 });
    let timescale = r.u32()?;
    let duration = if version == 0 {
        r.u32()? as u64
    } else {
        r.u64()?
    };
    if timescale == 0 {
        return Err(CoreError::Parse("mdhd timescale is 0".into()));
    }
    Ok((timescale, duration))
}

fn parse_hdlr(content: &[u8]) -> Result<TrackType> {
    let mut r = ByteReader::new(content);
    r.skip(8); // version/flags + pre_defined
    let handler = r.u32()?;
    let h = handler.to_be_bytes();
    match &h {
        b"vide" => Ok(TrackType::Video),
        b"soun" => Ok(TrackType::Audio),
        _ => Err(CoreError::Unsupported(format!(
            "track handler {:?}",
            String::from_utf8_lossy(&h)
        ))),
    }
}

/// `media_time` of the first non-empty edit. An "empty edit" (media_time
/// == -1) is a delay before the track starts; we do not model delays, so
/// they are skipped and a following real edit is used instead.
pub fn parse_elst_media_time(content: &[u8]) -> Result<i64> {
    let mut r = ByteReader::new(content);
    let version = r.u8()?;
    r.skip(3);
    let count = r.u32()?;
    let entry = if version == 0 { 12 } else { 20 };
    let count = (count as usize).min(r.remaining() / entry);
    for _ in 0..count {
        let media_time = if version == 0 {
            r.skip(4); // segment_duration
            r.i32()? as i64
        } else {
            r.skip(8);
            r.u64()? as i64
        };
        r.skip(4); // media_rate (16.16)
        if media_time >= 0 {
            return Ok(media_time);
        }
    }
    Ok(0)
}

/// content = trak box content; content_start = absolute offset of content[0].
/// Everything in a `trak` except the expanded sample table — cheap to
/// parse (box headers + sample entry), so callers can decide which tracks
/// deserve the per-sample work.
struct TrakParts<'a> {
    id: u32,
    track_type: TrackType,
    timescale: u32,
    duration: u64,
    edit_media_time: i64,
    se: SampleEntry,
    tables: SampleTables<'a>,
}

fn locate_trak<'a>(trak_content: &'a [u8], trak_start: u64) -> Result<TrakParts<'a>> {
    let (_h, tkhd) = find_child(trak_content, trak_start, b"tkhd")?
        .ok_or_else(|| CoreError::Parse("trak missing tkhd".into()))?;
    let (id, _width, _height) = parse_tkhd(tkhd)?;

    // Edit list lives at trak/edts/elst (NOT under mdia).
    let mut edit_media_time: i64 = 0;
    if let Some((edts_h, edts)) = find_child(trak_content, trak_start, b"edts")? {
        if let Some((_eh, elst)) = find_child(edts, edts_h.content_start, b"elst")? {
            edit_media_time = parse_elst_media_time(elst)?;
        }
    }

    let (mdia_h, mdia) = find_child(trak_content, trak_start, b"mdia")?
        .ok_or_else(|| CoreError::Parse("trak missing mdia".into()))?;
    let mdia_start = mdia_h.content_start;

    let (_mh, mdhd) = find_child(mdia, mdia_start, b"mdhd")?
        .ok_or_else(|| CoreError::Parse("mdia missing mdhd".into()))?;
    let (timescale, duration) = parse_mdhd(mdhd)?;

    let (_hh, hdlr) = find_child(mdia, mdia_start, b"hdlr")?
        .ok_or_else(|| CoreError::Parse("mdia missing hdlr".into()))?;
    let track_type = parse_hdlr(hdlr)?;

    let (minf_h, minf) = find_child(mdia, mdia_start, b"minf")?
        .ok_or_else(|| CoreError::Parse("mdia missing minf".into()))?;
    let (stbl_h, stbl) = find_child(minf, minf_h.content_start, b"stbl")?
        .ok_or_else(|| CoreError::Parse("minf missing stbl".into()))?;
    let stbl_start = stbl_h.content_start;

    let (_dh, stsd) = find_child(stbl, stbl_start, b"stsd")?
        .ok_or_else(|| CoreError::Parse("stbl missing stsd".into()))?;
    let mut r = ByteReader::new(stsd);
    r.skip(4);
    let entry_count = r.u32()?;
    if entry_count == 0 {
        return Err(CoreError::Parse("stsd has no entries".into()));
    }
    let entry_size = r.u32()? as usize;
    if entry_size < 8 || 8 + entry_size > stsd.len() {
        return Err(CoreError::Parse("bad stsd entry size".into()));
    }
    let se: SampleEntry = parse_sample_entry(&stsd[8..8 + entry_size])?;

    let stts = find_child(stbl, stbl_start, b"stts")?
        .ok_or_else(|| CoreError::Parse("stbl missing stts".into()))?;
    let sizes = match find_child(stbl, stbl_start, b"stsz")? {
        Some((_, c)) => SizeTable::from_stsz(c)?,
        None => match find_child(stbl, stbl_start, b"stz2")? {
            Some((_, c)) => SizeTable::from_stz2(c)?,
            None => return Err(CoreError::Parse("stbl missing stsz/stz2".into())),
        },
    };
    let stsc = find_child(stbl, stbl_start, b"stsc")?
        .ok_or_else(|| CoreError::Parse("stbl missing stsc".into()))?;
    let (co64, stco) = match find_child(stbl, stbl_start, b"co64")? {
        Some(x) => (true, Some(x)),
        None => (false, find_child(stbl, stbl_start, b"stco")?),
    };
    let stco = stco.ok_or_else(|| CoreError::Parse("stbl missing stco/co64".into()))?;
    let ctts = find_child(stbl, stbl_start, b"ctts")?;
    let stss = find_child(stbl, stbl_start, b"stss")?;

    Ok(TrakParts {
        id,
        track_type,
        timescale,
        duration,
        edit_media_time,
        se,
        tables: SampleTables {
            stts: stts.1,
            sizes,
            chunk_offsets: stco.1,
            co64,
            stsc: stsc.1,
            ctts: ctts.map(|(_, c)| c),
            stss: stss.map(|(_, s)| s),
        },
    })
}

fn finish_trak(p: TrakParts) -> Result<ParsedTrack> {
    let samples = expand_sample_tables(&p.tables)?;
    Ok(ParsedTrack {
        id: p.id,
        track_type: p.track_type,
        codec_string: p.se.codec_string.clone(),
        timescale: p.timescale,
        duration: p.duration,
        edit_media_time: p.edit_media_time,
        width: p.se.width,
        height: p.se.height,
        sample_entry: p.se.box_bytes,
        samples,
    })
}

pub fn parse_trak(trak_content: &[u8], trak_start: u64) -> Result<ParsedTrack> {
    finish_trak(locate_trak(trak_content, trak_start)?)
}

/// `(rel_start, rel_end, content_start)` of every `trak` child of the moov.
fn trak_ranges(moov: &[u8], moov_content_start: u64) -> Result<Vec<(usize, usize, u64)>> {
    let mut out = Vec::new();
    crate::boxes::walk_children(moov, moov_content_start, |h| {
        if &h.box_type == b"trak" {
            let rel = (h.content_start - moov_content_start) as usize;
            let end = ((h.end() - moov_content_start) as usize).min(moov.len());
            if rel <= end {
                out.push((rel, end, h.content_start));
            }
        }
        true
    })?;
    Ok(out)
}

pub fn parse_mvhd_pub(moov_content: &[u8], moov_start: u64) -> Result<u32> {
    let (_h, mvhd) = find_child(moov_content, moov_start, b"mvhd")?
        .ok_or_else(|| CoreError::Parse("moov missing mvhd".into()))?;
    parse_mvhd(mvhd)
}

/// Every parseable track, sample tables expanded. Tracks that fail to
/// parse (unsupported handler, missing tables) are skipped.
pub fn parse_tracks(moov: &[u8], moov_content_start: u64) -> Result<Vec<ParsedTrack>> {
    let mut tracks = Vec::new();
    for (rel, end, cs) in trak_ranges(moov, moov_content_start)? {
        if let Ok(t) = parse_trak(&moov[rel..end], cs) {
            tracks.push(t);
        }
    }
    Ok(tracks)
}

/// Only the tracks the index will serve — the primary (video, else the
/// longest track) plus the first audio track — chosen from cheap header
/// facts *before* any sample table is expanded, so dubbed/commentary audio
/// tracks never cost per-sample memory. Returned in served order (see
/// `index_builder::select_served`). Tracks with empty sample tables
/// (fragmented sources) are never selected: an empty result means "nothing
/// regular to serve", not an error.
pub fn parse_tracks_served(moov: &[u8], moov_content_start: u64) -> Result<Vec<ParsedTrack>> {
    let mut parts: Vec<Option<TrakParts>> = Vec::new();
    for (rel, end, cs) in trak_ranges(moov, moov_content_start)? {
        if let Ok(p) = locate_trak(&moov[rel..end], cs) {
            parts.push(Some(p));
        }
    }
    let facts: Vec<crate::index_builder::TrackFacts> = parts
        .iter()
        .map(|p| {
            let p = p.as_ref().expect("unconsumed");
            crate::index_builder::TrackFacts {
                track_type: p.track_type,
                samples: p.tables.sizes.len(),
                codec: &p.se.codec_string,
            }
        })
        .collect();
    let order = crate::index_builder::select_served(&facts);
    let mut out = Vec::with_capacity(order.len());
    for i in order {
        let p = parts[i].take().expect("served indices are unique");
        let id = p.id;
        out.push(finish_trak(p).map_err(|e| CoreError::Parse(format!("track {id}: {e}")))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::ByteWriter;

    #[test]
    fn elst_first_non_empty_edit() {
        // v0: [empty edit (media_time -1)] then [media_time 2002]
        let mut w = ByteWriter::new();
        w.u32(0);
        w.u32(2);
        w.u32(500);
        w.i32(-1);
        w.u32(0x00010000);
        w.u32(10_000);
        w.i32(2002);
        w.u32(0x00010000);
        assert_eq!(parse_elst_media_time(w.as_slice()).unwrap(), 2002);
        // v1 single edit
        let mut w = ByteWriter::new();
        w.u8(1);
        w.u24(0);
        w.u32(1);
        w.u64(10_000);
        w.u64(1024);
        w.u32(0x00010000);
        assert_eq!(parse_elst_media_time(w.as_slice()).unwrap(), 1024);
    }

    #[test]
    fn scan_rejects_false_positive_and_finds_real_moov() {
        // media bytes containing the "moov" pattern with a plausible size but
        // garbage children, followed by the genuine moov of a fixture
        let real = crate::testmp4::regular_two_track();
        let (real_h, _) = find_moov(&real, 0).unwrap();
        let moov_bytes = real[real_h.start as usize..real_h.end() as usize].to_vec();
        let mut buf = vec![0xAAu8; 64];
        buf.extend_from_slice(&64u32.to_be_bytes());
        buf.extend_from_slice(b"moov");
        buf.extend_from_slice(&[0xBB; 56]);
        let real_pos = buf.len() as u64;
        buf.extend_from_slice(&moov_bytes);
        let (h, content) = find_moov(&buf, 1_000_000).unwrap();
        assert_eq!(h.start, 1_000_000 + real_pos);
        assert_eq!(content.len(), moov_bytes.len() - 8);
    }
}
