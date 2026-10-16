// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Case B init segment: constructs ftyp + moov (with mvex/trex) from a
//! MediaIndex so players can consume assembled segments without the original
//! moov's sample tables.

use crate::bytes::ByteWriter;
use crate::error::{CoreError, Result};
use crate::schema::*;

fn decode_stsd(t: &Track) -> Result<Vec<u8>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&t.stsd_b64)
        .map_err(|e| CoreError::Parse(format!("bad stsd_b64: {e}")))?;
    if bytes.len() < 8 {
        return Err(CoreError::Parse("stsd entry too small".into()));
    }
    Ok(bytes)
}

fn identity_matrix() -> [u8; 36] {
    let mut m = [0u8; 36];
    m[0..4].copy_from_slice(&0x00010000u32.to_be_bytes());
    m[16..20].copy_from_slice(&0x00010000u32.to_be_bytes());
    m[32..36].copy_from_slice(&0x40000000u32.to_be_bytes());
    m
}

/// `ftyp` for a CMAF-style init segment. Also prepended to source moovs
/// served for fragmented sources (a media segment stream must begin with
/// `ftyp` — Safari and Chrome's MSE both reject a bare `moov`).
pub fn ftyp_bytes() -> Vec<u8> {
    let mut w = ByteWriter::new();
    let f = w.open_box(b"ftyp");
    w.buf.extend_from_slice(b"iso6");
    w.u32(1);
    w.buf.extend_from_slice(b"isomiso6iso2mp41cmfcdash");
    w.close_box(f).unwrap();
    w.into_vec()
}

/// Build the complete init segment (ftyp + moov + mvex/trex).
///
/// # Why a fresh moov instead of the source's?
///
/// The source's `moov` contains a full sample table (stts/stsz/... describing
/// every sample of the original file). An fMP4 init segment must NOT carry
/// those tables — the player reads per-segment timing from `moof/trun`s
/// instead, driven by the `mvex`/`trex` "movie extends" declaration.
/// So we rebuild the container:
///
///   * `stsd` bytes are copied VERBATIM from the source (they carry avcC /
///     hvcC / esds — the codec configuration the player needs),
///   * `tkhd`/`mdhd` metadata (dimensions, timescales, durations) comes from
///     the index (64-bit box versions when a duration overflows 32 bits),
///   * sample tables are replaced by EMPTY stbl tables (Chrome's MP4 parser
///     rejects an init segment whose stbl lacks stts/stsc/stsz/stco, even
///     though ffprobe tolerates it) + mvex/trex defaults,
///   * the mandatory `vmhd`/`smhd` and `dinf/dref` boxes are present —
///     omitting them is tolerated by some players and fatal for others.
///
/// The result is byte-compatible with what shaka/Bento4 emit for CMAF.
pub fn build_init_segment(idx: &MediaIndex) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new();
    w.bytes(&ftyp_bytes());

    let movie_ts = idx
        .tracks
        .first()
        .map(|t| t.movie_timescale)
        .unwrap_or(1000)
        .max(1);
    let movie_duration = idx.duration_ms as u128 * movie_ts as u128 / 1000;
    let m = w.open_box(b"moov");
    let v = w.open_box(b"mvhd");
    let v1 = movie_duration > u32::MAX as u128;
    w.u32(if v1 { 0x01000000 } else { 0 }); // version+flags
    if v1 {
        w.u64(0); // creation
        w.u64(0); // modification
        w.u32(movie_ts);
        w.u64(movie_duration as u64);
    } else {
        w.u32(0);
        w.u32(0);
        w.u32(movie_ts);
        w.u32(movie_duration as u32);
    }
    w.u32(0x00010000); // rate
    w.u16(0x0100); // volume
    w.u16(0); // reserved
    w.u32(0); // reserved
    w.u32(0); // reserved
    w.bytes(&identity_matrix());
    w.bytes(&[0u8; 24]); // pre_defined
    w.u32(idx.tracks.iter().map(|t| t.id).max().unwrap_or(1) + 1);
    w.close_box(v)?;

    for t in &idx.tracks {
        let entry = decode_stsd(t)?;
        let is_video = t.track_type == TrackType::Video;
        let track_movie_dur = t.duration as u128 * movie_ts as u128 / t.timescale.max(1) as u128;
        let trak = w.open_box(b"trak");
        let k = w.open_box(b"tkhd");
        let tk1 = track_movie_dur > u32::MAX as u128;
        w.u32(if tk1 { 0x01000007 } else { 0x00000007 }); // flags: enabled + in_movie + in_preview
        if tk1 {
            w.u64(0);
            w.u64(0);
            w.u32(t.id);
            w.u32(0);
            w.u64(track_movie_dur as u64);
        } else {
            w.u32(0);
            w.u32(0);
            w.u32(t.id);
            w.u32(0);
            w.u32(track_movie_dur as u32);
        }
        w.u32(0); // reserved[2]
        w.u32(0);
        w.u16(0); // layer
        w.u16(0); // alternate group
        w.u16(if is_video { 0 } else { 0x0100 }); // volume
        w.u16(0); // reserved
        w.bytes(&identity_matrix());
        w.u32((t.width as u32) << 16);
        w.u32((t.height as u32) << 16);
        w.close_box(k)?;

        let mdia = w.open_box(b"mdia");
        let mh = w.open_box(b"mdhd");
        let md1 = t.duration > u32::MAX as u64;
        w.u32(if md1 { 0x01000000 } else { 0 });
        if md1 {
            w.u64(0);
            w.u64(0);
            w.u32(t.timescale);
            w.u64(t.duration);
        } else {
            w.u32(0);
            w.u32(0);
            w.u32(t.timescale);
            w.u32(t.duration as u32);
        }
        w.u16(0x55C4); // language "und"
        w.u16(0);
        w.close_box(mh)?;
        let hh = w.open_box(b"hdlr");
        w.u32(0);
        w.u32(0);
        w.bytes(match t.track_type {
            TrackType::Video => b"vide",
            TrackType::Audio => b"soun",
        });
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.bytes(match t.track_type {
            TrackType::Video => b"VideoHandler\0",
            TrackType::Audio => b"SoundHandler\0",
        });
        w.close_box(hh)?;
        let minf = w.open_box(b"minf");
        // media header: vmhd (video) / smhd (sound) — mandatory
        if is_video {
            let vm = w.open_box(b"vmhd");
            w.u32(0x00000001); // version 0, flags 1
            w.u16(0); // graphicsmode
            w.u16(0); // opcolor r
            w.u16(0); // g
            w.u16(0); // b
            w.close_box(vm)?;
        } else {
            let sm = w.open_box(b"smhd");
            w.u32(0);
            w.u16(0); // balance
            w.u16(0); // reserved
            w.close_box(sm)?;
        }
        // data information: one self-contained data reference — mandatory
        let dinf = w.open_box(b"dinf");
        let dref = w.open_box(b"dref");
        w.u32(0);
        w.u32(1);
        let url = w.open_box(b"url ");
        w.u32(0x00000001); // flags: media data in the same file
        w.close_box(url)?;
        w.close_box(dref)?;
        w.close_box(dinf)?;

        let stbl = w.open_box(b"stbl");
        let sh = w.open_box(b"stsd");
        w.u32(0);
        w.u32(1); // one entry
        w.bytes(&entry);
        w.close_box(sh)?;
        let st = w.open_box(b"stts"); // time-to-sample: no entries
        w.u32(0);
        w.u32(0);
        w.close_box(st)?;
        let sc = w.open_box(b"stsc"); // sample-to-chunk: no entries
        w.u32(0);
        w.u32(0);
        w.close_box(sc)?;
        let sz = w.open_box(b"stsz"); // sizes: fixed=0, count=0
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.close_box(sz)?;
        let co = w.open_box(b"stco"); // chunk offsets: no entries
        w.u32(0);
        w.u32(0);
        w.close_box(co)?;
        w.close_box(stbl)?;
        w.close_box(minf)?;
        w.close_box(mdia)?;
        w.close_box(trak)?;
    }

    let mvex = w.open_box(b"mvex");
    for t in &idx.tracks {
        let trex = w.open_box(b"trex");
        w.u32(0); // version+flags
        w.u32(t.id);
        w.u32(1); // sample description index
        w.u32(0); // default duration (set per-sample in trun)
        w.u32(0); // default size
        w.u32(match t.track_type {
            TrackType::Video => crate::moof_builder::FLAG_NON_SYNC,
            TrackType::Audio => crate::moof_builder::FLAG_SYNC,
        });
        w.u32(0); // default cts
        w.close_box(trex)?;
    }
    w.close_box(mvex)?;
    w.close_box(m)?;
    Ok(w.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boxes::find_child;
    use crate::index_builder::{build_index, BuildOptions};
    use crate::moov::find_moov;
    use crate::schema::SourceInfo;

    fn test_index() -> MediaIndex {
        let f = crate::testmp4::regular_two_track();
        let (moov_h, moov) = find_moov(&f, 0).unwrap();
        let tracks = crate::moov::parse_tracks(&moov, moov_h.content_start).unwrap();
        build_index(
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
        .unwrap()
    }

    #[test]
    fn init_segment_parses_back() {
        let idx = test_index();
        let init = build_init_segment(&idx).unwrap();
        assert_eq!(&init[4..8], b"ftyp");
        let (moov_h, moov) = find_moov(&init, 0).unwrap();
        let skeletons =
            crate::parse_frag::parse_track_skeletons(&moov, moov_h.content_start).unwrap();
        let ids: Vec<(u32, u32)> = skeletons.iter().map(|s| (s.id, s.timescale)).collect();
        assert_eq!(ids, vec![(1, 900), (2, 44100)]);
        // stsd entries survive the roundtrip byte-for-byte
        assert_eq!(
            skeletons[0].stsd_entry,
            crate::schema::b64_decode(&idx.tracks[0].stsd_b64)
        );
        assert_eq!(skeletons[0].width, 320);
        assert_eq!(skeletons[0].height, 180);
    }

    #[test]
    fn init_segment_has_mandatory_minf_boxes() {
        let idx = test_index();
        let init = build_init_segment(&idx).unwrap();
        let (moov_h, moov) = find_moov(&init, 0).unwrap();
        let mut seen = Vec::new();
        crate::boxes::walk_children(&moov, moov_h.content_start, |h| {
            if &h.box_type == b"trak" {
                let rel = (h.content_start - moov_h.content_start) as usize;
                let end = ((h.end() - moov_h.content_start) as usize).min(moov.len());
                let trak = &moov[rel..end];
                let (mh, mdia) = find_child(trak, h.content_start, b"mdia").unwrap().unwrap();
                let (fh, minf) = find_child(mdia, mh.content_start, b"minf")
                    .unwrap()
                    .unwrap();
                let has = |t: &[u8; 4]| find_child(minf, fh.content_start, t).unwrap().is_some();
                seen.push((has(b"vmhd"), has(b"smhd"), has(b"dinf"), has(b"stbl")));
            }
            true
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![(true, false, true, true), (false, true, true, true)]
        );
    }

    #[test]
    fn long_durations_use_64bit_headers() {
        let mut idx = test_index();
        idx.tracks[0].timescale = 90_000;
        idx.tracks[0].duration = 90_000u64 * 3600 * 20; // 20h @ 90kHz > u32
        idx.duration_ms = 3600 * 20 * 1000;
        let init = build_init_segment(&idx).unwrap();
        let (moov_h, moov) = find_moov(&init, 0).unwrap();
        let skeletons =
            crate::parse_frag::parse_track_skeletons(&moov, moov_h.content_start).unwrap();
        assert_eq!(skeletons[0].duration, 90_000u64 * 3600 * 20);
    }
}
