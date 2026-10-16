// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Synthesized MP4 fixtures for tests (and docs/examples). Deterministic bytes.

use crate::bytes::ByteWriter;

pub const VIDEO_TS: u32 = 900;
pub const AUDIO_TS: u32 = 44100 / 10; // 4410 Hz ticks at 10 fps audio cadence

fn ftyp(w: &mut ByteWriter) {
    let b = w.open_box(b"ftyp");
    w.buf.extend_from_slice(b"isom");
    w.u32(0x200);
    w.buf.extend_from_slice(b"isomiso2avc1mp41");
    w.close_box(b).unwrap();
}

fn mvhd(w: &mut ByteWriter, duration_movie_ts: u32) {
    let b = w.open_box(b"mvhd");
    w.u32(0); // version+flags
    w.u32(0); // creation
    w.u32(0); // modification
    w.u32(1000); // timescale
    w.u32(duration_movie_ts);
    w.u32(0x00010000); // rate
    w.u16(0x0100); // volume
    w.u16(0); // reserved
    w.u32(0);
    w.u32(0);
    w.buf.extend_from_slice(&[0u8; 36]); // matrix
    w.buf.extend_from_slice(&[0u8; 24]); // pre_defined
    w.u32(2); // next_track_id
    w.close_box(b).unwrap();
}

fn mdhd(w: &mut ByteWriter, timescale: u32, duration: u32) {
    let b = w.open_box(b"mdhd");
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(timescale);
    w.u32(duration);
    w.u16(0x55C4); // lang und
    w.u16(0);
    w.close_box(b).unwrap();
}

fn hdlr(w: &mut ByteWriter, handler: &[u8; 4]) {
    let b = w.open_box(b"hdlr");
    w.u32(0);
    w.u32(0);
    w.buf.extend_from_slice(handler);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.buf.extend_from_slice(b"dhlr");
    w.close_box(b).unwrap();
}

pub fn avc1_entry() -> Vec<u8> {
    let mut w = ByteWriter::new();
    let e = w.open_box(b"avc1");
    w.zeros(6);
    w.u16(1); // data ref
    w.u16(0); // predefined
    w.u16(0); // reserved
    w.zeros(12); // predefined[3]
    w.u16(320); // width
    w.u16(180); // height
    w.u32(0x00480000); // h res
    w.u32(0x00480000); // v res
    w.u32(0); // reserved
    w.u16(1); // frame count
    w.zeros(32); // compressor name
    w.u16(0x0018); // depth
    w.u16(0xFFFF); // pre_defined
                   // avcC
    let c = w.open_box(b"avcC");
    w.u8(1); // version
    w.u8(100); // profile high
    w.u8(0); // compat
    w.u8(31); // level 3.1
    w.u8(0xFF); // 6 reserved + nal size 4
    w.u8(0xE1); // 3 reserved + 1 sps
    w.u16(4);
    w.bytes(&[0x67, 0x64, 0x00, 0x1F]);
    w.u8(1);
    w.u16(2);
    w.bytes(&[0x68, 0xEE]);
    w.close_box(c).unwrap();
    w.close_box(e).unwrap();
    w.into_vec()
}

pub fn mp4a_entry() -> Vec<u8> {
    let mut w = ByteWriter::new();
    let e = w.open_box(b"mp4a");
    w.zeros(6);
    w.u16(1); // data ref
    w.u16(0); // reserved
    w.u16(0); // reserved
    w.u16(2); // channels
    w.u16(16); // sample size
    w.u16(0); // pre_defined
    w.u16(0); // reserved
    w.u32(44100 << 16); // sample rate 16.16
                        // esds
    let s = w.open_box(b"esds");
    w.u32(0); // version+flags
              // ES_Descriptor
    w.u8(0x03);
    w.u8(0x19); // len 25
    w.u16(1); // ES_ID
    w.u8(0); // flags
             // DecoderConfigDescriptor
    w.u8(0x04);
    w.u8(0x11); // len 17
    w.u8(0x40); // oti = MPEG-4 Audio
    w.u8(0x15); // streamType/upStream/reserved
    w.u24(0); // buffer size
    w.u32(128000);
    w.u32(128000);
    // DecoderSpecificInfo
    w.u8(0x05);
    w.u8(0x02); // len 2
    w.u8(0x12);
    w.u8(0x10);
    // SLConfigDescriptor
    w.u8(0x06);
    w.u8(0x01);
    w.u8(0x02);
    w.close_box(s).unwrap();
    w.close_box(e).unwrap();
    w.into_vec()
}

fn stbl_video_opts(w: &mut ByteWriter, sample_count: usize, mdat_off: u64, opts: RegularOpts) {
    let b = w.open_box(b"stbl");
    // stsd
    let s = w.open_box(b"stsd");
    w.u32(0);
    w.u32(1); // entry count
    w.bytes(&avc1_entry());
    w.close_box(s).unwrap();
    // stts: all 100 dts
    let s = w.open_box(b"stts");
    w.u32(0);
    w.u32(1);
    w.u32(sample_count as u32);
    w.u32(VIDEO_TS / 10);
    w.close_box(s).unwrap();
    // stsc: 1 chunk per 5 samples? all samples one chunk per sample for simplicity
    let s = w.open_box(b"stsc");
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(1);
    w.u32(1);
    w.close_box(s).unwrap();
    // stsz
    let s = w.open_box(b"stsz");
    w.u32(0);
    w.u32(0);
    w.u32(sample_count as u32);
    for i in 0..sample_count {
        w.u32(100 + (i % 5) as u32);
    }
    w.close_box(s).unwrap();
    // stco/co64: one chunk per sample
    let s = w.open_box(if opts.co64 { b"co64" } else { b"stco" });
    w.u32(0);
    w.u32(sample_count as u32);
    let mut off = mdat_off + 8; // after mdat header
    for _ in 0..sample_count {
        if opts.co64 {
            w.u64(off);
        } else {
            w.u32(off as u32);
        }
        off += 100 + 5; // max size
    }
    w.close_box(s).unwrap();
    // stss
    let s = w.open_box(b"stss");
    let kfs: Vec<u32> = (1..=sample_count)
        .filter(|i: &usize| (i - 1).is_multiple_of(12))
        .map(|i: usize| i as u32)
        .collect();
    w.u32(0);
    w.u32(kfs.len() as u32);
    for k in kfs {
        w.u32(k);
    }
    w.close_box(s).unwrap();
    // ctts: fixed offsets (v0 unsigned), or v1 signed offsets alternating
    // +30 / -30 like a B-frame pattern after a CMAF-style shift
    let s = w.open_box(b"ctts");
    if opts.ctts_v1_negative {
        w.u8(1);
        w.u24(0);
        w.u32(sample_count as u32);
        for i in 0..sample_count {
            w.u32(1);
            w.i32(if i % 2 == 0 { 30 } else { -30 });
        }
    } else {
        w.u32(0);
        w.u32(1);
        w.u32(sample_count as u32);
        w.u32(VIDEO_TS / 30);
    }
    w.close_box(s).unwrap();
    w.close_box(b).unwrap();
}

fn stbl_audio(w: &mut ByteWriter, sample_count: usize, mdat_off: u64) {
    let b = w.open_box(b"stbl");
    let s = w.open_box(b"stsd");
    w.u32(0);
    w.u32(1);
    w.bytes(&mp4a_entry());
    w.close_box(s).unwrap();
    let s = w.open_box(b"stts");
    w.u32(0);
    w.u32(1);
    w.u32(sample_count as u32);
    w.u32(1024);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stsc");
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(1);
    w.u32(1);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stsz");
    w.u32(0);
    w.u32(4); // uniform
    w.u32(sample_count as u32);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stco");
    w.u32(0);
    w.u32(sample_count as u32);
    let mut off = mdat_off + 8;
    for _ in 0..sample_count {
        w.u32(off as u32);
        off += 4;
    }
    w.close_box(s).unwrap();
    w.close_box(b).unwrap();
}

/// Layout knobs for the synthetic regular fixture.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegularOpts {
    /// write chunk offsets as 64-bit `co64` instead of `stco`
    pub co64: bool,
    /// write `ctts` version 1 with SIGNED offsets (negative for B-frames)
    pub ctts_v1_negative: bool,
    /// omit the audio track entirely
    pub video_only: bool,
}

/// Regular MP4: N video frames (keyframe every 12) + matching audio.
pub fn regular_two_track() -> Vec<u8> {
    build_regular_two_track(60)
}

/// Same fixture with layout variations (co64 / ctts v1 / video-only).
pub fn regular_with(opts: RegularOpts) -> Vec<u8> {
    build_regular(60, opts)
}

fn build_regular_two_track(video_samples: usize) -> Vec<u8> {
    build_regular(video_samples, RegularOpts::default())
}

fn build_regular(video_samples: usize, opts: RegularOpts) -> Vec<u8> {
    // layout: ftyp | moov | mdat ; size moov via a dry run
    let mut probe = ByteWriter::new();
    moov_body_opts(&mut probe, video_samples, 0, opts);
    let mdat_off = probe.len() as u64 + 16 + 8; // ftyp(16) + mdat header(8)

    let mut w = ByteWriter::new();
    ftyp(&mut w);
    moov_body_opts(&mut w, video_samples, mdat_off, opts);
    let mdat = w.open_box(b"mdat");
    let video_bytes = video_samples * 105;
    let audio_bytes = audio_count(video_samples) * 4;
    w.zeros(video_bytes + audio_bytes);
    w.close_box(mdat).unwrap();
    w.into_vec()
}

fn audio_count(video_samples: usize) -> usize {
    // audio duration matches video duration (video_samples * 900 dts @ ts 900)
    let video_dur_ts = video_samples * 100; // video dts @ 900
    let audio_samples = video_dur_ts * 44100 / 900 / 1024; // ~1024 per aac frame
    audio_samples + 1
}

fn moov_body_opts(w: &mut ByteWriter, video_samples: usize, mdat_off: u64, opts: RegularOpts) {
    let m = w.open_box(b"moov");
    mvhd(w, 2000);
    write_video_trak_opts(w, video_samples, mdat_off, opts);
    if !opts.video_only {
        write_audio_trak(
            w,
            audio_count(video_samples),
            mdat_off + (video_samples * 105) as u64,
        );
    }
    w.close_box(m).unwrap();
}

fn write_video_trak_opts(
    w: &mut ByteWriter,
    video_samples: usize,
    mdat_off: u64,
    opts: RegularOpts,
) {
    let t = w.open_box(b"trak");
    // tkhd
    let k = w.open_box(b"tkhd");
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1); // id
    w.u32(0);
    w.u32(200); // duration movie ts
    w.u32(0);
    w.u32(0);
    w.u16(0);
    w.u16(0);
    w.u16(0); // volume
    w.u16(0);
    w.u32(0x00010000);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0x00010000);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0x40000000);
    w.u32(320 << 16);
    w.u32(180 << 16);
    w.close_box(k).unwrap();
    let d = w.open_box(b"mdia");
    mdhd(w, 900, (video_samples * 100) as u32);
    hdlr(w, b"vide");
    let m = w.open_box(b"minf");
    stbl_video_opts(w, video_samples, mdat_off, opts);
    w.close_box(m).unwrap();
    w.close_box(d).unwrap();
    w.close_box(t).unwrap();
}

fn write_audio_trak(w: &mut ByteWriter, audio_samples: usize, mdat_off: u64) {
    let t = w.open_box(b"trak");
    let k = w.open_box(b"tkhd");
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(2);
    w.u32(0);
    w.u32(200);
    w.u32(0);
    w.u32(0);
    w.u16(0);
    w.u16(0);
    w.u16(0x0100); // volume
    w.u16(0);
    w.u32(0x00010000);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0x00010000);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0x40000000);
    w.u32(0);
    w.u32(0);
    w.close_box(k).unwrap();
    let d = w.open_box(b"mdia");
    mdhd(w, 44100, (audio_samples as u32) * 1024);
    hdlr(w, b"soun");
    let m = w.open_box(b"minf");
    stbl_audio(w, audio_samples, mdat_off);
    w.close_box(m).unwrap();
    w.close_box(d).unwrap();
    w.close_box(t).unwrap();
}

// ---------------------------------------------------------------------------
// Fragmented MP4 fixture
// ---------------------------------------------------------------------------

fn trex(w: &mut ByteWriter, track_id: u32) {
    let b = w.open_box(b"trex");
    w.u32(0);
    w.u32(track_id);
    w.u32(1);
    w.u32(100);
    w.u32(64);
    w.u32(0x02000000);
    w.u32(0);
    w.close_box(b).unwrap();
}

fn trun_video(w: &mut ByteWriter, count: usize, data_offset: i32, first_flags: u32) {
    let b = w.open_box(b"trun");
    w.u32(0x00000305); // doff + first-flags + dur/size
    w.u32(count as u32);
    w.i32(data_offset);
    w.u32(first_flags);
    for _ in 0..count {
        w.u32(100);
        w.u32(64);
    }
    w.close_box(b).unwrap();
}

fn trun_audio(w: &mut ByteWriter, count: usize, data_offset: i32) {
    let b = w.open_box(b"trun");
    w.u32(0x00000301); // doff + dur/size
    w.u32(count as u32);
    w.i32(data_offset);
    for _ in 0..count {
        w.u32(1024);
        w.u32(4);
    }
    w.close_box(b).unwrap();
}

fn tfhd(w: &mut ByteWriter, track_id: u32) {
    let b = w.open_box(b"tfhd");
    w.u32(0x020000);
    w.u32(track_id);
    w.close_box(b).unwrap();
}

fn tfdt(w: &mut ByteWriter, base_dts: u32) {
    let b = w.open_box(b"tfdt");
    w.u32(0x01000000);
    w.u64(base_dts as u64);
    w.close_box(b).unwrap();
}

fn empty_stbl_video(w: &mut ByteWriter) {
    let mf = w.open_box(b"minf");
    let sb = w.open_box(b"stbl");
    let s = w.open_box(b"stsd");
    w.u32(0);
    w.u32(1);
    w.bytes(&avc1_entry());
    w.close_box(s).unwrap();
    for t in [b"stts", b"stsc"] {
        let s = w.open_box(t);
        w.u32(0);
        w.u32(0);
        w.close_box(s).unwrap();
    }
    let s = w.open_box(b"stsz");
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stco");
    w.u32(0);
    w.u32(0);
    w.close_box(s).unwrap();
    w.close_box(sb).unwrap();
    w.close_box(mf).unwrap();
}

fn empty_stbl_audio(w: &mut ByteWriter) {
    let mf = w.open_box(b"minf");
    let sb = w.open_box(b"stbl");
    let s = w.open_box(b"stsd");
    w.u32(0);
    w.u32(1);
    w.bytes(&mp4a_entry());
    w.close_box(s).unwrap();
    let s = w.open_box(b"stts");
    w.u32(0);
    w.u32(0);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stsc");
    w.u32(0);
    w.u32(0);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stsz");
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.close_box(s).unwrap();
    let s = w.open_box(b"stco");
    w.u32(0);
    w.u32(0);
    w.close_box(s).unwrap();
    w.close_box(sb).unwrap();
    w.close_box(mf).unwrap();
}

fn empty_trak(
    w: &mut ByteWriter,
    id: u32,
    timescale: u32,
    duration: u32,
    handler: &[u8; 4],
    volume: u16,
    wh: (u16, u16),
) {
    let t = w.open_box(b"trak");
    let k = w.open_box(b"tkhd");
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(id);
    w.u32(0);
    w.u32(3000);
    w.u32(0);
    w.u32(0);
    w.u16(0);
    w.u16(0);
    w.u16(volume);
    w.u16(0);
    w.u32(0x00010000);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0x00010000);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0x40000000);
    w.u32((wh.0 as u32) << 16);
    w.u32((wh.1 as u32) << 16);
    w.close_box(k).unwrap();
    let d = w.open_box(b"mdia");
    mdhd(w, timescale, duration);
    hdlr(w, handler);
    if handler == b"vide" {
        empty_stbl_video(w);
    } else {
        empty_stbl_audio(w);
    }
    w.close_box(d).unwrap();
    w.close_box(t).unwrap();
}

/// Fragmented MP4: `fragments` fragments, each 24 video + 96 audio samples.
/// Video data offsets are patched to point at the mdat payload.
pub fn fragmented_two_track(fragments: usize) -> Vec<u8> {
    let mut w = ByteWriter::new();
    ftyp(&mut w);
    let m = w.open_box(b"moov");
    mvhd(&mut w, 3000);
    empty_trak(
        &mut w,
        1,
        900,
        (fragments * 24 * 100) as u32,
        b"vide",
        0,
        (320, 180),
    );
    empty_trak(
        &mut w,
        2,
        44100,
        (fragments * 96 * 1024) as u32,
        b"soun",
        0x0100,
        (0, 0),
    );
    let v = w.open_box(b"mvex");
    trex(&mut w, 1);
    trex(&mut w, 2);
    w.close_box(v).unwrap();
    w.close_box(m).unwrap();

    let mut base_video = 0u32;
    let mut base_audio = 0u32;
    for f in 0..fragments {
        let first_flags = if f == 0 { 0x02000000 } else { 0x01010000 };
        let moof_start = w.len() as u64;
        let moof = w.open_box(b"moof");
        let h = w.open_box(b"mfhd");
        w.u32(0);
        w.u32(f as u32 + 1);
        w.close_box(h).unwrap();
        let t = w.open_box(b"traf");
        tfhd(&mut w, 1);
        tfdt(&mut w, base_video);
        trun_video(&mut w, 24, 0, first_flags);
        w.close_box(t).unwrap();
        let t = w.open_box(b"traf");
        tfhd(&mut w, 2);
        tfdt(&mut w, base_audio);
        trun_audio(&mut w, 96, 0);
        w.close_box(t).unwrap();
        w.close_box(moof).unwrap();
        let mdat_start = w.len() as u64;
        let video_off = (mdat_start + 8 - moof_start) as i32;
        let audio_off = (mdat_start + 8 + 24 * 64 - moof_start) as i32;
        // patch both truns' data_offset fields now that positions are known
        let moof_bytes = moof_start as usize;
        patch_data_offset(&mut w.buf, moof_bytes, 0, video_off);
        patch_data_offset(&mut w.buf, moof_bytes, 1, audio_off);
        let md = w.open_box(b"mdat");
        w.zeros(24 * 64 + 96 * 4);
        w.close_box(md).unwrap();
        base_video += 24 * 100;
        base_audio += 96 * 1024;
    }
    w.into_vec()
}

/// Patch the data_offset field of the nth trun box whose header starts at
/// or after `from` (byte offset in buf).
fn patch_data_offset(buf: &mut [u8], from: usize, nth: usize, value: i32) {
    let mut seen = 0usize;
    let mut i = from;
    while i + 20 <= buf.len() {
        if &buf[i + 4..i + 8] == b"trun" {
            if seen == nth {
                buf[i + 16..i + 20].copy_from_slice(&value.to_be_bytes());
                return;
            }
            seen += 1;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_builder::{build_index, BuildOptions};
    use crate::moov::find_moov;
    use crate::schema::*;

    fn parse_regular() -> (SourceInfo, Vec<crate::moov::ParsedTrack>, u32) {
        let f = regular_two_track();
        let (moov_h, moov) = find_moov(&f, 0).unwrap();
        let tracks = crate::moov::parse_tracks(&moov, moov_h.content_start).unwrap();
        (
            SourceInfo {
                key: "test/a.mp4".into(),
                size: f.len() as u64,
                etag: None,
            },
            tracks,
            1000,
        )
    }

    #[test]
    fn regular_parse_and_index() {
        let (source, tracks, movie_ts) = parse_regular();
        assert_eq!(tracks.len(), 2);
        let video = tracks
            .iter()
            .find(|t| t.track_type == TrackType::Video)
            .unwrap();
        let audio = tracks
            .iter()
            .find(|t| t.track_type == TrackType::Audio)
            .unwrap();
        assert_eq!(video.id, 1);
        assert_eq!(video.samples.len(), 60);
        assert_eq!(video.codec_string, "avc1.64001F");
        assert_eq!(video.timescale, 900);
        assert!(video.samples[0].keyframe);
        assert!(!video.samples[1].keyframe);
        assert_eq!(audio.id, 2);
        assert_eq!(audio.timescale, 44100);
        // audio sample sizes uniform 4
        assert_eq!(audio.samples[0].size, 4);

        let idx = build_index(
            source,
            tracks,
            movie_ts,
            &BuildOptions {
                target_segment_ms: 1500,
            },
        )
        .unwrap();
        assert_eq!(idx.kind, SourceKind::Regular);
        assert_eq!(idx.primary_track_id, 1);
        // keyframes at 0/12/24/36/48; target 1350dts => cuts at 0,24,48,60
        assert_eq!(idx.segments.len(), 3);
        assert_eq!(idx.segments[0].tracks[0].sample_count, 24);
        // offsets: video sample i at mdat_off + i*105
        let voff = idx.segments[0].tracks[0].first_sample_offset;
        assert_eq!(
            idx.segments[1].tracks[0].first_sample_offset,
            voff + 24 * 105
        );
        // duration_ms = 60 samples * 90 dts @ 900ts = 6000ms
        assert_eq!(idx.duration_ms, 6000);
        // audio included
        let seg_audio = idx.segments[0]
            .tracks
            .iter()
            .find(|t| t.track_id == 2)
            .unwrap();
        assert!(seg_audio.sample_count > 100);
        // codec strings in tracks
        assert_eq!(idx.tracks[0].codec_string, "avc1.64001F");
        assert_eq!(idx.tracks[1].codec_string, "mp4a.40.2");
    }

    fn index_of(f: &[u8]) -> MediaIndex {
        let (moov_h, moov) = find_moov(f, 0).unwrap();
        let tracks = crate::moov::parse_tracks(&moov, moov_h.content_start).unwrap();
        build_index(
            SourceInfo {
                key: "x.mp4".into(),
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

    /// co64 (64-bit chunk offsets) must yield the same segmentation as stco.
    #[test]
    fn co64_matches_stco() {
        let a = index_of(&regular_two_track());
        let f64 = regular_with(RegularOpts {
            co64: true,
            ..Default::default()
        });
        let b = index_of(&f64);
        assert_eq!(a.segments.len(), b.segments.len());
        for (sa, sb) in a.segments.iter().zip(&b.segments) {
            assert_eq!(sa.duration, sb.duration);
            for (ta, tb) in sa.tracks.iter().zip(&sb.tracks) {
                assert_eq!(ta.sample_count, tb.sample_count);
                assert_eq!(ta.start_dts, tb.start_dts);
                assert_eq!(ta.byte_ranges.len(), tb.byte_ranges.len());
                let la: u64 = ta.byte_ranges.iter().map(|r| r.length).sum();
                let lb: u64 = tb.byte_ranges.iter().map(|r| r.length).sum();
                assert_eq!(la, lb);
            }
        }
        // co64 adds 4 bytes per chunk entry (60 video chunks) to the moov,
        // so every sample offset shifts by exactly that much
        assert_eq!(
            b.segments[0].tracks[0].first_sample_offset,
            a.segments[0].tracks[0].first_sample_offset + 4 * 60
        );
        let (h, _) = find_moov(&f64, 0).unwrap();
        assert!(b.segments[0].tracks[0].first_sample_offset >= h.end());
    }

    /// ctts version 1 carries signed offsets; they must survive into the
    /// index and into the built moof (trun v1) unchanged.
    #[test]
    fn ctts_v1_negative_offsets_roundtrip() {
        let f = regular_with(RegularOpts {
            ctts_v1_negative: true,
            ..Default::default()
        });
        let idx = index_of(&f);
        let st = &idx.segments[0].tracks[0];
        let mut run = crate::moof_builder::expand_track_run(&idx, st, 0).unwrap();
        assert_eq!(run.samples[0].cts_delta, 30);
        assert_eq!(run.samples[1].cts_delta, -30);
        run.payload = vec![0u8; run.payload_len()];
        let bytes = crate::moof_builder::build_segment(&[run], 1).unwrap();
        let mut moof_h = None;
        crate::boxes::walk_top_level(&bytes, 0, |h| {
            if &h.box_type == b"moof" {
                moof_h = Some(h);
                return false;
            }
            true
        })
        .unwrap();
        let mh = moof_h.unwrap();
        let moof = crate::boxes::content_of(&bytes, 0, &mh).to_vec();
        let t =
            crate::parse_frag::parse_moof(&moof, mh.content_start, mh.start, &Default::default())
                .unwrap();
        assert_eq!(t[0].samples[1].cts_delta, -30);
        assert_eq!(t[0].samples[2].cts_delta, 30);
    }

    /// Video-only sources index, build an init segment and a playlist.
    #[test]
    fn video_only_source() {
        let f = regular_with(RegularOpts {
            video_only: true,
            ..Default::default()
        });
        let idx = index_of(&f);
        assert_eq!(idx.tracks.len(), 1);
        assert!(idx.audio_track().is_none());
        assert!(idx.segments.iter().all(|s| s.tracks.len() == 1));
        let init = crate::moov_builder::build_init_segment(&idx).unwrap();
        let (h, moov) = find_moov(&init, 0).unwrap();
        assert_eq!(
            crate::parse_frag::parse_track_skeletons(&moov, h.content_start)
                .unwrap()
                .len(),
            1
        );
        let pl = crate::playlist::media_playlist(&idx, "init.mp4", &|i| format!("{i}.m4s"), None);
        assert_eq!(pl.matches("#EXTINF").count(), idx.segments.len());
    }

    #[test]
    fn fragmented_parse_and_index() {
        let f = fragmented_two_track(5);
        let (moov_h, _moov) = find_moov(&f, 0).unwrap();
        let idx = crate::parse_frag::build_fragmented_index(
            SourceInfo {
                key: "test/b.mp4".into(),
                size: f.len() as u64,
                etag: None,
            },
            &f,
            0,
            &BuildOptions::default(),
        )
        .unwrap();
        assert_eq!(idx.kind, SourceKind::Fragmented);
        assert_eq!(idx.tracks.len(), 2);
        assert_eq!(idx.segments.len(), 5);
        // each fragment: 24 video samples @ 900 ts => 2400 dts = 2666ms
        assert_eq!(idx.segments[0].duration, 24 * 100);
        // fragment ranges are contiguous and non-overlapping
        let r0 = idx.segments[0].fragment_range.unwrap();
        let r1 = idx.segments[1].fragment_range.unwrap();
        assert_eq!(r0.offset + r0.length, r1.offset);
        // video first_sample_offset points into mdat after moof+mdat headers
        assert!(r1.offset > r0.offset);
        let _ = moov_h;
    }
}
