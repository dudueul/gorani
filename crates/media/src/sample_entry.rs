// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! stsd sample-entry parsing: dimensions, codec strings, raw box bytes.
//!
//! Codec strings follow RFC 6381 / ISO 14496-15 Annex E — they are what HLS
//! `CODECS=` and DASH `codecs=` carry, and players refuse to even try a
//! variant whose string they cannot parse. Supported families:
//!
//! | sample entry | config box | string shape |
//! |---|---|---|
//! | avc1/avc2/avc3/avc4 | avcC | `avc1.PPCCLL` (hex) |
//! | hev1/hvc1 | hvcC | `hvc1.[A|B|C]P.CCC.[L|H]LLL.cc[.cc…]` |
//! | av01 | av1C | `av01.P.LLT.DD` |
//! | vp09 | vpcC | `vp09.PP.LL.DD` |
//! | mp4a | esds | `mp4a.OO[.AOT]` |
//! | ac-3 / ec-3 / alac | — | the bare fourcc |
//! | Opus / fLaC | — | `opus` / `flac` (lower case, as MSE names them) |
//! | encv / enca | sinf/frma | resolved through the original format |

use crate::bytes::ByteReader;
use crate::error::{CoreError, Result};

#[derive(Debug, Clone)]
pub struct SampleEntry {
    pub box_bytes: Vec<u8>,
    pub codec_string: String,
    pub is_video: bool,
    pub width: u16,
    pub height: u16,
    pub encrypted: bool,
    /// `sinf/schm` scheme_type of an encrypted entry (`cenc`, `cbcs`, …)
    pub scheme: Option<[u8; 4]>,
}

fn hex2(b: u8) -> String {
    format!("{b:02X}")
}

fn parse_avcc(c: &[u8], fourcc: &str) -> String {
    let mut r = ByteReader::new(c);
    let _v = r.u8().unwrap_or(1);
    let profile = r.u8().unwrap_or(0);
    let compat = r.u8().unwrap_or(0);
    let level = r.u8().unwrap_or(0);
    format!("{fourcc}.{}{}{}", hex2(profile), hex2(compat), hex2(level))
}

/// ISO/IEC 14496-15 Annex E.3 — the notable trap is that the 32 profile
/// compatibility flags are printed BIT-REVERSED (flag[0] is the LSB of the
/// printed number), so Main profile's `0x60000000` becomes `6`.
fn parse_hvcc(c: &[u8], fourcc: &str) -> String {
    let mut r = ByteReader::new(c);
    let _v = r.u8().unwrap_or(1);
    let b1 = r.u8().unwrap_or(0);
    let profile_space = b1 >> 6;
    let tier = (b1 >> 5) & 1;
    let profile = b1 & 0x1F;
    let compat = r.u32().unwrap_or(0);
    let mut constraint = [0u8; 6];
    for cb in constraint.iter_mut() {
        *cb = r.u8().unwrap_or(0);
    }
    let level = r.u8().unwrap_or(0);
    let space = match profile_space {
        1 => "A",
        2 => "B",
        3 => "C",
        _ => "",
    };
    let mut s = format!(
        "{fourcc}.{space}{profile}.{:X}.{}{level}",
        compat.reverse_bits(),
        if tier != 0 { 'H' } else { 'L' }
    );
    // constraint bytes: trailing zero bytes are omitted
    let mut last = constraint.len();
    while last > 0 && constraint[last - 1] == 0 {
        last -= 1;
    }
    for b in &constraint[..last] {
        s.push('.');
        s.push_str(&hex2(*b));
    }
    s
}

/// AV1 (av1C, AV1-ISOBMFF §2.3): `av01.P.LLT.DD` short form, which every
/// browser accepts (the optional colour fields are only needed for HDR
/// negotiation).
fn parse_av1c(c: &[u8]) -> String {
    let mut r = ByteReader::new(c);
    let _marker_version = r.u8().unwrap_or(0x81);
    let b1 = r.u8().unwrap_or(0);
    let b2 = r.u8().unwrap_or(0);
    let profile = b1 >> 5;
    let level = b1 & 0x1F;
    let tier = (b2 >> 7) & 1;
    let high_bitdepth = (b2 >> 6) & 1;
    let twelve_bit = (b2 >> 5) & 1;
    let bit_depth = if high_bitdepth == 1 {
        if twelve_bit == 1 {
            12
        } else {
            10
        }
    } else {
        8
    };
    format!(
        "av01.{profile}.{level:02}{}.{bit_depth:02}",
        if tier != 0 { 'H' } else { 'M' }
    )
}

/// VP9 (vpcC, VP Codec ISO Media File Format Binding): `vp09.PP.LL.DD`.
fn parse_vpcc(c: &[u8]) -> String {
    let mut r = ByteReader::new(c);
    r.skip(4); // version + flags
    let profile = r.u8().unwrap_or(0);
    let level = r.u8().unwrap_or(0);
    let b = r.u8().unwrap_or(0);
    let bit_depth = b >> 4;
    format!("vp09.{profile:02}.{level:02}.{bit_depth:02}")
}

fn read_descriptor_len(b: &[u8]) -> Option<(usize, usize)> {
    let mut len = 0usize;
    let mut n = 0;
    loop {
        let byte = *b.get(n)?;
        len = (len << 7) | (byte & 0x7F) as usize;
        n += 1;
        if byte & 0x80 == 0 {
            break;
        }
        if n > 4 {
            return None;
        }
    }
    Some((len, n))
}

fn parse_esds_audio(esds: &[u8]) -> Option<String> {
    // after version/flags: ES_Descriptor(0x03) { ES_ID(2) flags(1)
    //   [dependsOn(2)] [ocr(2)] DecoderConfigDescriptor(0x04) { oti ... } }
    let mut i = 4;
    while i < esds.len() && esds[i] != 0x03 {
        i += 1;
    }
    if i >= esds.len() {
        return None;
    }
    let (_l, h) = read_descriptor_len(&esds[i + 1..])?;
    let mut j = i + 1 + h + 2; // ES_ID
    let es_flags = *esds.get(j)?;
    j += 1;
    if es_flags & 0x80 != 0 {
        j += 2; // dependsOn_ES_ID
    }
    if es_flags & 0x40 != 0 {
        let url_len = *esds.get(j)? as usize;
        j += 1 + url_len;
    }
    if es_flags & 0x20 != 0 {
        j += 2; // OCR_ES_Id
    }
    if j >= esds.len() || esds[j] != 0x04 {
        return None;
    }
    let (l2, h2) = read_descriptor_len(&esds[j + 1..])?;
    let dcd = j + 1 + h2;
    let oti = *esds.get(dcd)?;
    if oti != 0x40 {
        return Some(format!("mp4a.{:02X}", oti));
    }
    // AAC: the DecoderConfigDescriptor body is 13 fixed bytes
    // (objectTypeIndication, streamType, bufferSizeDB(3), maxBitrate(4),
    // avgBitrate(4)) followed by sub-descriptors. Walk those by tag+length
    // — never byte-scan for 0x05: bitrate fields routinely contain that
    // byte, and reading a "DecoderSpecificInfo" out of a bitrate produced
    // codec strings like mp4a.40.1 for plain AAC-LC files, which browsers
    // then refused to play.
    let dcd_end = (dcd + l2).min(esds.len());
    let mut k = dcd + 13;
    while k + 1 < dcd_end {
        let tag = esds[k];
        let (l3, h3) = read_descriptor_len(&esds[k + 1..])?;
        let body = k + 1 + h3;
        if tag == 0x05 {
            // AudioSpecificConfig: audioObjectType(5) [escape: 6 more bits]
            let dsi = *esds.get(body)?;
            let mut aot = (dsi >> 3) as u32;
            if aot == 31 {
                let next = *esds.get(body + 1).unwrap_or(&0);
                aot = 32 + (((dsi & 0x07) << 3) | (next >> 5)) as u32;
            }
            if aot == 0 {
                break; // malformed config — assume the overwhelmingly common LC
            }
            return Some(format!("mp4a.40.{aot}"));
        }
        k = body + l3;
    }
    Some("mp4a.40.2".into())
}

fn is_video_4cc(f: &[u8; 4]) -> bool {
    matches!(
        f,
        b"avc1"
            | b"avc2"
            | b"avc3"
            | b"avc4"
            | b"hev1"
            | b"hvc1"
            | b"hvc2"
            | b"encv"
            | b"mp4v"
            | b"av01"
            | b"vp09"
            | b"vp08"
            | b"dvh1"
            | b"dvhe"
    )
}

fn is_audio_4cc(f: &[u8; 4]) -> bool {
    matches!(
        f,
        b"mp4a" | b"enca" | b"ac-3" | b"ec-3" | b"Opus" | b"fLaC" | b"alac" | b"ac-4" | b"mlpa"
    )
}

/// `sinf/schm` scheme_type of an encrypted entry: what the manifests must
/// advertise. `cenc` and `cbcs` need different players (Safari only does
/// the latter) and dash.js/shaka hand it to the CDM as `encryptionScheme`.
pub fn protection_scheme(entry: &[u8]) -> Option<[u8; 4]> {
    let (sinf, _) = find_child_box(entry, b"sinf")?;
    let (schm, _) = scan_children_from(sinf, 0, b"schm")?;
    // FullBox: version(1) flags(3) scheme_type(4) scheme_version(4)
    schm.get(4..8).map(|b| [b[0], b[1], b[2], b[3]])
}

/// `sinf/frma` of an encrypted entry: the original (unencrypted) fourcc.
fn original_format(entry: &[u8]) -> Option<[u8; 4]> {
    let (sinf, _) = find_child_box(entry, b"sinf")?;
    let (frma, _) = scan_children_from(sinf, 0, b"frma")?;
    frma.get(0..4).map(|b| [b[0], b[1], b[2], b[3]])
}

pub fn parse_sample_entry(entry: &[u8]) -> Result<SampleEntry> {
    if entry.len() < 16 {
        return Err(CoreError::Parse("stsd entry too small".into()));
    }
    let fourcc = [entry[4], entry[5], entry[6], entry[7]];
    let encrypted = matches!(&fourcc, b"encv" | b"enca");
    // Encrypted entries keep their codec config boxes (avcC/hvcC/esds) next
    // to `sinf`; only the fourcc changes. Resolve the original format so the
    // codec string describes what the decoder will see after decryption.
    let effective = if encrypted {
        original_format(entry).unwrap_or(fourcc)
    } else {
        fourcc
    };
    let fourcc_str = String::from_utf8_lossy(&effective).to_string();
    let scheme = if encrypted {
        protection_scheme(entry)
    } else {
        None
    };

    let mut r = ByteReader::new(entry);
    r.skip(8); // size + type
    r.skip(8); // reserved(6) + data_ref_index(2)

    let mut is_video = false;
    let mut width = 0u16;
    let mut height = 0u16;
    // The fourcc is the codec string for most audio entries — but not as
    // written: the MSE / RFC 6381 names of Opus and FLAC are lower case
    // ("opus", "flac"), while their sample entries are "Opus" and "fLaC".
    // (gorani, 39p: Chromium refuses `codecs="…,Opus"` outright, and the
    // in-page player fell back for every Opus file.)
    let mut codec = match &effective {
        b"Opus" => "opus".to_string(),
        b"fLaC" => "flac".to_string(),
        _ => fourcc_str.clone(),
    };

    let video = is_video_4cc(&effective) || is_video_4cc(&fourcc);
    if video && entry.len() < 86 {
        return Err(CoreError::Parse("video sample entry too small".into()));
    }
    if video {
        is_video = true;
        r.skip(16); // predefined(2)+reserved(6)+pre_defined(2)+reserved(6)
        width = r.u16()?;
        height = r.u16()?;
        match &effective {
            b"avc1" | b"avc2" | b"avc3" | b"avc4" => {
                if let Some((c, _)) = find_child_box(entry, b"avcC") {
                    codec = parse_avcc(c, &fourcc_str);
                }
            }
            b"hev1" | b"hvc1" | b"hvc2" | b"dvh1" | b"dvhe" => {
                if let Some((c, _)) = find_child_box(entry, b"hvcC") {
                    codec = parse_hvcc(
                        c,
                        if &effective == b"hev1" {
                            "hev1"
                        } else {
                            "hvc1"
                        },
                    );
                }
            }
            b"av01" => {
                if let Some((c, _)) = find_child_box(entry, b"av1C") {
                    codec = parse_av1c(c);
                }
            }
            b"vp09" | b"vp08" => {
                if let Some((c, _)) = find_child_box(entry, b"vpcC") {
                    codec = parse_vpcc(c);
                }
            }
            _ => {}
        }
    } else if (is_audio_4cc(&effective) || is_audio_4cc(&fourcc)) && &effective == b"mp4a" {
        // (ac-3 / ec-3 / Opus / fLaC / alac: the bare fourcc IS the RFC 6381 string)
        if let Some((esds, _)) = find_child_box(entry, b"esds") {
            if let Some(s) = parse_esds_audio(esds) {
                codec = s;
            }
        } else {
            codec = "mp4a.40.2".into();
        }
    }

    Ok(SampleEntry {
        box_bytes: entry.to_vec(),
        codec_string: codec,
        is_video,
        width,
        height,
        encrypted,
        scheme,
    })
}

/// Find a direct child box of a sample entry; returns (content, content_offset).
pub fn find_child_box<'a>(entry: &'a [u8], fourcc: &[u8; 4]) -> Option<(&'a [u8], u64)> {
    let kind = &entry[4..8];
    // audio: spec puts children at 36; QuickTime v1/v2 audio entries insert
    // 16/52 extra bytes first — try each known layout
    let starts: &[usize] = if is_video_4cc_from(kind) {
        &[86]
    } else if is_audio_4cc_from(kind) {
        &[36, 52, 88]
    } else {
        &[16]
    };
    for fixed in starts {
        if let Some(hit) = scan_children_from(entry, *fixed, fourcc) {
            return Some(hit);
        }
    }
    None
}

fn scan_children_from<'a>(
    entry: &'a [u8],
    start: usize,
    fourcc: &[u8; 4],
) -> Option<(&'a [u8], u64)> {
    let mut off = start;
    while off + 8 <= entry.len() {
        let size = u32::from_be_bytes(entry[off..off + 4].try_into().ok()?) as usize;
        if size < 8 || off + size > entry.len() {
            return None;
        }
        if &entry[off + 4..off + 8] == fourcc {
            return Some((&entry[off + 8..off + size], (off + 8) as u64));
        }
        off += size;
    }
    None
}

fn is_video_4cc_from(f: &[u8]) -> bool {
    f.len() == 4 && is_video_4cc(&[f[0], f[1], f[2], f[3]])
}

fn is_audio_4cc_from(f: &[u8]) -> bool {
    f.len() == 4 && is_audio_4cc(&[f[0], f[1], f[2], f[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::ByteWriter;

    fn video_entry(fourcc: &[u8; 4], config: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut w = ByteWriter::new();
        let e = w.open_box(fourcc);
        w.zeros(6);
        w.u16(1);
        w.zeros(16);
        w.u16(1920);
        w.u16(1080);
        w.u32(0x00480000);
        w.u32(0x00480000);
        w.u32(0);
        w.u16(1);
        w.zeros(32);
        w.u16(0x0018);
        w.u16(0xFFFF);
        let c = w.open_box(config);
        w.bytes(payload);
        w.close_box(c).unwrap();
        w.close_box(e).unwrap();
        w.into_vec()
    }

    #[test]
    fn hevc_main_profile_string() {
        // hvcC: version 1, profile_space 0 / tier 0 / profile 1 (Main),
        // compat flags 0x60000000, constraints 90 00 00 00 00 00, level 93
        let hvcc = [1u8, 0x01, 0x60, 0, 0, 0, 0x90, 0, 0, 0, 0, 0, 93];
        let e = video_entry(b"hvc1", b"hvcC", &hvcc);
        let se = parse_sample_entry(&e).unwrap();
        assert_eq!(se.codec_string, "hvc1.1.6.L93.90");
        assert_eq!((se.width, se.height), (1920, 1080));
        // Main10 high tier with profile space B and two constraint bytes
        let hvcc = [1u8, 0b1010_0010, 0x40, 0, 0, 0, 0xB0, 0x40, 0, 0, 0, 0, 123];
        let e = video_entry(b"hev1", b"hvcC", &hvcc);
        assert_eq!(
            parse_sample_entry(&e).unwrap().codec_string,
            "hev1.B2.2.H123.B0.40"
        );
    }

    /// gorani 39p: the MSE names of Opus and FLAC are lower case; the sample
    /// entries' fourccs are not. (Chromium refuses `codecs="…,Opus"`.)
    #[test]
    fn opus_and_flac_strings_are_lower_case() {
        for (fourcc, want) in [(b"Opus", "opus"), (b"fLaC", "flac"), (b"ac-3", "ac-3")] {
            let mut e = vec![0u8; 36];
            e[0..4].copy_from_slice(&36u32.to_be_bytes());
            e[4..8].copy_from_slice(fourcc);
            let parsed = parse_sample_entry(&e).unwrap();
            assert_eq!(parsed.codec_string, want, "{}", String::from_utf8_lossy(fourcc));
        }
    }

    #[test]
    fn av1_and_vp9_strings() {
        // av1C: marker|version=0x81, profile 0 / level 8 (4.0), tier 0, 10-bit
        let av1c = [0x81u8, 0x08, 0x40, 0];
        let e = video_entry(b"av01", b"av1C", &av1c);
        assert_eq!(
            parse_sample_entry(&e).unwrap().codec_string,
            "av01.0.08M.10"
        );
        // vpcC: version 1, profile 0, level 10, bitdepth 8 (<<4)
        let vpcc = [1u8, 0, 0, 0, 0, 10, 0x80, 1, 1, 1, 0, 0];
        let e = video_entry(b"vp09", b"vpcC", &vpcc);
        assert_eq!(
            parse_sample_entry(&e).unwrap().codec_string,
            "vp09.00.10.08"
        );
    }

    #[test]
    fn encrypted_video_resolves_original_format() {
        let mut w = ByteWriter::new();
        let e = w.open_box(b"encv");
        w.zeros(6);
        w.u16(1);
        w.zeros(16);
        w.u16(640);
        w.u16(360);
        w.u32(0x00480000);
        w.u32(0x00480000);
        w.u32(0);
        w.u16(1);
        w.zeros(32);
        w.u16(0x0018);
        w.u16(0xFFFF);
        let c = w.open_box(b"avcC");
        w.bytes(&[1, 0x64, 0, 0x1F, 0xFF, 0xE1, 0, 0]);
        w.close_box(c).unwrap();
        let s = w.open_box(b"sinf");
        let f = w.open_box(b"frma");
        w.bytes(b"avc1");
        w.close_box(f).unwrap();
        let m = w.open_box(b"schm");
        w.u32(0); // version + flags
        w.bytes(b"cbcs");
        w.u32(0x0001_0000);
        w.close_box(m).unwrap();
        w.close_box(s).unwrap();
        w.close_box(e).unwrap();
        let bytes = w.into_vec();
        let se = parse_sample_entry(&bytes).unwrap();
        assert!(se.encrypted);
        assert_eq!(se.codec_string, "avc1.64001F");
        assert_eq!(
            se.scheme,
            Some(*b"cbcs"),
            "sinf/schm is what the manifests must advertise"
        );
        assert_eq!(protection_scheme(&bytes), Some(*b"cbcs"));
    }

    /// esds bytes of a production AAC-LC file whose maxBitrate field holds
    /// a 0x05 byte (`00 02 05 d3`): the old byte-scan read a "decoder
    /// specific info" out of the bitrate and reported AAC Main (mp4a.40.1),
    /// which every browser's MediaSource rejects.
    #[test]
    fn esds_bitrate_bytes_are_not_mistaken_for_the_audio_config() {
        let esds: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, // version/flags
            0x03, 0x80, 0x80, 0x80, 0x22, 0x00, 0x02, 0x00, // ES_Descriptor
            0x04, 0x80, 0x80, 0x80, 0x14, 0x40, 0x15, 0x00, 0x00,
            0x00, // DCD: oti, streamType, bufferSize
            0x00, 0x02, 0x05, 0xd3, // maxBitrate (contains 0x05)
            0x00, 0x01, 0xf3, 0xf5, // avgBitrate
            0x05, 0x80, 0x80, 0x80, 0x02, 0x12,
            0x10, // DecoderSpecificInfo: AAC-LC 44.1k stereo
            0x06, 0x80, 0x80, 0x80, 0x01, 0x02, // SLConfig
        ];
        assert_eq!(parse_esds_audio(&esds).as_deref(), Some("mp4a.40.2"));
        // real AAC Main / HE-AAC configs are still reported as such
        let mut main = esds.clone();
        main[35] = 0x0A; // aot 1 (first AudioSpecificConfig byte)
        assert_eq!(parse_esds_audio(&main).as_deref(), Some("mp4a.40.1"));
        let mut he = esds.clone();
        he[35] = 0x2B; // aot 5 (SBR)
        assert_eq!(parse_esds_audio(&he).as_deref(), Some("mp4a.40.5"));
        // a config without DecoderSpecificInfo defaults to LC
        let no_dsi = &esds[..28];
        assert_eq!(parse_esds_audio(no_dsi).as_deref(), Some("mp4a.40.2"));
    }

    #[test]
    fn synthetic_fixture_entries() {
        let v = parse_sample_entry(&crate::testmp4::avc1_entry()).unwrap();
        assert_eq!(v.codec_string, "avc1.64001F");
        let a = parse_sample_entry(&crate::testmp4::mp4a_entry()).unwrap();
        assert_eq!(a.codec_string, "mp4a.40.2");
        assert!(!a.is_video);
    }
}
