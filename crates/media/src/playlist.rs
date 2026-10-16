// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! HLS playlist generation (master + media), fMP4 / EXT-X-MAP style.
//!
//! # Format notes (RFC 8216)
//!
//! * `#EXT-X-VERSION:7` — required for fMP4 (`EXT-X-MAP`) playlists.
//! * `#EXT-X-MAP:URI=…` — points at the init segment; players read it once
//!   then concatenate `moof+mdat` media segments.
//! * `#EXTINF` durations are printed with 5 decimal digits, in SECONDS —
//!   converted here from the primary track's timescale.
//! * `#EXT-X-TARGETDURATION` is an integer CEIL of the longest segment —
//!   players use it for buffering decisions; it must never shrink.
//! * `#EXT-X-PLAYLIST-TYPE:VOD` + `#EXT-X-ENDLIST` — immutable VOD manifest,
//!   safe to cache at the CDN (modulo the token query).
//! * AES-128 mode adds `#EXT-X-KEY:METHOD=AES-128,URI=…` WITHOUT an `IV`
//!   attribute: per §5.2 the player then derives each segment's IV from its
//!   Media Sequence Number, which is exactly the IV the worker encrypts
//!   with (`aes_hls::iv_for_sequence`). An explicit IV would apply to EVERY
//!   following segment and break decryption from segment 1 on.
//! * The key line is written AFTER `#EXT-X-MAP`: §4.3.2.4 makes a key apply
//!   to every Media Initialization Section declared after it, so a key
//!   line before the map would tell players to decrypt the (clear) init
//!   segment. Map first, key second = clear init, encrypted segments — the
//!   layout ffmpeg, hls.js and Safari agree on. SAMPLE-AES (FairPlay) keeps
//!   Apple's key-before-map order; sample encryption never touches the init.
//!
//! Worker-agnostic: callers supply closures producing segment URIs (which
//! embed the token) and the init segment URI.

use crate::schema::{MediaIndex, StreamManifest};

fn fmt_secs(dts: u64, timescale: u32) -> String {
    let v = dts as f64 / timescale.max(1) as f64;
    format!("{v:.5}")
}

/// What `#EXT-X-KEY` line (if any) the media playlist should carry.
///
/// * `None`                     — clean output
/// * `Aes128 { uri }`           — classic HLS AES-128 (worker encrypts
///   segments; IV = media sequence number, implicit)
/// * `SampleAesCenc { skd_uri, kid_uuid }` — FairPlay/`sample-aes-cenc` for
///   pre-encrypted CENC content (Apple path). Segments pass through
///   untouched; Safari + KSM handle decryption.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaKey {
    Aes128 { uri: String },
    SampleAesCenc { skd_uri: String, kid_uuid: String },
}

pub fn media_playlist(
    idx: &MediaIndex,
    init_uri: &str,
    seg_url: &dyn Fn(usize) -> String,
    encrypt: Option<MediaKey>,
) -> String {
    let ts = idx.primary_timescale();
    let mut out = String::with_capacity(idx.segments.len() * 48 + 320);
    out.push_str("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n");
    out.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    let max_dur = idx.segments.iter().map(|s| s.duration).max().unwrap_or(0);
    let target = (max_dur as f64 / ts as f64).round().max(1.0) as u64;
    out.push_str(&format!("#EXT-X-TARGETDURATION:{}\n", target));
    out.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
    match encrypt {
        Some(MediaKey::Aes128 { uri }) => {
            out.push_str(&format!("#EXT-X-MAP:URI=\"{init_uri}\"\n"));
            out.push_str(&format!("#EXT-X-KEY:METHOD=AES-128,URI=\"{uri}\"\n"));
        }
        Some(MediaKey::SampleAesCenc { skd_uri, kid_uuid }) => {
            // FairPlay streamingkeydelivery + CENC variant (multi-DRM):
            // Safari reads skd://; the urn:uuid KEYFORMAT carries the KID
            // matching the CENC metadata inside the (pre-encrypted) segments.
            out.push_str(&format!(
                "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"{skd_uri}\",KEYFORMAT=\"com.apple.streamingkeydelivery\",KEYFORMATVERSIONS=\"1\"\n"
            ));
            out.push_str(&format!(
                "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"{skd_uri}\",KEYFORMAT=\"urn:uuid:{kid_uuid}\",KEYFORMATVERSIONS=\"1\"\n"
            ));
            out.push_str(&format!("#EXT-X-MAP:URI=\"{init_uri}\"\n"));
        }
        None => out.push_str(&format!("#EXT-X-MAP:URI=\"{init_uri}\"\n")),
    }
    for (i, seg) in idx.segments.iter().enumerate() {
        out.push_str(&format!(
            "#EXTINF:{},\n{}\n",
            fmt_secs(seg.duration, ts),
            seg_url(i)
        ));
    }
    out.push_str("#EXT-X-ENDLIST\n");
    out
}

/// Per-variant attributes the master playlist needs (read from each
/// rendition's index.json by the caller).
#[derive(Debug, Clone, Default)]
pub struct VariantInfo {
    /// index into `stream.renditions`
    pub index: usize,
    /// RFC 6381 codecs of the rendition's own tracks
    pub codecs: String,
    pub resolution: Option<(u16, u16)>,
    /// measured average bitrate (bits/s), when known
    pub average_bandwidth: Option<u64>,
}

/// A separate audio rendition group (`#EXT-X-MEDIA:TYPE=AUDIO`).
#[derive(Debug, Clone, Default)]
pub struct AudioGroupInfo {
    /// media playlist URI of the audio rendition (token embedded)
    pub uri: String,
    /// RFC 6381 codec of the audio track (merged into every variant's CODECS)
    pub codecs: String,
    pub name: String,
    pub language: Option<String>,
    pub channels: Option<u16>,
}

/// Master playlist from a stream manifest. `stream.renditions[i].path` must
/// already be the URI the player should fetch (the worker rewrites it to
/// `/media/…?token=…` before calling).
pub fn master_playlist(
    stream: &StreamManifest,
    variants: &[VariantInfo],
    audio: Option<&AudioGroupInfo>,
) -> String {
    let mut out = String::new();
    out.push_str("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n");
    if let Some(a) = audio {
        out.push_str(&format!(
            "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",NAME=\"{}\"",
            escape(&a.name)
        ));
        if let Some(lang) = &a.language {
            out.push_str(&format!(",LANGUAGE=\"{}\"", escape(lang)));
        }
        out.push_str(",DEFAULT=YES,AUTOSELECT=YES");
        if let Some(ch) = a.channels {
            out.push_str(&format!(",CHANNELS=\"{ch}\""));
        }
        out.push_str(&format!(",URI=\"{}\"\n", a.uri));
    }
    for v in variants {
        let Some(rend) = stream.renditions.get(v.index) else {
            continue;
        };
        let mut codecs: Vec<&str> = v.codecs.split(',').filter(|c| !c.is_empty()).collect();
        if let Some(a) = audio {
            for c in a.codecs.split(',').filter(|c| !c.is_empty()) {
                if !codecs.contains(&c) {
                    codecs.push(c);
                }
            }
        }
        let mut attrs = format!("BANDWIDTH={}", rend.bitrate.max(1));
        if let Some(avg) = v.average_bandwidth {
            if avg > 0 {
                attrs.push_str(&format!(
                    ",AVERAGE-BANDWIDTH={}",
                    avg.min(rend.bitrate.max(avg))
                ));
            }
        }
        if !codecs.is_empty() {
            attrs.push_str(&format!(",CODECS=\"{}\"", codecs.join(",")));
        }
        if let Some((w, h)) = v.resolution {
            if w > 0 && h > 0 {
                attrs.push_str(&format!(",RESOLUTION={w}x{h}"));
            }
        }
        if audio.is_some() {
            attrs.push_str(",AUDIO=\"aud\"");
        }
        if let Some(name) = &rend.name {
            attrs.push_str(&format!(",NAME=\"{}\"", escape(name)));
        }
        out.push_str(&format!("#EXT-X-STREAM-INF:{attrs}\n{}\n", rend.path));
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('"', "'").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    fn idx() -> MediaIndex {
        let f = crate::testmp4::regular_two_track();
        let (moov_h, moov) = crate::moov::find_moov(&f, 0).unwrap();
        let tracks = crate::moov::parse_tracks(&moov, moov_h.content_start).unwrap();
        crate::index_builder::build_index(
            SourceInfo {
                key: "v.mp4".into(),
                size: f.len() as u64,
                etag: None,
            },
            tracks,
            1000,
            &crate::index_builder::BuildOptions {
                target_segment_ms: 1500,
            },
        )
        .unwrap()
    }

    #[test]
    fn media_playlist_structure() {
        let idx = idx();
        let seg_url = |i: usize| format!("seg-{i}.m4s?tok=x");
        let pl = media_playlist(
            &idx,
            "init.mp4?tok=x",
            &seg_url,
            Some(MediaKey::Aes128 {
                uri: "key.bin?tok=x".into(),
            }),
        );
        assert!(pl.starts_with("#EXTM3U\n"));
        assert!(pl.contains("#EXT-X-VERSION:7"));
        assert!(pl.contains("#EXT-X-MAP:URI=\"init.mp4?tok=x\""));
        // no IV attribute: IV = media sequence number, matching the encryptor
        assert!(pl.contains("#EXT-X-KEY:METHOD=AES-128,URI=\"key.bin?tok=x\"\n"));
        assert!(!pl.contains("IV="));
        // map BEFORE key: the init segment is served in the clear
        assert!(pl.find("#EXT-X-MAP").unwrap() < pl.find("#EXT-X-KEY").unwrap());
        assert!(pl.contains("\nseg-0.m4s?tok=x\n"));
        assert!(pl.contains("#EXTINF:2."));
        assert!(pl.trim_end().ends_with("#EXT-X-ENDLIST"));
        let segs = pl.matches("#EXTINF").count();
        assert_eq!(segs, idx.segments.len());
        // target duration = rounded longest segment (2.4s → 2), never 0
        assert!(pl.contains("#EXT-X-TARGETDURATION:2\n"));
    }

    #[test]
    fn media_playlist_sample_aes_multi_drm() {
        let idx = idx();
        let seg_url = |i: usize| format!("seg-{i}.m4s?tok=x");
        let pl = media_playlist(
            &idx,
            "init.mp4?tok=x",
            &seg_url,
            Some(MediaKey::SampleAesCenc {
                skd_uri: "skd://movie".into(),
                kid_uuid: "11223344-5566-7788-9900-112233445566".into(),
            }),
        );
        assert!(pl.contains(
            "METHOD=SAMPLE-AES,URI=\"skd://movie\",KEYFORMAT=\"com.apple.streamingkeydelivery\""
        ));
        assert!(pl.contains("KEYFORMAT=\"urn:uuid:11223344-5566-7788-9900-112233445566\""));
    }

    fn manifest() -> StreamManifest {
        StreamManifest {
            renditions: vec![
                Rendition {
                    path: "media/720.m3u8?tok=x".into(),
                    bitrate: 2_500_000,
                    name: Some("720p".into()),
                    source: None,
                },
                Rendition {
                    path: "media/360.m3u8?tok=x".into(),
                    bitrate: 800_000,
                    name: Some("360p".into()),
                    source: None,
                },
            ],
            audio: None,
            segment_duration_ms: None,
        }
    }

    #[test]
    fn master_playlist_structure() {
        let variants = vec![
            VariantInfo {
                index: 0,
                codecs: "avc1.64001f,mp4a.40.2".into(),
                resolution: Some((1280, 720)),
                average_bandwidth: Some(2_000_000),
            },
            VariantInfo {
                index: 1,
                codecs: "avc1.64001e,mp4a.40.2".into(),
                resolution: Some((640, 360)),
                average_bandwidth: None,
            },
        ];
        let pl = master_playlist(&manifest(), &variants, None);
        assert!(pl.contains("#EXT-X-STREAM-INF:BANDWIDTH=2500000,AVERAGE-BANDWIDTH=2000000,CODECS=\"avc1.64001f,mp4a.40.2\",RESOLUTION=1280x720,NAME=\"720p\"\nmedia/720.m3u8?tok=x\n"));
        assert!(pl.contains("#EXT-X-STREAM-INF:BANDWIDTH=800000,CODECS=\"avc1.64001e,mp4a.40.2\",RESOLUTION=640x360,NAME=\"360p\"\nmedia/360.m3u8?tok=x\n"));
        assert!(!pl.contains("AUDIO="));
    }

    #[test]
    fn master_playlist_with_audio_group() {
        let variants = vec![VariantInfo {
            index: 0,
            codecs: "avc1.64001f".into(),
            resolution: Some((1280, 720)),
            average_bandwidth: None,
        }];
        let audio = AudioGroupInfo {
            uri: "media/aud.m3u8?tok=x".into(),
            codecs: "mp4a.40.2".into(),
            name: "English".into(),
            language: Some("en".into()),
            channels: Some(2),
        };
        let pl = master_playlist(&manifest(), &variants, Some(&audio));
        assert!(pl.contains("#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",NAME=\"English\",LANGUAGE=\"en\",DEFAULT=YES,AUTOSELECT=YES,CHANNELS=\"2\",URI=\"media/aud.m3u8?tok=x\"\n"));
        // the audio codec is merged into the variant CODECS and the group is referenced
        assert!(pl.contains("CODECS=\"avc1.64001f,mp4a.40.2\",RESOLUTION=1280x720,AUDIO=\"aud\""));
    }
}
