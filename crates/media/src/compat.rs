// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Browser playability of codec strings — what `MediaSource.isTypeSupported`
//! will say about a rendition before a single byte is fetched.
//!
//! The worker never transcodes, so the only lever is choosing which of a
//! file's tracks to serve and telling the operator plainly when the served
//! codecs cannot play in browsers (Shaka reports 4032
//! CONTENT_UNSUPPORTED_BY_BROWSER, hls.js "incompatible codecs" — neither
//! says why).

/// How widely a codec plays in browsers' MediaSource implementations:
/// 0 = everywhere (AAC-LC/HE-AAC, Opus, FLAC, H.264, AV1, VP9),
/// 1 = platform-dependent (Dolby Digital, HEVC), 2 = effectively nowhere.
pub fn support_tier(codec: &str) -> u8 {
    let c = codec.to_ascii_lowercase();
    if let Some(aot) = c.strip_prefix("mp4a.40.") {
        return match aot {
            "2" | "5" | "29" | "42" => 0,
            _ => 2, // Main (1), SSR (3), LTP (4), ...: rejected by isTypeSupported
        };
    }
    if c.starts_with("avc1")
        || c.starts_with("avc3")
        || c.starts_with("av01")
        || c.starts_with("vp09")
    {
        return 0;
    }
    if c == "opus" || c == "flac" || c == "mp4a.6b" || c == "mp4a.69" {
        return 0;
    }
    if c.starts_with("hvc1") || c.starts_with("hev1") || c == "ac-3" || c == "ec-3" {
        return 1;
    }
    2
}

/// A one-line explanation for codecs of tier 1–2, with the usual fix.
pub fn support_note(codec: &str) -> Option<String> {
    let c = codec.to_ascii_lowercase();
    let note = if let Some(aot) = c.strip_prefix("mp4a.40.") {
        match aot {
            "2" | "5" | "29" | "42" => return None,
            "1" => "AAC Main profile — browsers' MediaSource only accepts AAC-LC/HE-AAC; re-encode the audio (ffmpeg -c:v copy -c:a aac)",
            "3" | "4" => "AAC SSR/LTP profile — not accepted by browsers' MediaSource; re-encode the audio (ffmpeg -c:v copy -c:a aac)",
            _ => "unusual AAC object type — likely rejected by browsers' MediaSource; re-encode the audio to AAC-LC",
        }
    } else if c == "ac-3" || c == "ec-3" {
        "Dolby Digital — decodable by Safari/Edge only; Chrome and Firefox reject it. Publish an AAC audio rendition (or re-encode: ffmpeg -c:v copy -c:a aac)"
    } else if c.starts_with("hvc1") || c.starts_with("hev1") {
        "HEVC — plays only where the browser has hardware HEVC decoding (Safari; Chrome on supported GPUs); never in Firefox"
    } else if c.starts_with("dvh") || c.starts_with("dva") {
        "Dolby Vision — Safari only"
    } else if c.starts_with("dts") || c == "mlpa" || c == "alac" || c == "ac-4" {
        "not decodable by browsers' MediaSource; publish an AAC audio rendition"
    } else if support_tier(&c) == 0 {
        return None;
    } else {
        "codec unknown to browsers' MediaSource — expect isTypeSupported to fail"
    };
    Some(format!("{codec}: {note}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_and_notes() {
        assert_eq!(support_tier("mp4a.40.2"), 0);
        assert_eq!(support_tier("mp4a.40.5"), 0);
        assert_eq!(support_tier("mp4a.40.1"), 2);
        assert_eq!(support_tier("ac-3"), 1);
        assert_eq!(support_tier("hvc1.1.6.L120.90"), 1);
        assert_eq!(support_tier("avc1.64001E"), 0);
        assert_eq!(support_tier("Opus"), 0);
        assert!(support_note("mp4a.40.2").is_none());
        assert!(support_note("mp4a.40.1").unwrap().contains("AAC Main"));
        assert!(support_note("ec-3").unwrap().contains("Dolby Digital"));
        assert!(support_note("hev1.1.6.L93.B0").unwrap().contains("HEVC"));
    }
}
