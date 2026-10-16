// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Index schema: everything the worker needs to package HLS without
//! re-parsing the MP4. One `index.json` per rendition directory in R2.
//!
//! # Why an index at all?
//!
//! Parsing a full `moov` per request would cost CPU and several R2 reads
//! (moov can be megabytes). Instead, the indexer CLI (or an upload job)
//! parses the source *once* and stores this compact JSON next to it. At
//! serve time the worker only needs:
//!   * `index.json` (one GET) → playlists, init segments, segment maps
//!   * `byte_ranges` per segment → raw sample bytes for Case B assembly
//!
//! # The two source kinds
//!
//! * `Regular` — classic MP4 (moov + one mdat). Segments are *cut* from the
//!   sample table; the worker assembles moof/mdat on the fly (Case B).
//! * `Fragmented` — fMP4 (CMAF). Segments are stored fragments; the worker
//!   passes the exact byte range through (Case A, near-zero CPU).
//!
//! # Field conventions
//!
//! * All `*_deltas` lists: the FIRST element is an absolute value; every
//!   subsequent element is a delta from the previous (prefix-sum to expand).
//! * `Option` + `skip_serializing_if` keeps absent data out of the JSON so
//!   long files don't bloat.
//! * Every field added after schema version 1 shipped carries
//!   `#[serde(default)]` so older `index.json` files keep deserializing —
//!   the worker treats a missing value as "compute the legacy way".
//!
//! One `index.json` per source object in R2.

use serde::{Deserialize, Serialize};

pub const INDEX_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceInfo {
    /// storage key of the media. A bare file name (what `r2-index` writes)
    /// means "next to this index" — the worker resolves it relative to the
    /// index's own location; the worker's indexer writes the full key.
    pub key: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrackType {
    Video,
    Audio,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// plain (non-fragmented) MP4 — sample tables only
    Regular,
    /// fragmented MP4 (moof-driven)
    Fragmented,
}

/// Raw track-level metadata. `stsd_b64` carries the exact sample-entry box
/// bytes (avc1/hev1/mp4a...) so the worker can build a valid init segment
/// without re-reading the source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Track {
    pub id: u32,
    #[serde(rename = "type")]
    pub track_type: TrackType,
    /// RFC-6381 codec string, e.g. "avc1.64001f", "mp4a.40.2"
    pub codec_string: String,
    /// mdhd timescale
    pub timescale: u32,
    /// total duration in timescale units
    pub duration: u64,
    /// Legacy field (always 0 in practice). Kept for on-disk compatibility;
    /// see `edit_media_time` for the edit-list offset that actually matters.
    #[serde(default)]
    pub base_dts: i64,
    /// `media_time` of the track's first non-empty edit (trak/edts/elst), in
    /// track timescale units. For B-frame video this is the presentation
    /// offset ffmpeg records so that frame 0 displays at t=0; the segment
    /// builder subtracts it from composition offsets (trun v1, signed), which
    /// is exactly what CMAF packagers do instead of shipping an edit list.
    #[serde(default)]
    pub edit_media_time: i64,
    /// width (video) or 0
    pub width: u16,
    /// height (video) or 0
    pub height: u16,
    /// raw sample entry box bytes (from stsd), including 8-byte header
    pub stsd_b64: String,
    /// For fragmented sources: default sample duration/flags/size from trex
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trex: Option<TrexDefaults>,
    /// timescale of the enclosing movie (mvhd)
    pub movie_timescale: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct TrexDefaults {
    pub default_sample_description_index: u32,
    pub default_sample_duration: u32,
    pub default_sample_size: u32,
    pub default_sample_flags: u32,
}

/// A byte range in the source object.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

impl ByteRange {
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }
}

/// One HLS media segment = one aligned group of source samples
/// (regular MP4s), or one fragment (fragmented MP4s).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Segment {
    /// decode time (timescale of the primary track) of segment start
    pub start_dts: i64,
    /// duration in primary-track timescale
    pub duration: u64,
    /// per-track sample runs
    pub tracks: Vec<SegmentTrack>,
    /// byte range covering the whole fragment (fragmented sources only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_range: Option<ByteRange>,
}

/// Samples of one track within a segment. For regular MP4s we store the
/// compact sample run: first sample index + count; byte positions are
/// derived from the sample table delta list stored in the index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SegmentTrack {
    pub track_id: u32,
    /// index of first sample (into the track's sample table) in this segment
    pub first_sample: u32,
    pub sample_count: u32,
    /// duration of first sample (timescale units)
    pub first_sample_duration: u32,
    /// sum of sample durations
    pub duration: u64,
    /// EXACT decode time of this track's first sample in the segment, in the
    /// track's own timescale. This is what `tfdt` must carry; older indexes
    /// omit it and the builder reconstructs it by summing prior segments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_dts: Option<i64>,
    /// compose offsets (cts - dts) of the samples, delta-encoded, first is absolute
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cts_deltas: Vec<i64>,
    /// sample sizes delta-encoded (only when they vary; uniform case stores size once)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uniform_sample_size: Option<u32>,
    /// delta-encoded sample sizes when non-uniform
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_size_deltas: Option<Vec<i64>>,
    /// delta-encoded sample durations when non-uniform
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_duration_deltas: Option<Vec<i64>>,
    /// In-segment indexes (0-based) of additional sync samples for video
    /// tracks. Sample 0 is always a sync sample (segments are cut on
    /// keyframes) and is not listed. Audio tracks leave this empty — every
    /// audio sample is a sync sample.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_samples: Vec<u32>,
    /// absolute file offset of first sample (== byte_ranges[0].offset)
    pub first_sample_offset: u64,
    /// merged contiguous byte ranges covering the segment's samples for this
    /// track (regular sources; interleaved A/V produces multiple ranges).
    /// Empty for fragmented sources (fragment_range applies instead).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byte_ranges: Vec<ByteRange>,
}

/// The complete per-source index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MediaIndex {
    pub version: u32,
    pub source: SourceInfo,
    pub kind: SourceKind,
    /// primary track id (video preferred) used for segment timing
    pub primary_track_id: u32,
    pub tracks: Vec<Track>,
    /// master playlist metadata
    pub duration_ms: u64,
    pub segments: Vec<Segment>,
    /// sidx reference for fragmented sources (speeds up nothing at serve time
    /// but documents the source layout)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidx_range: Option<ByteRange>,
    /// byte range of the moov box in the source (fragmented sources only;
    /// used to serve the init segment without re-parsing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moov_range: Option<ByteRange>,
    /// Present on a SPLIT index: this document is the header only — every
    /// `segments[i].tracks` is empty and the sample runs live in shard
    /// objects addressed through `split::shard_key`. Absent on a classic
    /// single-document index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs: Option<RunsLayout>,
    /// Total media bytes referenced, recorded when the runs are split out
    /// (the header alone can no longer sum them); see `media_bytes()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_bytes: Option<u64>,
}

/// Where a split index keeps its sample runs (see the `split` module).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunsLayout {
    /// segments per shard object
    pub shard_segments: u32,
    /// opaque id baked into every shard key; a re-index mints a new one, so
    /// a header can never be paired with shards from an older build
    pub id: String,
}

/// One shard of a split index: the sample runs of `shard_segments`
/// consecutive segments starting at `first_segment`. Each entry repeats
/// the segment's timing so a shard is checkable against its header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunsShard {
    pub version: u32,
    pub first_segment: u32,
    pub segments: Vec<Segment>,
}

impl MediaIndex {
    pub fn track(&self, id: u32) -> Option<&Track> {
        self.tracks.iter().find(|t| t.id == id)
    }

    pub fn primary_track(&self) -> Option<&Track> {
        self.track(self.primary_track_id)
    }

    pub fn primary_timescale(&self) -> u32 {
        self.primary_track()
            .map(|t| t.timescale)
            .unwrap_or(1000)
            .max(1)
    }

    pub fn video_track(&self) -> Option<&Track> {
        self.tracks
            .iter()
            .find(|t| t.track_type == TrackType::Video)
    }

    pub fn audio_track(&self) -> Option<&Track> {
        self.tracks
            .iter()
            .find(|t| t.track_type == TrackType::Audio)
    }

    /// RFC 6381 codec list for HLS `CODECS=` / DASH `codecs=`.
    pub fn codec_string(&self) -> String {
        self.tracks
            .iter()
            .map(|t| t.codec_string.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Re-derive every track's codec string from its stored sample entry.
    /// The string is what players are told (`CODECS=`, `codecs=`), so a
    /// parser fix must reach indexes that were written before it — the
    /// worker calls this on load. Returns how many strings changed; tracks
    /// whose entry no longer parses keep the stored string.
    pub fn refresh_codec_strings(&mut self) -> usize {
        let mut changed = 0;
        for t in &mut self.tracks {
            let bytes = b64_decode(&t.stsd_b64);
            if bytes.is_empty() {
                continue;
            }
            if let Ok(se) = crate::sample_entry::parse_sample_entry(&bytes) {
                if se.codec_string != t.codec_string {
                    t.codec_string = se.codec_string;
                    changed += 1;
                }
            }
        }
        changed
    }

    /// The CENC scheme the primary track was packaged with (`cenc`, `cbcs`),
    /// read from its sample entry; None for clear content.
    pub fn protection_scheme(&self) -> Option<String> {
        let t = self
            .tracks
            .iter()
            .find(|t| t.id == self.primary_track_id)
            .or(self.tracks.first())?;
        let bytes = b64_decode(&t.stsd_b64);
        crate::sample_entry::protection_scheme(&bytes)
            .map(|s| String::from_utf8_lossy(&s).to_string())
    }

    /// Why the served codecs may not play in browsers (empty = fine).
    pub fn compat_warnings(&self) -> Vec<String> {
        self.tracks
            .iter()
            .filter_map(|t| crate::compat::support_note(&t.codec_string))
            .collect()
    }

    /// True when the sample runs live in shard objects (header-only document).
    pub fn is_split(&self) -> bool {
        self.runs.is_some()
    }

    /// Total bytes of media referenced by the index (all segments). A split
    /// header reports the value recorded when it was split.
    pub fn media_bytes(&self) -> u64 {
        if let Some(b) = self.media_bytes {
            return b;
        }
        self.segments
            .iter()
            .map(|s| match s.fragment_range {
                Some(fr) => fr.length,
                None => s
                    .tracks
                    .iter()
                    .flat_map(|t| t.byte_ranges.iter())
                    .map(|r| r.length)
                    .sum(),
            })
            .sum()
    }

    /// Average bitrate estimate in bits per second (0 when unknown).
    pub fn estimated_bitrate(&self) -> u64 {
        if self.duration_ms == 0 {
            return 0;
        }
        (self.media_bytes() as f64 * 8.0 / (self.duration_ms as f64 / 1000.0)) as u64
    }
}

/// ABR manifest stored next to sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StreamManifest {
    pub renditions: Vec<Rendition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<AudioRendition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_duration_ms: Option<u64>,
}

impl StreamManifest {
    /// Reject manifests that would produce unroutable URLs or escape the
    /// stream's key space. Called by every admin write path.
    pub fn validate(&self) -> Result<(), String> {
        // an empty rendition list is legal (a freshly created stream); the
        // master playlist answers 404 until something is indexed
        for r in &self.renditions {
            validate_path(&r.path)?;
        }
        if let Some(a) = &self.audio {
            validate_path(&a.path)?;
        }
        Ok(())
    }
}

fn validate_path(p: &str) -> Result<(), String> {
    if p.is_empty() {
        return Err("rendition path must not be empty".into());
    }
    if p.starts_with('/') || p.ends_with('/') {
        return Err(format!(
            "rendition path {p:?} must not start or end with '/'"
        ));
    }
    if p.split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(format!(
            "rendition path {p:?} contains an empty or dot segment"
        ));
    }
    if p.contains(|c: char| c == '?' || c == '#' || c.is_control()) {
        return Err(format!(
            "rendition path {p:?} contains an illegal character"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rendition {
    /// key prefix (dir) of the rendition inside the bucket, no trailing slash
    pub path: String,
    /// peak bitrate in bits per second
    pub bitrate: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Where the BYTES live when the stream is not on R2. Absent for legacy
    /// R2 streams (path composition still works there).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RenditionSource>,
}

/// Backend pointer for a non-R2 rendition. `index_file_id` carries the
/// pre-resolved companion ID so the serving path does zero name lookups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RenditionSource {
    /// "box" | "s3" (R2 needs no entry — path composition is canonical)
    pub storage: String,
    /// Box file id of the MEDIA file (s3: unused — s3 uses `key`)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_id: String,
    /// Box file id of the index.json companion
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub index_file_id: String,
    /// Full store key for the media: "box:{id}" or "s3:{object-key}"
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
}

impl RenditionSource {
    /// The store key the worker should read the rendition's index from.
    pub fn index_key(&self) -> String {
        if !self.index_file_id.is_empty() {
            return format!("box:{}", self.index_file_id);
        }
        // s3 + box-by-name fallbacks compose from the media key's dir
        match self.key.strip_suffix(".mp4") {
            Some(stem) => format!("{stem}.index.json"),
            None => String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AudioRendition {
    pub path: String,
    pub bitrate: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RenditionSource>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let idx = MediaIndex {
            version: INDEX_VERSION,
            source: SourceInfo {
                key: "v/a.mp4".into(),
                size: 123,
                etag: Some("\"x\"".into()),
            },
            kind: SourceKind::Regular,
            primary_track_id: 1,
            tracks: vec![Track {
                id: 1,
                track_type: TrackType::Video,
                codec_string: "avc1.64001f".into(),
                timescale: 90000,
                duration: 900000,
                base_dts: 0,
                edit_media_time: 6006,
                width: 1280,
                height: 720,
                stsd_b64: "AAAA".into(),
                trex: None,
                movie_timescale: 1000,
            }],
            duration_ms: 10000,
            segments: vec![Segment {
                start_dts: 0,
                duration: 900000,
                tracks: vec![SegmentTrack {
                    track_id: 1,
                    first_sample: 0,
                    sample_count: 30,
                    first_sample_duration: 3000,
                    duration: 900000,
                    start_dts: Some(0),
                    cts_deltas: vec![0, 0],
                    uniform_sample_size: Some(1000),
                    sample_size_deltas: None,
                    sample_duration_deltas: None,
                    sync_samples: vec![12, 24],
                    first_sample_offset: 48,
                    byte_ranges: vec![ByteRange {
                        offset: 48,
                        length: 30_000,
                    }],
                }],
                fragment_range: None,
            }],
            sidx_range: None,
            moov_range: None,
            runs: None,
            media_bytes: None,
        };
        let s = serde_json::to_string(&idx).unwrap();
        let back: MediaIndex = serde_json::from_str(&s).unwrap();
        assert_eq!(back, idx);
        assert_eq!(back.media_bytes(), 30_000);
        assert_eq!(back.estimated_bitrate(), 24_000);
    }

    /// An index written before `start_dts` / `sync_samples` /
    /// `edit_media_time` existed must still deserialize (fields default).
    #[test]
    fn legacy_index_deserializes() {
        let legacy = r#"{
          "version":1,"source":{"key":"a.mp4","size":10},"kind":"regular","primary_track_id":1,
          "tracks":[{"id":1,"type":"video","codec_string":"avc1.64001f","timescale":900,
                     "duration":5400,"base_dts":0,"width":320,"height":180,"stsd_b64":"AAAA","movie_timescale":1000}],
          "duration_ms":6000,
          "segments":[{"start_dts":0,"duration":2400,"tracks":[{"track_id":1,"first_sample":0,"sample_count":24,
            "first_sample_duration":90,"duration":2400,"cts_deltas":[0,0],"uniform_sample_size":104,
            "first_sample_offset":2636,"byte_ranges":[{"offset":2636,"length":12504}]}]}]
        }"#;
        let idx: MediaIndex = serde_json::from_str(legacy).unwrap();
        assert_eq!(idx.tracks[0].edit_media_time, 0);
        assert_eq!(idx.segments[0].tracks[0].start_dts, None);
        assert!(idx.segments[0].tracks[0].sync_samples.is_empty());
    }

    #[test]
    fn manifest_validation() {
        let ok = StreamManifest {
            renditions: vec![Rendition {
                path: "movie/1080p".into(),
                bitrate: 1,
                name: None,
                source: None,
            }],
            audio: None,
            segment_duration_ms: None,
        };
        assert!(ok.validate().is_ok());
        for bad in ["", "/movie/1080p", "movie/../x", "movie//x", "a?b", "x/"] {
            let m = StreamManifest {
                renditions: vec![Rendition {
                    path: bad.into(),
                    bitrate: 1,
                    name: None,
                    source: None,
                }],
                audio: None,
                segment_duration_ms: None,
            };
            assert!(m.validate().is_err(), "{bad:?} should be rejected");
        }
        let empty = StreamManifest {
            renditions: vec![],
            audio: None,
            segment_duration_ms: None,
        };
        assert!(empty.validate().is_ok());
    }
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}
