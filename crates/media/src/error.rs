// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("unexpected EOF at offset {offset}, needed {needed} bytes")]
    Eof { offset: u64, needed: usize },

    #[error("invalid box type {0:?} at offset {1}")]
    BadBoxType(String, u64),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("track {0} not found")]
    TrackNotFound(u32),

    #[error("no tracks of type {0}")]
    NoTrackOfType(String),

    #[error("segment {0} out of range (count {1})")]
    SegmentOutOfRange(usize, usize),

    #[error("index stale: source size {0} != index size {1}")]
    IndexStale(u64, u64),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("codec error: {0}")]
    Codec(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
