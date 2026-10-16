// Copyright 2026- Seongwoo Hong. All rights reserved.

//! gorani-media — the MP4 engine of the video sidecar (docs/VIDEO.md,
//! commit 39p): an ISO-BMFF parser, the index builder (keyframe-aligned
//! segments with their sample tables and PLAINTEXT byte ranges), and the
//! fMP4 init / media segment muxers.
//!
//! Vendored from the author's own `mp4-hls-core` (the stream-worker
//! project), trimmed to what gorani needs. Gone: FairPlay, AES-128 HLS,
//! DASH and the token signer — there the SERVER assembled segments from
//! plaintext it could read; here the server never reads a byte, so this
//! runs in the browser (crates/media-wasm) and in the native clients, over
//! frames they decrypted themselves. Key handling never enters this crate:
//! it parses boxes and builds segments, nothing else.

pub mod boxes;
pub mod bytes;
pub mod compat;
pub mod error;
pub mod index_builder;
pub mod indexer;
pub mod moof_builder;
pub mod moov;
pub mod moov_builder;
pub mod parse_frag;
pub mod playlist;
pub mod readplan;
pub mod sample_entry;
pub mod schema;
pub mod split;
pub mod tables;

#[cfg(any(test, feature = "fixtures"))]
pub mod testmp4;

pub use error::{CoreError, Result};
