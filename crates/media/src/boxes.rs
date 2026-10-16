// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! ISO-BMFF ("ISO Base Media File Format", a.k.a. MP4) box primitives.
//!
//! # 30-second MP4 primer
//!
//! An MP4 file is a tree of *boxes*. Every box starts with:
//! ```text
//! [u32 size][u8 type×4][payload...]
//! ```
//! `size` counts the header itself. A size of `1` means a 64-bit `largesize`
//! follows the type (huge boxes); `0` means "until end of file".
//!
//! Container boxes (`moov`, `trak`, `mdia`, `minf`, `stbl`, `moof`, `traf`,
//! ...) simply contain other boxes; leaf boxes carry typed data.
//!
//! Two boxes matter for streaming:
//! * `moov` — the *sample table* (index of every audio/video sample: where it
//!   sits in the file, how big, how long). A `moov` at the file end forces a
//!   full read before the first byte can play ("moov at end", bad for streaming).
//! * `moof` — a *movie fragment*: a per-fragment sample index used by fMP4
//!   (CMAF). `moof` boxes are interleaved with `mdat` (raw media) chunks.
//!
//! # Absolute vs relative offsets
//!
//! All offsets in this module are *absolute* — relative to the start of the
//! source object, not the buffer. That matters because the worker never holds
//! whole files: buffers are ranged R2 reads whose first byte may be at
//! arbitrary offset. Every parse function therefore takes the buffer's base
//! offset (`buf_base`) alongside the buffer itself.

use crate::bytes::ByteReader;
use crate::error::{CoreError, Result};

pub const FTYP: &[u8; 4] = b"ftyp";
pub const MOOV: &[u8; 4] = b"moov";
pub const MOOF: &[u8; 4] = b"moof";
pub const SIDX: &[u8; 4] = b"sidx";
pub const MDAT: &[u8; 4] = b"mdat";
pub const MFRP: &[u8; 4] = b"mfro";

/// A parsed box header: `type` plus absolute offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxHeader {
    pub box_type: [u8; 4],
    /// absolute offset of the box start (size field)
    pub start: u64,
    /// absolute offset of the first byte after the header
    pub content_start: u64,
    /// total box size in bytes (including header; largesize-aware)
    pub size: u64,
}

impl BoxHeader {
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    pub fn content_size(&self) -> u64 {
        self.size - (self.content_start - self.start)
    }

    /// Parse a header at `abs_offset` from a buffer whose first byte is at
    /// absolute offset `buf_base`. Reads at most 16 bytes.
    pub fn parse_at(buf: &[u8], buf_base: u64, abs_offset: u64) -> Result<BoxHeader> {
        let rel = (abs_offset - buf_base) as usize;
        if rel + 8 > buf.len() {
            return Err(CoreError::Eof {
                offset: buf_base + buf.len() as u64,
                needed: 8,
            });
        }
        let mut r = ByteReader::with_base(&buf[rel..], abs_offset);
        let mut size = r.u32()? as u64;
        let mut box_type = [0u8; 4];
        box_type.copy_from_slice(r.bytes(4)?);
        let mut content_start = abs_offset + 8;
        if size == 1 {
            // largesize
            size = r.u64()?;
            content_start = abs_offset + 16;
        } else if size == 0 {
            return Err(CoreError::Unsupported(
                "box size 0 (to end of file) not supported in this position".into(),
            ));
        }
        if size < (content_start - abs_offset) {
            return Err(CoreError::Parse(format!(
                "box {:?} at {abs_offset}: size {size} smaller than header",
                String::from_utf8_lossy(&box_type)
            )));
        }
        Ok(BoxHeader {
            box_type,
            start: abs_offset,
            content_start,
            size,
        })
    }
}

/// Scan top-level boxes in `buf` (which starts at absolute `buf_base` and
/// covers up to `total_size` bytes of the source), invoking `f` per box.
/// If `f` returns false, scanning stops early. Boxes whose payload extends
/// past `buf` are still reported (header only) — callers decide whether the
/// content is needed and must range-read it separately.
pub fn walk_top_level<F>(buf: &[u8], buf_base: u64, mut f: F) -> Result<()>
where
    F: FnMut(BoxHeader) -> bool,
{
    let mut offset = buf_base;
    let end = buf_base + buf.len() as u64;
    while offset + 8 <= end {
        let h = BoxHeader::parse_at(buf, buf_base, offset)?;
        if h.size < 8 {
            return Err(CoreError::Parse(format!(
                "degenerate box size {} at {offset}",
                h.size
            )));
        }
        if !f(h) {
            return Ok(());
        }
        offset = h.end();
    }
    Ok(())
}

/// Iterate child boxes of a container whose content slice is `content`
/// starting at absolute `content_start`.
pub fn walk_children<F>(content: &[u8], content_start: u64, f: F) -> Result<()>
where
    F: FnMut(BoxHeader) -> bool,
{
    walk_top_level(content, content_start, f)
}

/// Extract a child-content slice for a box header from its containing buffer.
pub fn content_of<'a>(buf: &'a [u8], buf_base: u64, h: &BoxHeader) -> &'a [u8] {
    let rel = (h.content_start - buf_base) as usize;
    let end = ((h.end() - buf_base) as usize).min(buf.len());
    &buf[rel..end]
}

/// Find a child box by type; returns its content byte slice.
pub fn find_child<'a>(
    content: &'a [u8],
    content_start: u64,
    fourcc: &[u8; 4],
) -> Result<Option<(BoxHeader, &'a [u8])>> {
    let mut found = None;
    walk_children(content, content_start, |h| {
        if &h.box_type == fourcc {
            let rel = (h.content_start - content_start) as usize;
            let end_rel = (h.end() - content_start) as usize;
            if end_rel <= content.len() {
                found = Some((h, &content[rel..end_rel]));
            } else {
                // content truncated; return what we have
                found = Some((h, &content[rel..]));
            }
            return false;
        }
        true
    })?;
    Ok(found)
}

/// One top-level box as seen by a header-only ("lazy") walk of a large
/// object: the worker and the CLI read 16-byte headers and skip payloads
/// analytically, so multi-GB files are indexed without touching `mdat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopBox {
    pub offset: u64,
    pub box_type: [u8; 4],
    /// total box size including its header
    pub size: u64,
    /// 8 (32-bit size) or 16 (largesize)
    pub header_len: u8,
}

impl TopBox {
    pub fn end(&self) -> u64 {
        self.offset + self.size
    }
}

/// Parse one top-level header from `hdr` (the first 8–16 bytes of the box at
/// absolute `offset`, in an object of `file_size` bytes). `size == 0`
/// ("to end of file") is legal for the last box only.
pub fn parse_top_header(hdr: &[u8], offset: u64, file_size: u64) -> Result<TopBox> {
    if hdr.len() < 8 {
        return Err(CoreError::Eof { offset, needed: 8 });
    }
    let size32 = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as u64;
    let box_type: [u8; 4] = hdr[4..8].try_into().unwrap();
    let (size, header_len) = match size32 {
        1 => {
            if hdr.len() < 16 {
                return Err(CoreError::Eof { offset, needed: 16 });
            }
            (u64::from_be_bytes(hdr[8..16].try_into().unwrap()), 16u8)
        }
        0 => (file_size.saturating_sub(offset), 8u8),
        s => (s, 8u8),
    };
    if size < header_len as u64 {
        return Err(CoreError::Parse(format!(
            "corrupt box header at {offset}: size {size} smaller than header"
        )));
    }
    if offset + size > file_size {
        return Err(CoreError::Parse(format!(
            "box {:?} at {offset} (size {size}) extends past end of file ({file_size})",
            String::from_utf8_lossy(&box_type)
        )));
    }
    Ok(TopBox {
        offset,
        box_type,
        size,
        header_len,
    })
}

/// End of the fragment whose `moof` is `boxes[moof_idx]`: the start of the
/// first later top-level box that is not an `mdat`. A fragment is
/// `moof` + its `mdat`(s); anything else that follows (`mfra`, `sidx`,
/// `styp`, `free`, the next `moof`) belongs to the file or the next
/// fragment, never to this segment.
pub fn fragment_end(boxes: &[TopBox], moof_idx: usize, file_size: u64) -> u64 {
    boxes[moof_idx + 1..]
        .iter()
        .find(|b| &b.box_type != MDAT)
        .map(|b| b.offset)
        .unwrap_or(file_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::ByteWriter;

    fn sample_file() -> Vec<u8> {
        let mut w = ByteWriter::new();
        let ftyp = w.open_box(b"ftyp");
        w.u32(0x69736f6d); // major brand "isom"
        w.u32(0x200); // minor
        w.close_box(ftyp).unwrap();
        let free = w.open_box(b"free");
        w.zeros(10);
        w.close_box(free).unwrap();
        let mdat = w.open_box(b"mdat");
        w.bytes(&[0xAAu8; 32]);
        w.close_box(mdat).unwrap();
        w.into_vec()
    }

    #[test]
    fn walk_and_find() {
        let f = sample_file();
        let mut types = Vec::new();
        walk_top_level(&f, 0, |h| {
            types.push(h.box_type);
            true
        })
        .unwrap();
        assert_eq!(types[0], *b"ftyp");
        assert_eq!(types[1], *b"free");
        assert_eq!(types[2], *b"mdat");

        let (h, content) = find_child(&f, 0, b"mdat").unwrap().unwrap();
        assert_eq!(h.start, 34); // ftyp 16 + free 18
        assert_eq!(content.len(), 32);
        assert_eq!(content[0], 0xAA);
    }

    #[test]
    fn largesize_header() {
        let mut w = ByteWriter::new();
        // size=1, type, largesize
        w.u32(1);
        w.buf.extend_from_slice(b"mdat");
        w.u64(8 + 16 + 8);
        w.zeros(16);
        // trailing box
        w.u32(8);
        w.buf.extend_from_slice(b"free");
        let f = w.into_vec();
        let mut seen = Vec::new();
        walk_top_level(&f, 0, |h| {
            seen.push((h.box_type, h.content_start, h.end()));
            true
        })
        .unwrap();
        assert_eq!(seen[0].0, *b"mdat");
        assert_eq!(seen[0].1, 16);
        assert_eq!(seen[0].2, 32);
        assert_eq!(seen[1].0, *b"free");
    }

    #[test]
    fn fragment_end_excludes_trailing_mfra() {
        let b = |off: u64, t: &[u8; 4], size: u64| TopBox {
            offset: off,
            box_type: *t,
            size,
            header_len: 8,
        };
        let boxes = vec![
            b(0, b"ftyp", 24),
            b(24, b"moov", 100),
            b(124, b"moof", 50),
            b(174, b"mdat", 1000),
            b(1174, b"moof", 50),
            b(1224, b"mdat", 1000),
            b(2224, b"mfra", 40),
        ];
        assert_eq!(fragment_end(&boxes, 2, 2264), 1174);
        assert_eq!(fragment_end(&boxes, 4, 2264), 2224);
        let h = parse_top_header(&[0, 0, 0, 0, b'm', b'd', b'a', b't'], 100, 500).unwrap();
        assert_eq!(h.size, 400);
        assert!(parse_top_header(&[0, 0, 4, 0, b'm', b'd', b'a', b't'], 100, 500).is_err());
    }
}
