// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Byte reading primitives over an in-memory buffer.
//!
//! All offsets are absolute (relative to the start of the source object),
//! because the buffer itself may be a ranged read of a larger file.

use crate::error::{CoreError, Result};

#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    buf: &'a [u8],
    /// absolute offset of buf[0] within the source object
    base: u64,
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            base: 0,
            pos: 0,
        }
    }

    pub fn with_base(buf: &'a [u8], base: u64) -> Self {
        Self { buf, base, pos: 0 }
    }

    pub fn pos(&self) -> u64 {
        self.base + self.pos as u64
    }

    pub fn abs_pos(&self) -> u64 {
        self.pos as u64
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn seek(&mut self, abs_offset: u64) -> Result<()> {
        let rel = abs_offset.checked_sub(self.base).ok_or_else(|| {
            CoreError::Parse(format!("seek {abs_offset} below base {}", self.base))
        })?;
        if rel as usize > self.buf.len() {
            return Err(CoreError::Eof {
                offset: self.base + self.buf.len() as u64,
                needed: rel as usize,
            });
        }
        self.pos = rel as usize;
        Ok(())
    }

    /// Skip forward; silently clamps at EOF (headers are validated elsewhere).
    pub fn skip(&mut self, n: usize) {
        let n = n.min(self.buf.len().saturating_sub(self.pos));
        self.pos += n;
    }

    pub fn u8(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(self.eof());
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    pub fn u24(&mut self) -> Result<u32> {
        let b = self.take::<3>()?;
        Ok(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take::<4>()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(self.eof());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.pos + N > self.buf.len() {
            return Err(self.eof());
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn eof(&self) -> CoreError {
        CoreError::Eof {
            offset: self.base + self.buf.len() as u64,
            needed: 0,
        }
    }
}

/// Growing byte writer with u32-size-patch support for ISO-BMFF box assembly.
#[derive(Debug, Default)]
pub struct ByteWriter {
    pub buf: Vec<u8>,
    pub sizes: Vec<(usize, Vec<usize>)>, // size-field offset -> box header starts
}

impl ByteWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u24(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes()[1..4]);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.buf.extend_from_slice(&vec![0u8; n]);
        self
    }

    /// Start a box: writes a placeholder 32-bit size + 4cc, remembers the offset.
    pub fn start_box(&mut self, fourcc: &[u8; 4]) {
        self.sizes.push((self.buf.len(), vec![]));
        self.buf.extend_from_slice(&0u32.to_be_bytes());
        self.buf.extend_from_slice(fourcc);
    }

    /// Close all boxes opened since `header_start` was returned by `start_box_marker`.
    /// Actually simpler API: `open_box` returns marker; `close_box(marker)` patches
    /// the size of that specific box (nested close order = reverse open order).
    pub fn open_box(&mut self, fourcc: &[u8; 4]) -> usize {
        let marker = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_be_bytes());
        self.buf.extend_from_slice(fourcc);
        marker
    }

    pub fn close_box(&mut self, marker: usize) -> Result<()> {
        let size = (self.buf.len() - marker) as u32;
        if size > u32::MAX - 8 {
            return Err(CoreError::Parse(format!(
                "box at {marker} exceeds u32 size"
            )));
        }
        self.buf[marker..marker + 4].copy_from_slice(&size.to_be_bytes());
        Ok(())
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_absolute_offsets() {
        let buf = [1u8, 2, 3, 4];
        let mut r = ByteReader::with_base(&buf, 1000);
        assert_eq!(r.u32().unwrap(), 0x01020304);
        assert_eq!(r.pos(), 1004);
        assert!(r.seek(999).is_err());
        r.seek(1002).unwrap();
        assert_eq!(r.u16().unwrap(), 0x0304);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn writer_nested_boxes() {
        let mut w = ByteWriter::new();
        let moov = w.open_box(b"moov");
        let trak = w.open_box(b"trak");
        w.u32(0xdeadbeef);
        w.close_box(trak).unwrap();
        w.close_box(moov).unwrap();
        let v = w.into_vec();
        assert_eq!(&v[4..8], b"moov");
        assert_eq!(
            u32::from_be_bytes(v[0..4].try_into().unwrap()),
            v.len() as u32
        );
        assert_eq!(u32::from_be_bytes(v[8..12].try_into().unwrap()), 12);
    }

    #[test]
    fn reader_u24() {
        let buf = [0u8, 1, 2, 3];
        let mut r = ByteReader::new(&buf);
        r.u8().unwrap();
        assert_eq!(r.u24().unwrap(), 0x010203);
    }
}
