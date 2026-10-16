// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core, the author's stream-worker project — commit 39p.)

//! Sample-table expansion: `stts`/`stsz`(`stz2`)/`stco`(`co64`)/`stsc`/
//! `ctts`/`stss` → one compact [`Sample`] per sample, in a single streaming
//! pass over the raw table bytes.
//!
//! # Why streaming
//!
//! Memory is the design constraint. A feature-length title has 0.5–2M
//! samples per served track and the worker parses inside a 128MB isolate
//! that also holds the moov itself (12MB for a 2.5h film). Expanding every
//! table into its own per-sample vector first (durations, composition
//! offsets, chunk map, keyframe flags, sizes …) costs ~60 bytes per sample;
//! this module walks the run-length tables as cursors and reads the
//! random-access ones straight from their bytes, so the only per-sample
//! allocation is the 24-byte `Sample` output.
//!
//! # Hostile input
//!
//! Every entry count is bounded by the bytes actually present in its box,
//! so an `stts` claiming four billion entries fails cleanly instead of
//! allocating gigabytes, and the total sample count is capped by
//! [`MAX_SAMPLES`].

use crate::error::{CoreError, Result};

/// Upper bound on samples per track we are willing to expand: ~7.7 days of
/// 24fps video or ~4 days of 48kHz AAC — far beyond any VOD asset, tiny
/// compared to what a corrupt count could request.
pub const MAX_SAMPLES: usize = 16_000_000;

/// One sample of a regular (non-fragmented) track. 24 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// absolute file offset
    pub offset: u64,
    pub size: u32,
    /// decode duration (track timescale)
    pub duration: u32,
    /// composition offset (cts − dts) as stored in `ctts`; unsigned v0
    /// values beyond `i32::MAX` are rejected at parse time
    pub cts_delta: i32,
    pub keyframe: bool,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn be64(b: &[u8], at: usize) -> u64 {
    ((be32(b, at) as u64) << 32) | be32(b, at + 4) as u64
}

/// Split a full-box payload into `(entry_count, entries)`, refusing counts
/// that do not fit the bytes present.
fn entries<'a>(
    content: &'a [u8],
    header_len: usize,
    entry_size: usize,
    what: &str,
) -> Result<(usize, &'a [u8])> {
    if content.len() < header_len {
        return Err(CoreError::Parse(format!("{what}: truncated header")));
    }
    let count = be32(content, header_len - 4) as usize;
    let rest = &content[header_len..];
    if count.saturating_mul(entry_size) > rest.len() {
        return Err(CoreError::Parse(format!(
            "{what}: entry count {count} exceeds box payload ({} bytes)",
            rest.len()
        )));
    }
    Ok((count, rest))
}

/// Sample sizes read in place: fixed, `stsz` entries, or `stz2` packed
/// fields.
#[derive(Debug, Clone, Copy)]
pub enum SizeTable<'a> {
    Fixed {
        size: u32,
        count: usize,
    },
    Stsz {
        entries: &'a [u8],
        count: usize,
    },
    Stz2 {
        entries: &'a [u8],
        bits: u8,
        count: usize,
    },
}

impl<'a> SizeTable<'a> {
    /// `stsz` payload: version/flags, sample_size, sample_count, [sizes].
    pub fn from_stsz(content: &'a [u8]) -> Result<Self> {
        if content.len() < 12 {
            return Err(CoreError::Parse("stsz: truncated header".into()));
        }
        let fixed = be32(content, 4);
        let count = be32(content, 8) as usize;
        if count > MAX_SAMPLES {
            return Err(CoreError::Parse(format!(
                "stsz: {count} samples exceeds cap"
            )));
        }
        if fixed != 0 {
            return Ok(SizeTable::Fixed { size: fixed, count });
        }
        let (count, entries) = entries(content, 12, 4, "stsz")?;
        Ok(SizeTable::Stsz { entries, count })
    }

    /// `stz2` payload: version/flags, reserved(3), field_size, count, packed.
    pub fn from_stz2(content: &'a [u8]) -> Result<Self> {
        if content.len() < 12 {
            return Err(CoreError::Parse("stz2: truncated header".into()));
        }
        let bits = content[7];
        let count = be32(content, 8) as usize;
        if count > MAX_SAMPLES {
            return Err(CoreError::Parse(format!(
                "stz2: {count} samples exceeds cap"
            )));
        }
        let needed = match bits {
            4 => count.div_ceil(2),
            8 => count,
            16 => count * 2,
            _ => return Err(CoreError::Parse(format!("stz2: bad field size {bits}"))),
        };
        let entries = &content[12..];
        if needed > entries.len() {
            return Err(CoreError::Parse(
                "stz2: entry count exceeds box payload".into(),
            ));
        }
        Ok(SizeTable::Stz2 {
            entries,
            bits,
            count,
        })
    }

    pub fn len(&self) -> usize {
        match self {
            SizeTable::Fixed { count, .. }
            | SizeTable::Stsz { count, .. }
            | SizeTable::Stz2 { count, .. } => *count,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Size of sample `i` (`i < len()`).
    pub fn get(&self, i: usize) -> u32 {
        match *self {
            SizeTable::Fixed { size, .. } => size,
            SizeTable::Stsz { entries, .. } => be32(entries, i * 4),
            SizeTable::Stz2 { entries, bits, .. } => match bits {
                4 => {
                    let b = entries[i / 2];
                    if i.is_multiple_of(2) {
                        (b >> 4) as u32
                    } else {
                        (b & 0x0F) as u32
                    }
                }
                8 => entries[i] as u32,
                _ => u16::from_be_bytes([entries[i * 2], entries[i * 2 + 1]]) as u32,
            },
        }
    }
}

/// Raw payloads (box header stripped) of one `stbl`'s tables.
#[derive(Debug, Clone, Copy)]
pub struct SampleTables<'a> {
    pub stts: &'a [u8],
    pub sizes: SizeTable<'a>,
    /// `stco` or `co64` payload (see `co64`)
    pub chunk_offsets: &'a [u8],
    pub co64: bool,
    pub stsc: &'a [u8],
    pub ctts: Option<&'a [u8]>,
    pub stss: Option<&'a [u8]>,
}

/// Cursor over a `(count, value)` run-length table (`stts`, `ctts`): yields
/// one value per sample without materialising the expansion.
struct Runs<'a> {
    entries: &'a [u8],
    n_runs: usize,
    next_run: usize,
    left: u32,
    cur: i64,
    signed: bool,
}

impl<'a> Runs<'a> {
    fn new(entries: &'a [u8], n_runs: usize, signed: bool) -> Self {
        Self {
            entries,
            n_runs,
            next_run: 0,
            left: 0,
            cur: 0,
            signed,
        }
    }

    fn next(&mut self) -> Option<i64> {
        while self.left == 0 {
            if self.next_run >= self.n_runs {
                return None;
            }
            let at = self.next_run * 8;
            self.next_run += 1;
            let count = be32(self.entries, at);
            self.cur = if self.signed {
                be32(self.entries, at + 4) as i32 as i64
            } else {
                be32(self.entries, at + 4) as i64
            };
            self.left = count; // zero-count runs are skipped by the loop
        }
        self.left -= 1;
        Some(self.cur)
    }
}

/// Expand the tables into absolute-offset, sized, timed samples.
pub fn expand_sample_tables(t: &SampleTables) -> Result<Vec<Sample>> {
    let n = t.sizes.len();
    if n == 0 {
        return Err(CoreError::Parse("empty sample table".into()));
    }
    if n > MAX_SAMPLES {
        return Err(CoreError::Parse(format!("{n} samples exceeds cap")));
    }

    let (stts_runs, stts_entries) = entries(t.stts, 8, 8, "stts")?;
    let mut durations = Runs::new(stts_entries, stts_runs, false);

    let mut cts = match t.ctts {
        Some(c) => {
            let (runs, e) = entries(c, 8, 8, "ctts")?;
            Some(Runs::new(e, runs, c[0] != 0))
        }
        None => None,
    };

    // stss is a sorted list of 1-based sync sample numbers; sort defensively
    // (a few thousand entries at most — keyframes only).
    let stss: Option<Vec<u32>> = match t.stss {
        Some(s) => {
            let (count, e) = entries(s, 8, 4, "stss")?;
            let mut v: Vec<u32> = (0..count).map(|i| be32(e, i * 4)).collect();
            v.sort_unstable();
            Some(v)
        }
        None => None,
    };
    let mut stss_pos = 0usize;

    let (chunk_count, chunk_entries) =
        entries(t.chunk_offsets, 8, if t.co64 { 8 } else { 4 }, "stco/co64")?;
    let chunk_offset = |c: usize| -> u64 {
        if t.co64 {
            be64(chunk_entries, c * 8)
        } else {
            be32(chunk_entries, c * 4) as u64
        }
    };

    // stsc runs: (first_chunk 0-based, samples_per_chunk). Small (one entry
    // per change of chunking pattern), so a Vec is fine.
    let (stsc_n, stsc_e) = entries(t.stsc, 8, 12, "stsc")?;
    let stsc: Vec<(usize, u32)> = (0..stsc_n)
        .map(|i| {
            (
                (be32(stsc_e, i * 12) as usize).saturating_sub(1),
                be32(stsc_e, i * 12 + 4),
            )
        })
        .collect();
    let run_end = |w: usize| -> usize { stsc.get(w + 1).map(|r| r.0).unwrap_or(chunk_count) };
    // first run with a non-zero samples-per-chunk (a zero run contributes
    // nothing; skipping it is what ffmpeg does)
    let mut w = match stsc.iter().position(|r| r.1 > 0) {
        Some(w) => w,
        None => {
            return Err(CoreError::Parse(format!(
                "stsc maps 0 samples but stsz has {n}"
            )))
        }
    };
    let mut chunk = stsc[w].0;
    let mut spc = stsc[w].1;
    let mut in_chunk: u32 = 0;
    let mut pos: u64 = 0;

    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        // ── chunk bookkeeping ───────────────────────────────────────────
        if in_chunk == spc {
            chunk += 1;
            in_chunk = 0;
        }
        while chunk >= run_end(w) {
            // advance to the next run with samples
            loop {
                w += 1;
                if w >= stsc.len() {
                    return Err(CoreError::Parse(format!(
                        "stsc maps {i} samples but stsz has {n}"
                    )));
                }
                if stsc[w].1 > 0 {
                    break;
                }
            }
            chunk = chunk.max(stsc[w].0);
            spc = stsc[w].1;
            in_chunk = 0;
        }
        if chunk >= chunk_count {
            return Err(CoreError::Parse(format!(
                "sample {i} references chunk {chunk} beyond stco ({chunk_count})"
            )));
        }
        if in_chunk == 0 {
            pos = chunk_offset(chunk);
        }
        in_chunk += 1;

        // ── timing ─────────────────────────────────────────────────────
        let duration = durations
            .next()
            .ok_or_else(|| CoreError::Parse(format!("stts covers {i} samples, stsz has {n}")))?
            as u32;
        let cts_delta = match cts.as_mut().and_then(|c| c.next()) {
            Some(v) => i32::try_from(v).map_err(|_| {
                CoreError::Parse(format!("ctts offset {v} out of range at sample {i}"))
            })?,
            None => 0,
        };

        // ── sync flag ──────────────────────────────────────────────────
        let keyframe = match &stss {
            None => true,
            Some(list) => {
                let num = (i + 1) as u32;
                while stss_pos < list.len() && list[stss_pos] < num {
                    stss_pos += 1;
                }
                stss_pos < list.len() && list[stss_pos] == num
            }
        };

        let size = t.sizes.get(i);
        samples.push(Sample {
            offset: pos,
            size,
            duration,
            cts_delta,
            keyframe,
        });
        pos += size as u64;
    }
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::ByteWriter;

    fn full_box(entries: &[u32]) -> Vec<u8> {
        // version/flags + count + entries (u32 each)
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(entries.len() as u32);
        for e in entries {
            b.u32(*e);
        }
        b.as_slice().to_vec()
    }

    fn stts(runs: &[(u32, u32)]) -> Vec<u8> {
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(runs.len() as u32);
        for (c, d) in runs {
            b.u32(*c);
            b.u32(*d);
        }
        b.as_slice().to_vec()
    }

    fn stsc(runs: &[(u32, u32)]) -> Vec<u8> {
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(runs.len() as u32);
        for (first, spc) in runs {
            b.u32(*first);
            b.u32(*spc);
            b.u32(1);
        }
        b.as_slice().to_vec()
    }

    fn stsz(sizes: &[u32]) -> Vec<u8> {
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(0);
        b.u32(sizes.len() as u32);
        for s in sizes {
            b.u32(*s);
        }
        b.as_slice().to_vec()
    }

    fn expand(
        stts_b: &[u8],
        stsz_b: &[u8],
        stco_b: &[u8],
        stsc_b: &[u8],
        ctts_b: Option<&[u8]>,
        stss_b: Option<&[u8]>,
    ) -> Result<Vec<Sample>> {
        expand_sample_tables(&SampleTables {
            stts: stts_b,
            sizes: SizeTable::from_stsz(stsz_b)?,
            chunk_offsets: stco_b,
            co64: false,
            stsc: stsc_b,
            ctts: ctts_b,
            stss: stss_b,
        })
    }

    #[test]
    fn stsz_fixed() {
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(100); // fixed size
        b.u32(3);
        let t = SizeTable::from_stsz(b.as_slice()).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!((0..3).map(|i| t.get(i)).collect::<Vec<_>>(), vec![100; 3]);
    }

    #[test]
    fn hostile_counts_are_rejected_not_allocated() {
        // stts claiming 4 billion entries in a 16-byte box
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(u32::MAX);
        b.u32(1);
        b.u32(1);
        let bad_stts = b.as_slice().to_vec();
        let r = expand(
            &bad_stts,
            &stsz(&[1, 2, 3]),
            &full_box(&[0]),
            &stsc(&[(1, 3)]),
            None,
            None,
        );
        assert!(r.is_err());
        // stsz with a fixed size and an absurd count
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u32(7);
        b.u32(u32::MAX);
        assert!(SizeTable::from_stsz(b.as_slice()).is_err());
        // a single stts run claiming more samples than stsz: expansion stops
        // at n instead of materialising billions of durations
        let s = expand(
            &stts(&[(u32::MAX, 10)]),
            &stsz(&[1, 2, 3]),
            &full_box(&[0]),
            &stsc(&[(1, 3)]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s[2].offset, 3);
        assert!(s.iter().all(|s| s.duration == 10 && s.keyframe));
    }

    #[test]
    fn stts_short_is_an_error() {
        let r = expand(
            &stts(&[(2, 10)]),
            &stsz(&[1, 2, 3]),
            &full_box(&[0]),
            &stsc(&[(1, 3)]),
            None,
            None,
        );
        assert!(r.unwrap_err().to_string().contains("stts covers 2 samples"));
    }

    #[test]
    fn stsc_zero_spc_and_short_map() {
        // zero samples-per-chunk run is skipped, not a divide-by-zero:
        // chunk 1 has 0 samples, chunks 2.. have 2 → samples land in chunks 1,1,2,2 (0-based)
        let s = expand(
            &stts(&[(4, 1)]),
            &stsz(&[1, 1, 1, 1]),
            &full_box(&[100, 200, 300]),
            &stsc(&[(1, 0), (2, 2)]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            s.iter().map(|s| s.offset).collect::<Vec<_>>(),
            vec![200, 201, 300, 301]
        );
        // a map that covers fewer samples than stsz is corrupt
        let r = expand(
            &stts(&[(3, 1)]),
            &stsz(&[1, 1, 1]),
            &full_box(&[0]),
            &stsc(&[(1, 1)]),
            None,
            None,
        );
        assert!(r.unwrap_err().to_string().contains("stsc maps 1 samples"));
    }

    #[test]
    fn interleaved_chunks_ctts_and_stss() {
        // 2 chunks of 2 samples at 1000 and 5000; sizes vary; B-frame style
        // ctts v1 (signed); keyframes 1 and 3
        let mut ctts = ByteWriter::new();
        ctts.u8(1);
        ctts.u24(0);
        ctts.u32(3);
        ctts.u32(1);
        ctts.u32(0);
        ctts.u32(2);
        ctts.u32((-30i32) as u32);
        ctts.u32(1);
        ctts.u32(30);
        let s = expand(
            &stts(&[(1, 10), (3, 12)]),
            &stsz(&[5, 6, 7, 8]),
            &full_box(&[1000, 5000]),
            &stsc(&[(1, 2)]),
            Some(ctts.as_slice()),
            Some(&full_box(&[3, 1])), // unsorted on purpose
        )
        .unwrap();
        assert_eq!(
            s.iter().map(|s| s.offset).collect::<Vec<_>>(),
            vec![1000, 1005, 5000, 5007]
        );
        assert_eq!(
            s.iter().map(|s| s.duration).collect::<Vec<_>>(),
            vec![10, 12, 12, 12]
        );
        assert_eq!(
            s.iter().map(|s| s.cts_delta).collect::<Vec<_>>(),
            vec![0, -30, -30, 30]
        );
        assert_eq!(
            s.iter().map(|s| s.keyframe).collect::<Vec<_>>(),
            vec![true, false, true, false]
        );
        assert_eq!(std::mem::size_of::<Sample>(), 24);
    }

    #[test]
    fn ctts_v0_out_of_i32_range_is_rejected() {
        let mut ctts = ByteWriter::new();
        ctts.u32(0);
        ctts.u32(1);
        ctts.u32(1);
        ctts.u32(0x9000_0000);
        let r = expand(
            &stts(&[(1, 1)]),
            &stsz(&[1]),
            &full_box(&[0]),
            &stsc(&[(1, 1)]),
            Some(ctts.as_slice()),
            None,
        );
        assert!(r.unwrap_err().to_string().contains("out of range"));
    }

    #[test]
    fn stz2_nibbles() {
        let mut b = ByteWriter::new();
        b.u32(0);
        b.u24(0);
        b.u8(4);
        b.u32(3);
        b.u8(0x12);
        b.u8(0x30);
        let t = SizeTable::from_stz2(b.as_slice()).unwrap();
        assert_eq!((0..3).map(|i| t.get(i)).collect::<Vec<_>>(), vec![1, 2, 3]);
    }
}
