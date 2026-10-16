// Copyright 2026- Seongwoo Hong. All rights reserved.

//! NAL units of H.264 and HEVC — as far as protecting them needs, and no
//! further (commit 40a, docs/DRM.md).
//!
//! `cbcs` encryption (ISO/IEC 23001-7) leaves each video slice's HEADER in
//! the clear and encrypts what follows: a hardware decoder inside the DRM
//! path must read the header to set itself up before it ever sees the
//! decrypted slice data. So the packager has to know, for every slice, how
//! many bytes its header takes — and a slice header has no length field.
//! The only way to find its end is to parse it, syntax element by syntax
//! element, with the parameter sets (SPS, PPS) it refers to. That is this
//! module: the bit reader, the parameter sets, and the two slice headers.
//!
//! What it does NOT do is decode anything. Every field is read only to step
//! over it; the values kept are the handful that change what comes next.
//!
//! # The two traps
//!
//! - **Emulation prevention.** Inside a NAL unit the byte sequence
//!   `00 00 03` means `00 00` — the `03` was inserted so the payload never
//!   looks like a start code. Syntax is defined on the bytes WITHOUT those
//!   `03`s (the RBSP), but the clear length must be counted in the bytes as
//!   stored. [`BitReader`] removes them as it reads and counts the raw bytes
//!   it passed, so [`BitReader::consumed`] is a stored-bytes length.
//! - **A header that ends mid-byte.** The last header bit may share its byte
//!   with the first bit of slice data (CAVLC H.264). That byte must stay
//!   clear, so the clear length is rounded UP. (CABAC H.264 pads the header
//!   to a byte with `cabac_alignment_one_bit`s, and HEVC ends every slice
//!   header with `byte_alignment()`, so there it is exact.)
//!
//! # What is refused
//!
//! A stream this module cannot parse with certainty is refused, never
//! guessed at: a wrong guess would either encrypt a header (the video does
//! not play) or leave slice data clear (the copy is not protected). Refused:
//! H.264 data partitioning (Extended profile), SVC/MVC and 3D extensions,
//! HEVC layers above 0 (MV-HEVC — iPhone "spatial" video), and HEVC's
//! multilayer, 3D and screen-content PPS extensions. Camera, phone and
//! editor output uses none of them.

use std::collections::BTreeMap;

use crate::error::{CoreError, Result};

fn bad(msg: impl Into<String>) -> CoreError {
	CoreError::Parse(msg.into())
}

/// A stream this module understands and will not protect (see the module
/// note) — said to the person as it is.
fn refused(msg: impl Into<String>) -> CoreError {
	CoreError::Refused(msg.into())
}

const MULTILAYER: &str = "this HEVC video has more than one layer (MV-HEVC, such as iPhone spatial video) — it cannot be protected yet";

/// Reads bits MSB-first from a NAL unit's payload, dropping emulation
/// prevention bytes, and remembers how many STORED bytes it has passed.
pub struct BitReader<'a> {
	data: &'a [u8],
	/// Next stored byte to load.
	pos: usize,
	/// Zero bytes seen in a row, in the RBSP (an `03` after two is dropped).
	zeros: u8,
	cur: u8,
	/// Bits of `cur` not yet read.
	left: u8,
}

impl<'a> BitReader<'a> {
	pub fn new(data: &'a [u8]) -> Self {
		BitReader { data, pos: 0, zeros: 0, cur: 0, left: 0 }
	}

	fn load(&mut self) -> Result<()> {
		loop {
			let Some(&b) = self.data.get(self.pos) else {
				return Err(bad("NAL unit ends inside its header"));
			};
			self.pos += 1;
			if self.zeros >= 2 && b == 0x03 {
				// an emulation prevention byte: not part of the RBSP
				self.zeros = 0;
				continue;
			}
			self.zeros = if b == 0 { self.zeros.saturating_add(1) } else { 0 };
			self.cur = b;
			self.left = 8;
			return Ok(());
		}
	}

	pub fn bit(&mut self) -> Result<u32> {
		if self.left == 0 {
			self.load()?;
		}
		self.left -= 1;
		Ok(u32::from((self.cur >> self.left) & 1))
	}

	pub fn flag(&mut self) -> Result<bool> {
		Ok(self.bit()? == 1)
	}

	/// `n` ≤ 32 bits as an unsigned number.
	pub fn bits(&mut self, n: u32) -> Result<u32> {
		debug_assert!(n <= 32);
		let mut v: u64 = 0;
		for _ in 0..n {
			v = (v << 1) | u64::from(self.bit()?);
		}
		Ok(v as u32)
	}

	pub fn skip(&mut self, n: u32) -> Result<()> {
		for _ in 0..n {
			self.bit()?;
		}
		Ok(())
	}

	/// Exp-Golomb `ue(v)`. More than 31 leading zeros is not a valid code in
	/// any field either standard defines.
	pub fn ue(&mut self) -> Result<u32> {
		let mut zeros = 0u32;
		while self.bit()? == 0 {
			zeros += 1;
			if zeros > 31 {
				return Err(bad("Exp-Golomb code longer than 32 bits"));
			}
		}
		Ok(((1u64 << zeros) - 1 + u64::from(self.bits(zeros)?)) as u32)
	}

	/// Signed Exp-Golomb `se(v)`: 1, −1, 2, −2, … for 1, 2, 3, 4, …
	pub fn se(&mut self) -> Result<i32> {
		let k = i64::from(self.ue()?);
		Ok(if k % 2 == 1 { ((k + 1) / 2) as i32 } else { (-(k / 2)) as i32 })
	}

	pub fn byte_aligned(&self) -> bool {
		self.left == 0
	}

	/// Stored bytes passed so far, a partly read byte included — the clear
	/// length of everything read.
	pub fn consumed(&self) -> usize {
		self.pos
	}
}

/// `Ceil(Log2(n))`: the bits a value below `n` needs (0 for n ≤ 1).
fn ceil_log2(n: u64) -> u32 {
	let mut k = 0;
	while (1u64 << k) < n {
		k += 1;
	}
	k
}

/// A guard for the loops a stream controls (list modifications, memory
/// management operations): far above any real count, far below a hang.
const LOOP_CAP: usize = 1024;

// ── H.264 (ITU-T H.264, 7.3) ───────────────────────────────────────────

/// The SPS fields a slice header's layout depends on.
#[derive(Debug, Clone)]
pub struct AvcSps {
	chroma_array_type: u32,
	separate_colour_plane: bool,
	log2_max_frame_num: u32,
	poc_type: u32,
	log2_max_poc_lsb: u32,
	delta_pic_order_always_zero: bool,
	frame_mbs_only: bool,
	pic_size_in_map_units: u64,
}

/// The PPS fields a slice header's layout depends on.
#[derive(Debug, Clone)]
pub struct AvcPps {
	sps_id: u32,
	entropy_coding_mode: bool,
	bottom_field_pic_order_in_frame_present: bool,
	num_slice_groups_minus1: u32,
	slice_group_map_type: u32,
	slice_group_change_rate: u64,
	num_ref_idx_l0_default_minus1: u32,
	num_ref_idx_l1_default_minus1: u32,
	weighted_pred: bool,
	weighted_bipred_idc: u32,
	deblocking_filter_control_present: bool,
	redundant_pic_cnt_present: bool,
}

/// The profiles whose SPS carries chroma format, bit depths and scaling
/// matrices (7.3.2.1.1).
fn avc_high_profile(profile_idc: u32) -> bool {
	matches!(profile_idc, 100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135)
}

fn avc_scaling_list(r: &mut BitReader, size: usize) -> Result<()> {
	let (mut last, mut next) = (8i32, 8i32);
	for _ in 0..size {
		if next != 0 {
			let delta = r.se()?;
			next = (last + delta + 256).rem_euclid(256);
		}
		if next != 0 {
			last = next;
		}
	}
	Ok(())
}

/// Every SPS and PPS seen so far, by id: from `avcC`, then any carried in
/// the samples (`avc3`, or a stream that repeats them at keyframes).
#[derive(Debug, Clone, Default)]
pub struct AvcParams {
	sps: BTreeMap<u32, AvcSps>,
	pps: BTreeMap<u32, AvcPps>,
}

impl AvcParams {
	/// Take an SPS (type 7) or PPS (type 8) NAL unit, header byte included.
	/// Anything else is ignored.
	pub fn add(&mut self, nal: &[u8]) -> Result<()> {
		match nal.first().map(|b| b & 0x1f) {
			Some(7) => self.add_sps(&nal[1..]),
			Some(8) => self.add_pps(&nal[1..]),
			_ => Ok(()),
		}
	}

	fn add_sps(&mut self, rbsp: &[u8]) -> Result<()> {
		let mut r = BitReader::new(rbsp);
		let profile_idc = r.bits(8)?;
		r.skip(16)?; // constraint flags, level_idc
		let id = r.ue()?;
		if id > 31 {
			return Err(bad(format!("H.264 SPS id {id}")));
		}
		let (mut chroma_format_idc, mut separate_colour_plane) = (1, false);
		if avc_high_profile(profile_idc) {
			chroma_format_idc = r.ue()?;
			if chroma_format_idc == 3 {
				separate_colour_plane = r.flag()?;
			}
			r.ue()?; // bit_depth_luma_minus8
			r.ue()?; // bit_depth_chroma_minus8
			r.skip(1)?; // qpprime_y_zero_transform_bypass_flag
			if r.flag()? {
				// seq_scaling_matrix_present_flag
				for i in 0..if chroma_format_idc != 3 { 8 } else { 12 } {
					if r.flag()? {
						avc_scaling_list(&mut r, if i < 6 { 16 } else { 64 })?;
					}
				}
			}
		}
		let log2_max_frame_num = r.ue()? + 4;
		let poc_type = r.ue()?;
		let (mut log2_max_poc_lsb, mut delta_pic_order_always_zero) = (0, false);
		match poc_type {
			0 => log2_max_poc_lsb = r.ue()? + 4,
			1 => {
				delta_pic_order_always_zero = r.flag()?;
				r.se()?; // offset_for_non_ref_pic
				r.se()?; // offset_for_top_to_bottom_field
				let n = r.ue()? as usize;
				if n > 255 {
					return Err(bad("H.264 SPS: too many POC cycle offsets"));
				}
				for _ in 0..n {
					r.se()?;
				}
			}
			2 => {}
			t => return Err(bad(format!("H.264 SPS: pic_order_cnt_type {t}"))),
		}
		r.ue()?; // max_num_ref_frames
		r.skip(1)?; // gaps_in_frame_num_value_allowed_flag
		let width_mbs = u64::from(r.ue()?) + 1;
		let height_map_units = u64::from(r.ue()?) + 1;
		let frame_mbs_only = r.flag()?;
		if log2_max_frame_num > 16 || (poc_type == 0 && log2_max_poc_lsb > 16) {
			return Err(bad("H.264 SPS: frame_num or POC wider than 16 bits"));
		}
		self.sps.insert(
			id,
			AvcSps {
				chroma_array_type: if separate_colour_plane { 0 } else { chroma_format_idc },
				separate_colour_plane,
				log2_max_frame_num,
				poc_type,
				log2_max_poc_lsb,
				delta_pic_order_always_zero,
				frame_mbs_only,
				pic_size_in_map_units: width_mbs * height_map_units,
			},
		);
		Ok(())
	}

	fn add_pps(&mut self, rbsp: &[u8]) -> Result<()> {
		let mut r = BitReader::new(rbsp);
		let id = r.ue()?;
		let sps_id = r.ue()?;
		if id > 255 || sps_id > 31 {
			return Err(bad(format!("H.264 PPS id {id} / SPS id {sps_id}")));
		}
		let entropy_coding_mode = r.flag()?;
		let bottom_field_pic_order_in_frame_present = r.flag()?;
		let num_slice_groups_minus1 = r.ue()?;
		let (mut slice_group_map_type, mut slice_group_change_rate) = (0, 1);
		if num_slice_groups_minus1 > 7 {
			return Err(bad("H.264 PPS: more than 8 slice groups"));
		}
		if num_slice_groups_minus1 > 0 {
			slice_group_map_type = r.ue()?;
			match slice_group_map_type {
				0 => {
					for _ in 0..=num_slice_groups_minus1 {
						r.ue()?; // run_length_minus1
					}
				}
				2 => {
					for _ in 0..num_slice_groups_minus1 {
						r.ue()?; // top_left
						r.ue()?; // bottom_right
					}
				}
				3..=5 => {
					r.skip(1)?; // slice_group_change_direction_flag
					slice_group_change_rate = u64::from(r.ue()?) + 1;
				}
				6 => {
					let units = r.ue()? as usize + 1;
					if units > 1 << 20 {
						return Err(bad("H.264 PPS: slice group map too large"));
					}
					let bits = ceil_log2(u64::from(num_slice_groups_minus1) + 1);
					for _ in 0..units {
						r.skip(bits)?;
					}
				}
				1 => {}
				t => return Err(bad(format!("H.264 PPS: slice_group_map_type {t}"))),
			}
		}
		let num_ref_idx_l0_default_minus1 = r.ue()?;
		let num_ref_idx_l1_default_minus1 = r.ue()?;
		let weighted_pred = r.flag()?;
		let weighted_bipred_idc = r.bits(2)?;
		r.se()?; // pic_init_qp_minus26
		r.se()?; // pic_init_qs_minus26
		r.se()?; // chroma_qp_index_offset
		let deblocking_filter_control_present = r.flag()?;
		r.skip(1)?; // constrained_intra_pred_flag
		let redundant_pic_cnt_present = r.flag()?;
		if num_ref_idx_l0_default_minus1 > 31 || num_ref_idx_l1_default_minus1 > 31 {
			return Err(bad("H.264 PPS: more than 32 reference indexes"));
		}
		self.pps.insert(
			id,
			AvcPps {
				sps_id,
				entropy_coding_mode,
				bottom_field_pic_order_in_frame_present,
				num_slice_groups_minus1,
				slice_group_map_type,
				slice_group_change_rate,
				num_ref_idx_l0_default_minus1,
				num_ref_idx_l1_default_minus1,
				weighted_pred,
				weighted_bipred_idc,
				deblocking_filter_control_present,
				redundant_pic_cnt_present,
			},
		);
		Ok(())
	}

	/// How many stored bytes of this slice NAL unit (header byte included)
	/// are its header — the part `cbcs` leaves clear (7.3.3).
	pub fn slice_header_len(&self, nal: &[u8]) -> Result<usize> {
		let first = *nal.first().ok_or_else(|| bad("empty NAL unit"))?;
		let nal_ref_idc = (first >> 5) & 3;
		let nal_type = first & 0x1f;
		let idr = nal_type == 5;
		let mut r = BitReader::new(&nal[1..]);
		r.ue()?; // first_mb_in_slice
		let slice_type = r.ue()? % 5; // 0 P, 1 B, 2 I, 3 SP, 4 SI
		let pps_id = r.ue()?;
		let pps = self.pps.get(&pps_id).ok_or_else(|| bad(format!("H.264 slice refers to PPS {pps_id}, which was never sent")))?;
		let sps = self.sps.get(&pps.sps_id).ok_or_else(|| bad(format!("H.264 PPS refers to SPS {}, which was never sent", pps.sps_id)))?;
		let (p, b, sp, si) = (slice_type == 0, slice_type == 1, slice_type == 3, slice_type == 4);
		if sps.separate_colour_plane {
			r.skip(2)?; // colour_plane_id
		}
		r.skip(sps.log2_max_frame_num)?; // frame_num
		let mut field_pic = false;
		if !sps.frame_mbs_only {
			field_pic = r.flag()?;
			if field_pic {
				r.skip(1)?; // bottom_field_flag
			}
		}
		if idr {
			r.ue()?; // idr_pic_id
		}
		if sps.poc_type == 0 {
			r.skip(sps.log2_max_poc_lsb)?;
			if pps.bottom_field_pic_order_in_frame_present && !field_pic {
				r.se()?; // delta_pic_order_cnt_bottom
			}
		}
		if sps.poc_type == 1 && !sps.delta_pic_order_always_zero {
			r.se()?;
			if pps.bottom_field_pic_order_in_frame_present && !field_pic {
				r.se()?;
			}
		}
		if pps.redundant_pic_cnt_present {
			r.ue()?;
		}
		if b {
			r.skip(1)?; // direct_spatial_mv_pred_flag
		}
		let (mut l0, mut l1) = (pps.num_ref_idx_l0_default_minus1, pps.num_ref_idx_l1_default_minus1);
		// num_ref_idx_active_override_flag
		if (p || sp || b) && r.flag()? {
			l0 = r.ue()?;
			if b {
				l1 = r.ue()?;
			}
		}
		if l0 > 31 || l1 > 31 {
			return Err(bad("H.264 slice: more than 32 reference indexes"));
		}
		// ref_pic_list_modification() — types 20/21 (MVC) never reach here
		let list_mod = |r: &mut BitReader| -> Result<()> {
			if r.flag()? {
				for _ in 0..LOOP_CAP {
					match r.ue()? {
						0..=2 => {
							r.ue()?; // abs_diff_pic_num_minus1 / long_term_pic_num
						}
						3 => return Ok(()),
						v => return Err(bad(format!("H.264 slice: modification_of_pic_nums_idc {v}"))),
					}
				}
				return Err(bad("H.264 slice: endless ref list modification"));
			}
			Ok(())
		};
		if !(slice_type == 2 || si) {
			list_mod(&mut r)?;
		}
		if b {
			list_mod(&mut r)?;
		}
		if (pps.weighted_pred && (p || sp)) || (pps.weighted_bipred_idc == 1 && b) {
			// pred_weight_table()
			r.ue()?; // luma_log2_weight_denom
			if sps.chroma_array_type != 0 {
				r.ue()?; // chroma_log2_weight_denom
			}
			let lists = if b { 2 } else { 1 };
			for list in 0..lists {
				for _ in 0..=if list == 0 { l0 } else { l1 } {
					if r.flag()? {
						r.se()?;
						r.se()?;
					}
					if sps.chroma_array_type != 0 && r.flag()? {
						for _ in 0..2 {
							r.se()?;
							r.se()?;
						}
					}
				}
			}
		}
		if nal_ref_idc != 0 {
			// dec_ref_pic_marking()
			if idr {
				r.skip(2)?; // no_output_of_prior_pics_flag, long_term_reference_flag
			} else if r.flag()? {
				// adaptive_ref_pic_marking_mode_flag
				let mut done = false;
				for _ in 0..LOOP_CAP {
					let op = r.ue()?;
					match op {
						0 => {
							done = true;
							break;
						}
						1 | 3 => {
							r.ue()?; // difference_of_pic_nums_minus1
							if op == 3 {
								r.ue()?; // long_term_frame_idx
							}
						}
						2 | 6 => {
							r.ue()?; // long_term_pic_num / long_term_frame_idx
						}
						4 => {
							r.ue()?; // max_long_term_frame_idx_plus1
						}
						5 => {}
						v => return Err(bad(format!("H.264 slice: memory_management_control_operation {v}"))),
					}
				}
				if !done {
					return Err(bad("H.264 slice: endless memory management"));
				}
			}
		}
		if pps.entropy_coding_mode && !(slice_type == 2 || si) {
			r.ue()?; // cabac_init_idc
		}
		r.se()?; // slice_qp_delta
		if sp || si {
			if sp {
				r.skip(1)?; // sp_for_switch_flag
			}
			r.se()?; // slice_qs_delta
		}
		// disable_deblocking_filter_idc: 1 turns the filter off, and the two
		// offsets are sent only when it is on
		if pps.deblocking_filter_control_present && r.ue()? != 1 {
			r.se()?; // slice_alpha_c0_offset_div2
			r.se()?; // slice_beta_offset_div2
		}
		if pps.num_slice_groups_minus1 > 0 && (3..=5).contains(&pps.slice_group_map_type) {
			// Ceil(Log2(PicSizeInMapUnits ÷ SliceGroupChangeRate + 1)), exact division
			let (size, rate) = (sps.pic_size_in_map_units, pps.slice_group_change_rate.max(1));
			let mut k = 0;
			while (1u64 << k) * rate < size + rate {
				k += 1;
			}
			r.skip(k)?;
		}
		// slice_data() follows; CABAC pads to a byte with alignment ones,
		// which belong to the same clear byte either way.
		Ok(1 + r.consumed())
	}
}

// ── HEVC (ITU-T H.265, 7.3) ────────────────────────────────────────────

/// One short-term reference picture set, as far as later sets (inter RPS
/// prediction) and `NumPicTotalCurr` need it: the deltas and which are used.
#[derive(Debug, Clone, Default)]
struct StRps {
	s0: Vec<(i32, bool)>,
	s1: Vec<(i32, bool)>,
}

impl StRps {
	fn num_delta_pocs(&self) -> usize {
		self.s0.len() + self.s1.len()
	}
	fn used(&self) -> usize {
		self.s0.iter().chain(&self.s1).filter(|(_, u)| *u).count()
	}
}

/// `st_ref_pic_set(idx)` (7.3.7) and its derivation (7.4.8): `sets` holds
/// the SPS's sets parsed so far (`idx == sets.len()` for a slice header's).
fn hevc_st_rps(r: &mut BitReader, idx: usize, sets: &[StRps], in_slice: bool) -> Result<StRps> {
	let inter = idx != 0 && r.flag()?;
	if inter {
		let delta_idx = if in_slice { r.ue()? as usize + 1 } else { 1 };
		if delta_idx > idx {
			return Err(bad("HEVC RPS predicts from a set that does not exist"));
		}
		let reference = &sets[idx - delta_idx];
		let sign = r.flag()?;
		let abs = i64::from(r.ue()?) + 1;
		let delta_rps = if sign { -abs } else { abs } as i32;
		let n = reference.num_delta_pocs();
		let mut used = Vec::with_capacity(n + 1);
		let mut use_delta = Vec::with_capacity(n + 1);
		for _ in 0..=n {
			let u = r.flag()?;
			used.push(u);
			use_delta.push(if u { true } else { r.flag()? });
		}
		// (7-61), (7-62): the reference set's pictures shifted by delta_rps,
		// plus the reference picture itself (index n), sorted into s0/s1
		let neg = reference.s0.len();
		let mut out = StRps::default();
		for j in (0..reference.s1.len()).rev() {
			let d = reference.s1[j].0 + delta_rps;
			if d < 0 && use_delta[neg + j] {
				out.s0.push((d, used[neg + j]));
			}
		}
		if delta_rps < 0 && use_delta[n] {
			out.s0.push((delta_rps, used[n]));
		}
		for j in 0..neg {
			let d = reference.s0[j].0 + delta_rps;
			if d < 0 && use_delta[j] {
				out.s0.push((d, used[j]));
			}
		}
		for j in (0..neg).rev() {
			let d = reference.s0[j].0 + delta_rps;
			if d > 0 && use_delta[j] {
				out.s1.push((d, used[j]));
			}
		}
		if delta_rps > 0 && use_delta[n] {
			out.s1.push((delta_rps, used[n]));
		}
		for j in 0..reference.s1.len() {
			let d = reference.s1[j].0 + delta_rps;
			if d > 0 && use_delta[neg + j] {
				out.s1.push((d, used[neg + j]));
			}
		}
		if out.num_delta_pocs() > 32 {
			return Err(bad("HEVC RPS with more than 32 pictures"));
		}
		Ok(out)
	} else {
		let neg = r.ue()? as usize;
		let pos = r.ue()? as usize;
		if neg + pos > 32 {
			return Err(bad("HEVC RPS with more than 32 pictures"));
		}
		let mut out = StRps::default();
		let mut poc = 0i32;
		for _ in 0..neg {
			poc -= r.ue()? as i32 + 1;
			out.s0.push((poc, r.flag()?));
		}
		poc = 0;
		for _ in 0..pos {
			poc += r.ue()? as i32 + 1;
			out.s1.push((poc, r.flag()?));
		}
		Ok(out)
	}
}

/// `profile_tier_level(1, max_sub_layers_minus1)` (7.3.3): stepped over.
fn hevc_ptl(r: &mut BitReader, max_sub_layers_minus1: u32) -> Result<()> {
	r.skip(96)?; // the general profile, tier and level: 88 + 8 bits
	let mut present = Vec::new();
	for _ in 0..max_sub_layers_minus1 {
		present.push((r.flag()?, r.flag()?));
	}
	if max_sub_layers_minus1 > 0 {
		for _ in max_sub_layers_minus1..8 {
			r.skip(2)?;
		}
	}
	for (profile, level) in present {
		if profile {
			r.skip(88)?;
		}
		if level {
			r.skip(8)?;
		}
	}
	Ok(())
}

/// `scaling_list_data()` (7.3.4): stepped over.
fn hevc_scaling_list_data(r: &mut BitReader) -> Result<()> {
	for size_id in 0..4u32 {
		let mut matrix_id = 0;
		while matrix_id < 6 {
			if !r.flag()? {
				r.ue()?; // scaling_list_pred_matrix_id_delta
			} else {
				let coefs = 64.min(1 << (4 + (size_id << 1)));
				if size_id > 1 {
					r.se()?; // scaling_list_dc_coef_minus8
				}
				for _ in 0..coefs {
					r.se()?;
				}
			}
			matrix_id += if size_id == 3 { 3 } else { 1 };
		}
	}
	Ok(())
}

#[derive(Debug, Clone)]
pub struct HevcSps {
	chroma_array_type: u32,
	separate_colour_plane: bool,
	log2_max_poc_lsb: u32,
	st_rps: Vec<StRps>,
	long_term_ref_pics_present: bool,
	used_by_curr_pic_lt_sps: Vec<bool>,
	temporal_mvp_enabled: bool,
	sao_enabled: bool,
	pic_size_in_ctbs: u64,
}

#[derive(Debug, Clone)]
pub struct HevcPps {
	sps_id: u32,
	dependent_slice_segments_enabled: bool,
	output_flag_present: bool,
	num_extra_slice_header_bits: u32,
	cabac_init_present: bool,
	num_ref_idx_l0_default_minus1: u32,
	num_ref_idx_l1_default_minus1: u32,
	slice_chroma_qp_offsets_present: bool,
	weighted_pred: bool,
	weighted_bipred: bool,
	tiles_enabled: bool,
	entropy_coding_sync_enabled: bool,
	loop_filter_across_slices_enabled: bool,
	deblocking_filter_override_enabled: bool,
	deblocking_filter_disabled: bool,
	lists_modification_present: bool,
	slice_segment_header_extension_present: bool,
	chroma_qp_offset_list_enabled: bool,
}

/// HEVC NAL unit header (two bytes): (type, nuh_layer_id).
pub fn hevc_nal_header(nal: &[u8]) -> Result<(u8, u8)> {
	if nal.len() < 2 {
		return Err(bad("HEVC NAL unit shorter than its header"));
	}
	Ok(((nal[0] >> 1) & 0x3f, ((nal[0] & 1) << 5) | (nal[1] >> 3)))
}

#[derive(Debug, Clone, Default)]
pub struct HevcParams {
	sps: BTreeMap<u32, HevcSps>,
	pps: BTreeMap<u32, HevcPps>,
}

impl HevcParams {
	/// Take an SPS (33) or PPS (34) NAL unit, header included. VPS (32)
	/// and everything else are ignored: no slice header field depends on
	/// the VPS in a single-layer stream.
	pub fn add(&mut self, nal: &[u8]) -> Result<()> {
		let (ty, layer) = hevc_nal_header(nal)?;
		if layer != 0 && matches!(ty, 32..=34) {
			return Err(refused(MULTILAYER));
		}
		match ty {
			33 => self.add_sps(&nal[2..]),
			34 => self.add_pps(&nal[2..]),
			_ => Ok(()),
		}
	}

	fn add_sps(&mut self, rbsp: &[u8]) -> Result<()> {
		let mut r = BitReader::new(rbsp);
		r.skip(4)?; // sps_video_parameter_set_id
		let max_sub_layers_minus1 = r.bits(3)?;
		r.skip(1)?; // sps_temporal_id_nesting_flag
		hevc_ptl(&mut r, max_sub_layers_minus1)?;
		let id = r.ue()?;
		if id > 15 {
			return Err(bad(format!("HEVC SPS id {id}")));
		}
		let chroma_format_idc = r.ue()?;
		let separate_colour_plane = chroma_format_idc == 3 && r.flag()?;
		let width = u64::from(r.ue()?);
		let height = u64::from(r.ue()?);
		if r.flag()? {
			// conformance_window_flag
			for _ in 0..4 {
				r.ue()?;
			}
		}
		r.ue()?; // bit_depth_luma_minus8
		r.ue()?; // bit_depth_chroma_minus8
		let log2_max_poc_lsb = r.ue()? + 4;
		if log2_max_poc_lsb > 16 {
			return Err(bad("HEVC SPS: POC wider than 16 bits"));
		}
		let ordering_all = r.flag()?;
		for _ in if ordering_all { 0 } else { max_sub_layers_minus1 }..=max_sub_layers_minus1 {
			r.ue()?;
			r.ue()?;
			r.ue()?;
		}
		let log2_min_cb = r.ue()? + 3;
		let log2_ctb = log2_min_cb + r.ue()?;
		if !(3..=7).contains(&log2_ctb) {
			return Err(bad(format!("HEVC SPS: coding tree block of 2^{log2_ctb}")));
		}
		r.ue()?; // log2_min_luma_transform_block_size_minus2
		r.ue()?; // log2_diff_max_min_luma_transform_block_size
		r.ue()?; // max_transform_hierarchy_depth_inter
		r.ue()?; // max_transform_hierarchy_depth_intra
		if r.flag()? && r.flag()? {
			// scaling_list_enabled_flag && sps_scaling_list_data_present_flag
			hevc_scaling_list_data(&mut r)?;
		}
		r.skip(1)?; // amp_enabled_flag
		let sao_enabled = r.flag()?;
		if r.flag()? {
			// pcm_enabled_flag
			r.skip(8)?; // pcm sample bit depths
			r.ue()?;
			r.ue()?;
			r.skip(1)?; // pcm_loop_filter_disabled_flag
		}
		let num_sets = r.ue()? as usize;
		if num_sets > 64 {
			return Err(bad("HEVC SPS: more than 64 reference picture sets"));
		}
		let mut st_rps = Vec::with_capacity(num_sets);
		for i in 0..num_sets {
			let set = hevc_st_rps(&mut r, i, &st_rps, false)?;
			st_rps.push(set);
		}
		let long_term_ref_pics_present = r.flag()?;
		let mut used_by_curr_pic_lt_sps = Vec::new();
		if long_term_ref_pics_present {
			let n = r.ue()?;
			if n > 32 {
				return Err(bad("HEVC SPS: more than 32 long-term pictures"));
			}
			for _ in 0..n {
				r.skip(log2_max_poc_lsb)?; // lt_ref_pic_poc_lsb_sps
				used_by_curr_pic_lt_sps.push(r.flag()?);
			}
		}
		let temporal_mvp_enabled = r.flag()?;
		// strong_intra_smoothing, VUI and extensions follow: none changes a
		// slice header in a camera's single-layer, non-SCC stream (the PPS
		// side of those extensions is checked in add_pps).
		let ctb = 1u64 << log2_ctb;
		self.sps.insert(
			id,
			HevcSps {
				chroma_array_type: if separate_colour_plane { 0 } else { chroma_format_idc },
				separate_colour_plane,
				log2_max_poc_lsb,
				st_rps,
				long_term_ref_pics_present,
				used_by_curr_pic_lt_sps,
				temporal_mvp_enabled,
				sao_enabled,
				pic_size_in_ctbs: width.div_ceil(ctb) * height.div_ceil(ctb),
			},
		);
		Ok(())
	}

	fn add_pps(&mut self, rbsp: &[u8]) -> Result<()> {
		let mut r = BitReader::new(rbsp);
		let id = r.ue()?;
		let sps_id = r.ue()?;
		if id > 63 || sps_id > 15 {
			return Err(bad(format!("HEVC PPS id {id} / SPS id {sps_id}")));
		}
		let dependent_slice_segments_enabled = r.flag()?;
		let output_flag_present = r.flag()?;
		let num_extra_slice_header_bits = r.bits(3)?;
		r.skip(1)?; // sign_data_hiding_enabled_flag
		let cabac_init_present = r.flag()?;
		let num_ref_idx_l0_default_minus1 = r.ue()?;
		let num_ref_idx_l1_default_minus1 = r.ue()?;
		r.se()?; // init_qp_minus26
		r.skip(1)?; // constrained_intra_pred_flag
		let transform_skip_enabled = r.flag()?;
		if r.flag()? {
			// cu_qp_delta_enabled_flag
			r.ue()?;
		}
		r.se()?; // pps_cb_qp_offset
		r.se()?; // pps_cr_qp_offset
		let slice_chroma_qp_offsets_present = r.flag()?;
		let weighted_pred = r.flag()?;
		let weighted_bipred = r.flag()?;
		r.skip(1)?; // transquant_bypass_enabled_flag
		let tiles_enabled = r.flag()?;
		let entropy_coding_sync_enabled = r.flag()?;
		if tiles_enabled {
			let cols = r.ue()?;
			let rows = r.ue()?;
			if cols > 64 || rows > 64 {
				return Err(bad("HEVC PPS: too many tiles"));
			}
			if !r.flag()? {
				// uniform_spacing_flag == 0
				for _ in 0..cols + rows {
					r.ue()?;
				}
			}
			r.skip(1)?; // loop_filter_across_tiles_enabled_flag
		}
		let loop_filter_across_slices_enabled = r.flag()?;
		let (mut deblocking_filter_override_enabled, mut deblocking_filter_disabled) = (false, false);
		if r.flag()? {
			// deblocking_filter_control_present_flag
			deblocking_filter_override_enabled = r.flag()?;
			deblocking_filter_disabled = r.flag()?;
			if !deblocking_filter_disabled {
				r.se()?;
				r.se()?;
			}
		}
		if r.flag()? {
			// pps_scaling_list_data_present_flag
			hevc_scaling_list_data(&mut r)?;
		}
		let lists_modification_present = r.flag()?;
		r.ue()?; // log2_parallel_merge_level_minus2
		let slice_segment_header_extension_present = r.flag()?;
		let mut chroma_qp_offset_list_enabled = false;
		if r.flag()? {
			// pps_extension_present_flag
			let range = r.flag()?;
			let multilayer = r.flag()?;
			let three_d = r.flag()?;
			let scc = r.flag()?;
			r.skip(4)?;
			if multilayer || three_d || scc {
				return Err(refused("this HEVC video uses multilayer, 3D or screen-content coding — it cannot be protected"));
			}
			if range {
				if transform_skip_enabled {
					r.ue()?; // log2_max_transform_skip_block_size_minus2
				}
				r.skip(1)?; // cross_component_prediction_enabled_flag
				chroma_qp_offset_list_enabled = r.flag()?;
			}
		}
		if num_ref_idx_l0_default_minus1 > 14 || num_ref_idx_l1_default_minus1 > 14 {
			return Err(bad("HEVC PPS: more than 15 reference indexes"));
		}
		self.pps.insert(
			id,
			HevcPps {
				sps_id,
				dependent_slice_segments_enabled,
				output_flag_present,
				num_extra_slice_header_bits,
				cabac_init_present,
				num_ref_idx_l0_default_minus1,
				num_ref_idx_l1_default_minus1,
				slice_chroma_qp_offsets_present,
				weighted_pred,
				weighted_bipred,
				tiles_enabled,
				entropy_coding_sync_enabled,
				loop_filter_across_slices_enabled,
				deblocking_filter_override_enabled,
				deblocking_filter_disabled,
				lists_modification_present,
				slice_segment_header_extension_present,
				chroma_qp_offset_list_enabled,
			},
		);
		Ok(())
	}

	/// How many stored bytes of this slice segment NAL unit (two-byte
	/// header included) are its header (7.3.6.1), ending with
	/// `byte_alignment()`.
	pub fn slice_header_len(&self, nal: &[u8]) -> Result<usize> {
		let (nal_type, layer) = hevc_nal_header(nal)?;
		if layer != 0 {
			return Err(refused(MULTILAYER));
		}
		let mut r = BitReader::new(&nal[2..]);
		let first_slice_segment_in_pic = r.flag()?;
		if (16..=23).contains(&nal_type) {
			r.skip(1)?; // no_output_of_prior_pics_flag
		}
		let pps_id = r.ue()?;
		let pps = self.pps.get(&pps_id).ok_or_else(|| bad(format!("HEVC slice refers to PPS {pps_id}, which was never sent")))?;
		let sps = self.sps.get(&pps.sps_id).ok_or_else(|| bad(format!("HEVC PPS refers to SPS {}, which was never sent", pps.sps_id)))?;
		let mut dependent = false;
		if !first_slice_segment_in_pic {
			if pps.dependent_slice_segments_enabled {
				dependent = r.flag()?;
			}
			r.skip(ceil_log2(sps.pic_size_in_ctbs))?; // slice_segment_address
		}
		if !dependent {
			r.skip(pps.num_extra_slice_header_bits)?;
			let slice_type = r.ue()?; // 0 B, 1 P, 2 I
			if slice_type > 2 {
				return Err(bad(format!("HEVC slice_type {slice_type}")));
			}
			let (b, p) = (slice_type == 0, slice_type == 1);
			if pps.output_flag_present {
				r.skip(1)?; // pic_output_flag
			}
			if sps.separate_colour_plane {
				r.skip(2)?; // colour_plane_id
			}
			let mut temporal_mvp = false;
			let mut num_pic_total_curr = 0usize;
			if nal_type != 19 && nal_type != 20 {
				// not IDR
				r.skip(sps.log2_max_poc_lsb)?; // slice_pic_order_cnt_lsb
				let num_sets = sps.st_rps.len();
				if !r.flag()? {
					// short_term_ref_pic_set_sps_flag == 0: the set is here
					num_pic_total_curr += hevc_st_rps(&mut r, num_sets, &sps.st_rps, true)?.used();
				} else {
					let idx = if num_sets > 1 { r.bits(ceil_log2(num_sets as u64))? as usize } else { 0 };
					num_pic_total_curr += sps.st_rps.get(idx).ok_or_else(|| bad("HEVC slice names a missing RPS"))?.used();
				}
				if sps.long_term_ref_pics_present {
					let lt_sps_count = sps.used_by_curr_pic_lt_sps.len();
					let num_lt_sps = if lt_sps_count > 0 { r.ue()? as usize } else { 0 };
					let num_lt_pics = r.ue()? as usize;
					if num_lt_sps > lt_sps_count || num_lt_sps + num_lt_pics > 32 {
						return Err(bad("HEVC slice: too many long-term pictures"));
					}
					for i in 0..num_lt_sps + num_lt_pics {
						if i < num_lt_sps {
							let idx = if lt_sps_count > 1 { r.bits(ceil_log2(lt_sps_count as u64))? as usize } else { 0 };
							if *sps.used_by_curr_pic_lt_sps.get(idx).ok_or_else(|| bad("HEVC slice names a missing long-term picture"))? {
								num_pic_total_curr += 1;
							}
						} else {
							r.skip(sps.log2_max_poc_lsb)?; // poc_lsb_lt
							if r.flag()? {
								num_pic_total_curr += 1;
							}
						}
						if r.flag()? {
							// delta_poc_msb_present_flag
							r.ue()?;
						}
					}
				}
				if sps.temporal_mvp_enabled {
					temporal_mvp = r.flag()?;
				}
			}
			let (mut sao_luma, mut sao_chroma) = (false, false);
			if sps.sao_enabled {
				sao_luma = r.flag()?;
				if sps.chroma_array_type != 0 {
					sao_chroma = r.flag()?;
				}
			}
			if p || b {
				let (mut l0, mut l1) = (pps.num_ref_idx_l0_default_minus1, pps.num_ref_idx_l1_default_minus1);
				if r.flag()? {
					// num_ref_idx_active_override_flag
					l0 = r.ue()?;
					if b {
						l1 = r.ue()?;
					}
				}
				if l0 > 14 || l1 > 14 {
					return Err(bad("HEVC slice: more than 15 reference indexes"));
				}
				if pps.lists_modification_present && num_pic_total_curr > 1 {
					let bits = ceil_log2(num_pic_total_curr as u64);
					if r.flag()? {
						r.skip(bits * (l0 + 1))?;
					}
					if b && r.flag()? {
						r.skip(bits * (l1 + 1))?;
					}
				}
				if b {
					r.skip(1)?; // mvd_l1_zero_flag
				}
				if pps.cabac_init_present {
					r.skip(1)?; // cabac_init_flag
				}
				if temporal_mvp {
					let from_l0 = if b { r.flag()? } else { true };
					if (from_l0 && l0 > 0) || (!from_l0 && l1 > 0) {
						r.ue()?; // collocated_ref_idx
					}
				}
				if (pps.weighted_pred && p) || (pps.weighted_bipred && b) {
					// pred_weight_table() (7.3.6.3)
					r.ue()?; // luma_log2_weight_denom
					if sps.chroma_array_type != 0 {
						r.se()?; // delta_chroma_log2_weight_denom
					}
					for list in 0..if b { 2 } else { 1 } {
						let n = (if list == 0 { l0 } else { l1 }) as usize + 1;
						let mut luma = Vec::with_capacity(n);
						for _ in 0..n {
							luma.push(r.flag()?);
						}
						let mut chroma = vec![false; n];
						if sps.chroma_array_type != 0 {
							for c in chroma.iter_mut() {
								*c = r.flag()?;
							}
						}
						for i in 0..n {
							if luma[i] {
								r.se()?;
								r.se()?;
							}
							if chroma[i] {
								for _ in 0..4 {
									r.se()?;
								}
							}
						}
					}
				}
				r.ue()?; // five_minus_max_num_merge_cand
			}
			r.se()?; // slice_qp_delta
			if pps.slice_chroma_qp_offsets_present {
				r.se()?;
				r.se()?;
			}
			if pps.chroma_qp_offset_list_enabled {
				r.skip(1)?; // cu_chroma_qp_offset_enabled_flag
			}
			let override_flag = pps.deblocking_filter_override_enabled && r.flag()?;
			let mut deblocking_disabled = pps.deblocking_filter_disabled;
			if override_flag {
				deblocking_disabled = r.flag()?;
				if !deblocking_disabled {
					r.se()?; // slice_beta_offset_div2
					r.se()?; // slice_tc_offset_div2
				}
			}
			if pps.loop_filter_across_slices_enabled && (sao_luma || sao_chroma || !deblocking_disabled) {
				r.skip(1)?; // slice_loop_filter_across_slices_enabled_flag
			}
		}
		if pps.tiles_enabled || pps.entropy_coding_sync_enabled {
			let n = r.ue()?;
			if n > 1 << 16 {
				return Err(bad("HEVC slice: too many entry points"));
			}
			if n > 0 {
				let len = r.ue()? + 1;
				if len > 32 {
					return Err(bad("HEVC slice: entry point offsets wider than 32 bits"));
				}
				for _ in 0..n {
					r.skip(len)?;
				}
			}
		}
		if pps.slice_segment_header_extension_present {
			let n = r.ue()?;
			if n > 256 {
				return Err(bad("HEVC slice: header extension over 256 bytes"));
			}
			r.skip(8 * n)?;
		}
		// byte_alignment(): a one, then zeros to the byte boundary
		if r.bit()? != 1 {
			return Err(bad("HEVC slice header does not end where its syntax says"));
		}
		while !r.byte_aligned() {
			if r.bit()? != 0 {
				return Err(bad("HEVC slice header does not end where its syntax says"));
			}
		}
		Ok(2 + r.consumed())
	}
}

/// Split a length-prefixed sample (the MP4 way: no start codes) into its
/// NAL units. A sample whose lengths do not add up exactly is refused.
pub fn split_nals(sample: &[u8], length_size: usize) -> Result<Vec<(usize, usize)>> {
	if !(1..=4).contains(&length_size) {
		return Err(bad(format!("NAL length size {length_size}")));
	}
	let mut out = Vec::new();
	let mut at = 0usize;
	while at < sample.len() {
		if at + length_size > sample.len() {
			return Err(bad("sample ends inside a NAL length"));
		}
		let len = sample[at..at + length_size].iter().fold(0usize, |v, b| (v << 8) | usize::from(*b));
		at += length_size;
		if len == 0 || at + len > sample.len() {
			return Err(bad("a NAL unit's length runs past its sample"));
		}
		out.push((at, len));
		at += len;
	}
	Ok(out)
}

/// The NAL length size and parameter sets of an `avcC` box's content.
pub fn parse_avcc(c: &[u8]) -> Result<(usize, AvcParams)> {
	let short = || bad("avcC is truncated");
	let length_size = usize::from(c.get(4).ok_or_else(short)? & 3) + 1;
	let mut params = AvcParams::default();
	let mut at = 5usize;
	for kind in 0..2 {
		let count = usize::from(*c.get(at).ok_or_else(short)?) & if kind == 0 { 0x1f } else { 0xff };
		at += 1;
		for _ in 0..count {
			let len = usize::from(u16::from_be_bytes([*c.get(at).ok_or_else(short)?, *c.get(at + 1).ok_or_else(short)?]));
			at += 2;
			params.add(c.get(at..at + len).ok_or_else(short)?)?;
			at += len;
		}
	}
	Ok((length_size, params))
}

/// The NAL length size and parameter sets of an `hvcC` box's content.
pub fn parse_hvcc(c: &[u8]) -> Result<(usize, HevcParams)> {
	let short = || bad("hvcC is truncated");
	let length_size = usize::from(c.get(21).ok_or_else(short)? & 3) + 1;
	let arrays = usize::from(*c.get(22).ok_or_else(short)?);
	let mut params = HevcParams::default();
	let mut at = 23usize;
	for _ in 0..arrays {
		at += 1; // array_completeness, reserved, NAL_unit_type
		let count = usize::from(u16::from_be_bytes([*c.get(at).ok_or_else(short)?, *c.get(at + 1).ok_or_else(short)?]));
		at += 2;
		for _ in 0..count {
			let len = usize::from(u16::from_be_bytes([*c.get(at).ok_or_else(short)?, *c.get(at + 1).ok_or_else(short)?]));
			at += 2;
			params.add(c.get(at..at + len).ok_or_else(short)?)?;
			at += len;
		}
	}
	Ok((length_size, params))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn exp_golomb_and_emulation_prevention() {
		// 1 → 0, 010 → 1, 011 → 2, 00100 → 3; se: 010 → +1, 011 → −1
		let mut r = BitReader::new(&[0b1010_0110, 0b0100_0000]);
		assert_eq!(r.ue().unwrap(), 0);
		assert_eq!(r.ue().unwrap(), 1);
		assert_eq!(r.ue().unwrap(), 2);
		assert_eq!(r.ue().unwrap(), 3);
		let mut r = BitReader::new(&[0b0100_1100]);
		assert_eq!(r.se().unwrap(), 1);
		assert_eq!(r.se().unwrap(), -1);
		// 00 00 03 01: the 03 is dropped from the bits but counted as stored
		let mut r = BitReader::new(&[0x00, 0x00, 0x03, 0x01]);
		assert_eq!(r.bits(24).unwrap(), 0x000001);
		assert_eq!(r.consumed(), 4, "four stored bytes for three RBSP bytes");
		// a reader that runs out says so instead of inventing zeros
		let mut r = BitReader::new(&[0x00]);
		assert!(r.ue().is_err());
	}

	#[test]
	fn a_partly_read_byte_counts_as_consumed() {
		let mut r = BitReader::new(&[0xff, 0xff]);
		r.skip(9).unwrap();
		assert_eq!(r.consumed(), 2);
		assert!(!r.byte_aligned());
	}

	#[test]
	fn ceil_log2_matches_the_spec() {
		assert_eq!(ceil_log2(0), 0);
		assert_eq!(ceil_log2(1), 0);
		assert_eq!(ceil_log2(2), 1);
		assert_eq!(ceil_log2(3), 2);
		assert_eq!(ceil_log2(510), 9); // 1080p in 64×64 CTBs: 30 × 17
		assert_eq!(ceil_log2(512), 9);
		assert_eq!(ceil_log2(513), 10);
	}

	#[test]
	fn lengths_must_add_up() {
		assert_eq!(split_nals(&[0, 0, 0, 2, 9, 9, 0, 0, 0, 1, 7], 4).unwrap(), vec![(4, 2), (10, 1)]);
		assert!(split_nals(&[0, 0, 0, 5, 9], 4).is_err());
		assert!(split_nals(&[0, 0, 0, 0], 4).is_err(), "a zero length is not a NAL unit");
	}

	#[test]
	fn a_slice_without_its_pps_is_refused() {
		let p = AvcParams::default();
		// IDR slice: first_mb 0 (1), slice_type 7 (0001000), pps 0 (1)
		assert!(p.slice_header_len(&[0x65, 0b1000_1000, 0b1000_0000]).unwrap_err().to_string().contains("PPS 0"));
	}
}
