// Copyright 2026- Seongwoo Hong. All rights reserved.
// (Vendored from mp4-hls-core's fairplay.rs, the author's stream-worker
// project — commit 40b. Ported from aes 0.9/cbc to this workspace's aes 0.8,
// with blinded RSA and one error type; the protocol code is unchanged.)

//! FairPlay Streaming Key Security Module — an SPC in, a CKC out, no vendor.
//!
//! # What this is
//!
//! Safari, iOS and tvOS play encrypted HLS only through FairPlay. The player
//! sends the key server a *Server Playback Context* (SPC) — an RSA-wrapped,
//! AES-wrapped bundle of session material — and expects a *Content Key
//! Context* (CKC) carrying the content key, encrypted so that only that
//! session's DRM module can open it. The piece that turns one into the other
//! is the Key Security Module (KSM). Vendors sell it as a service; this is
//! one, small enough to run inside the Worker. It needs what Apple's FPS
//! Deployment Package issues: the FPS certificate, its RSA private key, and
//! the Application Secret Key (ASK). See docs/DRM.md.
//!
//! In gorani the KSM is where "who may watch" is enforced last: the Worker
//! checks the viewer's link or grant, finds the video's content key (sealed
//! under a Worker secret, worker/src/drm.rs), and only then calls
//! [`respond`]. This crate decides nothing about who — it only speaks the
//! protocol.
//!
//! # The protocol, as verified
//!
//! Every constant and step below was checked against Apple's SDK test
//! vectors with an independent decoder before the original was written,
//! because public reference implementations disagree with each other and
//! with the vectors on two points: the RSA-OAEP hash is **SHA-1** (not
//! SHA-256), and the CKC payload key is **16 bytes**.
//!
//! ```text
//! SPC  = version(4)=1 | reserved(4) | IV(16) | RSA-OAEP-SHA1(SPCK)(128)
//!      | SHA1(cert DER)(20) | len(4) | AES-128-CBC(SPCK, IV, TLLVs…)
//! TLLV = tag(8) | block_len(4) | value_len(4) | value | random padding
//! [SK…R1] TLLV value = IV(16) | AES-128-CBC(DASk, IV, SK(16) HU(20) R1(44) integrity(16))
//! DASk = AES-128-ECB(ASK, D_hash(R2))          — the "D function"
//! CKC  = version(4)=1 | reserved(4) | IV(16) | len(4)
//!      | AES-128-CBC(AES-ECB(SHA1(R1)[..16], anti-replay seed), IV, TLLVs…)
//! CKC TLLVs = encrypted CK (content IV | AES-ECB(SK, CK)) , R1 , every TLLV
//!             the SPC's return-request list names , [content key duration]
//!             , [HDCP enforcement]
//! ```
//!
//! Only a real Safari with real credentials proves the last step of the D
//! function; until Apple issues the package, the tests here check this
//! module against its own client half ([`client`]) and the D function's
//! hash against the published vectors.
//!
//! # Hardening for an endpoint anyone can reach
//!
//! The license route answers share-link viewers, who are not signed in. So:
//! the RSA decryption is **blinded** (a fresh random factor per call, so its
//! timing says nothing about the key); every SPC failure the route reports
//! to such a caller is one generic message (worker/src/drm.rs), with the
//! precise reason below kept for the log; and parsing never panics on any
//! input (the tests feed it garbage and truncations).

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::{Oaep, RsaPrivateKey};
use sha1::{Digest, Sha1};

/// Why an SPC or a credential was refused — precise, for the operator's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpsError(pub String);

impl std::fmt::Display for FpsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for FpsError {}

pub type Result<T> = std::result::Result<T, FpsError>;

fn err(msg: impl Into<String>) -> FpsError {
	FpsError(msg.into())
}

// ── TLLV tags (Apple FPS) ──────────────────────────────────────────────
pub const TAG_SK_R1: u64 = 0x3d1a_10b8_bffa_c2ec;
pub const TAG_SK_R1_INTEGRITY: u64 = 0xb349_d480_9e91_0687;
pub const TAG_ANTI_REPLAY_SEED: u64 = 0x89c9_0f12_2041_06b2;
pub const TAG_R2: u64 = 0x71b5_595a_c152_1133;
pub const TAG_RETURN_REQUEST: u64 = 0x19f9_d4e5_ab76_09cb;
pub const TAG_ASSET_ID: u64 = 0x1bf7_f53f_5d5d_5a1f;
pub const TAG_TRANSACTION_ID: u64 = 0x47aa_7ad3_4405_77de;
pub const TAG_PROTOCOL_VERSIONS_SUPPORTED: u64 = 0x67b8_fb79_ecce_1a13;
pub const TAG_PROTOCOL_VERSION_USED: u64 = 0x5d81_bcbc_c7f6_1703;
pub const TAG_STREAMING_INDICATOR: u64 = 0xabb0_256a_3184_3974;
pub const TAG_MEDIA_PLAYBACK_STATE: u64 = 0xeb8e_fdf2_b25a_b3a0;
pub const TAG_ENCRYPTED_CK: u64 = 0x58b3_8165_af0e_3d5a;
pub const TAG_R1: u64 = 0xea74_c464_5d5e_fee9;
pub const TAG_CONTENT_KEY_DURATION: u64 = 0x47ac_f6a4_18cd_091a;
pub const TAG_HDCP_ENFORCEMENT: u64 = 0x2e52_f153_0d8d_db4a;
/// HDCP enforcement values (the TLLV above).
pub const HDCP_NOT_REQUIRED: u64 = 0xef72_894c_a789_5b78;
pub const HDCP_TYPE0: u64 = 0x4079_1ac7_8bd5_c571;
pub const HDCP_TYPE1: u64 = 0x285a_0863_bba8_e1d3;
/// Key type inside the duration TLLV: "content key valid for lease only".
const KEY_TYPE_LEASE: u32 = 0x1a4b_de7e;
const DURATION_RESERVED: u32 = 0x86d3_4a3a;

const SPC_HEADER_LEN: usize = 176;
const CKC_HEADER_LEN: usize = 28;

// ── primitives ─────────────────────────────────────────────────────────

/// Randomness from the platform (the Worker's crypto.getRandomValues,
/// the OS elsewhere), in the shape the rsa crate takes.
pub struct SystemRandom;

impl RngCore for SystemRandom {
	fn next_u32(&mut self) -> u32 {
		let mut b = [0u8; 4];
		self.fill_bytes(&mut b);
		u32::from_le_bytes(b)
	}
	fn next_u64(&mut self) -> u64 {
		let mut b = [0u8; 8];
		self.fill_bytes(&mut b);
		u64::from_le_bytes(b)
	}
	fn fill_bytes(&mut self, dest: &mut [u8]) {
		// No randomness is not something to carry on without.
		getrandom::getrandom(dest).expect("the platform has no randomness");
	}
	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rsa::rand_core::Error> {
		getrandom::getrandom(dest).map_err(|e| rsa::rand_core::Error::from(std::num::NonZeroU32::new(e.code().get()).expect("non-zero")))
	}
}

impl CryptoRng for SystemRandom {}

fn cipher(key: &[u8; 16]) -> Aes128 {
	Aes128::new_from_slice(key).expect("a 16-byte key")
}

fn aes_block(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
	let mut b = aes::Block::from(*data);
	cipher(key).encrypt_block(&mut b);
	b.into()
}

fn cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
	if !data.len().is_multiple_of(16) {
		return Err(err("cbc: input is not a multiple of 16"));
	}
	let c = cipher(key);
	let mut chain = *iv;
	let mut out = Vec::with_capacity(data.len());
	for block in data.chunks_exact(16) {
		let mut b = aes::Block::default();
		for i in 0..16 {
			b[i] = block[i] ^ chain[i];
		}
		c.encrypt_block(&mut b);
		chain.copy_from_slice(&b);
		out.extend_from_slice(&b);
	}
	Ok(out)
}

fn cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
	if !data.len().is_multiple_of(16) {
		return Err(err("cbc: input is not a multiple of 16"));
	}
	let c = cipher(key);
	let mut chain = *iv;
	let mut out = Vec::with_capacity(data.len());
	for block in data.chunks_exact(16) {
		let mut b = aes::Block::default();
		b.copy_from_slice(block);
		c.decrypt_block(&mut b);
		for i in 0..16 {
			b[i] ^= chain[i];
		}
		chain.copy_from_slice(block);
		out.extend_from_slice(&b);
	}
	Ok(out)
}

fn sha1(data: &[u8]) -> [u8; 20] {
	Sha1::digest(data).into()
}

fn arr<const N: usize>(s: &[u8]) -> [u8; N] {
	let mut a = [0u8; N];
	a.copy_from_slice(&s[..N]);
	a
}

/// 32 hex chars → 16 bytes.
pub fn hex16(s: &str) -> Result<[u8; 16]> {
	let s = s.trim();
	if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
		return Err(err("expected 32 hex characters"));
	}
	let mut out = [0u8; 16];
	for (i, o) in out.iter_mut().enumerate() {
		*o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| err(e.to_string()))?;
	}
	Ok(out)
}

// ── the D function ─────────────────────────────────────────────────────

/// The hash half of Apple's D function: R2 (≤ 55 bytes) → 16 bytes.
/// Wrapping 32-bit arithmetic and little-endian tail bytes are part of
/// the definition, not accidents — the published vectors only pass this way.
pub fn d_hash(r2: &[u8]) -> Result<[u8; 16]> {
	const PRIME: u32 = 813_416_437;
	const ROUNDS: u32 = 16;
	if r2.is_empty() || r2.len() > 55 {
		return Err(err("R2 must be 1..=55 bytes"));
	}
	let mut pad = [0u8; 64];
	pad[..r2.len()].copy_from_slice(r2);
	pad[r2.len()] = 0x80;
	let mut m = [0u32; 14];
	for (i, w) in m.iter_mut().enumerate() {
		*w = u32::from_be_bytes(arr(&pad[4 * i..4 * i + 4]));
	}
	for i in 1..7 {
		m[0] = m[0].wrapping_add(m[i]);
	}
	m[1] = 0;
	for i in 0..7 {
		m[1] = m[1].wrapping_add(m[i + 7]);
	}
	for w in m.iter_mut().take(2) {
		for _ in 0..ROUNDS {
			if *w & 1 == 1 {
				*w >>= 1;
			} else {
				*w = w.wrapping_mul(3).wrapping_add(1) % PRIME;
			}
		}
	}
	for i in 0..4 {
		pad[56 + i] = (m[0] >> (8 * i)) as u8;
		pad[60 + i] = (m[1] >> (8 * i)) as u8;
	}
	Ok(arr(&sha1(&pad)))
}

/// Derived Application Secret Key for one session.
pub fn dask(ask: &[u8; 16], r2: &[u8]) -> Result<[u8; 16]> {
	Ok(aes_block(ask, &d_hash(r2)?))
}

// ── credentials ────────────────────────────────────────────────────────

/// What Apple issues: the FPS certificate, its private key, and the ASK.
/// Accepts PEM or base64 DER for the first two, hex for the ASK.
pub struct Credentials {
	pub cert_der: Vec<u8>,
	pub cert_sha1: [u8; 20],
	key: RsaPrivateKey,
	ask: [u8; 16],
}

impl std::fmt::Debug for Credentials {
	/// The private key and the ASK are never printed.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Credentials").field("cert_sha1", &self.cert_sha1).finish_non_exhaustive()
	}
}

fn b64_decode_loose(s: &str) -> Result<Vec<u8>> {
	use base64::Engine;
	let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
	base64::engine::general_purpose::STANDARD.decode(&compact).map_err(|e| err(format!("base64: {e}")))
}

fn pem_body(s: &str) -> String {
	s.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("")
}

impl Credentials {
	pub fn new(cert_der: Vec<u8>, key: RsaPrivateKey, ask: [u8; 16]) -> Self {
		let cert_sha1 = sha1(&cert_der);
		Credentials { cert_der, cert_sha1, key, ask }
	}

	/// `cert`: PEM (`-----BEGIN CERTIFICATE-----`) or base64 DER.
	/// `private_key`: PKCS#1 or PKCS#8 PEM, or base64 DER of either.
	/// `ask_hex`: 32 hex characters.
	pub fn parse(cert: &str, private_key: &str, ask_hex: &str) -> Result<Self> {
		let cert_der = if cert.contains("-----BEGIN") { b64_decode_loose(&pem_body(cert))? } else { b64_decode_loose(cert)? };
		if cert_der.len() < 64 || cert_der[0] != 0x30 {
			return Err(err("FairPlay certificate is not DER (expected PEM or base64 DER)"));
		}
		let pk = private_key.trim();
		let key = if pk.contains("-----BEGIN RSA PRIVATE KEY-----") {
			RsaPrivateKey::from_pkcs1_pem(pk).map_err(|e| e.to_string())
		} else if pk.contains("-----BEGIN PRIVATE KEY-----") {
			RsaPrivateKey::from_pkcs8_pem(pk).map_err(|e| e.to_string())
		} else {
			let der = b64_decode_loose(pk)?;
			RsaPrivateKey::from_pkcs8_der(&der).map_err(|e| e.to_string()).or_else(|_| RsaPrivateKey::from_pkcs1_der(&der).map_err(|e| e.to_string()))
		}
		.map_err(|e| err(format!("FairPlay private key: {e}")))?;
		let ask = hex16(ask_hex).map_err(|_| err("FairPlay ASK must be 32 hex characters"))?;
		Ok(Self::new(cert_der, key, ask))
	}

	pub fn public_key(&self) -> rsa::RsaPublicKey {
		self.key.to_public_key()
	}
}

// ── SPC ────────────────────────────────────────────────────────────────

/// A parsed, authenticated Server Playback Context.
#[derive(Clone)]
pub struct Spc {
	pub version: u32,
	/// What the player names the key by: from the playlist's `skd://` URI.
	pub asset_id: Vec<u8>,
	pub transaction_id: Option<[u8; 8]>,
	pub has_media_playback_state: bool,
	pub protocol_version_used: u32,
	/// tags the client asked to have echoed back, in order
	pub return_request: Vec<u64>,
	sk: [u8; 16],
	r1: [u8; 44],
	anti_replay_seed: [u8; 16],
	tllvs: Vec<(u64, Vec<u8>)>,
}

impl std::fmt::Debug for Spc {
	/// The session key and R1 are never printed.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Spc").field("version", &self.version).field("asset_id", &String::from_utf8_lossy(&self.asset_id)).field("return_request", &self.return_request).finish_non_exhaustive()
	}
}

impl Spc {
	pub fn tllv(&self, tag: u64) -> Option<&[u8]> {
		self.tllvs.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice())
	}
	/// The session's R1, needed to open the CKC this SPC will get.
	pub fn r1(&self) -> &[u8; 44] {
		&self.r1
	}
	pub fn session_key(&self) -> &[u8; 16] {
		&self.sk
	}
}

fn parse_tllvs(buf: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
	let mut out = Vec::new();
	let mut o = 0usize;
	while o < buf.len() {
		if o + 16 > buf.len() {
			return Err(err("TLLV header truncated"));
		}
		let tag = u64::from_be_bytes(arr(&buf[o..o + 8]));
		let block = u32::from_be_bytes(arr(&buf[o + 8..o + 12])) as usize;
		let vlen = u32::from_be_bytes(arr(&buf[o + 12..o + 16])) as usize;
		if vlen > block || o + 16 + block > buf.len() {
			return Err(err(format!("TLLV {tag:016x} overruns the payload")));
		}
		out.push((tag, buf[o + 16..o + 16 + vlen].to_vec()));
		o += 16 + block;
	}
	Ok(out)
}

/// Serialize one TLLV with random padding to a 16-byte boundary plus one
/// extra block, the shape Apple's reference output uses.
fn tllv(tag: u64, value: &[u8], random: &mut dyn FnMut(&mut [u8]) -> Result<()>) -> Result<Vec<u8>> {
	let pad_len = 32 - value.len() % 16;
	let mut pad = vec![0u8; pad_len];
	random(&mut pad)?;
	let mut out = Vec::with_capacity(16 + value.len() + pad_len);
	out.extend_from_slice(&tag.to_be_bytes());
	out.extend_from_slice(&((value.len() + pad_len) as u32).to_be_bytes());
	out.extend_from_slice(&(value.len() as u32).to_be_bytes());
	out.extend_from_slice(value);
	out.extend_from_slice(&pad);
	Ok(out)
}

fn hex_prefix(b: &[u8]) -> String {
	b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

/// Parse and authenticate an SPC with these credentials.
pub fn parse_spc(creds: &Credentials, spc: &[u8]) -> Result<Spc> {
	if spc.len() < SPC_HEADER_LEN {
		return Err(err(format!("SPC too short ({} bytes; header is {SPC_HEADER_LEN})", spc.len())));
	}
	let version = u32::from_be_bytes(arr(&spc[0..4]));
	if version != 1 {
		return Err(err(format!("SPC version {version} is not supported (expected 1)")));
	}
	let iv: [u8; 16] = arr(&spc[8..24]);
	let wrapped_key = &spc[24..152];
	let cert_hash: [u8; 20] = arr(&spc[152..172]);
	if cert_hash != creds.cert_sha1 {
		return Err(err(format!(
			"SPC was created for a different application certificate (SPC {}…, ours {}…)",
			hex_prefix(&cert_hash),
			hex_prefix(&creds.cert_sha1)
		)));
	}
	let len = u32::from_be_bytes(arr(&spc[172..176])) as usize;
	if len == 0 || !len.is_multiple_of(16) || SPC_HEADER_LEN + len > spc.len() {
		return Err(err(format!("SPC payload length {len} is inconsistent with {} bytes", spc.len())));
	}
	// Blinded: the RSA operation's timing is decoupled from the key by a
	// fresh random factor — this endpoint answers callers who are not
	// signed in (the rsa crate's own advice since RUSTSEC-2023-0071).
	let spck = creds
		.key
		.decrypt_blinded(&mut SystemRandom, Oaep::new::<Sha1>(), wrapped_key)
		.map_err(|_| err("SPC session key does not open with this private key (certificate and key mismatched?)"))?;
	if spck.len() != 16 {
		return Err(err("SPC session key is not 16 bytes"));
	}
	let payload = cbc_decrypt(&arr(&spck), &iv, &spc[SPC_HEADER_LEN..SPC_HEADER_LEN + len])?;
	let tllvs = parse_tllvs(&payload)?;
	let get = |tag: u64| tllvs.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice());

	let r2 = get(TAG_R2).ok_or_else(|| err("SPC has no R2"))?;
	let dask = dask(&creds.ask, r2)?;
	let skr1 = get(TAG_SK_R1).ok_or_else(|| err("SPC has no [SK…R1]"))?;
	if skr1.len() != 112 {
		return Err(err(format!("[SK…R1] is {} bytes, expected 112", skr1.len())));
	}
	let opened = cbc_decrypt(&dask, &arr(&skr1[..16]), &skr1[16..112])?;
	let integrity = get(TAG_SK_R1_INTEGRITY).ok_or_else(|| err("SPC has no integrity block"))?;
	if opened[80..96] != *integrity {
		return Err(err("SPC integrity check failed: the Application Secret Key (ASK) does not match this certificate"));
	}
	let seed = get(TAG_ANTI_REPLAY_SEED).ok_or_else(|| err("SPC has no anti-replay seed"))?;
	if seed.len() != 16 {
		return Err(err("anti-replay seed is not 16 bytes"));
	}
	let asset_id = get(TAG_ASSET_ID).unwrap_or(&[]).to_vec();
	if asset_id.len() < 2 || asset_id.len() > 200 {
		return Err(err(format!("asset id is {} bytes; FairPlay allows 2..=200", asset_id.len())));
	}
	let rr = get(TAG_RETURN_REQUEST).unwrap_or(&[]);
	if rr.len() % 8 != 0 {
		return Err(err("return-request list is not a multiple of 8 bytes"));
	}
	let return_request: Vec<u64> = rr.chunks(8).map(|c| u64::from_be_bytes(arr(c))).collect();
	let transaction_id = get(TAG_TRANSACTION_ID).filter(|v| v.len() == 8).map(arr::<8>);
	let protocol_version_used = get(TAG_PROTOCOL_VERSION_USED).filter(|v| v.len() == 4).map(|v| u32::from_be_bytes(arr(v))).unwrap_or(1);
	Ok(Spc {
		version,
		asset_id,
		transaction_id,
		has_media_playback_state: get(TAG_MEDIA_PLAYBACK_STATE).is_some(),
		protocol_version_used,
		return_request,
		sk: arr(&opened[0..16]),
		r1: arr(&opened[36..80]),
		anti_replay_seed: arr(seed),
		tllvs,
	})
}

// ── CKC ────────────────────────────────────────────────────────────────

/// What the KSM hands out for one asset.
#[derive(Clone, Copy)]
pub struct ContentKey {
	pub key: [u8; 16],
	/// The IV the CKC advertises next to the key. For fMP4 `cbcs` content
	/// the IV lives in the init segment (`tenc`), so this is informational;
	/// gorani sends the packaging IV anyway.
	pub iv: [u8; 16],
	/// Above zero adds a Content Key Duration TLLV (lease type) when the
	/// client sent a Media Playback State; zero omits it — valid for the session.
	pub lease_seconds: u32,
	/// HDCP requirement TLLV value; None omits the TLLV.
	pub hdcp: Option<u64>,
}

impl std::fmt::Debug for ContentKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ContentKey").field("lease_seconds", &self.lease_seconds).field("hdcp", &self.hdcp).finish_non_exhaustive()
	}
}

/// The key that encrypts a CKC for this session.
fn ckc_key(spc: &Spc) -> [u8; 16] {
	let ar_key: [u8; 16] = arr(&sha1(&spc.r1));
	aes_block(&ar_key, &spc.anti_replay_seed)
}

/// Build the CKC answering `spc`. `random` fills IVs and padding.
pub fn build_ckc(spc: &Spc, ck: &ContentKey, random: &mut dyn FnMut(&mut [u8]) -> Result<()>) -> Result<Vec<u8>> {
	let mut payload = Vec::new();
	// 1. the content key, wrapped with the session key (one block: ECB)
	let mut ck_value = [0u8; 32];
	ck_value[..16].copy_from_slice(&ck.iv);
	ck_value[16..].copy_from_slice(&aes_block(&spc.sk, &ck.key));
	// Apple's reference pads this one block to 48 bytes, not the generic rule
	let mut pad = [0u8; 16];
	random(&mut pad)?;
	payload.extend_from_slice(&TAG_ENCRYPTED_CK.to_be_bytes());
	payload.extend_from_slice(&48u32.to_be_bytes());
	payload.extend_from_slice(&32u32.to_be_bytes());
	payload.extend_from_slice(&ck_value);
	payload.extend_from_slice(&pad);
	// 2. R1, proving we opened the SPC
	payload.extend_from_slice(&tllv(TAG_R1, &spc.r1, random)?);
	// 3. everything the client asked to see again, verbatim
	for tag in &spc.return_request {
		let v = spc.tllv(*tag).ok_or_else(|| err(format!("return-request names TLLV {tag:016x}, which the SPC does not carry")))?;
		payload.extend_from_slice(&tllv(*tag, v, random)?);
	}
	// 4. duration, only in the shape Apple's reference uses it
	if ck.lease_seconds > 0 && spc.has_media_playback_state {
		let mut v = Vec::with_capacity(16);
		v.extend_from_slice(&ck.lease_seconds.to_be_bytes());
		v.extend_from_slice(&0u32.to_be_bytes());
		v.extend_from_slice(&KEY_TYPE_LEASE.to_be_bytes());
		v.extend_from_slice(&DURATION_RESERVED.to_be_bytes());
		payload.extend_from_slice(&tllv(TAG_CONTENT_KEY_DURATION, &v, random)?);
	}
	// 5. HDCP (gorani: Type 0 required — docs/DRM.md › Decisions)
	if let Some(h) = ck.hdcp {
		payload.extend_from_slice(&tllv(TAG_HDCP_ENFORCEMENT, &h.to_be_bytes(), random)?);
	}
	let mut iv = [0u8; 16];
	random(&mut iv)?;
	let encrypted = cbc_encrypt(&ckc_key(spc), &iv, &payload)?;
	let mut out = Vec::with_capacity(CKC_HEADER_LEN + encrypted.len());
	out.extend_from_slice(&1u32.to_be_bytes());
	out.extend_from_slice(&0u32.to_be_bytes());
	out.extend_from_slice(&iv);
	out.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
	out.extend_from_slice(&encrypted);
	Ok(out)
}

/// Open a CKC with the session it answers — what a client does, and what
/// the tests need. Returns the TLLVs in order.
pub fn open_ckc(spc: &Spc, ckc: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
	if ckc.len() < CKC_HEADER_LEN {
		return Err(err("CKC too short"));
	}
	let version = u32::from_be_bytes(arr(&ckc[0..4]));
	if version != 1 {
		return Err(err(format!("CKC version {version}")));
	}
	let iv: [u8; 16] = arr(&ckc[8..24]);
	let len = u32::from_be_bytes(arr(&ckc[24..28])) as usize;
	if CKC_HEADER_LEN + len > ckc.len() {
		return Err(err("CKC payload length overruns"));
	}
	parse_tllvs(&cbc_decrypt(&ckc_key(spc), &iv, &ckc[CKC_HEADER_LEN..CKC_HEADER_LEN + len])?)
}

/// The content key and IV a CKC carries, as the client recovers them.
pub fn unwrap_content_key(spc: &Spc, ckc_tllvs: &[(u64, Vec<u8>)]) -> Result<([u8; 16], [u8; 16])> {
	let v = ckc_tllvs.iter().find(|(t, _)| *t == TAG_ENCRYPTED_CK).map(|(_, v)| v.as_slice()).ok_or_else(|| err("CKC has no encrypted content key"))?;
	if v.len() != 32 {
		return Err(err("encrypted content key block is not 32 bytes"));
	}
	let iv: [u8; 16] = arr(&v[..16]);
	let key = cbc_decrypt(&spc.sk, &[0u8; 16], &v[16..32])?;
	Ok((arr(&key), iv))
}

/// The CKC for a parsed SPC, with platform randomness. Which key to hand
/// over is the caller's question, answered by the SPC's asset id — see
/// [`respond_checked`], the one call the Worker makes.
pub fn respond(ck: &ContentKey, spc: &Spc) -> Result<Vec<u8>> {
	let mut rng = |buf: &mut [u8]| getrandom::getrandom(buf).map_err(|e| err(format!("random: {e}")));
	build_ckc(spc, ck, &mut rng)
}

/// Parse the SPC, let `key_for` look the content key up by the SPC's asset
/// id (None = this caller may not have it), and answer.
pub fn respond_checked(creds: &Credentials, spc: &[u8], key_for: impl FnOnce(&[u8]) -> Option<ContentKey>) -> Result<Vec<u8>> {
	let parsed = parse_spc(creds, spc)?;
	let ck = key_for(&parsed.asset_id).ok_or_else(|| err("the SPC asks for a key this caller may not have"))?;
	respond(&ck, &parsed)
}

// ── the client half ────────────────────────────────────────────────────

/// A client-side SPC builder: what Safari does, minus the DRM module.
/// Public so the Worker's tests and tooling can play the player against
/// any credentials — throwaway ones made at run time, in gorani's tests.
pub mod client {
	use super::*;
	use rsa::RsaPublicKey;

	pub struct SpcOptions<'a> {
		pub asset_id: &'a [u8],
		pub with_media_playback_state: bool,
		pub with_streaming_indicator: bool,
		/// tags to list in the return-request block
		pub return_request: &'a [u64],
	}

	/// The material the client keeps to open the CKC later.
	pub struct Session {
		pub spc: Vec<u8>,
		pub sk: [u8; 16],
		pub r1: [u8; 44],
		pub anti_replay_seed: [u8; 16],
	}

	/// Build an SPC for a certificate (its public key and SHA-1), for a
	/// session derived with `ask` — the same ASK the server holds.
	pub fn build_spc<R: RngCore + CryptoRng>(rng: &mut R, public_key: &RsaPublicKey, cert_sha1: &[u8; 20], ask: &[u8; 16], opts: &SpcOptions<'_>) -> Result<Session> {
		let mut fill = |buf: &mut [u8]| -> Result<()> {
			rng.fill_bytes(buf);
			Ok(())
		};
		let mut sk = [0u8; 16];
		let mut hu = [0u8; 20];
		let mut r1 = [0u8; 44];
		let mut r2 = [0u8; 21];
		let mut seed = [0u8; 16];
		let mut integrity = [0u8; 16];
		let mut skr1_iv = [0u8; 16];
		let mut tx = [0u8; 8];
		for b in [&mut sk[..], &mut hu[..], &mut r1[..], &mut r2[..], &mut seed[..], &mut integrity[..], &mut skr1_iv[..], &mut tx[..]] {
			fill(b)?;
		}
		let dask = dask(ask, &r2)?;
		let mut inner = Vec::with_capacity(96);
		inner.extend_from_slice(&sk);
		inner.extend_from_slice(&hu);
		inner.extend_from_slice(&r1);
		inner.extend_from_slice(&integrity);
		let mut skr1 = skr1_iv.to_vec();
		skr1.extend_from_slice(&cbc_encrypt(&dask, &skr1_iv, &inner)?);

		let mut body = Vec::new();
		body.extend_from_slice(&tllv(TAG_SK_R1, &skr1, &mut fill)?);
		body.extend_from_slice(&tllv(TAG_SK_R1_INTEGRITY, &integrity, &mut fill)?);
		body.extend_from_slice(&tllv(TAG_ANTI_REPLAY_SEED, &seed, &mut fill)?);
		body.extend_from_slice(&tllv(TAG_R2, &r2, &mut fill)?);
		body.extend_from_slice(&tllv(TAG_ASSET_ID, opts.asset_id, &mut fill)?);
		body.extend_from_slice(&tllv(TAG_TRANSACTION_ID, &tx, &mut fill)?);
		body.extend_from_slice(&tllv(TAG_PROTOCOL_VERSIONS_SUPPORTED, &1u32.to_be_bytes(), &mut fill)?);
		body.extend_from_slice(&tllv(TAG_PROTOCOL_VERSION_USED, &1u32.to_be_bytes(), &mut fill)?);
		if opts.with_streaming_indicator {
			body.extend_from_slice(&tllv(TAG_STREAMING_INDICATOR, &0x891d_bf47_c0e6_66abu64.to_be_bytes(), &mut fill)?);
		}
		if opts.with_media_playback_state {
			let mut v = [0u8; 16];
			v[4..8].copy_from_slice(&0xf4de_e5a2u32.to_be_bytes()); // ReadyToStart
			body.extend_from_slice(&tllv(TAG_MEDIA_PLAYBACK_STATE, &v, &mut fill)?);
		}
		let rr: Vec<u8> = opts.return_request.iter().flat_map(|t| t.to_be_bytes()).collect();
		body.extend_from_slice(&tllv(TAG_RETURN_REQUEST, &rr, &mut fill)?);

		let mut spck = [0u8; 16];
		let mut iv = [0u8; 16];
		fill(&mut spck)?;
		fill(&mut iv)?;
		let payload = cbc_encrypt(&spck, &iv, &body)?;
		let wrapped = public_key.encrypt(rng, Oaep::new::<Sha1>(), &spck).map_err(|e| err(format!("rsa: {e}")))?;
		if wrapped.len() != 128 {
			return Err(err(format!("FairPlay expects a 1024-bit RSA key (wrapped key is {} bytes)", wrapped.len())));
		}
		let mut spc = Vec::with_capacity(SPC_HEADER_LEN + payload.len());
		spc.extend_from_slice(&1u32.to_be_bytes());
		spc.extend_from_slice(&0u32.to_be_bytes());
		spc.extend_from_slice(&iv);
		spc.extend_from_slice(&wrapped);
		spc.extend_from_slice(cert_sha1);
		spc.extend_from_slice(&(payload.len() as u32).to_be_bytes());
		spc.extend_from_slice(&payload);
		Ok(Session { spc, sk, r1, anti_replay_seed: seed })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(s: &str) -> Vec<u8> {
		(0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
	}

	#[test]
	fn d_hash_matches_published_vectors() {
		// (R2, expected) from the public reference implementation's test set
		let cases = [
			("a4c411c54d94727143504aece5613da8c6ee6dd2", "3a24a068c116842f10fac5c86cb1cb5c"),
			("ee810dd5779ce50aa8df3824b3f2594cf9ee68a9", "93c82dc4d1c4a338896bfce2e7dc12a0"),
			("a4c411c54d94727143504aece5613da8c6ee6dd26ba5d07ec0dc44c84ec4", "4b46ab65bd04af0dd721718a68663390"),
			("303838a2b4cab66f25d53bd331b5ee4c035b6e12afcd05c5a5a85a382ff4bfae230844aef7e2ae5c", "a77994aeda51df868cd82bd3b1131401"),
		];
		for (r2, want) in cases {
			assert_eq!(d_hash(&hex(r2)).unwrap().to_vec(), hex(want), "R2 {r2}");
		}
		assert!(d_hash(&[]).is_err());
		assert!(d_hash(&[0u8; 56]).is_err());
	}

	/// Throwaway credentials, made here and gone with the test: a fresh
	/// 1024-bit RSA key, DER-looking bytes for the certificate (only its
	/// hash is used), a random ASK. Nothing of Apple's is in this repository.
	fn throwaway() -> (Credentials, [u8; 16]) {
		let key = RsaPrivateKey::new(&mut SystemRandom, 1024).unwrap();
		let mut cert = vec![0x30, 0x82, 0x01, 0x00];
		cert.resize(260, 0);
		SystemRandom.fill_bytes(&mut cert[4..]);
		let mut ask = [0u8; 16];
		SystemRandom.fill_bytes(&mut ask);
		(Credentials::new(cert, key, ask), ask)
	}

	fn session(creds: &Credentials, ask: &[u8; 16], asset: &[u8], state: bool) -> client::Session {
		client::build_spc(
			&mut SystemRandom,
			&creds.public_key(),
			&creds.cert_sha1,
			ask,
			&client::SpcOptions { asset_id: asset, with_media_playback_state: state, with_streaming_indicator: true, return_request: &[TAG_ASSET_ID, TAG_TRANSACTION_ID, TAG_STREAMING_INDICATOR] },
		)
		.unwrap()
	}

	#[test]
	fn an_spc_round_trip_hands_over_the_content_key() {
		let (creds, ask) = throwaway();
		let s = session(&creds, &ask, b"skd://0011aabb", true);
		let spc = parse_spc(&creds, &s.spc).unwrap();
		assert_eq!(spc.asset_id, b"skd://0011aabb");
		assert_eq!(spc.r1(), &s.r1);
		assert_eq!(spc.session_key(), &s.sk);
		let ck = ContentKey { key: hex16("00112233445566778899aabbccddeeff").unwrap(), iv: hex16("ffeeddccbbaa99887766554433221100").unwrap(), lease_seconds: 3600, hdcp: Some(HDCP_TYPE0) };
		let ckc = respond(&ck, &spc).unwrap();
		let tl = open_ckc(&spc, &ckc).unwrap();
		let tags: Vec<u64> = tl.iter().map(|(t, _)| *t).collect();
		assert_eq!(tags, vec![TAG_ENCRYPTED_CK, TAG_R1, TAG_ASSET_ID, TAG_TRANSACTION_ID, TAG_STREAMING_INDICATOR, TAG_CONTENT_KEY_DURATION, TAG_HDCP_ENFORCEMENT], "CKC TLLV order mirrors Apple's reference output");
		let (key, iv) = unwrap_content_key(&spc, &tl).unwrap();
		assert_eq!((key, iv), (ck.key, ck.iv));
		assert_eq!(tl[1].1, s.r1.to_vec(), "R1 echoed");
		assert_eq!(tl[6].1, HDCP_TYPE0.to_be_bytes().to_vec(), "HDCP Type 0 required");
		let dur = &tl[5].1;
		assert_eq!(&dur[0..4], &3600u32.to_be_bytes());
		assert_eq!(&dur[8..12], &KEY_TYPE_LEASE.to_be_bytes());
	}

	#[test]
	fn respond_checked_asks_who_may_have_the_key() {
		let (creds, ask) = throwaway();
		let s = session(&creds, &ask, b"skd://a1", false);
		let ck = ContentKey { key: [9; 16], iv: [0; 16], lease_seconds: 0, hdcp: None };
		let mut asked = None;
		let ckc = respond_checked(&creds, &s.spc, |asset| {
			asked = Some(asset.to_vec());
			Some(ck)
		})
		.unwrap();
		assert_eq!(asked.as_deref(), Some(&b"skd://a1"[..]), "the lookup sees the asset id the SPC names");
		let spc = parse_spc(&creds, &s.spc).unwrap();
		let tl = open_ckc(&spc, &ckc).unwrap();
		assert!(tl.iter().all(|(t, _)| *t != TAG_CONTENT_KEY_DURATION && *t != TAG_HDCP_ENFORCEMENT), "no lease, no HDCP TLLV when none asked");
		assert_eq!(unwrap_content_key(&spc, &tl).unwrap().0, [9; 16]);
		let e = respond_checked(&creds, &s.spc, |_| None).unwrap_err();
		assert!(e.0.contains("may not have"), "{e}");
	}

	#[test]
	fn wrong_credentials_are_named_and_garbage_never_panics() {
		let (creds, ask) = throwaway();
		let s = session(&creds, &ask, b"a1", true);
		let mut bad_ask = ask;
		bad_ask[0] ^= 1;
		let other = Credentials::new(creds.cert_der.clone(), creds.key.clone(), bad_ask);
		assert!(parse_spc(&other, &s.spc).unwrap_err().0.contains("Application Secret Key"));
		let mut cert = creds.cert_der.clone();
		cert[10] ^= 1;
		let other = Credentials::new(cert, creds.key.clone(), ask);
		assert!(parse_spc(&other, &s.spc).unwrap_err().0.contains("different application certificate"));
		let (stranger, _) = throwaway();
		let other = Credentials::new(creds.cert_der.clone(), stranger.key.clone(), ask);
		assert!(parse_spc(&other, &s.spc).unwrap_err().0.contains("private key"));
		assert!(parse_spc(&creds, &[0u8; 10]).is_err());
		for cut in [176, 200, s.spc.len() - 1] {
			let mut trunc = s.spc.clone();
			trunc.truncate(cut);
			assert!(parse_spc(&creds, &trunc).is_err(), "cut at {cut}");
		}
		// every single-byte flip is refused or harmless — never a panic
		for i in (0..s.spc.len()).step_by(7) {
			let mut flipped = s.spc.clone();
			flipped[i] ^= 0x41;
			let _ = parse_spc(&creds, &flipped);
		}
	}

	#[test]
	fn credentials_parse_pem_and_base64_and_never_print() {
		let (creds, _) = throwaway();
		use base64::Engine;
		use rsa::pkcs1::EncodeRsaPrivateKey;
		use rsa::pkcs8::EncodePrivateKey;
		let pkcs8 = creds.key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
		let pkcs1 = creds.key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
		let der_b64 = base64::engine::general_purpose::STANDARD.encode(creds.key.to_pkcs8_der().unwrap().as_bytes());
		let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&creds.cert_der);
		let cert_pem = format!("-----BEGIN CERTIFICATE-----\n{cert_b64}\n-----END CERTIFICATE-----\n");
		let ask = "00112233445566778899aabbccddeeff";
		for k in [pkcs8.as_str(), pkcs1.as_str(), der_b64.as_str()] {
			for c in [cert_b64.as_str(), cert_pem.as_str()] {
				assert_eq!(Credentials::parse(c, k, ask).unwrap().cert_sha1, creds.cert_sha1);
			}
		}
		assert!(Credentials::parse(&cert_b64, &pkcs8, "zz").is_err());
		assert!(Credentials::parse("not-der", &pkcs8, ask).is_err());
		let shown = format!("{:?}", Credentials::parse(&cert_b64, &pkcs8, ask).unwrap());
		assert!(!shown.contains("0011223344") && !shown.to_lowercase().contains("key:"), "{shown}");
	}
}
