// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The byte formats themselves (docs/ENCRYPTION.md is the prose twin of this
//! file — when they disagree, this file is right and the doc is stale).
//!
//! Layouts, all big-endian, `‖` concatenation; "AAD" is AES-GCM's additional
//! authenticated data (not encrypted, but any change to it fails the open):
//!
//! ```text
//! GV01 = "GV01" ‖ ephemeral P-256 public (65) ‖ nonce (12) ‖ ciphertext ‖ tag (16)
//!       AAD = the whole header
//!       key = HKDF-SHA256(ikm = ECDH(ephemeral private, recipient public),
//!                         salt = ephemeral public key, info = "gorani-vault-v1")
//! GV02 = "GV02" ‖ nonce (12) ‖ ciphertext ‖ tag (16)
//!       AAD = "GV02" ‖ nonce;  key = the 32-byte content key
//! GV03 = "GV03" ‖ ephemeral P-256 public (65) ‖ ML-KEM-768 ciphertext (1088) ‖ nonce (12) ‖ ciphertext ‖ tag
//!       ss_ec  = ECDH(ephemeral private, recipient P-256 public)
//!       ss_kem = ML-KEM-768 encapsulation to the recipient ML-KEM public
//!       salt   = SHA-256(ephemeral public ‖ ML-KEM ciphertext ‖ recipient P-256 public ‖ recipient ML-KEM public)
//!       key    = HKDF-SHA256(ikm = ss_ec ‖ ss_kem, salt, info = "gorani-vault-v3")
//! GK01 = "GK01" ‖ len(PKCS#8):2 ‖ P-256 private, PKCS#8 ‖ ML-KEM seed (64) ‖ P-256 public (65)
//! GW01 = "GW01" ‖ nonce (12) ‖ AES-256-GCM(KEK, key bytes) ‖ tag (16),  AAD = "GW01"
//! ```
//!
//! A fresh ephemeral key per sealed object means every object has its own
//! AES key; the nonce is belt and braces. GV03's salt binds both ciphertexts
//! and both recipient public halves into the key, so neither half can be
//! swapped or replayed against another recipient — the "X-Wing" combiner.
//! Intermediate secrets (ECDH output, ML-KEM shared secret, HKDF input) are
//! zeroized where the platform allows.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

pub const MAGIC_V1: &[u8; 4] = b"GV01";
pub const MAGIC_V2: &[u8; 4] = b"GV02";
pub const MAGIC_V3: &[u8; 4] = b"GV03";
pub const MAGIC_WRAP: &[u8; 4] = b"GW01";
pub const MAGIC_BUNDLE: &[u8; 4] = b"GK01";
const INFO_V1: &[u8] = b"gorani-vault-v1";
const INFO_V3: &[u8] = b"gorani-vault-v3";
const EPH_LEN: usize = 65;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEM_CT_LEN: usize = 1088;
const KEM_PK_LEN: usize = 1184;
const KEM_SEED_LEN: usize = 64;

type DecapsKey = ml_kem::kem::DecapsulationKey<MlKem768Params>;
type EncapsKey = ml_kem::kem::EncapsulationKey<MlKem768Params>;

/// A public key things are sealed to: P-256 alone (GV01), or hybrid with
/// ML-KEM-768 (GV03). Cloning is safe: public halves are public.
#[derive(Clone)]
pub enum VaultPublicKey {
	P256(PublicKey),
	Hybrid { ec: PublicKey, kem: Vec<u8> },
}

/// A private key that opens what was sealed to it. Its secret parts are
/// wiped when it is dropped (p256/zeroize handle the halves; the bundle
/// path below zeroes its inputs).
pub enum VaultPrivateKey {
	P256(SecretKey),
	Hybrid { ec: SecretKey, ec_public: [u8; EPH_LEN], kem: Box<DecapsKey>, kem_public: Vec<u8> },
}

impl VaultPrivateKey {
	/// The key as the browser imports it: a hybrid bundle (GK01) or a plain
	/// P-256 PKCS#8. Anything else is refused — never guess a key's shape.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
		if !bytes.starts_with(MAGIC_BUNDLE) {
			return Ok(Self::P256(SecretKey::from_pkcs8_der(bytes).map_err(|_| Error::Format("not a P-256 PKCS#8 key"))?));
		}
		if bytes.len() < 6 {
			return Err(Error::Format("not a key bundle"));
		}
		let len = ((bytes[4] as usize) << 8) | bytes[5] as usize;
		let rest = &bytes[6..];
		if rest.len() < len + KEM_SEED_LEN + EPH_LEN {
			return Err(Error::Format("not a key bundle"));
		}
		let ec = SecretKey::from_pkcs8_der(&rest[..len]).map_err(|_| Error::Format("not a key bundle"))?;
		let seed = &rest[len..len + KEM_SEED_LEN];
		let mut ec_public = [0u8; EPH_LEN];
		ec_public.copy_from_slice(&rest[len + KEM_SEED_LEN..len + KEM_SEED_LEN + EPH_LEN]);
		let (dk, ek) = kem_from_seed(seed);
		Ok(Self::Hybrid { ec, ec_public, kem: Box::new(dk), kem_public: ek.as_bytes().to_vec() })
	}

	fn ec(&self) -> &SecretKey {
		match self {
			Self::P256(k) => k,
			Self::Hybrid { ec, .. } => ec,
		}
	}

	pub fn is_hybrid(&self) -> bool {
		matches!(self, Self::Hybrid { .. })
	}
}

/// ML-KEM-768 from the 64-byte seed the bundle keeps (FIPS 203
/// KeyGen_internal: d = seed[..32], z = seed[32..]). The seed is the bundle's
/// private half — the caller's bytes are borrowed here, not zeroized, because
/// the bundle's owner wipes it.
fn kem_from_seed(seed: &[u8]) -> (DecapsKey, EncapsKey) {
	let d = ml_kem::B32::try_from(&seed[..32]).expect("32 bytes");
	let z = ml_kem::B32::try_from(&seed[32..64]).expect("32 bytes");
	MlKem768::generate_deterministic(&d, &z)
}

impl VaultPublicKey {
	/// From settings: the P-256 half as a JWK (`x`, `y` base64url) and, for a
	/// hybrid key, the ML-KEM half (base64, 1184 bytes).
	pub fn from_jwk(x: &str, y: &str, kem: Option<&str>) -> Result<Self, Error> {
		let x = URL_SAFE_NO_PAD.decode(x.trim_end_matches('=')).map_err(|_| Error::Format("bad JWK"))?;
		let y = URL_SAFE_NO_PAD.decode(y.trim_end_matches('=')).map_err(|_| Error::Format("bad JWK"))?;
		if x.len() != 32 || y.len() != 32 {
			return Err(Error::Format("bad JWK"));
		}
		let mut raw = [4u8; EPH_LEN];
		raw[1..33].copy_from_slice(&x);
		raw[33..].copy_from_slice(&y);
		let ec = PublicKey::from_sec1_bytes(&raw).map_err(|_| Error::Format("bad P-256 public key"))?;
		match kem {
			Some(k) if !k.is_empty() => {
				let kem = STANDARD.decode(k).map_err(|_| Error::Format("bad ML-KEM public key"))?;
				if kem.len() != KEM_PK_LEN {
					return Err(Error::Format("bad ML-KEM public key"));
				}
				Ok(Self::Hybrid { ec, kem })
			}
			_ => Ok(Self::P256(ec)),
		}
	}
}

fn aes(key: &[u8]) -> Aes256Gcm {
	Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

fn random<const N: usize>() -> [u8; N] {
	let mut b = [0u8; N];
	OsRng.fill_bytes(&mut b);
	b
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
	let mut out = Zeroizing::new([0u8; 32]);
	Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out.as_mut()).expect("32 bytes");
	out
}

fn ecdh(secret: &SecretKey, public: &PublicKey) -> Zeroizing<[u8; 32]> {
	let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
	let mut out = Zeroizing::new([0u8; 32]);
	out.copy_from_slice(shared.raw_secret_bytes());
	out
}

/// The raw uncompressed P-256 public key (65 bytes: `04 ‖ X ‖ Y`), the wire
/// shape every format carries. `pub(crate)`: unlock's key generation uses it.
pub(crate) fn raw_public(pk: &PublicKey) -> [u8; EPH_LEN] {
	let mut out = [0u8; EPH_LEN];
	out.copy_from_slice(pk.to_encoded_point(false).as_bytes());
	out
}

/// A 12-byte nonce from a slice (the formats always carry exactly 12).
pub(crate) fn nonce_of(b: &[u8]) -> Nonce<aes_gcm::aead::consts::U12> {
	let mut n = [0u8; NONCE_LEN];
	n.copy_from_slice(&b[..NONCE_LEN]);
	Nonce::from(n)
}

fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8], what: &'static str) -> Result<Zeroizing<Vec<u8>>, Error> {
	aes(key).decrypt(&nonce_of(nonce), Payload { msg: ct, aad }).map(Zeroizing::new).map_err(|_| Error::Open(what))
}

/// AES-256-GCM under `key`: `nonce ‖ ciphertext ‖ tag` with `aad` (the
/// building block of the formats). Encryption cannot fail with a fresh
/// nonce; the expect documents the invariant rather than inventing an error
/// type for the impossible.
fn encrypt(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], plain: &[u8]) -> Vec<u8> {
	aes(key).encrypt(&Nonce::from(*nonce), Payload { msg: plain, aad }).expect("AES-GCM encrypt")
}

// ── GV01 / GV03: sealing to a public key ──────────────────────────────────────

/// Seal bytes to a public key: GV03 when it has an ML-KEM half, GV01 otherwise.
/// Anyone with the public key can seal; only the matching private key opens —
/// so a sealed object proves nothing about who sealed it (integrity covers
/// tampering, not origin; docs/VAULT.md).
pub fn seal(public: &VaultPublicKey, plain: &[u8]) -> Vec<u8> {
	match public {
		VaultPublicKey::P256(pk) => {
			let eph = EphemeralSecret::random(&mut OsRng);
			let eph_pub = raw_public(&eph.public_key());
			let shared = eph.diffie_hellman(pk);
			let key = hkdf32(shared.raw_secret_bytes(), &eph_pub, INFO_V1);
			let nonce = random::<NONCE_LEN>();
			let mut header = Vec::with_capacity(4 + EPH_LEN + NONCE_LEN);
			header.extend_from_slice(MAGIC_V1);
			header.extend_from_slice(&eph_pub);
			header.extend_from_slice(&nonce);
			let ct = encrypt(key.as_ref(), &nonce, &header, plain);
			[header, ct].concat()
		}
		VaultPublicKey::Hybrid { ec, kem } => {
			let eph = EphemeralSecret::random(&mut OsRng);
			let eph_pub = raw_public(&eph.public_key());
			let shared = eph.diffie_hellman(ec);
			let ek = EncapsKey::from_bytes(&ml_kem::Encoded::<EncapsKey>::try_from(kem.as_slice()).expect("1184 bytes"));
			let (kem_ct, kem_ss) = ek.encapsulate(&mut OsRng).expect("ML-KEM encapsulate");
			let key = hybrid_key(shared.raw_secret_bytes(), kem_ss.as_slice(), &eph_pub, kem_ct.as_slice(), &raw_public(ec), kem);
			let nonce = random::<NONCE_LEN>();
			let mut header = Vec::with_capacity(4 + EPH_LEN + KEM_CT_LEN + NONCE_LEN);
			header.extend_from_slice(MAGIC_V3);
			header.extend_from_slice(&eph_pub);
			header.extend_from_slice(kem_ct.as_slice());
			header.extend_from_slice(&nonce);
			let ct = encrypt(key.as_ref(), &nonce, &header, plain);
			[header, ct].concat()
		}
	}
}

/// HKDF over both shared secrets, salted with a hash of both ciphertexts and
/// both recipient public halves (GV03). The salt is what makes the combiner
/// binding: an attacker cannot lift the ECDH part of one object onto the
/// KEM part of another.
fn hybrid_key(ecdh: &[u8], kem_ss: &[u8], eph_pub: &[u8], kem_ct: &[u8], recipient_ec: &[u8], recipient_kem: &[u8]) -> Zeroizing<[u8; 32]> {
	let salt = Sha256::new().chain_update(eph_pub).chain_update(kem_ct).chain_update(recipient_ec).chain_update(recipient_kem).finalize();
	let mut ikm = Zeroizing::new(Vec::with_capacity(64));
	ikm.extend_from_slice(ecdh);
	ikm.extend_from_slice(kem_ss);
	hkdf32(&ikm, &salt, INFO_V3)
}

/// Open GV01 or GV03 bytes with a private key (GV03 needs the hybrid key).
pub fn open(private: &VaultPrivateKey, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
	if sealed.starts_with(MAGIC_V3) {
		let VaultPrivateKey::Hybrid { ec, ec_public, kem, kem_public } = private else {
			return Err(Error::Open("sealed post-quantum: needs the hybrid key"));
		};
		let header_len = 4 + EPH_LEN + KEM_CT_LEN + NONCE_LEN;
		if sealed.len() < header_len + TAG_LEN {
			return Err(Error::Format("not a sealed object"));
		}
		let eph_pub = &sealed[4..4 + EPH_LEN];
		let kem_ct = &sealed[4 + EPH_LEN..4 + EPH_LEN + KEM_CT_LEN];
		let nonce = &sealed[header_len - NONCE_LEN..header_len];
		let eph = PublicKey::from_sec1_bytes(eph_pub).map_err(|_| Error::Format("bad ephemeral key"))?;
		let shared = ecdh(ec, &eph);
		let ct = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct).map_err(|_| Error::Format("bad ML-KEM ciphertext"))?;
		let kem_ss = kem.decapsulate(&ct).map_err(|_| Error::Open("ML-KEM"))?;
		let key = hybrid_key(shared.as_ref(), kem_ss.as_slice(), eph_pub, kem_ct, ec_public, kem_public);
		return decrypt(key.as_ref(), nonce, &sealed[..header_len], &sealed[header_len..], "wrong key or corrupted object");
	}
	if !sealed.starts_with(MAGIC_V1) || sealed.len() < 4 + EPH_LEN + NONCE_LEN + TAG_LEN {
		return Err(Error::Format("not a sealed object"));
	}
	let eph_pub = &sealed[4..4 + EPH_LEN];
	let header_len = 4 + EPH_LEN + NONCE_LEN;
	let eph = PublicKey::from_sec1_bytes(eph_pub).map_err(|_| Error::Format("bad ephemeral key"))?;
	let shared = ecdh(private.ec(), &eph);
	let key = hkdf32(shared.as_ref(), eph_pub, INFO_V1);
	decrypt(key.as_ref(), &sealed[4 + EPH_LEN..header_len], &sealed[..header_len], &sealed[header_len..], "wrong key or corrupted object")
}

/// A text value sealed to a public key: `"GV01:"` or `"GV03:"` + base64.
pub fn seal_text(public: &VaultPublicKey, text: &str) -> String {
	let prefix = if matches!(public, VaultPublicKey::Hybrid { .. }) { "GV03:" } else { "GV01:" };
	format!("{prefix}{}", STANDARD.encode(seal(public, text.as_bytes())))
}

/// Open a `"GV01:"` / `"GV03:"` text value; anything else is returned as it is
/// (an unsealed value — callers that require sealed input must check
/// `is_sealed_text` first and refuse; the Worker always does).
pub fn open_text(private: &VaultPrivateKey, value: &str) -> Result<Zeroizing<String>, Error> {
	let Some(b64) = value.strip_prefix("GV01:").or_else(|| value.strip_prefix("GV03:")) else {
		return Ok(Zeroizing::new(value.to_string()));
	};
	let bytes = STANDARD.decode(b64).map_err(|_| Error::Format("bad base64"))?;
	let plain = open(private, &bytes)?;
	String::from_utf8(plain.to_vec()).map(Zeroizing::new).map_err(|_| Error::Format("not text"))
}

/// The three sealed text shapes; a Worker route accepts **only** these (or
/// nothing) for names, types and other sealed columns.
pub fn is_sealed_text(value: &str) -> bool {
	value.starts_with("GV01:") || value.starts_with("GV02:") || value.starts_with("GV03:")
}

// ── GV02: content keys ───────────────────────────────────────────────────────

/// A content key: 32 random bytes, wiped when dropped. One per file version,
/// one per backup, one per sealed object family: content is fast symmetric
/// AES under it, and only this small key is sealed to a store key — so
/// rotating a store key re-wraps these, never the content itself.
pub type ContentKey = Zeroizing<[u8; 32]>;

pub fn new_content_key() -> ContentKey {
	Zeroizing::new(random::<32>())
}

/// `"GV02" ‖ nonce ‖ AES-256-GCM(content key, plain)`, the header as AAD.
pub fn seal_with(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
	let nonce = random::<NONCE_LEN>();
	let mut header = Vec::with_capacity(16);
	header.extend_from_slice(MAGIC_V2);
	header.extend_from_slice(&nonce);
	let ct = encrypt(key, &nonce, &header, plain);
	[header, ct].concat()
}

pub fn open_with(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
	if !sealed.starts_with(MAGIC_V2) || sealed.len() < 16 + TAG_LEN {
		return Err(Error::Format("not a v2 sealed object"));
	}
	decrypt(key, &sealed[4..16], &sealed[..16], &sealed[16..], "wrong content key or corrupted object")
}

pub fn seal_text_with(key: &[u8; 32], text: &str) -> String {
	format!("GV02:{}", STANDARD.encode(seal_with(key, text.as_bytes())))
}

pub fn open_text_with(key: &[u8; 32], value: &str) -> Result<Zeroizing<String>, Error> {
	let Some(b64) = value.strip_prefix("GV02:") else { return Ok(Zeroizing::new(value.to_string())) };
	let plain = open_with(key, &STANDARD.decode(b64).map_err(|_| Error::Format("bad base64"))?)?;
	String::from_utf8(plain.to_vec()).map(Zeroizing::new).map_err(|_| Error::Format("not text"))
}

/// A content key sealed to a store key, as rows keep it: `seal_text(base64(key))`.
pub fn wrap_content_key(public: &VaultPublicKey, key: &[u8; 32]) -> String {
	let b64 = Zeroizing::new(STANDARD.encode(key));
	seal_text(public, &b64)
}

pub fn unwrap_content_key(private: &VaultPrivateKey, sealed: &str) -> Result<ContentKey, Error> {
	let b64 = open_text(private, sealed)?;
	let mut raw = Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| Error::Format("bad content key"))?);
	if raw.len() != 32 {
		return Err(Error::Format("bad content key"));
	}
	let mut key = Zeroizing::new([0u8; 32]);
	key.copy_from_slice(&raw);
	raw.zeroize();
	Ok(key)
}

// ── GW01: a private key wrapped by an unlock method (or a device copy) ───────

/// `base64("GW01" ‖ nonce ‖ AES-256-GCM(kek, key bytes))`, AAD `"GW01"`.
pub fn wrap_private_key(kek: &[u8; 32], key_bytes: &[u8]) -> String {
	let nonce = random::<NONCE_LEN>();
	let ct = encrypt(kek, &nonce, MAGIC_WRAP, key_bytes);
	STANDARD.encode([MAGIC_WRAP.as_slice(), &nonce, &ct].concat())
}

pub fn unwrap_private_key(kek: &[u8; 32], wrapped: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
	let bytes = STANDARD.decode(wrapped).map_err(|_| Error::Format("bad base64"))?;
	if !bytes.starts_with(MAGIC_WRAP) || bytes.len() < 4 + NONCE_LEN + TAG_LEN {
		return Err(Error::Format("not a wrapped key"));
	}
	decrypt(kek, &bytes[4..16], MAGIC_WRAP, &bytes[16..], "wrong password or key")
}

/// A key's id as settings name it: base64 of the first 12 bytes of SHA-256 of
/// the raw public key, `+/=` removed, 16 characters; a hybrid key's is `"pq"`
/// + 14 such characters of SHA-256(P-256 raw ‖ ML-KEM public). Ids name keys
/// in rows (`vault_key_id`) so openers pick the right retired key.
pub fn key_id(public: &VaultPublicKey) -> String {
	let (digest, prefix, len) = match public {
		VaultPublicKey::P256(pk) => (Sha256::digest(raw_public(pk)), "", 16),
		VaultPublicKey::Hybrid { ec, kem } => (Sha256::new().chain_update(raw_public(ec)).chain_update(kem).finalize(), "pq", 14),
	};
	let b64: String = STANDARD.encode(&digest[..12]).chars().filter(|c| !matches!(c, '+' | '/' | '=')).take(len).collect();
	format!("{prefix}{b64}")
}

/// The public half of a private key.
pub fn public_of(private: &VaultPrivateKey) -> VaultPublicKey {
	match private {
		VaultPrivateKey::P256(k) => VaultPublicKey::P256(k.public_key()),
		VaultPrivateKey::Hybrid { ec, kem_public, .. } => VaultPublicKey::Hybrid { ec: ec.public_key(), kem: kem_public.clone() },
	}
}