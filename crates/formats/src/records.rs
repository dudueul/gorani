// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Authenticated store-key records — the Rust twin of
//! `web/src/vault/records.ts` (docs/SECURITY-REVIEW.md › O3).
//!
//! A store record (`keyId`, public halves, private half sealed to the
//! member's root) is only trusted when its MAC verifies under the member's
//! RECORD KEY, which only the root's holder can derive:
//!
//! ```text
//! shared  = ECDH(root P-256 private, root P-256 PUBLIC)   (the root with itself — 32 bytes, x)
//! kem     = SHA-256(root ML-KEM-768 decapsulation key, FIPS 203 encoding, 2400 bytes)
//! key     = HKDF-SHA256(ikm = shared ‖ kem, salt = "gorani-records", info = "gorani-records-v1") → 32 bytes
//! mac     = HMAC-SHA256(key, record_bytes)
//! record_bytes = for each of [domain, name, keyId, P-256 raw (65), ML-KEM public, privateKeySealed]:
//!                u32 BE length ‖ bytes          (domain = "gorani-store-record-v1")
//! ```
//!
//! The root's public half comes from the root BUNDLE itself (decrypted with
//! the member's secret), never from the server's copy of the settings — so
//! nothing the server supplies can steer the key. Byte equality with the
//! TypeScript implementation is proven by `tests/vectors.rs` (the `record`
//! vector, written by scripts/make-vectors.mjs).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::formats::VaultPrivateKey;
use crate::Error;

const DOMAIN: &[u8] = b"gorani-store-record-v1";

/// The fields the MAC covers — exactly what a client acts on.
pub struct StoreRecord<'a> {
	pub name: &'a str,
	pub key_id: &'a str,
	/// The P-256 public key, uncompressed (0x04 ‖ x ‖ y), 65 bytes.
	pub ec_public: &'a [u8],
	/// The ML-KEM-768 public key (1184 bytes).
	pub kem_public: &'a [u8],
	pub private_key_sealed: &'a str,
}

/// u32 BE length ‖ bytes, per field, in a fixed order (one spelling only —
/// unlike JSON, which has many for the same object).
pub fn record_bytes(r: &StoreRecord) -> Vec<u8> {
	let fields: [&[u8]; 6] = [DOMAIN, r.name.as_bytes(), r.key_id.as_bytes(), r.ec_public, r.kem_public, r.private_key_sealed.as_bytes()];
	let mut out = Vec::with_capacity(fields.iter().map(|f| 4 + f.len()).sum());
	for f in fields {
		out.extend_from_slice(&(f.len() as u32).to_be_bytes());
		out.extend_from_slice(f);
	}
	out
}

/// The member's record key, from the root alone (hybrid roots only) — the
/// shared self-secret construction (formats.rs › self_secret) under the
/// records label.
pub fn record_key(root: &VaultPrivateKey) -> Result<Zeroizing<[u8; 32]>, Error> {
	crate::formats::self_secret(root, b"gorani-records", b"gorani-records-v1").map_err(|_| Error::Format("store records are authenticated with a hybrid root"))
}

fn hmac(key: &[u8; 32]) -> Hmac<Sha256> {
	<Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length")
}

/// The record's MAC, base64 (standard alphabet, padded — as the browser's).
pub fn record_mac(key: &[u8; 32], r: &StoreRecord) -> String {
	use base64::Engine;
	let mut m = hmac(key);
	m.update(&record_bytes(r));
	base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes())
}

/// Verify in constant time (`verify_slice`). A malformed MAC is a failure.
pub fn verify_record(key: &[u8; 32], r: &StoreRecord, mac_b64: &str) -> bool {
	use base64::Engine;
	let Ok(mac) = base64::engine::general_purpose::STANDARD.decode(mac_b64) else { return false };
	let mut m = hmac(key);
	m.update(&record_bytes(r));
	m.verify_slice(&mac).is_ok()
}
