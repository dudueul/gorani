// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! Unlocking the vault's root key, and making the keys to unlock.
//!
//! Every member's vault has one **root key pair** (P-256, or hybrid
//! P-256 + ML-KEM-768 once post-quantum — Gorani starts hybrid from day
//! one). The private half never reaches the server unwrapped: each *unlock
//! method* holds its own GW01-wrapped copy, under a key-encryption key (KEK)
//! derived from a secret the server never sees. This module is each
//! method's KEK, exactly as the browser derives it (docs/ENCRYPTION.md):
//!
//! | Method   | KEK                                                                                   |
//! |----------|---------------------------------------------------------------------------------------|
//! | password | Argon2id(NFKC(password), salt, m, t, p) → 32 bytes — the only password KDF gorani has  |
//! | recovery | HKDF-SHA256(normalised code, salt, "gorani-recovery-v1")                              |
//! | passkey  | HKDF-SHA256(WebAuthn PRF output, salt, "gorani-passkey-v1")                           |
//! | device   | HKDF-SHA256(the device's 32-byte secret, salt, "gorani-device-v1")                    |
//!
//! Gorani has no PBKDF2 legacy path (Mailflare kept one for methods made
//! before 2026-10-06): a fresh product has no old methods, so the weakest
//! derivation it can be talked into is Argon2id — and the parameters are
//! **bounded** below and above, so a tampered settings object can neither
//! weaken a password check (m < 19 MiB) nor exhaust the opener (1 GiB).
//!
//! Also here: key generation (the native clients create vaults and rotate
//! keys; the browser does it with its own code and the vectors prove the two
//! agree), and device copies (docs/DESKTOP.md): a computer's own wrapped copy
//! of the root, under a KEK only that computer can produce.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::formats::{self, VaultPrivateKey, VaultPublicKey};
use crate::Error;

/// One unlock method as settings keep it (the browser owns this shape; the
/// clients read it to open the root without a browser).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockMethod {
	pub id: String,
	pub kind: String,
	#[serde(default)]
	pub label: Option<String>,
	pub wrapped: String,
	pub salt: String,
	#[serde(default)]
	pub argon2: Option<Argon2Cost>,
	#[serde(default)]
	pub credential_id: Option<String>,
	#[serde(default)]
	pub prf_salt: Option<String>,
	#[serde(default)]
	pub created_at: Option<String>,
}

/// Argon2id cost: memory in KiB, passes, lanes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Argon2Cost {
	pub m: u32,
	pub t: u32,
	pub p: u32,
}

/// The cost new passwords get: RFC 9106's second recommended setting
/// (64 MiB, 3 passes, 4 lanes). Each guess needs 64 MiB for its whole run —
/// the part that keeps GPUs and custom chips from shining. About a quarter
/// of a second on a laptop, around a second on a phone.
pub const ARGON2ID_PARAMS: Argon2Cost = Argon2Cost { m: 64 * 1024, t: 3, p: 4 };

fn hkdf_kek(secret: &[u8], salt: &[u8], info: &str) -> Zeroizing<[u8; 32]> {
	let mut out = Zeroizing::new([0u8; 32]);
	Hkdf::<Sha256>::new(Some(salt), secret).expand(info.as_bytes(), out.as_mut()).expect("32 bytes");
	out
}

/// The password KEK: Argon2id, and *only* Argon2id — with the method's cost
/// bounded (never weaker than RFC 9106's minimum, never an absurd
/// allocation). A gorani settings object asking for anything else is not a
/// gorani settings object.
pub fn password_kek(password: &str, salt: &[u8], method: &UnlockMethod) -> Result<Zeroizing<[u8; 32]>, Error> {
	let Some(a) = method.argon2 else { return Err(Error::Kdf("password method lacks Argon2id parameters")) };
	if !(19 * 1024..=1024 * 1024).contains(&a.m) || !(1..=20).contains(&a.t) || !(1..=16).contains(&a.p) {
		return Err(Error::Kdf("unsupported password parameters"));
	}
	let pw = Zeroizing::new(password.nfkc().collect::<String>());
	let mut out = Zeroizing::new([0u8; 32]);
	let params = Params::new(a.m, a.t, a.p, Some(32)).map_err(|_| Error::Kdf("unsupported password parameters"))?;
	Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
		.hash_password_into(pw.as_bytes(), salt, out.as_mut())
		.map_err(|_| Error::Kdf("Argon2id"))?;
	Ok(out)
}

/// A recovery code as typed (any case, with or without dashes), the way the
/// browser reads it: only A–Z and digits survive, and the visually ambiguous
/// letters fold onto digits (the code's alphabet omits 0, O, 1, I, L and U).
pub fn normalize_recovery_code(code: &str) -> String {
	code.to_uppercase()
		.chars()
		.filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
		.map(|c| match c {
			'O' => '0',
			'I' | 'L' => '1',
			c => c,
		})
		.collect()
}

pub fn recovery_kek(code: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
	let normal = Zeroizing::new(normalize_recovery_code(code));
	hkdf_kek(normal.as_bytes(), salt, "gorani-recovery-v1")
}

pub fn passkey_kek(prf_output: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
	hkdf_kek(prf_output, salt, "gorani-passkey-v1")
}

/// The device copy's KEK: from the secret only this computer can produce
/// (a TPM key behind Windows Hello, a Secure Enclave agreement, a keyring +
/// TPM pair on Linux — docs/DESKTOP.md, per platform).
pub fn device_kek(device_secret: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
	hkdf_kek(device_secret, salt, "gorani-device-v1")
}

/// The secret a method needs: what the person typed, or what an
/// authenticator produced.
pub enum Secret<'a> {
	Password(&'a str),
	RecoveryCode(&'a str),
	PasskeyPrf(&'a [u8]),
}

/// Open the root private key's bytes (GK01 bundle or PKCS#8) with one method.
pub fn unlock_with_method(method: &UnlockMethod, secret: &Secret) -> Result<Zeroizing<Vec<u8>>, Error> {
	let salt = STANDARD.decode(&method.salt).map_err(|_| Error::Format("bad salt"))?;
	let kek = match (method.kind.as_str(), secret) {
		("password", Secret::Password(p)) => password_kek(p, &salt, method)?,
		("recovery", Secret::RecoveryCode(c)) => recovery_kek(c, &salt),
		("passkey", Secret::PasskeyPrf(o)) => passkey_kek(o, &salt),
		_ => return Err(Error::Open("this method needs another kind of secret")),
	};
	formats::unwrap_private_key(&kek, &method.wrapped)
}

/// Try every method of the matching kind (a vault can have several
/// passwords, several passkeys) until one opens.
pub fn unlock(methods: &[UnlockMethod], secret: &Secret) -> Result<(Zeroizing<Vec<u8>>, String), Error> {
	let kind = match secret {
		Secret::Password(_) => "password",
		Secret::RecoveryCode(_) => "recovery",
		Secret::PasskeyPrf(_) => "passkey",
	};
	let mut last = Error::Open("no unlock method of this kind");
	for m in methods.iter().filter(|m| m.kind == kind) {
		match unlock_with_method(m, secret) {
			Ok(k) => return Ok((k, m.id.clone())),
			Err(e) => last = e,
		}
	}
	Err(last)
}

// ── Key generation (clients rotate and create; the browser does its own) ────

/// A fresh P-256 key pair: the private half as PKCS#8 (wrap it, never store
/// it bare) and its public half.
pub fn generate_p256() -> Result<(Zeroizing<Vec<u8>>, VaultPublicKey), Error> {
	let secret = SecretKey::random(&mut OsRng);
	let pkcs8 = secret.to_pkcs8_der().map_err(|_| Error::Format("PKCS#8"))?;
	let public = VaultPublicKey::P256(secret.public_key());
	Ok((Zeroizing::new(pkcs8.as_bytes().to_vec()), public))
}

/// A fresh hybrid key pair: the private bundle (GK01: PKCS#8 ‖ ML-KEM seed ‖
/// P-256 public) and its public half. The ML-KEM secret key is *regenerated
/// from the seed* wherever the bundle is imported (FIPS 203 KeyGen_internal),
/// so the bundle is short and the seed is the only thing to keep.
pub fn generate_hybrid() -> Result<(Zeroizing<Vec<u8>>, VaultPublicKey), Error> {
	let secret = SecretKey::random(&mut OsRng);
	let pkcs8 = secret.to_pkcs8_der().map_err(|_| Error::Format("PKCS#8"))?;
	let ec_public = formats::raw_public(&secret.public_key());
	let mut seed = Zeroizing::new([0u8; 64]);
	RngCore::fill_bytes(&mut OsRng, seed.as_mut());
	let (_, ek) = {
		let d = ml_kem::B32::try_from(&seed[..32]).expect("32 bytes");
		let z = ml_kem::B32::try_from(&seed[32..64]).expect("32 bytes");
		MlKem768::generate_deterministic(&d, &z)
	};
	let kem_public = ek.as_bytes().to_vec();
	let pkcs8_len = pkcs8.as_bytes().len();
	let mut bundle = Vec::with_capacity(4 + 2 + pkcs8_len + 64 + 65);
	bundle.extend_from_slice(formats::MAGIC_BUNDLE);
	bundle.extend_from_slice(&[(pkcs8_len >> 8) as u8, (pkcs8_len & 0xff) as u8]);
	bundle.extend_from_slice(pkcs8.as_bytes());
	bundle.extend_from_slice(&seed[..]);
	bundle.extend_from_slice(&ec_public);
	Ok((Zeroizing::new(bundle), VaultPublicKey::Hybrid { ec: secret.public_key(), kem: kem_public }))
}

/// A private key from generated bundle bytes (round-trip helper for tests
/// and clients).
pub fn key_from_bytes(bytes: &[u8]) -> Result<VaultPrivateKey, Error> {
	VaultPrivateKey::from_bytes(bytes)
}

// ── Device copies ───────────────────────────────────────────────────────────

/// A device copy of the root key: its wrapped bytes and salt, to enrol (the
/// server keeps them and hands them back only to that device's token).
pub struct DeviceCopy {
	pub wrapped: String,
	pub salt: String,
}

pub fn make_device_copy(root_bytes: &[u8], device_secret: &[u8]) -> DeviceCopy {
	let mut salt = [0u8; 16];
	RngCore::fill_bytes(&mut OsRng, &mut salt);
	let kek = device_kek(device_secret, &salt);
	DeviceCopy { wrapped: formats::wrap_private_key(&kek, root_bytes), salt: STANDARD.encode(salt) }
}

pub fn open_device_copy(wrapped: &str, salt_b64: &str, device_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
	let salt = STANDARD.decode(salt_b64).map_err(|_| Error::Format("bad salt"))?;
	formats::unwrap_private_key(&device_kek(device_secret, &salt), wrapped)
}

/// The digest used for key ids, exposed for tests (TS and Rust must agree).
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
	let mut h = Sha256::new();
	for p in parts {
		h.update(p);
	}
	h.finalize().into()
}

/// Wipe a mutable secret in place (callers that hold raw key material they
/// did not get wrapped in `Zeroizing`).
pub fn wipe(bytes: &mut [u8]) {
	bytes.zeroize();
}