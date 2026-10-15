// Copyright 2026- Seongwoo Hong. All rights reserved.

//! GV04 — placed, store-authenticated sealing (commit 25,
//! docs/SECURITY-REVIEW.md › O6). Everything a files store keeps sealed —
//! file names, each version's content key, type and signed content hash,
//! music tags, folder names, share names, the store's secrets — is GV04.
//! The TypeScript twin
//! is `web/src/vault/vault-crypto.ts › sealPlaced` + `places.ts`.
//!
//! # The two attacks it closes
//!
//! GV03 seals to a PUBLIC key. Two consequences in a store the server keeps:
//!
//! 1. **Moving.** A sealed value says nothing about where it belongs. The
//!    server can swap two files' content keys (with their objects), or two
//!    files' names: "invoice.pdf" now opens a malware sample's bytes, and
//!    evidence item A is presented as item B. Every value still opens.
//! 2. **Minting.** Sealing needs only the public key, which the server
//!    holds. It can make up a content key, encrypt bytes of its choosing,
//!    seal the key and a name to the store — and a file appears in your
//!    store that no member ever uploaded.
//!
//! # The construction
//!
//! ```text
//! place     = lp("gorani-place-v1") ‖ lp(kind) ‖ lp(store) ‖ lp(item) ‖ lp(version)
//!             lp(x) = u32 BE length ‖ UTF-8 bytes;  version = decimal, or "" for none
//! store_psk = HKDF-SHA256(ikm  = ECDH(store private, store public) ‖ SHA-256(ML-KEM dk),
//!                         salt = "gorani-store-psk", info = "gorani-store-psk-v1")
//! GV04      = "GV04" ‖ ephemeral P-256 public (65) ‖ ML-KEM-768 ct (1088) ‖ nonce (12) ‖ ct ‖ tag
//!   ss_ec   = ECDH(ephemeral, store P-256 public);  ss_kem = ML-KEM-768 encapsulation to the store
//!   salt    = SHA-256(eph public ‖ ML-KEM ct ‖ store P-256 public ‖ store ML-KEM public)  (as GV03)
//!   key     = HKDF-SHA256(ikm = ss_ec ‖ ss_kem ‖ store_psk, salt, info = "gorani-vault-v4")
//!   AAD     = header ‖ place
//! ```
//!
//! - The **place** in the AAD answers moving: a value opens only where it
//!   was sealed. It is not stored — the opener rebuilds it from what it is
//!   opening (`file.key` of file F, version 3), so a value moved anywhere
//!   else fails authentication.
//! - The **store PSK** in the key schedule answers minting. It is a secret
//!   only the store's PRIVATE key computes (the same self-ECDH construction
//!   as the record key, records.rs), so sealing to a store now needs what
//!   opening needs. This is HPKE's PSK mode (RFC 9180 §5.1) in our own
//!   framing: the recipient learns "a holder of this PSK sealed it".
//!
//! # The honest limits
//!
//! - **Who** sealed it stays unknown: every holder of the store key holds
//!   the PSK. Per-member signatures over each upload are D5 (custody).
//! - **Freshness** is not covered: the server can still answer with an
//!   older version of a row (a rename undone, version 3 hidden so version 2
//!   looks current). Version 2 will say it is version 2 — consistently.
//! - A departed member keeps the OLD store key, so until the rotation walk
//!   (rotation.ts) they could mint values sealed to the old key — which the
//!   new key refuses. The walk re-seals every value under the new PSK.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::MlKem768;
use p256::ecdh::EphemeralSecret;
use p256::PublicKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::formats::{self, ContentKey, VaultPrivateKey};
use crate::Error;

pub const MAGIC_V4: &[u8; 4] = b"GV04";
const INFO_V4: &[u8] = b"gorani-vault-v4";
const PLACE_DOMAIN: &str = "gorani-place-v1";
const HEADER_LEN: usize = 4 + formats::EPH_LEN + formats::KEM_CT_LEN + formats::NONCE_LEN;

/// Where a sealed value lives. Built by the code that seals or opens it,
/// never read off the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place(Vec<u8>);

impl Place {
	/// The general form; the named constructors below are the vocabulary.
	pub fn new(kind: &str, store: &str, item: &str, version: Option<i64>) -> Self {
		let v = version.map(|v| v.to_string()).unwrap_or_default();
		let mut out = Vec::new();
		for f in [PLACE_DOMAIN, kind, store, item, v.as_str()] {
			out.extend_from_slice(&(f.len() as u32).to_be_bytes());
			out.extend_from_slice(f.as_bytes());
		}
		Self(out)
	}
	pub fn file_name(store: &str, file: &str) -> Self {
		Self::new("file.name", store, file, None)
	}
	pub fn file_key(store: &str, file: &str, version: i64) -> Self {
		Self::new("file.key", store, file, Some(version))
	}
	pub fn file_type(store: &str, file: &str, version: i64) -> Self {
		Self::new("file.type", store, file, Some(version))
	}
	pub fn file_music(store: &str, file: &str, version: i64) -> Self {
		Self::new("file.music", store, file, Some(version))
	}
	/// Version n's signed content hash (commit 29d, docs/CUSTODY.md › stage 4).
	pub fn file_hash(store: &str, file: &str, version: i64) -> Self {
		Self::new("file.hash", store, file, Some(version))
	}
	/// An evidence file's signed intake record (commit 29g, stage 6).
	pub fn file_intake(store: &str, file: &str) -> Self {
		Self::new("file.intake", store, file, None)
	}
	/// Custody link n's reason (commit 29g, stage 6).
	pub fn custody_reason(store: &str, file: &str, seq: i64) -> Self {
		Self::new("custody.reason", store, file, Some(seq))
	}
	pub fn folder_name(store: &str, folder: &str) -> Self {
		Self::new("folder.name", store, folder, None)
	}
	pub fn share_name(store: &str, share: &str) -> Self {
		Self::new("share.name", store, share, None)
	}
	pub fn store_secrets(store: &str) -> Self {
		Self::new("store.secrets", store, "", None)
	}
	/// A case's title (commit 26): sealed with the case key, kept in the
	/// registry. `store` is the case's area, `case:<id>`.
	pub fn case_title(store: &str) -> Self {
		Self::new("case.title", store, "", None)
	}
	/// A case inbox's private key (commit 37b, docs/COLLECTORS.md): sealed
	/// with the case key, kept in the registry, named by the inbox key's id.
	pub fn case_inbox(store: &str, key_id: &str) -> Self {
		Self::new("case.inbox", store, key_id, None)
	}
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// The store's write secret — computable only from its private key.
pub fn store_psk(store: &VaultPrivateKey) -> Result<Zeroizing<[u8; 32]>, Error> {
	formats::self_secret(store, b"gorani-store-psk", b"gorani-store-psk-v1")
}

fn placed_key(ss_ec: &[u8], kem_ss: &[u8], psk: &[u8; 32], eph_pub: &[u8], kem_ct: &[u8], store_ec: &[u8], store_kem: &[u8]) -> Zeroizing<[u8; 32]> {
	let salt = Sha256::new().chain_update(eph_pub).chain_update(kem_ct).chain_update(store_ec).chain_update(store_kem).finalize();
	let mut ikm = Zeroizing::new(Vec::with_capacity(96));
	ikm.extend_from_slice(ss_ec);
	ikm.extend_from_slice(kem_ss);
	ikm.extend_from_slice(psk);
	formats::hkdf32(&ikm, &salt, INFO_V4)
}

/// Seal `plain` into `place` of the store whose private key this is (a
/// store seals to itself: the public half comes from the private key, never
/// from a settings row — the O3 lesson).
pub fn seal_placed(store: &VaultPrivateKey, place: &Place, plain: &[u8]) -> Result<Vec<u8>, Error> {
	let VaultPrivateKey::Hybrid { ec_public, kem_public, .. } = store else {
		return Err(Error::Format("placed sealing needs a hybrid store key"));
	};
	let psk = store_psk(store)?;
	let store_ec = PublicKey::from_sec1_bytes(ec_public).map_err(|_| Error::Format("bad store public key"))?;
	let eph = EphemeralSecret::random(&mut OsRng);
	let eph_pub = formats::raw_public(&eph.public_key());
	let shared = eph.diffie_hellman(&store_ec);
	let ek = formats::encaps_key(kem_public)?;
	let (kem_ct, kem_ss) = ek.encapsulate(&mut OsRng).map_err(|_| Error::Format("ML-KEM encapsulate"))?;
	let key = placed_key(shared.raw_secret_bytes(), kem_ss.as_slice(), &psk, &eph_pub, kem_ct.as_slice(), ec_public, kem_public);
	let nonce = formats::random::<{ formats::NONCE_LEN }>();
	let mut header = Vec::with_capacity(HEADER_LEN);
	header.extend_from_slice(MAGIC_V4);
	header.extend_from_slice(&eph_pub);
	header.extend_from_slice(kem_ct.as_slice());
	header.extend_from_slice(&nonce);
	let aad = [header.as_slice(), place.as_bytes()].concat();
	let ct = formats::encrypt(key.as_ref(), &nonce, &aad, plain);
	Ok([header, ct].concat())
}

/// Open a GV04 value found at `place`. Anything else — another format, a
/// value from another place, one minted without the store's PSK — fails.
pub fn open_placed(store: &VaultPrivateKey, place: &Place, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
	let VaultPrivateKey::Hybrid { ec, ec_public, kem, kem_public } = store else {
		return Err(Error::Format("placed values open with a hybrid store key"));
	};
	if !sealed.starts_with(MAGIC_V4) || sealed.len() < HEADER_LEN + formats::TAG_LEN {
		return Err(Error::Format("not a placed (GV04) value"));
	}
	let eph_pub = &sealed[4..4 + formats::EPH_LEN];
	let kem_ct = &sealed[4 + formats::EPH_LEN..4 + formats::EPH_LEN + formats::KEM_CT_LEN];
	let nonce = &sealed[HEADER_LEN - formats::NONCE_LEN..HEADER_LEN];
	let eph = PublicKey::from_sec1_bytes(eph_pub).map_err(|_| Error::Format("bad ephemeral key"))?;
	let shared = formats::ecdh(ec, &eph);
	let ct = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct).map_err(|_| Error::Format("bad ML-KEM ciphertext"))?;
	let kem_ss = kem.decapsulate(&ct).map_err(|_| Error::Open("ML-KEM"))?;
	let psk = store_psk(store)?;
	let key = placed_key(shared.as_ref(), kem_ss.as_slice(), &psk, eph_pub, kem_ct, ec_public, kem_public);
	let aad = [&sealed[..HEADER_LEN], place.as_bytes()].concat();
	formats::decrypt(key.as_ref(), nonce, &aad, &sealed[HEADER_LEN..], "not sealed here, or not by a holder of this store's key")
}

/// `"GV04:"` + base64 — the text form rows keep.
pub fn seal_placed_text(store: &VaultPrivateKey, place: &Place, text: &str) -> Result<String, Error> {
	Ok(format!("GV04:{}", STANDARD.encode(seal_placed(store, place, text.as_bytes())?)))
}

/// Open placed text. Unlike `formats::open_text`, nothing passes through:
/// a value that is not GV04 is refused, so a server cannot downgrade a
/// name to an older (movable, mintable) format or to plain text.
pub fn open_placed_text(store: &VaultPrivateKey, place: &Place, value: &str) -> Result<Zeroizing<String>, Error> {
	let b64 = value.strip_prefix("GV04:").ok_or(Error::Format("not a placed (GV04) value"))?;
	let bytes = STANDARD.decode(b64).map_err(|_| Error::Format("bad base64"))?;
	let plain = open_placed(store, place, &bytes)?;
	String::from_utf8(plain.to_vec()).map(Zeroizing::new).map_err(|_| Error::Format("not text"))
}

/// The one shape a files-store column accepts (the Worker's check).
pub fn is_placed_text(value: &str) -> bool {
	value.starts_with("GV04:")
}

/// A version's content key, sealed into its place (`Place::file_key`).
pub fn wrap_placed_key(store: &VaultPrivateKey, place: &Place, key: &[u8; 32]) -> Result<String, Error> {
	let b64 = Zeroizing::new(STANDARD.encode(key));
	seal_placed_text(store, place, &b64)
}

pub fn unwrap_placed_key(store: &VaultPrivateKey, place: &Place, sealed: &str) -> Result<ContentKey, Error> {
	let b64 = open_placed_text(store, place, sealed)?;
	let mut raw = Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| Error::Format("bad content key"))?);
	if raw.len() != 32 {
		return Err(Error::Format("bad content key"));
	}
	let mut key = Zeroizing::new([0u8; 32]);
	key.copy_from_slice(&raw);
	raw.zeroize();
	Ok(key)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::formats::{public_of, seal_text, VaultPublicKey};

	fn store() -> VaultPrivateKey {
		let (bundle, _) = crate::unlock::generate_hybrid().unwrap();
		VaultPrivateKey::from_bytes(&bundle).unwrap()
	}

	#[test]
	fn opens_only_in_its_place() {
		let s = store();
		let here = Place::file_name("jinu", "f1");
		let sealed = seal_placed_text(&s, &here, "contract.pdf").unwrap();
		assert_eq!(&*open_placed_text(&s, &here, &sealed).unwrap(), "contract.pdf");
		// Moved: another file, another store, another kind, another version.
		for elsewhere in [Place::file_name("jinu", "f2"), Place::file_name("mom", "f1"), Place::folder_name("jinu", "f1"), Place::file_type("jinu", "f1", 1)] {
			assert!(open_placed_text(&s, &elsewhere, &sealed).is_err());
		}
		let k = formats::new_content_key();
		let w = wrap_placed_key(&s, &Place::file_key("jinu", "f1", 1), &k).unwrap();
		assert_eq!(*unwrap_placed_key(&s, &Place::file_key("jinu", "f1", 1), &w).unwrap(), *k);
		assert!(unwrap_placed_key(&s, &Place::file_key("jinu", "f1", 2), &w).is_err(), "version 1's key is not version 2's");
	}

	#[test]
	fn the_public_key_alone_cannot_mint() {
		// The server's position: the store's public half, nothing else. The
		// best it can do is the old construction (GV03 to the public key) —
		// refused — or GV04 bytes under a key schedule without the PSK.
		let s = store();
		let here = Place::file_name("jinu", "f1");
		let VaultPublicKey::Hybrid { .. } = public_of(&s) else { panic!() };
		let gv03 = seal_text(&public_of(&s), "minted.exe");
		assert!(open_placed_text(&s, &here, &gv03).is_err());
		// A different store's PSK (a holder of ANOTHER key) cannot mint here either.
		let other = store();
		let foreign = seal_placed_text(&other, &here, "minted.exe").unwrap();
		assert!(open_placed_text(&s, &here, &foreign).is_err());
		assert!(open_placed_text(&s, &here, "minted.exe").is_err(), "plain text never passes");
	}

	#[test]
	fn place_encoding_is_unambiguous() {
		// Length prefixes: ("ab","c") and ("a","bc") are different places.
		assert_ne!(Place::new("k", "ab", "c", None), Place::new("k", "a", "bc", None));
		assert_ne!(Place::new("k", "s", "i", Some(1)), Place::new("k", "s", "i", Some(11)));
		assert_ne!(Place::new("k", "s", "i", None), Place::new("k", "s", "i", Some(0)));
	}
}
