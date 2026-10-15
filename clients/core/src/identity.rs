// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Member identity keys and trust, natively (commit 33c) — the twin of
//! `web/src/vault/identity.ts` (docs/CASES.md › Member identity keys). The
//! browser's module is the specification; this one must agree with it byte
//! for byte, because a grant the browser signed is verified here and a
//! content hash signed here is verified there (api:client-cases proves both
//! directions over the wire).
//!
//! Three ideas, as in the browser:
//!
//! 1. **An identity key per member** — ECDSA P-256 / SHA-256, its private
//!    half sealed to the member's root, its public half in the registry.
//!    Signatures are IEEE P1363 (`r ‖ s`, 64 bytes, base64) — WebCrypto's
//!    encoding, not DER.
//! 2. **Trust is the member's own decision.** The identity record in their
//!    vault settings lists the identities they PINNED (compared in person),
//!    under a MAC from their root that the server cannot forge. A
//!    certificate from a pinned identity extends trust ONE hop.
//! 3. **Statements, not objects, are signed** — length-prefixed fields
//!    under a domain string (`stmt`), so no signature can be replayed as
//!    another kind of statement.
//!
//! What the CLI does NOT do: create an identity, pin, or certify. Those
//! write the member's settings, and the CLI never writes settings (the
//! same rule `Session::files_store` follows) — the web app does them once,
//! after fingerprints are compared in person.

use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::Jwk;
use crate::transfer::hex;
use crate::Error;
use gorani_formats::formats::{self, VaultPrivateKey};

// ── statements ────────────────────────────────────────────────────────

/// `lp(domain) ‖ lp(field)…`, `lp(x)` = u32 BE length ‖ bytes — one spelling
/// per statement (identity.ts › stmt).
pub fn stmt(domain: &str, fields: &[&[u8]]) -> Vec<u8> {
	let mut out = Vec::with_capacity(4 + domain.len() + fields.iter().map(|f| 4 + f.len()).sum::<usize>());
	for part in std::iter::once(domain.as_bytes()).chain(fields.iter().copied()) {
		out.extend_from_slice(&(part.len() as u32).to_be_bytes());
		out.extend_from_slice(part);
	}
	out
}

/// The statements this client signs or verifies (identity.ts › statements).
pub mod statements {
	use super::stmt;

	pub fn identity(member: &str, key_id: &str, root_digest: &str) -> Vec<u8> {
		stmt("gorani-identity-v1", &[member.as_bytes(), key_id.as_bytes(), root_digest.as_bytes()])
	}
	pub fn cert(member: &str, key_id: &str, root_digest: &str) -> Vec<u8> {
		stmt("gorani-cert-v1", &[member.as_bytes(), key_id.as_bytes(), root_digest.as_bytes()])
	}
	pub fn grant(case_id: &str, case_key_digest: &str, grantee: &str) -> Vec<u8> {
		stmt("gorani-grant-v1", &[case_id.as_bytes(), case_key_digest.as_bytes(), grantee.as_bytes()])
	}
	/// Numbers are their decimal text, as the browser's `String(n)`.
	pub fn content_hash(area: &str, file: &str, version: u64, sha256: &str, size: u64) -> Vec<u8> {
		stmt("gorani-content-hash-v1", &[area.as_bytes(), file.as_bytes(), version.to_string().as_bytes(), sha256.as_bytes(), size.to_string().as_bytes()])
	}
	#[allow(clippy::too_many_arguments)]
	pub fn intake(area: &str, file: &str, source: &str, collector: &str, method: &str, collected_at: &str, notes: &str) -> Vec<u8> {
		stmt("gorani-intake-v1", &[area.as_bytes(), file.as_bytes(), source.as_bytes(), collector.as_bytes(), method.as_bytes(), collected_at.as_bytes(), notes.as_bytes()])
	}
}

// ── ids and digests ───────────────────────────────────────────────────

fn sha256_hex(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

/// The uncompressed point (`04 ‖ x ‖ y`) of a P-256 JWK — records.ts ›
/// ecRawOfJwk. Base64url, with or without padding; anything but two
/// 32-byte coordinates is refused.
pub fn ec_raw_of_jwk(jwk: &Jwk) -> Result<[u8; 65], Error> {
	let b64u = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| Error::Format("not a P-256 public key"));
	let (x, y) = (b64u(&jwk.x)?, b64u(&jwk.y)?);
	if x.len() != 32 || y.len() != 32 || jwk.kty.as_deref().is_some_and(|k| k != "EC") || jwk.crv.as_deref().is_some_and(|c| c != "P-256") {
		return Err(Error::Format("not a P-256 public key"));
	}
	let mut out = [4u8; 65];
	out[1..33].copy_from_slice(&x);
	out[33..].copy_from_slice(&y);
	Ok(out)
}

/// An identity key's id: SHA-256 over its domain and point, hex.
pub fn identity_key_id(public_key: &Jwk) -> Result<String, Error> {
	Ok(sha256_hex(&stmt("gorani-identity-key-v1", &[&ec_raw_of_jwk(public_key)?])))
}

/// A hybrid key's FULL digest (a root's, a case key's) from its public
/// halves. The short `keyId`s elsewhere are labels; this is what is signed.
pub fn hybrid_digest(ec_raw: &[u8], kem_public: &[u8]) -> String {
	sha256_hex(&stmt("gorani-hybrid-key-v1", &[ec_raw, kem_public]))
}

/// The same digest from an opened private key — its public halves derived
/// from the secret, not read from the bundle beside it.
pub fn hybrid_digest_of(key: &VaultPrivateKey) -> Result<String, Error> {
	match formats::public_of(key) {
		formats::VaultPublicKey::Hybrid { ec, kem } => Ok(hybrid_digest(&formats::raw_public_bytes(&ec), &kem)),
		_ => Err(Error::Open("hybrid keys only")),
	}
}

/// What people compare: 128 bits of the id, eight groups of four.
pub fn fingerprint(key_id: &str) -> String {
	key_id.chars().take(32).collect::<Vec<_>>().chunks(4).map(|c| c.iter().collect::<String>().to_uppercase()).collect::<Vec<_>>().join(" ")
}

pub(crate) fn verifying_key(public_key: &Jwk) -> Result<VerifyingKey, Error> {
	// from_sec1_bytes checks the point is on the curve — a JWK that is not
	// a real P-256 key never becomes a verifier.
	VerifyingKey::from_sec1_bytes(&ec_raw_of_jwk(public_key)?).map_err(|_| Error::Format("not a P-256 public key"))
}

pub(crate) fn verify_with(key: &VerifyingKey, statement: &[u8], signature_b64: &str) -> bool {
	let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(signature_b64) else { return false };
	// P1363 only (64 bytes): WebCrypto's encoding. A DER signature is refused
	// here exactly as the browser refuses it.
	let Ok(sig) = Signature::from_slice(&bytes) else { return false };
	key.verify(statement, &sig).is_ok()
}

// ── the member's own identity ─────────────────────────────────────────

/// A pin: an identity the member verified themselves.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pin {
	pub member: String,
	pub key_id: String,
}

/// The identity record in the member's vault settings (MAC'd by the root).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRecord {
	pub key_id: String,
	pub public_key: Jwk,
	pub private_key_sealed: String,
	#[serde(default)]
	pub pins: Vec<Pin>,
	#[serde(default)]
	pub mac: Option<String>,
}

/// The bytes the record's MAC covers (identity.ts › identityRecordBytes).
/// Pins are sorted, so one set has one spelling — by `member \0 keyId`,
/// which in UTF-8 byte order is the browser's UTF-16 order for every id the
/// registry admits (ASCII: `[a-z0-9-]` members, hex key ids).
fn identity_record_bytes(member: &str, rec: &IdentityRecord) -> Result<Vec<u8>, Error> {
	let ec = ec_raw_of_jwk(&rec.public_key)?;
	let mut pins: Vec<&Pin> = rec.pins.iter().collect();
	pins.sort_by(|a, b| format!("{}\0{}", a.member, a.key_id).cmp(&format!("{}\0{}", b.member, b.key_id)));
	let mut fields: Vec<&[u8]> = vec![member.as_bytes(), rec.key_id.as_bytes(), &ec, rec.private_key_sealed.as_bytes()];
	for p in &pins {
		fields.push(p.member.as_bytes());
		fields.push(p.key_id.as_bytes());
	}
	Ok(stmt("gorani-identity-record-v1", &fields))
}

/// The record's MAC verifies under this root's record key (the same key
/// the store records use — gorani_formats::records — under another domain).
fn verify_identity_mac(root: &VaultPrivateKey, member: &str, rec: &IdentityRecord) -> Result<(), Error> {
	let refused = Error::Open("the identity record does not verify under your root — refusing it");
	let Some(mac) = rec.mac.as_deref() else { return Err(refused) };
	let Ok(mac) = base64::engine::general_purpose::STANDARD.decode(mac) else { return Err(refused) };
	let key = gorani_formats::records::record_key(root).map_err(|_| Error::Open("record key"))?;
	let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key[..]).expect("HMAC takes any key length");
	m.update(&identity_record_bytes(member, rec)?);
	// verify_slice compares in constant time.
	m.verify_slice(&mac).map_err(|_| refused)
}

/// Who signs: the member and their identity key (in memory for the
/// command's lifetime; p256 wipes the scalar on drop).
pub struct Signer {
	pub member: String,
	pub key_id: String,
	key: SigningKey,
}

impl Signer {
	/// ECDSA P-256 / SHA-256, P1363, base64 — what WebCrypto's verify takes.
	pub fn sign(&self, statement: &[u8]) -> String {
		let sig: Signature = self.key.sign(statement);
		base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
	}
}

/// Open the member's identity from their settings: the MAC first, then the
/// key id, then the private key — which must be the record's public key.
pub fn open_identity(member: &str, root: &VaultPrivateKey, rec: &IdentityRecord) -> Result<Signer, Error> {
	verify_identity_mac(root, member, rec)?;
	if identity_key_id(&rec.public_key)? != rec.key_id {
		return Err(Error::Open("the identity record's key id does not match its key"));
	}
	let b64 = formats::open_text(root, &rec.private_key_sealed).map_err(|_| Error::Open("the identity key does not open under your root"))?;
	let pkcs8 = crate::decode(&b64)?;
	let key = SigningKey::from_pkcs8_der(&pkcs8).map_err(|_| Error::Format("the identity key is not a P-256 PKCS#8 key"))?;
	// (The browser trusts the MAC for this; checking costs one comparison.)
	let point = key.verifying_key().to_encoded_point(false);
	if point.as_bytes() != ec_raw_of_jwk(&rec.public_key)?.as_slice() {
		return Err(Error::Open("the identity record's private key is not its public key's"));
	}
	Ok(Signer { member: member.into(), key_id: rec.key_id.clone(), key })
}

// ── trust ─────────────────────────────────────────────────────────────

/// What the registry holds for each member (`GET /api/v1/family/identities`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryIdentity {
	pub member: String,
	pub key_id: String,
	pub public_key: Jwk,
	pub root_digest: String,
	pub signature: String,
	/// False once the member left: past signatures verify, new ones are not taken.
	#[serde(default)]
	pub active: Option<bool>,
	#[serde(default)]
	pub certs: Vec<Cert>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cert {
	pub by: String,
	pub key_id: String,
	pub root_digest: String,
	pub signature: String,
}

/// A member whose identity this client trusts, and why.
pub struct Trusted {
	pub member: String,
	pub key_id: String,
	pub root_digest: String,
	/// `pin`, or `cert:<certifier>`.
	pub via: String,
	pub active: bool,
	key: VerifyingKey,
}

impl Trusted {
	pub fn verify(&self, statement: &[u8], signature_b64: &str) -> bool {
		verify_with(&self.key, statement, signature_b64)
	}
}

pub struct Trust {
	pub me: String,
	trusted: std::collections::BTreeMap<String, Trusted>,
}

impl Trust {
	/// The trusted identity of `member`, or None.
	pub fn of(&self, member: &str) -> Option<&Trusted> {
		self.trusted.get(member)
	}
}

/// Decide, from the registry's identities and the member's OWN pins, whom
/// to trust (identity.ts › buildTrust). An entry counts only if its key id
/// matches its key, its self-signature verifies, and it is pinned — or
/// certified by a PINNED identity whose own entry passed the same checks.
/// One hop: a certificate from a certified (not pinned) member counts for
/// nothing.
pub fn build_trust(member: &str, root: &VaultPrivateKey, rec: &IdentityRecord, registry: &[RegistryIdentity]) -> Result<Trust, Error> {
	verify_identity_mac(root, member, rec)?;
	Ok(trust_rules(member, &rec.pins, registry))
}

/// The rules themselves, once the pins are known to be the member's own —
/// or a collector's (collector.rs: its pins are MAC'd by its device secret).
pub fn trust_rules(member: &str, pins: &[Pin], registry: &[RegistryIdentity]) -> Trust {
	let pinned: std::collections::BTreeMap<&str, &str> = pins.iter().map(|p| (p.member.as_str(), p.key_id.as_str())).collect();
	let mut sound: std::collections::BTreeMap<String, (&RegistryIdentity, VerifyingKey)> = std::collections::BTreeMap::new();
	for e in registry {
		let Ok(id) = identity_key_id(&e.public_key) else { continue };
		if id != e.key_id {
			continue;
		}
		let Ok(key) = verifying_key(&e.public_key) else { continue };
		if !verify_with(&key, &statements::identity(&e.member, &e.key_id, &e.root_digest), &e.signature) {
			continue;
		}
		sound.insert(e.member.clone(), (e, key));
	}
	let make = |e: &RegistryIdentity, key: VerifyingKey, via: String| Trusted { member: e.member.clone(), key_id: e.key_id.clone(), root_digest: e.root_digest.clone(), via, active: e.active != Some(false), key };
	let mut trusted = std::collections::BTreeMap::new();
	for (m, (e, key)) in &sound {
		if pinned.get(m.as_str()) == Some(&e.key_id.as_str()) {
			trusted.insert(m.clone(), make(e, *key, "pin".into()));
		}
	}
	// One hop: a certificate counts only from a PINNED certifier.
	for (m, (e, key)) in &sound {
		if trusted.contains_key(m) {
			continue;
		}
		for c in &e.certs {
			let Some(by) = trusted.get(&c.by) else { continue };
			if by.via != "pin" || c.key_id != e.key_id || c.root_digest != e.root_digest {
				continue;
			}
			if by.verify(&statements::cert(m, &e.key_id, &e.root_digest), &c.signature) {
				let via = format!("cert:{}", c.by);
				trusted.insert(m.clone(), make(e, *key, via));
				break;
			}
		}
	}
	Trust { me: member.into(), trusted }
}

/// SHA-256 of a signature's bytes, hex — the RFC 3161 imprint an upload
/// sends (timestamp.ts › stampImprint): the TSA sees a random-looking
/// value, never the evidence's fingerprint.
pub fn stamp_imprint(signature_b64: &str) -> Result<String, Error> {
	let bytes = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(signature_b64).map_err(|_| Error::Format("bad signature base64"))?);
	Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_core::OsRng;

	fn jwk_of(key: &SigningKey) -> Jwk {
		let p = key.verifying_key().to_encoded_point(false);
		let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
		Jwk { x: b64u(p.x().unwrap()), y: b64u(p.y().unwrap()), kty: Some("EC".into()), crv: Some("P-256".into()) }
	}

	fn signer(member: &str) -> Signer {
		let key = SigningKey::random(&mut OsRng);
		Signer { member: member.into(), key_id: identity_key_id(&jwk_of(&key)).unwrap(), key }
	}

	fn entry(s: &Signer, certs: Vec<Cert>) -> RegistryIdentity {
		let root_digest = format!("{:0>64}", s.member.len());
		RegistryIdentity { member: s.member.clone(), key_id: s.key_id.clone(), public_key: jwk_of(&s.key), signature: s.sign(&statements::identity(&s.member, &s.key_id, &root_digest)), root_digest, active: None, certs }
	}

	fn cert(by: &Signer, of: &RegistryIdentity) -> Cert {
		Cert { by: by.member.clone(), key_id: of.key_id.clone(), root_digest: of.root_digest.clone(), signature: by.sign(&statements::cert(&of.member, &of.key_id, &of.root_digest)) }
	}

	#[test]
	fn statements_are_length_prefixed_as_the_browser_spells_them() {
		// u32 BE length ‖ bytes, domain first: 15 "gorani-grant-v1", 4 "ir-7", 2 "ab", 2 "bo".
		// (The browser's side of this agreement is proven live: api:client-cases
		// verifies here a grant the browser signed, and there a hash signed here.)
		assert_eq!(hex(&statements::grant("ir-7", "ab", "bo")), "0000000f676f72616e692d6772616e742d7631" .to_owned() + "0000000469722d37" + "000000026162" + "00000002626f");
		assert_ne!(statements::grant("ab", "c", "d"), statements::grant("a", "bc", "d"), "fields cannot slide");
		assert_eq!(fingerprint("3f2a9c1b0000111122223333444455556666"), "3F2A 9C1B 0000 1111 2222 3333 4444 5555");
	}

	#[test]
	fn signatures_are_p1363_and_bound_to_their_statement() {
		let s = signer("bo");
		let e = entry(&s, vec![]);
		let key = verifying_key(&e.public_key).unwrap();
		let sig = s.sign(b"one statement");
		assert_eq!(base64::engine::general_purpose::STANDARD.decode(&sig).unwrap().len(), 64, "r ‖ s, as WebCrypto");
		assert!(verify_with(&key, b"one statement", &sig));
		assert!(!verify_with(&key, b"another statement", &sig));
		let der = base64::engine::general_purpose::STANDARD.encode(Signature::from_slice(&base64::engine::general_purpose::STANDARD.decode(&sig).unwrap()).unwrap().to_der().as_bytes());
		assert!(!verify_with(&key, b"one statement", &der), "DER is not what the browser signs — refused");
	}

	/// The trust rules (build_trust after its MAC check).
	fn trust_from(me: &str, pins: &[(&str, &str)], registry: &[RegistryIdentity]) -> Trust {
		trust_rules(me, &pins.iter().map(|(m, k)| Pin { member: (*m).into(), key_id: (*k).into() }).collect::<Vec<_>>(), registry)
	}

	#[test]
	fn a_pin_trusts_a_certificate_from_a_pin_extends_one_hop_and_no_further() {
		let (ana, bo, cy, dee) = (signer("ana"), signer("bo"), signer("cy"), signer("dee"));
		let ana_e = entry(&ana, vec![]);
		let mut bo_e = entry(&bo, vec![]);
		bo_e.certs.push(cert(&ana, &bo_e));
		let mut cy_e = entry(&cy, vec![]);
		// cy is certified only by bo — a certified, not pinned, member.
		cy_e.certs.push(cert(&bo, &cy_e));
		let mut dee_e = entry(&dee, vec![]);
		dee_e.signature = bo.sign(&statements::identity("dee", &dee_e.key_id, &dee_e.root_digest));
		dee_e.certs.push(cert(&ana, &dee_e));
		let registry = vec![ana_e.clone(), bo_e, cy_e, dee_e];
		let t = trust_from("eve", &[("ana", &ana_e.key_id)], &registry);
		assert_eq!(t.of("ana").map(|x| x.via.as_str()), Some("pin"));
		assert_eq!(t.of("bo").map(|x| x.via.as_str()), Some("cert:ana"), "certified by a pinned lead");
		assert!(t.of("cy").is_none(), "two hops: a certificate from a certified member counts for nothing");
		assert!(t.of("dee").is_none(), "a self-signature by another key: not a sound entry, whoever certified it");
		// A pin names a key: a registry entry with another key is not the pinned one.
		let t = trust_from("eve", &[("ana", "00")], &registry);
		assert!(t.of("ana").is_none() && t.of("bo").is_none());
	}

	#[test]
	fn a_registry_entry_whose_id_is_not_its_key_is_dropped() {
		let ana = signer("ana");
		let mut e = entry(&ana, vec![]);
		e.key_id = "f".repeat(64);
		e.signature = ana.sign(&statements::identity("ana", &e.key_id, &e.root_digest));
		let pinned = e.key_id.clone();
		let t = trust_from("eve", &[("ana", &pinned)], &[e]);
		assert!(t.of("ana").is_none(), "self-signed and pinned, but the id is not the key's");
	}
}
