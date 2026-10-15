// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Cases from the command line (commit 33c, docs/DESKTOP.md) — the native
//! twin of `web/src/vault/cases.ts`, `content-hash.ts` and `intake.ts`, for
//! the three things a desktop needs in a case:
//!
//! ```text
//! open the key   your grant: sealed to your root, SIGNED by whoever granted it.
//!                The signer must be someone YOU trust (identity.rs), the
//!                signature must name this case, this key (full digest) and you,
//!                and the key must be the registry's — or nothing opens.
//! upload         name, type and content key sealed into the case store's
//!                places (GV04, store = case:<id>); on evidence, the content
//!                hash SIGNED by you and sealed into its version's place, its
//!                RFC 3161 imprint, and a signed intake record.
//! download       the bytes, and what the uploader's signed hash says of them:
//!                verified, mismatch, untrusted, invalid or unsigned.
//! ```
//!
//! What a server could try, and where it stops:
//! - **hand you a key of its own** (so what you upload opens for it): the
//!   grant's signature names the key's digest, and only a trusted identity's
//!   signature counts;
//! - **replay another case's grant**: the statement names the case;
//! - **move a hash or intake record to another file or version**: each is
//!   sealed into its place AND its signed statement names area, file and
//!   version — a co-worker holding the case key can re-seal, not re-sign.
//!
//! The limit the browser names applies here too: a validly signed OLDER
//! grant can be replayed to a client that never saw the newer one
//! (identity.ts › rollback). The CLI keeps no memory between runs.

use gorani_formats::formats::{self, VaultPrivateKey};
use gorani_formats::placed::{self, Place};

use crate::api::Jwk;
use crate::identity::{self, statements, Signer, Trust};
use crate::Error;

/// A case as `GET /api/v1/cases` lists it (the fields the CLI reads).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRow {
	pub id: String,
	pub kind: String,
	#[serde(default)]
	pub title_sealed: Option<String>,
	pub key_id: String,
	pub public_key: CasePublic,
	#[serde(default)]
	pub closed: bool,
	#[serde(default)]
	pub rotation_required: bool,
	/// A rotation whose reseal walk has not finished.
	#[serde(default)]
	pub rotating: Option<serde_json::Value>,
	#[serde(default)]
	pub hold: Option<serde_json::Value>,
	/// The caller's own grant — None for a lead's or auditor's structure view.
	#[serde(default)]
	pub grant: Option<CaseGrant>,
	/// The case's inbox keys (commit 37b, inbox.rs): what collectors seal to.
	#[serde(default)]
	pub inbox_keys: Vec<crate::inbox::InboxKeyRow>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CasePublic {
	pub ec: Jwk,
	pub kem: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseGrant {
	pub permission: String,
	pub key_sealed: String,
	#[serde(default)]
	pub expires_at: Option<String>,
	#[serde(default)]
	pub signature: Option<String>,
	#[serde(default)]
	pub signed_by: Option<String>,
}

impl CaseRow {
	/// The case's area string (lib/area.ts › caseArea).
	pub fn area(&self) -> String {
		format!("case:{}", self.id)
	}

	pub fn is_evidence(&self) -> bool {
		self.kind == "evidence"
	}
}

/// Open your copy of a case key (cases.ts › openSigned + openCaseKey):
///
/// 1. the grant is signed, by someone `trust` trusts;
/// 2. it opens under your root (a hybrid seal to you);
/// 3. the signature covers (this case, this key's FULL digest, you);
/// 4. the key IS the registry's: both public halves and the key id agree.
///
/// Every refusal names what failed; nothing is sealed or opened with a key
/// that did not pass all four.
pub fn open_case_key(root: &VaultPrivateKey, c: &CaseRow, trust: &Trust) -> Result<VaultPrivateKey, Error> {
	let Some(g) = &c.grant else { return Err(Error::Config(format!("you hold no grant on case {}", c.id))) };
	if c.rotating.is_some() {
		// Mid-walk, values sit under both keys; the web app's rotation (which
		// holds both, signed) finishes it. The CLI reads one key, so it waits.
		return Err(Error::Config(format!("case {}'s key is rotating — its manager finishes the rotation in the web app; try again after", c.id)));
	}
	let (Some(signature), Some(signed_by)) = (&g.signature, &g.signed_by) else {
		return Err(Error::Open("your copy of this case's key is unsigned — ask a manager to grant it again"));
	};
	let Some(signer) = trust.of(signed_by) else {
		return Err(Error::Config(format!("your copy of case {}'s key was signed by {signed_by}, whose identity you have not verified — compare fingerprints in the web app (Team › People) first", c.id)));
	};
	let b64 = formats::open_text(root, &g.key_sealed).map_err(|_| Error::Open("your copy of the case key does not open under your root"))?;
	let bundle = crate::decode(&b64)?;
	let key = VaultPrivateKey::from_bytes(&bundle).map_err(|_| Error::Open("the case key is not a key bundle"))?;
	if !signer.verify(&statements::grant(&c.id, &identity::hybrid_digest_of(&key)?, &trust.me), signature) {
		return Err(Error::Config(format!("the signature on your copy of case {}'s key does not verify — it is not the key {signed_by} granted you", c.id)));
	}
	check_record_matches(&key, c)?;
	Ok(key)
}

/// records.ts › checkRecordMatches: the opened key's public halves and id
/// are the ones the registry lists for the case.
fn check_record_matches(key: &VaultPrivateKey, c: &CaseRow) -> Result<(), Error> {
	let formats::VaultPublicKey::Hybrid { ec, kem } = formats::public_of(key) else { return Err(Error::Open("case keys are hybrid")) };
	if formats::raw_public_bytes(&ec) != identity::ec_raw_of_jwk(&c.public_key.ec)? {
		return Err(Error::Open("case key record: the public key does not belong to the sealed private key"));
	}
	if crate::decode(&c.public_key.kem)?.as_slice() != kem.as_slice() {
		return Err(Error::Open("case key record: the post-quantum public key does not belong to the sealed private key"));
	}
	if formats::key_id(&formats::public_of(key)) != c.key_id {
		return Err(Error::Open("case key record: the key id does not match the key"));
	}
	Ok(())
}

/// The case's title, opened in its place (None when it has none or it
/// does not open — the caller prints the id).
pub fn open_title(key: &VaultPrivateKey, c: &CaseRow) -> Option<String> {
	let sealed = c.title_sealed.as_deref()?;
	placed::open_placed_text(key, &Place::case_title(&c.area()), sealed).ok().map(|t| t.to_string())
}

// ── signed content hashes (content-hash.ts) ───────────────────────────

/// What is sealed into `file.hash(area, file, version)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentHashRecord {
	pub v: u8,
	pub sha256: String,
	pub size: u64,
	pub signer: String,
	pub key_id: String,
	pub signature: String,
}

/// The uploader's half: sign (area, file, version, SHA-256, size), seal the
/// record into the version's place. Returns the `hash` and `stamp` form
/// fields — the stamp is SHA-256 of the signature (identity::stamp_imprint).
#[allow(clippy::too_many_arguments)]
pub fn sign_content_hash(signer: &Signer, store: &VaultPrivateKey, area: &str, file: &str, version: u64, sha256: &str, size: u64) -> Result<(String, String), Error> {
	let signature = signer.sign(&statements::content_hash(area, file, version, sha256, size));
	let stamp = identity::stamp_imprint(&signature)?;
	let record = ContentHashRecord { v: 1, sha256: sha256.into(), size, signer: signer.member.clone(), key_id: signer.key_id.clone(), signature };
	let json = serde_json::to_string(&record).map_err(|e| Error::Config(e.to_string()))?;
	let sealed = placed::seal_placed_text(store, &Place::file_hash(area, file, version as i64), &json).map_err(|_| Error::Open("case key"))?;
	Ok((sealed, stamp))
}

/// What a reader learns. Only `Verified` means "these are the signer's bytes".
#[derive(Debug, PartialEq)]
pub enum HashCheck {
	Verified { signer: String, via: String, active: bool },
	Unsigned,
	Mismatch { signer: String, claimed: String, actual: String },
	Untrusted { signer: String, why: String },
	Invalid { why: String },
}

impl HashCheck {
	/// One line for a person (content-hash.ts › describeHashCheck).
	pub fn describe(&self) -> String {
		match self {
			HashCheck::Verified { signer, active, .. } => format!("content verified — exactly the bytes {signer} signed{}", if *active { "" } else { " (they have since left the team)" }),
			HashCheck::Unsigned => "content not signed by its uploader".into(),
			HashCheck::Mismatch { signer, claimed, actual } => format!("⚠ content does NOT match what {signer} signed (SHA-256 {}…, signed {}…)", &actual[..16.min(actual.len())], &claimed[..16.min(claimed.len())]),
			HashCheck::Untrusted { signer, why } => format!("⚠ signed by {signer}, not verified: {why}"),
			HashCheck::Invalid { why } => format!("⚠ content signature invalid: {why}"),
		}
	}
}

fn hex64(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The reader's half (content-hash.ts › checkContentHash), in the same
/// order: the record must open in THIS version's place, be well formed,
/// come from a trusted signer with their current key, and verify — only
/// then is it compared with what was decrypted, so a `Mismatch` always
/// means "a person you trust vouched for other bytes than these".
#[allow(clippy::too_many_arguments)]
pub fn check_content_hash(store: &VaultPrivateKey, trust: &Trust, area: &str, file: &str, version: u64, sealed: Option<&str>, sha256: &str, size: u64) -> HashCheck {
	let Some(sealed) = sealed.filter(|s| !s.is_empty()) else { return HashCheck::Unsigned };
	let Ok(text) = placed::open_placed_text(store, &Place::file_hash(area, file, version as i64), sealed) else {
		return HashCheck::Invalid { why: "the hash record does not open in this version's place — moved from another file or version, or not sealed by this store".into() };
	};
	let Ok(r) = serde_json::from_str::<ContentHashRecord>(&text) else { return HashCheck::Invalid { why: "the hash record is malformed".into() } };
	if r.v != 1 || !hex64(&r.sha256) || !hex64(&r.key_id) {
		return HashCheck::Invalid { why: "the hash record is malformed".into() };
	}
	let Some(t) = trust.of(&r.signer) else {
		return HashCheck::Untrusted { signer: r.signer.clone(), why: format!("{} is not an identity you verified (compare fingerprints, or have a lead you verified certify them)", r.signer) };
	};
	if t.key_id != r.key_id {
		return HashCheck::Untrusted { signer: r.signer.clone(), why: format!("signed with an identity key ({}…) that is not {}'s current one — re-enrolled since?", &r.key_id[..16], r.signer) };
	}
	if !t.verify(&statements::content_hash(area, file, version, &r.sha256, r.size), &r.signature) {
		return HashCheck::Invalid { why: format!("the signature does not verify — {} did not sign this record", r.signer) };
	}
	if r.sha256 != sha256 || r.size != size {
		return HashCheck::Mismatch { signer: r.signer, claimed: r.sha256, actual: sha256.into() };
	}
	HashCheck::Verified { signer: r.signer, via: t.via.clone(), active: t.active }
}

// ── intake records (intake.ts) ────────────────────────────────────────

/// What the person fills in: where an evidence item came from.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntakeFields {
	pub source: String,
	pub collector: String,
	pub method: String,
	pub collected_at: String,
	pub notes: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntakeRecord {
	pub v: u8,
	pub source: String,
	pub collector: String,
	pub method: String,
	pub collected_at: String,
	pub notes: String,
	pub signer: String,
	pub key_id: String,
	pub signature: String,
}

/// An ISO 8601 date, or date and time — what the browser's `Date.parse`
/// takes in the shapes a person types: `2026-10-14`, `2026-10-14T09:30`,
/// `…:05`, `….250`, then `Z` or `±hh:mm`. Calendar-checked (no 31 April).
pub fn is_iso_datetime(s: &str) -> bool {
	let b = s.as_bytes();
	let digits = |r: std::ops::Range<usize>| b.get(r.clone()).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
	let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().unwrap_or(0);
	if b.len() < 10 || !digits(0..4) || b[4] != b'-' || !digits(5..7) || b[7] != b'-' || !digits(8..10) {
		return false;
	}
	let (y, m, d) = (num(0..4), num(5..7), num(8..10));
	let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
	let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
	if !(1..=12).contains(&m) || d == 0 || d > days[(m - 1) as usize] {
		return false;
	}
	let mut i = 10;
	if i == b.len() {
		return true;
	}
	if b[i] != b'T' || !digits(i + 1..i + 3) || b.get(i + 3) != Some(&b':') || !digits(i + 4..i + 6) || num(i + 1..i + 3) > 23 || num(i + 4..i + 6) > 59 {
		return false;
	}
	i += 6;
	if b.get(i) == Some(&b':') {
		if !digits(i + 1..i + 3) || num(i + 1..i + 3) > 59 {
			return false;
		}
		i += 3;
		if b.get(i) == Some(&b'.') {
			let n = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
			if n == 0 {
				return false;
			}
			i += 1 + n;
		}
	}
	match b.get(i) {
		None => true,
		Some(b'Z') => i + 1 == b.len(),
		Some(b'+' | b'-') => b.len() == i + 6 && digits(i + 1..i + 3) && b[i + 3] == b':' && digits(i + 4..i + 6) && num(i + 1..i + 3) <= 23 && num(i + 4..i + 6) <= 59,
		_ => false,
	}
}

/// Seal and sign an intake record for a NEW file (intake.ts › signIntake):
/// trimmed fields, source/collector/method required, a real date.
pub fn sign_intake(signer: &Signer, store: &VaultPrivateKey, area: &str, file: &str, f: &IntakeFields) -> Result<String, Error> {
	let f = IntakeFields { source: f.source.trim().into(), collector: f.collector.trim().into(), method: f.method.trim().into(), collected_at: f.collected_at.trim().into(), notes: f.notes.trim().into() };
	if f.source.is_empty() || f.collector.is_empty() || f.method.is_empty() {
		return Err(Error::Config("an intake record names its source, its collector and its method (--source, --collector, --method)".into()));
	}
	if !is_iso_datetime(&f.collected_at) {
		return Err(Error::Config("--collected-at must be an ISO 8601 date and time (2026-10-14T09:30Z)".into()));
	}
	let signature = signer.sign(&statements::intake(area, file, &f.source, &f.collector, &f.method, &f.collected_at, &f.notes));
	let record = IntakeRecord { v: 1, source: f.source, collector: f.collector, method: f.method, collected_at: f.collected_at, notes: f.notes, signer: signer.member.clone(), key_id: signer.key_id.clone(), signature };
	let json = serde_json::to_string(&record).map_err(|e| Error::Config(e.to_string()))?;
	placed::seal_placed_text(store, &Place::file_intake(area, file), &json).map_err(|_| Error::Open("case key"))
}

/// A file's intake record, opened in its place and checked against YOUR
/// trust — one line for a person, or None when the file has none.
pub fn describe_intake(store: &VaultPrivateKey, trust: &Trust, area: &str, file: &str, sealed: Option<&str>) -> Option<String> {
	let sealed = sealed.filter(|s| !s.is_empty())?;
	let Ok(text) = placed::open_placed_text(store, &Place::file_intake(area, file), sealed) else {
		return Some("⚠ intake record invalid: it does not open in this file's place".into());
	};
	let Ok(r) = serde_json::from_str::<IntakeRecord>(&text) else { return Some("⚠ intake record malformed".into()) };
	let what = format!("from {} — collected by {} ({}) at {}{}", r.source, r.collector, r.method, r.collected_at, if r.notes.is_empty() { String::new() } else { format!("; {}", r.notes) });
	let Some(t) = trust.of(&r.signer) else { return Some(format!("⚠ intake signed by {}, whose identity you have not verified: {what}", r.signer)) };
	if t.key_id != r.key_id {
		return Some(format!("⚠ intake signed by {} with a key that is not their current one: {what}", r.signer));
	}
	if r.v != 1 || !t.verify(&statements::intake(area, file, &r.source, &r.collector, &r.method, &r.collected_at, &r.notes), &r.signature) {
		return Some(format!("⚠ intake record invalid: the signature does not verify — {} did not sign it", r.signer));
	}
	Some(format!("intake verified (signed by {}): {what}", r.signer))
}

#[cfg(test)]
mod tests {
	use super::is_iso_datetime;

	#[test]
	fn collected_at_takes_the_dates_people_type_and_refuses_the_rest() {
		for ok in ["2026-10-14", "2026-10-14T09:30", "2026-10-14T09:30:05", "2026-10-14T09:30:05.250Z", "2026-10-14T09:30+09:00", "2024-02-29T00:00Z"] {
			assert!(is_iso_datetime(ok), "{ok}");
		}
		for bad in ["", "yesterday", "2026-13-01", "2026-04-31", "2025-02-29", "2026-10-14 09:30", "2026-10-14T24:00", "2026-10-14T09:30Zjunk", "2026-10-14T09:30:05.", "2026-10-14T09:30+9"] {
			assert!(!is_iso_datetime(bad), "{bad}");
		}
	}
}
