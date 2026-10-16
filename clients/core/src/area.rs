// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Where a client works (commit 33c; shared by the CLI and the shells from
//! 33d): the member's own area, or a case they are granted — the store key
//! that seals and opens there, and the member's identity and trust when
//! their vault has one (always in a case: the case key opens only through
//! a trusted signature). The twin of `web/src/lib/area.ts` plus the team
//! context the browser opens beside it.

use gorani_formats::formats::{ContentKey, VaultPrivateKey};
use gorani_formats::placed::{self, Place};

use crate::cases::{self, CaseRow, HashCheck, IntakeFields};
use crate::identity::{self, RegistryIdentity, Signer, Trust};
use crate::{api, Error, Session};

pub struct Area {
	/// `<member>` or `case:<id>` — the GV04 `store` of every place.
	pub name: String,
	pub key: VaultPrivateKey,
	pub case: Option<CaseRow>,
	pub team: Option<(Signer, Trust)>,
	/// The area's fingerprint secret (`fp` of its files secrets, commit
	/// 39n): what makes a duplicate tag. None until a browser has made the
	/// secrets (at its first upload) — files sent before then carry none.
	pub fp: Option<Vec<u8>>,
}

/// A file already in the area with the same bytes.
#[derive(Debug, Clone)]
pub struct Twin {
	pub id: String,
	pub name: String,
	pub folder: Option<String>,
}

/// The duplicate tag of a file (commit 39n): HMAC-SHA256 under the area's
/// fingerprint secret of the plaintext's SHA-256 (the 32 bytes, not the
/// hex), as hex — byte for byte what the browser makes (web/src/ui/files/
/// model.ts › fingerprint), so a file pushed from here and one uploaded in
/// the browser are known as the same bytes. Until 39n the native clients
/// sent no tag at all: nothing they uploaded was ever found as a duplicate.
pub fn duplicate_tag(fp: &[u8], sha256_hex: &str) -> Option<String> {
	use hmac::{Hmac, Mac};
	let digest: Vec<u8> = (0..sha256_hex.len()).step_by(2).map(|i| u8::from_str_radix(sha256_hex.get(i..i + 2)?, 16).ok()).collect::<Option<_>>()?;
	if digest.len() != 32 {
		return None;
	}
	let mut mac = Hmac::<sha2::Sha256>::new_from_slice(fp).ok()?;
	mac.update(&digest);
	Some(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

impl Area {
	pub fn is_evidence(&self) -> bool {
		self.case.as_ref().is_some_and(CaseRow::is_evidence)
	}

	/// Open text sealed into a place of this area; None when it does not
	/// open there (moved, minted, or another store's).
	pub fn open(&self, place: &Place, sealed: &str) -> Option<String> {
		placed::open_placed_text(&self.key, place, sealed).ok().map(|s| s.to_string())
	}

	pub fn seal(&self, place: &Place, text: &str) -> Result<String, Error> {
		placed::seal_placed_text(&self.key, place, text).map_err(|_| Error::Open("the area's store key"))
	}

	/// A version's content key, opened only from THAT version's place (O6).
	pub fn content_key(&self, file: &str, version: i64, sealed: &str) -> Result<[u8; 32], Error> {
		let ck = placed::unwrap_placed_key(&self.key, &Place::file_key(&self.name, file, version), sealed).map_err(|_| Error::Open("content key (not sealed for this file and version)"))?;
		Ok(gorani_formats::formats::import_content_key(&ck))
	}

	/// What the uploader signed, against what was decrypted (cases.rs ›
	/// check_content_hash). None when this vault has no identity to check with.
	pub fn check_hash(&self, file: &str, version: u64, hash: Option<&str>, sha256: &str, size: u64) -> Option<HashCheck> {
		let (_, trust) = self.team.as_ref()?;
		Some(cases::check_content_hash(&self.key, trust, &self.name, file, version, hash, sha256, size))
	}

	/// A new file's form fields (version 1), every value sealed into its
	/// place here: the name, the type, the content key — and, when the
	/// member's identity is open, the signed content hash with its
	/// timestamp imprint (29d/29j) and, when given, the signed intake (29g).
	#[allow(clippy::too_many_arguments)]
	pub fn new_file_fields(&self, file_id: &str, name: &str, ck: &ContentKey, size: u64, sha256: &str, intake: Option<&IntakeFields>) -> Result<Vec<(String, String)>, Error> {
		let ck_wrapped = placed::wrap_placed_key(&self.key, &Place::file_key(&self.name, file_id, 1), ck).map_err(|_| Error::Open("the area's store key"))?;
		let mut fields = vec![
			("file_id".to_string(), file_id.to_string()),
			("ck".into(), ck_wrapped),
			("name".into(), self.seal(&Place::file_name(&self.name, file_id), name)?),
			("type".into(), self.seal(&Place::file_type(&self.name, file_id, 1), "application/octet-stream")?),
			("size".into(), size.to_string()),
		];
		fields.extend(self.tag_field(sha256));
		fields.extend(self.signed_fields(file_id, 1, size, sha256, intake)?);
		Ok(fields)
	}

	/// The `modified` form field (39y): the local copy's modified time —
	/// seconds since the epoch — sealed into version `version`'s place, as
	/// the browser seals File.lastModified. None for a time the clock does
	/// not know (0: before 1970, or a file system without one).
	pub fn modified_field(&self, file_id: &str, version: i64, secs: u64) -> Result<Option<(String, String)>, Error> {
		if secs == 0 {
			return Ok(None);
		}
		Ok(Some(("modified".into(), self.seal(&Place::file_modified(&self.name, file_id, version), &crate::engine::iso_of(secs))?)))
	}

	/// A version's original modified date, opened from its place — seconds
	/// since the epoch, or None (absent, opens nowhere, or not a date).
	pub fn open_modified(&self, file_id: &str, version: i64, sealed: &str) -> Option<u64> {
		let text = self.open(&Place::file_modified(&self.name, file_id, version), sealed)?;
		let secs = crate::engine::iso_seconds(&text);
		(secs > 0).then_some(secs)
	}

	/// The `tag` form field, when the area has its fingerprint secret.
	fn tag_field(&self, sha256: &str) -> Option<(String, String)> {
		Some(("tag".into(), duplicate_tag(self.fp.as_deref()?, sha256)?))
	}

	/// The note a sync engine logs when a new file is a copy of one already
	/// stored (it uploads anyway: a folder the system manages cannot refuse
	/// a copy put into it — the file must exist — so the duplicate is
	/// reported, and Find duplicates in the web app lists it). None when
	/// there is no twin, or the check could not be made.
	pub fn duplicate_note(&self, client: &api::Client, name: &str, size: u64, sha256: &str) -> Option<String> {
		let twins = self.twins(client, size, sha256).ok()?;
		let first = twins.first()?;
		Some(format!("“{name}” has the same bytes as “{}”{} — stored as a second copy (Find duplicates in the web app lists such copies)", first.name, if twins.len() > 1 { format!(" and {} more", twins.len() - 1) } else { String::new() }))
	}

	/// The live files with exactly these bytes (same size, same tag), named
	/// and placed — the duplicate check. Empty while the area has no secret.
	pub fn twins(&self, client: &api::Client, size: u64, sha256: &str) -> Result<Vec<Twin>, Error> {
		let Some(tag) = self.fp.as_deref().and_then(|fp| duplicate_tag(fp, sha256)) else { return Ok(vec![]) };
		Ok(client
			.files_match(size)?
			.into_iter()
			.filter(|f| f.get("tag").and_then(|t| t.as_str()) == Some(tag.as_str()))
			.map(|f| {
				let id = f.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
				let name = f.get("name").and_then(|v| v.as_str()).and_then(|sealed| self.open(&Place::file_name(&self.name, &id), sealed)).unwrap_or_else(|| "a file".into());
				Twin { name, folder: f.get("folder").and_then(|v| v.as_str()).map(str::to_string), id }
			})
			.collect())
	}

	/// A new VERSION's form fields: its key and type sealed into the places
	/// of version `base + 1` (the server refuses any other number — it would
	/// be unopenable), and its signed hash.
	pub fn version_fields(&self, file_id: &str, base: i64, ck: &ContentKey, size: u64, sha256: &str) -> Result<Vec<(String, String)>, Error> {
		let next = base + 1;
		let mut fields = vec![
			("base_version".to_string(), base.to_string()),
			("ck".into(), placed::wrap_placed_key(&self.key, &Place::file_key(&self.name, file_id, next), ck).map_err(|_| Error::Open("the area's store key"))?),
			("type".into(), self.seal(&Place::file_type(&self.name, file_id, next), "application/octet-stream")?),
			("size".into(), size.to_string()),
		];
		fields.extend(self.tag_field(sha256));
		fields.extend(self.signed_fields(file_id, next as u64, size, sha256, None)?);
		Ok(fields)
	}

	fn signed_fields(&self, file_id: &str, version: u64, size: u64, sha256: &str, intake: Option<&IntakeFields>) -> Result<Vec<(String, String)>, Error> {
		let Some((signer, _)) = &self.team else {
			if self.is_evidence() || intake.is_some() {
				return Err(Error::Config("signing needs your identity — open the vault once in the web app (Team)".into()));
			}
			return Ok(vec![]);
		};
		let (hash, stamp) = cases::sign_content_hash(signer, &self.key, &self.name, file_id, version, sha256, size)?;
		let mut out = vec![("hash".to_string(), hash), ("stamp".to_string(), stamp)];
		if let Some(f) = intake {
			out.push(("intake".into(), cases::sign_intake(signer, &self.key, &self.name, file_id, f)?));
		}
		Ok(out)
	}
}

/// The member's identity and trust (identity.rs): the record from their
/// settings (MAC'd by the root), the registry's identities. None when the
/// vault has no identity yet — the web app makes one on first open.
pub fn open_team(client: &api::Client, sess: &Session, member: &str) -> Result<Option<(Signer, Trust)>, Error> {
	let Some(rec) = &sess.settings.identity else { return Ok(None) };
	let root = VaultPrivateKey::from_bytes(&sess.root).map_err(|_| Error::Open("root bundle"))?;
	let signer = identity::open_identity(member, &root, rec)?;
	let registry: Vec<RegistryIdentity> = serde_json::from_value(client.team_get("family/identities")?["identities"].clone()).map_err(|e| Error::Config(format!("identities: {e}")))?;
	let trust = identity::build_trust(member, &root, rec, &registry)?;
	Ok(Some((signer, trust)))
}

/// The cases the registry lists for the caller (`GET /api/v1/cases`).
pub fn listed_cases(client: &api::Client) -> Result<Vec<CaseRow>, Error> {
	serde_json::from_value(client.team_get("cases")?["cases"].clone()).map_err(|e| Error::Config(format!("cases: {e}")))
}

/// Open the area a command names: `case`, or the member's own.
pub fn open_area(client: &api::Client, sess: &Session, member: &str, case: Option<&str>) -> Result<Area, Error> {
	let team = open_team(client, sess, member)?;
	let Some(case_id) = case else {
		let mut area = Area { name: member.into(), key: sess.files_store()?, case: None, team, fp: None };
		area.fp = fingerprint_secret(client, &area);
		return Ok(area);
	};
	let Some((signer, trust)) = team else {
		return Err(Error::Config("your vault has no identity yet — open it once in the web app (Team), where it is made and your lead's fingerprint compared; a case key opens only through a signature you can check".into()));
	};
	let c = listed_cases(client)?.into_iter().find(|c| c.id == case_id).ok_or_else(|| Error::Config(format!("no case {case_id} is listed for you")))?;
	let root = VaultPrivateKey::from_bytes(&sess.root).map_err(|_| Error::Open("root bundle"))?;
	let key = cases::open_case_key(&root, &c, &trust)?;
	let mut area = Area { name: c.area(), key, case: Some(c), team: Some((signer, trust)), fp: None };
	area.fp = fingerprint_secret(client, &area);
	Ok(area)
}

/// The area's fingerprint secret, opened with its key — best effort: an
/// area without secrets yet (or a server too old to say) simply makes no
/// duplicate tags. Secrets that are there but do not open are reported:
/// they were sealed by someone without this area's key.
fn fingerprint_secret(client: &api::Client, area: &Area) -> Option<Vec<u8>> {
	use base64::Engine;
	let sealed = client.files_secrets_of(&area.name).ok().flatten()?;
	let Some(json) = area.open(&Place::store_secrets(&area.name), &sealed) else {
		eprintln!("gorani: this area's files secrets do not open with its key — duplicate checks are off for it");
		return None;
	};
	let v: serde_json::Value = serde_json::from_str(&json).ok()?;
	base64::engine::general_purpose::STANDARD.decode(v.get("fp")?.as_str()?).ok()
}

#[cfg(test)]
mod tests {
	use super::duplicate_tag;

	/// The same tag the browser makes (model.ts › fingerprint: HMAC-SHA256
	/// under fp of the RAW 32-byte digest, as hex) — a vector computed
	/// outside both implementations (Python's hmac + hashlib).
	#[test]
	fn the_duplicate_tag_is_the_browsers() {
		let sha256_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
		assert_eq!(duplicate_tag(&[1u8; 32], sha256_abc).as_deref(), Some("67a782af2dbd92253f592f996d654a6276a1ef081e28ab9df3cdadd5474b6a71"));
		assert_eq!(duplicate_tag(&[1u8; 32], "not hex"), None);
		assert_eq!(duplicate_tag(&[1u8; 32], "abcd"), None, "a digest is 32 bytes");
	}
}
