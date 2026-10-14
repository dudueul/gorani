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
		fields.extend(self.signed_fields(file_id, 1, size, sha256, intake)?);
		Ok(fields)
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
		return Ok(Area { name: member.into(), key: sess.files_store()?, case: None, team });
	};
	let Some((signer, trust)) = team else {
		return Err(Error::Config("your vault has no identity yet — open it once in the web app (Team), where it is made and your lead's fingerprint compared; a case key opens only through a signature you can check".into()));
	};
	let c = listed_cases(client)?.into_iter().find(|c| c.id == case_id).ok_or_else(|| Error::Config(format!("no case {case_id} is listed for you")))?;
	let root = VaultPrivateKey::from_bytes(&sess.root).map_err(|_| Error::Open("root bundle"))?;
	let key = cases::open_case_key(&root, &c, &trust)?;
	Ok(Area { name: c.area(), key, case: Some(c), team: Some((signer, trust)) })
}
