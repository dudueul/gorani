// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Which timestamp authority the team trusts (commit 29j, docs/CUSTODY.md ›
//! Stage 7, D5.5).
//!
//! A timestamp token is only as good as the key that signed it — and the
//! certificate inside a token is the TSA's own claim. Who says that key is
//! DigiCert's (or the court's, or your own)? Not the server: a deployment
//! that could name the TSA could name one of its own and date anything.
//! A LEAD says so, the way a lead vouches for a co-worker's identity:
//!
//! ```text
//! stmt("gorani-tsa-v1", spki, name)   signed by the lead's identity key
//! spki = SHA-256 of the TSA certificate's SubjectPublicKeyInfo, hex
//! ```
//!
//! The lead's client reads the certificate from a probe token, shows the
//! fingerprint, and signs only after the lead compared it with the one the
//! TSA publishes. Readers count a TSA key when a certification of it
//! verifies under an identity THEY trust (web/src/vault/timestamp.ts ›
//! trustedTsas). The key, not the certificate: a renewed certificate on the
//! same key needs nothing; a new key needs a new certification — and the
//! old one stays, so tokens it signed keep verifying.
//!
//! The registry enforces policy only — leads certify, leads withdraw — and
//! verifies no signature. Withdrawing is one lead's call: taking trust away
//! is protective, like placing a hold.

use worker::{Response, Result};

use super::{is_signature, json_error, GoraniFamilyDO};

#[derive(serde::Deserialize)]
struct TsaCertRow {
	spki: String,
	name: String,
	by_member: String,
	key_id: String,
	signature: String,
	at: String,
}

#[derive(serde::Deserialize)]
struct KeyIdRow {
	key_id: String,
}

fn hex64(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl GoraniFamilyDO {
	/// `GET tsa`: whether the deployment asks a TSA at all, and every
	/// certification of a TSA key — for any member's client to judge.
	pub(super) async fn tsa_get(&self, actor: &str) -> Result<Response> {
		if self.member_by_email(actor)?.is_none() {
			return json_error(403, "not a team member");
		}
		let rows: Vec<TsaCertRow> = self.sql.exec("SELECT spki, name, by_member, key_id, signature, at FROM tsa_certs ORDER BY at", None)?.to_array()?;
		let certs: Vec<serde_json::Value> = rows
			.into_iter()
			.map(|r| serde_json::json!({ "spki": r.spki, "name": r.name, "by": r.by_member, "keyId": r.key_id, "signature": r.signature, "at": r.at }))
			.collect();
		Response::from_json(&serde_json::json!({ "configured": crate::tsa::configured(&self.env).is_some(), "certs": certs }))
	}

	/// `PUT tsa { spki, name, keyId, signature }`: a lead certifies a TSA key.
	pub(super) async fn tsa_certify(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead certifies the timestamp authority");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let (Some(spki), Some(name), Some(key_id), Some(signature)) = (get("spki").filter(|s| hex64(s)), get("name").filter(|n| !n.is_empty() && n.len() <= 200), get("keyId"), get("signature").filter(|s| is_signature(s))) else {
			return json_error(400, "spki (SHA-256 of the TSA's public key, hex), name (≤ 200 characters), keyId and signature required");
		};
		// Signed with the lead's CURRENT identity key — the one readers know.
		let current: Option<KeyIdRow> = self.sql.exec("SELECT key_id FROM identities WHERE member_id = ?1", Some(vec![me.id.clone().into()]))?.to_array()?.into_iter().next();
		match current {
			None => return json_error(409, "register your own identity first — a certification is signed with it"),
			Some(c) if c.key_id != key_id => return json_error(409, "signed with a key that is not your current identity key"),
			Some(_) => {}
		}
		self.sql.exec(
			"INSERT INTO tsa_certs (spki, by_member, name, key_id, signature, at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT (spki, by_member) DO UPDATE SET name = ?3, key_id = ?4, signature = ?5, at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
			Some(vec![spki.clone().into(), me.id.clone().into(), name.clone().into(), key_id.into(), signature.into()]),
		)?;
		self.audit(actor, "tsa.certify", &spki, Some(&serde_json::json!({ "name": name }))).await?;
		self.tsa_get(actor).await
	}

	/// `DELETE tsa/<spki>`: no longer trust that key — every lead's
	/// certification of it goes. Tokens it signed then verify as
	/// "not a certified TSA", which is the point.
	pub(super) async fn tsa_withdraw(&self, actor: &str, spki: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead withdraws a timestamp authority");
		}
		let n = self.sql.exec("DELETE FROM tsa_certs WHERE spki = ?1", Some(vec![spki.into()]))?.rows_written();
		if n == 0 {
			return json_error(404, "no certification of that key");
		}
		self.audit(actor, "tsa.withdraw", spki, Some(&serde_json::json!({ "certsDropped": n }))).await?;
		self.tsa_get(actor).await
	}
}
