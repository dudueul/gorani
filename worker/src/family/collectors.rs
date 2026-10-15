// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Collectors (commit 37a, docs/COLLECTORS.md): machines that drop evidence
//! into case inboxes with no person signed in — an acquisition server, an
//! EDR drop. A collector is an Access *service token* (its JWT names a
//! `common_name`, no email) bound here to an identity key, by two leads:
//!
//! ```text
//! request   a lead A    signs stmt("gorani-collector-v1", id, common_name, key id, A)
//! approve   a lead B≠A  signs stmt("gorani-collector-approve-v1", id, common_name, key id, A, B)
//!           → active: the Worker lets that service token use the drop routes
//! grant     a manager of the case (or a lead): the collector may drop into it
//! revoke    any one lead — taking trust away is protective, like a hold
//! ```
//!
//! Both statements NAME the collector, its token and its key: two leads'
//! agreement cannot be attached to a collector the server made up (the
//! case two-person rule's statements name only an action and a case — why
//! this has its own). As everywhere since commit 27 the registry enforces
//! the policy and verifies no signature; members' clients do
//! (web/src/vault/collectors.ts), and count a collector's key only when both
//! signatures verify under leads THEY trust.
//!
//! What a collector can do, once active and granted, is drop into a case's
//! inbox — sealed to the inbox's public key (37b). It holds no case key and
//! reads nothing.

use worker::{Response, Result};

use super::{is_signature, json_error, GoraniFamilyDO};

/// A registration nobody approved in a week is stale: ask again (as 29f).
const REQUEST_DAYS: i64 = 7;

#[derive(serde::Deserialize)]
struct CollectorRow {
	id: String,
	name: String,
	common_name: String,
	key_id: String,
	public_key: String,
	requested_by: String,
	requested_at: String,
	request_signature: String,
	approved_by: Option<String>,
	approved_at: Option<String>,
	approve_signature: Option<String>,
	revoked_by: Option<String>,
	revoked_at: Option<String>,
	/// 1 when a pending request is older than REQUEST_DAYS (computed by SQLite).
	expired: i64,
}

impl CollectorRow {
	fn status(&self) -> &'static str {
		match (&self.revoked_at, &self.approved_at) {
			(Some(_), _) => "revoked",
			(None, Some(_)) => "active",
			(None, None) if self.expired == 1 => "expired",
			(None, None) => "pending",
		}
	}

	fn json(&self, cases: Vec<String>) -> serde_json::Value {
		serde_json::json!({
			"id": self.id, "name": self.name, "commonName": self.common_name, "status": self.status(),
			"keyId": self.key_id, "publicKey": serde_json::from_str::<serde_json::Value>(&self.public_key).unwrap_or(serde_json::Value::Null),
			"requestedBy": self.requested_by, "requestedAt": self.requested_at, "requestSignature": self.request_signature,
			"approvedBy": self.approved_by, "approvedAt": self.approved_at, "approveSignature": self.approve_signature,
			"revokedBy": self.revoked_by, "revokedAt": self.revoked_at, "cases": cases,
		})
	}
}

#[derive(serde::Deserialize)]
struct CaseIdRow {
	case_id: String,
}

const SELECT: &str = "SELECT id, name, common_name, key_id, public_key, requested_by, requested_at, request_signature, approved_by, approved_at, approve_signature, revoked_by, revoked_at";

/// An Access service token's Client ID as its JWT names it
/// (`<32 hex>.access`), or any similar short machine name.
fn valid_common_name(s: &str) -> bool {
	(1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn hex64(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The identity key id a client computes (identity.ts › identityKeyId):
/// SHA-256 over lp("gorani-identity-key-v1") ‖ lp(04 ‖ x ‖ y), hex. The
/// registry checks only that the id IS this key's — a mismatch is a broken
/// client, not something to store.
fn identity_key_id(jwk: &serde_json::Value) -> Option<String> {
	use base64::Engine;
	use sha2::Digest;
	let b64u = |k: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwk.get(k)?.as_str()?.trim_end_matches('=')).ok();
	let (x, y) = (b64u("x")?, b64u("y")?);
	if x.len() != 32 || y.len() != 32 || jwk.get("kty").and_then(|v| v.as_str()).is_some_and(|k| k != "EC") || jwk.get("crv").and_then(|v| v.as_str()).is_some_and(|c| c != "P-256") {
		return None;
	}
	let mut point = vec![4u8];
	point.extend_from_slice(&x);
	point.extend_from_slice(&y);
	let mut h = sha2::Sha256::new();
	for part in [b"gorani-identity-key-v1".as_slice(), point.as_slice()] {
		h.update((part.len() as u32).to_be_bytes());
		h.update(part);
	}
	Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

impl GoraniFamilyDO {
	fn collector_row(&self, id: &str) -> Result<Option<CollectorRow>> {
		Ok(self
			.sql
			.exec(&format!("{SELECT}, (approved_at IS NULL AND requested_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{REQUEST_DAYS} days')) AS expired FROM collectors WHERE id = ?1"), Some(vec![id.into()]))?
			.to_array::<CollectorRow>()?
			.into_iter()
			.next())
	}

	fn collector_cases(&self, id: &str) -> Result<Vec<String>> {
		let rows: Vec<CaseIdRow> = self.sql.exec("SELECT case_id FROM collector_grants WHERE collector_id = ?1 ORDER BY case_id", Some(vec![id.into()]))?.to_array()?;
		Ok(rows.into_iter().map(|r| r.case_id).collect())
	}

	/// `GET collectors`: every collector, with its registration's two
	/// signatures and the cases it may drop into — readable by any member,
	/// so any member's client can judge it (like the identities).
	pub(super) async fn collectors_list(&self, actor: &str) -> Result<Response> {
		if self.member_by_email(actor)?.is_none() {
			return json_error(403, "not a team member");
		}
		let rows: Vec<CollectorRow> = self
			.sql
			.exec(&format!("{SELECT}, (approved_at IS NULL AND requested_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{REQUEST_DAYS} days')) AS expired FROM collectors ORDER BY requested_at"), None)?
			.to_array()?;
		let mut out = Vec::new();
		for r in rows {
			let cases = self.collector_cases(&r.id)?;
			out.push(r.json(cases));
		}
		Ok(Response::from_json(&serde_json::json!({ "collectors": out }))?)
	}

	/// `POST collectors { id, name, commonName, publicKey, keyId, signature }`
	/// — a lead asks to register a collector.
	pub(super) async fn collector_request(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead registers a collector (and a second lead approves)");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(id) = get("id").filter(|i| crate::auth::valid_member_id(i)) else { return json_error(400, "id: 2–32 of a–z, 0–9 and dashes") };
		let Some(name) = get("name").map(|n| n.trim().to_string()).filter(|n| (1..=80).contains(&n.chars().count())) else { return json_error(400, "name: 1–80 characters") };
		let Some(common_name) = get("commonName").filter(|c| valid_common_name(c)) else { return json_error(400, "commonName: the Access service token's Client ID (what its JWT names as common_name)") };
		let Some(public_key) = body.get("publicKey").filter(|k| k.is_object()).cloned() else { return json_error(400, "publicKey: the collector's identity key (a P-256 JWK)") };
		let Some(key_id) = get("keyId").filter(|k| hex64(k)) else { return json_error(400, "keyId: the identity key's id (64 hex)") };
		if identity_key_id(&public_key).as_deref() != Some(key_id.as_str()) {
			return json_error(400, "keyId is not this key's id (SHA-256 of the key) — refusing a registration whose two signatures would name another key");
		}
		let Some(signature) = get("signature").filter(|s| is_signature(s)) else { return json_error(400, "signature: the requesting lead's, over the registration statement") };
		let member_taken = self.sql.exec("SELECT COUNT(*) AS n FROM members WHERE id = ?1", Some(vec![id.clone().into()]))?.one::<super::Count>()?.n > 0;
		if member_taken || self.collector_row(&id)?.is_some() {
			return json_error(409, "that id is taken (a member or a collector) — choose another");
		}
		// One service token, one live collector: two would split its trail.
		let live: Vec<CaseIdRow> = self
			.sql
			.exec(
				&format!("SELECT id AS case_id FROM collectors WHERE common_name = ?1 AND revoked_at IS NULL AND (approved_at IS NOT NULL OR requested_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-{REQUEST_DAYS} days'))"),
				Some(vec![common_name.clone().into()]),
			)?
			.to_array()?;
		if let Some(other) = live.first() {
			return json_error(409, &format!("this service token is already collector {} — revoke it first", other.case_id));
		}
		self.sql.exec(
			"INSERT INTO collectors (id, name, common_name, key_id, public_key, requested_by, requested_at, request_signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?7)",
			Some(vec![id.clone().into(), name.into(), common_name.clone().into(), key_id.into(), public_key.to_string().into(), me.id.clone().into(), signature.into()]),
		)?;
		self.audit(actor, "collector.request", &id, Some(&serde_json::json!({ "commonName": common_name }))).await?;
		let row = self.collector_row(&id)?.ok_or_else(|| worker::Error::RustError("collector vanished".into()))?;
		Ok(Response::from_json(&row.json(vec![]))?)
	}

	/// `POST collector-approve/<id> { signature }` — a second lead agrees,
	/// and the collector is active from this request on.
	pub(super) async fn collector_approve(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead approves a collector");
		}
		let Some(row) = self.collector_row(id)? else { return json_error(404, "no such collector") };
		if row.requested_by == me.id {
			return json_error(403, "the second person must be a different lead — you asked for this");
		}
		match row.status() {
			"active" => return json_error(409, "already approved"),
			"revoked" => return json_error(409, "the collector was revoked"),
			"expired" => return json_error(409, "the request expired — register it again"),
			_ => {}
		}
		let Some(signature) = body.get("signature").and_then(|v| v.as_str()).filter(|s| is_signature(s)).map(str::to_string) else {
			return json_error(400, "signature: the approving lead's, over the approval statement");
		};
		self.sql.exec(
			"UPDATE collectors SET approved_by = ?1, approved_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), approve_signature = ?2 WHERE id = ?3 AND approved_at IS NULL AND revoked_at IS NULL",
			Some(vec![me.id.clone().into(), signature.into(), id.into()]),
		)?;
		self.audit(actor, "collector.approve", id, Some(&serde_json::json!({ "requestedBy": row.requested_by, "commonName": row.common_name }))).await?;
		let row = self.collector_row(id)?.ok_or_else(|| worker::Error::RustError("collector vanished".into()))?;
		let cases = self.collector_cases(id)?;
		Ok(Response::from_json(&row.json(cases))?)
	}

	/// `DELETE collectors/<id>` — any lead revokes: the token is refused
	/// from the next request on. A revoked collector is not reinstated —
	/// register it anew (with a new key, if the machine was the reason).
	pub(super) async fn collector_revoke(&self, actor: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead revokes a collector");
		}
		let n = self
			.sql
			.exec("UPDATE collectors SET revoked_by = ?1, revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2 AND revoked_at IS NULL", Some(vec![me.id.clone().into(), id.into()]))?
			.rows_written();
		if n == 0 {
			return json_error(404, "no such live collector");
		}
		self.audit(actor, "collector.revoke", id, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "revoked": id }))?)
	}

	/// `PUT collector-grants/<case>/<collector>` — the collector may drop
	/// into this case's inbox. One person (a manager of the case, or a lead):
	/// a drop only adds to an inbox that people review.
	pub(super) async fn collector_grant(&self, actor: &str, case: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let manager = self.grant_of(case, &me.id)?.is_some_and(|g| g.permission == "manage");
		if !manager && me.role != "lead" {
			return json_error(403, "only a manager of the case, or a lead, lets a collector drop into it");
		}
		match self.case_row(case)? {
			None => return json_error(404, "no such case"),
			Some(c) if c.closed_at.is_some() => return json_error(409, "the case is closed — nothing more is collected into it"),
			Some(_) => {}
		}
		match self.collector_row(id)?.map(|r| r.status()) {
			Some("active") => {}
			Some(other) => return json_error(409, &format!("the collector is {other}, not active")),
			None => return json_error(404, "no such collector"),
		}
		self.sql.exec(
			"INSERT INTO collector_grants (collector_id, case_id, granted_by, granted_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT (collector_id, case_id) DO NOTHING",
			Some(vec![id.into(), case.into(), me.id.into()]),
		)?;
		self.audit(actor, "collector.grant", case, Some(&serde_json::json!({ "collector": id }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "collector": id, "cases": self.collector_cases(id)? }))?)
	}

	pub(super) async fn collector_ungrant(&self, actor: &str, case: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let manager = self.grant_of(case, &me.id)?.is_some_and(|g| g.permission == "manage");
		if !manager && me.role != "lead" {
			return json_error(403, "only a manager of the case, or a lead, removes a collector from it");
		}
		self.sql.exec("DELETE FROM collector_grants WHERE collector_id = ?1 AND case_id = ?2", Some(vec![id.into(), case.into()]))?;
		self.audit(actor, "collector.ungrant", case, Some(&serde_json::json!({ "collector": id }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "collector": id, "cases": self.collector_cases(id)? }))?)
	}

	/// `GET collector-auth/<common_name>` — the Worker's question on every
	/// request a service token makes: which ACTIVE collector is this, and
	/// where may it drop? 404 for anything else (pending, revoked, unknown).
	pub(super) async fn collector_auth(&self, common_name: &str) -> Result<Response> {
		let rows: Vec<CollectorRow> = self
			.sql
			.exec(&format!("{SELECT}, 0 AS expired FROM collectors WHERE common_name = ?1 AND approved_at IS NOT NULL AND revoked_at IS NULL"), Some(vec![common_name.into()]))?
			.to_array()?;
		let Some(r) = rows.into_iter().next() else { return json_error(404, "this service token is not a registered, active collector") };
		Ok(Response::from_json(&serde_json::json!({ "id": r.id, "name": r.name, "keyId": r.key_id, "cases": self.collector_cases(&r.id)? }))?)
	}
}
