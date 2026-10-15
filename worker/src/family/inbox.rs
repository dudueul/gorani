// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Case inbox keys (commit 37b, docs/COLLECTORS.md) — what a collector
//! seals to, so that it never holds the case key.
//!
//! ```text
//! make      a manager of the case, in their browser: a fresh hybrid key pair;
//!           public halves + stmt("gorani-inbox-v1", case, inbox key digest) signed by them;
//!           the private half sealed UNDER THE CASE KEY into place case.inbox(area, key id)
//! keep      every key the case ever had — items stay sealed to the key they arrived
//!           under; a new key only RETIRES the old one (collectors seal to the current)
//! rotate    a case-key rotation re-seals every inbox private half under the new
//!           case key, exactly the set this table holds (family.rs › case_rekey)
//! serve     to a collector with a drop grant on an open case: the current key, its
//!           signature, and the registry's identities — the collector checks the
//!           signature against the leads IT pinned (identity.rs › trust_rules)
//! ```
//!
//! The registry checks shapes and policy and verifies no signature, as
//! everywhere: a server that served a key of its own would fail the
//! collector's check, not this one.

use worker::{Response, Result};

use super::{is_signature, json_error, GoraniFamilyDO};

#[derive(serde::Deserialize)]
struct InboxKeyRow {
	key_id: String,
	public_key: String,
	signature: String,
	signed_by: String,
	private_sealed: String,
	created_at: String,
	retired_at: Option<String>,
}

impl InboxKeyRow {
	fn json(&self, private: bool) -> serde_json::Value {
		let mut v = serde_json::json!({
			"keyId": self.key_id,
			"publicKey": serde_json::from_str::<serde_json::Value>(&self.public_key).unwrap_or(serde_json::Value::Null),
			"signature": self.signature, "signedBy": self.signed_by,
			"createdAt": self.created_at, "retiredAt": self.retired_at,
		});
		if private {
			v["privateSealed"] = self.private_sealed.clone().into();
		}
		v
	}
}

const COLUMNS: &str = "key_id, public_key, signature, signed_by, private_sealed, created_at, retired_at";

impl GoraniFamilyDO {
	pub(super) fn inbox_keys(&self, case: &str) -> Result<Vec<InboxKeyRowJson>> {
		let rows: Vec<InboxKeyRow> = self.sql.exec(&format!("SELECT {COLUMNS} FROM case_inbox_keys WHERE case_id = ?1 ORDER BY created_at"), Some(vec![case.into()]))?.to_array()?;
		Ok(rows.into_iter().map(|r| InboxKeyRowJson { key_id: r.key_id.clone(), json: r.json(true) }).collect())
	}

	/// `PUT case-inbox-key/<case> { keyId, publicKey: { ec, kem }, signature, privateSealed }`
	/// — a manager makes the case's (next) inbox key.
	pub(super) async fn inbox_key_put(&self, actor: &str, case: &str, body: serde_json::Value) -> Result<Response> {
		let me = match self.require_manager(actor, case) {
			Ok(m) => m,
			Err(r) => return Ok(r),
		};
		let Some(c) = self.case_row(case)? else { return json_error(404, "no such case") };
		if c.closed_at.is_some() {
			return json_error(409, "the case is closed — nothing more is collected into it");
		}
		if c.prev_key_id.is_some() {
			return json_error(409, "the case key is rotating — finish the rotation first (the inbox key is sealed under the case key)");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(key_id) = get("keyId").filter(|k| crate::auth::valid_object_id(k)) else { return json_error(400, "keyId: the inbox key's id") };
		let public_key = body.get("publicKey").cloned().unwrap_or_default();
		if !public_key.get("ec").is_some_and(|e| e.get("x").is_some() && e.get("y").is_some()) || !public_key.get("kem").and_then(|k| k.as_str()).is_some_and(|k| !k.is_empty()) {
			return json_error(400, "publicKey: { ec: a P-256 JWK, kem: the ML-KEM-768 public key } — inbox keys are hybrid");
		}
		let Some(signature) = get("signature").filter(|s| is_signature(s)) else { return json_error(400, "signature: the manager's, over stmt(\"gorani-inbox-v1\", case, key digest)") };
		let Some(private_sealed) = get("privateSealed").filter(|p| gorani_formats::placed::is_placed_text(p)) else {
			return json_error(400, "privateSealed: the inbox private key sealed under the case key, into its place (GV04)");
		};
		let taken = self.sql.exec("SELECT COUNT(*) AS n FROM case_inbox_keys WHERE case_id = ?1 AND key_id = ?2", Some(vec![case.into(), key_id.clone().into()]))?.one::<super::Count>()?.n;
		if taken > 0 {
			return json_error(409, "the case already has an inbox key with this id");
		}
		self.sql.exec("UPDATE case_inbox_keys SET retired_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE case_id = ?1 AND retired_at IS NULL", Some(vec![case.into()]))?;
		self.sql.exec(
			&format!("INSERT INTO case_inbox_keys (case_id, {COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'), NULL)"),
			Some(vec![case.into(), key_id.clone().into(), public_key.to_string().into(), signature.into(), me.id.clone().into(), private_sealed.into()]),
		)?;
		self.audit(actor, "inbox.key", case, Some(&serde_json::json!({ "keyId": key_id }))).await?;
		self.case_list(actor).await
	}

	/// `GET collector-inbox/<case>/<collector>` — the Worker's question when a
	/// collector asks where to seal: is it granted, is the case open, and
	/// what is the current key — with the identities a collector needs to
	/// check the key's signature against the leads it pinned.
	pub(super) async fn collector_inbox(&self, case: &str, collector: &str) -> Result<Response> {
		let granted = self.sql.exec("SELECT COUNT(*) AS n FROM collector_grants g JOIN collectors c ON c.id = g.collector_id WHERE g.case_id = ?1 AND g.collector_id = ?2 AND c.approved_at IS NOT NULL AND c.revoked_at IS NULL", Some(vec![case.into(), collector.into()]))?.one::<super::Count>()?.n;
		if granted == 0 {
			return json_error(403, "this collector may not drop into that case");
		}
		let Some(c) = self.case_row(case)? else { return json_error(404, "no such case") };
		if c.closed_at.is_some() {
			return json_error(409, "the case is closed — nothing more is collected into it");
		}
		let rows: Vec<InboxKeyRow> = self.sql.exec(&format!("SELECT {COLUMNS} FROM case_inbox_keys WHERE case_id = ?1 AND retired_at IS NULL"), Some(vec![case.into()]))?.to_array()?;
		let Some(key) = rows.into_iter().next() else { return json_error(409, "the case has no inbox key yet — a manager of the case makes one (Team › Cases)") };
		Ok(Response::from_json(&serde_json::json!({ "case": case, "kind": c.kind, "key": key.json(false), "identities": self.identities_json()? }))?)
	}

	/// Is `key_id` the CURRENT inbox key of an open case (a drop's check)?
	pub(super) async fn inbox_key_current(&self, case: &str, key_id: &str) -> Result<Response> {
		let n = self.sql.exec("SELECT COUNT(*) AS n FROM case_inbox_keys k JOIN cases c ON c.id = k.case_id WHERE k.case_id = ?1 AND k.key_id = ?2 AND k.retired_at IS NULL AND c.closed_at IS NULL", Some(vec![case.into(), key_id.into()]))?.one::<super::Count>()?.n;
		Ok(Response::from_json(&serde_json::json!({ "current": n > 0 }))?)
	}
}

/// An inbox key row as the case list carries it.
pub(super) struct InboxKeyRowJson {
	pub key_id: String,
	pub json: serde_json::Value,
}
