// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The two-person rule and the legal hold (commit 29f, docs/CUSTODY.md ›
//! Stage 6, D5.7).
//!
//! Some actions on a case must not rest on one person: closing an EVIDENCE
//! case, lifting a legal hold, and (stage 7) exporting a case. Each is a
//! two-step affair:
//!
//! ```text
//! request   a manager of the case, or a lead     signs stmt("gorani-approval-v1", id, action, case, requester)
//! approve   a lead — active, NOT the requester   signs stmt("gorani-approve-v1", id, action, case, requester, approver)
//!           → the action runs in the same request, once
//! ```
//!
//! What this module enforces is POLICY, like a read-only grant: who may
//! ask, who may agree, once, within 7 days. What the signatures add is
//! proof any client can check later against its own trust (identity.ts) —
//! the registry stores them and, as everywhere since commit 27, verifies
//! none of them: a server that skipped this check could close a case, but
//! it could not produce the two signatures a reviewer looks for.
//!
//! The legal hold: PLACED by one person (adding protection never waits),
//! LIFTED only by an approved `hold.release`. The registry is the record;
//! the Worker tells the case's store, which refuses trash and purges
//! nothing while held (files_store.rs, member.rs › housekeeping).

use worker::{Response, Result};

use super::{is_signature, json_error, Count, GoraniFamilyDO};

/// What the two-person rule covers. `case.export` (commit 29h) is approved
/// like the others but runs later: the export it allows CONSUMES it, once
/// (`case_export`).
const ACTIONS: [&str; 3] = ["case.close", "hold.release", "case.export"];
/// A request nobody approved in a week is stale: ask again.
const APPROVAL_DAYS: i64 = 7;

#[derive(serde::Deserialize)]
struct ApprovalRow {
	id: String,
	action: String,
	requested_by: String,
	requested_at: String,
	request_signature: String,
	approved_by: Option<String>,
	approved_at: Option<String>,
	approve_signature: Option<String>,
	cancelled_at: Option<String>,
	#[serde(default)]
	consumed_at: Option<String>,
	#[serde(default)]
	consumed_by: Option<String>,
	/// 1 when the request is older than APPROVAL_DAYS (computed by SQLite).
	expired: i64,
}

impl ApprovalRow {
	fn status(&self) -> &'static str {
		match (&self.approved_at, &self.cancelled_at) {
			(Some(_), _) => "approved",
			(None, Some(_)) => "cancelled",
			(None, None) if self.expired != 0 => "expired",
			_ => "pending",
		}
	}
	fn json(&self, case: &str) -> serde_json::Value {
		serde_json::json!({
			"id": self.id, "case": case, "action": self.action, "status": self.status(),
			"requestedBy": self.requested_by, "requestedAt": self.requested_at, "requestSignature": self.request_signature,
			"approvedBy": self.approved_by, "approvedAt": self.approved_at, "approveSignature": self.approve_signature,
			"cancelledAt": self.cancelled_at, "consumedAt": self.consumed_at, "consumedBy": self.consumed_by,
		})
	}
}

/// A client-chosen approval id: 22–64 of [A-Za-z0-9_-] (it is signed before
/// the server sees it, so the client must choose it).
fn valid_approval_id(id: &str) -> bool {
	(22..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl GoraniFamilyDO {
	fn approval_row(&self, case: &str, id: &str) -> Result<Option<ApprovalRow>> {
		Ok(self
			.sql
			.exec(
				&format!("SELECT id, action, requested_by, requested_at, request_signature, approved_by, approved_at, approve_signature, cancelled_at, consumed_at, consumed_by, (requested_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{APPROVAL_DAYS} days')) AS expired FROM approvals WHERE case_id = ?1 AND id = ?2"),
				Some(vec![case.into(), id.into()]),
			)?
			.to_array::<ApprovalRow>()?
			.into_iter()
			.next())
	}

	/// Is `action` possible on this case right now? (Checked when asked AND
	/// again when approved: the case may have moved on in between.)
	fn action_ready(&self, case: &str, action: &str) -> Result<std::result::Result<(), &'static str>> {
		let Some(c) = self.case_row(case)? else { return Ok(Err("no such case")) };
		Ok(match action {
			"case.close" if c.closed_at.is_some() => Err("the case is already closed"),
			"case.close" if c.kind != "evidence" => Err("a working case closes with one manager — POST /api/v1/cases/<id>/close"),
			"hold.release" if c.hold_at.is_none() => Err("the case is not on hold"),
			// (case.export: any case, open or closed — exporting what was
			// kept is exactly what a closed evidence case is for.)
			_ => Ok(()),
		})
	}

	/// `POST case-approvals/<case> { id, action, signature }` — ask.
	pub(super) async fn approval_request(&self, actor: &str, case: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let manager = self.grant_of(case, &me.id)?.is_some_and(|g| g.permission == "manage");
		if !manager && me.role != "lead" {
			return json_error(403, "only a manager of the case, or a lead, asks for a two-person action");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(id) = get("id").filter(|i| valid_approval_id(i)) else { return json_error(400, "id: 22–64 of [A-Za-z0-9_-], chosen by the client (it is signed)") };
		let Some(action) = get("action").filter(|a| ACTIONS.contains(&a.as_str())) else { return json_error(400, "action: case.close, hold.release or case.export") };
		let Some(signature) = get("signature").filter(|s| is_signature(s)) else { return json_error(400, "signature: the requester's, over the request statement") };
		if let Err(why) = self.action_ready(case, &action)? {
			return json_error(409, why);
		}
		// One open request per case and action: a second would only be a
		// second chance to find a lead who says yes.
		let open = self
			.sql
			.exec(
				&format!("SELECT COUNT(*) AS n FROM approvals WHERE case_id = ?1 AND action = ?2 AND approved_at IS NULL AND cancelled_at IS NULL AND requested_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-{APPROVAL_DAYS} days')"),
				Some(vec![case.into(), action.clone().into()]),
			)?
			.one::<Count>()?
			.n;
		if open > 0 {
			return json_error(409, "a request for this is already waiting for a second lead");
		}
		let inserted = self.sql.exec(
			"INSERT INTO approvals (id, case_id, action, requested_by, requested_at, request_signature) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?5)",
			Some(vec![id.clone().into(), case.into(), action.clone().into(), me.id.clone().into(), signature.into()]),
		);
		if inserted.is_err() {
			return json_error(409, "an approval with this id exists — choose a fresh id");
		}
		self.audit(actor, "approval.request", case, Some(&serde_json::json!({ "id": id, "action": action }))).await?;
		let row = self.approval_row(case, &id)?.ok_or_else(|| worker::Error::RustError("approval vanished".into()))?;
		Ok(Response::from_json(&row.json(case))?)
	}

	/// `GET case-approvals/<case>` — everyone with standing on the case
	/// (a grant, or a lead's or auditor's view) sees its requests.
	pub(super) async fn approvals_list(&self, actor: &str, case: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if self.grant_of(case, &me.id)?.is_none() && me.role != "lead" && me.role != "auditor" {
			return json_error(403, "you are not on this case");
		}
		let rows: Vec<ApprovalRow> = self
			.sql
			.exec(
				&format!("SELECT id, action, requested_by, requested_at, request_signature, approved_by, approved_at, approve_signature, cancelled_at, consumed_at, consumed_by, (requested_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{APPROVAL_DAYS} days')) AS expired FROM approvals WHERE case_id = ?1 ORDER BY requested_at DESC"),
				Some(vec![case.into()]),
			)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "approvals": rows.iter().map(|r| r.json(case)).collect::<Vec<_>>() }))?)
	}

	/// `POST case-approve/<case>/<id> { signature }` — the second person
	/// agrees, and the action runs, here, once.
	pub(super) async fn approval_approve(&self, actor: &str, case: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead approves a two-person action");
		}
		let Some(row) = self.approval_row(case, id)? else { return json_error(404, "no such request") };
		if row.requested_by == me.id {
			return json_error(403, "the second person must be a different lead — you asked for this");
		}
		match row.status() {
			"approved" => return json_error(409, "already approved"),
			"cancelled" => return json_error(409, "the request was cancelled"),
			"expired" => return json_error(409, "the request expired — ask again"),
			_ => {}
		}
		let Some(signature) = body.get("signature").and_then(|v| v.as_str()).filter(|s| is_signature(s)).map(str::to_string) else {
			return json_error(400, "signature: the approver's, over the approval statement");
		};
		if let Err(why) = self.action_ready(case, &row.action)? {
			return json_error(409, why);
		}
		// The action, then the record of who agreed — one request, so a
		// refusal above changed nothing and success changes both.
		match row.action.as_str() {
			"case.close" => {
				self.sql.exec("UPDATE cases SET closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND closed_at IS NULL", Some(vec![case.into()]))?;
			}
			"hold.release" => {
				self.sql.exec("UPDATE cases SET hold_at = NULL, hold_by = NULL WHERE id = ?1", Some(vec![case.into()]))?;
			}
			// Approved now, run later: the export consumes it (case_export).
			"case.export" => {}
			_ => return json_error(400, "unknown action"),
		}
		self.sql.exec(
			"UPDATE approvals SET approved_by = ?1, approved_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), approve_signature = ?2 WHERE id = ?3 AND case_id = ?4",
			Some(vec![me.id.clone().into(), signature.into(), id.into(), case.into()]),
		)?;
		self.audit(actor, "approval.approve", case, Some(&serde_json::json!({ "id": id, "action": row.action, "requestedBy": row.requested_by }))).await?;
		self.audit(actor, &row.action, case, Some(&serde_json::json!({ "approval": id, "requestedBy": row.requested_by, "approvedBy": me.id }))).await?;
		let done = self.approval_row(case, id)?.ok_or_else(|| worker::Error::RustError("approval vanished".into()))?;
		Ok(Response::from_json(&serde_json::json!({ "executed": row.action, "approval": done.json(case) }))?)
	}

	/// `DELETE case-approvals/<case>/<id>` — the requester (or a lead)
	/// withdraws a pending request.
	pub(super) async fn approval_cancel(&self, actor: &str, case: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(row) = self.approval_row(case, id)? else { return json_error(404, "no such request") };
		if row.requested_by != me.id && me.role != "lead" {
			return json_error(403, "only the requester or a lead withdraws a request");
		}
		if row.status() != "pending" {
			return json_error(409, "only a pending request can be withdrawn");
		}
		self.sql.exec("UPDATE approvals SET cancelled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND case_id = ?2", Some(vec![id.into(), case.into()]))?;
		self.audit(actor, "approval.cancel", case, Some(&serde_json::json!({ "id": id, "action": row.action }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// `POST case-export/<case> { approval }` — one of the two people who
	/// agreed runs the export, and the approval is spent: a second package
	/// needs a second approval. Within 7 days of the approval. The registry
	/// records it (`case.export`); the package itself is built in the
	/// exporter's browser (web/src/vault/export.ts), which holds the key.
	pub(super) async fn case_export(&self, actor: &str, case: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(id) = body.get("approval").and_then(|v| v.as_str()) else { return json_error(400, "approval: the id of an approved case.export") };
		let Some(row) = self.approval_row(case, id)? else { return json_error(404, "no such approval") };
		if row.action != "case.export" {
			return json_error(409, "that approval is not for an export");
		}
		if row.approved_at.is_none() {
			return json_error(409, "the export is not approved yet — a second lead must agree");
		}
		if row.consumed_at.is_some() {
			return json_error(409, "this approval was used by an earlier export — each package needs its own");
		}
		if me.id != row.requested_by && Some(&me.id) != row.approved_by.as_ref() {
			return json_error(403, "one of the two people who agreed runs the export");
		}
		let fresh = self
			.sql
			.exec(&format!("SELECT COUNT(*) AS n FROM approvals WHERE id = ?1 AND approved_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now','-{APPROVAL_DAYS} days')"), Some(vec![id.into()]))?
			.one::<Count>()?
			.n;
		if fresh == 0 {
			return json_error(409, "the approval is older than a week — ask again");
		}
		self.sql.exec(
			"UPDATE approvals SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), consumed_by = ?1 WHERE id = ?2 AND case_id = ?3 AND consumed_at IS NULL",
			Some(vec![me.id.clone().into(), id.into(), case.into()]),
		)?;
		self.audit(actor, "case.export", case, Some(&serde_json::json!({ "approval": id, "exporter": me.id, "requestedBy": row.requested_by, "approvedBy": row.approved_by }))).await?;
		let done = self.approval_row(case, id)?.ok_or_else(|| worker::Error::RustError("approval vanished".into()))?;
		Ok(Response::from_json(&serde_json::json!({ "exportId": id, "case": case, "exporter": me.id, "approval": done.json(case) }))?)
	}

	/// `POST case-hold/<case>` — a manager of the case, or a lead, places a
	/// legal hold. One person: adding protection never waits for a second.
	/// Idempotent (a held case stays held, the first time is the record).
	pub(super) async fn case_hold(&self, actor: &str, case: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let manager = self.grant_of(case, &me.id)?.is_some_and(|g| g.permission == "manage");
		if !manager && me.role != "lead" {
			return json_error(403, "only a manager of the case, or a lead, places a legal hold");
		}
		let Some(c) = self.case_row(case)? else { return json_error(404, "no such case") };
		if c.hold_at.is_none() {
			self.sql.exec("UPDATE cases SET hold_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), hold_by = ?1 WHERE id = ?2", Some(vec![me.id.clone().into(), case.into()]))?;
			self.audit(actor, "case.hold", case, None).await?;
		}
		Ok(Response::from_json(&serde_json::json!({ "hold": true }))?)
	}
}
