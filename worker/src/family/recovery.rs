// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Team recovery in the registry — docs/CASES.md › Recovery and › The
//! protocol, concretely (stage 5, commit 27). The client half is
//! web/src/vault/recovery.ts; this module never holds a key that opens
//! anything. It keeps:
//!
//! | table | what | written by |
//! |---|---|---|
//! | `recovery` | the team recovery key's PUBLIC record (digest, M, holders, the creator's signature) | a lead |
//! | `recovery_shares` | one Shamir share per lead, sealed to that lead's root | the same lead, with the record |
//! | `recovery_copies` | each area key sealed to the recovery public key | the area's holder (the member; a case's manager) |
//! | `ceremonies`, `ceremony_shares` | an open ceremony, and the approvers' shares re-sealed to its ephemeral key | a lead (open), holders (approve) |
//! | `reenrol_drafts` | a locked-out member's new vault settings, waiting for a ceremony | that member |
//!
//! What it enforces is bookkeeping: who may write which row, that rows name
//! the CURRENT recovery key, one open ceremony per target, M approvals
//! before the coordinator gets the material, and the recovery key marked
//! "rotation required" after any completed ceremony. Everything that is a
//! matter of trust — is this the recovery key, is this the coordinator's
//! ephemeral key — is signed, and checked by the clients.

use worker::{Response, Result};

use super::{is_hex256, is_signature, json_error, Count, GoraniFamilyDO};

#[derive(serde::Deserialize)]
struct RecoveryRow {
	key_id: String,
	public_key: String,
	digest: String,
	threshold: i64,
	holders: String,
	created_by: String,
	signature: String,
	rotation_required: i64,
}
#[derive(serde::Deserialize)]
struct ShareRow {
	share_sealed: String,
}
#[derive(serde::Deserialize)]
struct CeremonyRow {
	id: String,
	coordinator: String,
	target: String,
	reason: String,
	ephemeral_public: String,
	ephemeral_digest: String,
	recovery_key_id: String,
	signature: String,
	state: String,
}
#[derive(serde::Deserialize)]
struct ApprovalRow {
	member_id: String,
	share_sealed: String,
}
#[derive(serde::Deserialize)]
struct CopyRow {
	area: String,
	key_id: String,
	updated_at: String,
}
#[derive(serde::Deserialize)]
struct SealedRow {
	sealed: String,
}
#[derive(serde::Deserialize)]
struct DraftRow {
	settings: String,
	root_digest: String,
}

const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

impl GoraniFamilyDO {
	fn recovery_row(&self) -> Result<Option<RecoveryRow>> {
		Ok(self
			.sql
			.exec("SELECT key_id, public_key, digest, threshold, holders, created_by, signature, rotation_required FROM recovery WHERE k = 'current'", None)?
			.to_array::<RecoveryRow>()?
			.into_iter()
			.next())
	}

	fn lead_ids(&self) -> Result<Vec<String>> {
		#[derive(serde::Deserialize)]
		struct Id {
			id: String,
		}
		Ok(self.sql.exec("SELECT id FROM members WHERE active = 1 AND role = 'lead' ORDER BY id", None)?.to_array::<Id>()?.into_iter().map(|r| r.id).collect())
	}

	fn ceremony_row(&self, id: &str) -> Result<Option<CeremonyRow>> {
		Ok(self
			.sql
			.exec("SELECT id, coordinator, target, reason, ephemeral_public, ephemeral_digest, recovery_key_id, signature, state FROM ceremonies WHERE id = ?1", Some(vec![id.into()]))?
			.to_array::<CeremonyRow>()?
			.into_iter()
			.next())
	}

	fn approvals(&self, id: &str) -> Result<Vec<ApprovalRow>> {
		Ok(self.sql.exec("SELECT member_id, share_sealed FROM ceremony_shares WHERE ceremony_id = ?1 ORDER BY member_id", Some(vec![id.into()]))?.to_array()?)
	}

	/// The public recovery record and — for a holder — their own sealed share.
	/// Any member but an external (they hold no area key to copy).
	pub(super) async fn recovery_get(&self, actor: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role == "external" {
			return json_error(403, "external members hold no area key to recover");
		}
		let Some(r) = self.recovery_row()? else { return Ok(Response::from_json(&serde_json::json!({ "recovery": null, "myShare": null }))?) };
		let holders: Vec<String> = serde_json::from_str(&r.holders).unwrap_or_default();
		let my_share = self.sql.exec("SELECT share_sealed FROM recovery_shares WHERE member_id = ?1 AND key_id = ?2", Some(vec![me.id.clone().into(), r.key_id.clone().into()]))?.to_array::<ShareRow>()?.into_iter().next().map(|s| s.share_sealed);
		// Holders that are no longer leads, or leads without a share: a cue
		// to rotate (the client says so; the registry only reports).
		let current = holders == self.lead_ids()?;
		Ok(Response::from_json(&serde_json::json!({
			"recovery": {
				"keyId": r.key_id, "publicKey": serde_json::from_str::<serde_json::Value>(&r.public_key).unwrap_or_default(), "digest": r.digest,
				"threshold": r.threshold, "holders": holders, "createdBy": r.created_by, "signature": r.signature,
				"rotationRequired": r.rotation_required != 0 || !current, "holdersCurrent": current,
			},
			"myShare": my_share,
		}))?)
	}

	/// Set up (or rotate) the team recovery key. The holders are EVERY active
	/// lead — not a subset a single lead picks — and M is at least 2: one
	/// lead can start a rotation, none can make the key theirs alone.
	pub(super) async fn recovery_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead sets up the team recovery key");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let (Some(key_id), Some(digest), Some(signature)) = (get("keyId"), get("digest").filter(|d| is_hex256(d)), get("signature").filter(|s| is_signature(s))) else {
			return json_error(400, "keyId, digest (SHA-256 hex) and signature required");
		};
		let Some(public_key) = body.get("publicKey").filter(|p| p.get("ec").is_some_and(|e| e.is_object()) && p.get("kem").is_some_and(|k| k.is_string())) else {
			return json_error(400, "publicKey { ec, kem } required");
		};
		let threshold = body.get("threshold").and_then(|t| t.as_i64()).unwrap_or(0);
		let mut holders: Vec<String> = body.get("holders").and_then(|h| serde_json::from_value(h.clone()).ok()).unwrap_or_default();
		holders.sort();
		let leads = self.lead_ids()?;
		if holders != leads {
			return json_error(409, "the holders must be exactly the active leads — every lead gets a share");
		}
		if threshold < 2 || threshold as usize > holders.len() {
			return json_error(400, "threshold: at least 2, at most the number of leads (a team of one lead cannot have M-of-N recovery)");
		}
		let shares: std::collections::BTreeMap<String, String> = body
			.get("shares")
			.and_then(|s| s.as_array())
			.map(|list| list.iter().filter_map(|s| Some((s.get("member")?.as_str()?.to_string(), s.get("shareSealed")?.as_str()?.to_string()))).collect())
			.unwrap_or_default();
		if shares.keys().cloned().collect::<Vec<_>>() != holders || shares.values().any(|s| !gorani_formats::formats::is_sealed_text(s)) {
			return json_error(400, "one sealed share per holder, no more, no fewer");
		}
		let previous = self.recovery_row()?.map(|r| r.key_id);
		self.sql.exec("DELETE FROM recovery_shares", None)?;
		for (member, sealed) in &shares {
			self.sql.exec("INSERT INTO recovery_shares (member_id, key_id, share_sealed) VALUES (?1, ?2, ?3)", Some(vec![member.clone().into(), key_id.clone().into(), sealed.clone().into()]))?;
		}
		self.sql.exec(
			&format!("INSERT INTO recovery (k, key_id, public_key, digest, threshold, holders, created_by, signature, created_at, rotation_required) VALUES ('current', ?1, ?2, ?3, ?4, ?5, ?6, ?7, {NOW}, 0) ON CONFLICT (k) DO UPDATE SET key_id = ?1, public_key = ?2, digest = ?3, threshold = ?4, holders = ?5, created_by = ?6, signature = ?7, created_at = {NOW}, rotation_required = 0"),
			Some(vec![key_id.clone().into(), public_key.to_string().into(), digest.into(), threshold.into(), serde_json::to_string(&holders).unwrap_or_default().into(), me.id.into(), signature.into()]),
		)?;
		// Open ceremonies name the old key: their shares cannot combine any more.
		self.sql.exec("UPDATE ceremonies SET state = 'cancelled', closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state IN ('open','applying')", None)?;
		self.sql.exec("DELETE FROM ceremony_shares", None)?;
		self.audit(actor, "recovery.setup", &key_id, Some(&serde_json::json!({ "threshold": threshold, "holders": holders, "replaces": previous }))).await?;
		self.recovery_get(actor).await
	}

	/// Store an area's recovery copy: a member for their own area, a manager
	/// for a case; always under the CURRENT recovery key.
	pub(super) async fn recovery_copy_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let (Some(area), Some(key_id), Some(sealed)) = (get("area"), get("keyId"), get("sealed")) else { return json_error(400, "area, keyId and sealed required") };
		let may = match crate::area::case_of(&area) {
			Some(case) => self.grant_of(case, &me.id)?.is_some_and(|g| g.permission == "manage"),
			None => area == me.id,
		};
		if !may {
			return json_error(403, "a recovery copy is written by the area's holder: the member, or a manager of the case");
		}
		let Some(r) = self.recovery_row()? else { return json_error(409, "the team has no recovery key yet") };
		if r.key_id != key_id {
			return json_error(409, "the copy names an old recovery key — seal it to the current one");
		}
		if !gorani_formats::formats::is_sealed_text(&sealed) {
			return json_error(400, "a recovery copy is sealed text");
		}
		self.sql.exec(
			&format!("INSERT INTO recovery_copies (area, key_id, sealed, updated_by, updated_at) VALUES (?1, ?2, ?3, ?4, {NOW}) ON CONFLICT (area) DO UPDATE SET key_id = ?2, sealed = ?3, updated_by = ?4, updated_at = {NOW}"),
			Some(vec![area.clone().into(), key_id.into(), sealed.into(), me.id.into()]),
		)?;
		self.audit(actor, "recovery.copy", &area, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// Coverage, for leads and auditors: which areas have a copy under the
	/// current key. (No sealed values — nothing here is for opening.)
	pub(super) async fn recovery_copies(&self, actor: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" && me.role != "auditor" {
			return json_error(403, "recovery coverage is for leads and auditors");
		}
		let current = self.recovery_row()?.map(|r| r.key_id);
		let rows: Vec<CopyRow> = self.sql.exec("SELECT area, key_id, updated_at FROM recovery_copies ORDER BY area", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"copies": rows.into_iter().map(|c| serde_json::json!({ "area": c.area, "keyId": c.key_id, "updatedAt": c.updated_at, "current": Some(&c.key_id) == current.as_ref() })).collect::<Vec<_>>(),
		}))?)
	}

	/// A locked-out member's new vault settings, waiting for a ceremony.
	pub(super) async fn reenrol_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(settings) = body.get("settings").filter(|s| s.get("keyId").is_some() && s.get("publicKey").is_some() && s.get("pqPublicKey").is_some()) else {
			return json_error(400, "settings with the new root (keyId, publicKey, pqPublicKey) required");
		};
		let Some(root_digest) = body.get("rootDigest").and_then(|d| d.as_str()).filter(|d| is_hex256(d)) else { return json_error(400, "rootDigest required") };
		self.sql.exec(
			&format!("INSERT INTO reenrol_drafts (member_id, settings, root_digest, at) VALUES (?1, ?2, ?3, {NOW}) ON CONFLICT (member_id) DO UPDATE SET settings = ?2, root_digest = ?3, at = {NOW}"),
			Some(vec![me.id.clone().into(), settings.to_string().into(), root_digest.into()]),
		)?;
		self.audit(actor, "recovery.reenrol", &me.id, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	pub(super) async fn ceremony_open(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "only a lead coordinates a recovery ceremony");
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let (Some(id), Some(target), Some(reason), Some(eph_digest), Some(rec_key), Some(signature)) =
			(get("id").filter(|i| crate::auth::valid_object_id(i)), get("target"), get("reason").filter(|r| !r.trim().is_empty() && r.len() <= 500), get("ephemeralDigest").filter(|d| is_hex256(d)), get("recoveryKeyId"), get("signature").filter(|s| is_signature(s)))
		else {
			return json_error(400, "id, target, reason (≤ 500 chars), ephemeralDigest, recoveryKeyId and the coordinator's signature required");
		};
		let Some(eph) = body.get("ephemeralPublic").filter(|p| p.get("ec").is_some_and(|e| e.is_object()) && p.get("kem").is_some_and(|k| k.is_string())) else { return json_error(400, "ephemeralPublic { ec, kem } required") };
		let Some(r) = self.recovery_row()? else { return json_error(409, "the team has no recovery key") };
		if r.key_id != rec_key {
			return json_error(409, "the ceremony names an old recovery key");
		}
		// The target: a member (who re-enrolled) or a case — with a copy under the current key.
		match crate::area::case_of(&target) {
			Some(case) => {
				if self.case_row(case)?.is_none() {
					return json_error(404, "no such case");
				}
			}
			None => {
				if target == me.id {
					return json_error(400, "another lead coordinates your own recovery");
				}
				if self.sql.exec("SELECT COUNT(*) AS n FROM reenrol_drafts WHERE member_id = ?1", Some(vec![target.clone().into()]))?.one::<Count>()?.n == 0 {
					return json_error(409, "the member has not re-enrolled yet (their new root comes first)");
				}
			}
		}
		if self.sql.exec("SELECT COUNT(*) AS n FROM recovery_copies WHERE area = ?1 AND key_id = ?2", Some(vec![target.clone().into(), r.key_id.clone().into()]))?.one::<Count>()?.n == 0 {
			return json_error(409, "that area has no recovery copy under the current recovery key — there is nothing a ceremony could open");
		}
		if self.sql.exec("SELECT COUNT(*) AS n FROM ceremonies WHERE target = ?1 AND state IN ('open','applying')", Some(vec![target.clone().into()]))?.one::<Count>()?.n > 0 {
			return json_error(409, "a ceremony for that target is already open");
		}
		if self.ceremony_row(&id)?.is_some() {
			return json_error(409, "ceremony id taken");
		}
		self.sql.exec(
			&format!("INSERT INTO ceremonies (id, coordinator, target, reason, ephemeral_public, ephemeral_digest, recovery_key_id, signature, state, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', {NOW})"),
			Some(vec![id.clone().into(), me.id.into(), target.clone().into(), reason.clone().into(), eph.to_string().into(), eph_digest.into(), rec_key.into(), signature.into()]),
		)?;
		self.audit(actor, "recovery.ceremony.open", &id, Some(&serde_json::json!({ "target": target, "reason": reason }))).await?;
		self.ceremonies(actor).await
	}

	/// Every ceremony, for leads (who approve) and auditors (who watch).
	pub(super) async fn ceremonies(&self, actor: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" && me.role != "auditor" {
			return json_error(403, "ceremonies are for leads and auditors");
		}
		let rows: Vec<CeremonyRow> = self.sql.exec("SELECT id, coordinator, target, reason, ephemeral_public, ephemeral_digest, recovery_key_id, signature, state FROM ceremonies ORDER BY created_at DESC LIMIT 100", None)?.to_array()?;
		let mut out = Vec::new();
		for c in rows {
			let approvals: Vec<String> = self.approvals(&c.id)?.into_iter().map(|a| a.member_id).collect();
			out.push(serde_json::json!({
				"id": c.id, "coordinator": c.coordinator, "target": c.target, "reason": c.reason,
				"ephemeralPublic": serde_json::from_str::<serde_json::Value>(&c.ephemeral_public).unwrap_or_default(),
				"ephemeralDigest": c.ephemeral_digest, "recoveryKeyId": c.recovery_key_id, "signature": c.signature,
				"state": c.state, "approvals": approvals,
			}));
		}
		Ok(Response::from_json(&serde_json::json!({ "ceremonies": out }))?)
	}

	/// An approver's share, re-sealed to the ceremony's ephemeral key.
	pub(super) async fn ceremony_approve(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(c) = self.ceremony_row(id)? else { return json_error(404, "no such ceremony") };
		if c.state != "open" {
			return json_error(409, "the ceremony is not open");
		}
		let holds = self.sql.exec("SELECT COUNT(*) AS n FROM recovery_shares WHERE member_id = ?1 AND key_id = ?2", Some(vec![me.id.clone().into(), c.recovery_key_id.clone().into()]))?.one::<Count>()?.n > 0;
		if me.role != "lead" || !holds {
			return json_error(403, "only a lead holding a share of this recovery key approves");
		}
		let Some(sealed) = body.get("shareSealed").and_then(|s| s.as_str()).filter(|s| gorani_formats::formats::is_sealed_text(s)) else { return json_error(400, "shareSealed (sealed to the ceremony's key) required") };
		self.sql.exec(
			&format!("INSERT INTO ceremony_shares (ceremony_id, member_id, share_sealed, at) VALUES (?1, ?2, ?3, {NOW}) ON CONFLICT (ceremony_id, member_id) DO UPDATE SET share_sealed = ?3, at = {NOW}"),
			Some(vec![id.into(), me.id.into(), sealed.into()]),
		)?;
		self.audit(actor, "recovery.ceremony.approve", id, Some(&serde_json::json!({ "target": c.target }))).await?;
		self.ceremonies(actor).await
	}

	/// What the coordinator combines and opens — once M leads approved.
	pub(super) async fn ceremony_material(&self, actor: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(c) = self.ceremony_row(id)? else { return json_error(404, "no such ceremony") };
		if c.coordinator != me.id {
			return json_error(403, "the material goes to the ceremony's coordinator only");
		}
		if c.state != "open" && c.state != "applying" {
			return json_error(409, "the ceremony is not open");
		}
		let Some(r) = self.recovery_row()? else { return json_error(409, "the team has no recovery key") };
		let shares = self.approvals(id)?;
		if (shares.len() as i64) < r.threshold {
			return json_error(409, &format!("{} of {} approvals so far", shares.len(), r.threshold));
		}
		let copy = self.sql.exec("SELECT sealed FROM recovery_copies WHERE area = ?1 AND key_id = ?2", Some(vec![c.target.clone().into(), r.key_id.clone().into()]))?.to_array::<SealedRow>()?.into_iter().next().map(|s| s.sealed);
		let Some(copy) = copy else { return json_error(409, "the target's recovery copy is gone") };
		let (case, draft) = match crate::area::case_of(&c.target) {
			Some(case) => {
				let row = self.case_row(case)?;
				(row.map(|r| serde_json::json!({ "id": r.id, "keyId": r.key_id, "publicKey": serde_json::from_str::<serde_json::Value>(&r.public_key).unwrap_or_default() })), None)
			}
			None => {
				let d = self.sql.exec("SELECT settings, root_digest FROM reenrol_drafts WHERE member_id = ?1", Some(vec![c.target.clone().into()]))?.to_array::<DraftRow>()?.into_iter().next();
				(None, d.map(|d| {
					let s: serde_json::Value = serde_json::from_str(&d.settings).unwrap_or_default();
					serde_json::json!({ "rootDigest": d.root_digest, "root": { "ec": s["publicKey"], "kem": s["pqPublicKey"] } })
				}))
			}
		};
		self.audit(actor, "recovery.ceremony.material", id, Some(&serde_json::json!({ "target": c.target, "approvals": shares.iter().map(|s| s.member_id.clone()).collect::<Vec<_>>() }))).await?;
		Ok(Response::from_json(&serde_json::json!({ "shares": shares.into_iter().map(|s| s.share_sealed).collect::<Vec<_>>(), "copy": copy, "case": case, "draft": draft }))?)
	}

	/// Complete a ceremony. A case: the signed manage grant goes in, and the
	/// ceremony closes. A member: the Worker gets the new settings to write
	/// into the member's store (the ONLY path that changes a vault root), and
	/// the ceremony waits in `applying` until ceremony_close.
	pub(super) async fn ceremony_complete(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(c) = self.ceremony_row(id)? else { return json_error(404, "no such ceremony") };
		if c.coordinator != me.id {
			return json_error(403, "only the coordinator completes a ceremony");
		}
		if c.state != "open" && c.state != "applying" {
			return json_error(409, "the ceremony is not open");
		}
		let Some(r) = self.recovery_row()? else { return json_error(409, "the team has no recovery key") };
		if (self.approvals(id)?.len() as i64) < r.threshold {
			return json_error(409, "not enough approvals");
		}
		match crate::area::case_of(&c.target) {
			Some(case) => {
				let Some(g) = body.get("grant") else { return json_error(400, "grant { member, keyId, keySealed, signature } required") };
				let s = |k: &str| g.get(k).and_then(|v| v.as_str()).map(str::to_string);
				let (Some(member), Some(key_id), Some(key_sealed), Some(signature)) = (s("member"), s("keyId"), s("keySealed"), s("signature").filter(|x| is_signature(x))) else { return json_error(400, "grant { member, keyId, keySealed, signature } required") };
				let Some(row) = self.case_row(case)? else { return json_error(404, "no such case") };
				if key_id != row.key_id || !gorani_formats::formats::is_sealed_text(&key_sealed) {
					return json_error(409, "the recovered grant must carry the case's CURRENT key, sealed");
				}
				let role: Option<String> = self.sql.exec("SELECT role AS id FROM members WHERE id = ?1 AND active = 1", Some(vec![member.clone().into()]))?.to_array::<super::IdRow>()?.into_iter().next().map(|r| r.id);
				if !matches!(role.as_deref(), Some("lead") | Some("analyst")) {
					return json_error(400, "a recovered case goes to an active lead or analyst (it becomes its manager)");
				}
				self.sql.exec(
					&format!("INSERT INTO case_grants (case_id, member_id, permission, key_sealed, key_id, granted_by, granted_at, signature, signed_by) VALUES (?1, ?2, 'manage', ?3, ?4, ?5, {NOW}, ?6, ?5) ON CONFLICT (case_id, member_id) DO UPDATE SET permission = 'manage', key_sealed = ?3, key_id = ?4, granted_by = ?5, granted_at = {NOW}, signature = ?6, signed_by = ?5, expires_at = NULL"),
					Some(vec![case.into(), member.clone().into(), key_sealed.into(), key_id.into(), me.id.clone().into(), signature.into()]),
				)?;
				self.ceremony_finish(actor, &c, &serde_json::json!({ "grantedTo": member })).await?;
				Ok(Response::from_json(&serde_json::json!({ "done": true }))?)
			}
			None => {
				let Some(rec) = body.get("storeRecord").filter(|s| s.get("privateKeySealed").and_then(|p| p.as_str()).is_some_and(gorani_formats::formats::is_sealed_text)) else {
					return json_error(400, "storeRecord (the area key sealed to the new root) required");
				};
				let Some(d) = self.sql.exec("SELECT settings, root_digest FROM reenrol_drafts WHERE member_id = ?1", Some(vec![c.target.clone().into()]))?.to_array::<DraftRow>()?.into_iter().next() else {
					return json_error(409, "the member's re-enrolment is gone");
				};
				let mut settings: serde_json::Value = serde_json::from_str(&d.settings).unwrap_or_default();
				let Some(obj) = settings.as_object_mut() else { return json_error(409, "the re-enrolment draft is not an object") };
				obj.insert("stores".into(), serde_json::json!({ "files": rec }));
				obj.insert("enabled".into(), serde_json::json!(true));
				self.sql.exec("UPDATE ceremonies SET state = 'applying' WHERE id = ?1", Some(vec![id.into()]))?;
				Ok(Response::from_json(&serde_json::json!({ "reroot": { "member": c.target, "settings": settings } }))?)
			}
		}
	}

	/// After the Worker wrote a member's new settings: close the ceremony.
	/// Internal — routes.rs maps no public path here.
	pub(super) async fn ceremony_close(&self, actor: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		let Some(c) = self.ceremony_row(id)? else { return json_error(404, "no such ceremony") };
		if c.coordinator != me.id || c.state != "applying" {
			return json_error(409, "nothing to close");
		}
		self.sql.exec("DELETE FROM reenrol_drafts WHERE member_id = ?1", Some(vec![c.target.clone().into()]))?;
		// Their identity key was sealed to the root they lost: it goes, with
		// every certificate of and by it; they enrol a new one and get it
		// verified again (stage 4's rules).
		self.sql.exec("DELETE FROM identities WHERE member_id = ?1", Some(vec![c.target.clone().into()]))?;
		self.sql.exec("DELETE FROM identity_certs WHERE member_id = ?1 OR by_member = ?1", Some(vec![c.target.clone().into()]))?;
		self.ceremony_finish(actor, &c, &serde_json::json!({ "rerooted": c.target })).await?;
		Ok(Response::from_json(&serde_json::json!({ "done": true }))?)
	}

	async fn ceremony_finish(&self, actor: &str, c: &CeremonyRow, details: &serde_json::Value) -> Result<()> {
		self.sql.exec("DELETE FROM ceremony_shares WHERE ceremony_id = ?1", Some(vec![c.id.clone().into()]))?;
		self.sql.exec("UPDATE ceremonies SET state = 'done', closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![c.id.clone().into()]))?;
		// The key existed whole in one browser: from now on it is owed a rotation.
		self.sql.exec("UPDATE recovery SET rotation_required = 1 WHERE k = 'current'", None)?;
		self.audit(actor, "recovery.ceremony.done", &c.id, Some(&serde_json::json!({ "target": c.target, "outcome": details, "recoveryRotationRequired": true }))).await
	}

	pub(super) async fn ceremony_cancel(&self, actor: &str, id: &str) -> Result<Response> {
		let Some(me) = self.member_by_email(actor)? else { return json_error(403, "not a team member") };
		if me.role != "lead" {
			return json_error(403, "a lead cancels a ceremony");
		}
		let Some(c) = self.ceremony_row(id)? else { return json_error(404, "no such ceremony") };
		if c.state != "open" && c.state != "applying" {
			return json_error(409, "the ceremony is not open");
		}
		self.sql.exec("DELETE FROM ceremony_shares WHERE ceremony_id = ?1", Some(vec![id.into()]))?;
		self.sql.exec("UPDATE ceremonies SET state = 'cancelled', closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![id.into()]))?;
		self.audit(actor, "recovery.ceremony.cancel", id, Some(&serde_json::json!({ "target": c.target }))).await?;
		self.ceremonies(actor).await
	}
}
