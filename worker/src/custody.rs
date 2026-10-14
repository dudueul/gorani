// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Custody transfers (commit 29g, docs/CUSTODY.md › Stage 6, D5.6) — the
//! case store's half; the client half is web/src/vault/custody.ts.
//!
//! Per evidence file, a chain: the custodian is the uploader (`files.owner`)
//! until a transfer is OFFERED by the custodian and ACCEPTED by the person
//! named, each signing a statement that names the area, the file, the
//! link's number and both people (the offer also the reason's digest).
//!
//! What the store enforces: evidence only; one open offer per file; only
//! the current custodian offers, only the named receiver accepts, only the
//! offerer withdraws; links are numbered 1, 2, 3 … with no gap (the client
//! signs the number, so a server cannot reorder what it shows). What it
//! cannot do — and does not try — is check the signatures: every client
//! checks the whole chain against its own trust (custody.ts › verifyChain).

use worker::{Response, Result};

use crate::family::json_error;
use crate::member::GoraniMemberDO;

#[derive(serde::Deserialize)]
struct CustodyRow {
	seq: i64,
	from_member: String,
	to_member: String,
	reason_sealed: String,
	offered_at: String,
	offer_signature: String,
	accepted_at: Option<String>,
	accept_signature: Option<String>,
	cancelled_at: Option<String>,
}

impl CustodyRow {
	fn json(&self) -> serde_json::Value {
		serde_json::json!({
			"seq": self.seq, "from": self.from_member, "to": self.to_member, "reasonSealed": self.reason_sealed,
			"offeredAt": self.offered_at, "offerSignature": self.offer_signature,
			"acceptedAt": self.accepted_at, "acceptSignature": self.accept_signature, "cancelledAt": self.cancelled_at,
		})
	}
}

#[derive(serde::Deserialize)]
struct OwnerRow {
	owner: Option<String>,
}

/// A base64 signature's shape (the store never verifies one).
fn signature_shape(s: &str) -> bool {
	(40..=200).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

impl GoraniMemberDO {
	fn custody_rows(&self, file: &str) -> Result<Vec<CustodyRow>> {
		self.sql
			.exec("SELECT seq, from_member, to_member, reason_sealed, offered_at, offer_signature, accepted_at, accept_signature, cancelled_at FROM custody WHERE file_id = ?1 ORDER BY seq", Some(vec![file.into()]))?
			.to_array()
	}

	/// The custodian now: the last accepted link's receiver, else the uploader.
	fn custodian(&self, owner: &str, rows: &[CustodyRow]) -> String {
		rows.iter().filter(|r| r.accepted_at.is_some()).last().map(|r| r.to_member.clone()).unwrap_or_else(|| owner.to_string())
	}

	async fn custody_file(&self, file: &str) -> Result<std::result::Result<String, Response>> {
		if !self.is_evidence().await? {
			return Ok(Err(json_error(409, "custody is kept for evidence files (an evidence case)")?));
		}
		let owner: Option<OwnerRow> = self.sql.exec("SELECT owner FROM files WHERE id = ?1", Some(vec![file.into()]))?.to_array::<OwnerRow>()?.into_iter().next();
		match owner {
			Some(OwnerRow { owner: Some(o) }) => Ok(Ok(o)),
			Some(_) => Ok(Err(json_error(409, "this file has no recorded uploader to start its chain")?)),
			None => Ok(Err(json_error(404, "no such file")?)),
		}
	}

	/// `GET files/<id>/custody` — the chain, for the client to verify.
	pub(crate) async fn custody_get(&self, file: &str) -> Result<Response> {
		let owner = match self.custody_file(file).await? {
			Ok(o) => o,
			Err(r) => return Ok(r),
		};
		let rows = self.custody_rows(file)?;
		Ok(Response::from_json(&serde_json::json!({ "owner": owner, "custodian": self.custodian(&owner, &rows), "entries": rows.iter().map(CustodyRow::json).collect::<Vec<_>>() }))?)
	}

	/// `POST files/<id>/custody { seq, to, reasonSealed, signature }` (the Worker adds `member`).
	pub(crate) async fn custody_offer(&self, actor: &str, file: &str, body: serde_json::Value) -> Result<Response> {
		let owner = match self.custody_file(file).await? {
			Ok(o) => o,
			Err(r) => return Ok(r),
		};
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let member = get("member").unwrap_or_default();
		let rows = self.custody_rows(file)?;
		if self.custodian(&owner, &rows) != member {
			return json_error(403, "only the current custodian hands a file over");
		}
		if rows.iter().any(|r| r.accepted_at.is_none() && r.cancelled_at.is_none()) {
			return json_error(409, "an offer for this file is already open — it is accepted or withdrawn first");
		}
		let next = rows.last().map(|r| r.seq).unwrap_or(0) + 1;
		if body.get("seq").and_then(|v| v.as_i64()) != Some(next) {
			return json_error(409, &format!("this is link {next} of the chain (the client signs the number)"));
		}
		let Some(to) = get("to").filter(|t| crate::auth::valid_member_id(t) && *t != member) else { return json_error(400, "to: another member's id") };
		let Some(reason) = get("reasonSealed").filter(|r| gorani_formats::placed::is_placed_text(r)) else { return json_error(400, "the reason must arrive sealed into its place (GV04)") };
		let Some(signature) = get("signature").filter(|s| signature_shape(s)) else { return json_error(400, "signature: the custodian's, over the offer statement") };
		self.sql.exec(
			"INSERT INTO custody (file_id, seq, from_member, to_member, reason_sealed, offered_at, offer_signature) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?6)",
			Some(vec![file.into(), next.into(), member.clone().into(), to.clone().into(), reason.into(), signature.into()]),
		)?;
		self.audit(actor, "custody.offer", file, None, Some(format!("seq:{next},from:{member},to:{to}").as_str())).await?;
		self.custody_get(file).await
	}

	/// `POST files/<id>/custody/<seq>/accept { signature }` — by the receiver named.
	pub(crate) async fn custody_accept(&self, actor: &str, file: &str, seq: i64, body: serde_json::Value) -> Result<Response> {
		if let Err(r) = self.custody_file(file).await? {
			return Ok(r);
		}
		let member = body.get("member").and_then(|v| v.as_str()).unwrap_or_default().to_string();
		let Some(row) = self.custody_rows(file)?.into_iter().find(|r| r.seq == seq) else { return json_error(404, "no such link") };
		if row.to_member != member {
			return json_error(403, "only the person the file was offered to accepts it");
		}
		if row.accepted_at.is_some() || row.cancelled_at.is_some() {
			return json_error(409, "this offer is no longer open");
		}
		let Some(signature) = body.get("signature").and_then(|v| v.as_str()).filter(|s| signature_shape(s)).map(str::to_string) else {
			return json_error(400, "signature: the receiver's, over the acceptance statement");
		};
		self.sql.exec(
			"UPDATE custody SET accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), accept_signature = ?1 WHERE file_id = ?2 AND seq = ?3",
			Some(vec![signature.into(), file.into(), seq.into()]),
		)?;
		self.audit(actor, "custody.accept", file, None, Some(format!("seq:{seq},from:{},to:{member}", row.from_member).as_str())).await?;
		self.custody_get(file).await
	}

	/// `DELETE files/<id>/custody/<seq>` — the offerer withdraws an open offer.
	pub(crate) async fn custody_cancel(&self, actor: &str, file: &str, seq: i64, member: &str) -> Result<Response> {
		if let Err(r) = self.custody_file(file).await? {
			return Ok(r);
		}
		let Some(row) = self.custody_rows(file)?.into_iter().find(|r| r.seq == seq) else { return json_error(404, "no such link") };
		if row.from_member != member {
			return json_error(403, "only the person who offered withdraws the offer");
		}
		if row.accepted_at.is_some() || row.cancelled_at.is_some() {
			return json_error(409, "this offer is no longer open");
		}
		self.sql.exec("UPDATE custody SET cancelled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE file_id = ?1 AND seq = ?2", Some(vec![file.into(), seq.into()]))?;
		self.audit(actor, "custody.cancel", file, None, Some(format!("seq:{seq}").as_str())).await?;
		self.custody_get(file).await
	}
}
