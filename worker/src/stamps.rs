// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Trusted timestamps on evidence versions (commit 29j, docs/CUSTODY.md ›
//! Stage 7, D5.5) — the case store's half. The TSA client is tsa.rs; the
//! verifier is the client's (web/src/vault/timestamp.ts) and the export's
//! (tools/verify-export.mjs).
//!
//! What a version's token is over: its **imprint**, SHA-256 of the
//! uploader's signature inside the sealed hash record (commit 29d). The
//! client computes it — the store cannot open the record — and sends it
//! with the upload, beside the hash. That choice, over stamping the sealed
//! record itself, is what makes the stamp checkable OUTSIDE the vault: an
//! export carries the opened record, so anyone can hash its signature and
//! compare it with the token, then verify that signature names the content
//! hash. "Bo signed that these are the bytes" + "that signature existed by
//! 17:38 UTC, says a third party" — no step rests on gorani's word.
//!
//! The store cannot check an imprint (it is a hash of something sealed). A
//! client that sends a wrong one gets a stamp that verifies nothing, and
//! every reader reports exactly that — the same failure mode as a wrong
//! hash record.
//!
//! Stamping is the DO's ALARM, never the upload's request: no request
//! waits on a third party, and a TSA that is down backs off (1 s doubling
//! to an hour) instead of slowing every read of the case. The nightly pass
//! runs it too and reports what is still pending.

use base64::Engine;
use worker::{Response, Result};

use crate::family::json_error;
use crate::files_store::TotalCount;
use crate::member::GoraniMemberDO;

/// 64 lowercase hex — a SHA-256, as the client sends it.
pub(crate) fn imprint_shape(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Refuse a malformed imprint, or one without a hash record to belong to.
pub(crate) fn stamp_refusal(hash: Option<&str>, stamp: Option<&str>) -> Option<&'static str> {
	match (hash, stamp) {
		(_, Some(s)) if !imprint_shape(s) => Some("the timestamp imprint is SHA-256 of the hash record's signature: 64 lowercase hex"),
		(None, Some(_)) => Some("a timestamp imprint names the hash record's signature — send the hash with it"),
		_ => None,
	}
}

pub(crate) struct StampReport {
	pub stamped: u64,
	pub failed: u64,
	pub pending: u64,
}

#[derive(serde::Deserialize)]
struct Unstamped {
	file_id: String,
	version: i64,
	stamp_imprint: String,
}

#[derive(serde::Deserialize)]
struct StampRow {
	version: i64,
	stamp_imprint: Option<String>,
	stamp_token: Option<String>,
	stamped_at: Option<String>,
	hash: i64,
}

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}

impl GoraniMemberDO {
	/// An imprint was recorded: wake the stamp pass soon — unless an alarm is
	/// already set (a failing TSA's backoff is never cut short by uploads).
	pub(crate) async fn arm_stamps(&self) -> Result<()> {
		if crate::tsa::configured(&self.env).is_some() && self.state.storage().get_alarm().await?.is_none() {
			self.state.storage().set_alarm(1_000i64).await?;
		}
		Ok(())
	}

	/// Stamp what has an imprint and no token, oldest first, up to 20 per
	/// run. The first failure ends the run: a TSA that is down is asked
	/// once, not twenty times.
	pub(crate) async fn stamp_pass(&self) -> Result<StampReport> {
		let mut report = StampReport { stamped: 0, failed: 0, pending: 0 };
		if crate::tsa::configured(&self.env).is_none() || !self.is_evidence().await? {
			return Ok(report);
		}
		let rows: Vec<Unstamped> = self
			.sql
			.exec("SELECT file_id, version, stamp_imprint FROM file_versions WHERE stamp_imprint IS NOT NULL AND stamp_token IS NULL ORDER BY created_at LIMIT 20", None)?
			.to_array()?;
		for r in rows {
			let mut imprint = [0u8; 32];
			if hex::decode_to_slice(&r.stamp_imprint, &mut imprint).is_err() {
				continue; // refused at insert (imprint_shape); never sent
			}
			match crate::tsa::stamp(&self.env, &imprint).await {
				Ok(Some(s)) => {
					let token = base64::engine::general_purpose::STANDARD.encode(&s.token);
					// `AND stamp_token IS NULL`: the alarm and the nightly pass
					// may both be asking; the first token stays.
					self.sql.exec(
						"UPDATE file_versions SET stamp_token = ?1, stamped_at = ?2 WHERE file_id = ?3 AND version = ?4 AND stamp_token IS NULL",
						Some(vec![token.into(), s.at.into(), r.file_id.into(), r.version.into()]),
					)?;
					report.stamped += 1;
				}
				Ok(None) => break,
				Err(e) => {
					worker::console_error!("gorani: timestamp for {} v{} failed (retried): {e}", r.file_id, r.version);
					report.failed += 1;
					break;
				}
			}
		}
		// Collected items (commit 37b): stamped at receipt, the same way — the
		// imprint is SHA-256 of the COLLECTOR's signature.
		if report.failed == 0 {
			#[derive(serde::Deserialize)]
			struct Item {
				id: String,
				stamp_imprint: String,
			}
			let items: Vec<Item> = self.sql.exec("SELECT id, stamp_imprint FROM inbox_items WHERE stamp_imprint IS NOT NULL AND stamp_token IS NULL ORDER BY received_at LIMIT 20", None)?.to_array()?;
			for r in items {
				let mut imprint = [0u8; 32];
				if hex::decode_to_slice(&r.stamp_imprint, &mut imprint).is_err() {
					continue;
				}
				match crate::tsa::stamp(&self.env, &imprint).await {
					Ok(Some(s)) => {
						let token = base64::engine::general_purpose::STANDARD.encode(&s.token);
						self.sql.exec("UPDATE inbox_items SET stamp_token = ?1, stamped_at = ?2 WHERE id = ?3 AND stamp_token IS NULL", Some(vec![token.into(), s.at.into(), r.id.into()]))?;
						report.stamped += 1;
					}
					Ok(None) => break,
					Err(e) => {
						worker::console_error!("gorani: timestamp for inbox item {} failed (retried): {e}", r.id);
						report.failed += 1;
						break;
					}
				}
			}
		}
		report.pending = self.sql.exec("SELECT (SELECT COUNT(*) FROM file_versions WHERE stamp_imprint IS NOT NULL AND stamp_token IS NULL) + (SELECT COUNT(*) FROM inbox_items WHERE stamp_imprint IS NOT NULL AND stamp_token IS NULL) AS n", None)?.one::<TotalCount>()?.n as u64;
		Ok(report)
	}

	/// The alarm: one pass, then the next wake-up — soon while it makes
	/// progress, later (backoff) while the TSA fails, none when done.
	pub(crate) async fn stamp_alarm(&self) -> Result<()> {
		let r = self.stamp_pass().await?;
		let prev: i64 = self.sql.exec("SELECT v FROM vault WHERE k = 'stamp_backoff'", None)?.to_array::<KvRow>()?.into_iter().next().and_then(|r| r.v.parse().ok()).unwrap_or(0);
		let next = if r.failed > 0 {
			(prev * 2).clamp(1_000, 3_600_000)
		} else {
			0
		};
		self.sql.exec("INSERT INTO vault (k, v) VALUES ('stamp_backoff', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", Some(vec![next.to_string().into()]))?;
		if r.failed > 0 {
			self.state.storage().set_alarm(next).await?;
		} else if r.stamped > 0 && r.pending > 0 {
			self.state.storage().set_alarm(100i64).await?;
		}
		Ok(())
	}

	/// `GET stamps/<file>`: every version's imprint and token (base64 DER),
	/// for the reader's own check — the store vouches for none of them.
	pub(crate) async fn stamps_get(&self, file: &str) -> Result<Response> {
		let rows: Vec<StampRow> = self
			.sql
			.exec("SELECT version, stamp_imprint, stamp_token, stamped_at, hash_sealed IS NOT NULL AS hash FROM file_versions WHERE file_id = ?1 ORDER BY version", Some(vec![file.into()]))?
			.to_array()?;
		if rows.is_empty() {
			return json_error(404, "no such file");
		}
		// Only evidence is stamped (stamp_pass): elsewhere an imprint waits for nothing.
		let configured = crate::tsa::configured(&self.env).is_some() && self.is_evidence().await?;
		let versions: Vec<serde_json::Value> = rows
			.into_iter()
			.map(|r| {
				let status = match (&r.stamp_imprint, &r.stamp_token) {
					(_, Some(_)) => "stamped",
					(Some(_), None) if configured => "pending",
					(Some(_), None) => "no-tsa",
					(None, _) if r.hash != 0 => "no-imprint",
					(None, _) => "unsigned",
				};
				serde_json::json!({ "version": r.version, "status": status, "imprint": r.stamp_imprint, "token": r.stamp_token, "at": r.stamped_at })
			})
			.collect();
		Response::from_json(&serde_json::json!({ "file": file, "versions": versions }))
	}

	/// `PUT stamps/<file> { version, imprint }`: an imprint for a version
	/// recorded without one (before 29j, or by a client that could not sign
	/// then) — re-verification sends it. Only where none is recorded: a
	/// stamp's imprint is never replaced.
	pub(crate) async fn stamps_put(&self, actor: &str, file: &str, body: serde_json::Value) -> Result<Response> {
		let version = body.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
		let imprint = body.get("imprint").and_then(|v| v.as_str()).unwrap_or_default().to_string();
		if !imprint_shape(&imprint) {
			return json_error(400, "the timestamp imprint is SHA-256 of the hash record's signature: 64 lowercase hex");
		}
		let rows: Vec<StampRow> = self
			.sql
			.exec("SELECT version, stamp_imprint, stamp_token, stamped_at, hash_sealed IS NOT NULL AS hash FROM file_versions WHERE file_id = ?1 AND version = ?2", Some(vec![file.into(), version.into()]))?
			.to_array()?;
		let Some(row) = rows.into_iter().next() else { return json_error(404, "no such version") };
		if row.hash == 0 {
			return json_error(400, "this version has no signed hash record — there is no signature to stamp");
		}
		if row.stamp_imprint.is_some() {
			return json_error(409, "this version already has its imprint — a stamp's imprint is never replaced");
		}
		self.sql.exec("UPDATE file_versions SET stamp_imprint = ?1 WHERE file_id = ?2 AND version = ?3 AND stamp_imprint IS NULL", Some(vec![imprint.into(), file.into(), version.into()]))?;
		self.audit(actor, "file.stamp", file, None, Some(&format!("v{version}"))).await?;
		self.arm_stamps().await?;
		self.stamps_get(file).await
	}
}
