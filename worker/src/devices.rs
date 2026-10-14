// Copyright 2026- Seongwoo Hong. All rights reserved.
// The device-copy design follows Mailflare's desktop sync (Apache 2.0, ©
// Cloudflare, Inc.); see NOTICE.

//! Devices (docs/DESKTOP.md): each enrolled computer holds its **own wrapped
//! copy of the member's root key** — wrapped under a secret only that
//! computer can produce (TPM behind Windows Hello, a Secure Enclave
//! agreement, a keyring + TPM pair). The server keeps the wrapped copy and
//! hands it back **only** to that device's token, and only while enrolled.
//!
//! ```text
//! enrol:  computer wraps the root (it must be able to open it once) → POST /devices
//! unlock: computer proves its token → gets its wrapped copy back → opens with its own secret
//! revoke: the copy is deleted — the computer can never unlock again, even with its PIN
//! ```
//!
//! Neither half is enough alone: the server's copy needs the computer's TPM
//! and its owner; the computer holds nothing it could open without asking
//! the server. Losing one device affects no other.

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use worker::{Response, Result};

use crate::auth;
use crate::family::json_error;
use crate::member::GoraniMemberDO;

fn token() -> String {
	let mut b = [0u8; 32];
	OsRng.fill_bytes(&mut b);
	b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(serde::Deserialize)]
struct DeviceRow {
	id: String,
	name: String,
	platform: Option<String>,
	app_version: Option<String>,
	key_id: Option<String>,
	wrapped: String,
	salt: String,
	protection: Option<String>,
	token_hash: String,
	policy: Option<String>,
	created_at: String,
	last_seen: Option<String>,
	revoked_at: Option<String>,
	wipe_at: Option<String>,
}

/// The enrolment body — `pub(crate)` because member.rs's dispatcher parses it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnrolBody {
	pub name: String,
	#[serde(default)]
	pub platform: Option<String>,
	#[serde(default)]
	pub app_version: Option<String>,
	pub key_id: String,
	pub wrapped: String,
	pub salt: String,
	#[serde(default)]
	pub protection: Option<String>,
}

impl GoraniMemberDO {
	// ── Enrolment (the member's own unlocked session or a parent acts) ──

	/// Enrol a device. The vault must be on, and the wrapped copy must claim
	/// the current root (the client opened it, so it can wrap it).
	pub(crate) async fn device_enrol(&self, actor: &str, body: EnrolBody) -> Result<Response> {
		let settings = self.vault_settings().await?;
		let Some(settings) = settings else { return json_error(400, "the vault is not set up") };
		if settings.get("enabled").and_then(|e| e.as_bool()) != Some(true) {
			return json_error(400, "the vault is off");
		}
		if settings.get("keyId").and_then(|k| k.as_str()) != Some(body.key_id.as_str()) {
			return json_error(409, "the wrapped copy must be of the current root key");
		}
		let id = crate::files_store::uuid();
		let device_token = token();
		self.sql
			.exec(
				"INSERT INTO devices (id, name, platform, app_version, key_id, wrapped, salt, protection, token_hash, policy, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![
					id.clone().into(),
					body.name.clone().into(),
					bind_str(body.platform.clone()),
					bind_str(body.app_version.clone()),
					body.key_id.clone().into(),
					body.wrapped.clone().into(),
					body.salt.clone().into(),
					bind_str(body.protection.clone()),
					auth::sha256_hex(device_token.as_bytes()).into(),
					// The owner's per-computer rules live here; the web UI edits
					// them (commit ⑨), the device only reads them.
					serde_json::json!({ "trusted": false, "hoursLocked": 3, "unusedDays": 30 }).to_string().into(),
				]),
			)
			.map_err(|e| worker::Error::RustError(format!("device insert: {e}")))?;
		self.audit(actor, "device.enrol", &id, None, Some(&format!("{} ({})", body.name, body.platform.clone().unwrap_or_default()))).await?;
		// The token is returned ONCE; only its hash is stored.
		Ok(Response::from_json(&serde_json::json!({ "deviceId": id, "token": device_token }))?)
	}

	/// Prove the device token, or refuse with the reasons a client acts on:
	/// 403 revoked, 410 wipe requested.
	async fn device_auth(&self, id: &str, token_header: Option<String>) -> std::result::Result<DeviceRow, Response> {
		let row = self.device_token_ok(id, token_header).await?;
		if row.revoked_at.is_some() {
			return Err(json_error_raw(403, "revoked"));
		}
		if row.wipe_at.is_some() {
			return Err(json_error_raw(410, "wipe"));
		}
		Ok(row)
	}

	/// The token half alone: the device exists and the caller holds ITS
	/// token (404 / 401 / 403 otherwise) — whatever state it is in.
	///
	/// Split out in the security review (commit 23). The wiped/leave reports
	/// must work for a device that is already revoked or told to wipe, so
	/// they used to call [`Self::device_auth`] and carry on after ANY 403 —
	/// including "wrong device token". The device routes skip the member
	/// scope (the token is their authority), so any Access identity that
	/// knew a device id could revoke anyone's computer with a garbage token.
	/// Now: state may be anything; the token may not.
	async fn device_token_ok(&self, id: &str, token_header: Option<String>) -> std::result::Result<DeviceRow, Response> {
		let Some(token) = token_header else { return Err(json_error_raw(401, "missing device token")) };
		let rows: Vec<DeviceRow> = match self
			.sql
			.exec("SELECT id, name, platform, app_version, key_id, wrapped, salt, protection, token_hash, policy, created_at, last_seen, revoked_at, wipe_at FROM devices WHERE id = ?1", Some(vec![id.into()]))
		{
			Ok(cursor) => match cursor.to_array() {
				Ok(rows) => rows,
				Err(e) => return Err(json_error_raw(500, &e.to_string())),
			},
			Err(e) => return Err(json_error_raw(500, &e.to_string())),
		};
		let Some(row) = rows.into_iter().next() else { return Err(json_error_raw(404, "no such device")) };
		// (A plain comparison is fine here: both sides are SHA-256 digests of a
		// 256-bit random token, so timing reveals nothing usable.)
		if auth::sha256_hex(token.as_bytes()) != row.token_hash {
			return Err(json_error_raw(403, "wrong device token"));
		}
		Ok(row)
	}

	/// Unlock: the device's own wrapped copy of the root, plus the vault
	/// settings it needs (public halves, store keys) to work offline-ish.
	pub(crate) async fn device_unlock(&self, id: &str, token_header: Option<String>, body: serde_json::Value) -> Result<Response> {
		let row = match self.device_auth(id, token_header).await {
			Ok(r) => r,
			Err(resp) => return Ok(resp),
		};
		self.sql.exec("UPDATE devices SET last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now'), app_version = COALESCE(?1, app_version) WHERE id = ?2", Some(vec![bind_str(body.get("appVersion").and_then(|v| v.as_str()).map(str::to_string)), id.into()]))?;
		let Some(settings) = self.vault_settings().await? else { return json_error(400, "the vault is not set up") };
		Ok(Response::from_json(&serde_json::json!({
			"keyId": settings.get("keyId"),
			"wrapped": row.wrapped,
			"salt": row.salt,
			"protection": row.protection,
			"settings": settings,
		}))?)
	}

	/// The same check without the key: liveness + the owner's rules.
	pub(crate) async fn device_check(&self, id: &str, token_header: Option<String>) -> Result<Response> {
		let row = match self.device_auth(id, token_header).await {
			Ok(r) => r,
			Err(resp) => return Ok(resp),
		};
		self.sql.exec("UPDATE devices SET last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![id.into()]))?;
		let policy = row.policy.and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok()).unwrap_or(serde_json::json!({}));
		Ok(Response::from_json(&serde_json::json!({ "policy": policy }))?)
	}

	/// Re-key (after a root rotation): the device re-wraps its copy to the
	/// new root and uploads it.
	pub(crate) async fn device_rekey(&self, id: &str, token_header: Option<String>, body: serde_json::Value) -> Result<Response> {
		let row = match self.device_auth(id, token_header).await {
			Ok(r) => r,
			Err(resp) => return Ok(resp),
		};
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(key_id) = get("keyId") else { return json_error(400, "keyId required") };
		let Some(wrapped) = get("wrapped") else { return json_error(400, "wrapped required") };
		let Some(salt) = get("salt") else { return json_error(400, "salt required") };
		self.sql
			.exec(
				"UPDATE devices SET key_id = ?1, wrapped = ?2, salt = ?3, protection = COALESCE(?4, protection) WHERE id = ?5",
				Some(vec![key_id.into(), wrapped.into(), salt.into(), bind_str(get("protection")), id.into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("rekey: {e}")))?;
		self.audit("device", "device.rekey", &row.id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// The device wiped itself (after a 410): its enrolment is over.
	/// Revoked or wipe-flagged devices may still report — with their token.
	pub(crate) async fn device_wiped(&self, actor: &str, id: &str, token_header: Option<String>) -> Result<Response> {
		if let Err(resp) = self.device_token_ok(id, token_header).await {
			return Ok(resp);
		}
		self.revoke_copy(id)?;
		self.audit(actor, "device.wiped", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// The device left (uninstalled): revoke its copy.
	pub(crate) async fn device_leave(&self, actor: &str, id: &str, token_header: Option<String>) -> Result<Response> {
		if let Err(resp) = self.device_token_ok(id, token_header).await {
			return Ok(resp);
		}
		self.revoke_copy(id)?;
		self.audit(actor, "device.leave", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// Revoke a device AND delete its wrapped root copy. Returns how many
	/// rows changed (0 = unknown or already revoked).
	///
	/// "Revoking deletes the copy" was the design (docs/DESKTOP.md) but the
	/// code only stamped `revoked_at`, keeping `wrapped` + `salt` in the row
	/// forever — so a later DB leak plus the stolen computer's TPM secret
	/// would still open the root. Blanking them is crypto-shredding of that
	/// one copy (the columns are NOT NULL, hence '' rather than NULL).
	fn revoke_copy(&self, id: &str) -> Result<usize> {
		Ok(self
			.sql
			.exec(
				"UPDATE devices SET revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')), wrapped = '', salt = '' WHERE id = ?1 AND wrapped != ''",
				Some(vec![id.into()]),
			)?
			.rows_written())
	}

	/// The member's list (Settings › Devices).
	pub(crate) async fn devices_list(&self) -> Result<Response> {
		let rows: Vec<DeviceRow> = self
			.sql
			.exec("SELECT id, name, platform, app_version, key_id, wrapped, salt, protection, token_hash, policy, created_at, last_seen, revoked_at, wipe_at FROM devices ORDER BY created_at", None)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::Value::Array(
			rows.into_iter()
				.map(|d| {
					serde_json::json!({
						"id": d.id, "name": d.name, "platform": d.platform, "appVersion": d.app_version,
						"keyId": d.key_id, "protection": d.protection,
						"policy": d.policy.and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok()),
						"createdAt": d.created_at, "lastSeen": d.last_seen,
						"revoked": d.revoked_at.is_some(),
					})
				})
				.collect(),
		))?)
	}

	/// Revoke (Settings › Devices, or the member themselves): the wrapped
	/// copy is deleted — the computer can never unlock again.
	pub(crate) async fn device_revoke(&self, actor: &str, id: &str) -> Result<Response> {
		let n = self.revoke_copy(id)?;
		if n == 0 {
			return json_error(404, "no such device");
		}
		self.audit(actor, "device.revoke", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	// ── Vault settings plumbing (shared by vault routes here) ───────────

	pub(crate) async fn vault_settings(&self) -> Result<Option<serde_json::Value>> {
		let rows: Vec<KvRow> = self.sql.exec("SELECT v FROM vault WHERE k = 'settings'", None)?.to_array()?;
		Ok(rows.into_iter().next().and_then(|r| serde_json::from_str(&r.v).ok()))
	}

	/// Crypto-shredding: the settings row goes; every sealed byte stays but
	/// can never be opened again, by anyone (docs/VAULT.md). The Worker
	/// checked the confirm phrase and the destroy secret before calling.
	pub(crate) async fn vault_destroy(&self, actor: &str) -> Result<Response> {
		self.sql.exec("DELETE FROM vault WHERE k = 'settings'", None)?;
		// Every enrolled computer holds a wrapped copy of the same root here.
		// Leaving them would make "destroyed" a lie: a device that kept its
		// secret could ask for its copy back once settings were re-created.
		// (commit 23 — the settings row was the only thing deleted before)
		self.sql.exec("UPDATE devices SET revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')), wrapped = '', salt = ''", None)?;
		self.audit(actor, "vault.destroy", "settings", None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "destroyed": true }))?)
	}
}

fn bind_str(v: Option<String>) -> worker::SqlStorageValue {
	match v {
		Some(s) => worker::SqlStorageValue::String(s),
		None => worker::SqlStorageValue::Null,
	}
}

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}

fn json_error_raw(status: u16, message: &str) -> Response {
	Response::from_json(&serde_json::json!({ "error": message })).unwrap().with_status(status)
}