// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Upload links (commit 38, docs/REQUESTS.md): an outsider sends files into
//! a folder of this store, or into a case — sealed in their browser to the
//! area's INBOX key, so nothing they send is readable here, and nothing is
//! filed until a person accepts it.
//!
//! ```text
//! link      /s/r/<id>#<secret>.<inbox key digest>    (the fragment never reaches a server)
//! record    here: folder, inbox key (its public halves, as the owner's browser sent them),
//!           SHA-256 of the view and send tokens (request-crypto.ts), the note sealed with
//!           the link's note key, the label sealed with the store key, expiry, limits,
//!           counters, failed attempts, lock, revocation
//! public    view token → the note, the limits, the inbox key; send token → may upload
//! counted   files and bytes are reserved when an item is RECEIVED (inbox.rs), in the same
//!           synchronous step that checks the limits — two uploads racing for the last
//!           slot cannot both get it
//! locked    after LOCK_AFTER wrong send tokens (a wrong password): every send refused
//!           until the owner revokes it and makes a new link
//! ```
//!
//! What the server could do with these rows: refuse, withhold, or count
//! wrongly. It cannot read an upload (sealed to a key it does not hold),
//! nor put its own inbox key in front of the uploader (their page checks
//! the key against the digest in the link), nor upload without the secret
//! (it stores hashes of tokens derived from it).

use worker::{Response, Result};

use crate::family::json_error;
use crate::member::GoraniMemberDO;

/// Wrong send tokens before a link locks.
pub(crate) const LOCK_AFTER: i64 = 10;
/// The longest a link may stay open (an inbound channel is narrower than a share).
const MAX_DAYS: f64 = 30.0;
/// At most this many files per link, and this many bytes (D12's file limit).
const MAX_FILES: i64 = 1000;
const MAX_BYTES: i64 = 255 * 1024 * 1024 * 1024;

pub(crate) fn is_request_id(s: &str) -> bool {
	s.len() == 22 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn hex64(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// SHA-256 of a token, hex — what request-crypto.ts › tokenHash computes.
fn hash_of(token: &str) -> String {
	gorani_formats::unlock::sha256(&[token.as_bytes()]).iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(serde::Deserialize)]
struct RequestRow {
	id: String,
	folder_id: Option<String>,
	inbox_key_id: String,
	inbox_public: String,
	view_hash: String,
	send_hash: String,
	note_sealed: String,
	label_sealed: String,
	expires_at: String,
	max_files: i64,
	max_bytes: i64,
	files_received: i64,
	bytes_received: i64,
	failed_attempts: i64,
	locked_at: Option<String>,
	revoked_at: Option<String>,
	created_by: String,
	created_at: String,
	expired: i64,
}

const COLUMNS: &str = "id, folder_id, inbox_key_id, inbox_public, view_hash, send_hash, note_sealed, label_sealed, expires_at, max_files, max_bytes, files_received, bytes_received, failed_attempts, locked_at, revoked_at, created_by, created_at, expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now') AS expired";

impl RequestRow {
	/// The owner's view: everything but the token hashes.
	fn json(&self) -> serde_json::Value {
		serde_json::json!({
			"id": self.id, "folderId": self.folder_id, "inboxKeyId": self.inbox_key_id,
			"label": self.label_sealed, "expiresAt": self.expires_at,
			"maxFiles": self.max_files, "maxBytes": self.max_bytes,
			"filesReceived": self.files_received, "bytesReceived": self.bytes_received,
			"failedAttempts": self.failed_attempts, "locked": self.locked_at.is_some(),
			"revoked": self.revoked_at.is_some(), "expired": self.expired != 0,
			"createdBy": self.created_by, "createdAt": self.created_at,
		})
	}

	/// Why the link takes nothing more (for the public routes), or None.
	fn closed(&self) -> Option<(u16, &'static str)> {
		if self.revoked_at.is_some() {
			return Some((404, "no such link"));
		}
		if self.expired != 0 {
			return Some((410, "this link has expired"));
		}
		if self.locked_at.is_some() {
			return Some((423, "this link is locked after too many wrong passwords — ask its owner for a new one"));
		}
		None
	}
}

impl GoraniMemberDO {
	fn request_row(&self, id: &str) -> Result<Option<RequestRow>> {
		let rows: Vec<RequestRow> = self.sql.exec(&format!("SELECT {COLUMNS} FROM upload_requests WHERE id = ?1"), Some(vec![id.into()]))?.to_array()?;
		Ok(rows.into_iter().next())
	}

	/// `POST requests { id, folderId?, inboxKeyId, inboxPublic: { ec, kem }, viewHash, sendHash,
	/// noteSealed, labelSealed, expiresAt, maxFiles, maxBytes, by }` — the owner's browser
	/// made the link. For a member's own area the inbox key must be one of
	/// this store's; for a case the Worker checked it against the registry.
	pub(crate) async fn request_create(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if let Some(msg) = self.vault_gate().await? {
			return json_error(400, &msg);
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(id) = get("id").filter(|i| is_request_id(i)) else { return json_error(400, "id: 22 characters of base64url (request-crypto.ts › newRequestId)") };
		let (Some(view), Some(send)) = (get("viewHash").filter(|h| hex64(h)), get("sendHash").filter(|h| hex64(h))) else {
			return json_error(400, "viewHash and sendHash: SHA-256 (hex) of the tokens the link derives");
		};
		if view == send {
			return json_error(400, "a link has a password: its send token differs from its view token");
		}
		let Some(key_id) = get("inboxKeyId").filter(|k| crate::auth::valid_object_id(k)) else { return json_error(400, "inboxKeyId") };
		let public = body.get("inboxPublic").cloned().unwrap_or_default();
		if !public.get("ec").is_some_and(|e| e.get("x").is_some() && e.get("y").is_some()) || !public.get("kem").and_then(|k| k.as_str()).is_some_and(|k| !k.is_empty()) {
			return json_error(400, "inboxPublic: { ec, kem } — the inbox key the uploader seals to");
		}
		// (request-crypto.ts › sealRequestNote: base64 of "GR01" ‖ nonce ‖ ciphertext.)
		use base64::Engine;
		let Some(note) = get("noteSealed").filter(|n| base64::engine::general_purpose::STANDARD.decode(n).is_ok_and(|b| b.len() >= 32 && b.starts_with(b"GR01"))) else {
			return json_error(400, "noteSealed: sealed with the link's note key (GR01)");
		};
		let Some(label) = get("labelSealed").filter(|l| gorani_formats::placed::is_placed_text(l)) else { return json_error(400, "labelSealed: placed with the store key (GV04)") };
		let Some(expires_at) = get("expiresAt") else { return json_error(400, "expiresAt") };
		let now = worker::Date::now().as_millis() as f64;
		let Some(until) = parse_iso_ms(&expires_at).filter(|t| *t > now && *t <= now + MAX_DAYS * 86_400_000.0 + 300_000.0) else {
			return json_error(400, "expiresAt: in the future, at most 30 days away — an upload link is a narrow door");
		};
		let _ = until;
		let max_files = body.get("maxFiles").and_then(|v| v.as_i64()).filter(|n| (1..=MAX_FILES).contains(n)).unwrap_or(0);
		let max_bytes = body.get("maxBytes").and_then(|v| v.as_i64()).filter(|n| (1..=MAX_BYTES).contains(n)).unwrap_or(0);
		if max_files == 0 || max_bytes == 0 {
			return json_error(400, "maxFiles (1–1000) and maxBytes (up to 255 GiB): a link says how much it takes");
		}
		let folder = get("folderId");
		if let Some(f) = &folder {
			let n = self.sql.exec("SELECT COUNT(*) AS n FROM file_folders WHERE id = ?1 AND deleted_at IS NULL", Some(vec![f.clone().into()]))?.one::<crate::files_store::TotalCount>()?.n;
			if n == 0 {
				return json_error(404, "no such folder");
			}
		}
		// A member's own area: the key must be this store's, and the halves its own.
		if !self.is_case_store().await? {
			let rows: Vec<AreaKeyRow> = self.sql.exec("SELECT key_id, public_key, signature, signed_by, private_sealed, created_at, retired_at FROM area_inbox_keys WHERE key_id = ?1", Some(vec![key_id.clone().into()]))?.to_array()?;
			let Some(k) = rows.into_iter().next() else { return json_error(409, "no such inbox key in this store — make it first") };
			if serde_json::from_str::<serde_json::Value>(&k.public_key).ok().as_ref() != Some(&public) {
				return json_error(409, "inboxPublic is not that inbox key's public halves");
			}
		}
		let by = get("by").unwrap_or_default();
		let taken = self.sql.exec("SELECT COUNT(*) AS n FROM upload_requests WHERE id = ?1", Some(vec![id.clone().into()]))?.one::<crate::files_store::TotalCount>()?.n;
		if taken > 0 {
			return json_error(409, "a link with this id exists");
		}
		self.sql.exec(
			"INSERT INTO upload_requests (id, folder_id, inbox_key_id, inbox_public, view_hash, send_hash, note_sealed, label_sealed, expires_at, max_files, max_bytes, files_received, bytes_received, failed_attempts, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, 0, 0, ?12, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![
				id.clone().into(),
				crate::files_store::bind(folder),
				key_id.into(),
				public.to_string().into(),
				view.into(),
				send.into(),
				note.into(),
				label.into(),
				expires_at.into(),
				max_files.into(),
				max_bytes.into(),
				by.into(),
			]),
		)?;
		self.audit(actor, "request.create", &id, None, None).await?;
		Ok(Response::from_json(&self.request_row(&id)?.map(|r| r.json()).unwrap_or_default())?)
	}

	pub(crate) async fn requests_list(&self) -> Result<Response> {
		let rows: Vec<RequestRow> = self.sql.exec(&format!("SELECT {COLUMNS} FROM upload_requests ORDER BY created_at DESC"), None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "requests": rows.iter().map(RequestRow::json).collect::<Vec<_>>() }))?)
	}

	pub(crate) async fn request_revoke(&self, actor: &str, id: &str) -> Result<Response> {
		let n = self.sql.exec("SELECT COUNT(*) AS n FROM upload_requests WHERE id = ?1 AND revoked_at IS NULL", Some(vec![id.into()]))?.one::<crate::files_store::TotalCount>()?.n;
		if n == 0 {
			return json_error(404, "no such open link");
		}
		self.sql.exec("UPDATE upload_requests SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![id.into()]))?;
		self.audit(actor, "request.revoke", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "id": id, "revoked": true }))?)
	}

	/// `POST requests/<id>/public-meta { view }` — what the uploader's page needs.
	pub(crate) async fn request_public_meta(&self, id: &str, body: serde_json::Value) -> Result<Response> {
		let Some(r) = self.request_row(id)? else { return json_error(404, "no such link") };
		let view = body.get("view").and_then(|v| v.as_str()).unwrap_or_default();
		if hash_of(view) != r.view_hash {
			return json_error(404, "no such link");
		}
		if let Some((status, msg)) = r.closed() {
			return json_error(status, msg);
		}
		Ok(Response::from_json(&serde_json::json!({
			"noteSealed": r.note_sealed, "expiresAt": r.expires_at,
			"filesLeft": (r.max_files - r.files_received).max(0), "bytesLeft": (r.max_bytes - r.bytes_received).max(0),
			"inboxKey": { "keyId": r.inbox_key_id, "publicKey": serde_json::from_str::<serde_json::Value>(&r.inbox_public).unwrap_or_default() },
		}))?)
	}

	/// `POST requests/<id>/check-send { send, size? }` — may this caller send
	/// (a file of `size` bytes)? A wrong token counts toward the lock.
	pub(crate) async fn request_check_send(&self, id: &str, body: serde_json::Value) -> Result<Response> {
		let Some(r) = self.request_row(id)? else { return json_error(404, "no such link") };
		if let Some((status, msg)) = r.closed() {
			return json_error(status, msg);
		}
		let send = body.get("send").and_then(|v| v.as_str()).unwrap_or_default();
		if hash_of(send) != r.send_hash {
			let failed = r.failed_attempts + 1;
			self.sql.exec(
				"UPDATE upload_requests SET failed_attempts = ?1, locked_at = CASE WHEN ?1 >= ?2 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE locked_at END WHERE id = ?3",
				Some(vec![failed.into(), LOCK_AFTER.into(), id.into()]),
			)?;
			if failed >= LOCK_AFTER {
				self.audit("upload-link", "request.locked", id, None, None).await?;
			}
			return json_error(403, "wrong password for this link");
		}
		let size = body.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
		if r.files_received >= r.max_files {
			return json_error(409, "this link has taken all the files it was opened for");
		}
		if r.bytes_received + size > r.max_bytes {
			return json_error(413, "this file is more than the link has left");
		}
		Ok(Response::from_json(&serde_json::json!({ "inboxKeyId": r.inbox_key_id, "folderId": r.folder_id }))?)
	}

	/// Reserve one file of `size` bytes on a link — called by inbox_receive
	/// in the same synchronous step as the item's insert. Err = the refusal.
	pub(crate) fn request_take(&self, id: &str, inbox_key: &str, size: i64) -> Result<std::result::Result<(), (u16, &'static str)>> {
		let Some(r) = self.request_row(id)? else { return Ok(Err((404, "no such link"))) };
		if let Some(closed) = r.closed() {
			return Ok(Err(closed));
		}
		if r.inbox_key_id != inbox_key {
			return Ok(Err((409, "the item is not sealed to this link's inbox key")));
		}
		if r.files_received >= r.max_files || r.bytes_received + size > r.max_bytes {
			return Ok(Err((413, "this link has no room left for that")));
		}
		self.sql.exec("UPDATE upload_requests SET files_received = files_received + 1, bytes_received = bytes_received + ?1 WHERE id = ?2", Some(vec![size.into(), id.into()]))?;
		Ok(Ok(()))
	}

	// ── a member's own inbox keys (commit 38a) ────────────────────────────

	/// `GET inbox-keys` — this store's inbox keys, private halves (sealed
	/// under the files key) included: the owner opens them.
	pub(crate) async fn area_inbox_keys(&self) -> Result<Response> {
		let rows: Vec<AreaKeyRow> = self.sql.exec("SELECT key_id, public_key, signature, signed_by, private_sealed, created_at, retired_at FROM area_inbox_keys ORDER BY created_at", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "inboxKeys": rows.iter().map(AreaKeyRow::json).collect::<Vec<_>>() }))?)
	}

	/// `PUT inbox-key { keyId, publicKey, signature, signedBy, privateSealed }` — the
	/// owner's browser made this store's (next) inbox key; the previous one retires.
	pub(crate) async fn area_inbox_key_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if self.is_case_store().await? {
			return json_error(400, "a case's inbox keys live in the registry (PUT /api/v1/cases/<id>/inbox-key)");
		}
		if let Some(msg) = self.vault_gate().await? {
			return json_error(400, &msg);
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(key_id) = get("keyId").filter(|k| crate::auth::valid_object_id(k)) else { return json_error(400, "keyId") };
		let public = body.get("publicKey").cloned().unwrap_or_default();
		if !public.get("ec").is_some_and(|e| e.get("x").is_some() && e.get("y").is_some()) || !public.get("kem").and_then(|k| k.as_str()).is_some_and(|k| !k.is_empty()) {
			return json_error(400, "publicKey: { ec, kem } — inbox keys are hybrid");
		}
		let Some(signature) = get("signature").filter(|s| !s.is_empty() && s.len() < 200) else { return json_error(400, "signature: the owner's, over stmt(\"gorani-area-inbox-v1\", member, key digest)") };
		let Some(private) = get("privateSealed").filter(|p| gorani_formats::placed::is_placed_text(p)) else { return json_error(400, "privateSealed: sealed under the files key into place store.inbox (GV04)") };
		let n = self.sql.exec("SELECT COUNT(*) AS n FROM area_inbox_keys WHERE key_id = ?1", Some(vec![key_id.clone().into()]))?.one::<crate::files_store::TotalCount>()?.n;
		if n > 0 {
			return json_error(409, "an inbox key with this id exists");
		}
		self.sql.exec("UPDATE area_inbox_keys SET retired_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE retired_at IS NULL", None)?;
		self.sql.exec(
			"INSERT INTO area_inbox_keys (key_id, public_key, signature, signed_by, private_sealed, created_at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![key_id.clone().into(), public.to_string().into(), signature.into(), get("signedBy").unwrap_or_default().into(), private.into()]),
		)?;
		self.audit(actor, "inbox.key", &key_id, None, None).await?;
		self.area_inbox_keys().await
	}

	async fn is_case_store(&self) -> Result<bool> {
		// (A case's store says which case it is — routes.rs › case_open.)
		Ok(self.vault_settings().await?.is_some_and(|s| s.get("case").is_some()))
	}
}

#[derive(serde::Deserialize)]
struct AreaKeyRow {
	key_id: String,
	public_key: String,
	signature: String,
	signed_by: String,
	private_sealed: String,
	created_at: String,
	retired_at: Option<String>,
}

impl AreaKeyRow {
	fn json(&self) -> serde_json::Value {
		serde_json::json!({
			"keyId": self.key_id, "publicKey": serde_json::from_str::<serde_json::Value>(&self.public_key).unwrap_or_default(),
			"signature": self.signature, "signedBy": self.signed_by, "privateSealed": self.private_sealed,
			"createdAt": self.created_at, "retiredAt": self.retired_at,
		})
	}
}

/// RFC 3339 / ISO 8601 (UTC, as browsers write it) → epoch milliseconds.
fn parse_iso_ms(s: &str) -> Option<f64> {
	let ms = js_sys::Date::parse(s);
	(!ms.is_nan()).then_some(ms)
}
