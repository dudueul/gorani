// Copyright 2026- Seongwoo Hong. All rights reserved.
// The change-feed and tombstone design follows Mailflare's files store
// (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! `GoraniMemberDO` — one family member's database (instance `member:<id>`).
//!
//! A SQLite database per member: the vault settings (public keys and *sealed*
//! private copies), the files store (rows, folders, versions), the change
//! feed, the audit log — and, in later commits, devices, shares, requests
//! and music metadata. The schema is created whole (migration v1) so later
//! commits never re-migrate; the tables fill as their routes land.
//!
//! # What the server can see (docs/VAULT.md's table, member edition)
//!
//! | Column | Readable? |
//! |---|---|
//! | file sizes, version numbers, times, folder *shape*, ids | yes (structure) |
//! | file names, types, folder names, extracted text, dates inside documents | **no** — sealed text (`GV01:`/`GV02:`/`GV03:`) |
//! | content keys | stored **wrapped** to a store key; the server cannot open them |
//! | vault settings | public halves + wrapped private copies only |
//!
//! # The change feed (docs/DESKTOP.md's cursor)
//!
//! Every change to a file, folder or version row takes the next number of
//! **one counter** — enforced by SQLite triggers, so no write path can miss
//! it (the DO code never increments by hand). The journal is the feed:
//! `files_journal(seq, kind, data, at)` is paged by `seq`, deletions leave
//! rows marked deleted (tombstones), and permanent purges leave their own
//! entries. The journal doubles as the point-in-time restore source
//! (kept 180 days by the daily housekeeping, commit ⑫).
//!
//! ```text
//! files_seq (one row, the counter)  ◀── triggers bump ──▶ files_journal (append-only)
//! ```

use serde::Deserialize;
use worker::{durable_object, DurableObject, Env, Error, Request, Response, Result, State};

use crate::family::json_error;
use crate::devices::EnrolBody;

pub const MIGRATIONS: &[&str] = &[
	// Vault settings: one row. The JSON carries public halves, unlock methods
	// (wrapped private copies), store keys, and the family links
	// (masterSealed for parents, guardian.* for children) — shared/family.ts
	// is the authoritative shape.
	"CREATE TABLE IF NOT EXISTS vault (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
	// The member's own audit log. Free-text details are sealed; structure is
	// readable (docs/APPS.md's audit rules).
	"CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
		target TEXT NOT NULL, details_sealed TEXT
	)",
	// ── Files: folders (tree in SQL only — R2/S3 stays flat), files, versions.
	"CREATE TABLE IF NOT EXISTS file_folders (
		id TEXT PRIMARY KEY,
		parent_id TEXT REFERENCES file_folders(id),
		name_sealed TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT,
		trashed_with TEXT
	)",
	"CREATE TABLE IF NOT EXISTS files (
		id TEXT PRIMARY KEY,
		folder_id TEXT,
		name_sealed TEXT NOT NULL,
		size INTEGER NOT NULL DEFAULT 0,
		version INTEGER NOT NULL DEFAULT 1,
		deleted_at TEXT,
		trashed_with TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)",
	"CREATE TABLE IF NOT EXISTS file_versions (
		file_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		content_key TEXT NOT NULL,
		vault_key_id TEXT,
		object_key TEXT NOT NULL,
		type_sealed TEXT,
		size INTEGER NOT NULL,
		chunk_size INTEGER,
		created_at TEXT NOT NULL,
		PRIMARY KEY (file_id, version)
	)",
	// The files secrets (fingerprint + index keys), sealed to the files store
	// key by the first device that needs them (docs/APPS.md › Files secrets).
	"CREATE TABLE IF NOT EXISTS files_secrets (v TEXT NOT NULL)",
	// ── The change feed: one counter, one append-only journal.
	"CREATE TABLE IF NOT EXISTS files_seq (n INTEGER PRIMARY KEY CHECK (n = 1), v INTEGER NOT NULL DEFAULT 0)",
	"INSERT OR IGNORE INTO files_seq (n, v) VALUES (1, 0)",
	"CREATE TABLE IF NOT EXISTS files_journal (
		seq INTEGER PRIMARY KEY,
		kind TEXT NOT NULL,
		data TEXT NOT NULL,
		at TEXT NOT NULL
	)",
	// ── Devices (docs/DESKTOP.md): each computer's own wrapped copy of the
	// root. token_hash is SHA-256 of the device token — the secret itself is
	// held by the device only.
	"CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		platform TEXT, app_version TEXT,
		key_id TEXT, wrapped TEXT NOT NULL, salt TEXT NOT NULL, protection TEXT,
		token_hash TEXT NOT NULL,
		policy TEXT,
		created_at TEXT NOT NULL, last_seen TEXT, revoked_at TEXT, wipe_at TEXT
	)",
	// ── Share links and file requests (commit ⑪ routes): sealed names, token
	// hashes, expiry and limits. The share's copy object lives in S3, not here.
	"CREATE TABLE IF NOT EXISTS shares (
		id TEXT PRIMARY KEY,
		file_id TEXT NOT NULL, version INTEGER NOT NULL,
		name_sealed TEXT NOT NULL, object_key TEXT NOT NULL, meta_sealed TEXT NOT NULL,
		kdf TEXT, expires_at TEXT NOT NULL, downloads_left INTEGER,
		link_sealed TEXT,
		created_at TEXT NOT NULL, revoked_at TEXT
	)",
	"CREATE TABLE IF NOT EXISTS requests (
		id TEXT PRIMARY KEY,
		folder_id TEXT,
		note_sealed TEXT,
		view_hash TEXT NOT NULL, send_hash TEXT NOT NULL, kdf TEXT,
		expires_at TEXT NOT NULL, max_bytes INTEGER, used_bytes INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL, closed_at TEXT
	)",
	// ── Music metadata (docs/MUSIC.md): one sealed blob per file version, so
	// the library opens from one feed instead of re-reading tags.
	"CREATE TABLE IF NOT EXISTS music_meta (
		file_id TEXT NOT NULL, version INTEGER NOT NULL,
		blob_sealed TEXT NOT NULL,
		PRIMARY KEY (file_id, version)
	)",
	"CREATE TABLE IF NOT EXISTS music_seq (n INTEGER PRIMARY KEY CHECK (n = 1), v INTEGER NOT NULL DEFAULT 0)",
	"INSERT OR IGNORE INTO music_seq (n, v) VALUES (1, 0)",
	// ── Triggers: the write paths never touch the counter themselves.
	"CREATE TRIGGER IF NOT EXISTS files_ins AFTER INSERT ON files BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'file.put',
			json_object('file', json_object('id', NEW.id, 'folder', NEW.folder_id, 'name', NEW.name_sealed, 'size', NEW.size, 'version', NEW.version, 'deleted', NEW.deleted_at IS NOT NULL)),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS files_upd AFTER UPDATE ON files BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'file.put',
			json_object('file', json_object('id', NEW.id, 'folder', NEW.folder_id, 'name', NEW.name_sealed, 'size', NEW.size, 'version', NEW.version, 'deleted', NEW.deleted_at IS NOT NULL)),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS files_del AFTER DELETE ON files BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'file.purge',
			json_object('id', OLD.id),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS folders_ins AFTER INSERT ON file_folders BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'folder.put',
			json_object('folder', json_object('id', NEW.id, 'parent', NEW.parent_id, 'name', NEW.name_sealed, 'deleted', NEW.deleted_at IS NOT NULL)),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS folders_upd AFTER UPDATE ON file_folders BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'folder.put',
			json_object('folder', json_object('id', NEW.id, 'parent', NEW.parent_id, 'name', NEW.name_sealed, 'deleted', NEW.deleted_at IS NOT NULL)),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS folders_del AFTER DELETE ON file_folders BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'folder.purge',
			json_object('id', OLD.id),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS versions_ins AFTER INSERT ON file_versions BEGIN
		INSERT INTO files_journal (seq, kind, data, at)
		SELECT (SELECT v FROM files_seq WHERE n = 1) + 1, 'version.put',
			json_object('file', NEW.file_id, 'version', NEW.version, 'key', NEW.content_key, 'vaultKeyId', NEW.vault_key_id, 'object', NEW.object_key, 'type', NEW.type_sealed, 'size', NEW.size, 'chunk', NEW.chunk_size),
			strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
		UPDATE files_seq SET v = v + 1 WHERE n = 1;
	END",
	"CREATE TRIGGER IF NOT EXISTS music_ins AFTER INSERT ON music_meta BEGIN
		UPDATE music_seq SET v = v + 1 WHERE n = 1;
	END",
	// Migration v2 (commit ⑦): upload bookkeeping and duplicate fingerprints.
	"CREATE TABLE IF NOT EXISTS uploads (
		id TEXT PRIMARY KEY,
		object_key TEXT NOT NULL,
		file_id TEXT,
		s3_upload_id TEXT NOT NULL,
		created_at TEXT NOT NULL
	)",
	"ALTER TABLE file_versions ADD COLUMN tag TEXT",
	// Migration v3 (commit ⑧): the member audit gains a readable-details
	// column beside the sealed one (device names and the like are structure,
	// not content).
	"ALTER TABLE audit ADD COLUMN details TEXT",
	// Migration v4 (commit ⑪): share-link copies. The sealed copy lives in
	// S3 under shares/<id>; the row tracks its multipart bookkeeping, the
	// plaintext size (the recipient's progress), and readiness.
	"ALTER TABLE shares ADD COLUMN s3_upload_id TEXT",
	// Migration v5 (commit ⑫): backup manifests (one row per .gbak run).
	// Migration v6 (commit 15): strict ownership (first uploader) + the
	// contributors trail, readable structure like the rest.
	"ALTER TABLE files ADD COLUMN owner TEXT",
	"CREATE TABLE IF NOT EXISTS file_contributors (file_id TEXT NOT NULL, member TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (file_id, member))",
	"CREATE TABLE IF NOT EXISTS backups (
		stamp TEXT PRIMARY KEY,
		kind TEXT NOT NULL,
		size INTEGER NOT NULL,
		entries INTEGER NOT NULL,
		created_at TEXT NOT NULL
	)",
	"ALTER TABLE shares ADD COLUMN ready INTEGER DEFAULT 0",
	"ALTER TABLE shares ADD COLUMN size INTEGER",
];

/// The internal DO API (called only by the Worker, which authenticates first
/// and forwards the actor email):
///
/// | Call | What |
/// |---|---|
/// | `GET /vault` | the member's vault settings, or `null` |
/// | `PUT /vault` | create/replace settings; a different root is refused |
/// | `GET /audit` | the member's audit lines (newest first, paged) |
/// | `POST /audit` | append one line (actor, action, target, detailsSealed) |
/// | `GET /stats` | schema-present + counter values (tests, commit ⑥ only) |
#[durable_object]
pub struct GoraniMemberDO {
	pub(crate) sql: worker::SqlStorage,
	pub(crate) env: Env,
}

impl DurableObject for GoraniMemberDO {
	fn new(state: State, env: Env) -> Self {
		let sql = state.storage().sql();
		for stmt in MIGRATIONS {
			sql.exec(stmt, None).expect("member migration");
		}
		Self { sql, env }
	}

	async fn fetch(&self, req: Request) -> Result<Response> {
		// Errors become JSON with their message: an opaque 500 helps nobody,
		// least of all the tests that must tell refusals from faults.
		match self.dispatch(req).await {
			Ok(r) => Ok(r),
			Err(e) => json_error(500, &e.to_string()),
		}
	}

}

// The files operations live beside the core (worker/src/files_store.rs) —
// same DO, another `impl` block, one module per concern.
pub(crate) fn now_iso() -> String {
	// The DO's SQL clock is the single source of time in this database.
	"strftime".to_string()
}

impl GoraniMemberDO {

	async fn dispatch(&self, mut req: Request) -> Result<Response> {
		let path = req.path().trim_start_matches('/').to_string();
		let actor = req.headers().get("x-gorani-actor")?.unwrap_or_default();
		match (req.method().to_string().as_str(), path.as_str()) {
			("GET", "vault") => self.get_vault().await,
			("PUT", "vault") => {
				let body = req.json::<VaultPut>().await?;
				self.put_vault(&actor, body).await
			}
			("GET", "audit") => self.get_audit().await,
			("POST", "audit") => {
				let body = req.json::<AuditPut>().await?;
				self.audit(&actor, &body.action, &body.target, body.details_sealed.as_deref(), None).await?;
				self.get_audit().await
			}
			("GET", "stats") => self.stats().await,
			// ── Devices (worker/src/devices.rs) ──
			("GET", "devices") => self.devices_list().await,
			("POST", "devices") => {
				let body = req.json::<serde_json::Value>().await?;
				match serde_json::from_value::<EnrolBody>(body) {
					Ok(b) => self.device_enrol(&actor, b).await,
					Err(e) => json_error(400, &format!("bad enrolment: {e}")),
				}
			}
			("POST", id) if id.starts_with("devices/") && id.ends_with("/unlock") => {
				let body = req.json::<serde_json::Value>().await?;
				let token = req.headers().get("x-gorani-device-token")?;
				self.device_unlock(&id["devices/".len()..id.len() - "/unlock".len()], token, body).await
			}
			("POST", id) if id.starts_with("devices/") && id.ends_with("/check") => {
				let token = req.headers().get("x-gorani-device-token")?;
				self.device_check(&id["devices/".len()..id.len() - "/check".len()], token).await
			}
			("PUT", id) if id.starts_with("devices/") && id.ends_with("/key") => {
				let body = req.json::<serde_json::Value>().await?;
				let token = req.headers().get("x-gorani-device-token")?;
				self.device_rekey(&id["devices/".len()..id.len() - "/key".len()], token, body).await
			}
			("POST", id) if id.starts_with("devices/") && id.ends_with("/wiped") => {
				let token = req.headers().get("x-gorani-device-token")?;
				self.device_wiped(&actor, &id["devices/".len()..id.len() - "/wiped".len()], token).await
			}
			("POST", id) if id.starts_with("devices/") && id.ends_with("/leave") => {
				let token = req.headers().get("x-gorani-device-token")?;
				self.device_leave(&actor, &id["devices/".len()..id.len() - "/leave".len()], token).await
			}
			("DELETE", id) if id.starts_with("devices/") => self.device_revoke(&actor, &id["devices/".len()..]).await,
			// ── Vault destruction (crypto-shredding) ──
			("DELETE", "vault") => self.vault_destroy(&actor).await,
			// ── Trash and rotation (worker/src/files_store.rs) ──
			("GET", "files/trash") => self.trash_list().await,
			("POST", "files/trash/restore") => {
				let body = req.json::<serde_json::Value>().await?;
				self.trash_restore(&actor, body).await
			}
			("POST", "files/shares") => {
				let body = req.json::<serde_json::Value>().await?;
				self.share_create(&actor, body).await
			}
			("GET", "files/shares") => self.shares_list().await,
			("GET", id) if id.starts_with("shares/") && id.ends_with("/obj") => {
				self.share_obj(&id["shares/".len()..id.len() - "/obj".len()]).await
			}
			("POST", id) if id.starts_with("shares/") && id.ends_with("/complete") => {
				let body = req.json::<serde_json::Value>().await?;
				self.share_complete(&actor, &id["shares/".len()..id.len() - "/complete".len()], body).await
			}
			("DELETE", id) if id.starts_with("shares/") => self.share_revoke(&actor, &id["shares/".len()..]).await,
			("POST", id) if id.starts_with("shares/") && id.ends_with("/public-meta") => {
				self.share_public_meta(&id["shares/".len()..id.len() - "/public-meta".len()]).await
			}
			("POST", id) if id.starts_with("shares/") && id.ends_with("/claim") => {
				self.share_claim(&id["shares/".len()..id.len() - "/claim".len()]).await
			}
			("POST", id) if id.starts_with("shares/") && id.ends_with("/public-object") => {
				match self.share_public_object(&id["shares/".len()..id.len() - "/public-object".len()]).await {
					Ok(object) => Ok(Response::from_json(&serde_json::json!({ "objectKey": object }))?),
					Err(resp) => Ok(resp),
				}
			}
			("PUT", "backup-key") => {
				let body = req.json::<serde_json::Value>().await?;
				self.backup_key_put(&actor, body).await
			}
			("GET", "backup-key") => self.backup_key_get().await,
			("POST", "backup/run") => {
				let body = req.json::<serde_json::Value>().await?;
				self.backup_run(&actor, body).await
			}
			("GET", "backups") => self.backups_list().await,
			("GET", id) if id.starts_with("backups/") => self.backup_object(&id["backups/".len()..]).await,
			("POST", "backup/restore") => {
				let body = req.json::<serde_json::Value>().await?;
				self.backup_restore(&actor, body).await
			}
			("POST", "housekeeping") => {
				let body = req.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
				self.housekeeping(&actor, body).await
			}
			("POST", "cron") => {
				let body = req.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
				self.cron_pass(&actor, body).await
			}
			("GET", "music/feed") => self.music_feed().await,
			("PUT", "files/reseal") => {
				let body = req.json::<serde_json::Value>().await?;
				self.files_reseal(&actor, body).await
			}
			("GET", id) if id.starts_with("files-object/") => {
				let rest = &id["files-object/".len()..];
				let (file_id, version) = match rest.split_once('?') {
					Some((f, qs)) => (f, urlquery(qs).get("version").and_then(|x| x.parse::<i64>().ok())),
					None => (rest, None),
				};
				self.file_object_route(file_id, version).await
			}
			// ── Files (implemented in worker/src/files_store.rs) ──
			("POST", "files/put") => {
				let body = req.json::<serde_json::Value>().await?;
				self.file_put(&actor, body).await
			}
			("POST", "files/versions") => {
				let body = req.json::<serde_json::Value>().await?;
				self.file_version_put(&actor, body).await
			}
			("GET", "files/list") => self.files_list(req).await,
			("POST", "files/keys") => {
				let body = req.json::<serde_json::Value>().await?;
				self.files_keys(body).await
			}
			("GET", "files/changes") => self.files_changes(req).await,
			("GET", "files/match") => self.files_match(req).await,
			("GET", "files/secrets") => self.secrets_get().await,
			("PUT", "files/secrets") => {
				let body = req.json::<serde_json::Value>().await?;
				self.secrets_put(&actor, body).await
			}
			("GET", "files/meta") => self.files_meta(req).await,
			("POST", "files/folders") => {
				let body = req.json::<serde_json::Value>().await?;
				self.folder_put(&actor, body).await
			}
			("PATCH", id) if id.starts_with("files-folders/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.folder_patch(&actor, &id["files-folders/".len()..], body).await
			}
			("DELETE", id) if id.starts_with("files-folders/") => self.folder_trash(&actor, &id["files-folders/".len()..]).await,
			("PATCH", id) if id.starts_with("files/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.file_patch(&actor, &id["files/".len()..], body).await
			}
			("DELETE", id) if id.starts_with("files/") => self.file_trash(&actor, &id["files/".len()..]).await,
			("POST", "uploads/start") => {
				let body = req.json::<serde_json::Value>().await?;
				self.upload_start(&actor, body).await
			}
			("GET", id) if id.starts_with("uploads/") => self.upload_get(&id["uploads/".len()..]).await,
			("PUT", id) if id.starts_with("uploads/") && id.ends_with("/s3") => {
				let body = req.json::<serde_json::Value>().await?;
				let s3_id = body.get("s3UploadId").and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| Error::RustError("missing s3UploadId".into()))?;
				self.upload_set_s3(&id["uploads/".len()..id.len() - "/s3".len()], &s3_id).await
			}
			("POST", id) if id.starts_with("uploads/") && id.ends_with("/complete") => {
				let body = req.json::<serde_json::Value>().await?;
				self.upload_complete(&actor, &id["uploads/".len()..id.len() - "/complete".len()], body).await
			}
			("DELETE", id) if id.starts_with("uploads/") => self.upload_abort(&actor, &id["uploads/".len()..]).await,
			_ => Response::error("Not Found", 404),
		}
	}

	async fn get_vault(&self) -> Result<Response> {
		let row: Option<KvRow> = self.sql.exec("SELECT v FROM vault WHERE k = 'settings'", None)?.to_array::<KvRow>().ok().and_then(|mut r| r.pop());
		Ok(match row {
			Some(r) => Response::from_json(&serde_json::from_str::<serde_json::Value>(&r.v).unwrap_or(serde_json::Value::Null))?,
			None => Response::from_json(&serde_json::Value::Null)?,
		})
	}

	/// Create or replace the settings. The one hard rule (the full guard
	/// arrives with commit ⑧): a settings object naming a **different root**
	/// never replaces an existing one — a stale browser copy could otherwise
	/// orphan keys (docs/VAULT.md › Why a settings save cannot lose keys).
	async fn put_vault(&self, actor: &str, body: VaultPut) -> Result<Response> {
		let existing: Option<KvRow> = self.sql.exec("SELECT v FROM vault WHERE k = 'settings'", None)?.to_array::<KvRow>().ok().and_then(|mut r| r.pop());
		if let Some(row) = existing {
			let old: serde_json::Value = serde_json::from_str(&row.v).unwrap_or(serde_json::Value::Null);
			let old_root = old.get("keyId").and_then(|k| k.as_str());
			let new_root = body.settings.get("keyId").and_then(|k| k.as_str());
			if old_root.is_some() && new_root != old_root {
				return json_error(409, "the vault root cannot change through this call");
			}
			if old.get("enabled").and_then(|e| e.as_bool()) == Some(false) && body.settings.get("enabled").and_then(|e| e.as_bool()) == Some(true) {
				return json_error(409, "turning the vault on is a vault-route decision, not a settings save");
			}
		}
		let v = serde_json::to_string(&body.settings).map_err(|_| Error::RustError("bad settings JSON".into()))?;
		self.sql.exec("INSERT INTO vault (k, v) VALUES ('settings', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", Some(vec![v.into()]))?;
		self.audit(actor, "vault.save", "settings", None, None).await?;
		self.get_vault().await
	}

	async fn get_audit(&self) -> Result<Response> {
		let rows: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details_sealed FROM audit ORDER BY id DESC LIMIT 200", None)?.to_array()?;
		let lines: Vec<serde_json::Value> = rows
			.into_iter()
			.map(|a| {
				serde_json::json!({
					"id": a.id, "at": a.at, "actor": a.actor, "action": a.action,
					"target": a.target, "detailsSealed": a.details_sealed, "details": a.details,
				})
			})
			.collect();
		Ok(Response::from_json(&lines)?)
	}

	pub(crate) async fn audit(&self, actor: &str, action: &str, target: &str, details_sealed: Option<&str>, details: Option<&str>) -> Result<()> {
		// A sealed detail is accepted only in a sealed-text shape; the server
		// stores what it cannot read, and never stores what it can in that
		// column by accident.
		if let Some(d) = details_sealed {
			if !gorani_formats::formats::is_sealed_text(d) {
				return Err(Error::RustError("audit details must be sealed text".into()));
			}
		}
		self.sql
			.exec(
				"INSERT INTO audit (at, actor, action, target, details_sealed, details) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4, ?5)",
				Some(vec![
					actor.into(),
					action.into(),
					target.into(),
					details_sealed.unwrap_or_default().into(),
					details.unwrap_or_default().into(),
				]),
			)
			.map(|_| ())
			.map_err(Error::from)
	}

	/// The retention levers that keep the member database inside its budget
	/// (docs/ARCHITECTURE.md › Growth): the journal and audit are bounded by
	/// age/count, trashed items purge after their window (their sealed
	/// objects go from S3 too), dead share copies are removed. Every knob is
	/// a parameter so tests can force the clocks.
	pub(crate) async fn housekeeping(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let trash_days = body.get("trashDays").and_then(|v| v.as_i64()).unwrap_or(30).max(0);
		let journal_days = body.get("journalDays").and_then(|v| v.as_i64()).unwrap_or(180).max(0);
		let audit_keep = body.get("auditKeep").and_then(|v| v.as_i64()).unwrap_or(500).max(1);
		let share_days = body.get("shareDays").and_then(|v| v.as_i64()).unwrap_or(1).max(0);

		// 1. Trash purge: sealed objects leave S3, rows leave (triggers
		// journal the purge).
		let mut purged_objects: Vec<String> = Vec::new();
		let purged_files: Vec<ObjRow> = self
			.sql
			.exec(
				&format!("SELECT v.object_key AS object_key FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.deleted_at IS NOT NULL AND f.deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{trash_days} days')"),
				None,
			)?
			.to_array()?;
		for r in &purged_files {
			purged_objects.push(r.object_key.clone());
		}
		let n_files_purged = self
			.sql
			.exec(
				&format!("DELETE FROM files WHERE deleted_at IS NOT NULL AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{trash_days} days')"),
				None,
			)?
			.rows_written();
		let n_folders_purged = self
			.sql
			.exec(
				&format!("DELETE FROM file_folders WHERE deleted_at IS NOT NULL AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{trash_days} days')"),
				None,
			)?
			.rows_written();

		// 2. Dead share copies: revoked or expired past the grace window.
		let dead_shares: Vec<ShareObjRow> = self
			.sql
			.exec(
				&format!("SELECT object_key, s3_upload_id FROM shares WHERE (revoked_at IS NOT NULL OR expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')) AND COALESCE(revoked_at, expires_at) < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{share_days} days')"),
				None,
			)?
			.to_array()?;
		for r in &dead_shares {
			purged_objects.push(r.object_key.clone());
		}
		let n_shares_purged = self
			.sql
			.exec(
				&format!("DELETE FROM shares WHERE (revoked_at IS NOT NULL OR expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')) AND COALESCE(revoked_at, expires_at) < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{share_days} days')"),
				None,
			)?
			.rows_written();

		// 3. The journal and the audit: the two append-only tables.
		let journal_pruned = self
			.sql
			.exec(
				&format!("DELETE FROM files_journal WHERE at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{journal_days} days')"),
				None,
			)?
			.rows_written();
		let audit_pruned = self
			.sql
			.exec(
				&format!("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT {audit_keep})"),
				None,
			)?
			.rows_written();

		for key in &purged_objects {
			let _ = crate::s3::delete(&self.env, key).await;
		}
		if !purged_objects.is_empty() || n_files_purged + n_shares_purged > 0 {
			self.audit(actor, "housekeeping.run", "retention", None, Some(&format!("files:{n_files_purged},shares:{n_shares_purged},journal:{journal_pruned},audit:{audit_pruned}"))).await?;
		}
		Ok(Response::from_json(&serde_json::json!({
			"purgedFiles": n_files_purged, "purgedFolders": n_folders_purged, "purgedShares": n_shares_purged,
			"journalPruned": journal_pruned, "auditPruned": audit_pruned, "objectsDeleted": purged_objects.len(),
		}))?)
	}

	/// The nightly pass (worker/src/cron.rs knocks here as the system actor
	/// `cron`): retention housekeeping on the deployment defaults, then
	/// backup-manifest pruning — the newest `keep` .gbak runs survive, older
	/// rows and their S3 objects go. Backups are CREATED by the browser flow
	/// (docs/PRODUCTION.md › Backups): the in-memory GB1 job is sized for
	/// that, so the cron only tends the museum, it doesn't fire the kiln.
	async fn cron_pass(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let keep = body.get("keep").and_then(|v| v.as_i64()).unwrap_or(7).clamp(1, 100);
		let mut house = self.housekeeping(actor, serde_json::json!({})).await?;
		let house: serde_json::Value = house.json().await?;
		let stale: Vec<BackupStamp> = self
			.sql
			.exec(&format!("SELECT stamp FROM backups ORDER BY created_at DESC, stamp DESC LIMIT -1 OFFSET {keep}"), None)?
			.to_array()?;
		let mut pruned = 0u64;
		for r in &stale {
			let _ = crate::s3::delete(&self.env, &format!("backups/{}.gbak", r.stamp)).await;
			self.sql.exec("DELETE FROM backups WHERE stamp = ?1", Some(vec![r.stamp.clone().into()]))?.rows_written();
			pruned += 1;
		}
		self.audit(actor, "cron.pass", "retention", None, Some(&format!("backupsPruned:{pruned}"))).await?;
		Ok(Response::from_json(&serde_json::json!({ "housekeeping": house, "backupsPruned": pruned }))?)
	}

	async fn stats(&self) -> Result<Response> {
		let seq = self.sql.exec("SELECT v FROM files_seq WHERE n = 1", None)?.one::<Count>()?.v;
		let music_seq = self.sql.exec("SELECT v FROM music_seq WHERE n = 1", None)?.one::<Count>()?.v;
		let files = self.sql.exec("SELECT COUNT(*) AS n FROM files", None)?.one::<TotalCount>()?.n;
		// The growth metric (docs/ARCHITECTURE.md › Growth): the number the
		// GoraniFilesDO split watches.
		let db_size = self.sql.database_size();
		Ok(Response::from_json(&serde_json::json!({ "filesSeq": seq, "musicSeq": music_seq, "files": files, "dbSize": db_size }))?)
	}
}

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}
#[derive(serde::Deserialize)]
struct BackupStamp {
	stamp: String,
}
#[derive(serde::Deserialize)]
struct AuditRow {
	id: i64,
	at: String,
	actor: String,
	action: String,
	target: String,
	details_sealed: Option<String>,
	details: Option<String>,
}
#[derive(serde::Deserialize)]
struct ObjRow {
	object_key: String,
}
#[derive(serde::Deserialize)]
struct ShareObjRow {
	object_key: String,
	s3_upload_id: Option<String>,
}
#[derive(serde::Deserialize)]
struct Count {
	v: i64,
}
#[derive(serde::Deserialize)]
struct TotalCount {
	n: i64,
}
#[derive(Debug, Deserialize)]
struct VaultPut {
	settings: serde_json::Value,
}
#[derive(Debug, Deserialize)]
struct AuditPut {
	action: String,
	target: String,
	#[serde(default)]
	details_sealed: Option<String>,
}

/// A tiny query-string reader for the few DO routes that take one (the
/// Worker forwards the caller's query verbatim).
fn urlquery(qs: &str) -> std::collections::BTreeMap<String, String> {
	qs.split('&')
		.filter_map(|pair| {
			let (k, v) = pair.split_once('=')?;
			Some((k.to_string(), v.to_string()))
		})
		.collect()
}