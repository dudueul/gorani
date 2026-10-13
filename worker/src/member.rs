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
	sql: worker::SqlStorage,
}

impl DurableObject for GoraniMemberDO {
	fn new(state: State, _env: Env) -> Self {
		let sql = state.storage().sql();
		for stmt in MIGRATIONS {
			sql.exec(stmt, None).expect("member migration");
		}
		Self { sql }
	}

	async fn fetch(&self, mut req: Request) -> Result<Response> {
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
				self.audit(&actor, &body.action, &body.target, body.details_sealed.as_deref()).await?;
				self.get_audit().await
			}
			("GET", "stats") => self.stats().await,
			_ => Response::error("Not Found", 404),
		}
	}
}

impl GoraniMemberDO {
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
		self.audit(actor, "vault.save", "settings", None).await?;
		self.get_vault().await
	}

	async fn get_audit(&self) -> Result<Response> {
		let rows: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details_sealed FROM audit ORDER BY id DESC LIMIT 200", None)?.to_array()?;
		let lines: Vec<serde_json::Value> = rows
			.into_iter()
			.map(|a| {
				serde_json::json!({
					"id": a.id, "at": a.at, "actor": a.actor, "action": a.action,
					"target": a.target, "detailsSealed": a.details_sealed,
				})
			})
			.collect();
		Ok(Response::from_json(&lines)?)
	}

	async fn audit(&self, actor: &str, action: &str, target: &str, details_sealed: Option<&str>) -> Result<()> {
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
				"INSERT INTO audit (at, actor, action, target, details_sealed) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, ?2, ?3, ?4)",
				Some(vec![
					actor.into(),
					action.into(),
					target.into(),
					details_sealed.unwrap_or_default().into(),
				]),
			)
			.map(|_| ())
			.map_err(Error::from)
	}

	async fn stats(&self) -> Result<Response> {
		let seq = self.sql.exec("SELECT v FROM files_seq WHERE n = 1", None)?.one::<Count>()?.v;
		let music_seq = self.sql.exec("SELECT v FROM music_seq WHERE n = 1", None)?.one::<Count>()?.v;
		let files = self.sql.exec("SELECT COUNT(*) AS n FROM files", None)?.one::<TotalCount>()?.n;
		Ok(Response::from_json(&serde_json::json!({ "filesSeq": seq, "musicSeq": music_seq, "files": files }))?)
	}
}

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}
#[derive(serde::Deserialize)]
struct AuditRow {
	id: i64,
	at: String,
	actor: String,
	action: String,
	target: String,
	details_sealed: Option<String>,
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