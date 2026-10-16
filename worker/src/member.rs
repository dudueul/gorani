// Copyright 2026- Seongwoo Hong. All rights reserved.
// The change-feed and tombstone design follows Mailflare's files store
// (Seongwoo Hong's modified version; Apache 2.0, original © Cloudflare, Inc.); see NOTICE.

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
//! | file names, types, folder names, extracted text, dates inside documents | **no** — placed sealed text (`GV04:`, commit 25) |
//! | content keys | stored **sealed into their place** (GV04) under the store key; the server can neither open them nor make new ones |
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
use crate::files_store::urlquery;

/// APPEND-ONLY: a statement's index is its identity in the schema ledger
/// (schema.rs). Never reorder or edit a shipped line; add new ones at the end.
pub const MIGRATIONS: &[&str] = &[
	// Vault settings: one row. The JSON carries public halves, unlock methods
	// (wrapped private copies), store keys and the identity record —
	// web/src/vault/methods.ts › VaultSettings is the authoritative shape.
	// (Until commit 27c it also carried the family links, masterSealed and
	// guardian.*; the recovery copies that replaced them live in the
	// registry.)
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
	// Migration v7 (commit 25): a backup records the objects it could not
	// include (O9). The first ADD COLUMN written under the ledger
	// (schema.rs) — it runs once per store, then never again.
	"ALTER TABLE backups ADD COLUMN missing INTEGER DEFAULT 0",
	// Migration v8 (commit 25): the deletion outbox (O10). An object key is
	// queued in the same pass that removes the row pointing at it, and leaves
	// the queue only once storage confirms the delete — so a failed delete
	// is retried every night instead of orphaning the object for good.
	"CREATE TABLE IF NOT EXISTS pending_deletes (
		key TEXT PRIMARY KEY,
		upload_id TEXT,
		reason TEXT NOT NULL,
		since TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0,
		last_error TEXT
	)",
	// Migration v9 (commit 25): share download tokens (O12). A claim — which
	// spends one download — returns a token; /data serves only to a live
	// token. Stored as SHA-256: a leaked table cannot be replayed.
	"CREATE TABLE IF NOT EXISTS share_tokens (
		hash TEXT PRIMARY KEY,
		share_id TEXT NOT NULL,
		expires_at TEXT NOT NULL
	)",
	// Migration v10 (commit 25): the read log (O14, docs/DECISIONS.md › D10).
	// One MERGED row per reader × file version × client × 5-minute window —
	// a video seek is dozens of range requests, a custody record needs one
	// line: "who read evidence item F, version 3, from what, when".
	"CREATE TABLE IF NOT EXISTS read_log (
		actor TEXT NOT NULL,
		file_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		client TEXT NOT NULL,
		win INTEGER NOT NULL,
		first_at TEXT NOT NULL,
		last_at TEXT NOT NULL,
		requests INTEGER NOT NULL,
		PRIMARY KEY (actor, file_id, version, client, win)
	)",
	// Migration v11 (commit 29c, docs/CUSTODY.md › Stage 3, D6): when an
	// evidence version's object got its COMPLIANCE retention. NULL until the
	// lock lands (the lock pass retries); 'bucket-rule' on R2, whose lock is
	// a bucket rule, not a per-object call.
	"ALTER TABLE file_versions ADD COLUMN locked_until TEXT",
	// Migration v12 (commit 29d, docs/CUSTODY.md › Stage 4, D5.1): the
	// uploader's signed content hash — { sha256 of the plaintext, size,
	// signer, signature } sealed into the place `file.hash(area, file,
	// version)`, so the server stores a claim it can neither read nor
	// forge. Required on evidence (files_store.rs › hash_refusal).
	"ALTER TABLE file_versions ADD COLUMN hash_sealed TEXT",
	// Migration v13 (commit 29e, docs/CUSTODY.md › Stage 5, D8): a malware
	// sample. Readable, because the SERVER enforces what follows from it (no
	// share links; one way); the client's own mark is the sealed type
	// (web/src/vault/samples.ts), which a server cannot clear.
	"ALTER TABLE files ADD COLUMN sample INTEGER NOT NULL DEFAULT 0",
	// Migration v14 (commit 29g, docs/CUSTODY.md › Stage 6, D5.6): an
	// evidence file's intake record (sealed, signed by the uploader), and
	// its custody chain — offers and acceptances, each signed (custody.rs).
	"ALTER TABLE files ADD COLUMN intake_sealed TEXT",
	"CREATE TABLE IF NOT EXISTS custody (
		file_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		from_member TEXT NOT NULL,
		to_member TEXT NOT NULL,
		reason_sealed TEXT NOT NULL,
		offered_at TEXT NOT NULL,
		offer_signature TEXT NOT NULL,
		accepted_at TEXT,
		accept_signature TEXT,
		cancelled_at TEXT,
		PRIMARY KEY (file_id, seq)
	)",
	// Migration v15 (commit 29j, docs/CUSTODY.md › Stage 7, D5.5): an RFC
	// 3161 timestamp per evidence version. The imprint is the client's
	// (SHA-256 of the uploader's signature, which the store cannot open);
	// the token is the TSA's, stored as it came (base64 DER), with the time
	// it states — readable, because a token is a public proof.
	"ALTER TABLE file_versions ADD COLUMN stamp_imprint TEXT",
	"ALTER TABLE file_versions ADD COLUMN stamp_token TEXT",
	"ALTER TABLE file_versions ADD COLUMN stamped_at TEXT",
	// Migration v16 (commit 37b, inbox.rs, docs/COLLECTORS.md): what
	// collectors dropped into a case's inbox, sealed to its inbox key —
	// waiting for a person to accept (into a file) or reject it.
	"CREATE TABLE IF NOT EXISTS inbox_items (
		id TEXT PRIMARY KEY,
		collector_id TEXT NOT NULL,
		inbox_key_id TEXT NOT NULL,
		object_key TEXT NOT NULL,
		size INTEGER NOT NULL,
		chunk_size INTEGER,
		ck_sealed TEXT NOT NULL,
		meta_sealed TEXT NOT NULL,
		stamp_imprint TEXT,
		stamp_token TEXT,
		stamped_at TEXT,
		locked_until TEXT,
		received_at TEXT NOT NULL,
		accepted_at TEXT,
		accepted_by TEXT,
		accepted_file TEXT,
		rejected_at TEXT,
		rejected_by TEXT,
		reject_reason TEXT
	)",
	// Migration v17 (commit 37c, inbox.rs › inbox_accept): an accepted item's
	// collection record — the collector's signed fields, sealed with the case
	// key into place file.collection(area, file), kept beside the file so the
	// collector's signature travels with it (exports, docs/COLLECTORS.md).
	"ALTER TABLE files ADD COLUMN collection_sealed TEXT",
	// Migration v18 (commit 38a/38b, requests.rs, docs/REQUESTS.md): a
	// member's own inbox keys (a case keeps its in the registry) — the
	// private half sealed under the files key into place store.inbox — and
	// the upload links that seal to them.
	"CREATE TABLE IF NOT EXISTS area_inbox_keys (
		key_id TEXT PRIMARY KEY,
		public_key TEXT NOT NULL,
		signature TEXT NOT NULL,
		signed_by TEXT NOT NULL,
		private_sealed TEXT NOT NULL,
		created_at TEXT NOT NULL,
		retired_at TEXT
	)",
	"CREATE TABLE IF NOT EXISTS upload_requests (
		id TEXT PRIMARY KEY,
		folder_id TEXT,
		inbox_key_id TEXT NOT NULL,
		inbox_public TEXT NOT NULL,
		view_hash TEXT NOT NULL,
		send_hash TEXT NOT NULL,
		note_sealed TEXT NOT NULL,
		label_sealed TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		max_files INTEGER NOT NULL,
		max_bytes INTEGER NOT NULL,
		files_received INTEGER NOT NULL,
		bytes_received INTEGER NOT NULL,
		failed_attempts INTEGER NOT NULL,
		locked_at TEXT,
		revoked_at TEXT,
		created_by TEXT NOT NULL,
		created_at TEXT NOT NULL
	)",
	// Migration v19 (commit 39p, docs/VIDEO.md): the video sidecar — one
	// sealed summary per file version (where the moov box is, duration,
	// codecs, the picture's size), sealed under the files key into place
	// file.video(area, file, version) as the music tags are; and its poster
	// frame (39o, place file.poster). Derived data: any client holding the
	// plaintext can make it again, so it rides in no backup and is checked
	// by nothing but its seal.
	"CREATE TABLE IF NOT EXISTS video_meta (
		file_id TEXT NOT NULL, version INTEGER NOT NULL,
		meta_sealed TEXT NOT NULL,
		poster_sealed TEXT,
		written_by TEXT NOT NULL,
		PRIMARY KEY (file_id, version)
	)",
	// Migration v20 (commit 39o, docs/MOVIES.md): where each member left
	// off in a video — sealed under the files key into place
	// file.position(area, file, member), so no other area can be shown it
	// and the server reads none of it. One row per (file, member): a later
	// save replaces it.
	"CREATE TABLE IF NOT EXISTS watch_positions (
		file_id TEXT NOT NULL, member TEXT NOT NULL,
		position_sealed TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		PRIMARY KEY (file_id, member)
	)",
	// Migration v21 (commit 40b, docs/DRM.md): protected copies.
	//
	// `drm_files` is the switch: a row means a lead chose Protect, and from
	// then on the original's bytes go only to those routes.rs › drm says may
	// have them. `drm_copies` is one FairPlay copy per file version — its
	// content key SEALED under the Worker secret DRM_KEY_SECRET (never the
	// store key: the license server must open it, and nobody who holds only
	// this database can), its key id and constant IV (public: they are in the
	// copy's own boxes), where it lives, and its layout (the playlist's byte
	// ranges, written once it is uploaded).
	"CREATE TABLE IF NOT EXISTS drm_files (
		file_id TEXT PRIMARY KEY,
		protected_by TEXT NOT NULL,
		protected_at TEXT NOT NULL
	)",
	"CREATE TABLE IF NOT EXISTS drm_copies (
		file_id TEXT NOT NULL, version INTEGER NOT NULL,
		kid TEXT NOT NULL,
		key_sealed TEXT NOT NULL,
		iv TEXT NOT NULL,
		object_key TEXT NOT NULL,
		upload_id TEXT,
		state TEXT NOT NULL,
		size INTEGER,
		layout TEXT,
		created_by TEXT NOT NULL,
		created_at TEXT NOT NULL,
		ready_at TEXT,
		PRIMARY KEY (file_id, version)
	)",
	// A view-only link plays the protected copy of its file (40b): no
	// sealed copy of its own (object_key stays empty), and its claims are
	// viewing sessions rather than downloads.
	"ALTER TABLE shares ADD COLUMN drm INTEGER NOT NULL DEFAULT 0",
	// …and since its page plays without ever opening a sealed byte, the
	// claim itself must prove the link's secret and password (an ordinary
	// link's data is useless without them; a license is not). The page
	// derives a proof from both; only its SHA-256 is stored.
	"ALTER TABLE shares ADD COLUMN claim_hash TEXT",
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
	/// (commit 29j) The alarm that stamps evidence versions (stamps.rs).
	pub(crate) state: State,
	/// A failed migration, kept instead of panicking (schema.rs): every
	/// request is answered with it until a fixed deploy migrates cleanly.
	schema: std::result::Result<(), String>,
}

impl DurableObject for GoraniMemberDO {
	fn new(state: State, env: Env) -> Self {
		let sql = state.storage().sql();
		// Ledgered (commit 25): the constructor runs on EVERY wake-up, and
		// re-running an ADD COLUMN panicked the second one (schema.rs).
		let schema = crate::schema::migrate(&sql, MIGRATIONS);
		Self { sql, env, schema, state }
	}

	/// The only alarm this DO sets: trusted timestamps for evidence versions
	/// (commit 29j, stamps.rs), off every request's path.
	async fn alarm(&self) -> Result<Response> {
		if self.schema.is_ok() {
			self.stamp_alarm().await?;
		}
		Response::ok("")
	}

	async fn fetch(&self, req: Request) -> Result<Response> {
		if let Err(e) = &self.schema {
			return json_error(500, &format!("member store schema: {e}"));
		}
		// Which area this database is (the Worker names it in
		// `x-gorani-member`; remembered, because not every caller does — a
		// device's token routes, the cron's knock).
		let named = req.headers().get("x-gorani-member").ok().flatten();
		// Errors become JSON with their message: an opaque 500 helps nobody,
		// least of all the tests that must tell refusals from faults.
		let out = match self.dispatch(req).await {
			Ok(r) => Ok(r),
			Err(e) => json_error(500, &e.to_string()),
		};
		// Evidence versions recorded by this request (or left unlocked by an
		// earlier one) get their write-once retention now (D6, commit 29c).
		if let Err(e) = self.lock_pass().await {
			worker::console_error!("gorani: evidence lock pass failed (retried next time): {e}");
		}
		// Ship this request's audit lines (and any a failed ship left) to the
		// area's chained trail. Best effort: the outbox keeps what did not
		// go, and the next request — or tonight's cron — sends it.
		if let Some(area) = self.area(named.as_deref()) {
			if let Err(e) = self.ship_audit(&area).await {
				worker::console_error!("gorani: audit ship for {area} failed (kept in the outbox): {e}");
			}
		}
		out
	}

}

// ── The legal hold (commit 29f, docs/CUSTODY.md › Stage 6, D5.7) ────────

impl GoraniMemberDO {
	/// Is this store under a legal hold? While it is, nothing leaves: trash
	/// is refused (files_store.rs › evidence_refusal) and housekeeping purges
	/// and prunes nothing.
	pub(crate) async fn is_held(&self) -> Result<bool> {
		Ok(self.vault_settings().await?.is_some_and(|s| s.get("hold").and_then(|h| h.as_bool()) == Some(true)))
	}

	/// Bring this store's copy of the hold in line with the registry's
	/// (the record — family/approvals.rs): told by the Worker when the hold
	/// changes, and again by every nightly pass (cron.rs), so a lost call
	/// heals by morning. A change is audited in the case's own trail too:
	/// its history says when the hold began and ended.
	async fn sync_hold(&self, actor: &str, hold: bool) -> Result<()> {
		let Some(mut settings) = self.vault_settings().await? else { return Ok(()) };
		if settings.get("hold").and_then(|h| h.as_bool()).unwrap_or(false) == hold {
			return Ok(());
		}
		settings["hold"] = serde_json::json!(hold);
		let v = serde_json::to_string(&settings).map_err(|_| Error::RustError("bad settings JSON".into()))?;
		self.sql.exec("INSERT INTO vault (k, v) VALUES ('settings', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", Some(vec![v.into()]))?;
		self.audit(actor, if hold { "case.hold" } else { "case.hold.release" }, "settings", None, None).await
	}
}

// ── Re-verification (commit 29h, docs/CUSTODY.md › Stage 7, D5.8) ───────

impl GoraniMemberDO {
	/// A client re-hashed this store's evidence: record WHO, WHEN and the
	/// counts (the store cannot check them — it has no key; the audit line
	/// is the record that someone did, and what they found).
	async fn reverify_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let n = |k: &str| body.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
		let (checked, failed) = (n("checked"), n("failed"));
		let member = body.get("member").and_then(|v| v.as_str()).unwrap_or_default();
		self.sql.exec(
			"INSERT INTO vault (k, v) VALUES ('reverified', json_object('by', ?1, 'checked', ?2, 'failed', ?3, 'at', strftime('%Y-%m-%dT%H:%M:%fZ','now'))) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
			Some(vec![member.into(), (checked as i64).into(), (failed as i64).into()]),
		)?;
		self.audit(actor, "case.reverify", "evidence", None, Some(&format!("checked:{checked},failed:{failed}"))).await?;
		Ok(Response::from_json(&self.reverify_state().await?)?)
	}

	/// The last re-verification, and whether one is owed: an evidence store
	/// with files, never re-verified or last re-verified more than
	/// REVERIFY_DAYS (default 30) ago.
	pub(crate) async fn reverify_state(&self) -> Result<serde_json::Value> {
		let days: i64 = self.env.var("REVERIFY_DAYS").ok().and_then(|v| v.to_string().parse().ok()).unwrap_or(30).max(1);
		let last: Option<serde_json::Value> = self
			.sql
			.exec("SELECT v FROM vault WHERE k = 'reverified'", None)?
			.to_array::<KvRow>()?
			.into_iter()
			.next()
			.and_then(|r| serde_json::from_str(&r.v).ok());
		let evidence = self.is_evidence().await?;
		let files = self.sql.exec("SELECT COUNT(*) AS n FROM files", None)?.one::<crate::files_store::TotalCount>()?.n;
		#[derive(serde::Deserialize)]
		struct Old {
			old: i64,
		}
		let stale = match last.as_ref().and_then(|l| l.get("at")).and_then(|a| a.as_str()) {
			Some(at) => self.sql.exec(&format!("SELECT (?1 < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{days} days')) AS old"), Some(vec![at.into()]))?.one::<Old>()?.old != 0,
			None => true,
		};
		Ok(serde_json::json!({ "last": last, "days": days, "overdue": evidence && files > 0 && stale }))
	}
}

// ── Write-once evidence (commit 29c, docs/CUSTODY.md › Stage 3, D6) ─────

/// What one lock pass did.
pub(crate) struct LockReport {
	pub locked: u64,
	pub failed: u64,
	pub pending: u64,
}

impl GoraniMemberDO {
	/// Lock every evidence version whose object has no retention yet:
	/// COMPLIANCE until its creation + EVIDENCE_RETAIN_DAYS (default 7
	/// years). Nothing to do unless the deployment turned OBJECT_LOCK on
	/// (a bucket created with Object Lock) and this store is evidence.
	pub(crate) async fn lock_pass(&self) -> Result<LockReport> {
		let none = LockReport { locked: 0, failed: 0, pending: 0 };
		if self.env.var("OBJECT_LOCK").map(|v| v.to_string()).unwrap_or_default() != "on" || !self.is_evidence().await? {
			return Ok(none);
		}
		let days: i64 = self.env.var("EVIDENCE_RETAIN_DAYS").ok().and_then(|v| v.to_string().parse().ok()).unwrap_or(2557).max(1);
		#[derive(serde::Deserialize)]
		struct Unlocked {
			file_id: String,
			version: i64,
			object_key: String,
			until: String,
		}
		let rows: Vec<Unlocked> = self
			.sql
			.exec(&format!("SELECT file_id, version, object_key, strftime('%Y-%m-%dT%H:%M:%SZ', created_at, '+{days} days') AS until FROM file_versions WHERE locked_until IS NULL ORDER BY created_at LIMIT 100"), None)?
			.to_array()?;
		let mut report = none;
		for r in rows {
			match crate::s3::put_retention(&self.env, &r.object_key, &r.until).await {
				Ok(lock) => {
					let mark = match lock {
						crate::s3::Lock::Locked => r.until.clone(),
						crate::s3::Lock::BucketRule => "bucket-rule".to_string(),
					};
					self.sql.exec("UPDATE file_versions SET locked_until = ?1 WHERE file_id = ?2 AND version = ?3", Some(vec![mark.into(), r.file_id.into(), r.version.into()]))?;
					report.locked += 1;
				}
				Err(e) => {
					worker::console_error!("gorani: lock {} failed: {e}", r.object_key);
					report.failed += 1;
				}
			}
		}
		// Collected evidence is write-once from receipt (commit 37b): the
		// inbox objects of an evidence case are locked the same way — all but
		// an item ACCEPTED before its lock (commit 37c): its object is now a
		// version's, locked above until a later date, and COMPLIANCE refuses
		// a shorter retention on an object (the pass would fail every night).
		let items: Vec<Unlocked> = self
			.sql
			.exec(&format!("SELECT id AS file_id, 0 AS version, object_key, strftime('%Y-%m-%dT%H:%M:%SZ', received_at, '+{days} days') AS until FROM inbox_items WHERE locked_until IS NULL AND accepted_file IS NULL ORDER BY received_at LIMIT 100"), None)?
			.to_array()?;
		for r in items {
			match crate::s3::put_retention(&self.env, &r.object_key, &r.until).await {
				Ok(lock) => {
					let mark = match lock {
						crate::s3::Lock::Locked => r.until.clone(),
						crate::s3::Lock::BucketRule => "bucket-rule".to_string(),
					};
					self.sql.exec("UPDATE inbox_items SET locked_until = ?1 WHERE id = ?2", Some(vec![mark.into(), r.file_id.into()]))?;
					report.locked += 1;
				}
				Err(e) => {
					worker::console_error!("gorani: lock {} failed: {e}", r.object_key);
					report.failed += 1;
				}
			}
		}
		report.pending = self.sql.exec("SELECT (SELECT COUNT(*) FROM file_versions WHERE locked_until IS NULL) + (SELECT COUNT(*) FROM inbox_items WHERE locked_until IS NULL AND accepted_file IS NULL) AS n", None)?.one::<crate::files_store::TotalCount>()?.n as u64;
		Ok(report)
	}
}

// ── The audit outbox (commit 29, docs/CUSTODY.md › Stage 1) ─────────────
//
// `audit()` writes into the local `audit` table in the same database, in
// the same request, as the action it records — the line exists if the
// action did. That table is now an OUTBOX: lines leave for the area's
// chained trail (audit.rs) and are deleted only once acknowledged.

impl GoraniMemberDO {
	/// The area's name, from this request's header (and remembered), or the
	/// one remembered before.
	fn area(&self, named: Option<&str>) -> Option<String> {
		#[derive(serde::Deserialize)]
		struct V {
			v: String,
		}
		if let Some(a) = named.filter(|a| crate::area::valid_area(a)) {
			let _ = self.sql.exec("INSERT INTO vault (k, v) VALUES ('area', ?1) ON CONFLICT(k) DO NOTHING", Some(vec![a.into()]));
			return Some(a.to_string());
		}
		self.sql.exec("SELECT v FROM vault WHERE k = 'area'", None).ok()?.to_array::<V>().ok()?.into_iter().next().map(|r| r.v)
	}

	pub(crate) async fn ship_audit(&self, area: &str) -> Result<()> {
		loop {
			let rows: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details_sealed, details FROM audit ORDER BY id LIMIT 500", None)?.to_array()?;
			if rows.is_empty() {
				return Ok(());
			}
			let n = rows.len();
			let lines: Vec<crate::audit::LineIn> = rows.into_iter().map(|a| crate::audit::LineIn { id: a.id, at: a.at, actor: a.actor, action: a.action, target: a.target, details: a.details, details_sealed: a.details_sealed }).collect();
			let acked = crate::audit::ship(&self.env, area, &lines).await?;
			self.sql.exec("DELETE FROM audit WHERE id <= ?1", Some(vec![acked.into()]))?;
			if n < 500 {
				return Ok(());
			}
		}
	}
}

// The files operations live beside the core (worker/src/files_store.rs) —
// same DO, another `impl` block, one module per concern.

impl GoraniMemberDO {

	async fn dispatch(&self, mut req: Request) -> Result<Response> {
		let path = req.path().trim_start_matches('/').to_string();
		let actor = req.headers().get("x-gorani-actor")?.unwrap_or_default();
		// Whose database this is (routes.rs › forward_member sets it; a DO
		// cannot read its own instance name).
		let member = req.headers().get("x-gorani-member")?.unwrap_or_default();
		match (req.method().to_string().as_str(), path.as_str()) {
			("GET", "vault") => self.get_vault().await,
			("PUT", "vault") => {
				let body = req.json::<VaultPut>().await?;
				self.put_vault(&actor, body).await
			}
			// The ONE way a vault's root changes (commit 27): a completed
			// recovery ceremony for this member (routes.rs › ceremony_complete,
			// after the registry validated it). Internal — no public path.
			("PUT", "vault-reroot") => {
				let body = req.json::<VaultPut>().await?;
				self.vault_reroot(&actor, body).await
			}
			// A case's legal hold placed or released (commit 29f): internal,
			// from routes.rs after the registry recorded it. No public path.
			// Custody (commit 29g, custody.rs). The Worker names the acting
			// member in the body (`member`), from its own check of the caller.
			("GET", id) if id.starts_with("custody/") => self.custody_get(&id["custody/".len()..]).await,
			// Timestamps (commit 29j, stamps.rs).
			("GET", id) if id.starts_with("stamps/") => self.stamps_get(&id["stamps/".len()..]).await,
			("PUT", id) if id.starts_with("stamps/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.stamps_put(&actor, &id["stamps/".len()..], body).await
			}
			("POST", id) if id.starts_with("custody/") => {
				let body = req.json::<serde_json::Value>().await?;
				match id["custody/".len()..].split('/').collect::<Vec<_>>().as_slice() {
					[file] => self.custody_offer(&actor, file, body).await,
					[file, seq, "accept"] => self.custody_accept(&actor, file, seq.parse().unwrap_or(0), body).await,
					[file, seq, "cancel"] => {
						let member = body.get("member").and_then(|v| v.as_str()).unwrap_or_default().to_string();
						self.custody_cancel(&actor, file, seq.parse().unwrap_or(0), &member).await
					}
					_ => json_error(404, "custody/<file>[/<seq>/accept|cancel]"),
				}
			}
			("GET", "reverify") => Response::from_json(&self.reverify_state().await?),
			("POST", "reverify") => {
				let body = req.json::<serde_json::Value>().await?;
				self.reverify_put(&actor, body).await
			}
			("PUT", "case-hold") => {
				let body = req.json::<serde_json::Value>().await?;
				let hold = body.get("hold").and_then(|h| h.as_bool()).unwrap_or(false);
				self.sync_hold(&actor, hold).await?;
				Ok(Response::from_json(&serde_json::json!({ "hold": hold }))?)
			}
			("GET", "audit") => self.get_audit(Some(&member).filter(|m| !m.is_empty()).map(|m| m.as_str())).await,
			("POST", "audit") => {
				let body = req.json::<AuditPut>().await?;
				self.audit(&actor, &body.action, &body.target, body.details_sealed.as_deref(), None).await?;
				self.get_audit(Some(&member).filter(|m| !m.is_empty()).map(|m| m.as_str())).await
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
			// Delete forever and Empty Trash (commit 39v): the Worker has
			// already asked for a lead, or the area's owner (routes.rs ›
			// purge_allowed).
			("POST", "files/purge") => {
				let body = req.json::<serde_json::Value>().await?;
				self.files_purge(&actor, body).await
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
			// A view-only link's viewing session (40b, drm_store.rs).
			("POST", id) if id.starts_with("shares/") && id.ends_with("/drm-copy") => {
				let body = req.json::<serde_json::Value>().await?;
				let session = body.get("session").and_then(|s| s.as_str()).unwrap_or_default().to_string();
				self.share_drm_copy(&id["shares/".len()..id.len() - "/drm-copy".len()], &session).await
			}
			("POST", id) if id.starts_with("shares/") && id.ends_with("/drm-license") => {
				let body = req.json::<serde_json::Value>().await?;
				let (file, version) = (body.get("file").and_then(|f| f.as_str()).unwrap_or_default(), body.get("version").and_then(|v| v.as_i64()).unwrap_or(0));
				self.drm_license_audit(&format!("share-link:{}", &id["shares/".len()..id.len() - "/drm-license".len()]), file, &version.to_string()).await
			}
			("POST", id) if id.starts_with("shares/") && id.ends_with("/claim") => {
				let body = req.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
				self.share_claim(&id["shares/".len()..id.len() - "/claim".len()], &body).await
			}
			("POST", id) if id.starts_with("shares/") && id.ends_with("/public-object") => {
				let body = req.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
				let token = body.get("token").and_then(|t| t.as_str()).unwrap_or_default().to_string();
				match self.share_public_object(&id["shares/".len()..id.len() - "/public-object".len()], &token).await {
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
			("GET", "storage/pending") => self.pending_deletes().await,
			("GET", "reads") => {
				let q = req.url()?.query().map(urlquery).unwrap_or_default();
				self.read_log(q.get("file").map(String::as_str)).await
			}
			("GET", id) if id.starts_with("backups/") => self.backup_object(&id["backups/".len()..]).await,
			("POST", "backup/restore") => {
				let body = req.json::<serde_json::Value>().await?;
				self.backup_restore(&actor, &member, body).await
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
			("GET", "files/sealed") => self.sealed_page(req).await,
			("PUT", "files/reseal") => {
				let body = req.json::<serde_json::Value>().await?;
				self.files_reseal(&actor, body).await
			}
			("GET", id) if id.starts_with("files-object/") => {
				// The version rides in the QUERY. `req.path()` never contains
				// one, so the old `split_once('?')` on the path never matched
				// and `?version=n` downloads silently served the CURRENT
				// version (commit 23).
				let q = req.url()?.query().map(urlquery).unwrap_or_default();
				let version = q.get("version").and_then(|x| x.parse::<i64>().ok());
				// The Worker sends the READER as the actor and the client kind
				// in `client` (O14): this lookup is where every download —
				// browser, media worker, CLI — passes before the edge cache.
				let client = q.get("client").cloned();
				self.file_object_route(&id["files-object/".len()..], version, &actor, client.as_deref()).await
			}
			("GET", id) if id.starts_with("restore-target/") => match id["restore-target/".len()..].split_once('/') {
				Some((file_id, obj)) => self.restore_target(&member, file_id, obj).await,
				None => json_error(400, "restore-target/<file>/<object>"),
			},
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
			("GET", "files/duplicates") => self.files_duplicates().await,
			// Lost bytes (commit 39t, routes.rs › lost_object): the Worker's
			// questions — never a route of the public API.
			("GET", "files/canary") => self.canary(req).await,
			("POST", id) if id.starts_with("files-lost/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.file_lost(&actor, &id["files-lost/".len()..], body).await
			}
			// The video sidecars (commit 39p, files_store.rs › video_*).
			("GET", "files/videos") => self.videos_feed().await,
			// ── Protected copies (commit 40b, worker/src/drm_store.rs) ──
			("GET", id) if id.starts_with("files-drm/") => self.drm_state(&id["files-drm/".len()..]).await,
			("POST", id) if id.starts_with("files-drm/") && id.ends_with("/complete") => {
				let body = req.json::<serde_json::Value>().await?;
				let rest = &id["files-drm/".len()..id.len() - "/complete".len()];
				match rest.split_once('/') {
					Some((file, version)) => self.drm_complete(&actor, file, version, body).await,
					None => json_error(400, "files-drm/<file>/<version>/complete"),
				}
			}
			("POST", id) if id.starts_with("files-drm/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.drm_start(&actor, &id["files-drm/".len()..], body).await
			}
			("DELETE", id) if id.starts_with("files-drm/") => self.drm_unprotect(&actor, &id["files-drm/".len()..]).await,
			// The copy itself (its sealed key included) — for the Worker's
			// playlist, media and license routes, never for a browser.
			("GET", id) if id.starts_with("files-drm-copy/") => match id["files-drm-copy/".len()..].split_once('/') {
				Some((file, version)) => self.drm_copy(file, version).await,
				None => json_error(400, "files-drm-copy/<file>/<version>"),
			},
			// A license handed out — recorded in the area's trail, with the
			// viewer as the actor (a member's address, or `share-link`).
			("POST", id) if id.starts_with("files-drm-license/") => match id["files-drm-license/".len()..].split_once('/') {
				Some((file, version)) => self.drm_license_audit(&actor, file, version).await,
				None => json_error(400, "files-drm-license/<file>/<version>"),
			},
			("GET", id) if id.starts_with("files-video/") => {
				let q = req.url()?.query().map(urlquery).unwrap_or_default();
				let version = q.get("version").and_then(|x| x.parse::<i64>().ok());
				self.video_get(&id["files-video/".len()..], version).await
			}
			("PUT", id) if id.starts_with("files-video/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.video_put(&actor, &id["files-video/".len()..], body).await
			}
			// Where each member left off (commit 39o). The Worker names the
			// member (the caller's own id, never one the client sends).
			("GET", "files/positions") => self.positions_get(req).await,
			("PUT", id) if id.starts_with("files-position/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.position_put(&id["files-position/".len()..], body).await
			}
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
			// ── The inbox (commit 37b, inbox.rs) ──
			("POST", "inbox/receive") => {
				let body = req.json::<serde_json::Value>().await?;
				self.inbox_receive(&actor, body).await
			}
			("GET", "inbox/list") => self.inbox_list().await,
			// ── Upload links and a member's own inbox keys (commit 38, requests.rs) ──
			("GET", "inbox-keys") => self.area_inbox_keys().await,
			("PUT", "inbox-key") => {
				let body = req.json::<serde_json::Value>().await?;
				self.area_inbox_key_put(&actor, body).await
			}
			("GET", "requests") => self.requests_list().await,
			("POST", "requests") => {
				let body = req.json::<serde_json::Value>().await?;
				self.request_create(&actor, body).await
			}
			("DELETE", id) if id.starts_with("requests/") => self.request_revoke(&actor, &id["requests/".len()..]).await,
			("POST", id) if id.starts_with("request-meta/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.request_public_meta(&id["request-meta/".len()..], body).await
			}
			("POST", id) if id.starts_with("request-send/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.request_check_send(&id["request-send/".len()..], body).await
			}
			("POST", id) if id.starts_with("inbox/accept/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.inbox_accept(&actor, &id["inbox/accept/".len()..], body).await
			}
			("POST", id) if id.starts_with("inbox/reject/") => {
				let body = req.json::<serde_json::Value>().await?;
				self.inbox_reject(&actor, &id["inbox/reject/".len()..], body).await
			}
			("GET", id) if id.starts_with("inbox-object/") => {
				let q = crate::files_store::urlquery(req.url()?.query().unwrap_or(""));
				self.inbox_object(&id["inbox-object/".len()..], &actor, q.get("client").map(String::as_str)).await
			}
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
		// (A member's own vault has its unlock methods checked on the way in
		// — routes.rs, methods_refusal. A case's settings, written here by
		// the Worker when a lead opens the case, have none: its key comes
		// through grants.)
		let v = serde_json::to_string(&body.settings).map_err(|_| Error::RustError("bad settings JSON".into()))?;
		self.sql.exec("INSERT INTO vault (k, v) VALUES ('settings', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", Some(vec![v.into()]))?;
		// Which kinds of way in the vault has after this save — kinds and
		// counts only, nothing secret — so the trail shows a method added
		// or removed, by whom and when (commit 39l).
		self.audit(actor, "vault.save", "settings", None, methods_summary(&body.settings).as_deref()).await?;
		self.get_vault().await
	}

	/// Replace the settings — root included — after a recovery ceremony.
	/// The devices go too: each held a copy of the OLD root (the lost one),
	/// which opens nothing in the new settings and must not linger.
	async fn vault_reroot(&self, actor: &str, body: VaultPut) -> Result<Response> {
		let v = serde_json::to_string(&body.settings).map_err(|_| Error::RustError("bad settings JSON".into()))?;
		self.sql.exec("INSERT INTO vault (k, v) VALUES ('settings', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", Some(vec![v.into()]))?;
		let devices = self.sql.exec("DELETE FROM devices", None)?.rows_written();
		self.audit(actor, "vault.reroot", "settings", None, Some(&format!("devicesDropped:{devices}"))).await?;
		self.get_vault().await
	}

	/// The newest lines: the chained trail's, after any not yet shipped
	/// (those are listed first, with `"pending": true` — the outbox).
	async fn get_audit(&self, area: Option<&str>) -> Result<Response> {
		if let Some(a) = self.area(area) {
			let _ = self.ship_audit(&a).await; // best effort; what stays is listed below
			let pending: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details_sealed, details FROM audit ORDER BY id DESC LIMIT 200", None)?.to_array()?;
			let mut out: Vec<serde_json::Value> = pending
				.into_iter()
				.map(|a| serde_json::json!({ "id": null, "at": a.at, "actor": a.actor, "action": a.action, "target": a.target, "detailsSealed": a.details_sealed, "details": a.details, "pending": true }))
				.collect();
			out.extend(crate::audit::lines(&self.env, &a, 200).await?);
			return Ok(Response::from_json(&out)?);
		}
		// An area that was never named has never shipped: its outbox is all.
		// (`details` was missing from this SELECT until commit 25: every
		// readable detail — retention outcomes, device names, backup counts —
		// was written and then listed as null. Found by api:cron's O10 block.)
		let rows: Vec<AuditRow> = self.sql.exec("SELECT id, at, actor, action, target, details_sealed, details FROM audit ORDER BY id DESC LIMIT 200", None)?.to_array()?;
		Ok(Response::from_json(&rows.into_iter().map(|a| serde_json::json!({ "id": a.id, "at": a.at, "actor": a.actor, "action": a.action, "target": a.target, "detailsSealed": a.details_sealed, "details": a.details })).collect::<Vec<_>>())?)
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
	///
	/// **Who may turn the knobs** (security review, commit 23): only the dev
	/// server. The route is member-scoped, so before this change any member
	/// could POST `{ auditKeep: 1, journalDays: 0 }` and erase their own
	/// audit trail and restore history — the person being audited holding
	/// the eraser. In production the body is ignored and the deployment
	/// defaults apply; the tests (GORANI_DEV=1) still force their clocks.
	pub(crate) async fn housekeeping(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let dev = self.env.var("GORANI_DEV").map(|v| v.to_string() == "1").unwrap_or(false);
		let knob = |k: &str, default: i64| if dev { body.get(k).and_then(|v| v.as_i64()).unwrap_or(default) } else { default };
		let trash_days = knob("trashDays", 30).max(0);
		let journal_days = knob("journalDays", 180).max(0);
		let share_days = knob("shareDays", 1).max(0);
		let upload_days = knob("uploadDays", 2).max(0);
		// D7 (commit 29b): a working area keeps a file's OLDER versions for a
		// year; an evidence case keeps every version for its whole life (its
		// files cannot even be trashed — files_store.rs › evidence_refusal).
		let version_days = knob("versionDays", 365).max(0);
		let evidence = self.is_evidence().await?;
		// A legal hold (commit 29f): nothing leaves while it stands — every
		// purge query below carries `AND 0`, so it matches no row at all.
		let held = self.is_held().await?;
		let hold_gate = if held { " AND 0" } else { "" };

		// 1. Trash purge: sealed objects leave S3, rows leave (triggers
		// journal the purge). Every object key goes into the deletion outbox
		// BEFORE its row goes (commit 25, O10): the row was the only pointer
		// to the object, and the S3 delete that used to follow could fail —
		// `let _ =` — leaving an object nothing would ever find again.
		let mut purged_objects: Vec<String> = Vec::new();
		let purged_files: Vec<ObjRow> = self
			.sql
			.exec(
				&format!("SELECT v.object_key AS object_key FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.deleted_at IS NOT NULL AND f.deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{trash_days} days'){hold_gate}"),
				None,
			)?
			.to_array()?;
		for r in &purged_files {
			purged_objects.push(r.object_key.clone());
			self.enqueue_delete(&r.object_key, None, "trash purge")?;
		}
		let n_files_purged = self
			.sql
			.exec(
				&format!("DELETE FROM files WHERE deleted_at IS NOT NULL AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{trash_days} days'){hold_gate}"),
				None,
			)?
			.rows_written();
		self.purge_dependents()?;
		let n_folders_purged = self
			.sql
			.exec(
				&format!("DELETE FROM file_folders WHERE deleted_at IS NOT NULL AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{trash_days} days'){hold_gate}"),
				None,
			)?
			.rows_written();

		// 1b. Version retention (D7), working areas only: versions older than
		// the window that are NOT a file's current one. Objects into the
		// outbox first, then the rows — the same order as the trash purge.
		let mut n_versions_pruned = 0u64;
		if !evidence && !held {
			#[derive(serde::Deserialize)]
			struct OldVersion {
				file_id: String,
				version: i64,
				object_key: String,
			}
			let old: Vec<OldVersion> = self
				.sql
				.exec(
					&format!("SELECT v.file_id, v.version, v.object_key FROM file_versions v JOIN files f ON f.id = v.file_id WHERE v.version < f.version AND v.created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{version_days} days')"),
					None,
				)?
				.to_array()?;
			for v in &old {
				purged_objects.push(v.object_key.clone());
				self.enqueue_delete(&v.object_key, None, "version retention")?;
				n_versions_pruned += self.sql.exec("DELETE FROM file_versions WHERE file_id = ?1 AND version = ?2", Some(vec![v.file_id.clone().into(), v.version.into()]))?.rows_written() as u64;
			}
		}

		// 2. Dead share copies: revoked or expired past the grace window.
		let dead_shares: Vec<ShareObjRow> = self
			.sql
			.exec(
				&format!("SELECT object_key, s3_upload_id FROM shares WHERE (revoked_at IS NOT NULL OR expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')) AND COALESCE(revoked_at, expires_at) < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{share_days} days')"),
				None,
			)?
			.to_array()?;
		let mut stale_multipart: Vec<(String, String)> = Vec::new();
		for r in &dead_shares {
			purged_objects.push(r.object_key.clone());
			self.enqueue_delete(&r.object_key, None, "dead share copy")?;
			// A share that never completed holds an open multipart upload:
			// its parts are billed storage until someone aborts it.
			if let Some(u) = r.s3_upload_id.as_ref().filter(|u| !u.is_empty()) {
				stale_multipart.push((r.object_key.clone(), u.clone()));
			}
		}

		// 2b. Uploads that never completed (a closed tab, a crashed client).
		// The bookkeeping row is the only pointer to the multipart upload; the
		// docs promised this sweep, the code never had it (commit 23).
		let stale_uploads: Vec<StaleUpload> = self
			.sql
			.exec(&format!("SELECT id, object_key, s3_upload_id FROM uploads WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{upload_days} days')"), None)?
			.to_array()?;
		for u in &stale_uploads {
			if u.s3_upload_id != "pending" {
				stale_multipart.push((u.object_key.clone(), u.s3_upload_id.clone()));
			}
		}
		// Aborts ride the same outbox (an upload id is all that frees the
		// parts — once its bookkeeping row is gone, nothing else knows it).
		for (key, upload) in &stale_multipart {
			self.enqueue_delete(&format!("{key}#upload:{upload}"), Some(upload), "stale multipart upload")?;
		}
		for u in &stale_uploads {
			self.sql.exec("DELETE FROM uploads WHERE id = ?1", Some(vec![u.id.clone().into()]))?;
		}
		let n_shares_purged = self
			.sql
			.exec(
				&format!("DELETE FROM shares WHERE (revoked_at IS NOT NULL OR expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')) AND COALESCE(revoked_at, expires_at) < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{share_days} days')"),
				None,
			)?
			.rows_written();

		// 2c. Strays (commit 39t): living files and folders whose folder is
		// gone — purged, or in the Trash while they are not (a file sent into
		// a folder deleted meanwhile, before file_put refused that). No
		// listing shows them: the explorer lists a folder's items only inside
		// it. They come back at the top, each move on the trail — never
		// deleted: the bytes are fine, only the place was lost. Folders
		// first, so a re-homed folder brings its contents back with it.
		#[derive(serde::Deserialize)]
		struct StrayRow {
			id: String,
		}
		let stray_folders: Vec<StrayRow> = self
			.sql
			.exec("SELECT id FROM file_folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL AND parent_id NOT IN (SELECT id FROM file_folders WHERE deleted_at IS NULL) LIMIT 500", None)?
			.to_array()?;
		for f in &stray_folders {
			self.sql.exec("UPDATE file_folders SET parent_id = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![f.id.clone().into()]))?;
			self.audit(actor, "folder.rehome", &f.id, None, Some("its folder was gone — moved to the top")).await?;
		}
		let stray_files: Vec<StrayRow> = self
			.sql
			.exec("SELECT id FROM files WHERE deleted_at IS NULL AND folder_id IS NOT NULL AND folder_id NOT IN (SELECT id FROM file_folders WHERE deleted_at IS NULL) LIMIT 500", None)?
			.to_array()?;
		for f in &stray_files {
			self.sql.exec("UPDATE files SET folder_id = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![f.id.clone().into()]))?;
			self.audit(actor, "file.rehome", &f.id, None, Some("its folder was gone — moved to the top")).await?;
		}

		// 3. The journal and the audit: the two append-only tables.
		let journal_pruned = self
			.sql
			.exec(
				&format!("DELETE FROM files_journal WHERE at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{journal_days} days')"),
				None,
			)?
			.rows_written();
		// (The audit is no longer pruned here: since commit 29 it lives in the
		// area's chained trail, kept 7 years with no line cap (D7) — the local
		// table is only the outbox, and its lines leave when acknowledged.
		// Pruning it here would delete lines before they were chained.)
		let audit_pruned = 0;
		// The read log keeps as long as the change journal (O14).
		self.sql.exec(&format!("DELETE FROM read_log WHERE last_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{journal_days} days')"), None)?;
		// Share download tokens: expired, or of a share that is gone (O12).
		self.sql.exec("DELETE FROM share_tokens WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now') OR share_id NOT IN (SELECT id FROM shares)", None)?;

		// 4. Drain the outbox — this pass's keys and any earlier failures.
		let drained = self.drain_deletes().await?;
		if !purged_objects.is_empty() || n_files_purged + n_shares_purged > 0 || drained.failed > 0 {
			self.audit(actor, "housekeeping.run", "retention", None, Some(&format!("files:{n_files_purged},versions:{n_versions_pruned},shares:{n_shares_purged},journal:{journal_pruned},audit:{audit_pruned},deleted:{},deletesPending:{}", drained.done, drained.pending))).await?;
		}
		Ok(Response::from_json(&serde_json::json!({
			"purgedFiles": n_files_purged, "purgedFolders": n_folders_purged, "purgedShares": n_shares_purged, "versionsPruned": n_versions_pruned, "evidence": evidence, "held": held,
			"journalPruned": journal_pruned, "auditPruned": audit_pruned, "objectsDeleted": drained.done,
			"uploadsAborted": stale_uploads.len(), "deletesFailed": drained.failed, "deletesPending": drained.pending,
			"rehomedFolders": stray_folders.len(), "rehomedFiles": stray_files.len(),
		}))?)
	}

	/// Queue an object (or, with `upload_id`, a multipart upload) for
	/// deletion. Idempotent: a key already queued keeps its history.
	/// The rows that hang off a file, for the files that are gone — after
	/// the Trash's purge (housekeeping) and after Delete forever
	/// (files_store.rs › files_purge, commit 39v), the same list for both.
	/// `files` has no foreign keys (SQLite DOs run without them), so
	/// `DELETE FROM files` used to leave every version row — wrapped content
	/// key, object key — plus music blobs and contributor rows behind
	/// forever: unbounded growth, and key material outliving the file it
	/// belonged to. (The version OBJECTS must already be in the deletion
	/// outbox: these rows were the last pointers to them.)
	pub(crate) fn purge_dependents(&self) -> Result<()> {
		self.sql.exec("DELETE FROM file_versions WHERE file_id NOT IN (SELECT id FROM files)", None)?;
		self.sql.exec("DELETE FROM music_meta WHERE file_id NOT IN (SELECT id FROM files)", None)?;
		// (A video sidecar goes with its file — and with its VERSION, which
		// the working-file retention prunes after a year.)
		self.sql.exec("DELETE FROM video_meta WHERE NOT EXISTS (SELECT 1 FROM file_versions v WHERE v.file_id = video_meta.file_id AND v.version = video_meta.version)", None)?;
		self.sql.exec("DELETE FROM watch_positions WHERE file_id NOT IN (SELECT id FROM files)", None)?;
		// A protected copy goes with its version too — its object queued for
		// deletion, its sealed key with the row: once both are gone the copy
		// can never be opened again, from any backup of the bucket (40b).
		self.drm_purge_orphans()?;
		self.sql.exec("DELETE FROM file_contributors WHERE file_id NOT IN (SELECT id FROM files)", None)?;
		Ok(())
	}

	pub(crate) fn enqueue_delete(&self, key: &str, upload_id: Option<&str>, reason: &str) -> Result<()> {
		self.sql.exec(
			"INSERT OR IGNORE INTO pending_deletes (key, upload_id, reason, since) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![key.into(), crate::files_store::bind(upload_id.map(str::to_string)), reason.into()]),
		)?;
		Ok(())
	}

	/// Try every queued delete; a key leaves the queue only when storage
	/// confirmed it (S3's 204, or 404 — already gone counts as done). A
	/// failure stays queued with its attempt count and the error, for the
	/// next pass and for whoever reads `storage/pending`.
	pub(crate) async fn drain_deletes(&self) -> Result<Drained> {
		let rows: Vec<PendingDelete> = self.sql.exec("SELECT key, upload_id FROM pending_deletes ORDER BY since LIMIT 500", None)?.to_array()?;
		let (mut done, mut failed) = (0u64, 0u64);
		for r in rows {
			let outcome = match &r.upload_id {
				Some(u) => crate::s3::multipart_abort(&self.env, r.key.split("#upload:").next().unwrap_or_default(), u).await,
				None => crate::s3::delete(&self.env, &r.key).await,
			};
			match outcome {
				Ok(()) => {
					self.sql.exec("DELETE FROM pending_deletes WHERE key = ?1", Some(vec![r.key.into()]))?;
					done += 1;
				}
				Err(e) => {
					self.sql.exec("UPDATE pending_deletes SET attempts = attempts + 1, last_error = ?2 WHERE key = ?1", Some(vec![r.key.into(), e.to_string().into()]))?;
					failed += 1;
				}
			}
		}
		let pending = self.sql.exec("SELECT COUNT(*) AS n FROM pending_deletes", None)?.one::<TotalCount>()?.n as u64;
		Ok(Drained { done, failed, pending })
	}

	/// What is waiting to be deleted, and why (`GET …/storage/pending`) —
	/// object keys and errors only: structure, like the rest of this DO.
	pub(crate) async fn pending_deletes(&self) -> Result<Response> {
		let rows: Vec<PendingDeleteRow> = self.sql.exec("SELECT key, reason, since, attempts, last_error FROM pending_deletes ORDER BY since", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"pending": rows.into_iter().map(|r| serde_json::json!({ "key": r.key, "reason": r.reason, "since": r.since, "attempts": r.attempts, "lastError": r.last_error })).collect::<Vec<_>>(),
		}))?)
	}

	/// The nightly pass (worker/src/cron.rs knocks here as the system actor
	/// `cron`): retention housekeeping on the deployment defaults, then
	/// backup-manifest pruning — the newest `keep` .gbak runs survive, older
	/// rows and their S3 objects go. Backups are CREATED by the browser flow
	/// (docs/PRODUCTION.md › Backups): the in-memory GB1 job is sized for
	/// that, so the cron only tends the museum, it doesn't fire the kiln.
	///
	/// A pass that could not finish its deletions FAILS (503, commit 25 —
	/// O10): the fan-out (cron.rs) reports it, the outbox keeps the keys, and
	/// the next night retries. It used to answer 200 whatever S3 said.
	async fn cron_pass(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		// A case's legal hold, as the registry has it (commit 29f; cron.rs):
		// reconciled FIRST, so tonight's purge already obeys it.
		if let Some(hold) = body.get("hold").and_then(|h| h.as_bool()) {
			self.sync_hold(actor, hold).await?;
		}
		let keep = body.get("keep").and_then(|v| v.as_i64()).unwrap_or(7).clamp(1, 100);
		let stale: Vec<BackupStamp> = self
			.sql
			.exec(&format!("SELECT stamp FROM backups ORDER BY created_at DESC, stamp DESC LIMIT -1 OFFSET {keep}"), None)?
			.to_array()?;
		let mut pruned = 0u64;
		for r in &stale {
			// The object into the outbox first, then the manifest row (which
			// was the only pointer to the object).
			self.enqueue_delete(&format!("backups/{}.gbak", r.stamp), None, "backup pruned")?;
			self.sql.exec("DELETE FROM backups WHERE stamp = ?1", Some(vec![r.stamp.clone().into()]))?.rows_written();
			pruned += 1;
		}
		// Housekeeping drains the outbox — this pass's backups included.
		let mut house = self.housekeeping(actor, serde_json::json!({})).await?;
		let house: serde_json::Value = house.json().await?;
		let failed = house.get("deletesFailed").and_then(|v| v.as_u64()).unwrap_or(0);
		let pending = house.get("deletesPending").and_then(|v| v.as_u64()).unwrap_or(0);
		// Evidence still without its write-once retention: a failure the pass
		// reports (503), like a delete storage refused — never silence.
		let locks = self.lock_pass().await?;
		// Evidence versions still without their timestamp (commit 29j): the
		// alarm retries on its own; tonight's pass tries too, and says so.
		let stamps = self.stamp_pass().await?;
		if stamps.pending > 0 {
			worker::console_error!("gorani: {} evidence version(s) in {} still without a trusted timestamp (TSA_URL)", stamps.pending, self.area(None).unwrap_or_default());
		}
		// Evidence nobody re-verified lately (commit 29h): the server cannot
		// re-hash (it has no key) — it can notice nobody did, and say so.
		let reverify = self.reverify_state().await?;
		if reverify.get("overdue").and_then(|o| o.as_bool()) == Some(true) {
			worker::console_error!("gorani: evidence store {} not re-verified for {} days or more (REVERIFY_DAYS) — a client must re-hash it", self.area(None).unwrap_or_default(), reverify["days"]);
		}
		self.audit(actor, "cron.pass", "retention", None, Some(&format!("backupsPruned:{pruned},deletesFailed:{failed},deletesPending:{pending},locksFailed:{},locksPending:{},stampsFailed:{},stampsPending:{}", locks.failed, locks.pending, stamps.failed, stamps.pending))).await?;
		let body = serde_json::json!({ "housekeeping": house, "backupsPruned": pruned, "deletesFailed": failed, "deletesPending": pending, "locked": locks.locked, "locksFailed": locks.failed, "locksPending": locks.pending, "stamped": stamps.stamped, "stampsFailed": stamps.failed, "stampsPending": stamps.pending, "reverify": reverify });
		if failed > 0 || locks.failed > 0 || stamps.failed > 0 {
			return Ok(Response::from_json(&body)?.with_status(503));
		}
		Ok(Response::from_json(&body)?)
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
struct StaleUpload {
	id: String,
	object_key: String,
	s3_upload_id: String,
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

#[derive(serde::Deserialize)]
struct PendingDelete {
	key: String,
	upload_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct PendingDeleteRow {
	key: String,
	reason: String,
	since: String,
	attempts: i64,
	last_error: Option<String>,
}

pub(crate) struct Drained {
	pub(crate) done: u64,
	pub(crate) failed: u64,
	pub(crate) pending: u64,
}

/// The checks a member's settings save must pass on its unlock methods
/// (commit 39l: Team › Unlock adds and removes them; routes.rs applies
/// this to `PUT members/<id>/vault`, the only way a person's client writes
/// a vault). The server cannot check that a method OPENS anything — it
/// holds no secret — but it can refuse the saves that would lose a vault
/// outright, whoever sends them:
///
/// - an ENABLED vault keeps at least one method: with none, the root key
///   is sealed under nothing anyone has, and the vault is lost for good;
/// - each method is an object of a known kind, with its wrap and salt;
/// - at most MAX_PASSWORD_METHODS passwords (web/src/vault/kdf-bounds.ts,
///   O8: each costs an Argon2 run at every unlock attempt, and a client
///   tries only that many — a fifth would never open).
pub(crate) fn methods_refusal(settings: &serde_json::Value) -> Option<&'static str> {
	const MAX_PASSWORD_METHODS: usize = 4;
	let enabled = settings.get("enabled").and_then(|e| e.as_bool()) == Some(true);
	let Some(methods) = settings.get("methods") else {
		return enabled.then_some("an enabled vault needs its unlock methods");
	};
	let Some(list) = methods.as_array() else { return Some("methods is a list") };
	if enabled && list.is_empty() {
		return Some("an enabled vault keeps at least one unlock method — with none it could never be opened again");
	}
	for m in list {
		let present = |f: &str| m.get(f).and_then(|v| v.as_str()).is_some_and(|v| !v.is_empty());
		if !matches!(m.get("kind").and_then(|k| k.as_str()), Some("password" | "recovery" | "passkey")) || !present("wrapped") || !present("salt") {
			return Some("each unlock method has a kind (password, recovery or passkey), its wrap and its salt");
		}
	}
	if list.iter().filter(|m| m.get("kind").and_then(|k| k.as_str()) == Some("password")).count() > MAX_PASSWORD_METHODS {
		return Some("at most 4 passwords — the unlock screen tries no more than that");
	}
	None
}

/// The trail's line for a save: which kinds of way in the vault has
/// (`methods:password,recovery,passkey×2`) — kinds and counts, nothing
/// secret. None for settings without methods (a case's).
pub(crate) fn methods_summary(settings: &serde_json::Value) -> Option<String> {
	let list = settings.get("methods")?.as_array()?;
	let count = |k: &str| list.iter().filter(|m| m.get("kind").and_then(|x| x.as_str()) == Some(k)).count();
	let parts: Vec<String> = ["password", "recovery", "passkey"]
		.iter()
		.filter(|k| count(k) > 0)
		.map(|k| if count(k) > 1 { format!("{k}×{}", count(k)) } else { (*k).to_string() })
		.collect();
	Some(format!("methods:{}", if parts.is_empty() { "none".to_string() } else { parts.join(",") }))
}

#[cfg(test)]
mod methods_tests {
	use super::{methods_refusal, methods_summary};
	use serde_json::json;

	fn m(kind: &str) -> serde_json::Value {
		json!({ "id": "x", "kind": kind, "wrapped": "R1cwMQ==", "salt": "c2FsdA==", "kdf": "argon2id", "createdAt": "2026-10-16T00:00:00.000Z" })
	}

	#[test]
	fn an_enabled_vault_keeps_a_way_in() {
		assert!(methods_refusal(&json!({ "enabled": true, "methods": [] })).is_some());
		assert!(methods_refusal(&json!({ "enabled": true })).is_some());
		assert_eq!(methods_refusal(&json!({ "enabled": false })), None, "a vault turned off, untouched");
		let four = json!({ "enabled": true, "methods": [m("password"), m("recovery"), m("passkey"), m("passkey")] });
		assert_eq!(methods_refusal(&four), None);
		assert_eq!(methods_summary(&four).as_deref(), Some("methods:password,recovery,passkey×2"));
		assert_eq!(methods_summary(&json!({ "enabled": true, "case": "ir-1" })), None, "a case's settings have no methods to summarise");
	}

	#[test]
	fn methods_are_well_formed_and_bounded() {
		assert!(methods_refusal(&json!({ "enabled": true, "methods": [{ "kind": "password" }] })).is_some(), "no wrap, no salt");
		assert!(methods_refusal(&json!({ "enabled": true, "methods": [m("pin")] })).is_some(), "an unknown kind");
		assert!(methods_refusal(&json!({ "enabled": true, "methods": "password" })).is_some());
		let five = (0..5).map(|_| m("password")).collect::<Vec<_>>();
		assert!(methods_refusal(&json!({ "enabled": true, "methods": five })).is_some(), "a fifth password would never be tried");
	}
}

