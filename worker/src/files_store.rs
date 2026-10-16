// Copyright 2026- Seongwoo Hong. All rights reserved.
// The files store's shape follows Mailflare's files DO (Seongwoo Hong's modified version; Apache 2.0,
// original © Cloudflare, Inc.); see NOTICE.

//! The files operations of `GoraniMemberDO` (the schema and the vault/audit
//! core are in member.rs — same DO, one module per concern).
//!
//! Division of labour between the Worker and this DO:
//!
//! | Where | Job |
//! |---|---|
//! | Worker routes | multipart parsing, sealed-shape checks (bytes must start `GV02`, names must be placed text), S3 put/multipart, streaming reads |
//! | This DO | rows: files, folders, versions, the change feed, secrets, upload bookkeeping |
//!
//! The DO never sees a plaintext name or an unsealed byte: every sealed
//! column it accepts is checked with `is_placed_text` before insert — GV04
//! only (commit 25, docs/SECURITY-REVIEW.md › O6). The DO cannot check that
//! a value sits in its RIGHT place (that takes the store's key); it refuses
//! the older formats, so an honest server keeps the clean break clean and
//! an old client gets a 400, not a store its own peers cannot open. Object
//! keys are opaque ids (`files/<member>/<file>/<v-uuid>`), never file names.

use rand_core::{OsRng, RngCore};
use base64::Engine;
use worker::{Error, Request, Response, Result};

use crate::family::json_error;
use crate::member::GoraniMemberDO;

pub(crate) fn uuid() -> String {
	let mut b = [0u8; 16];
	OsRng.fill_bytes(&mut b);
	b[6] = (b[6] & 0x0f) | 0x40;
	b[8] = (b[8] & 0x3f) | 0x80;
	format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

/// `Option<String>` as a SQL binding: `None` becomes NULL (the columns are
/// nullable; `SqlStorageValue` has no `From<Option<_>>` by design).
pub(crate) fn bind(v: Option<String>) -> worker::SqlStorageValue {
	match v {
		Some(s) => worker::SqlStorageValue::String(s),
		None => worker::SqlStorageValue::Null,
	}
}

#[derive(serde::Deserialize)]
struct MusicFeedRow {
	file_id: String,
	version: i64,
	blob_sealed: String,
	size: i64,
}
#[derive(serde::Deserialize)]
struct FileSqlRow {
	id: String,
	folder_id: Option<String>,
	name_sealed: String,
	size: i64,
	version: i64,
	created_at: String,
	updated_at: String,
	owner: Option<String>,
	/// 1 for a malware sample (commit 29e). Default 0 for SELECTs that do
	/// not ask for it.
	#[serde(default)]
	sample: i64,
}

#[derive(Clone, serde::Deserialize)]
struct FolderSqlRow {
	id: String,
	parent_id: Option<String>,
	name_sealed: String,
	created_at: String,
	updated_at: String,
}

#[derive(serde::Deserialize)]
struct VersionSqlRow {
	version: i64,
	content_key: String,
	vault_key_id: Option<String>,
	object_key: String,
	type_sealed: Option<String>,
	size: i64,
	chunk_size: Option<i64>,
	hash_sealed: Option<String>,
	#[serde(default)]
	sample: i64,
	#[serde(default)]
	intake_sealed: Option<String>,
	#[serde(default)]
	collection_sealed: Option<String>,
}

impl GoraniMemberDO {
	// ── Files: create (one-request upload) and versions ─────────────────

	/// Record a whole-file upload the Worker already put in S3. The CLIENT
	/// chose the file id (commit 25: it seals the name and the content key
	/// into places that name the file, so the id must exist before the
	/// sealing does); the Worker checked its shape and built the object key;
	/// the DO owns the rows — and refuses an id already taken (409).
	// ── Bytes the storage no longer has (commit 39t, routes.rs › lost_object) ──

	/// Up to three OTHER living files' current objects: what the Worker asks
	/// the storage about before it believes a file is lost. A storage that
	/// has none of them is not this deployment's (a wrong bucket, a wrong
	/// endpoint) — and then nothing is lost, everything is unreachable.
	pub(crate) async fn canary(&self, req: Request) -> Result<Response> {
		let not = urlquery(req.url()?.query().unwrap_or("")).get("not").cloned().unwrap_or_default();
		#[derive(serde::Deserialize)]
		struct Key {
			object_key: String,
		}
		let rows: Vec<Key> = self
			.sql
			.exec("SELECT v.object_key AS object_key FROM files f JOIN file_versions v ON v.file_id = f.id AND v.version = f.version WHERE f.deleted_at IS NULL AND f.id != ?1 ORDER BY f.created_at DESC LIMIT 3", Some(vec![not.into()]))?
			.to_array()?;
		Response::from_json(&serde_json::json!({ "objectKeys": rows.into_iter().map(|r| r.object_key).collect::<Vec<_>>() }))
	}

	/// `POST files-lost/<file> { version, objectKey }`: the Worker found no
	/// bytes for this version — twice — while the storage answered for this
	/// area's other files. A WORKING file whose living version is gone goes
	/// to the Trash (restorable for 30 days, should the bytes come back),
	/// with the reason on its trail. Evidence, a case on legal hold, or an
	/// older version is never moved: the loss is recorded, and a lead
	/// decides (for evidence it is an incident, not housekeeping).
	pub(crate) async fn file_lost(&self, actor: &str, file: &str, body: serde_json::Value) -> Result<Response> {
		let version = body.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
		let object_key = body.get("objectKey").and_then(|v| v.as_str()).unwrap_or_default();
		#[derive(serde::Deserialize)]
		struct Row {
			object_key: String,
			current: i64,
		}
		let rows: Vec<Row> = self
			.sql
			.exec("SELECT v.object_key AS object_key, f.version AS current FROM file_versions v JOIN files f ON f.id = v.file_id WHERE v.file_id = ?1 AND v.version = ?2 AND f.deleted_at IS NULL", Some(vec![file.into(), version.into()]))?
			.to_array()?;
		let Some(row) = rows.into_iter().next() else { return json_error(404, "no such live file version") };
		// (The Worker names the object this store gave it; another is refused.)
		if row.object_key != object_key {
			return json_error(409, "that is not this version's object");
		}
		let detail = format!("v{version}: the storage has no bytes for it (asked twice, while it answered for this area's other files)");
		let kept = self.evidence_refusal().await?.is_some() || row.current != version;
		if kept {
			self.audit(actor, "file.lost", file, None, Some(&detail)).await?;
			return Response::from_json(&serde_json::json!({ "trashed": false, "evidence": self.is_evidence().await?, "held": self.is_held().await? }));
		}
		self.sql.exec("UPDATE files SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND deleted_at IS NULL", Some(vec![file.into()]))?;
		self.audit(actor, "file.lost", file, None, Some(&format!("{detail} — moved to the Trash"))).await?;
		Response::from_json(&serde_json::json!({ "trashed": true, "evidence": false, "held": false }))
	}

	/// Where a file may go (commit 39t): the top folder, or a folder that
	/// exists and is not in the Trash. Until 39t a file sent into a folder
	/// deleted meanwhile (on another device, or while a big upload ran) was
	/// stored there — and no listing ever showed it again: the explorer
	/// lists a folder's files only inside that folder. (Folders themselves
	/// were already checked: folder_put and folder_patch refuse a gone parent.)
	async fn folder_refusal(&self, folder: Option<&str>) -> Result<Option<Response>> {
		let Some(folder) = folder else { return Ok(None) };
		let live: Option<ExistsRow> = self.sql.exec("SELECT 1 AS one FROM file_folders WHERE id = ?1 AND deleted_at IS NULL", Some(vec![folder.into()]))?.to_array::<ExistsRow>().ok().and_then(|mut r| r.pop());
		Ok(match live {
			Some(_) => None,
			None => Some(json_error_raw(404, "no such folder: it was deleted or moved to the Trash (on another device?) — refresh, and choose another")),
		})
	}

	pub(crate) async fn file_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if let Some(msg) = self.vault_gate().await? {
			return json_error(400, &msg);
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let name = get("name").ok_or_else(|| worker::Error::RustError("missing name".into()))?;
		let r#type = get("type");
		if !gorani_formats::placed::is_placed_text(&name) || r#type.as_ref().is_some_and(|t| !gorani_formats::placed::is_placed_text(t)) {
			return json_error(400, "names and types must be placed sealed text (GV04)");
		}
		if body.get("bytesSealed").and_then(|v| v.as_bool()) != Some(true) {
			return json_error(400, "the Worker confirms sealed bytes before calling the store");
		}
		// Every refusal BEFORE the first write (commit 25): the music blob was
		// checked after the file and version rows were inserted, so a refused
		// blob answered 400 — the Worker then deleted the object — and left
		// rows pointing at nothing.
		if get("mmeta").is_some_and(|b| !gorani_formats::placed::is_placed_text(&b)) {
			return json_error(400, "music metadata must arrive sealed into its place (GV04)");
		}
		if let Some(refused) = self.hash_refusal(get("hash").as_deref()).await? {
			return Ok(refused);
		}
		// Its timestamp imprint (commit 29j, stamps.rs), when the client sent one.
		if let Some(msg) = crate::stamps::stamp_refusal(get("hash").as_deref(), get("stamp").as_deref()) {
			return json_error(400, msg);
		}
		// The intake record (commit 29g): where the item came from — sealed,
		// signed, and required on evidence, like the hash. A NEW file only:
		// an item is acquired once; its later versions are its processing.
		let intake = get("intake");
		if intake.as_ref().is_some_and(|i| !gorani_formats::placed::is_placed_text(i)) {
			return json_error(400, "the intake record must arrive sealed into its place (GV04)");
		}
		if intake.is_none() && self.is_evidence().await? {
			return json_error(400, "an evidence file needs its intake record — source, collector, method, when (docs/CUSTODY.md › stage 6) — this client did not send one");
		}
		let Some(file_id) = get("id") else { return json_error(400, "the file id is chosen by the client (file_id)") };
		let taken: Option<ExistsRow> = self.sql.exec("SELECT 1 AS one FROM files WHERE id = ?1", Some(vec![file_id.clone().into()]))?.to_array::<ExistsRow>().ok().and_then(|mut r| r.pop());
		if taken.is_some() {
			return json_error(409, "a file with this id exists — choose a fresh id (a new version goes to files/<id>/versions)");
		}
		if let Some(refused) = self.folder_refusal(get("folderId").as_deref()).await? {
			return Ok(refused);
		}
		let version = 1i64;
		let object_key = get("objectKey").ok_or_else(|| worker::Error::RustError("missing objectKey".into()))?;
		let content_key = get("ck").ok_or_else(|| worker::Error::RustError("missing content key".into()))?;
		// The content key must arrive already sealed to the store key — a raw
		// key would let the server (or a leaked row) open the content.
		if !gorani_formats::placed::is_placed_text(&content_key) {
			return json_error(400, "the content key must arrive sealed into its place (GV04)");
		}
		let size = body.get("size").and_then(|v| v.as_i64()).ok_or_else(|| worker::Error::RustError("missing size".into()))?;
		let sample = body.get("sample").and_then(|v| v.as_bool()).unwrap_or(false);
		self.sql
			.exec(
				"INSERT INTO files (id, folder_id, name_sealed, size, version, created_at, updated_at, owner, sample, intake_sealed) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?6, ?7, ?8)",
				Some(vec![file_id.clone().into(), bind(get("folderId")), name.clone().into(), size.into(), version.into(), bind(get("owner")), (sample as i64).into(), bind(intake)]),
			)
			.map_err(|e| worker::Error::RustError(format!("file insert: {e}")))?;
		self.contributor_add(&file_id, actor).await?;
		self.sql
			.exec(
				"INSERT INTO file_versions (file_id, version, content_key, vault_key_id, object_key, type_sealed, size, chunk_size, tag, hash_sealed, stamp_imprint, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![
					file_id.clone().into(),
					version.into(),
					content_key.into(),
					bind(get("vaultKeyId")),
					object_key.into(),
					bind(r#type.clone()),
					size.into(),
					body.get("chunkSize").and_then(|v| v.as_i64()).map(worker::SqlStorageValue::Integer).unwrap_or(worker::SqlStorageValue::Null),
					bind(get("tag")),
					bind(get("hash")),
					bind(get("stamp")),
				]),
			)
			.map_err(|e| worker::Error::RustError(format!("version insert: {e}")))?;
		if let Err(resp) = self.music_meta_put(&file_id, version, get("mmeta")).await {
			return Ok(resp);
		}
		self.audit(actor, if sample { "file.upload.sample" } else { "file.upload" }, &file_id, None, None).await?;
		if get("stamp").is_some() {
			self.arm_stamps().await?;
		}
		self.file_row(&file_id).await
	}

	/// Add a version: the file must still be at `baseVersion` (409 otherwise,
	/// with the current version so the client can decide), then the version
	/// row lands and the file's pointer moves. Two racing uploads never
	/// overwrite each other's bytes (each has its own object key).
	pub(crate) async fn file_version_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if let Some(msg) = self.vault_gate().await? {
			return json_error(400, &msg);
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let file_id = get("fileId").ok_or_else(|| worker::Error::RustError("missing fileId".into()))?;
		let name = get("name");
		if let Some(n) = &name {
			if !gorani_formats::placed::is_placed_text(n) {
				return json_error(400, "names must be placed sealed text (GV04)");
			}
		}
		let current: Option<i64> = self.sql.exec("SELECT version FROM files WHERE id = ?1", Some(vec![file_id.clone().into()]))?.to_array::<CurrentVersion>().ok().and_then(|mut r| r.pop()).map(|r| r.version);
		let Some(current) = current else { return json_error(404, "no such file") };
		// Required since commit 25: the client sealed this version's key and
		// type into places that name version base + 1, so a write that lands
		// as any other number would be unopenable. No base, no guess.
		let Some(base) = body.get("baseVersion").and_then(|v| v.as_i64()) else {
			return json_error(400, "baseVersion is required (the version this one follows)");
		};
		if base != current {
			return Ok(Response::from_json(&serde_json::json!({ "error": "the file moved on since", "version": current }))?.with_status(409));
		}
		let next = current + 1;
		let object_key = get("objectKey").ok_or_else(|| worker::Error::RustError("missing objectKey".into()))?;
		let content_key = get("ck").ok_or_else(|| worker::Error::RustError("missing content key".into()))?;
		// The content key must arrive already sealed to the store key — a raw
		// key would let the server (or a leaked row) open the content.
		if !gorani_formats::placed::is_placed_text(&content_key) {
			return json_error(400, "the content key must arrive sealed into its place (GV04)");
		}
		let size = body.get("size").and_then(|v| v.as_i64()).ok_or_else(|| worker::Error::RustError("missing size".into()))?;
		let r#type = get("type");
		if r#type.as_ref().is_some_and(|t| !gorani_formats::placed::is_placed_text(t)) {
			return json_error(400, "types must be placed sealed text (GV04)");
		}
		if get("mmeta").is_some_and(|b| !gorani_formats::placed::is_placed_text(&b)) {
			return json_error(400, "music metadata must arrive sealed into its place (GV04)");
		}
		if let Some(refused) = self.hash_refusal(get("hash").as_deref()).await? {
			return Ok(refused);
		}
		// Its timestamp imprint (commit 29j, stamps.rs), when the client sent one.
		if let Some(msg) = crate::stamps::stamp_refusal(get("hash").as_deref(), get("stamp").as_deref()) {
			return json_error(400, msg);
		}
		self.sql
			.exec(
				"INSERT INTO file_versions (file_id, version, content_key, vault_key_id, object_key, type_sealed, size, chunk_size, tag, hash_sealed, stamp_imprint, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![
					file_id.clone().into(),
					next.into(),
					content_key.into(),
					bind(get("vaultKeyId")),
					object_key.into(),
					bind(r#type.clone()),
					size.into(),
					body.get("chunkSize").and_then(|v| v.as_i64()).map(worker::SqlStorageValue::Integer).unwrap_or(worker::SqlStorageValue::Null),
					bind(get("tag")),
					bind(get("hash")),
					bind(get("stamp")),
				]),
			)
			.map_err(|e| worker::Error::RustError(format!("version insert: {e}")))?;
		self.sql.exec(
			"UPDATE files SET version = ?1, size = ?2, name_sealed = COALESCE(?3, name_sealed), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?4",
			Some(vec![next.into(), size.into(), bind(name), file_id.clone().into()]),
		)?;
		self.contributor_add(&file_id, actor).await?;
		if let Err(resp) = self.music_meta_put(&file_id, next, get("mmeta")).await {
			return Ok(resp);
		}
		self.audit(actor, "file.version", &file_id, None, None).await?;
		if get("stamp").is_some() {
			self.arm_stamps().await?;
		}
		self.file_row(&file_id).await
	}

	/// The music metadata blob (docs/MUSIC.md): the client parsed the tags
	/// from plaintext it already held, sealed them to the store key, and the
	/// server stores the opaque blob per version. Unsealed blobs are refused
	/// like every other sealed text — the library opens them, not reads them.
	async fn music_meta_put(&self, file_id: &str, version: i64, blob: Option<String>) -> std::result::Result<(), Response> {
		if let Some(b) = blob {
			if !gorani_formats::placed::is_placed_text(&b) {
				return Err(json_error_raw(400, "music metadata must arrive sealed"));
			}
			if let Err(e) = self.sql.exec(
					"INSERT INTO music_meta (file_id, version, blob_sealed) VALUES (?1, ?2, ?3) ON CONFLICT (file_id, version) DO UPDATE SET blob_sealed = excluded.blob_sealed",
					Some(vec![file_id.into(), version.into(), b.into()]),
				) {
				return Err(json_error_raw(500, &format!("music meta insert: {e}")));
			}
		}
		Ok(())
	}

	/// The music library's feed (docs/MUSIC.md): every sealed metadata blob
	/// for living file versions in ONE response — the client opens each with
	/// the store key and never re-reads the audio for tags.
	pub(crate) async fn music_feed(&self) -> Result<Response> {
		let rows: Vec<MusicFeedRow> = self
			.sql
			.exec(
				"SELECT m.file_id AS file_id, m.version AS version, m.blob_sealed AS blob_sealed, f.size AS size FROM music_meta m JOIN files f ON f.id = m.file_id AND f.version = m.version WHERE f.deleted_at IS NULL ORDER BY f.created_at, f.id",
				None,
			)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "tracks": rows
			.into_iter()
			.map(|r| serde_json::json!({ "id": r.file_id, "version": r.version, "blobSealed": r.blob_sealed, "size": r.size }))
			.collect::<Vec<_>>() }))?)
	}

	// ── The video sidecar (commit 39p, docs/VIDEO.md) ───────────────────

	/// `PUT files-video/<file> { version, meta, poster? }`: a version's video
	/// sidecar, written by a client that held the plaintext (at upload, or
	/// the first time someone opened the video). The server can check only
	/// what it can see: the file and version exist and are live, the values
	/// are placed sealed text of a sane size, and the file is not a malware
	/// sample (nothing ever decodes one — a sidecar would mean someone did).
	/// What the blob says it cannot read; its place (file.video of THIS
	/// file and version) keeps it from being moved to another file.
	///
	/// A later write for the same version replaces the earlier one — the
	/// poster arrives after the sidecar (39o) — but a write with no poster
	/// keeps the poster that is there.
	pub(crate) async fn video_put(&self, actor: &str, file: &str, body: serde_json::Value) -> Result<Response> {
		/// A sidecar is a few hundred bytes; the cap only stops abuse of the row.
		const META_CAP: usize = 16 * 1024;
		/// A poster is a small WebP, sealed and base64'd (39o makes ~40 KB).
		const POSTER_CAP: usize = 512 * 1024;
		let Some(version) = body.get("version").and_then(|v| v.as_i64()) else { return json_error(400, "version required") };
		let Some(meta) = body.get("meta").and_then(|v| v.as_str()) else { return json_error(400, "meta required: the sealed sidecar") };
		let poster = body.get("poster").and_then(|v| v.as_str());
		if !gorani_formats::placed::is_placed_text(meta) || poster.is_some_and(|p| !gorani_formats::placed::is_placed_text(p)) {
			return json_error(400, "a video sidecar and its poster arrive sealed (GV04)");
		}
		if meta.len() > META_CAP || poster.is_some_and(|p| p.len() > POSTER_CAP) {
			return json_error(413, "a video sidecar is at most 16 KiB, a poster at most 512 KiB");
		}
		#[derive(serde::Deserialize)]
		struct Live {
			sample: i64,
		}
		let live: Vec<Live> = self
			.sql
			.exec("SELECT f.sample AS sample FROM files f JOIN file_versions v ON v.file_id = f.id WHERE f.id = ?1 AND v.version = ?2 AND f.deleted_at IS NULL", Some(vec![file.into(), version.into()]))?
			.to_array()?;
		let Some(row) = live.into_iter().next() else { return json_error(404, "no such live file version") };
		if row.sample != 0 {
			return json_error(400, "a malware sample is never decoded — it has no video sidecar");
		}
		self.sql.exec(
			"INSERT INTO video_meta (file_id, version, meta_sealed, poster_sealed, written_by) VALUES (?1, ?2, ?3, ?4, ?5)
			 ON CONFLICT (file_id, version) DO UPDATE SET meta_sealed = excluded.meta_sealed, poster_sealed = COALESCE(excluded.poster_sealed, video_meta.poster_sealed), written_by = excluded.written_by",
			Some(vec![file.into(), version.into(), meta.into(), bind(poster.map(str::to_string)), actor.into()]),
		)?;
		Response::from_json(&serde_json::json!({ "ok": true }))
	}

	/// `GET files-video/<file>[?version=n]`: the sidecar (and poster) of
	/// version n, or of the living version; 404 when none was written yet —
	/// the client then makes one from the file itself.
	pub(crate) async fn video_get(&self, file: &str, version: Option<i64>) -> Result<Response> {
		#[derive(serde::Deserialize)]
		struct Row {
			version: i64,
			meta_sealed: String,
			poster_sealed: Option<String>,
		}
		let rows: Vec<Row> = match version {
			Some(v) => self.sql.exec("SELECT version, meta_sealed, poster_sealed FROM video_meta WHERE file_id = ?1 AND version = ?2", Some(vec![file.into(), v.into()]))?.to_array()?,
			None => self
				.sql
				.exec("SELECT m.version AS version, m.meta_sealed AS meta_sealed, m.poster_sealed AS poster_sealed FROM video_meta m JOIN files f ON f.id = m.file_id AND f.version = m.version WHERE m.file_id = ?1 AND f.deleted_at IS NULL", Some(vec![file.into()]))?
				.to_array()?,
		};
		match rows.into_iter().next() {
			Some(r) => Response::from_json(&serde_json::json!({ "version": r.version, "meta": r.meta_sealed, "poster": r.poster_sealed })),
			None => json_error(404, "no video sidecar for this version yet"),
		}
	}

	/// `GET files/videos`: every living version's sidecar in one feed — the
	/// Movie tab (39o) opens them with the store key and never reads a
	/// video for its duration. Posters are not in it (a few hundred of them
	/// would be megabytes): `hasPoster` says whether `files-video/<id>` has one.
	pub(crate) async fn videos_feed(&self) -> Result<Response> {
		#[derive(serde::Deserialize)]
		struct Row {
			file_id: String,
			version: i64,
			meta_sealed: String,
			has_poster: i64,
			size: i64,
		}
		let rows: Vec<Row> = self
			.sql
			.exec(
				"SELECT m.file_id AS file_id, m.version AS version, m.meta_sealed AS meta_sealed, m.poster_sealed IS NOT NULL AS has_poster, f.size AS size FROM video_meta m JOIN files f ON f.id = m.file_id AND f.version = m.version WHERE f.deleted_at IS NULL ORDER BY f.created_at, f.id",
				None,
			)?
			.to_array()?;
		Response::from_json(&serde_json::json!({ "videos": rows
			.into_iter()
			.map(|r| serde_json::json!({ "id": r.file_id, "version": r.version, "meta": r.meta_sealed, "hasPoster": r.has_poster != 0, "size": r.size }))
			.collect::<Vec<_>>() }))
	}

	// ── Where each member left off (commit 39o, docs/MOVIES.md) ────────

	/// `GET files/positions?member=<id>` — this member's saved positions in
	/// this area, sealed (`{ file: sealed }`), for the files that still live.
	/// The member is the Worker's (the caller's own id).
	pub(crate) async fn positions_get(&self, req: Request) -> Result<Response> {
		let member = urlquery(req.url()?.query().unwrap_or("")).get("member").cloned().unwrap_or_default();
		#[derive(serde::Deserialize)]
		struct Row {
			file_id: String,
			position_sealed: String,
			updated_at: String,
		}
		let rows: Vec<Row> = self
			.sql
			.exec("SELECT p.file_id AS file_id, p.position_sealed AS position_sealed, p.updated_at AS updated_at FROM watch_positions p JOIN files f ON f.id = p.file_id WHERE p.member = ?1 AND f.deleted_at IS NULL", Some(vec![member.into()]))?
			.to_array()?;
		Response::from_json(&serde_json::json!({ "positions": rows.into_iter().map(|r| serde_json::json!({ "file": r.file_id, "position": r.position_sealed, "updatedAt": r.updated_at })).collect::<Vec<_>>() }))
	}

	/// `PUT files-position/<file> { member, position }` — sealed text, small,
	/// for a live file. A read-only grantee may save theirs (case_need):
	/// where someone paused is theirs, not the file's.
	pub(crate) async fn position_put(&self, file: &str, body: serde_json::Value) -> Result<Response> {
		let member = body.get("member").and_then(|v| v.as_str()).unwrap_or_default();
		let Some(position) = body.get("position").and_then(|v| v.as_str()) else { return json_error(400, "position required: sealed") };
		if member.is_empty() {
			return json_error(400, "the Worker names the member");
		}
		if !gorani_formats::placed::is_placed_text(position) || position.len() > 2048 {
			return json_error(400, "a position arrives sealed (GV04), and small");
		}
		let live: Option<ExistsRow> = self.sql.exec("SELECT 1 AS one FROM files WHERE id = ?1 AND deleted_at IS NULL", Some(vec![file.into()]))?.to_array::<ExistsRow>().ok().and_then(|mut r| r.pop());
		if live.is_none() {
			return json_error(404, "no such file");
		}
		self.sql.exec(
			"INSERT INTO watch_positions (file_id, member, position_sealed, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
			 ON CONFLICT (file_id, member) DO UPDATE SET position_sealed = excluded.position_sealed, updated_at = excluded.updated_at",
			Some(vec![file.into(), member.into(), position.into()]),
		)?;
		Response::from_json(&serde_json::json!({ "ok": true }))
	}

	/// The contributors trail: one row per (file, member) — readable
	/// structure, resolved to display names by the UI via the registry.
	pub(crate) async fn contributor_add(&self, file_id: &str, actor_email: &str) -> Result<()> {
		if actor_email.is_empty() || actor_email == "internal" || actor_email == "device" {
			return Ok(());
		}
		self.sql
			.exec(
				"INSERT OR IGNORE INTO file_contributors (file_id, member, at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![file_id.into(), actor_email.into()]),
			)
			.map(|_| ())
			.map_err(Error::from)
	}

	// ── Files: reads ────────────────────────────────────────────────────

	/// `GET files/list?folder=<id|root|all>&offset=&limit=` — the rows for the
	/// explorer, **without keys** (keys come in batches from files/keys, so a
	/// listing never hands out more key material than a view needs). Folders
	/// come along whole (a family store's tree is small).
	pub(crate) async fn files_list(&self, req: Request) -> Result<Response> {
		let url = req.url()?;
		let q = urlquery(url.query().unwrap_or(""));
		let folder = q.get("folder").cloned().unwrap_or_else(|| "all".to_string());
		let offset = q.get("offset").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
		let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(500).clamp(1, 1000);
		let (rows, total): (Vec<FileSqlRow>, TotalCount) = if folder == "all" {
			let rows = self.sql.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at, owner, sample FROM files WHERE deleted_at IS NULL ORDER BY created_at, id LIMIT ?1 OFFSET ?2", Some(vec![limit.into(), offset.into()]))?.to_array()?;
			let total = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL", None)?.one::<TotalCount>()?;
			(rows, total)
		} else {
			let parent = if folder == "root" { None } else { Some(folder.clone()) };
			let rows = self
				.sql
				.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at, owner, sample FROM files WHERE deleted_at IS NULL AND folder_id IS ?1 ORDER BY created_at, id LIMIT ?2 OFFSET ?3", Some(vec![bind(parent.clone()), limit.into(), offset.into()]))?
				.to_array()?;
			let total = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL AND folder_id IS ?1", Some(vec![bind(parent)]))?.one::<TotalCount>()?;
			(rows, total)
		};
		let folders: Vec<FolderSqlRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE deleted_at IS NULL ORDER BY name_sealed, id", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"total": total.n,
			"files": rows.into_iter().map(|f| serde_json::json!({
				"id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size,
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at, "owner": f.owner, "sample": f.sample != 0,
			})).collect::<Vec<_>>(),
			"folders": folders.into_iter().map(|f| serde_json::json!({
				"id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at,
			})).collect::<Vec<_>>(),
		}))?)
	}

	/// Batched content keys for what is being opened or previewed.
	pub(crate) async fn files_keys(&self, body: serde_json::Value) -> Result<Response> {
		let ids: Vec<String> = body.get("ids").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
		let mut out = serde_json::Map::new();
		for id in ids.into_iter().take(500) {
			let row: Option<VersionSqlRow> = self
				.sql
				.exec(
					"SELECT v.version, v.content_key, v.vault_key_id, v.object_key, v.type_sealed, v.size, v.chunk_size, v.hash_sealed, f.sample AS sample, f.intake_sealed AS intake_sealed, f.collection_sealed AS collection_sealed FROM file_versions v JOIN files f ON f.id = v.file_id AND f.version = v.version WHERE v.file_id = ?1",
					Some(vec![id.clone().into()]),
				)?
				.to_array::<VersionSqlRow>()
				.ok()
				.and_then(|mut r| r.pop());
			if let Some(v) = row {
				out.insert(
					id,
					serde_json::json!({
						"key": v.content_key, "vaultKeyId": v.vault_key_id, "chunk": v.chunk_size,
						"version": v.version, "type": v.type_sealed, "size": v.size, "object": v.object_key,
						"hash": v.hash_sealed, "sample": v.sample != 0, "intake": v.intake_sealed,
						// (commit 37c) a file accepted from the inbox: the collector's record.
						"collection": v.collection_sealed,
					}),
				);
			}
		}
		Ok(Response::from_json(&serde_json::json!({ "keys": out }))?)
	}

	/// Structure for the viewer pane (no keys): what the row says, current version.
	pub(crate) async fn files_meta(&self, req: Request) -> Result<Response> {
		let url = req.url()?;
		let ids: Vec<String> = urlquery(url.query().unwrap_or("")).get("ids").map(|s| s.split(',').map(str::to_string).collect()).unwrap_or_default();
		let mut out = Vec::new();
		for id in ids.into_iter().take(200) {
			if let Some(row) = self.file_sql_row(&id).await? {
				out.push(serde_json::json!({
					"id": row.id, "folder": row.folder_id, "name": row.name_sealed, "size": row.size,
					"version": row.version, "createdAt": row.created_at, "updatedAt": row.updated_at, "sample": row.sample != 0,
					"deleted": false,
				}));
			}
		}
		Ok(Response::from_json(&serde_json::json!({ "files": out }))?)
	}

	/// What changed after a cursor — the journal, paged (the feed IS the
	/// journal; see member.rs). Kinds: file.put/file.purge/folder.put/
	/// folder.purge/version.put; deleted flags travel inside file.put rows.
	pub(crate) async fn files_changes(&self, req: Request) -> Result<Response> {
		let url = req.url()?;
		let q = urlquery(url.query().unwrap_or(""));
		let since = q.get("since").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
		let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(1000).clamp(1, 5000);
		let rows: Vec<JournalRow> = self
			.sql
			.exec("SELECT seq, kind, data, at FROM files_journal WHERE seq > ?1 ORDER BY seq LIMIT ?2", Some(vec![since.into(), limit.into()]))?
			.to_array()?;
		let cursor = rows.last().map(|r| r.seq).unwrap_or(since);
		let more = rows.len() as i64 == limit;
		Ok(Response::from_json(&serde_json::json!({
			"cursor": cursor, "more": more,
			"changes": rows.into_iter().map(|r| serde_json::json!({ "seq": r.seq, "kind": r.kind, "at": r.at, "data": serde_json::from_str::<serde_json::Value>(&r.data).unwrap_or(serde_json::Value::Null) })).collect::<Vec<_>>(),
		}))?)
	}

	/// `GET files/match?size=` — the duplicate check: every live file of that
	/// exact size with its fingerprint tag (opaque: an HMAC under a secret
	/// only the area's members hold), and — since commit 39n — its folder
	/// and SEALED name, so the browser's prompt can say which file is
	/// already there and where. (The browser compares the tags. The server
	/// stores them, so it could always see that two tags are equal — what
	/// it cannot learn is what the bytes are, or match them to a hash it
	/// knows.)
	pub(crate) async fn files_match(&self, req: Request) -> Result<Response> {
		let url = req.url()?;
		let Some(size) = urlquery(url.query().unwrap_or("")).get("size").and_then(|v| v.parse::<i64>().ok()) else { return json_error(400, "size required") };
		let rows: Vec<MatchRow> = self
			.sql
			.exec(
				"SELECT f.id, v.tag, f.folder_id, f.name_sealed, f.owner AS owner, (SELECT group_concat(member, ',') FROM file_contributors c WHERE c.file_id = f.id) AS contributors FROM files f JOIN file_versions v ON v.file_id = f.id AND v.version = f.version WHERE f.size = ?1 AND f.deleted_at IS NULL",
				Some(vec![size.into()]),
			)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "files": rows.into_iter().map(|r| serde_json::json!({ "id": r.id, "tag": r.tag, "folder": r.folder_id, "name": r.name_sealed, "owner": r.owner, "contributors": r.contributors })).collect::<Vec<_>>() }))?)
	}

	/// `GET files/duplicates` (commit 39n, Find duplicates): every live file
	/// whose living version shares its size AND its fingerprint tag with
	/// another — folder, sealed name and time, for the browser to group,
	/// open and show. Nothing new is told to anyone: the tags are opaque
	/// HMACs the server already stores (it could always see that two are
	/// equal); the names stay sealed. Capped at 5 000 rows, largest first —
	/// the copies worth finding.
	pub(crate) async fn files_duplicates(&self) -> Result<Response> {
		let rows: Vec<DuplicateRow> = self
			.sql
			.exec(
				"SELECT f.id, f.size, v.tag, f.folder_id, f.name_sealed, f.updated_at FROM files f JOIN file_versions v ON v.file_id = f.id AND v.version = f.version \
				 WHERE f.deleted_at IS NULL AND v.tag IS NOT NULL AND (f.size, v.tag) IN ( \
				   SELECT f2.size, v2.tag FROM files f2 JOIN file_versions v2 ON v2.file_id = f2.id AND v2.version = f2.version \
				   WHERE f2.deleted_at IS NULL AND v2.tag IS NOT NULL GROUP BY f2.size, v2.tag HAVING COUNT(*) > 1) \
				 ORDER BY f.size DESC, v.tag, f.updated_at, f.id LIMIT 5000",
				None,
			)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"files": rows.into_iter().map(|r| serde_json::json!({ "id": r.id, "size": r.size, "tag": r.tag, "folder": r.folder_id, "name": r.name_sealed, "updatedAt": r.updated_at })).collect::<Vec<_>>(),
		}))?)
	}

	/// The `files-object/:id` route: the object's location + wrapped key, for
	/// the Worker to stream from S3. Metadata only — no name, no key material
	/// beyond the wrapped one the client will open.
	/// The object of a version, for the Worker's download route — and the
	/// read audit (O14): every download passes here BEFORE the edge cache, so
	/// a read served from cache is still a read on record. One merged row per
	/// reader × version × client × 5 minutes (a seek is many requests).
	pub(crate) async fn file_object_route(&self, file_id: &str, version: Option<i64>, reader: &str, client: Option<&str>) -> Result<Response> {
		// A protected video (commit 40b): routes.rs › file_download serves the
		// original only to those drm.rs › original_allowed names.
		let protected = self.drm_protected(file_id)?;
		match self.file_object(file_id, version).await? {
			Some(o) if reader != "internal" => {
				// (Sanitised: the client kind is a short label the caller picks.)
				let client: String = client.unwrap_or("unknown").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':').take(64).collect();
				self.sql.exec(
					"INSERT INTO read_log (actor, file_id, version, client, win, first_at, last_at, requests) VALUES (?1, ?2, ?3, ?4, CAST(strftime('%s','now') AS INTEGER) / 300, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), 1) ON CONFLICT (actor, file_id, version, client, win) DO UPDATE SET last_at = excluded.last_at, requests = requests + 1",
					Some(vec![reader.into(), file_id.into(), o.version.into(), client.into()]),
				)?;
				Ok(Response::from_json(&serde_json::json!({
					"objectKey": o.object_key, "ck": o.content_key, "vaultKeyId": o.vault_key_id,
					"chunk": o.chunk_size, "size": o.size, "version": o.version, "hash": o.hash_sealed,
					"protected": protected,
				}))?)
			}
			Some(o) => Ok(Response::from_json(&serde_json::json!({
				"objectKey": o.object_key, "ck": o.content_key, "vaultKeyId": o.vault_key_id,
				"chunk": o.chunk_size, "size": o.size, "version": o.version, "hash": o.hash_sealed,
				"protected": protected,
			}))?),
			None => json_error(404, "no such file"),
		}
	}

	/// The read log (`GET …/reads[?file=]`): who read which version, from
	/// what kind of client, when — newest first. Structure only, like the
	/// rest of this DO; readable to the member, leads and auditors
	/// (routes.rs › audit_ctx), and for a case to anyone on it.
	pub(crate) async fn read_log(&self, file: Option<&str>) -> Result<Response> {
		let rows: Vec<ReadRow> = match file {
			Some(f) => self.sql.exec("SELECT actor, file_id, version, client, first_at, last_at, requests FROM read_log WHERE file_id = ?1 ORDER BY last_at DESC LIMIT 500", Some(vec![f.into()]))?.to_array()?,
			None => self.sql.exec("SELECT actor, file_id, version, client, first_at, last_at, requests FROM read_log ORDER BY last_at DESC LIMIT 500", None)?.to_array()?,
		};
		Ok(Response::from_json(&serde_json::json!({
			"reads": rows.into_iter().map(|r| serde_json::json!({ "actor": r.actor, "file": r.file_id, "version": r.version, "client": r.client, "firstAt": r.first_at, "lastAt": r.last_at, "requests": r.requests })).collect::<Vec<_>>(),
		}))?)
	}

	/// Does a version row point at `<area prefix>/<file>/<obj>`
	/// (`files/<member>/…` or `cases/<case>/…`, area.rs)? The restore fill
	/// (routes.rs › backup_object_fill) writes only to keys a restore
	/// minted — this is how it asks.
	pub(crate) async fn restore_target(&self, member: &str, file_id: &str, obj: &str) -> Result<Response> {
		let key = format!("{}/{file_id}/{obj}", crate::area::key_prefix(member));
		let n = self.sql.exec("SELECT COUNT(*) AS n FROM file_versions WHERE file_id = ?1 AND object_key = ?2", Some(vec![file_id.into(), key.into()]))?.one::<TotalCount>()?.n;
		if n == 0 {
			return json_error(404, "no such restore target");
		}
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// The object of a version, for the Worker to stream from S3 with its
	/// wrapped key in a header.
	async fn file_object(&self, file_id: &str, version: Option<i64>) -> Result<Option<ObjectRow>> {
		let row: Option<ObjectRow> = match version {
			Some(v) => self
				.sql
				.exec("SELECT version, content_key, vault_key_id, object_key, chunk_size, size, hash_sealed FROM file_versions WHERE file_id = ?1 AND version = ?2", Some(vec![file_id.into(), v.into()]))?
				.to_array::<ObjectRow>()
				.ok()
				.and_then(|mut r| r.pop()),
			None => self
				.sql
				.exec(
					"SELECT v.version, v.content_key, v.vault_key_id, v.object_key, v.chunk_size, v.size, v.hash_sealed FROM file_versions v JOIN files f ON f.id = v.file_id AND f.version = v.version WHERE f.id = ?1",
					Some(vec![file_id.into()]),
				)?
				.to_array::<ObjectRow>()
				.ok()
				.and_then(|mut r| r.pop()),
		};
		Ok(row)
	}

	// ── Files: change (rename, move, trash) ─────────────────────────────

	pub(crate) async fn file_patch(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		if body.get("sample").is_some() {
			return self.file_mark_sample(actor, id, &body).await;
		}
		let name = body.get("name").and_then(|v| v.as_str()).map(str::to_string);
		if let Some(n) = &name {
			if !gorani_formats::placed::is_placed_text(n) {
				return json_error(400, "names must be placed sealed text (GV04)");
			}
		}
		// Dynamic SET list: `folderId: null` means "move to the root" — a
		// COALESCE could never express that, so absent means unchanged and
		// explicit null means root.
		let mut sets: Vec<&str> = vec![];
		let mut params: Vec<worker::SqlStorageValue> = vec![];
		if let Some(n) = &name {
			sets.push("name_sealed = ?");
			params.push(n.clone().into());
		}
		if body.get("folderId").is_some() {
			match body.get("folderId").and_then(|v| v.as_str()).map(str::to_string) {
				Some(f) => {
					if let Some(refused) = self.folder_refusal(Some(&f)).await? {
						return Ok(refused);
					}
					sets.push("folder_id = ?");
					params.push(f.into());
				}
				None => sets.push("folder_id = NULL"),
			}
		}
		if sets.is_empty() {
			return json_error(400, "nothing to change");
		}
		sets.push("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')");
		params.push(id.into());
		let sql = format!("UPDATE files SET {} WHERE id = ? AND deleted_at IS NULL", sets.join(", "));
		let n = self.sql.exec(&sql, Some(params))?.rows_written();
		if n == 0 {
			return json_error(404, "no such file");
		}
		self.audit(actor, "file.update", id, None, None).await?;
		self.file_row(id).await
	}

	/// To the Trash (deleted_at; bytes stay). Purges come with the
	/// housekeeping commit.
	/// Mark a file as a malware sample (commit 29e, docs/CUSTODY.md › Stage
	/// 5, D8): `PATCH files/<id> { sample: true, types: { "<n>": <sealed>, … } }`.
	///
	/// - **One way.** `sample: false` is refused: a sample never turns back
	///   into a normal file — someone uploads a new one, on the record.
	/// - **Every version's type, re-sealed, in the same request** — the
	///   client's own mark (`application/x-gorani-sample; original=…`, sealed
	///   into each version's `file.type` place), which a server cannot clear
	///   later. A mark that leaves a version out, or names one the file does
	///   not have, is refused: no version of a sample reads as a normal file.
	async fn file_mark_sample(&self, actor: &str, id: &str, body: &serde_json::Value) -> Result<Response> {
		if body.get("sample").and_then(|v| v.as_bool()) != Some(true) {
			return json_error(400, "a sample stays a sample: there is no unmarking (upload a new file instead, on the record)");
		}
		let Some(file) = self.file_sql_row(id).await? else { return json_error(404, "no such file") };
		let types = body.get("types").and_then(|v| v.as_object()).cloned().unwrap_or_default();
		#[derive(serde::Deserialize)]
		struct Ver {
			version: i64,
		}
		let versions: Vec<Ver> = self.sql.exec("SELECT version FROM file_versions WHERE file_id = ?1", Some(vec![id.into()]))?.to_array()?;
		let mut plan = Vec::with_capacity(versions.len());
		for v in &versions {
			let Some(t) = types.get(&v.version.to_string()).and_then(|t| t.as_str()) else {
				return json_error(400, &format!("re-seal every version's type as a sample's (version {} is missing)", v.version));
			};
			if !gorani_formats::placed::is_placed_text(t) {
				return json_error(400, "types must be placed sealed text (GV04)");
			}
			plan.push((v.version, t.to_string()));
		}
		if types.len() != versions.len() {
			return json_error(400, "types names a version this file does not have");
		}
		// (Validated whole, then applied: a refusal above wrote nothing.)
		for (version, t) in plan {
			self.sql.exec("UPDATE file_versions SET type_sealed = ?1 WHERE file_id = ?2 AND version = ?3", Some(vec![t.into(), id.into(), version.into()]))?;
		}
		if file.sample == 0 {
			self.sql.exec("UPDATE files SET sample = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1", Some(vec![id.into()]))?;
		}
		self.audit(actor, "file.sample", id, None, None).await?;
		self.file_row(id).await
	}

	/// Is this store an EVIDENCE case (D6/D7, commit 29b)? Its settings say
	/// so from the moment the case is opened (routes.rs › case_open).
	pub(crate) async fn is_evidence(&self) -> Result<bool> {
		Ok(self.vault_settings().await?.is_some_and(|s| s.get("kind").and_then(|k| k.as_str()) == Some("evidence")))
	}

	/// Evidence is never deleted (D7: "every version, for the case's life
	/// + retention"; D6 makes the objects themselves write-once). A file can
	/// gain versions, be renamed and moved — the audit records each — but
	/// it does not go to the Trash, so nothing ever purges it.
	///
	/// A legal hold (commit 29f) refuses the same, on any case, until two
	/// people lift it (family/approvals.rs).
	async fn evidence_refusal(&self) -> Result<Option<Response>> {
		if self.is_evidence().await? {
			return Ok(Some(json_error(409, "this is an evidence case: its files and folders are never deleted — they leave with the case's retention")?));
		}
		if self.is_held().await? {
			return Ok(Some(json_error(409, "this case is under a legal hold: nothing is deleted until two leads lift it")?));
		}
		Ok(None)
	}

	/// The uploader's signed content hash (commit 29d, docs/CUSTODY.md ›
	/// Stage 4, D5.1): `{ sha256, size, signer, keyId, signature }` over the
	/// PLAINTEXT, sealed into `file.hash(area, file, version)`. The store
	/// can check only its shape (GV04 text) — the signature and the hash are
	/// inside the seal, for readers to verify. Evidence REQUIRES it: an
	/// evidence version nobody vouched for is exactly what a later review
	/// cannot use. Elsewhere it is optional (sent when the client can sign).
	/// Checked before the first write, like every refusal here (commit 25).
	async fn hash_refusal(&self, hash: Option<&str>) -> Result<Option<Response>> {
		match hash {
			Some(h) if !gorani_formats::placed::is_placed_text(h) => Ok(Some(json_error(400, "the content hash must arrive sealed into its place (GV04)")?)),
			None if self.is_evidence().await? => Ok(Some(json_error(400, "an evidence version must carry its uploader's signed content hash (docs/CUSTODY.md › stage 4) — this client did not send one")?)),
			_ => Ok(None),
		}
	}

	pub(crate) async fn file_trash(&self, actor: &str, id: &str) -> Result<Response> {
		if let Some(refused) = self.evidence_refusal().await? {
			return Ok(refused);
		}
		let n = self
			.sql
			.exec("UPDATE files SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND deleted_at IS NULL", Some(vec![id.into()]))?
			.rows_written();
		if n == 0 {
			return json_error(404, "no such file");
		}
		self.audit(actor, "file.trash", id, None, None).await?;
		self.file_row(id).await
	}

	// ── Folders ─────────────────────────────────────────────────────────

	pub(crate) async fn folder_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let name = body.get("name").and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| worker::Error::RustError("missing name".into()))?;
		if !gorani_formats::placed::is_placed_text(&name) {
			return json_error(400, "names must be placed sealed text (GV04)");
		}
		let parent = body.get("parentId").and_then(|v| v.as_str()).map(str::to_string);
		if let Some(p) = &parent {
			let exists: Option<ExistsRow> = self.sql.exec("SELECT 1 AS one FROM file_folders WHERE id = ?1 AND deleted_at IS NULL", Some(vec![p.clone().into()]))?.to_array::<ExistsRow>().ok().and_then(|mut r| r.pop());
			if exists.is_none() {
				return json_error(404, "no such folder: the parent was deleted or moved to the Trash (on another device?) — refresh, and choose another");
			}
		}
		let id = body.get("id").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(uuid);
		self.sql
			.exec(
				"INSERT INTO file_folders (id, parent_id, name_sealed, created_at, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![id.clone().into(), parent.into(), name.into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("folder insert: {e}")))?;
		self.audit(actor, "folder.create", &id, None, None).await?;
		let folders: Vec<FolderSqlRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE id = ?1", Some(vec![id.into()]))?.to_array()?;
		let f = folders.first().cloned().ok_or_else(|| worker::Error::RustError("insert vanished".into()))?;
		Ok(Response::from_json(&serde_json::json!({ "id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at }))?)
	}

	pub(crate) async fn folder_patch(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let name = body.get("name").and_then(|v| v.as_str()).map(str::to_string);
		if let Some(n) = &name {
			if !gorani_formats::placed::is_placed_text(n) {
				return json_error(400, "names must be placed sealed text (GV04)");
			}
		}
		let parent_new: Option<Option<String>> = if body.get("parentId").is_some() {
			Some(body.get("parentId").and_then(|v| v.as_str()).map(str::to_string))
		} else {
			None
		};
		if let Some(Some(p)) = &parent_new {
			// Cycle check: walk up from the new parent; reaching ourselves
			// would make a loop the tree can never leave.
			let mut cursor: Option<String> = Some(p.clone());
			for _ in 0..64 {
				let Some(c) = cursor else { break };
				if c == id {
					return json_error(400, "a folder cannot move into itself");
				}
				let row: Option<FolderSqlRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE id = ?1", Some(vec![c.into()]))?.to_array::<FolderSqlRow>().ok().and_then(|mut r| r.pop());
				cursor = row.and_then(|r| r.parent_id);
			}
			let exists: Option<ExistsRow> = self.sql.exec("SELECT 1 AS one FROM file_folders WHERE id = ?1 AND deleted_at IS NULL", Some(vec![p.clone().into()]))?.to_array::<ExistsRow>().ok().and_then(|mut r| r.pop());
			if exists.is_none() {
				return json_error(404, "no such folder: the parent was deleted or moved to the Trash (on another device?) — refresh, and choose another");
			}
		}
		let mut sets: Vec<&str> = vec![];
		let mut params: Vec<worker::SqlStorageValue> = vec![];
		if let Some(n) = &name {
			sets.push("name_sealed = ?");
			params.push(n.clone().into());
		}
		if let Some(p) = &parent_new {
			sets.push("parent_id = ?");
			params.push(bind(p.clone()));
		}
		if sets.is_empty() {
			return json_error(400, "nothing to change");
		}
		sets.push("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')");
		params.push(id.into());
		let sql = format!("UPDATE file_folders SET {} WHERE id = ? AND deleted_at IS NULL", sets.join(", "));
		let n = self.sql.exec(&sql, Some(params))?.rows_written();
		if n == 0 {
			return json_error(404, "no such folder");
		}
		self.audit(actor, "folder.update", id, None, None).await?;
		let folders: Vec<FolderSqlRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE id = ?1", Some(vec![id.into()]))?.to_array()?;
		let f = folders.first().cloned().ok_or_else(|| worker::Error::RustError("row vanished".into()))?;
		Ok(Response::from_json(&serde_json::json!({ "id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at }))?)
	}

	/// To the Trash, recursively: the folder and everything under it
	/// (trashed_with names the folder so restore can bring back exactly what
	/// the deletion took).
	pub(crate) async fn folder_trash(&self, actor: &str, id: &str) -> Result<Response> {
		if let Some(refused) = self.evidence_refusal().await? {
			return Ok(refused);
		}
		// Count first, then update — as trash_restore does: rows_written
		// also counts the change-feed trigger's writes, so it overstated the
		// report (and a folder's trip through the Trash read 6 + 3 for 2 + 1).
		const TREE: &str = "WITH RECURSIVE d(id) AS (SELECT id FROM file_folders WHERE id = ?1 AND deleted_at IS NULL UNION ALL SELECT f.id FROM file_folders f JOIN d ON f.parent_id = d.id WHERE f.deleted_at IS NULL)";
		let p = Some(vec![id.into()]);
		let n = self.sql.exec(&format!("{TREE} SELECT COUNT(*) AS n FROM d"), p.clone())?.one::<TotalCount>()?.n;
		if n == 0 {
			return json_error(404, "no such folder");
		}
		let files = self.sql.exec(&format!("{TREE} SELECT COUNT(*) AS n FROM files WHERE folder_id IN (SELECT id FROM d) AND deleted_at IS NULL"), p.clone())?.one::<TotalCount>()?.n;
		// Files first, while the tree still reads as living; then the folders.
		self.sql.exec(
			&format!("{TREE} UPDATE files SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), trashed_with = ?1 WHERE folder_id IN (SELECT id FROM d) AND deleted_at IS NULL"),
			p.clone(),
		)?;
		self.sql.exec(&format!("{TREE} UPDATE file_folders SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), trashed_with = ?1 WHERE id IN (SELECT id FROM d)"), p)?;
		self.audit(actor, "folder.trash", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "folders": n, "files": files }))?)
	}

	// ── Share links (GS01): rows + multipart bookkeeping ────────────────

	/// Create a share row. The route has already opened the S3 multipart
	/// upload for the sealed copy (object `shares/<id>`) and hands its id in.
	pub(crate) async fn share_create(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		// (Commit 23: this line was `self.vault_gate().await?;` — the `?` only
		// propagates a SQL *error*; the refusal message in the Ok(Some(..))
		// was dropped on the floor, so a paused or absent vault could still
		// mint share links. A gate whose answer nobody reads is not a gate.)
		if let Some(msg) = self.vault_gate().await? {
			return json_error(400, &msg);
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let id = get("id").ok_or_else(|| worker::Error::RustError("missing id".into()))?;
		if !(22..=64).contains(&id.len()) || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
			return json_error(400, "share id shape");
		}
		let name = get("nameSealed").ok_or_else(|| worker::Error::RustError("missing nameSealed".into()))?;
		let meta = get("metaSealed").ok_or_else(|| worker::Error::RustError("missing metaSealed".into()))?;
		// The name is sealed to the owner's store key (GV*); the meta is
		// sealed to the link's meta key (GS01) — different keys, different
		// readers, both opaque here.
		if !gorani_formats::placed::is_placed_text(&name) {
			return json_error(400, "the share name must be placed sealed text (GV04)");
		}
		// sealShareMeta returns base64("GS01" ‖ nonce ‖ ct) — check the magic
		// after decoding (the recipient's page derives the meta key and opens
		// it; the server never can).
		let meta_ok = base64::engine::general_purpose::STANDARD.decode(&meta).map(|b| b.starts_with(b"GS01")).unwrap_or(false);
		if !meta_ok {
			return json_error(400, "the share meta must be sealed (GS01)");
		}
		let Some(expires_at) = get("expiresAt") else { return json_error(400, "expiresAt required") };
		let downloads_left = body.get("downloadsLeft").and_then(|v| v.as_i64()).unwrap_or(5);
		if let Some(msg) = share_policy_refusal(body.get("kdf"), &expires_at, downloads_left, worker::Date::now().as_millis() as f64) {
			return json_error(400, &msg);
		}
		// A view-only link (commit 40b) plays the file's protected copy: no
		// sealed copy of its own, so no upload — and it is made only for a
		// protected file whose current version's copy is ready.
		let drm = body.get("drm").and_then(|v| v.as_bool()) == Some(true);
		let claim_hash = get("claimHash");
		if drm {
			let Some(file_id) = get("fileId") else { return json_error(400, "a view-only link names its file") };
			if !self.drm_ready_current(&file_id)? {
				return json_error(409, "a view-only link plays the protected copy — protect this video first, and wait until its copy is ready");
			}
			// SHA-256 of the proof the page derives from the link's secret
			// and password, base64url: 43 characters.
			if !claim_hash.as_deref().is_some_and(|h| h.len() == 43 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
				return json_error(400, "a view-only link carries claimHash: SHA-256 (base64url) of the proof its page derives from the link's secret and password");
			}
		}
		let s3_upload_id = match get("s3UploadId") {
			Some(u) => u,
			None if drm => String::new(),
			None => return json_error(400, "s3UploadId required"),
		};
		// A malware sample never leaves by link (D8, commit 29e): a link's
		// recipient gets the bytes in a browser, outside every rule here. A
		// partner who needs the sample gets the case (D11) — and the zip.
		if let Some(file_id) = get("fileId") {
			if self.file_sql_row(&file_id).await?.is_some_and(|f| f.sample != 0) {
				return json_error(409, "a malware sample is never shared by link — grant the partner the case instead (docs/CUSTODY.md › stage 5)");
			}
		}
		self.sql
			.exec(
				"INSERT INTO shares (id, file_id, version, name_sealed, object_key, meta_sealed, kdf, expires_at, downloads_left, created_at, s3_upload_id, ready, size, drm, claim_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?10, ?12, ?11, ?12, ?13)",
				Some(vec![
					id.clone().into(),
					bind(get("fileId")),
					body.get("version").and_then(|v| v.as_i64()).unwrap_or(1).into(),
					name.into(),
					if drm { String::new() } else { format!("shares/{id}") }.into(),
					meta.into(),
					bind(body.get("kdf").map(|k| k.to_string())),
					expires_at.into(),
					downloads_left.into(),
					s3_upload_id.into(),
					body.get("size").and_then(|v| v.as_i64()).into(),
					i64::from(drm).into(),
					bind(claim_hash.filter(|_| drm)),
				]),
			)
			.map_err(|e| worker::Error::RustError(format!("share insert: {e}")))?;
		self.audit(actor, "share.create", &id, None, drm.then_some("view-only (protected copy)")).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// The object + multipart id for the route's S3 calls (auth'd path only).
	pub(crate) async fn share_obj(&self, id: &str) -> Result<Response> {
		let rows: Vec<ShareRow> = self.sql.exec("SELECT object_key, s3_upload_id FROM shares WHERE id = ?1", Some(vec![id.into()]))?.to_array()?;
		match rows.into_iter().next() {
			Some(r) => Ok(Response::from_json(&serde_json::json!({ "objectKey": r.object_key, "s3UploadId": r.s3_upload_id }))?),
			None => json_error(404, "no such share"),
		}
	}

	pub(crate) async fn share_complete(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let size = body.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
		let n = self.sql.exec("UPDATE shares SET ready = 1, size = ?1 WHERE id = ?2", Some(vec![size.into(), id.into()]))?.rows_written();
		if n == 0 {
			return json_error(404, "no such share");
		}
		self.audit(actor, "share.ready", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	/// The owner's list (names re-sealed to the files key — opened by the UI).
	pub(crate) async fn shares_list(&self) -> Result<Response> {
		let rows: Vec<ShareListRow> = self
			.sql
			.exec("SELECT id, file_id, name_sealed, expires_at, downloads_left, created_at, revoked_at, ready, size, drm FROM shares ORDER BY created_at DESC", None)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::Value::Array(
			rows.into_iter()
				.map(|r| {
					serde_json::json!({
						"id": r.id, "fileId": r.file_id, "name": r.name_sealed,
						"expiresAt": r.expires_at, "downloadsLeft": r.downloads_left,
						"createdAt": r.created_at, "revoked": r.revoked_at.is_some(),
						"ready": r.ready != 0, "size": r.size, "viewOnly": r.drm != 0,
					})
				})
				.collect(),
		))?)
	}

	pub(crate) async fn share_revoke(&self, actor: &str, id: &str) -> Result<Response> {
		let n = self.sql.exec("UPDATE shares SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND revoked_at IS NULL", Some(vec![id.into()]))?.rows_written();
		if n == 0 {
			return json_error(404, "no such share");
		}
		self.audit(actor, "share.revoke", id, None, None).await?;
		let object = self.share_object_key(id).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true, "objectKey": object }))?)
	}

	async fn share_object_key(&self, id: &str) -> Result<String> {
		let rows: Vec<ShareObjRow> = self.sql.exec("SELECT object_key FROM shares WHERE id = ?1", Some(vec![id.into()]))?.to_array()?;
		Ok(rows.into_iter().next().map(|r| r.object_key).ok_or_else(|| worker::Error::RustError("no such share".into()))?)
	}
	// (ShareObjRow below)

	/// The share's state for the PUBLIC endpoints: ready, not revoked, not
	/// expired, downloads left. Errors carry the status the route returns.
	async fn share_public_check(&self, id: &str) -> std::result::Result<ShareRow2, Response> {
		let rows: Vec<ShareRow2> = match self
			.sql
			.exec("SELECT meta_sealed, kdf, expires_at, downloads_left, ready, revoked_at, expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now') AS expired, drm, claim_hash FROM shares WHERE id = ?1", Some(vec![id.into()]))
		{
			Ok(c) => match c.to_array() {
				Ok(rows) => rows,
				Err(e) => return Err(json_error_raw(500, &e.to_string())),
			},
			Err(e) => return Err(json_error_raw(500, &e.to_string())),
		};
		let Some(r) = rows.into_iter().next() else { return Err(json_error_raw(404, "no such share")) };
		if r.ready == 0 {
			return Err(json_error_raw(404, "the link is still being prepared"));
		}
		if r.revoked_at.is_some() {
			return Err(json_error_raw(404, "no such share"));
		}
		if r.expired == 1 {
			return Err(json_error_raw(410, "this link has expired"));
		}
		if r.downloads_left <= 0 {
			return Err(json_error_raw(410, "this link is used up"));
		}
		Ok(r)
	}

	pub(crate) async fn share_public_meta(&self, id: &str) -> Result<Response> {
		match self.share_public_check(id).await {
			Ok(r) => Ok(Response::from_json(&serde_json::json!({
				"metaSealed": r.meta_sealed, "kdf": r.kdf.and_then(|k| serde_json::from_str::<serde_json::Value>(&k).ok()),
				"expiresAt": r.expires_at, "downloadsLeft": r.downloads_left,
				// A view-only link (40b): the page plays it, and each claim
				// is a viewing session instead of a download.
				"viewOnly": r.drm != 0,
			}))?),
			Err(resp) => Ok(resp),
		}
	}

	/// One download: decrement the counter (0 and below stay refused above).
	/// Spend one download and hand back the token that /data asks for
	/// (commit 25, docs/SECURITY-REVIEW.md › O12).
	///
	/// Before: the claim decremented a counter and /data served the copy to
	/// anyone holding the link — no claim needed, so "2 downloads" meant
	/// "as many as you like, if you skip the button". And /data re-ran the
	/// claim's own check (`downloads_left > 0`), so the claim that spent the
	/// LAST download was followed by a refused /data: a one-download link
	/// could never be downloaded at all.
	///
	/// Now one claim = one download session: a random token (only its
	/// SHA-256 is stored), valid for an hour — long enough for a large copy
	/// fetched in Range pieces, short enough that a token found later in a
	/// history file is dead.
	pub(crate) async fn share_claim(&self, id: &str, body: &serde_json::Value) -> Result<Response> {
		match self.share_public_check(id).await {
			Ok(r) => {
				// A view-only link's claim proves the link's secret and password
				// (40b): the hash of the page's proof must be the stored one.
				if r.drm != 0 {
					let proof = body.get("proof").and_then(|p| p.as_str()).unwrap_or_default();
					let ok = !proof.is_empty() && r.claim_hash.as_deref().is_some_and(|h| constant_eq(h.as_bytes(), token_hash(proof).as_bytes()));
					if !ok {
						self.audit("share-link", "share.refused", id, None, Some("a view-only claim without the link's proof")).await?;
						return json_error(403, "the password is not this link's");
					}
				}
				let left = r.downloads_left - 1;
				self.sql.exec("UPDATE shares SET downloads_left = ?1 WHERE id = ?2", Some(vec![left.into(), id.into()]))?;
				let mut raw = [0u8; 32];
				OsRng.fill_bytes(&mut raw);
				let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
				// A view-only link's claim is a viewing session (40b): long
				// enough for a film watched with pauses — and a license is
				// asked for at the start, so the session ending stops the next
				// play, not the one in progress.
				let ttl = if r.drm != 0 { 8 * 3600 } else { 3600 };
				self.sql.exec(
					&format!("INSERT INTO share_tokens (hash, share_id, expires_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now','+{ttl} seconds'))"),
					Some(vec![token_hash(&token).into(), id.into()]),
				)?;
				// The owner's audit records each download of their link (O14).
				self.audit("share-link", if r.drm != 0 { "share.view" } else { "share.claim" }, id, None, Some(&format!("downloadsLeft:{left}"))).await?;
				Ok(Response::from_json(&serde_json::json!({ "downloadsLeft": left, "token": token, "tokenExpiresIn": ttl, "viewOnly": r.drm != 0 }))?)
			}
			Err(resp) => Ok(resp),
		}
	}

	/// The sealed copy's object key — for a LIVE token of this share, on a
	/// share that is still live (ready, not revoked, not expired). The
	/// download count is NOT checked here: the claim that minted the token
	/// already spent its download.
	pub(crate) async fn share_public_object(&self, id: &str, token: &str) -> std::result::Result<String, Response> {
		let live = !token.is_empty()
			&& self
				.sql
				.exec(
					"SELECT 1 AS one FROM share_tokens WHERE hash = ?1 AND share_id = ?2 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
					Some(vec![token_hash(token).into(), id.into()]),
				)
				.ok()
				.and_then(|c| c.to_array::<ExistsRow>().ok())
				.is_some_and(|r| !r.is_empty());
		if !live {
			return Err(json_error_raw(403, "claim a download first (the link's data needs the token a claim returns)"));
		}
		let rows: Vec<ShareLive> = self
			.sql
			.exec("SELECT object_key, ready, revoked_at, expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now') AS expired FROM shares WHERE id = ?1", Some(vec![id.into()]))
			.and_then(|c| c.to_array())
			.map_err(|e| json_error_raw(500, &e.to_string()))?;
		match rows.into_iter().next() {
			// A view-only link has no copy to download (40b).
			Some(r) if r.object_key.is_empty() => Err(json_error_raw(409, "this link is view-only: it plays in its page and has nothing to download")),
			Some(r) if r.ready != 0 && r.revoked_at.is_none() && r.expired == 0 => Ok(r.object_key),
			Some(r) if r.expired == 1 => Err(json_error_raw(410, "this link has expired")),
			_ => Err(json_error_raw(404, "no such share")),
		}
	}

	// ── Files secrets (fingerprint + index keys, sealed) ────────────────

	pub(crate) async fn secrets_get(&self) -> Result<Response> {
		let row: Option<KvRow> = self.sql.exec("SELECT v FROM files_secrets LIMIT 1", None)?.to_array::<KvRow>().ok().and_then(|mut r| r.pop());
		Ok(Response::from_json(&serde_json::json!({ "sealed": row.map(|r| r.v) }))?)
	}

	pub(crate) async fn secrets_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(sealed) = body.get("sealed").and_then(|v| v.as_str()).map(str::to_string) else { return json_error(400, "sealed required") };
		if !gorani_formats::placed::is_placed_text(&sealed) {
			return json_error(400, "secrets must be placed sealed text (GV04)");
		}
		self.sql.exec("DELETE FROM files_secrets", None)?;
		self.sql.exec("INSERT INTO files_secrets (v) VALUES (?1)", Some(vec![sealed.into()]))?;
		self.audit(actor, "files.secrets", "secrets", None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	// ── Upload bookkeeping (the Worker drives S3; the DO remembers) ─────

	pub(crate) async fn upload_start(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let object_key = body.get("objectKey").and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| worker::Error::RustError("missing objectKey".into()))?;
		let file_id = body.get("fileId").and_then(|v| v.as_str()).map(str::to_string);
		let id = uuid();
		self.sql
			.exec(
				"INSERT INTO uploads (id, object_key, file_id, s3_upload_id, created_at) VALUES (?1, ?2, ?3, 'pending', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![id.clone().into(), object_key.into(), file_id.into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("upload insert: {e}")))?;
		self.audit(actor, "file.uploadStart", &id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "uploadId": id }))?)
	}

	pub(crate) async fn upload_set_s3(&self, id: &str, s3_upload_id: &str) -> Result<Response> {
		self.sql.exec("UPDATE uploads SET s3_upload_id = ?1 WHERE id = ?2", Some(vec![s3_upload_id.into(), id.into()]))?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	pub(crate) async fn upload_get(&self, id: &str) -> Result<Response> {
		let row: Option<UploadRow> = self.sql.exec("SELECT object_key, file_id, s3_upload_id FROM uploads WHERE id = ?1", Some(vec![id.into()]))?.to_array::<UploadRow>().ok().and_then(|mut r| r.pop());
		match row {
			Some(r) => Ok(Response::from_json(&serde_json::json!({ "objectKey": r.object_key, "fileId": r.file_id, "s3UploadId": r.s3_upload_id }))?),
			None => json_error(404, "no such upload"),
		}
	}

	/// Record the completed multipart upload as a file or a new version. The
	/// Worker has completed the S3 upload and checked the size; the DO only
	/// writes rows and removes the bookkeeping.
	pub(crate) async fn upload_complete(&self, actor: &str, id: &str, body: serde_json::Value) -> Result<Response> {
		let row: Option<UploadRow> = self.sql.exec("SELECT object_key, file_id, s3_upload_id FROM uploads WHERE id = ?1", Some(vec![id.into()]))?.to_array::<UploadRow>().ok().and_then(|mut r| r.pop());
		let Some(upload) = row else { return json_error(404, "no such upload") };
		let mut body = body;
		if body.get("objectKey").is_none() {
			body["objectKey"] = serde_json::json!(upload.object_key);
		}
		let target = body.get("fileId").and_then(|v| v.as_str()).map(str::to_string).or(upload.file_id.clone());
		let response = match target {
			Some(fid) => {
				body["fileId"] = serde_json::json!(fid);
				self.file_version_put(actor, body).await?
			}
			None => {
				// A new file: its client-chosen id is the object key's file
				// segment (`files/<member>/<file>/u-…`, set at start).
				body["id"] = serde_json::json!(upload.object_key.split('/').nth(2).unwrap_or_default());
				self.file_put(actor, body).await?
			}
		};
		if response.status_code() < 400 {
			self.sql.exec("DELETE FROM uploads WHERE id = ?1", Some(vec![id.into()]))?;
		}
		Ok(response)
	}

	pub(crate) async fn upload_abort(&self, actor: &str, id: &str) -> Result<Response> {
		self.sql.exec("DELETE FROM uploads WHERE id = ?1", Some(vec![id.into()]))?;
		self.audit(actor, "file.uploadAbort", id, None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "ok": true }))?)
	}

	// ── Trash and rotation ──────────────────────────────────────────────

	/// The Trash: what is deleted but not purged, files and folders, with
	/// where it was and whether a folder's deletion took it along.
	pub(crate) async fn trash_list(&self) -> Result<Response> {
		let files: Vec<FileSqlRow> = self
			.sql
			.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at, sample FROM files WHERE deleted_at IS NOT NULL ORDER BY updated_at DESC", None)?
			.to_array()?;
		let folders: Vec<FolderSqlRow> = self
			.sql
			.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE deleted_at IS NOT NULL ORDER BY updated_at DESC", None)?
			.to_array()?;
		let trashed_with: Vec<TrashedWithRow> = self.sql.exec("SELECT id, trashed_with FROM files WHERE deleted_at IS NOT NULL AND trashed_with IS NOT NULL", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"files": files.into_iter().map(|f| serde_json::json!({
				"id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size,
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at, "sample": f.sample != 0,
			})).collect::<Vec<_>>(),
			"folders": folders.into_iter().map(|f| serde_json::json!({
				"id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at,
			})).collect::<Vec<_>>(),
			"trashedWith": trashed_with.into_iter().map(|t| serde_json::json!({ "id": t.id, "with": t.trashed_with })).collect::<Vec<_>>(),
		}))?)
	}

	/// Restore files and folders from the Trash. A folder comes back with
	/// everything its deletion took along — the subfolders and files that
	/// share its `trashed_with` mark (folder_trash) — and nothing else: a file
	/// someone trashed on its own before the folder went stays in the Trash.
	/// A folder whose parent is still in the Trash comes back at the top
	/// level; a file whose folder is still there likewise (the tree must
	/// never dangle).
	pub(crate) async fn trash_restore(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let files: Vec<String> = body.get("files").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
		let folders: Vec<String> = body.get("folders").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
		// Count first, then update: rows_written includes the change-feed
		// trigger's writes (journal + counter), so it cannot be the report.
		let mut n_files = 0;
		let mut n_folders = 0;
		// The subtree one deletion took: the folder, then each trashed child
		// carrying the same mark. `=` rather than `IS`, so a folder trashed
		// before the mark existed (NULL) restores alone instead of sweeping
		// up every unmarked thing beneath it. One folder per statement (a
		// recursive CTE, not an id list): a big tree must not run into the
		// bound-parameter ceiling.
		const SUBTREE: &str = "WITH RECURSIVE d(id) AS (SELECT id FROM file_folders WHERE id = ?1 AND deleted_at IS NOT NULL UNION ALL SELECT f.id FROM file_folders f JOIN d ON f.parent_id = d.id WHERE f.deleted_at IS NOT NULL AND f.trashed_with = (SELECT trashed_with FROM file_folders WHERE id = ?1))";
		const SWEPT_FILES: &str = "FROM files WHERE deleted_at IS NOT NULL AND folder_id IN (SELECT id FROM d) AND trashed_with = (SELECT trashed_with FROM file_folders WHERE id = ?1)";
		for id in &folders {
			let p = Some(vec![id.as_str().into()]);
			n_folders += self.sql.exec(&format!("{SUBTREE} SELECT COUNT(*) AS n FROM d"), p.clone())?.one::<TotalCount>()?.n;
			n_files += self.sql.exec(&format!("{SUBTREE} SELECT COUNT(*) AS n {SWEPT_FILES}"), p.clone())?.one::<TotalCount>()?.n;
			// Files before folders: the files' test reads the folders' marks.
			self.sql.exec(&format!("{SUBTREE} UPDATE files SET deleted_at = NULL, trashed_with = NULL WHERE id IN (SELECT id {SWEPT_FILES})"), p.clone())?;
			self.sql.exec(&format!("{SUBTREE} UPDATE file_folders SET deleted_at = NULL, trashed_with = NULL WHERE id IN (SELECT id FROM d)"), p)?;
		}
		// Re-parent only once every requested folder is back, so restoring a
		// folder together with its (separately trashed) parent keeps it inside.
		for id in &folders {
			self.sql.exec(
				// (Not LIVE — in the Trash, or purged altogether: 39t. Only the
				// Trash was checked, so a folder whose parent had been purged
				// came back inside a folder that no longer existed.)
				"UPDATE file_folders SET parent_id = NULL WHERE id = ?1 AND parent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM file_folders p WHERE p.id = file_folders.parent_id AND p.deleted_at IS NULL)",
				Some(vec![id.as_str().into()]),
			)?;
		}
		if !files.is_empty() {
			let (qs, params) = in_clause(&files);
			n_files += self.sql.exec(&format!("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NOT NULL AND id IN ({qs})"), Some(params.clone()))?.one::<TotalCount>()?.n;
			self.sql
				.exec(
					&format!("UPDATE files SET deleted_at = NULL, trashed_with = NULL, folder_id = CASE WHEN folder_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM file_folders f2 WHERE f2.id = files.folder_id AND f2.deleted_at IS NULL) THEN NULL ELSE folder_id END WHERE id IN ({qs})"),
					Some(params),
				)?;
		}
		if n_files + n_folders > 0 {
			self.audit(actor, "files.restore", &format!("files:{n_files},folders:{n_folders}"), None, None).await?;
		}
		Ok(Response::from_json(&serde_json::json!({ "files": n_files, "folders": n_folders }))?)
	}

	// ── Delete forever (commit 39v) ─────────────────────────────────────

	/// What one deletion for good takes. Named files; named folders with
	/// everything beneath them, living or already in the Trash (a folder
	/// takes what is inside it, as Shift+Delete does); or, for Empty Trash,
	/// exactly what the Trash holds — nothing living, even a stray that sits
	/// in a trashed folder (housekeeping re-homes those, 39t).
	fn purge_targets(&self, files: &[String], folders: &[String], trash: bool) -> Result<(std::collections::BTreeSet<String>, std::collections::BTreeSet<String>)> {
		#[derive(serde::Deserialize)]
		struct IdRow {
			id: String,
		}
		let ids = |rows: Vec<IdRow>| rows.into_iter().map(|r| r.id);
		let mut out_files = std::collections::BTreeSet::new();
		let mut out_folders = std::collections::BTreeSet::new();
		if trash {
			out_files.extend(ids(self.sql.exec("SELECT id FROM files WHERE deleted_at IS NOT NULL", None)?.to_array()?));
			out_folders.extend(ids(self.sql.exec("SELECT id FROM file_folders WHERE deleted_at IS NOT NULL", None)?.to_array()?));
		}
		// (UNION, not UNION ALL: folder_patch refuses cycles, and if one
		// ever got in, the walk would still end.)
		const TREE: &str = "WITH RECURSIVE d(id) AS (SELECT id FROM file_folders WHERE id = ?1 UNION SELECT f.id FROM file_folders f JOIN d ON f.parent_id = d.id)";
		for id in folders {
			let p = Some(vec![id.as_str().into()]);
			out_folders.extend(ids(self.sql.exec(&format!("{TREE} SELECT id FROM d"), p.clone())?.to_array()?));
			out_files.extend(ids(self.sql.exec(&format!("{TREE} SELECT id FROM files WHERE folder_id IN (SELECT id FROM d)"), p)?.to_array()?));
		}
		// Named files that exist (a second device may have been first).
		for chunk in files.chunks(PURGE_CHUNK) {
			let (qs, params) = in_clause(chunk);
			out_files.extend(ids(self.sql.exec(&format!("SELECT id FROM files WHERE id IN ({qs})"), Some(params))?.to_array()?));
		}
		Ok((out_files, out_folders))
	}

	/// `POST files/purge` — Delete forever, and Empty Trash (commit 39v).
	/// Body: `{ files: [ids], folders: [ids] }`, or `{ trash: true }` for
	/// everything in the Trash; `preview: true` answers what it WOULD take
	/// — `{ files, folders, shares }` — and changes nothing, so the
	/// confirmation can say it before anyone agrees.
	///
	/// Only a lead, or the area's owner, gets here (routes.rs ›
	/// purge_allowed). Evidence is never deleted and a legal hold deletes
	/// nothing (evidence_refusal) — neither through the Trash, nor around it.
	///
	/// What goes, in the order the Trash's purge uses (member.rs ›
	/// housekeeping): every object into the deletion outbox FIRST — the
	/// version objects, the share links' copies, unfinished uploads — then
	/// the rows that pointed at them, then the outbox is drained. A file's
	/// share links are revoked at once — they answer as any revoked link
	/// does — and their copies leave storage now rather than at their
	/// expiry. The change feed's
	/// triggers journal each `file.purge` and `folder.purge`, so a synced
	/// device removes its copies too.
	pub(crate) async fn files_purge(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if let Some(refused) = self.evidence_refusal().await? {
			return Ok(refused);
		}
		let list = |k: &str| body.get(k).and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok()).unwrap_or_default();
		let (asked_files, asked_folders) = (list("files"), list("folders"));
		let trash = body.get("trash").and_then(|v| v.as_bool()) == Some(true);
		let preview = body.get("preview").and_then(|v| v.as_bool()) == Some(true);
		if asked_files.len() + asked_folders.len() > PURGE_ASK_CAP {
			return json_error(400, &format!("at most {PURGE_ASK_CAP} items at a time — a folder counts once, whatever it holds"));
		}
		if !trash && asked_files.is_empty() && asked_folders.is_empty() {
			return json_error(400, "name the files and folders to delete forever");
		}
		let (file_set, folder_set) = self.purge_targets(&asked_files, &asked_folders, trash)?;
		let (files, folders): (Vec<String>, Vec<String>) = (file_set.iter().cloned().collect(), folder_set.iter().cloned().collect());
		if files.is_empty() && folders.is_empty() {
			return if trash {
				Ok(Response::from_json(&serde_json::json!({ "files": 0, "folders": 0, "shares": 0 }))?)
			} else {
				json_error(404, "nothing to delete: those items are gone already (on another device?) — refresh")
			};
		}
		// Links that work now — the ones the confirmation warns about (one
		// still being sealed works for nobody yet; it is revoked all the same).
		let mut live_shares = 0i64;
		for chunk in files.chunks(PURGE_CHUNK) {
			let (qs, params) = in_clause(chunk);
			live_shares += self
				.sql
				.exec(&format!("SELECT COUNT(*) AS n FROM shares WHERE file_id IN ({qs}) AND ready = 1 AND revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')"), Some(params))?
				.one::<TotalCount>()?
				.n;
		}
		if preview {
			return Ok(Response::from_json(&serde_json::json!({ "files": files.len(), "folders": folders.len(), "shares": live_shares }))?);
		}

		// 1. Mark what goes, so every step after reads one predicate rather
		// than id lists (the bound-parameter ceiling): into the Trash, if it
		// was not there yet, under this deletion's own mark.
		let mark = format!("purge:{}", uuid());
		for chunk in files.chunks(PURGE_CHUNK) {
			let (qs, mut params) = in_clause(chunk);
			params.push(mark.as_str().into());
			self.sql.exec(&format!("UPDATE files SET deleted_at = COALESCE(deleted_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')), trashed_with = ?{} WHERE id IN ({qs})", chunk.len() + 1), Some(params))?;
		}
		for chunk in folders.chunks(PURGE_CHUNK) {
			let (qs, mut params) = in_clause(chunk);
			params.push(mark.as_str().into());
			self.sql.exec(&format!("UPDATE file_folders SET deleted_at = COALESCE(deleted_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')), trashed_with = ?{} WHERE id IN ({qs})", chunk.len() + 1), Some(params))?;
		}
		let m = || Some(vec![mark.as_str().into()]);
		const MARKED: &str = "SELECT id FROM files WHERE trashed_with = ?1";

		// 2. Objects into the outbox, before the rows that point at them.
		#[derive(serde::Deserialize)]
		struct GoneObject {
			object_key: String,
			s3_upload_id: Option<String>,
		}
		let gone = |sql: &str| -> Result<Vec<GoneObject>> { Ok(self.sql.exec(sql, m())?.to_array()?) };
		let delete = |rows: &[GoneObject], reason: &str| -> Result<()> {
			for r in rows.iter().filter(|r| !r.object_key.is_empty()) {
				self.enqueue_delete(&r.object_key, None, reason)?;
			}
			Ok(())
		};
		// (An open multipart upload holds billed parts until aborted, and its
		// upload id is all that frees them — "pending" means S3 never gave one.)
		let abort = |rows: &[GoneObject], reason: &str| -> Result<()> {
			for r in rows {
				if let Some(u) = r.s3_upload_id.as_deref().filter(|u| !u.is_empty() && *u != "pending") {
					self.enqueue_delete(&format!("{}#upload:{u}", r.object_key), Some(u), reason)?;
				}
			}
			Ok(())
		};
		delete(&gone(&format!("SELECT object_key, NULL AS s3_upload_id FROM file_versions WHERE file_id IN ({MARKED})"))?, "deleted forever")?;
		// The share links' copies — and the upload of one still being sealed
		// (a view-only link has no copy: its object_key is empty, 40b).
		let shares = gone(&format!("SELECT object_key, s3_upload_id FROM shares WHERE file_id IN ({MARKED})"))?;
		delete(&shares, "share copy of a file deleted forever")?;
		abort(&shares, "share copy of a file deleted forever")?;
		// A new version still uploading into one of these files.
		abort(&gone(&format!("SELECT object_key, s3_upload_id FROM uploads WHERE file_id IN ({MARKED})"))?, "upload into a file deleted forever")?;

		// 3. The rows. Shares are revoked here, as Revoke does, and
		// housekeeping removes the rows a day later as it does every revoked
		// one's (their copies are already in the outbox).
		let revoked = self.sql.exec(&format!("SELECT COUNT(*) AS n FROM shares WHERE file_id IN ({MARKED}) AND revoked_at IS NULL"), m())?.one::<TotalCount>()?.n;
		self.sql.exec(&format!("UPDATE shares SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE file_id IN ({MARKED}) AND revoked_at IS NULL"), m())?;
		self.sql.exec(&format!("DELETE FROM uploads WHERE file_id IN ({MARKED})"), m())?;
		// Count first, then delete: rows_written includes the change feed's
		// trigger writes (trash_restore says the same).
		let n_files = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE trashed_with = ?1", m())?.one::<TotalCount>()?.n;
		self.sql.exec("DELETE FROM files WHERE trashed_with = ?1", m())?;
		self.purge_dependents()?;
		let n_folders = self.sql.exec("SELECT COUNT(*) AS n FROM file_folders WHERE trashed_with = ?1", m())?.one::<TotalCount>()?.n;
		self.sql.exec("DELETE FROM file_folders WHERE trashed_with = ?1", m())?;

		// 4. The trail: each item asked for by name, then what it all came
		// to — so a review reads both who chose what and how much went.
		for id in asked_files.iter().filter(|id| file_set.contains(*id)) {
			self.audit(actor, "file.purge", id, None, Some("deleted forever")).await?;
		}
		for id in asked_folders.iter().filter(|id| folder_set.contains(*id)) {
			self.audit(actor, "folder.purge", id, None, Some("deleted forever, with everything in it")).await?;
		}
		let summary = format!("files:{n_files},folders:{n_folders},sharesRevoked:{revoked}");
		self.audit(actor, if trash { "trash.empty" } else { "files.purge" }, &summary, None, None).await?;

		// 5. Storage now (what fails stays queued for housekeeping).
		let drained = self.drain_deletes().await?;
		Ok(Response::from_json(&serde_json::json!({
			"files": n_files, "folders": n_folders, "sharesRevoked": revoked,
			"objectsDeleted": drained.done, "deletesPending": drained.pending,
		}))?)
	}

	/// Everything in this member's database that is sealed to the files STORE
	/// key, one kind at a time, paged by SQLite rowid — the input of a store
	/// rotation (docs/FAMILY.md › Removing a member, docs/SECURITY-REVIEW.md
	/// › O5). `GET files/sealed?kind=<kind>&after=<rowid>&limit=<n>`.
	///
	/// | kind | rows | sealed values |
	/// |---|---|---|
	/// | `version` | file_versions | content key, type |
	/// | `file` | files | name |
	/// | `folder` | file_folders | name |
	/// | `music` | music_meta | tag blob |
	/// | `video` | video_meta | the video sidecar, and its poster when there is one (39p) |
	/// | `position` | watch_positions | where a member left off in a video (39o) |
	/// | `share` | shares | the owner's copy of the name |
	/// | `secrets` | files_secrets | fingerprint + index keys |
	/// | `hash` | file_versions | the uploader's signed content hash (29d) |
	/// | `intake` | files | an evidence file's signed intake record (29g) |
	/// | `custody` | custody | each custody link's sealed reason (29g) |
	/// | `collection` | files | an accepted inbox item's collection record (37c) |
	/// | `reject` | inbox_items | a rejected item's sealed reason (37c) |
	/// | `inboxkey` | area_inbox_keys | a member's own inbox keys' private halves (38a) |
	/// | `requestlabel` | upload_requests | an upload link's label (38b) |
	///
	/// Before commit 24 the rotation walk could reach only each file's LIVING
	/// version (via `files/keys`) and file names — so a departed member's old
	/// key still opened every older version, every folder name, the music
	/// tags and the secrets. A rotation that misses rows is not a rotation.
	pub(crate) async fn sealed_page(&self, req: Request) -> Result<Response> {
		let url = req.url()?;
		let q = urlquery(url.query().unwrap_or(""));
		let after = q.get("after").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
		let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(500).clamp(1, 1000);
		let Some(kind) = q.get("kind").map(String::as_str) else { return json_error(400, "kind required") };
		let sql = match kind {
			"version" => "SELECT rowid AS row, file_id AS a, CAST(version AS TEXT) AS b, content_key AS v1, type_sealed AS v2 FROM file_versions WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"file" => "SELECT rowid AS row, id AS a, NULL AS b, name_sealed AS v1, NULL AS v2 FROM files WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"folder" => "SELECT rowid AS row, id AS a, NULL AS b, name_sealed AS v1, NULL AS v2 FROM file_folders WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"music" => "SELECT rowid AS row, file_id AS a, CAST(version AS TEXT) AS b, blob_sealed AS v1, NULL AS v2 FROM music_meta WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"video" => "SELECT rowid AS row, file_id AS a, CAST(version AS TEXT) AS b, meta_sealed AS v1, poster_sealed AS v2 FROM video_meta WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"position" => "SELECT rowid AS row, file_id AS a, member AS b, position_sealed AS v1, NULL AS v2 FROM watch_positions WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"share" => "SELECT rowid AS row, id AS a, NULL AS b, name_sealed AS v1, NULL AS v2 FROM shares WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"secrets" => "SELECT rowid AS row, NULL AS a, NULL AS b, v AS v1, NULL AS v2 FROM files_secrets WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			// (Its own kind, not a third value of `version`: most versions
			// carry no hash, and a walk's items stay one or two values.)
			"hash" => "SELECT rowid AS row, file_id AS a, CAST(version AS TEXT) AS b, hash_sealed AS v1, NULL AS v2 FROM file_versions WHERE rowid > ?1 AND hash_sealed IS NOT NULL ORDER BY rowid LIMIT ?2",
			"intake" => "SELECT rowid AS row, id AS a, NULL AS b, intake_sealed AS v1, NULL AS v2 FROM files WHERE rowid > ?1 AND intake_sealed IS NOT NULL ORDER BY rowid LIMIT ?2",
			"custody" => "SELECT rowid AS row, file_id AS a, CAST(seq AS TEXT) AS b, reason_sealed AS v1, NULL AS v2 FROM custody WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"collection" => "SELECT rowid AS row, id AS a, NULL AS b, collection_sealed AS v1, NULL AS v2 FROM files WHERE rowid > ?1 AND collection_sealed IS NOT NULL ORDER BY rowid LIMIT ?2",
			"reject" => "SELECT rowid AS row, id AS a, NULL AS b, reject_reason AS v1, NULL AS v2 FROM inbox_items WHERE rowid > ?1 AND reject_reason IS NOT NULL ORDER BY rowid LIMIT ?2",
			"inboxkey" => "SELECT rowid AS row, key_id AS a, NULL AS b, private_sealed AS v1, NULL AS v2 FROM area_inbox_keys WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"requestlabel" => "SELECT rowid AS row, id AS a, NULL AS b, label_sealed AS v1, NULL AS v2 FROM upload_requests WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			_ => return json_error(400, "kind: version | file | folder | music | video | position | share | secrets | hash | intake | custody | collection | reject | inboxkey | requestlabel"),
		};
		// `&file=<id>` narrows `version` to one file's versions (commit 29e:
		// marking a sample re-seals each of ITS versions' types — a walk of
		// the whole store would be the wrong tool).
		let rows: Vec<SealedRow> = match (kind, q.get("file")) {
			("version", Some(file)) => self
				.sql
				.exec("SELECT rowid AS row, file_id AS a, CAST(version AS TEXT) AS b, content_key AS v1, type_sealed AS v2 FROM file_versions WHERE rowid > ?1 AND file_id = ?3 ORDER BY rowid LIMIT ?2", Some(vec![after.into(), limit.into(), file.clone().into()]))?
				.to_array()?,
			_ => self.sql.exec(sql, Some(vec![after.into(), limit.into()]))?.to_array()?,
		};
		let next = (rows.len() as i64 == limit).then(|| rows.last().map(|r| r.row)).flatten();
		Ok(Response::from_json(&serde_json::json!({
			"kind": kind,
			"items": rows.into_iter().map(|r| serde_json::json!({ "row": r.row, "a": r.a, "b": r.b, "v1": r.v1, "v2": r.v2 })).collect::<Vec<_>>(),
			"next": next,
		}))?)
	}

	/// Store the results of a rotation walk: `PUT files/reseal { items: [{
	/// kind, row, v1, v2? }] }` — each row's sealed value(s), re-sealed by
	/// the CLIENT to the new store key (the server never sees a key; it
	/// checks that every value is sealed text and writes it to exactly the
	/// row named). Idempotent: the client re-seals only what still opens
	/// under the OLD key, so running the walk twice does no harm.
	///
	/// (Clean break, docs/DECISIONS.md › D13: the old `{ keys: { fileId:
	/// { ck, name, type } } }` form re-wrapped living versions only, and is
	/// refused.)
	pub(crate) async fn files_reseal(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if body.get("keys").is_some() {
			return json_error(400, "the current-version-only reseal form is gone (commit 24): send { items: [{ kind, row, v1, v2? }] } from a files/sealed walk");
		}
		let Some(items) = body.get("items").and_then(|k| k.as_array()) else { return json_error(400, "items required") };
		if items.len() > 1000 {
			return json_error(400, "at most 1000 items per call");
		}
		// Validate everything first: a batch is applied whole or not at all.
		let mut plan: Vec<(&'static str, i64, String, Option<String>)> = Vec::with_capacity(items.len());
		for it in items {
			let kind = it.get("kind").and_then(|v| v.as_str()).unwrap_or_default();
			let Some(row) = it.get("row").and_then(|v| v.as_i64()) else { return json_error(400, "each item needs its row") };
			let Some(v1) = it.get("v1").and_then(|v| v.as_str()).map(str::to_string) else { return json_error(400, "each item needs v1") };
			let v2 = it.get("v2").and_then(|v| v.as_str()).map(str::to_string);
			if !gorani_formats::placed::is_placed_text(&v1) || v2.as_ref().is_some_and(|t| !gorani_formats::placed::is_placed_text(t)) {
				return json_error(400, "reseal values must be placed sealed text (GV04)");
			}
			let sql: &'static str = match kind {
				"version" => "UPDATE file_versions SET content_key = ?1, type_sealed = COALESCE(?2, type_sealed) WHERE rowid = ?3",
				"file" => "UPDATE files SET name_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"folder" => "UPDATE file_folders SET name_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"music" => "UPDATE music_meta SET blob_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				// (A poster is resealed only where there is one: a reseal never adds a value.)
				"video" => "UPDATE video_meta SET meta_sealed = ?1, poster_sealed = CASE WHEN poster_sealed IS NULL THEN NULL ELSE COALESCE(?2, poster_sealed) END WHERE rowid = ?3",
				"position" => "UPDATE watch_positions SET position_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"share" => "UPDATE shares SET name_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"secrets" => "UPDATE files_secrets SET v = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				// (Only a row that HAS a hash: a reseal never adds a claim.)
				"hash" => "UPDATE file_versions SET hash_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL AND hash_sealed IS NOT NULL",
				"intake" => "UPDATE files SET intake_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL AND intake_sealed IS NOT NULL",
				"custody" => "UPDATE custody SET reason_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"collection" => "UPDATE files SET collection_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL AND collection_sealed IS NOT NULL",
				"reject" => "UPDATE inbox_items SET reject_reason = ?1 WHERE rowid = ?3 AND ?2 IS NULL AND reject_reason IS NOT NULL",
				"inboxkey" => "UPDATE area_inbox_keys SET private_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"requestlabel" => "UPDATE upload_requests SET label_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				_ => return json_error(400, "kind: version | file | folder | music | video | position | share | secrets | hash | intake | custody | collection | reject | inboxkey | requestlabel"),
			};
			plan.push((sql, row, v1, v2));
		}
		let mut updated = 0usize;
		for (sql, row, v1, v2) in plan {
			self.sql.exec(sql, Some(vec![v1.into(), bind(v2), row.into()]))?;
			updated += 1;
		}
		self.audit(actor, "files.reseal", &format!("{updated} sealed values"), None, None).await?;
		Ok(Response::from_json(&serde_json::json!({ "updated": updated }))?)
	}

	// ── small helpers ───────────────────────────────────────────────────

	/// No vault (or a paused one), no uploads: the member's own keys are what
	/// makes content sealed, so the store refuses writes that would land in
	/// the clear (docs/VAULT.md › Pause sealing). Returns the refusal message
	/// (a 400, an expectation) or None when the write may proceed.
	pub(crate) async fn vault_gate(&self) -> Result<Option<String>> {
		Ok(match self.vault_settings().await? {
			None => Some("the vault is not set up".into()),
			Some(s) if s.get("enabled").and_then(|e| e.as_bool()) == Some(true) => None,
			Some(_) => Some("the vault is paused".into()),
		})
	}

	async fn file_row(&self, id: &str) -> Result<Response> {
		match self.file_sql_row(id).await? {
			Some(f) => Ok(Response::from_json(&serde_json::json!({
				"id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size,
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at, "owner": f.owner, "sample": f.sample != 0,
			}))?),
			None => json_error(404, "no such file"),
		}
	}

	async fn file_sql_row(&self, id: &str) -> Result<Option<FileSqlRow>> {
		let rows: Vec<FileSqlRow> = self
			.sql
			.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at, owner, sample FROM files WHERE id = ?1", Some(vec![id.into()]))?
			.to_array()?;
		Ok(rows.into_iter().next())
	}
}

#[derive(serde::Deserialize)]
struct SealedRow {
	row: i64,
	a: Option<String>,
	b: Option<String>,
	v1: Option<String>,
	v2: Option<String>,
}
#[derive(serde::Deserialize)]
struct CurrentVersion {
	version: i64,
}
/// The link policy (D11, docs/DECISIONS.md › Sharing; commit 30). Partners
/// sign in — a guest account, a case grant — and a link is the exception,
/// for working areas only (a case has no link route at all: routes.rs ›
/// case_need). A link must:
///
/// - **carry a password.** The server never sees it (the recipient's page
///   stretches it with Argon2id and mixes it into the link's key,
///   share-crypto.ts); what the server CAN require is the KDF record that
///   says one exists, with parameters inside the bounds the recipient's
///   page enforces (kdf-bounds.ts, O8) — a link nobody could open is
///   refused here, not discovered by the partner;
/// - **expire within 7 days** (with five minutes for clock skew; a date
///   already past is harmless — that link opens for nobody);
/// - **allow 1–100 downloads.**
///
/// What it cannot enforce: a client that declares a KDF and then mixes in
/// an empty password. The honest client cannot (share-dialog.ts refuses
/// one shorter than 8 characters); a dishonest one holds the plaintext
/// anyway — the policy binds the tool, not the person.
pub(crate) fn share_policy_refusal(kdf: Option<&serde_json::Value>, expires_at: &str, downloads: i64, now_ms: f64) -> Option<String> {
	const WEEK_MS: f64 = 7.0 * 86_400_000.0;
	const SKEW_MS: f64 = 5.0 * 60_000.0;
	let Some(k) = kdf.filter(|k| k.is_object()) else {
		return Some("a link needs a password (D11): send its Argon2id parameters (kdf) — a partner who needs more gets a guest account and the case".into());
	};
	let within = |f: &str, lo: i64, hi: i64| k.get(f).and_then(|v| v.as_i64()).is_some_and(|v| (lo..=hi).contains(&v));
	// The bounds of kdf-bounds.ts › ARGON2_BOUNDS and SALT_BOUNDS.
	let salt = k.get("salt").and_then(|s| s.as_str()).and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()).map(|b| b.len());
	if !within("m", 19 * 1024, 256 * 1024) || !within("t", 2, 10) || !within("p", 1, 8) || !salt.is_some_and(|n| (16..=64).contains(&n)) {
		return Some("the link's password parameters are outside what a recipient's page accepts (Argon2id m 19–256 MiB, t 2–10, p 1–8, a 16–64-byte salt)".into());
	}
	let well_formed = expires_at.len() >= 20 && expires_at.ends_with('Z') && expires_at.as_bytes().get(10) == Some(&b'T');
	let Some(expires) = crate::audit::epoch_seconds(expires_at).filter(|_| well_formed).map(|s| s * 1000.0) else {
		return Some("expiresAt must be an RFC 3339 UTC time (YYYY-MM-DDThh:mm:ssZ)".into());
	};
	if expires > now_ms + WEEK_MS + SKEW_MS {
		return Some("a link expires within 7 days (D11) — for longer, grant the partner a guest account".into());
	}
	if !(1..=100).contains(&downloads) {
		return Some("downloadsLeft is 1–100".into());
	}
	None
}

#[cfg(test)]
mod share_policy_tests {
	use super::share_policy_refusal;

	const NOW: f64 = 1_791_996_658_000.0; // 2026-10-14T16:50:58Z

	fn kdf() -> serde_json::Value {
		serde_json::json!({ "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "m": 65536, "t": 3, "p": 4 })
	}

	#[test]
	fn a_compliant_link_passes() {
		assert_eq!(share_policy_refusal(Some(&kdf()), "2026-10-21T16:50:58Z", 5, NOW), None, "exactly a week");
		assert_eq!(share_policy_refusal(Some(&kdf()), "2026-10-13T00:00:00.000Z", 1, NOW), None, "already past: harmless");
	}

	#[test]
	fn each_rule_refuses_by_name() {
		let why = |k: Option<&serde_json::Value>, at: &str, n: i64| share_policy_refusal(k, at, n, NOW).unwrap_or_default();
		assert!(why(None, "2026-10-15T00:00:00Z", 5).contains("needs a password"));
		assert!(why(Some(&serde_json::json!({ "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "m": 1024, "t": 3, "p": 4 })), "2026-10-15T00:00:00Z", 5).contains("outside"), "below OWASP's memory floor");
		assert!(why(Some(&serde_json::json!({ "salt": "AAAA", "m": 65536, "t": 3, "p": 4 })), "2026-10-15T00:00:00Z", 5).contains("outside"), "a 3-byte salt");
		assert!(why(Some(&kdf()), "2026-10-21T17:00:00Z", 5).contains("within 7 days"), "a week and ten minutes");
		assert!(why(Some(&kdf()), "next tuesday", 5).contains("RFC 3339"));
		assert!(why(Some(&kdf()), "2026-10-15T00:00:00+02:00", 5).contains("RFC 3339"), "UTC only");
		assert!(why(Some(&kdf()), "2026-10-15T00:00:00Z", 0).contains("1–100"));
		assert!(why(Some(&kdf()), "2026-10-15T00:00:00Z", 101).contains("1–100"));
	}
}

#[derive(serde::Deserialize)]
pub(crate) struct TotalCount {
	pub(crate) n: i64,
}
#[derive(serde::Deserialize)]
struct JournalRow {
	seq: i64,
	kind: String,
	data: String,
	at: String,
}
#[derive(serde::Deserialize)]
struct DuplicateRow {
	id: String,
	size: i64,
	tag: String,
	folder_id: Option<String>,
	name_sealed: String,
	updated_at: String,
}
#[derive(serde::Deserialize)]
struct MatchRow {
	id: String,
	tag: Option<String>,
	folder_id: Option<String>,
	name_sealed: String,
	owner: Option<String>,
	contributors: Option<String>,
}
#[derive(serde::Deserialize)]
struct ObjectRow {
	version: i64,
	content_key: String,
	vault_key_id: Option<String>,
	object_key: String,
	chunk_size: Option<i64>,
	size: i64,
	hash_sealed: Option<String>,
}
#[derive(serde::Deserialize)]
struct ExistsRow {
	// Read for its existence only: a row came back, or none did.
	#[allow(dead_code)]
	one: i64,
}
#[derive(serde::Deserialize)]
struct UploadRow {
	object_key: String,
	file_id: Option<String>,
	s3_upload_id: String,
}
#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}
#[derive(serde::Deserialize)]
struct ReadRow {
	actor: String,
	file_id: String,
	version: i64,
	client: String,
	first_at: String,
	last_at: String,
	requests: i64,
}

#[derive(serde::Deserialize)]
struct ShareLive {
	object_key: String,
	ready: i64,
	revoked_at: Option<String>,
	expired: i64,
}

/// A share token as stored: SHA-256, base64url. (The token itself is a
/// 256-bit random secret, so a plain hash — not a slow KDF — is the right
/// tool: there is nothing to brute-force.)
/// Equal bytes, compared in time that does not depend on where they differ.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn token_hash(token: &str) -> String {
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(gorani_formats::unlock::sha256(&[token.as_bytes()]))
}

#[derive(serde::Deserialize)]
struct ShareObjRow {
	object_key: String,
}
#[derive(serde::Deserialize)]
struct ShareRow {
	object_key: String,
	s3_upload_id: Option<String>,
}
#[derive(Clone, serde::Deserialize)]
struct ShareListRow {
	id: String,
	file_id: Option<String>,
	name_sealed: String,
	expires_at: String,
	downloads_left: i64,
	created_at: String,
	revoked_at: Option<String>,
	ready: i64,
	size: Option<i64>,
	drm: i64,
}
#[derive(Clone, serde::Deserialize)]
struct ShareRow2 {
	meta_sealed: String,
	kdf: Option<String>,
	expires_at: String,
	downloads_left: i64,
	ready: i64,
	revoked_at: Option<String>,
	expired: i64,
	drm: i64,
	claim_hash: Option<String>,
}

pub(crate) fn json_error_raw(status: u16, message: &str) -> Response {
	Response::from_json(&serde_json::json!({ "error": message })).unwrap().with_status(status)
}
#[derive(serde::Deserialize)]
struct TrashedWithRow {
	id: String,
	trashed_with: Option<String>,
}

/// How many ids one Delete forever names at most (a folder counts once,
/// whatever it holds), and how many go into one `IN (…)` — the DO's SQL
/// takes at most 100 bound parameters a statement.
const PURGE_ASK_CAP: usize = 1000;
const PURGE_CHUNK: usize = 50;

/// `id IN (?, ?, …)` — placeholders plus the bound values, for the handful of
/// dynamic-list queries (trash restore, Delete forever — in chunks).
pub(crate) fn in_clause(ids: &[String]) -> (String, Vec<worker::SqlStorageValue>) {
	let qs = (0..ids.len()).map(|i| format!("?{}", i + 1)).collect::<Vec<_>>().join(",");
	let params = ids.iter().map(|s| worker::SqlStorageValue::String(s.clone())).collect();
	(qs, params)
}
/// A tiny query-string reader for the few DO routes that take one (the
/// Worker forwards the caller's query verbatim; `worker::Url` is the `url`
/// crate's, so pairs come from `query()`).
pub(crate) fn urlquery(qs: &str) -> std::collections::BTreeMap<String, String> {
	qs.split('&')
		.filter_map(|pair| {
			let (k, v) = pair.split_once('=')?;
			Some((k.to_string(), v.to_string()))
		})
		.collect()
}
