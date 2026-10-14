// Copyright 2026- Seongwoo Hong. All rights reserved.
// The files store's shape follows Mailflare's files DO (Apache 2.0, ©
// Cloudflare, Inc.); see NOTICE.

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
}

impl GoraniMemberDO {
	// ── Files: create (one-request upload) and versions ─────────────────

	/// Record a whole-file upload the Worker already put in S3. The CLIENT
	/// chose the file id (commit 25: it seals the name and the content key
	/// into places that name the file, so the id must exist before the
	/// sealing does); the Worker checked its shape and built the object key;
	/// the DO owns the rows — and refuses an id already taken (409).
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
		let Some(file_id) = get("id") else { return json_error(400, "the file id is chosen by the client (file_id)") };
		let taken: Option<ExistsRow> = self.sql.exec("SELECT 1 AS one FROM files WHERE id = ?1", Some(vec![file_id.clone().into()]))?.to_array::<ExistsRow>().ok().and_then(|mut r| r.pop());
		if taken.is_some() {
			return json_error(409, "a file with this id exists — choose a fresh id (a new version goes to files/<id>/versions)");
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
		self.sql
			.exec(
				"INSERT INTO files (id, folder_id, name_sealed, size, version, created_at, updated_at, owner) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?6)",
				Some(vec![file_id.clone().into(), bind(get("folderId")), name.clone().into(), size.into(), version.into(), bind(get("owner"))]),
			)
			.map_err(|e| worker::Error::RustError(format!("file insert: {e}")))?;
		self.contributor_add(&file_id, actor).await?;
		self.sql
			.exec(
				"INSERT INTO file_versions (file_id, version, content_key, vault_key_id, object_key, type_sealed, size, chunk_size, tag, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
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
				]),
			)
			.map_err(|e| worker::Error::RustError(format!("version insert: {e}")))?;
		if let Err(resp) = self.music_meta_put(&file_id, version, get("mmeta")).await {
			return Ok(resp);
		}
		self.audit(actor, "file.upload", &file_id, None, None).await?;
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
		self.sql
			.exec(
				"INSERT INTO file_versions (file_id, version, content_key, vault_key_id, object_key, type_sealed, size, chunk_size, tag, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
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
			let rows = self.sql.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at, owner FROM files WHERE deleted_at IS NULL ORDER BY created_at, id LIMIT ?1 OFFSET ?2", Some(vec![limit.into(), offset.into()]))?.to_array()?;
			let total = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL", None)?.one::<TotalCount>()?;
			(rows, total)
		} else {
			let parent = if folder == "root" { None } else { Some(folder.clone()) };
			let rows = self
				.sql
				.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at, owner FROM files WHERE deleted_at IS NULL AND folder_id IS ?1 ORDER BY created_at, id LIMIT ?2 OFFSET ?3", Some(vec![bind(parent.clone()), limit.into(), offset.into()]))?
				.to_array()?;
			let total = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL AND folder_id IS ?1", Some(vec![bind(parent)]))?.one::<TotalCount>()?;
			(rows, total)
		};
		let folders: Vec<FolderSqlRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE deleted_at IS NULL ORDER BY name_sealed, id", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"total": total.n,
			"files": rows.into_iter().map(|f| serde_json::json!({
				"id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size,
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at, "owner": f.owner,
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
					"SELECT v.version, v.content_key, v.vault_key_id, v.object_key, v.type_sealed, v.size, v.chunk_size FROM file_versions v JOIN files f ON f.id = v.file_id AND f.version = v.version WHERE v.file_id = ?1",
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
					"version": row.version, "createdAt": row.created_at, "updatedAt": row.updated_at,
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
	/// exact size with its fingerprint tag (opaque; the browser compares
	/// tags, the server learns only which files are the same size).
	pub(crate) async fn files_match(&self, req: Request) -> Result<Response> {
		let url = req.url()?;
		let Some(size) = urlquery(url.query().unwrap_or("")).get("size").and_then(|v| v.parse::<i64>().ok()) else { return json_error(400, "size required") };
		let rows: Vec<MatchRow> = self
			.sql
			.exec(
				"SELECT f.id, v.tag, f.owner AS owner, (SELECT group_concat(member, ',') FROM file_contributors c WHERE c.file_id = f.id) AS contributors FROM files f JOIN file_versions v ON v.file_id = f.id AND v.version = f.version WHERE f.size = ?1 AND f.deleted_at IS NULL",
				Some(vec![size.into()]),
			)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "files": rows.into_iter().map(|r| serde_json::json!({ "id": r.id, "tag": r.tag, "owner": r.owner, "contributors": r.contributors })).collect::<Vec<_>>() }))?)
	}

	/// The `files-object/:id` route: the object's location + wrapped key, for
	/// the Worker to stream from S3. Metadata only — no name, no key material
	/// beyond the wrapped one the client will open.
	/// The object of a version, for the Worker's download route — and the
	/// read audit (O14): every download passes here BEFORE the edge cache, so
	/// a read served from cache is still a read on record. One merged row per
	/// reader × version × client × 5 minutes (a seek is many requests).
	pub(crate) async fn file_object_route(&self, file_id: &str, version: Option<i64>, reader: &str, client: Option<&str>) -> Result<Response> {
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
					"chunk": o.chunk_size, "size": o.size, "version": o.version,
				}))?)
			}
			Some(o) => Ok(Response::from_json(&serde_json::json!({
				"objectKey": o.object_key, "ck": o.content_key, "vaultKeyId": o.vault_key_id,
				"chunk": o.chunk_size, "size": o.size, "version": o.version,
			}))?),
			None => json_error(404, "no such file"),
		}
	}

	/// The read log (`GET …/reads[?file=]`): who read which version, from
	/// what kind of client, when — newest first. Structure only, like the
	/// rest of this DO; readable to the member and their parents.
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
				.exec("SELECT version, content_key, vault_key_id, object_key, chunk_size, size FROM file_versions WHERE file_id = ?1 AND version = ?2", Some(vec![file_id.into(), v.into()]))?
				.to_array::<ObjectRow>()
				.ok()
				.and_then(|mut r| r.pop()),
			None => self
				.sql
				.exec(
					"SELECT v.version, v.content_key, v.vault_key_id, v.object_key, v.chunk_size, v.size FROM file_versions v JOIN files f ON f.id = v.file_id AND f.version = v.version WHERE f.id = ?1",
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
	pub(crate) async fn file_trash(&self, actor: &str, id: &str) -> Result<Response> {
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
				return json_error(400, "parent folder does not exist");
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
				return json_error(400, "parent folder does not exist");
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
		let n = self
			.sql
			.exec(
				"WITH RECURSIVE d(id) AS (SELECT id FROM file_folders WHERE id = ?1 AND deleted_at IS NULL UNION ALL SELECT f.id FROM file_folders f JOIN d ON f.parent_id = d.id) UPDATE file_folders SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), trashed_with = ?1 WHERE id IN (SELECT id FROM d)",
				Some(vec![id.into()]),
			)?
			.rows_written();
		if n == 0 {
			return json_error(404, "no such folder");
		}
		let files = self
			.sql
			.exec(
				"WITH RECURSIVE d(id) AS (SELECT id FROM file_folders WHERE id = ?1 UNION ALL SELECT f.id FROM file_folders f JOIN d ON f.parent_id = d.id) UPDATE files SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), trashed_with = ?1 WHERE folder_id IN (SELECT id FROM d) AND deleted_at IS NULL",
				Some(vec![id.into()]),
			)?
			.rows_written();
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
		let Some(s3_upload_id) = get("s3UploadId") else { return json_error(400, "s3UploadId required") };
		let downloads_left = body.get("downloadsLeft").and_then(|v| v.as_i64()).unwrap_or(9999);
		self.sql
			.exec(
				"INSERT INTO shares (id, file_id, version, name_sealed, object_key, meta_sealed, kdf, expires_at, downloads_left, created_at, s3_upload_id, ready, size) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?10, 0, ?11)",
				Some(vec![
					id.clone().into(),
					bind(get("fileId")),
					body.get("version").and_then(|v| v.as_i64()).unwrap_or(1).into(),
					name.into(),
					format!("shares/{id}").into(),
					meta.into(),
					bind(body.get("kdf").map(|k| k.to_string())),
					expires_at.into(),
					downloads_left.into(),
					s3_upload_id.into(),
					body.get("size").and_then(|v| v.as_i64()).into(),
				]),
			)
			.map_err(|e| worker::Error::RustError(format!("share insert: {e}")))?;
		self.audit(actor, "share.create", &id, None, None).await?;
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
			.exec("SELECT id, file_id, name_sealed, expires_at, downloads_left, created_at, revoked_at, ready, size FROM shares ORDER BY created_at DESC", None)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::Value::Array(
			rows.into_iter()
				.map(|r| {
					serde_json::json!({
						"id": r.id, "fileId": r.file_id, "name": r.name_sealed,
						"expiresAt": r.expires_at, "downloadsLeft": r.downloads_left,
						"createdAt": r.created_at, "revoked": r.revoked_at.is_some(),
						"ready": r.ready != 0, "size": r.size,
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
			.exec("SELECT meta_sealed, kdf, expires_at, downloads_left, ready, revoked_at, expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now') AS expired FROM shares WHERE id = ?1", Some(vec![id.into()]))
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
	pub(crate) async fn share_claim(&self, id: &str) -> Result<Response> {
		match self.share_public_check(id).await {
			Ok(r) => {
				let left = r.downloads_left - 1;
				self.sql.exec("UPDATE shares SET downloads_left = ?1 WHERE id = ?2", Some(vec![left.into(), id.into()]))?;
				let mut raw = [0u8; 32];
				OsRng.fill_bytes(&mut raw);
				let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
				self.sql.exec(
					"INSERT INTO share_tokens (hash, share_id, expires_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now','+1 hour'))",
					Some(vec![token_hash(&token).into(), id.into()]),
				)?;
				// The owner's audit records each download of their link (O14).
				self.audit("share-link", "share.claim", id, None, Some(&format!("downloadsLeft:{left}"))).await?;
				Ok(Response::from_json(&serde_json::json!({ "downloadsLeft": left, "token": token, "tokenExpiresIn": 3600 }))?)
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
			.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at FROM files WHERE deleted_at IS NOT NULL ORDER BY updated_at DESC", None)?
			.to_array()?;
		let folders: Vec<FolderSqlRow> = self
			.sql
			.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE deleted_at IS NOT NULL ORDER BY updated_at DESC", None)?
			.to_array()?;
		let trashed_with: Vec<TrashedWithRow> = self.sql.exec("SELECT id, trashed_with FROM files WHERE deleted_at IS NOT NULL AND trashed_with IS NOT NULL", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"files": files.into_iter().map(|f| serde_json::json!({
				"id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size,
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at,
			})).collect::<Vec<_>>(),
			"folders": folders.into_iter().map(|f| serde_json::json!({
				"id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at,
			})).collect::<Vec<_>>(),
			"trashedWith": trashed_with.into_iter().map(|t| serde_json::json!({ "id": t.id, "with": t.trashed_with })).collect::<Vec<_>>(),
		}))?)
	}

	/// Restore files and folders from the Trash. A folder whose parent is
	/// still in the Trash comes back at the top level; a file whose folder is
	/// still there likewise (the tree must never dangle).
	pub(crate) async fn trash_restore(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let files: Vec<String> = body.get("files").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
		let folders: Vec<String> = body.get("folders").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
		// Count first, then update: rows_written includes the change-feed
		// trigger's writes (journal + counter), so it cannot be the report.
		let mut n_files = 0;
		let mut n_folders = 0;
		if !folders.is_empty() {
			let (qs, params) = in_clause(&folders);
			n_folders = self.sql.exec(&format!("SELECT COUNT(*) AS n FROM file_folders WHERE deleted_at IS NOT NULL AND id IN ({qs})"), Some(params.clone()))?.one::<TotalCount>()?.n;
			self.sql
				.exec(
					&format!("UPDATE file_folders SET deleted_at = NULL, trashed_with = NULL, parent_id = CASE WHEN EXISTS (SELECT 1 FROM file_folders p WHERE p.id = file_folders.parent_id AND p.deleted_at IS NOT NULL) THEN NULL ELSE parent_id END WHERE id IN ({qs})"),
					Some(params),
				)?;
		}
		if !files.is_empty() {
			let (qs, params) = in_clause(&files);
			n_files = self.sql.exec(&format!("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NOT NULL AND id IN ({qs})"), Some(params.clone()))?.one::<TotalCount>()?.n;
			self.sql
				.exec(
					&format!("UPDATE files SET deleted_at = NULL, trashed_with = NULL, folder_id = CASE WHEN EXISTS (SELECT 1 FROM file_folders f2 WHERE f2.id = files.folder_id AND f2.deleted_at IS NOT NULL) THEN NULL ELSE folder_id END WHERE id IN ({qs})"),
					Some(params),
				)?;
		}
		if n_files + n_folders > 0 {
			self.audit(actor, "files.restore", &format!("files:{n_files},folders:{n_folders}"), None, None).await?;
		}
		Ok(Response::from_json(&serde_json::json!({ "files": n_files, "folders": n_folders }))?)
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
	/// | `share` | shares | the owner's copy of the name |
	/// | `secrets` | files_secrets | fingerprint + index keys |
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
			"share" => "SELECT rowid AS row, id AS a, NULL AS b, name_sealed AS v1, NULL AS v2 FROM shares WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			"secrets" => "SELECT rowid AS row, NULL AS a, NULL AS b, v AS v1, NULL AS v2 FROM files_secrets WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
			_ => return json_error(400, "kind: version | file | folder | music | share | secrets"),
		};
		let rows: Vec<SealedRow> = self.sql.exec(sql, Some(vec![after.into(), limit.into()]))?.to_array()?;
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
				"share" => "UPDATE shares SET name_sealed = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				"secrets" => "UPDATE files_secrets SET v = ?1 WHERE rowid = ?3 AND ?2 IS NULL",
				_ => return json_error(400, "kind: version | file | folder | music | share | secrets"),
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
	async fn vault_gate(&self) -> Result<Option<String>> {
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
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at, "owner": f.owner,
			}))?),
			None => json_error(404, "no such file"),
		}
	}

	async fn file_sql_row(&self, id: &str) -> Result<Option<FileSqlRow>> {
		let rows: Vec<FileSqlRow> = self
			.sql
			.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at FROM files WHERE id = ?1", Some(vec![id.into()]))?
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
#[derive(serde::Deserialize)]
struct TotalCount {
	n: i64,
}
#[derive(serde::Deserialize)]
struct JournalRow {
	seq: i64,
	kind: String,
	data: String,
	at: String,
}
#[derive(serde::Deserialize)]
struct MatchRow {
	id: String,
	tag: Option<String>,
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
fn token_hash(token: &str) -> String {
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
}

fn json_error_raw(status: u16, message: &str) -> Response {
	Response::from_json(&serde_json::json!({ "error": message })).unwrap().with_status(status)
}
#[derive(serde::Deserialize)]
struct TrashedWithRow {
	id: String,
	trashed_with: Option<String>,
}

/// `id IN (?, ?, …)` — placeholders plus the bound values, for the handful of
/// dynamic-list queries (trash restore).
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
