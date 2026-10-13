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
//! | Worker routes | multipart parsing, sealed-shape checks (bytes must start `GV02`, names must be sealed text), S3 put/multipart, streaming reads |
//! | This DO | rows: files, folders, versions, the change feed, secrets, upload bookkeeping |
//!
//! The DO never sees a plaintext name or an unsealed byte: every text column
//! it accepts is checked with `is_sealed_text` before insert. Object keys are
//! opaque ids (`files/<member>/<file>/<v-uuid>`), never file names.

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use worker::{Request, Response, Result};

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

/// A file row as lists return it (no keys — keys come in batches, docs/APPS.md).
#[derive(serde::Serialize)]
struct FileListRow {
	id: String,
	folder: Option<String>,
	name: String,
	size: i64,
	version: i64,
	created_at: String,
	updated_at: String,
}

#[derive(serde::Serialize)]
struct FolderListRow {
	id: String,
	parent: Option<String>,
	name: String,
	created_at: String,
	updated_at: String,
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
	file_id: String,
	version: i64,
	content_key: String,
	vault_key_id: Option<String>,
	object_key: String,
	type_sealed: Option<String>,
	size: i64,
	chunk_size: Option<i64>,
	tag: Option<String>,
}

impl GoraniMemberDO {
	// ── Files: create (one-request upload) and versions ─────────────────

	/// Record a whole-file upload the Worker already put in S3. The Worker
	/// generated the file id, version id and object key; the DO owns the rows.
	pub(crate) async fn file_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		if let Some(msg) = self.vault_gate().await? {
			return json_error(400, &msg);
		}
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let name = get("name").ok_or_else(|| worker::Error::RustError("missing name".into()))?;
		let r#type = get("type");
		if !gorani_formats::formats::is_sealed_text(&name) || r#type.as_ref().is_some_and(|t| !gorani_formats::formats::is_sealed_text(t)) {
			return json_error(400, "names and types must be sealed text");
		}
		if body.get("bytesSealed").and_then(|v| v.as_bool()) != Some(true) {
			return json_error(400, "the Worker confirms sealed bytes before calling the store");
		}
		let file_id = get("id").unwrap_or_else(uuid);
		let version = 1i64;
		let object_key = get("objectKey").ok_or_else(|| worker::Error::RustError("missing objectKey".into()))?;
		let content_key = get("ck").ok_or_else(|| worker::Error::RustError("missing content key".into()))?;
		// The content key must arrive already sealed to the store key — a raw
		// key would let the server (or a leaked row) open the content.
		if !gorani_formats::formats::is_sealed_text(&content_key) {
			return json_error(400, "the content key must arrive sealed to the store key");
		}
		let size = body.get("size").and_then(|v| v.as_i64()).ok_or_else(|| worker::Error::RustError("missing size".into()))?;
		self.sql
			.exec(
				"INSERT INTO files (id, folder_id, name_sealed, size, version, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![file_id.clone().into(), bind(get("folderId")), name.clone().into(), size.into(), version.into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("file insert: {e}")))?;
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
			if !gorani_formats::formats::is_sealed_text(n) {
				return json_error(400, "names must be sealed text");
			}
		}
		let current: Option<i64> = self.sql.exec("SELECT version FROM files WHERE id = ?1", Some(vec![file_id.clone().into()]))?.to_array::<CurrentVersion>().ok().and_then(|mut r| r.pop()).map(|r| r.version);
		let Some(current) = current else { return json_error(404, "no such file") };
		let base = body.get("baseVersion").and_then(|v| v.as_i64()).unwrap_or(current);
		if base != current {
			return Ok(Response::from_json(&serde_json::json!({ "error": "the file moved on since", "version": current }))?.with_status(409));
		}
		let next = current + 1;
		let object_key = get("objectKey").ok_or_else(|| worker::Error::RustError("missing objectKey".into()))?;
		let content_key = get("ck").ok_or_else(|| worker::Error::RustError("missing content key".into()))?;
		// The content key must arrive already sealed to the store key — a raw
		// key would let the server (or a leaked row) open the content.
		if !gorani_formats::formats::is_sealed_text(&content_key) {
			return json_error(400, "the content key must arrive sealed to the store key");
		}
		let size = body.get("size").and_then(|v| v.as_i64()).ok_or_else(|| worker::Error::RustError("missing size".into()))?;
		let r#type = get("type");
		if r#type.as_ref().is_some_and(|t| !gorani_formats::formats::is_sealed_text(t)) {
			return json_error(400, "types must be sealed text");
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
		self.audit(actor, "file.version", &file_id, None, None).await?;
		self.file_row(&file_id).await
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
			let rows = self.sql.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at FROM files WHERE deleted_at IS NULL ORDER BY created_at, id LIMIT ?1 OFFSET ?2", Some(vec![limit.into(), offset.into()]))?.to_array()?;
			let total = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL", None)?.one::<TotalCount>()?;
			(rows, total)
		} else {
			let parent = if folder == "root" { None } else { Some(folder.clone()) };
			let rows = self
				.sql
				.exec("SELECT id, folder_id, name_sealed, size, version, created_at, updated_at FROM files WHERE deleted_at IS NULL AND folder_id IS ?1 ORDER BY created_at, id LIMIT ?2 OFFSET ?3", Some(vec![bind(parent.clone()), limit.into(), offset.into()]))?
				.to_array()?;
			let total = self.sql.exec("SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL AND folder_id IS ?1", Some(vec![bind(parent)]))?.one::<TotalCount>()?;
			(rows, total)
		};
		let folders: Vec<FolderSqlRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE deleted_at IS NULL ORDER BY name_sealed, id", None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({
			"total": total.n,
			"files": rows.into_iter().map(|f| serde_json::json!({
				"id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size,
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at,
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
					"SELECT v.file_id, v.version, v.content_key, v.vault_key_id, v.object_key, v.type_sealed, v.size, v.chunk_size, v.tag FROM file_versions v JOIN files f ON f.id = v.file_id AND f.version = v.version WHERE v.file_id = ?1",
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
				"SELECT f.id, v.tag FROM files f JOIN file_versions v ON v.file_id = f.id AND v.version = f.version WHERE f.size = ?1 AND f.deleted_at IS NULL",
				Some(vec![size.into()]),
			)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "files": rows.into_iter().map(|r| serde_json::json!({ "id": r.id, "tag": r.tag })).collect::<Vec<_>>() }))?)
	}

	/// The `files-object/:id` route: the object's location + wrapped key, for
	/// the Worker to stream from S3. Metadata only — no name, no key material
	/// beyond the wrapped one the client will open.
	pub(crate) async fn file_object_route(&self, file_id: &str, version: Option<i64>) -> Result<Response> {
		match self.file_object(file_id, version).await? {
			Some(o) => Ok(Response::from_json(&serde_json::json!({
				"objectKey": o.object_key, "ck": o.content_key, "vaultKeyId": o.vault_key_id,
				"chunk": o.chunk_size, "size": o.size,
			}))?),
			None => json_error(404, "no such file"),
		}
	}

	/// The object of a version, for the Worker to stream from S3 with its
	/// wrapped key in a header.
	async fn file_object(&self, file_id: &str, version: Option<i64>) -> Result<Option<ObjectRow>> {
		let row: Option<ObjectRow> = match version {
			Some(v) => self
				.sql
				.exec("SELECT content_key, vault_key_id, object_key, chunk_size, size FROM file_versions WHERE file_id = ?1 AND version = ?2", Some(vec![file_id.into(), v.into()]))?
				.to_array::<ObjectRow>()
				.ok()
				.and_then(|mut r| r.pop()),
			None => self
				.sql
				.exec(
					"SELECT v.content_key, v.vault_key_id, v.object_key, v.chunk_size, v.size FROM file_versions v JOIN files f ON f.id = v.file_id AND f.version = v.version WHERE f.id = ?1",
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
			if !gorani_formats::formats::is_sealed_text(n) {
				return json_error(400, "names must be sealed text");
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
		if !gorani_formats::formats::is_sealed_text(&name) {
			return json_error(400, "names must be sealed text");
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
			if !gorani_formats::formats::is_sealed_text(n) {
				return json_error(400, "names must be sealed text");
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

	// ── Files secrets (fingerprint + index keys, sealed) ────────────────

	pub(crate) async fn secrets_get(&self) -> Result<Response> {
		let row: Option<KvRow> = self.sql.exec("SELECT v FROM files_secrets LIMIT 1", None)?.to_array::<KvRow>().ok().and_then(|mut r| r.pop());
		Ok(Response::from_json(&serde_json::json!({ "sealed": row.map(|r| r.v) }))?)
	}

	pub(crate) async fn secrets_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(sealed) = body.get("sealed").and_then(|v| v.as_str()).map(str::to_string) else { return json_error(400, "sealed required") };
		if !gorani_formats::formats::is_sealed_text(&sealed) {
			return json_error(400, "secrets must be sealed text");
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
			None => self.file_put(actor, body).await?,
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

	/// Rotation, client-driven (docs/VAULT.md: rotate = re-wrap small keys,
	/// never re-encrypt content). The client opened every content key under
	/// the old store key and sealed it to the new one; names and types are
	/// re-sealed the same way and sent along. This route stores the results —
	/// and is idempotent: a row is either under the old key or the new one,
	/// and doing it twice does no harm.
	pub(crate) async fn files_reseal(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let Some(entries) = body.get("keys").and_then(|k| k.as_object()) else { return json_error(400, "keys required") };
		let mut updated = 0;
		for (id, v) in entries {
			let ck = v.get("ck").and_then(|x| x.as_str()).unwrap_or_default().to_string();
			let name = v.get("name").and_then(|x| x.as_str()).map(str::to_string);
			let r#type = v.get("type").and_then(|x| x.as_str()).map(str::to_string);
			if !gorani_formats::formats::is_sealed_text(&ck) || name.as_ref().is_some_and(|n| !gorani_formats::formats::is_sealed_text(n)) || r#type.as_ref().is_some_and(|t| !gorani_formats::formats::is_sealed_text(t)) {
				return json_error(400, "reseal values must be sealed text");
			}
			let n = self
				.sql
				.exec(
					"SELECT COUNT(*) AS n FROM file_versions WHERE file_id = ?1 AND version = (SELECT version FROM files WHERE id = ?1)",
					Some(vec![id.clone().into()]),
				)?
				.one::<TotalCount>()?
				.n;
			self.sql.exec(
				"UPDATE file_versions SET content_key = ?1, type_sealed = COALESCE(?2, type_sealed) WHERE file_id = ?3 AND version = (SELECT version FROM files WHERE id = ?3)",
				Some(vec![ck.into(), bind(r#type), id.clone().into()]),
			)?;
			if let Some(nm) = &name {
				self.sql.exec("UPDATE files SET name_sealed = ?1 WHERE id = ?2", Some(vec![nm.clone().into(), id.clone().into()]))?;
			}
			updated += n;
		}
		self.audit(actor, "files.reseal", &format!("{updated} versions"), None, None).await?;
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
				"version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at,
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
}
#[derive(serde::Deserialize)]
struct ObjectRow {
	content_key: String,
	vault_key_id: Option<String>,
	object_key: String,
	chunk_size: Option<i64>,
	size: i64,
}
#[derive(serde::Deserialize)]
struct ExistsRow {
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
