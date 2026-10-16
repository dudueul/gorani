// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Protected copies in the member DO (commit 40b, docs/DRM.md): the rows of
//! migration v21. The routes that use them — and every decision about WHO —
//! are worker/src/drm.rs; this side keeps the rows honest:
//!
//! - a copy belongs to a LIVE version of a file that is not a malware
//!   sample (a sample is never decoded, let alone played);
//! - starting a copy for a version that already has one replaces it, and
//!   hands the old object and upload back so the Worker can delete them —
//!   never two keys for one version;
//! - a layout is written once, when the copy is complete, and the copy is
//!   `ready` only then;
//! - unprotecting, purging a version, or purging the file removes the rows
//!   — the sealed key with them — and queues the objects for deletion.
//!
//! The sealed content key is stored, and handed back to the Worker on the
//! internal `files-drm-copy` route only; no route of the DO's ever returns
//! it to a browser (drm.rs strips nothing, because the DO never gives the
//! browser-facing routes anything to strip — `files-drm/<file>` lists no
//! key material).

use worker::{Response, Result};

use crate::family::json_error;
use crate::member::GoraniMemberDO;

#[derive(serde::Deserialize)]
struct CopyRow {
	version: i64,
	kid: String,
	key_sealed: String,
	iv: String,
	object_key: String,
	upload_id: Option<String>,
	state: String,
	size: Option<i64>,
	layout: Option<String>,
	created_by: String,
	created_at: String,
	ready_at: Option<String>,
}

#[derive(serde::Deserialize)]
struct LiveVersion {
	sample: i64,
	current: i64,
}

#[derive(serde::Deserialize)]
struct Flag {
	protected_by: String,
	protected_at: String,
}

#[derive(serde::Deserialize)]
struct Orphan {
	object_key: String,
	upload_id: Option<String>,
	state: String,
}

impl GoraniMemberDO {
	/// The file's live state for a copy: is `version` one of its versions,
	/// is it a sample, and which version is current. None: no such live file.
	fn drm_live(&self, file: &str, version: i64) -> Result<Option<LiveVersion>> {
		Ok(self
			.sql
			.exec(
				"SELECT f.sample AS sample, f.version AS current FROM files f JOIN file_versions v ON v.file_id = f.id WHERE f.id = ?1 AND v.version = ?2 AND f.deleted_at IS NULL",
				Some(vec![file.into(), version.into()]),
			)?
			.to_array::<LiveVersion>()?
			.into_iter()
			.next())
	}

	/// `POST files-drm/<file>` {version, kid, keySealed, iv, objectKey,
	/// uploadId}: a copy begins (drm.rs made the key and opened the upload).
	/// Answers `{replaced}` — the copy this one replaces, for the Worker to
	/// abort and delete — or null.
	pub(crate) async fn drm_start(&self, actor: &str, file: &str, body: serde_json::Value) -> Result<Response> {
		let s = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(version) = body.get("version").and_then(|v| v.as_i64()) else { return json_error(400, "version required") };
		let (Some(kid), Some(key_sealed), Some(iv), Some(object_key), Some(upload_id)) = (s("kid"), s("keySealed"), s("iv"), s("objectKey"), s("uploadId")) else {
			return json_error(400, "kid, keySealed, iv, objectKey and uploadId required");
		};
		match self.drm_live(file, version)? {
			None => return json_error(404, "no such live file version"),
			Some(l) if l.sample != 0 => return json_error(409, "a malware sample is never played — it has no protected copy"),
			Some(_) => {}
		}
		let old: Vec<Orphan> = self
			.sql
			.exec("SELECT object_key, upload_id, state FROM drm_copies WHERE file_id = ?1 AND version = ?2", Some(vec![file.into(), version.into()]))?
			.to_array()?;
		self.sql.exec(
			"INSERT INTO drm_files (file_id, protected_by, protected_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT (file_id) DO NOTHING",
			Some(vec![file.into(), actor.into()]),
		)?;
		self.sql.exec(
			"INSERT INTO drm_copies (file_id, version, kid, key_sealed, iv, object_key, upload_id, state, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'packaging', ?8, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
			 ON CONFLICT (file_id, version) DO UPDATE SET kid = excluded.kid, key_sealed = excluded.key_sealed, iv = excluded.iv, object_key = excluded.object_key, upload_id = excluded.upload_id,
			   state = 'packaging', size = NULL, layout = NULL, created_by = excluded.created_by, created_at = excluded.created_at, ready_at = NULL",
			Some(vec![file.into(), version.into(), kid.clone().into(), key_sealed.into(), iv.into(), object_key.into(), upload_id.into(), actor.into()]),
		)?;
		self.audit(actor, "drm.protect", file, None, Some(&format!("version:{version} kid:{kid}"))).await?;
		let replaced = old.into_iter().next().map(|o| serde_json::json!({ "objectKey": o.object_key, "uploadId": if o.state == "packaging" { o.upload_id } else { None } }));
		Response::from_json(&serde_json::json!({ "replaced": replaced }))
	}

	/// `POST files-drm/<file>/<version>/complete` {layout, size}: the copy is
	/// uploaded (drm.rs completed the multipart upload and checked the
	/// layout against the size); it is ready to play.
	pub(crate) async fn drm_complete(&self, actor: &str, file: &str, version: &str, body: serde_json::Value) -> Result<Response> {
		let Ok(version) = version.parse::<i64>() else { return json_error(400, "version") };
		let Some(layout) = body.get("layout") else { return json_error(400, "layout required") };
		let size = body.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
		let n = self
			.sql
			.exec(
				"UPDATE drm_copies SET state = 'ready', layout = ?3, size = ?4, upload_id = NULL, ready_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE file_id = ?1 AND version = ?2 AND state = 'packaging'",
				Some(vec![file.into(), version.into(), layout.to_string().into(), size.into()]),
			)?
			.rows_written();
		if n == 0 {
			return json_error(404, "no copy of this version is being packaged");
		}
		self.audit(actor, "drm.ready", file, None, Some(&format!("version:{version} size:{size}"))).await?;
		Response::from_json(&serde_json::json!({ "ok": true }))
	}

	/// `GET files-drm/<file>`: what the app shows — whether the file is
	/// protected, by whom, its current version, and each copy's state. No
	/// key material.
	pub(crate) async fn drm_state(&self, file: &str) -> Result<Response> {
		let flag: Option<Flag> = self.sql.exec("SELECT protected_by, protected_at FROM drm_files WHERE file_id = ?1", Some(vec![file.into()]))?.to_array::<Flag>()?.into_iter().next();
		#[derive(serde::Deserialize)]
		struct Current {
			version: i64,
		}
		let current = self.sql.exec("SELECT version FROM files WHERE id = ?1 AND deleted_at IS NULL", Some(vec![file.into()]))?.to_array::<Current>()?.into_iter().next().map(|c| c.version);
		let copies: Vec<CopyRow> = self
			.sql
			.exec("SELECT version, kid, key_sealed, iv, object_key, upload_id, state, size, layout, created_by, created_at, ready_at FROM drm_copies WHERE file_id = ?1 ORDER BY version", Some(vec![file.into()]))?
			.to_array()?;
		Response::from_json(&serde_json::json!({
			"protected": flag.is_some(),
			"protectedBy": flag.as_ref().map(|f| f.protected_by.clone()),
			"protectedAt": flag.as_ref().map(|f| f.protected_at.clone()),
			"current": current,
			"copies": copies.iter().map(|c| serde_json::json!({
				"version": c.version, "state": c.state, "size": c.size, "kid": c.kid,
				"createdBy": c.created_by, "createdAt": c.created_at, "readyAt": c.ready_at,
				"segments": c.layout.as_deref().and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok()).and_then(|l| l.get("segments").and_then(|s| s.as_array()).map(|s| s.len())),
			})).collect::<Vec<_>>(),
		}))
	}

	/// `GET files-drm-copy/<file>/<version|current>`: the copy, sealed key
	/// included, for the Worker's own routes. `current` means the file's
	/// current version — the one a viewer is shown; drm.rs never serves an
	/// older copy in its place.
	pub(crate) async fn drm_copy(&self, file: &str, version: &str) -> Result<Response> {
		let version = if version == "current" {
			#[derive(serde::Deserialize)]
			struct Current {
				version: i64,
			}
			match self.sql.exec("SELECT version FROM files WHERE id = ?1 AND deleted_at IS NULL", Some(vec![file.into()]))?.to_array::<Current>()?.into_iter().next() {
				Some(c) => c.version,
				None => return json_error(404, "no such file"),
			}
		} else {
			match version.parse::<i64>() {
				Ok(v) => v,
				Err(_) => return json_error(400, "version"),
			}
		};
		let live = self.drm_live(file, version)?;
		let Some(live) = live else { return json_error(404, "no such live file version") };
		let row: Option<CopyRow> = self
			.sql
			.exec("SELECT version, kid, key_sealed, iv, object_key, upload_id, state, size, layout, created_by, created_at, ready_at FROM drm_copies WHERE file_id = ?1 AND version = ?2", Some(vec![file.into(), version.into()]))?
			.to_array::<CopyRow>()?
			.into_iter()
			.next();
		let Some(c) = row else { return json_error(404, "this version has no protected copy") };
		Response::from_json(&serde_json::json!({
			"version": c.version, "current": live.current, "kid": c.kid, "keySealed": c.key_sealed, "iv": c.iv,
			"objectKey": c.object_key, "uploadId": c.upload_id, "state": c.state, "size": c.size,
			"layout": c.layout.as_deref().and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok()),
		}))
	}

	/// `POST files-drm-license/<file>/<version>`: a license was handed to
	/// `actor` — one line in the area's trail per license.
	pub(crate) async fn drm_license_audit(&self, actor: &str, file: &str, version: &str) -> Result<Response> {
		self.audit(actor, "drm.license", file, None, Some(&format!("version:{version}"))).await?;
		Response::from_json(&serde_json::json!({ "ok": true }))
	}

	/// `DELETE files-drm/<file>`: protection off — every copy's rows (the
	/// sealed keys with them) gone, every object queued for deletion. The
	/// original is served by the usual rules again.
	pub(crate) async fn drm_unprotect(&self, actor: &str, file: &str) -> Result<Response> {
		let copies: Vec<Orphan> = self.sql.exec("SELECT object_key, upload_id, state FROM drm_copies WHERE file_id = ?1", Some(vec![file.into()]))?.to_array()?;
		let n = self.sql.exec("DELETE FROM drm_files WHERE file_id = ?1", Some(vec![file.into()]))?.rows_written();
		if n == 0 && copies.is_empty() {
			return json_error(404, "this file is not protected");
		}
		for c in &copies {
			self.enqueue_delete(&c.object_key, c.upload_id.as_deref().filter(|_| c.state == "packaging"), "protection removed")?;
		}
		self.sql.exec("DELETE FROM drm_copies WHERE file_id = ?1", Some(vec![file.into()]))?;
		self.audit(actor, "drm.unprotect", file, None, Some(&format!("copies:{}", copies.len()))).await?;
		Response::from_json(&serde_json::json!({ "ok": true, "copies": copies.len() }))
	}

	/// Housekeeping (member.rs): copies whose version is gone, and switches
	/// whose file is gone. Their objects queue for deletion; their rows —
	/// the sealed keys — go now.
	pub(crate) fn drm_purge_orphans(&self) -> Result<()> {
		let gone: Vec<Orphan> = self
			.sql
			.exec(
				"SELECT object_key, upload_id, state FROM drm_copies WHERE NOT EXISTS (SELECT 1 FROM file_versions v WHERE v.file_id = drm_copies.file_id AND v.version = drm_copies.version)",
				None,
			)?
			.to_array()?;
		for c in &gone {
			self.enqueue_delete(&c.object_key, c.upload_id.as_deref().filter(|_| c.state == "packaging"), "protected copy of a purged version")?;
		}
		self.sql.exec("DELETE FROM drm_copies WHERE NOT EXISTS (SELECT 1 FROM file_versions v WHERE v.file_id = drm_copies.file_id AND v.version = drm_copies.version)", None)?;
		self.sql.exec("DELETE FROM drm_files WHERE file_id NOT IN (SELECT id FROM files)", None)?;
		Ok(())
	}

	/// Has this file's CURRENT version a ready copy? (A view-only link is
	/// made only then — files_store.rs › share_create.)
	pub(crate) fn drm_ready_current(&self, file: &str) -> Result<bool> {
		#[derive(serde::Deserialize)]
		struct One {
			#[allow(dead_code)]
			one: i64,
		}
		Ok(!self
			.sql
			.exec(
				"SELECT 1 AS one FROM drm_copies c JOIN files f ON f.id = c.file_id AND f.version = c.version WHERE c.file_id = ?1 AND c.state = 'ready' AND f.deleted_at IS NULL",
				Some(vec![file.into()]),
			)?
			.to_array::<One>()?
			.is_empty())
	}

	/// `POST shares/<id>/drm-copy` {session}: for a LIVE viewing session of
	/// a live view-only link — the session's token hash, from a URL the
	/// Worker signed or a token the page sent — the copy of the link's file
	/// as it is now. Anything else: the refusal the public routes give.
	pub(crate) async fn share_drm_copy(&self, id: &str, session: &str) -> Result<Response> {
		#[derive(serde::Deserialize)]
		struct Live {
			file_id: Option<String>,
		}
		let live: Vec<Live> = self
			.sql
			.exec(
				"SELECT s.file_id AS file_id FROM shares s JOIN share_tokens t ON t.share_id = s.id
				 WHERE s.id = ?1 AND t.hash = ?2 AND t.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')
				   AND s.drm = 1 AND s.ready = 1 AND s.revoked_at IS NULL AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
				Some(vec![id.into(), session.into()]),
			)?
			.to_array()?;
		let Some(file) = live.into_iter().next().and_then(|l| l.file_id) else {
			return json_error(403, "this viewing session has ended — open the link again");
		};
		let mut copy = self.drm_copy(&file, "current").await?;
		if copy.status_code() != 200 {
			return Ok(copy);
		}
		let mut v: serde_json::Value = copy.json().await?;
		v["fileId"] = serde_json::json!(file);
		Response::from_json(&v)
	}

	/// Is this file protected? (The original's download route asks, through
	/// `files-object`.)
	pub(crate) fn drm_protected(&self, file: &str) -> Result<bool> {
		#[derive(serde::Deserialize)]
		struct One {
			#[allow(dead_code)]
			one: i64,
		}
		Ok(!self.sql.exec("SELECT 1 AS one FROM drm_files WHERE file_id = ?1", Some(vec![file.into()]))?.to_array::<One>()?.is_empty())
	}
}
