// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The backup job (⑫): one `.gbak` per run, written to S3 under
//! `backups/<stamp>.gbak`, containing every folder/file/version row and the
//! SEALED objects as stored — the GB1 container (crates/formats/src/backup.rs)
//! wraps it all under a per-run file key whose only unwrapped copy is sealed
//! to the owner's backup PUBLIC key. The server writes backups it cannot
//! open; the key file (the private bundle) never leaves the owner.
//!
//! v1 keeps the whole backup in memory before the S3 put — right for a
//! family NAS's first full backup (documented limit); multipart streaming
//! arrives with the restore commit.

use gorani_formats::backup::{self, BackupWriter, FileKey};
use worker::{Request, Response, Result};

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}

use crate::family::json_error;
use crate::member::GoraniMemberDO;

const STAMP_LEN: usize = 16;

fn stamp() -> String {
	let mut b = [0u8; 8];
	rand_core::OsRng.fill_bytes(&mut b);
	format!("{:016x}", u64::from_be_bytes(b))
}

impl GoraniMemberDO {
	/// The owner's backup public half (PUT once from the browser, which keeps
	/// the private bundle as its downloaded key file).
	pub(crate) async fn backup_key_put(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let key_id = get("keyId").ok_or_else(|| worker::Error::RustError("missing keyId".into()))?;
		let public_key = body.get("publicKey").cloned().ok_or_else(|| worker::Error::RustError("missing publicKey".into()))?;
		let pq = get("pqPublicKey");
		let record = serde_json::json!({ "keyId": key_id, "publicKey": public_key, "pqPublicKey": pq });
		self.sql
			.exec(
				"INSERT INTO vault (k, v) VALUES ('backup', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1",
				Some(vec![record.to_string().into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("backup key: {e}")))?;
		self.audit(actor, "backup.key", &key_id, None, None).await?;
		Ok(Response::from_json(&record)?)
	}

	pub(crate) async fn backup_key_get(&self) -> Result<Response> {
		let rows: Vec<KvRow> = self.sql.exec("SELECT v FROM vault WHERE k = 'backup'", None)?.to_array()?;
		match rows.into_iter().next() {
			Some(r) => Ok(Response::from_json(&serde_json::from_str::<serde_json::Value>(&r.v).unwrap_or(serde_json::Value::Null))?),
			None => Ok(Response::from_json(&serde_json::Value::Null)?),
		}
	}

	/// Run a full backup: rows + sealed objects → one GB1 container.
	pub(crate) async fn backup_run(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("full").to_string();
		if kind != "full" {
			return json_error(400, "only full backups are supported so far");
		}
		// The backup public key must exist (the browser PUT it with the
		// private half never leaving its tab).
		let key_rows: Vec<KvRow> = self.sql.exec("SELECT v FROM vault WHERE k = 'backup'", None)?.to_array()?;
		let Some(key_row) = key_rows.into_iter().next() else { return json_error(400, "no backup key is set up") };
		let keyrec: serde_json::Value = serde_json::from_str(&key_row.v).map_err(|e| worker::Error::RustError(format!("backup key: {e}")))?;
		let key_id = keyrec.get("keyId").and_then(|k| k.as_str()).unwrap_or_default().to_string();
		let public_key: Option<serde_json::Value> = keyrec.get("publicKey").cloned();
		let pq = keyrec.get("pqPublicKey").and_then(|k| k.as_str()).map(str::to_string);
		let pub_key = match (public_key, pq) {
			(Some(jwk), Some(kem)) => gorani_formats::formats::VaultPublicKey::from_jwk(jwk.get("x").and_then(|x| x.as_str()).unwrap_or_default(), jwk.get("y").and_then(|x| x.as_str()).unwrap_or_default(), Some(kem.as_str())).map_err(|e| worker::Error::RustError(format!("backup key: {e}")))?,
			(Some(jwk), None) => gorani_formats::formats::VaultPublicKey::from_jwk(jwk.get("x").and_then(|x| x.as_str()).unwrap_or_default(), jwk.get("y").and_then(|x| x.as_str()).unwrap_or_default(), None).map_err(|e| worker::Error::RustError(format!("backup key: {e}")))?,
			_ => return json_error(400, "backup key record is malformed"),
		};

		// The file key: random per run, sealed into the header (GV03).
		let file_key: FileKey = backup::new_file_key();
		let wrapped = gorani_formats::formats::seal_text(&pub_key, base64_of(file_key.as_ref()).as_str());
		let stamp = stamp();
		let header = serde_json::json!({
			"format": "gorani-backup",
			"v": 1,
			"stamp": stamp,
			"kind": kind,
			"keyId": key_id,
			"wrapped": wrapped,
			"seg": backup::SEG_SIZE,
			"alg": "AES-256-GCM",
		});

		// The entry stream: folders, files, versions (with objects), secrets.
		let folders: Vec<FolderJsonRow> = self.sql.exec("SELECT id, parent_id, name_sealed, created_at, updated_at FROM file_folders WHERE deleted_at IS NULL", None)?.to_array()?;
		let files: Vec<FileJsonRow> = self
			.sql
			.exec("SELECT f.id, f.folder_id, f.name_sealed, f.size, f.version, f.created_at, f.updated_at FROM files f WHERE f.deleted_at IS NULL", None)?
			.to_array()?;
		let versions: Vec<VersionJsonRow> = self
			.sql
			.exec("SELECT v.file_id, v.version, v.content_key, v.vault_key_id, v.object_key, v.type_sealed, v.size, v.chunk_size, v.created_at FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.deleted_at IS NULL", None)?
			.to_array()?;
		let secrets: Vec<KvRow> = self.sql.exec("SELECT v FROM files_secrets LIMIT 1", None)?.to_array()?;

		let mut writer = BackupWriter::new(file_key);
		let mut out: Vec<u8> = Vec::new();
		out.extend_from_slice(backup::MAGIC);
		out.extend_from_slice(&(header.to_string().len() as u32).to_be_bytes());
		out.extend_from_slice(header.to_string().as_bytes());

		let mut entries = 0u64;
		let mut push_entry = |json: serde_json::Value, object: Option<Vec<u8>>, writer: &mut BackupWriter, out: &mut Vec<u8>| -> Result<()> {
			let json_bytes = json.to_string().into_bytes();
			writer.write(&(json_bytes.len() as u32).to_be_bytes(), out);
			writer.write(&json_bytes, out);
			let obj = object.unwrap_or_default();
			writer.write(&(obj.len() as u64).to_be_bytes(), out);
			writer.write(&obj, out);
			Ok(())
		};

		for f in folders {
			push_entry(
				serde_json::json!({ "kind": "folder", "id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at }),
				None,
				&mut writer,
				&mut out,
			)?;
			entries += 1;
		}
		for f in files {
			push_entry(
				serde_json::json!({ "kind": "file", "id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size, "version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at }),
				None,
				&mut writer,
				&mut out,
			)?;
			entries += 1;
		}
		if let Some(s) = secrets.into_iter().next() {
			push_entry(serde_json::json!({ "kind": "files-secrets", "sealed": s.v }), None, &mut writer, &mut out)?;
			entries += 1;
		}
		for v in versions {
			let object = crate::s3::get(&self.env, &v.object_key).await?.ok_or_else(|| worker::Error::RustError(format!("missing object {}", v.object_key)))?;
			push_entry(
				serde_json::json!({ "kind": "version", "file": v.file_id, "version": v.version, "key": v.content_key, "vaultKeyId": v.vault_key_id, "type": v.type_sealed, "size": v.size, "chunk": v.chunk_size, "createdAt": v.created_at }),
				Some(object),
				&mut writer,
				&mut out,
			)?;
			entries += 1;
		}
		writer.finish(&mut out);

		// One S3 object per run (memory-bound for now; multipart streaming is
		// the restore commit's companion).
		let object_key = format!("backups/{stamp}.gbak");
		crate::s3::put(&self.env, &object_key, out.clone()).await?;
		self.sql
			.exec(
				"INSERT INTO backups (stamp, kind, size, entries, created_at) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
				Some(vec![stamp.clone().into(), kind.into(), (out.len() as i64).into(), (entries as i64).into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("backup record: {e}")))?;
		self.audit(actor, "backup.run", &stamp, None, Some(&format!("entries: {entries}"))).await?;
		Ok(Response::from_json(&serde_json::json!({ "stamp": stamp, "size": out.len(), "entries": entries }))?)
	}

	pub(crate) async fn backups_list(&self) -> Result<Response> {
		let rows: Vec<BackupRow> = self
			.sql
			.exec("SELECT stamp, kind, size, entries, created_at FROM backups ORDER BY created_at DESC", None)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::Value::Array(
			rows.into_iter()
				.map(|r| serde_json::json!({ "stamp": r.stamp, "kind": r.kind, "size": r.size, "entries": r.entries, "createdAt": r.created_at }))
				.collect(),
		))?)
	}

	pub(crate) async fn backup_object(&self, stamp: &str) -> Result<Response> {
		let rows: Vec<BackupRow> = self.sql.exec("SELECT stamp, kind, size, entries, created_at FROM backups WHERE stamp = ?1", Some(vec![stamp.into()]))?.to_array()?;
		let Some(_row) = rows.into_iter().next() else { return json_error(404, "no such backup") };
		let bytes = crate::s3::get(&self.env, &format!("backups/{stamp}.gbak")).await?.ok_or_else(|| worker::Error::RustError("backup object missing".into()))?;
		let mut headers = worker::Headers::new();
		headers.set("Content-Type", "application/octet-stream")?;
		headers.set("Content-Disposition", &format!("attachment; filename=\"gorani-{stamp}.gbak\""))?;
		Ok(Response::from_bytes(bytes)?.with_headers(headers))
	}
}

#[derive(serde::Deserialize)]
struct FolderJsonRow {
	id: String,
	parent_id: Option<String>,
	name_sealed: String,
	created_at: String,
	updated_at: String,
}
#[derive(serde::Deserialize)]
struct FileJsonRow {
	id: String,
	folder_id: Option<String>,
	name_sealed: String,
	size: i64,
	version: i64,
	created_at: String,
	updated_at: String,
}
#[derive(serde::Deserialize)]
struct VersionJsonRow {
	file_id: String,
	version: i64,
	content_key: String,
	vault_key_id: Option<String>,
	object_key: String,
	type_sealed: Option<String>,
	size: i64,
	chunk_size: Option<i64>,
	created_at: String,
}
#[derive(serde::Deserialize)]
struct BackupRow {
	stamp: String,
	kind: String,
	size: i64,
	entries: i64,
	created_at: String,
}

fn base64_of(b: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(b)
}

// (closure borrow discipline: the push closure is called through a binding)
#[allow(unused)]
fn void<F>(_: &F) {}
use rand_core::RngCore as _RngCore;