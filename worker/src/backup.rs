// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The backup job (⑫): one `.gbak` per run, written to S3 under
//! `backups/<stamp>.gbak`, containing every folder/file/version row and the
//! SEALED objects as stored — the GB2 container (crates/formats/src/backup.rs)
//! wraps it all under a per-run file key whose only unwrapped copy is sealed
//! to the owner's backup PUBLIC key. The server writes backups it cannot
//! open; the key file (the private bundle) never leaves the owner.
//!
//! # Streaming (commit 25, docs/SECURITY-REVIEW.md › O9)
//!
//! v1 assembled the whole container in memory — every object read whole
//! (`s3::get`), concatenated, then one PUT — so a store bigger than the
//! isolate's memory (128 MB) could not be backed up at all, and ONE missing
//! object aborted the run with nothing written. Now:
//!
//! ```text
//! rows ─┐                                    ┌─▶ part 1 (≥ 8 MiB) ─┐
//!       ├─▶ GB2 writer (1 MiB segments) ─▶ buffer ─▶ part 2 …     ├─▶ multipart complete
//! objects (streamed, chunk by chunk) ─┘      └─▶ last part (any size) ─┘
//! ```
//!
//! Memory is bounded by one part plus one segment, whatever the store's size.
//! An object that is gone from storage is RECORDED — its entry says
//! `"missing": true` with an empty object, the manifest row counts it, the
//! response lists it — and the run carries on: a backup that silently skips
//! is a lie, one that refuses to run is no backup at all; one that says what
//! it could not include is the only honest kind. An object whose length
//! changes mid-read (S3 said N bytes, the stream gave M) aborts the run: the
//! entry format announces the length first, and a backup must never be wrong.

use gorani_formats::backup::{self, BackupWriter, FileKey};
use worker::{Response, Result};

/// Each multipart part of a .gbak: the backends' 5 MiB minimum, with room.
const PART: usize = 8 * 1024 * 1024;

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}

use crate::family::json_error;
use crate::files_store::bind;
use crate::member::GoraniMemberDO;


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
		// When this backup was made, INSIDE the authenticated header (GB2): the
		// time a restore shows is one the server cannot relabel afterwards —
		// the manifest row's created_at is the server's word, this is sealed.
		let created_at = self
			.sql
			.exec("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now') AS v", None)?
			.one::<KvRow>()
			.map(|r| r.v)
			.unwrap_or_default();
		let header = serde_json::json!({
			"format": "gorani-backup",
			"v": 2, // GB2 (commit 25): the header is authenticated by every segment
			"createdAt": created_at,
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
			.exec("SELECT f.id, f.folder_id, f.name_sealed, f.size, f.version, f.created_at, f.updated_at, f.owner, f.intake_sealed FROM files f WHERE f.deleted_at IS NULL", None)?
			.to_array()?;
		let versions: Vec<VersionJsonRow> = self
			.sql
			.exec("SELECT v.file_id, v.version, v.content_key, v.vault_key_id, v.object_key, v.type_sealed, v.size, v.chunk_size, v.hash_sealed, v.stamp_imprint, v.stamp_token, v.stamped_at, v.created_at FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.deleted_at IS NULL", None)?
			.to_array()?;
		let secrets: Vec<KvRow> = self.sql.exec("SELECT v FROM files_secrets LIMIT 1", None)?.to_array()?;

		// The writer emits the prefix itself and binds its hash into every
		// segment (GB2) — the stamp a restore trusts is the stamp that was sealed.
		let object_key = format!("backups/{stamp}.gbak");
		let mut sink = PartSink::start(&self.env, &object_key).await?;
		let mut out: Vec<u8> = Vec::new();
		let mut writer = BackupWriter::start(file_key, header.to_string().as_bytes(), &mut out);
		let result = self.write_entries(&mut writer, &mut out, &mut sink, folders, files, secrets, versions).await;
		let (entries, missing) = match result {
			Ok(r) => r,
			Err(e) => {
				// Nothing half-written survives: the parts are freed.
				sink.abort().await;
				return Err(e);
			}
		};
		writer.finish(&mut out);
		let size = match sink.finish(out).await {
			Ok(n) => n,
			Err(e) => {
				sink.abort().await;
				return Err(e);
			}
		};
		self.sql
			.exec(
				"INSERT INTO backups (stamp, kind, size, entries, created_at, missing) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?5)",
				Some(vec![stamp.clone().into(), kind.into(), (size as i64).into(), (entries as i64).into(), (missing.len() as i64).into()]),
			)
			.map_err(|e| worker::Error::RustError(format!("backup record: {e}")))?;
		let note = if missing.is_empty() { format!("entries: {entries}") } else { format!("entries: {entries}, MISSING objects: {}", missing.len()) };
		self.audit(actor, "backup.run", &stamp, None, Some(&note)).await?;
		Ok(Response::from_json(&serde_json::json!({ "stamp": stamp, "size": size, "entries": entries, "missing": missing }))?)
	}

	/// The entry stream: folders, files, secrets, then versions with their
	/// sealed objects streamed in. Returns (entries, missing objects).
	#[allow(clippy::too_many_arguments)]
	async fn write_entries(
		&self,
		writer: &mut BackupWriter,
		out: &mut Vec<u8>,
		sink: &mut PartSink<'_>,
		folders: Vec<FolderJsonRow>,
		files: Vec<FileJsonRow>,
		secrets: Vec<KvRow>,
		versions: Vec<VersionJsonRow>,
	) -> Result<(u64, Vec<serde_json::Value>)> {
		let mut entries = 0u64;
		// A row entry: jsonLen ‖ json ‖ objectLen (0) — no object follows.
		let row = |json: serde_json::Value, writer: &mut BackupWriter, out: &mut Vec<u8>| {
			let json_bytes = json.to_string().into_bytes();
			writer.write(&(json_bytes.len() as u32).to_be_bytes(), out);
			writer.write(&json_bytes, out);
			writer.write(&0u64.to_be_bytes(), out);
		};
		for f in folders {
			row(serde_json::json!({ "kind": "folder", "id": f.id, "parent": f.parent_id, "name": f.name_sealed, "createdAt": f.created_at, "updatedAt": f.updated_at }), writer, out);
			entries += 1;
			sink.drain(out).await?;
		}
		for f in files {
			// (`intake`: an evidence file's sealed, signed intake record —
			// commit 29g; still sealed, as everything here.)
			row(serde_json::json!({ "kind": "file", "id": f.id, "folder": f.folder_id, "name": f.name_sealed, "size": f.size, "version": f.version, "createdAt": f.created_at, "updatedAt": f.updated_at, "owner": f.owner, "intake": f.intake_sealed }), writer, out);
			entries += 1;
			sink.drain(out).await?;
		}
		if let Some(s) = secrets.into_iter().next() {
			row(serde_json::json!({ "kind": "files-secrets", "sealed": s.v }), writer, out);
			entries += 1;
		}
		// The custody chains (commit 29g): every link with both signatures
		// and its sealed reason — a restored evidence file keeps its history
		// of who answered for it.
		let links: Vec<CustodyJsonRow> = self
			.sql
			.exec("SELECT file_id, seq, from_member, to_member, reason_sealed, offered_at, offer_signature, accepted_at, accept_signature, cancelled_at FROM custody ORDER BY file_id, seq", None)?
			.to_array()?;
		for l in links {
			row(serde_json::json!({ "kind": "custody", "file": l.file_id, "seq": l.seq, "from": l.from_member, "to": l.to_member, "reasonSealed": l.reason_sealed, "offeredAt": l.offered_at, "offerSignature": l.offer_signature, "acceptedAt": l.accepted_at, "acceptSignature": l.accept_signature, "cancelledAt": l.cancelled_at }), writer, out);
			entries += 1;
		}
		let mut missing = Vec::new();
		for v in versions {
			// (`hash`: the uploader's signed content hash, still sealed — commit
			// 29d. A restored evidence version keeps the claim that makes it
			// evidence. `stamp`: its RFC 3161 imprint and token — 29j; a token
			// cannot be asked for again with the original time.)
			let mut entry = serde_json::json!({ "kind": "version", "file": v.file_id, "version": v.version, "key": v.content_key, "vaultKeyId": v.vault_key_id, "type": v.type_sealed, "size": v.size, "chunk": v.chunk_size, "hash": v.hash_sealed, "stamp": { "imprint": v.stamp_imprint, "token": v.stamp_token, "at": v.stamped_at }, "createdAt": v.created_at });
			let mut resp = crate::s3::stream_uncached(&self.env, &v.object_key).await?;
			if resp.status_code() == 404 {
				// Recorded, not fatal: the entry says so, and so does the run.
				entry["missing"] = serde_json::json!(true);
				row(entry, writer, out);
				missing.push(serde_json::json!({ "file": v.file_id, "version": v.version, "object": v.object_key }));
				entries += 1;
				sink.drain(out).await?;
				continue;
			}
			if resp.status_code() != 200 {
				return Err(worker::Error::RustError(format!("backup: reading {} answered HTTP {}", v.object_key, resp.status_code())));
			}
			let announced: u64 = resp
				.headers()
				.get("Content-Length")?
				.and_then(|l| l.parse().ok())
				.ok_or_else(|| worker::Error::RustError(format!("backup: {} has no length", v.object_key)))?;
			let json_bytes = entry.to_string().into_bytes();
			writer.write(&(json_bytes.len() as u32).to_be_bytes(), out);
			writer.write(&json_bytes, out);
			writer.write(&announced.to_be_bytes(), out);
			let mut seen = 0u64;
			let mut body = resp.stream()?;
			while let Some(chunk) = futures_util::StreamExt::next(&mut body).await {
				let chunk = chunk?;
				seen += chunk.len() as u64;
				if seen > announced {
					break;
				}
				writer.write(&chunk, out);
				sink.drain(out).await?;
			}
			if seen != announced {
				return Err(worker::Error::RustError(format!("backup: {} changed length mid-read ({announced} announced, {seen} read) — run again", v.object_key)));
			}
			entries += 1;
		}
		Ok((entries, missing))
	}

	pub(crate) async fn backups_list(&self) -> Result<Response> {
		let rows: Vec<BackupRow> = self
			.sql
			.exec("SELECT stamp, kind, size, entries, created_at, missing FROM backups ORDER BY created_at DESC", None)?
			.to_array()?;
		Ok(Response::from_json(&serde_json::Value::Array(
			rows.into_iter()
				.map(|r| serde_json::json!({ "stamp": r.stamp, "kind": r.kind, "size": r.size, "entries": r.entries, "createdAt": r.created_at, "missing": r.missing.unwrap_or(0) }))
				.collect(),
		))?)
	}

	pub(crate) async fn backup_object(&self, stamp: &str) -> Result<Response> {
		let rows: Vec<BackupRow> = self.sql.exec("SELECT stamp, kind, size, entries, created_at, missing FROM backups WHERE stamp = ?1", Some(vec![stamp.into()]))?.to_array()?;
		// The manifest row only — the router streams the bytes (routes.rs ›
		// backup_download). This used to download the whole .gbak into the
		// DO's memory just to have the router discard it.
		let Some(r) = rows.into_iter().next() else { return json_error(404, "no such backup") };
		Ok(Response::from_json(&serde_json::json!({ "stamp": r.stamp, "kind": r.kind, "size": r.size, "entries": r.entries, "createdAt": r.created_at }))?)
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
	owner: Option<String>,
	intake_sealed: Option<String>,
}
#[derive(serde::Deserialize)]
struct CustodyJsonRow {
	file_id: String,
	seq: i64,
	from_member: String,
	to_member: String,
	reason_sealed: String,
	offered_at: String,
	offer_signature: String,
	accepted_at: Option<String>,
	accept_signature: Option<String>,
	cancelled_at: Option<String>,
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
	hash_sealed: Option<String>,
	stamp_imprint: Option<String>,
	stamp_token: Option<String>,
	stamped_at: Option<String>,
	created_at: String,
}
#[derive(serde::Deserialize)]
struct BackupRow {
	stamp: String,
	kind: String,
	size: i64,
	entries: i64,
	created_at: String,
	missing: Option<i64>,
}

fn base64_of(b: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(b)
}

// (closure borrow discipline: the push closure is called through a binding)
#[allow(unused)]
fn void<F>(_: &F) {}
use rand_core::RngCore as _RngCore;
// ── Restore (12c): replay decrypted rows + assign fresh object keys ──
//
// The CLIENT decrypts the .gbak with its key file and sends the rows; the
// server upserts them (ids preserved; triggers journal the changes so other
// devices converge) and assigns a FRESH object key per version — the client
// then re-puts the sealed object bytes to that key (zero-trust: the server
// stores what it cannot read, exactly like any upload).

impl GoraniMemberDO {
	/// Replay a decrypted backup's rows. The rules (security review, commit 23):
	///
	/// - **Object keys use the member whose DO this is** (`member`, from the
	///   router), not the actor. They used to be built from the ACTOR's id,
	///   so a parent restoring a child minted `files/<parent>/…` keys inside
	///   the child's database — keys the fill route (correctly) refused.
	/// - **Ids are ids**: every id that becomes a key segment passes the
	///   router's allow-list (`auth::valid_object_id`).
	/// - **A restore fills gaps; it does not rewrite history.** A version row
	///   that already exists keeps its object unless that object is gone
	///   from storage (the real disaster case); ownership is never
	///   reassigned (`COALESCE(owner, ?)`, first uploader wins — the
	///   ownership rule of commit 15); the files secrets are restored only
	///   when absent.
	pub(crate) async fn backup_restore(&self, actor: &str, member: &str, body: serde_json::Value) -> Result<Response> {
		// (`member` is the AREA — a member id or `case:<id>` — whose
		// prefix every minted key starts with.)
		if !crate::area::valid_area(member) {
			return json_error(400, "restore needs the area id");
		}
		let mut objects: Vec<(String, String)> = Vec::new(); // (versionRef, objectKey)
		if let Some(folders) = body.get("folders").and_then(|v| v.as_array()) {
			for f in folders {
				let get = |k: &str| f.get(k).and_then(|v| v.as_str()).map(str::to_string);
				let Some(id) = get("id") else { continue };
				let Some(name) = get("name") else { continue };
				if !crate::auth::valid_object_id(&id) || get("parent").is_some_and(|p| !crate::auth::valid_object_id(&p)) {
					return json_error(400, "restored folder ids must be ids");
				}
				if !gorani_formats::placed::is_placed_text(&name) {
					return json_error(400, "restored folder names must be placed sealed text (GV04)");
				}
				self.sql
					.exec(
						"INSERT INTO file_folders (id, parent_id, name_sealed, created_at, updated_at) VALUES (?1, ?2, ?3, COALESCE(?4, strftime('%Y-%m-%dT%H:%M:%fZ','now')), strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(id) DO UPDATE SET name_sealed = ?3, deleted_at = NULL, trashed_with = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
						Some(vec![id.clone().into(), bind(get("parent")), name.into(), bind(get("createdAt"))]),
					)
					.map_err(|e| worker::Error::RustError(format!("restore folder: {e}")))?;
			}
		}
		if let Some(files) = body.get("files").and_then(|v| v.as_array()) {
			for f in files {
				let get = |k: &str| f.get(k).and_then(|v| v.as_str()).map(str::to_string);
				let Some(id) = get("id") else { continue };
				let Some(name) = get("name") else { continue };
				if !crate::auth::valid_object_id(&id) {
					return json_error(400, "restored file ids must be ids");
				}
				if !gorani_formats::placed::is_placed_text(&name) || get("intake").is_some_and(|i| !gorani_formats::placed::is_placed_text(&i)) {
					return json_error(400, "restored file names and intake records must be placed sealed text (GV04)");
				}
				self.sql
					.exec(
						"INSERT INTO files (id, folder_id, name_sealed, size, version, created_at, updated_at, owner, intake_sealed) VALUES (?1, ?2, ?3, ?4, ?5, COALESCE(?6, strftime('%Y-%m-%dT%H:%M:%fZ','now')), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?7, ?8) ON CONFLICT(id) DO UPDATE SET folder_id = ?2, name_sealed = ?3, size = ?4, deleted_at = NULL, trashed_with = NULL, owner = COALESCE(owner, ?7), intake_sealed = COALESCE(intake_sealed, ?8), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
						Some(vec![id.clone().into(), bind(get("folder")), name.into(), f.get("size").and_then(|v| v.as_i64()).unwrap_or(0).into(), f.get("version").and_then(|v| v.as_i64()).unwrap_or(1).into(), bind(get("createdAt")), bind(get("owner")), bind(get("intake"))]),
					)
					.map_err(|e| worker::Error::RustError(format!("restore file: {e}")))?;
				self.contributor_add(&id, actor).await?;
			}
		}
		let mut skipped: Vec<serde_json::Value> = Vec::new();
		if let Some(versions) = body.get("versions").and_then(|v| v.as_array()) {
			for v in versions {
				let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
				// The backup recorded this object as missing when it ran (O9):
				// there are no bytes to restore — say so, never mint an empty
				// object for it.
				if v.get("missing").and_then(|m| m.as_bool()) == Some(true) {
					skipped.push(serde_json::json!({ "file": get("file"), "version": v.get("version"), "reason": "missing when the backup ran" }));
					continue;
				}
				let Some(file) = get("file") else { continue };
				let file_for_key = file.clone();
				let Some(ck) = get("key") else { continue };
				if !crate::auth::valid_object_id(&file) {
					return json_error(400, "restored version file ids must be ids");
				}
				if !gorani_formats::placed::is_placed_text(&ck) || get("type").is_some_and(|t| !gorani_formats::placed::is_placed_text(&t)) || get("hash").is_some_and(|h| !gorani_formats::placed::is_placed_text(&h)) {
					return json_error(400, "restored content keys, types and hashes must be placed sealed text (GV04)");
				}
				// The stamp (commit 29j), if the backup had one: the imprint's shape
				// checked; the token is a public proof every reader verifies, so
				// it is bounded, not judged.
				let stamp = |k: &str| v.get("stamp").and_then(|s| s.get(k)).and_then(|x| x.as_str()).map(str::to_string);
				let (imprint, token, stamped_at) = (stamp("imprint"), stamp("token"), stamp("at"));
				if imprint.as_deref().is_some_and(|i| !crate::stamps::imprint_shape(i)) || token.as_deref().is_some_and(|t| t.len() > 65_536 || !t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')) {
					return json_error(400, "a restored version's timestamp must be a 64-hex imprint and a base64 token");
				}
				let version = v.get("version").and_then(|x| x.as_i64()).unwrap_or(1);
				// Gap-filling: a version whose object still exists stays as it is.
				let existing: Option<ExistingObject> = self
					.sql
					.exec("SELECT object_key FROM file_versions WHERE file_id = ?1 AND version = ?2", Some(vec![file.clone().into(), version.into()]))?
					.to_array::<ExistingObject>()?
					.into_iter()
					.next();
				if let Some(e) = existing {
					if crate::s3::head(&self.env, &e.object_key).await?.is_some() {
						continue;
					}
				}
				let object_key = format!("{}/{file_for_key}/r-{}", crate::area::key_prefix(member), crate::files_store::uuid());
				self.sql
					.exec(
						"INSERT INTO file_versions (file_id, version, content_key, vault_key_id, object_key, type_sealed, size, chunk_size, created_at, hash_sealed, stamp_imprint, stamp_token, stamped_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, COALESCE(?9, strftime('%Y-%m-%dT%H:%M:%fZ','now')), ?10, ?11, ?12, ?13) ON CONFLICT(file_id, version) DO UPDATE SET content_key = ?3, object_key = ?5, type_sealed = COALESCE(?6, type_sealed), size = ?7, hash_sealed = COALESCE(?10, hash_sealed), stamp_imprint = COALESCE(stamp_imprint, ?11), stamp_token = COALESCE(stamp_token, ?12), stamped_at = COALESCE(stamped_at, ?13)",
						Some(vec![
							file.clone().into(),
							version.into(),
							ck.into(),
							bind(get("vaultKeyId")),
							object_key.clone().into(),
							bind(get("type")),
							v.get("size").and_then(|x| x.as_i64()).unwrap_or(0).into(),
							v.get("chunk").and_then(|x| x.as_i64()).into(),
							bind(get("createdAt")),
							bind(get("hash")),
							bind(imprint),
							bind(token),
							bind(stamped_at),
						]),
					)
					.map_err(|e| worker::Error::RustError(format!("restore version: {e}")))?;
				// The files row's pointer must move to the restored version.
				self.sql.exec(
					"UPDATE files SET version = MAX(version, ?1), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
					Some(vec![version.into(), file_for_key.clone().into()]),
				)?;
				objects.push((format!("{file_for_key}:{version}"), object_key));
			}
		}
		if let Some(sealed) = body.get("secrets").and_then(|v| v.as_str()).map(str::to_string) {
			if !gorani_formats::placed::is_placed_text(&sealed) {
				return json_error(400, "restored secrets must be placed sealed text (GV04)");
			}
			// Only into an empty slot: the secrets (fingerprint + index keys)
			// a live vault already uses are never swapped by a restore.
			self.sql.exec("INSERT INTO files_secrets (v) SELECT ?1 WHERE NOT EXISTS (SELECT 1 FROM files_secrets)", Some(vec![sealed.into()]))?;
		}
		// Custody links (commit 29g): only into a gap — a link the store
		// still has is never overwritten by an older copy of itself.
		if let Some(links) = body.get("custody").and_then(|v| v.as_array()) {
			for l in links {
				let get = |k: &str| l.get(k).and_then(|v| v.as_str()).map(str::to_string);
				let (Some(file), Some(seq), Some(from), Some(to), Some(reason), Some(offered), Some(sig)) = (get("file"), l.get("seq").and_then(|v| v.as_i64()), get("from"), get("to"), get("reasonSealed"), get("offeredAt"), get("offerSignature")) else { continue };
				if !gorani_formats::placed::is_placed_text(&reason) {
					return json_error(400, "restored custody reasons must be placed sealed text (GV04)");
				}
				self.sql.exec(
					"INSERT OR IGNORE INTO custody (file_id, seq, from_member, to_member, reason_sealed, offered_at, offer_signature, accepted_at, accept_signature, cancelled_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
					Some(vec![file.into(), seq.into(), from.into(), to.into(), reason.into(), offered.into(), sig.into(), bind(get("acceptedAt")), bind(get("acceptSignature")), bind(get("cancelledAt"))]),
				)?;
			}
		}
		self.audit(actor, "backup.restore", "restore", None, Some(&format!("objects: {}", objects.len()))).await?;
		Ok(Response::from_json(&serde_json::json!({ "objects": objects.into_iter().map(|(r, k)| serde_json::json!({ "ref": r, "objectKey": k })).collect::<Vec<_>>(), "skipped": skipped }))?)
	}
}

#[derive(serde::Deserialize)]
struct ExistingObject {
	object_key: String,
}

/// The .gbak's multipart upload: parts of at least `PART` bytes, the last
/// one any size (S3, MinIO and R2 alike). At 8 MiB × 10 000 parts a single
/// container tops out near 78 GiB — the honest ceiling of a copy-everything
/// backup inside one isolate; beyond it, backups become manifests of object
/// references (docs/DECISIONS.md › D12).
struct PartSink<'a> {
	env: &'a worker::Env,
	key: String,
	upload_id: String,
	parts: Vec<(u32, String)>,
	size: u64,
}

impl<'a> PartSink<'a> {
	async fn start(env: &'a worker::Env, key: &str) -> Result<Self> {
		let upload_id = crate::s3::multipart_init(env, key).await?;
		Ok(Self { env, key: key.to_string(), upload_id, parts: Vec::new(), size: 0 })
	}

	/// Ship a part once the buffer holds enough for one.
	async fn drain(&mut self, out: &mut Vec<u8>) -> Result<()> {
		if out.len() >= PART {
			self.ship(std::mem::take(out)).await?;
		}
		Ok(())
	}

	async fn ship(&mut self, bytes: Vec<u8>) -> Result<()> {
		let n = self.parts.len() as u32 + 1;
		if n > 10_000 {
			return Err(worker::Error::RustError("backup: more than 10 000 parts — the store is past what one container can hold".into()));
		}
		self.size += bytes.len() as u64;
		let etag = crate::s3::multipart_part(self.env, &self.key, &self.upload_id, n, bytes).await?;
		self.parts.push((n, etag));
		Ok(())
	}

	/// The last part (any size — possibly the only one), then complete.
	async fn finish(&mut self, out: Vec<u8>) -> Result<u64> {
		self.ship(out).await?;
		crate::s3::multipart_complete(self.env, &self.key, &self.upload_id, &self.parts).await?;
		Ok(self.size)
	}

	/// Free the parts of a run that failed (best effort: the housekeeping's
	/// stale-upload sweep cannot see this upload — it has no bookkeeping row).
	async fn abort(&self) {
		let _ = crate::s3::multipart_abort(self.env, &self.key, &self.upload_id).await;
	}
}
