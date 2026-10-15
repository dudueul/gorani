// Copyright 2026- Seongwoo Hong. All rights reserved.

//! A case's inbox (commit 37b, docs/COLLECTORS.md), in the case's own store:
//! what collectors dropped, waiting for a person to accept or reject it.
//!
//! ```text
//! item   the object (GV02 whole, or GC01 frames) under a content key
//!        ck     the content key sealed to the inbox PUBLIC key (GV03)
//!        meta   sealed to the inbox public key (GV03): name, type, size, SHA-256,
//!               the intake fields, and the collector's signature over them
//!        stamp  SHA-256 of that signature — the RFC 3161 imprint, stamped at
//!               receipt (stamps.rs, as a version's)
//! ```
//!
//! The store can open none of it: the inbox private key is sealed under the
//! case key, which only the case's members hold. What it records is
//! structure — who dropped what size when — on the case's chained trail.
//! On an evidence case the object is write-once from receipt: the nightly
//! lock pass covers inbox objects too (member.rs › lock_pass).

use worker::{Response, Result};

use crate::family::json_error;
use crate::member::GoraniMemberDO;

fn hex64(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sealed to a hybrid public key, as a collector must seal (never placed:
/// placing would need the store's PRIVATE key, which a collector never has).
fn sealed_to_inbox(v: &str) -> bool {
	v.starts_with("GV03:") && v.len() > 5
}

impl GoraniMemberDO {
	/// `POST inbox/receive` — the Worker stored a drop's object (and, for a
	/// multipart drop, checked it adds up); record the item.
	pub(crate) async fn inbox_receive(&self, actor: &str, body: serde_json::Value) -> Result<Response> {
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(id) = get("id").filter(|i| crate::auth::valid_object_id(i)) else { return json_error(400, "item id: [A-Za-z0-9_-], ≤ 64 — chosen by the collector") };
		// From a collector (its id), or from an upload link (`request:<id>`, commit 38).
		let Some(collector) = get("collector").filter(|c| crate::auth::valid_member_id(c) || c.strip_prefix("request:").is_some_and(crate::requests::is_request_id)) else {
			return json_error(400, "collector id, or request:<link id>");
		};
		let Some(inbox_key) = get("inboxKeyId").filter(|k| crate::auth::valid_object_id(k)) else { return json_error(400, "inbox_key_id: the inbox key the item is sealed to") };
		let Some(object_key) = get("objectKey") else { return json_error(400, "objectKey") };
		let (Some(ck), Some(meta)) = (get("ck").filter(|v| sealed_to_inbox(v)), get("meta").filter(|v| sealed_to_inbox(v))) else {
			return json_error(400, "ck and meta must arrive sealed to the inbox's public key (GV03)");
		};
		let stamp = get("stamp");
		if stamp.as_deref().is_some_and(|s| !hex64(s)) {
			return json_error(400, "stamp: SHA-256 of the collector's signature, 64 hex");
		}
		let size = body.get("size").and_then(|v| v.as_i64()).filter(|s| *s >= 0).ok_or_else(|| worker::Error::RustError("missing size".into()))?;
		let chunk = body.get("chunk").and_then(|v| v.as_i64()).filter(|c| *c > 0);
		let taken = self.sql.exec("SELECT COUNT(*) AS n FROM inbox_items WHERE id = ?1", Some(vec![id.clone().into()]))?.one::<crate::files_store::TotalCount>()?.n;
		if taken > 0 {
			return json_error(409, "an item with this id was already received — choose a fresh id");
		}
		// An upload link's item is counted against the link here, with the
		// insert below, in one synchronous step: two uploads racing for the
		// last slot cannot both get it.
		if let Some(link) = collector.strip_prefix("request:") {
			if let Err((status, msg)) = self.request_take(link, &inbox_key, size)? {
				return json_error(status, msg);
			}
		}
		self.sql.exec(
			"INSERT INTO inbox_items (id, collector_id, inbox_key_id, object_key, size, chunk_size, ck_sealed, meta_sealed, stamp_imprint, received_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
			Some(vec![
				id.clone().into(),
				collector.clone().into(),
				inbox_key.into(),
				object_key.into(),
				size.into(),
				chunk.map(worker::SqlStorageValue::Integer).unwrap_or(worker::SqlStorageValue::Null),
				ck.into(),
				meta.into(),
				crate::files_store::bind(stamp.clone()),
			]),
		)?;
		self.audit(actor, "inbox.receive", &id, None, Some(&serde_json::json!({ "collector": collector, "size": size }).to_string())).await?;
		if stamp.is_some() {
			self.arm_stamps().await?;
		}
		Ok(Response::from_json(&serde_json::json!({ "id": id, "received": true }))?)
	}

	/// `GET inbox/list` — the case's inbox, newest first: every item, its
	/// sealed key and metadata, its stamp, and what became of it. Members
	/// open the sealed halves with the inbox key; the store reads none.
	pub(crate) async fn inbox_list(&self) -> Result<Response> {
		let rows: Vec<InboxRow> = self.sql.exec(&format!("SELECT {ROW} FROM inbox_items ORDER BY received_at DESC LIMIT 1000"), None)?.to_array()?;
		Ok(Response::from_json(&serde_json::json!({ "items": rows.iter().map(InboxRow::json).collect::<Vec<_>>() }))?)
	}

	/// `GET inbox-object/<item>?client=…` — where an item's bytes are, for
	/// the Worker to stream — and the read on record, as a file's (O14):
	/// the read log names it `inbox:<item>` (a file id holds no ':').
	pub(crate) async fn inbox_object(&self, item: &str, reader: &str, client: Option<&str>) -> Result<Response> {
		let rows: Vec<InboxRow> = self.sql.exec(&format!("SELECT {ROW} FROM inbox_items WHERE id = ?1"), Some(vec![item.into()]))?.to_array()?;
		let Some(r) = rows.into_iter().next() else { return json_error(404, "no such inbox item") };
		if reader != "internal" {
			let client: String = client.unwrap_or("unknown").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':').take(64).collect();
			self.sql.exec(
				"INSERT INTO read_log (actor, file_id, version, client, win, first_at, last_at, requests) VALUES (?1, ?2, 0, ?3, CAST(strftime('%s','now') AS INTEGER) / 300, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), 1) ON CONFLICT (actor, file_id, version, client, win) DO UPDATE SET last_at = excluded.last_at, requests = requests + 1",
				Some(vec![reader.into(), format!("inbox:{item}").into(), client.into()]),
			)?;
		}
		let mut v = r.json();
		v["objectKey"] = r.object_key.clone().into();
		Ok(Response::from_json(&v)?)
	}
}

impl GoraniMemberDO {
	/// `POST inbox/accept/<item> { fileId, by, name, type, ck, hash, stamp,
	/// intake, collection, folderId? }` — a person files an item (commit 37c,
	/// docs/COLLECTORS.md › accept). The client opened it with the inbox key,
	/// checked the collector's signature and the bytes, and now sends what a
	/// NEW file's upload sends — name, type and content key placed with the
	/// case key, their own signed content hash and intake — plus the
	/// collector's record, placed as `file.collection(area, file)`.
	///
	/// The bytes do not move: the version points at the inbox object, whose
	/// size and frame size are the store's own count, not the client's.
	pub(crate) async fn inbox_accept(&self, actor: &str, item: &str, body: serde_json::Value) -> Result<Response> {
		let get = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
		let Some(collection) = get("collection").filter(|c| gorani_formats::placed::is_placed_text(c)) else {
			return json_error(400, "collection: the collector's record, sealed into its place (GV04)");
		};
		let Some(file_id) = get("fileId").filter(|f| crate::auth::valid_object_id(f)) else { return json_error(400, "fileId: the new file's id, chosen by the client") };
		let by = get("by").unwrap_or_default();
		let rows: Vec<InboxRow> = self.sql.exec(&format!("SELECT {ROW} FROM inbox_items WHERE id = ?1"), Some(vec![item.into()]))?.to_array()?;
		let Some(r) = rows.into_iter().next() else { return json_error(404, "no such inbox item") };
		if r.accepted_at.is_some() || r.rejected_at.is_some() {
			return json_error(409, "this item was already decided — accepted or rejected, once");
		}
		// Claim it before anything awaits: two people accepting at once must
		// not make two files of one item. (The SELECT above and this UPDATE
		// run with no await between them — nothing interleaves.)
		self.sql.exec(
			"UPDATE inbox_items SET accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), accepted_by = ?1, accepted_file = ?2 WHERE id = ?3 AND accepted_at IS NULL AND rejected_at IS NULL",
			Some(vec![by.clone().into(), file_id.clone().into(), item.into()]),
		)?;
		let mut file = body.clone();
		file["id"] = file_id.clone().into();
		file["objectKey"] = r.object_key.clone().into();
		file["size"] = r.size.into();
		file["chunkSize"] = r.chunk_size.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
		// (The Worker checked the bytes' shape when the collector dropped them.)
		file["bytesSealed"] = true.into();
		let mut made = self.file_put(actor, file).await?;
		if made.status_code() >= 400 {
			self.sql.exec("UPDATE inbox_items SET accepted_at = NULL, accepted_by = NULL, accepted_file = NULL WHERE id = ?1", Some(vec![item.into()]))?;
			return Ok(made);
		}
		self.sql.exec("UPDATE files SET collection_sealed = ?1 WHERE id = ?2", Some(vec![collection.into(), file_id.clone().into()]))?;
		self.audit(actor, "inbox.accept", item, None, Some(&serde_json::json!({ "file": file_id, "collector": r.collector_id }).to_string())).await?;
		let row: serde_json::Value = made.json().await?;
		Ok(Response::from_json(&serde_json::json!({ "item": item, "file": row }))?)
	}

	/// `POST inbox/reject/<item> { reason, by }` — a person declines an item,
	/// with a reason sealed into place `inbox.reject(area, item)` (it may name
	/// what the item is). Returns the object key and whether the case keeps
	/// it: an evidence case's objects are write-once; a working case's go.
	pub(crate) async fn inbox_reject(&self, actor: &str, item: &str, body: serde_json::Value) -> Result<Response> {
		let Some(reason) = body.get("reason").and_then(|v| v.as_str()).filter(|r| gorani_formats::placed::is_placed_text(r)).map(str::to_string) else {
			return json_error(400, "reason: sealed into its place (GV04) — a rejection says why");
		};
		let by = body.get("by").and_then(|v| v.as_str()).unwrap_or_default().to_string();
		let rows: Vec<InboxRow> = self.sql.exec(&format!("SELECT {ROW} FROM inbox_items WHERE id = ?1"), Some(vec![item.into()]))?.to_array()?;
		let Some(r) = rows.into_iter().next() else { return json_error(404, "no such inbox item") };
		if r.accepted_at.is_some() || r.rejected_at.is_some() {
			return json_error(409, "this item was already decided — accepted or rejected, once");
		}
		self.sql.exec(
			"UPDATE inbox_items SET rejected_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), rejected_by = ?1, reject_reason = ?2 WHERE id = ?3 AND accepted_at IS NULL AND rejected_at IS NULL",
			Some(vec![by.into(), reason.into(), item.into()]),
		)?;
		let keep = self.is_evidence().await?;
		self.audit(actor, "inbox.reject", item, None, Some(&serde_json::json!({ "collector": r.collector_id, "objectKept": keep }).to_string())).await?;
		Ok(Response::from_json(&serde_json::json!({ "item": item, "rejected": true, "objectKey": r.object_key, "keep": keep }))?)
	}
}

const ROW: &str = "id, collector_id, inbox_key_id, object_key, size, chunk_size, ck_sealed, meta_sealed, stamp_imprint, stamp_token, stamped_at, received_at, accepted_at, accepted_by, accepted_file, rejected_at, rejected_by, reject_reason";

#[derive(serde::Deserialize)]
struct InboxRow {
	id: String,
	collector_id: String,
	inbox_key_id: String,
	object_key: String,
	size: i64,
	chunk_size: Option<i64>,
	ck_sealed: String,
	meta_sealed: String,
	stamp_imprint: Option<String>,
	stamp_token: Option<String>,
	stamped_at: Option<String>,
	received_at: String,
	accepted_at: Option<String>,
	accepted_by: Option<String>,
	accepted_file: Option<String>,
	rejected_at: Option<String>,
	rejected_by: Option<String>,
	reject_reason: Option<String>,
}

impl InboxRow {
	fn json(&self) -> serde_json::Value {
		let status = if self.accepted_at.is_some() {
			"accepted"
		} else if self.rejected_at.is_some() {
			"rejected"
		} else {
			"waiting"
		};
		serde_json::json!({
			"id": self.id, "collector": self.collector_id, "inboxKeyId": self.inbox_key_id,
			"size": self.size, "chunk": self.chunk_size, "ck": self.ck_sealed, "meta": self.meta_sealed,
			"stamp": { "imprint": self.stamp_imprint, "token": self.stamp_token, "at": self.stamped_at },
			"receivedAt": self.received_at, "status": status,
			"accepted": self.accepted_at.as_ref().map(|at| serde_json::json!({ "at": at, "by": self.accepted_by, "file": self.accepted_file })),
			"rejected": self.rejected_at.as_ref().map(|at| serde_json::json!({ "at": at, "by": self.rejected_by, "reason": self.reject_reason })),
		})
	}
}
