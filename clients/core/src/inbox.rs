// Copyright 2026- Seongwoo Hong. All rights reserved.

//! A case's inbox, from a member's side (commit 37c, docs/COLLECTORS.md) —
//! the twin of `web/src/vault/inbox.ts` and of `collectors.ts`' verdict.
//! The browser's modules are the specification; this one must agree byte
//! for byte (api:collect drives both against one worker).
//!
//! ```text
//! open      an inbox key with the CASE key, from its place case.inbox(area, key id) —
//!           and only if it is the key the registry's public halves describe
//! believe   an item when the collector is one two leads THIS member trusts
//!           registered, its signature covers every field of this case's item,
//!           its stamp is over that signature, and the bytes hash to what it signed
//! accept    a NEW file: name, type, content key placed with the case key, the
//!           member's own signed hash and intake, the collector's record beside it;
//!           the bytes stay where they landed
//! reject    with a reason sealed into place inbox.reject(area, item)
//! ```

use std::collections::BTreeMap;

use p256::ecdsa::VerifyingKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::{Client, Jwk};
use crate::area::Area;
use crate::cases::{self, IntakeFields};
use crate::identity::{self, identity_key_id, stmt, Trust};
use crate::transfer::hex;
use crate::Error;
use gorani_formats::formats::{self, VaultPrivateKey, VaultPublicKey};
use gorani_formats::placed::{self, Place};

/// An inbox key as the case list carries it.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxKeyRow {
	pub key_id: String,
	pub public_key: crate::cases::CasePublic,
	pub signed_by: String,
	#[serde(default)]
	pub retired_at: Option<String>,
	#[serde(default)]
	pub private_sealed: Option<String>,
}

/// A collector as `GET /api/v1/family/collectors` lists it (what the verdict reads).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorRow {
	pub id: String,
	pub common_name: String,
	pub status: String,
	pub key_id: String,
	pub public_key: Jwk,
	pub requested_by: String,
	pub request_signature: String,
	#[serde(default)]
	pub approved_by: Option<String>,
	#[serde(default)]
	pub approve_signature: Option<String>,
}

/// collectors.ts › collectorStatements.
fn request_statement(c: &CollectorRow) -> Vec<u8> {
	stmt("gorani-collector-v1", &[c.id.as_bytes(), c.common_name.as_bytes(), c.key_id.as_bytes(), c.requested_by.as_bytes()])
}
fn approve_statement(c: &CollectorRow, approver: &str) -> Vec<u8> {
	stmt("gorani-collector-approve-v1", &[c.id.as_bytes(), c.common_name.as_bytes(), c.key_id.as_bytes(), c.requested_by.as_bytes(), approver.as_bytes()])
}

/// Why a collector is NOT counted (collectors.ts › collectorVerdict), or None.
pub fn collector_verdict(trust: &Trust, c: &CollectorRow) -> Option<String> {
	if c.status != "active" {
		return Some(format!("the collector is {}", c.status));
	}
	if identity_key_id(&c.public_key).ok().as_deref() != Some(c.key_id.as_str()) {
		return Some("its key id is not its key's".into());
	}
	let (Some(approver), Some(approve_sig)) = (&c.approved_by, &c.approve_signature) else { return Some("it was never approved".into()) };
	if approver == &c.requested_by {
		return Some("one person both asked and approved".into());
	}
	let Some(asker) = trust.of(&c.requested_by) else { return Some(format!("{}, who asked for it, is not an identity you verified", c.requested_by)) };
	let Some(agreed) = trust.of(approver) else { return Some(format!("{approver}, who approved it, is not an identity you verified")) };
	if !asker.verify(&request_statement(c), &c.request_signature) {
		return Some(format!("the registration's signature does not verify — {} did not ask for this collector", c.requested_by));
	}
	if !agreed.verify(&approve_statement(c, approver), approve_sig) {
		return Some(format!("the approval's signature does not verify — {approver} did not approve this collector"));
	}
	None
}

/// The collectors this member counts, by id → their verifying key.
pub fn counted(trust: &Trust, rows: &[CollectorRow]) -> BTreeMap<String, VerifyingKey> {
	rows.iter().filter(|c| collector_verdict(trust, c).is_none()).filter_map(|c| Some((c.id.clone(), identity::verifying_key(&c.public_key).ok()?))).collect()
}

/// Open every inbox key of the area's case with the case key (inbox.ts › openInboxKeys).
pub fn open_inbox_keys(area: &Area) -> Result<BTreeMap<String, VaultPrivateKey>, Error> {
	let c = area.case.as_ref().ok_or(Error::Config("an inbox is a case's — pass --case".into()))?;
	let mut out = BTreeMap::new();
	for k in &c.inbox_keys {
		let sealed = k.private_sealed.as_deref().ok_or(Error::Open("an inbox key came without its private half"))?;
		let b64 = placed::open_placed_text(&area.key, &Place::case_inbox(&area.name, &k.key_id), sealed).map_err(|_| Error::Open("an inbox key does not open in its place under the case key"))?;
		let key = VaultPrivateKey::from_bytes(&crate::decode(&b64)?).map_err(|_| Error::Open("an inbox key bundle"))?;
		// The registry's public halves must be this private key's (inbox.ts ›
		// openInboxKey): both halves in full, then the id.
		let VaultPublicKey::Hybrid { ec, kem } = formats::public_of(&key) else { return Err(Error::Open("inbox keys are hybrid")) };
		if formats::raw_public_bytes(&ec)[..] != identity::ec_raw_of_jwk(&k.public_key.ec)?[..] || kem != crate::decode(&k.public_key.kem)?.as_slice() || formats::key_id(&formats::public_of(&key)) != k.key_id {
			return Err(Error::Open("an inbox key's public halves are not its private key's — refusing it"));
		}
		out.insert(k.key_id.clone(), key);
	}
	Ok(out)
}

/// An inbox item as `GET …/inbox` lists it.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxItem {
	pub id: String,
	pub collector: String,
	pub inbox_key_id: String,
	pub size: u64,
	#[serde(default)]
	pub chunk: Option<u64>,
	pub ck: String,
	pub meta: String,
	#[serde(default)]
	pub stamp: Value,
	pub received_at: String,
	pub status: String,
}

/// What the collector sealed into `meta` (inbox.ts › CollectMeta).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectMeta {
	pub case: String,
	pub item: String,
	pub collector: String,
	pub name: String,
	#[serde(rename = "type")]
	pub mime: String,
	pub size: u64,
	pub sha256: String,
	pub source: String,
	pub method: String,
	pub collected_at: String,
	pub notes: String,
	pub signature: String,
}

pub struct Opened {
	pub meta: CollectMeta,
	pub content_key: formats::ContentKey,
	/// None when VERIFIED; otherwise why not.
	pub problem: Option<String>,
}

/// Open an item and decide whether to believe it (inbox.ts › openInboxItem).
pub fn open_item(keys: &BTreeMap<String, VaultPrivateKey>, case_id: &str, item: &InboxItem, trust: &Trust, collectors: &[CollectorRow]) -> Result<Opened, Error> {
	let key = keys.get(&item.inbox_key_id).ok_or(Error::Open("the item is sealed to an inbox key this case does not have"))?;
	let text = formats::open_text(key, &item.meta).map_err(|_| Error::Open("the item's record does not open with the inbox key"))?;
	let meta: CollectMeta = serde_json::from_str(&text).map_err(|_| Error::Format("the item's record"))?;
	let content_key = formats::unwrap_content_key(key, &item.ck).map_err(|_| Error::Open("the item's content key does not open with the inbox key"))?;
	let problem = problem_of(case_id, item, &meta, trust, collectors);
	Ok(Opened { meta, content_key, problem })
}

fn problem_of(case_id: &str, item: &InboxItem, m: &CollectMeta, trust: &Trust, collectors: &[CollectorRow]) -> Option<String> {
	if m.case != case_id {
		return Some(format!("its record is for case {}, not {case_id}", m.case));
	}
	if m.item != item.id {
		return Some(format!("its record is for item {}, not {}", m.item, item.id));
	}
	if m.collector != item.collector {
		return Some(format!("its record names collector {}, but {} dropped it", m.collector, item.collector));
	}
	if m.size != item.size {
		return Some(format!("its record says {} bytes, the store received {}", m.size, item.size));
	}
	if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
		return Some("its record carries no SHA-256".into());
	}
	let Some(key) = counted(trust, collectors).remove(&item.collector) else {
		return Some(format!("collector {} is not one you count — two leads you verified must have registered it", item.collector));
	};
	let i = crate::collector::Intake { name: m.name.clone(), mime: m.mime.clone(), source: m.source.clone(), method: m.method.clone(), collected_at: m.collected_at.clone(), notes: m.notes.clone() };
	if !identity::verify_with(&key, &crate::collector::collect_statement(&m.case, &m.item, &m.collector, &m.sha256, m.size, &i), &m.signature) {
		return Some(format!("the collector's signature does not verify — {} did not collect this", item.collector));
	}
	if let Some(imprint) = item.stamp["imprint"].as_str() {
		if identity::stamp_imprint(&m.signature).ok().as_deref() != Some(imprint) {
			return Some("its timestamp imprint is not over the collector's signature".into());
		}
	}
	None
}

/// Read the item's bytes from the store, decrypting and hashing as they
/// come (frames a window at a time — never the whole of a large item), and
/// hand each plaintext piece to `sink`. Returns the SHA-256 and size.
pub fn hash_item(client: &Client, item: &InboxItem, key: &[u8; 32], mut sink: impl FnMut(&[u8]) -> Result<(), Error>) -> Result<(String, u64), Error> {
	let mut h = Sha256::new();
	let mut size = 0u64;
	match item.chunk.filter(|c| *c > 0) {
		None => {
			let sealed = client.fetch_inbox(&item.id, None)?;
			let plain = formats::open_with(key, &sealed).map_err(|_| Error::Open("the item's content (altered or not its key)"))?;
			h.update(&plain[..]);
			size += plain.len() as u64;
			sink(&plain)?;
		}
		Some(chunk) => {
			let count = gorani_formats::chunked::frame_count(item.size, chunk);
			let frame = chunk + gorani_formats::chunked::FRAME_OVERHEAD;
			let sealed = gorani_formats::chunked::sealed_size(item.size, chunk);
			let per = ((16 * 1024 * 1024) / frame).max(1);
			let mut i = 0;
			while i < count {
				let n = per.min(count - i);
				let (start, end) = (i * frame, ((i + n) * frame).min(sealed));
				let bytes = client.fetch_inbox(&item.id, Some((start, end)))?;
				if bytes.len() as u64 != end - start {
					return Err(Error::Open("the server answered a different span than asked"));
				}
				for k in 0..n {
					let (at, to) = ((k * frame) as usize, (((k + 1) * frame) as usize).min(bytes.len()));
					let idx = i + k;
					let plain = gorani_formats::chunked::open_chunk(key, &bytes[at..to], idx, idx == count - 1).map_err(|_| Error::Open("the item's content (altered, reordered or cut short)"))?;
					h.update(&plain[..]);
					size += plain.len() as u64;
					sink(&plain)?;
				}
				i += n;
			}
		}
	}
	Ok((hex(&h.finalize()), size))
}

/// Accept a VERIFIED item whose bytes were checked (inbox.ts ›
/// acceptInboxItem): the member's signed fields for a new file, the
/// collector's record beside it. Returns the store's answer.
pub fn accept(client: &Client, area: &Area, item: &InboxItem, opened: &Opened, content: (&str, u64), name: Option<&str>) -> Result<Value, Error> {
	if let Some(p) = &opened.problem {
		return Err(Error::Config(format!("refusing to accept an item that is not verified: {p}")));
	}
	if content.0 != opened.meta.sha256 || content.1 != opened.meta.size {
		return Err(Error::Config("refusing to accept it: the content is not what the collector signed".into()));
	}
	let (signer, _) = area.team.as_ref().ok_or(Error::Config("accepting signs — your vault needs its identity".into()))?;
	let m = &opened.meta;
	let file = crate::new_item_id();
	let record = json!({
		"v": 1, "item": item.id, "collector": item.collector, "inboxKeyId": item.inbox_key_id,
		"receivedAt": item.received_at, "stamp": item.stamp, "meta": m, "acceptedBy": signer.member,
	});
	let (hash, stamp) = cases::sign_content_hash(signer, &area.key, &area.name, &file, 1, &m.sha256, m.size)?;
	let intake = IntakeFields { source: m.source.clone(), collector: format!("collector:{}", m.collector), method: m.method.clone(), collected_at: m.collected_at.clone(), notes: m.notes.clone() };
	let body = json!({
		"fileId": file,
		"name": area.seal(&Place::file_name(&area.name, &file), name.unwrap_or(&m.name))?,
		"type": area.seal(&Place::file_type(&area.name, &file, 1), if m.mime.is_empty() { "application/octet-stream" } else { &m.mime })?,
		"ck": placed::wrap_placed_key(&area.key, &Place::file_key(&area.name, &file, 1), &opened.content_key).map_err(|_| Error::Open("the case key"))?,
		"hash": hash,
		"stamp": stamp,
		"intake": cases::sign_intake(signer, &area.key, &area.name, &file, &intake)?,
		"collection": area.seal(&Place::file_collection(&area.name, &file), &record.to_string())?,
	});
	client.inbox_decide(&item.id, "accept", body)
}

/// Reject an item, the reason sealed into its place.
pub fn reject(client: &Client, area: &Area, item: &str, reason: &str) -> Result<Value, Error> {
	if reason.trim().is_empty() {
		return Err(Error::Config("--reason: a rejection says why".into()));
	}
	client.inbox_decide(item, "reject", json!({ "reason": area.seal(&Place::inbox_reject(&area.name, item), reason.trim())? }))
}
