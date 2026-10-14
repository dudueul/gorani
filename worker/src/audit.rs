// Copyright 2026- Seongwoo Hong. All rights reserved.

//! `GoraniAuditDO` — one area's audit trail, tamper-evident (docs/CUSTODY.md
//! › Stage 1; docs/DECISIONS.md › D5.3, D7). Instances: `audit:<area>` —
//! `audit:jinu`, `audit:case:ir-14`, and `audit:registry` for the team
//! registry.
//!
//! Until commit 29 an area's audit was a table in the area's own database,
//! capped at 500 lines by the housekeeping pass, editable by anyone who
//! could write that database. Now:
//!
//! ```text
//! area DO ── its outbox (the old `audit` table, written with the action) ──ship──▶ this DO
//!   line_n.hash = SHA-256( line_{n-1}.hash ‖ canonical(line_n) )     base: 64 × "0", or the
//!                                                                    last pruned line's hash
//!   daily checkpoint { area, date, seq, hash } ──▶ the bucket: audit-checkpoints/<area>/<date>.json
//! ```
//!
//! - **Idempotent appends.** Each line carries its outbox id; an id at or
//!   below the last one accepted is skipped, so a retried ship never
//!   duplicates a line (and never reorders: the outbox ships in id order).
//! - **One spelling per line.** The hash input is length-prefixed fields
//!   (`canonical`), like every signed statement since commit 27.
//! - **Retention: 7 years, no line cap** (D7). Pruning moves the chain's
//!   BASE to the last pruned line's hash, so what remains still verifies.
//! - **Verification** recomputes the chain from the base and returns the
//!   hash at every sequence number the caller asks about — the Worker asks
//!   about each checkpoint it found in the bucket (routes.rs ›
//!   audit_verify): the bucket's word, not this database's.

use sha2::{Digest, Sha256};
use worker::*;

use crate::family::json_error;

pub const MIGRATIONS: &[&str] = &[
	// The chained lines. `source_id` is the area outbox's id (idempotency).
	"CREATE TABLE IF NOT EXISTS lines (
		seq INTEGER PRIMARY KEY,
		source_id INTEGER NOT NULL,
		at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
		details TEXT, details_sealed TEXT,
		hash TEXT NOT NULL
	)",
	"CREATE INDEX IF NOT EXISTS lines_at ON lines (at)",
	// base_hash / base_seq: where the chain starts (moved by pruning);
	// last_source: the highest outbox id accepted.
	"CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
	// The checkpoints this DO handed out (the BUCKET holds the copies that
	// count; these are a convenience for listing).
	"CREATE TABLE IF NOT EXISTS checkpoints (date TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL)",
];

const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// D7: the audit is kept 7 years.
pub const RETENTION_DAYS: i64 = 7 * 365 + 2;

#[durable_object]
pub struct GoraniAuditDO {
	sql: SqlStorage,
	schema: std::result::Result<(), String>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub(crate) struct LineIn {
	pub id: i64,
	pub at: String,
	pub actor: String,
	pub action: String,
	pub target: String,
	#[serde(default)]
	pub details: Option<String>,
	#[serde(default, rename = "detailsSealed")]
	pub details_sealed: Option<String>,
}

#[derive(serde::Deserialize)]
struct LineRow {
	seq: i64,
	at: String,
	actor: String,
	action: String,
	target: String,
	details: Option<String>,
	details_sealed: Option<String>,
	hash: String,
}

#[derive(serde::Deserialize)]
struct KvRow {
	v: String,
}

/// u32 BE length ‖ bytes, per field — one spelling of a line.
pub(crate) fn canonical(seq: i64, at: &str, actor: &str, action: &str, target: &str, details: Option<&str>, details_sealed: Option<&str>) -> Vec<u8> {
	let seq_s = seq.to_string();
	let fields: [&[u8]; 8] = [b"gorani-audit-v1", seq_s.as_bytes(), at.as_bytes(), actor.as_bytes(), action.as_bytes(), target.as_bytes(), details.unwrap_or("").as_bytes(), details_sealed.unwrap_or("").as_bytes()];
	let mut out = Vec::new();
	for f in fields {
		out.extend_from_slice(&(f.len() as u32).to_be_bytes());
		out.extend_from_slice(f);
	}
	out
}

/// The next link: SHA-256(previous hash ‖ canonical line), lowercase hex.
pub(crate) fn link(prev: &str, line: &[u8]) -> String {
	let mut h = Sha256::new();
	h.update(prev.as_bytes());
	h.update(line);
	hex::encode(h.finalize())
}

impl DurableObject for GoraniAuditDO {
	fn new(state: State, _env: Env) -> Self {
		let sql = state.storage().sql();
		let schema = crate::schema::migrate(&sql, MIGRATIONS);
		Self { sql, schema }
	}

	async fn fetch(&self, req: Request) -> Result<Response> {
		if let Err(e) = &self.schema {
			return json_error(500, &format!("audit schema: {e}"));
		}
		match self.dispatch(req).await {
			Ok(r) => Ok(r),
			Err(e) => json_error(500, &e.to_string()),
		}
	}
}

impl GoraniAuditDO {
	async fn dispatch(&self, mut req: Request) -> Result<Response> {
		let path = req.path().trim_start_matches('/').to_string();
		let url = req.url()?;
		let q = crate::files_store::urlquery(url.query().unwrap_or(""));
		match (req.method().to_string().as_str(), path.as_str()) {
			("POST", "append") => {
				let body = req.json::<AppendBody>().await?;
				self.append(body.lines)
			}
			("GET", "lines") => {
				let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(200).clamp(1, 1000);
				self.list(limit)
			}
			("GET", "verify") => {
				let at: Vec<i64> = q.get("at").map(|v| v.split(',').filter_map(|s| s.parse().ok()).collect()).unwrap_or_default();
				self.verify(&at)
			}
			("POST", "checkpoint") => {
				let date = q.get("date").cloned().unwrap_or_default();
				self.checkpoint(&date)
			}
			("POST", "prune") => self.prune(),
			_ => Response::error("Not Found", 404),
		}
	}

	fn meta(&self, k: &str) -> Result<Option<String>> {
		Ok(self.sql.exec("SELECT v FROM meta WHERE k = ?1", Some(vec![k.into()]))?.to_array::<KvRow>()?.into_iter().next().map(|r| r.v))
	}

	fn set_meta(&self, k: &str, v: &str) -> Result<()> {
		self.sql.exec("INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT (k) DO UPDATE SET v = ?2", Some(vec![k.into(), v.into()]))?;
		Ok(())
	}

	/// The newest line's (seq, hash), or the base.
	fn head(&self) -> Result<(i64, String)> {
		#[derive(serde::Deserialize)]
		struct H {
			seq: i64,
			hash: String,
		}
		match self.sql.exec("SELECT seq, hash FROM lines ORDER BY seq DESC LIMIT 1", None)?.to_array::<H>()?.into_iter().next() {
			Some(h) => Ok((h.seq, h.hash)),
			None => Ok((self.meta("base_seq")?.and_then(|s| s.parse().ok()).unwrap_or(0), self.meta("base_hash")?.unwrap_or_else(|| ZERO.into()))),
		}
	}

	fn append(&self, lines: Vec<LineIn>) -> Result<Response> {
		let mut last: i64 = self.meta("last_source")?.and_then(|s| s.parse().ok()).unwrap_or(0);
		let (mut seq, mut prev) = self.head()?;
		let mut added = 0;
		for l in lines {
			if l.id <= last {
				continue; // a retried ship: already chained
			}
			seq += 1;
			let hash = link(&prev, &canonical(seq, &l.at, &l.actor, &l.action, &l.target, l.details.as_deref(), l.details_sealed.as_deref()));
			self.sql.exec(
				"INSERT INTO lines (seq, source_id, at, actor, action, target, details, details_sealed, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
				Some(vec![seq.into(), l.id.into(), l.at.into(), l.actor.into(), l.action.into(), l.target.into(), crate::files_store::bind(l.details), crate::files_store::bind(l.details_sealed), hash.clone().into()]),
			)?;
			prev = hash;
			last = l.id;
			added += 1;
		}
		self.set_meta("last_source", &last.to_string())?;
		Response::from_json(&serde_json::json!({ "acked": last, "added": added, "seq": seq }))
	}

	fn list(&self, limit: i64) -> Result<Response> {
		let rows: Vec<LineRow> = self.sql.exec("SELECT seq, at, actor, action, target, details, details_sealed, hash FROM lines ORDER BY seq DESC LIMIT ?1", Some(vec![limit.into()]))?.to_array()?;
		Response::from_json(
			&rows
				.into_iter()
				.map(|a| serde_json::json!({ "id": a.seq, "at": a.at, "actor": a.actor, "action": a.action, "target": a.target, "details": a.details, "detailsSealed": a.details_sealed, "hash": a.hash }))
				.collect::<Vec<_>>(),
		)
	}

	/// Recompute the chain from the base. `at`: sequence numbers whose
	/// recomputed hash the caller wants (each checkpoint it found).
	fn verify(&self, at: &[i64]) -> Result<Response> {
		let base_seq: i64 = self.meta("base_seq")?.and_then(|s| s.parse().ok()).unwrap_or(0);
		let mut prev = self.meta("base_hash")?.unwrap_or_else(|| ZERO.into());
		let mut expect = base_seq;
		let mut broken: Option<serde_json::Value> = None;
		let mut hashes = serde_json::Map::new();
		if at.contains(&base_seq) {
			hashes.insert(base_seq.to_string(), serde_json::json!(prev));
		}
		let rows: Vec<LineRow> = self.sql.exec("SELECT seq, at, actor, action, target, details, details_sealed, hash FROM lines ORDER BY seq", None)?.to_array()?;
		let count = rows.len();
		for r in rows {
			expect += 1;
			if r.seq != expect {
				broken.get_or_insert(serde_json::json!({ "seq": expect, "why": format!("line {expect} is missing (the next is {})", r.seq) }));
				expect = r.seq;
			}
			let h = link(&prev, &canonical(r.seq, &r.at, &r.actor, &r.action, &r.target, r.details.as_deref(), r.details_sealed.as_deref()));
			if h != r.hash {
				broken.get_or_insert(serde_json::json!({ "seq": r.seq, "why": format!("line {} does not hash to its stored link — edited after it was written", r.seq) }));
			}
			if at.contains(&r.seq) {
				hashes.insert(r.seq.to_string(), serde_json::json!(h));
			}
			// Chain on the RECOMPUTED hash: an edited line breaks every link after it.
			prev = h;
		}
		Response::from_json(&serde_json::json!({ "ok": broken.is_none(), "broken": broken, "lines": count, "baseSeq": base_seq, "lastSeq": expect, "lastHash": prev, "at": hashes }))
	}

	/// Today's checkpoint: the head (seq, hash), recorded and returned for
	/// the Worker to write to the bucket.
	fn checkpoint(&self, date: &str) -> Result<Response> {
		if date.len() != 10 {
			return json_error(400, "date: YYYY-MM-DD");
		}
		let (seq, hash) = self.head()?;
		self.sql.exec("INSERT INTO checkpoints (date, seq, hash) VALUES (?1, ?2, ?3) ON CONFLICT (date) DO UPDATE SET seq = ?2, hash = ?3", Some(vec![date.into(), seq.into(), hash.clone().into()]))?;
		Response::from_json(&serde_json::json!({ "date": date, "seq": seq, "hash": hash }))
	}

	/// Drop lines past the retention, moving the base to the last one dropped.
	fn prune(&self) -> Result<Response> {
		#[derive(serde::Deserialize)]
		struct H {
			seq: i64,
			hash: String,
		}
		let cut = self
			.sql
			.exec(&format!("SELECT seq, hash FROM lines WHERE at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-{RETENTION_DAYS} days') ORDER BY seq DESC LIMIT 1"), None)?
			.to_array::<H>()?
			.into_iter()
			.next();
		let Some(cut) = cut else { return Response::from_json(&serde_json::json!({ "pruned": 0 })) };
		let n = self.sql.exec("DELETE FROM lines WHERE seq <= ?1", Some(vec![cut.seq.into()]))?.rows_written();
		self.set_meta("base_seq", &cut.seq.to_string())?;
		self.set_meta("base_hash", &cut.hash)?;
		Response::from_json(&serde_json::json!({ "pruned": n, "baseSeq": cut.seq }))
	}
}

#[derive(serde::Deserialize)]
struct AppendBody {
	lines: Vec<LineIn>,
}

/// The stub of an area's audit DO (`audit:<area>`; `registry` for the registry).
pub(crate) fn stub(env: &Env, area: &str) -> Result<Stub> {
	env.durable_object("AUDIT")?.id_from_name(&format!("audit:{area}"))?.get_stub()
}

/// Ship lines to an area's audit DO; the highest outbox id it accepted.
pub(crate) async fn ship(env: &Env, area: &str, lines: &[LineIn]) -> Result<i64> {
	let headers = Headers::new();
	headers.set("Content-Type", "application/json")?;
	let req = Request::new_with_init("https://do.internal/append", &RequestInit { method: Method::Post, headers, body: Some(serde_json::json!({ "lines": lines }).to_string().into()), ..Default::default() })?;
	let mut resp = stub(env, area)?.fetch_with_request(req).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("audit ship {area}: HTTP {}", resp.status_code())));
	}
	let v: serde_json::Value = resp.json().await?;
	Ok(v.get("acked").and_then(|a| a.as_i64()).unwrap_or(0))
}

/// The newest `limit` chained lines of an area (newest first).
pub(crate) async fn lines(env: &Env, area: &str, limit: i64) -> Result<Vec<serde_json::Value>> {
	let req = Request::new_with_init(&format!("https://do.internal/lines?limit={limit}"), &RequestInit { method: Method::Get, ..Default::default() })?;
	let mut resp = stub(env, area)?.fetch_with_request(req).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("audit lines {area}: HTTP {}", resp.status_code())));
	}
	resp.json().await
}

// ── Checkpoints and verification (the Worker's side) ─────────────────

/// Where an area's checkpoints live in the bucket.
pub(crate) fn checkpoint_prefix(area: &str) -> String {
	match crate::area::case_of(area) {
		Some(c) => format!("audit-checkpoints/cases/{c}/"),
		None if area == "registry" => "audit-checkpoints/registry/".to_string(),
		None => format!("audit-checkpoints/members/{area}/"),
	}
}

/// Today in UTC, `YYYY-MM-DD` (civil-from-days, Howard Hinnant's algorithm).
pub(crate) fn today() -> String {
	let days = (Date::now().as_millis() / 86_400_000) as i64;
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
	format!("{y:04}-{m:02}-{d:02}")
}

async fn call(env: &Env, area: &str, method: Method, path: &str) -> Result<serde_json::Value> {
	let req = Request::new_with_init(&format!("https://do.internal/{path}"), &RequestInit { method, ..Default::default() })?;
	let mut resp = stub(env, area)?.fetch_with_request(req).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("audit {path} {area}: HTTP {}", resp.status_code())));
	}
	resp.json().await
}

/// Today's checkpoint of an area, written OUTSIDE its database: the bucket.
pub(crate) async fn checkpoint_area(env: &Env, area: &str) -> Result<()> {
	let date = today();
	let cp = call(env, area, Method::Post, &format!("checkpoint?date={date}")).await?;
	let body = serde_json::json!({ "area": area, "date": date, "seq": cp["seq"], "hash": cp["hash"] });
	crate::s3::put(env, &format!("{}{date}.json", checkpoint_prefix(area)), body.to_string().into_bytes()).await
}

/// The 7-year retention (D7): drop older lines, moving the chain's base.
pub(crate) async fn prune_area(env: &Env, area: &str) -> Result<()> {
	call(env, area, Method::Post, "prune").await.map(|_| ())
}

/// Verify an area's trail: the chain recomputed by its DO, and every
/// checkpoint THE BUCKET holds compared with the recomputed chain at that
/// sequence number. A checkpoint older than the chain's base was pruned
/// with the retention (reported, not a failure).
pub(crate) async fn verify_area(env: &Env, area: &str) -> Result<serde_json::Value> {
	let keys = crate::s3::list(env, &checkpoint_prefix(area), 4000).await?;
	let mut checkpoints: Vec<(String, i64, String)> = Vec::new(); // (date, seq, hash)
	for key in keys {
		let mut resp = crate::s3::stream_uncached(env, &key).await?;
		if resp.status_code() != 200 {
			continue;
		}
		let v: serde_json::Value = serde_json::from_str(&resp.text().await?).unwrap_or_default();
		if let (Some(date), Some(seq), Some(hash)) = (v["date"].as_str(), v["seq"].as_i64(), v["hash"].as_str()) {
			if v["area"].as_str() == Some(area) {
				checkpoints.push((date.to_string(), seq, hash.to_string()));
			}
		}
	}
	let at = checkpoints.iter().map(|c| c.1.to_string()).collect::<Vec<_>>().join(",");
	let chain = call(env, area, Method::Get, &format!("verify?at={at}")).await?;
	let base = chain["baseSeq"].as_i64().unwrap_or(0);
	let last = chain["lastSeq"].as_i64().unwrap_or(0);
	let mut ok = chain["ok"].as_bool() == Some(true);
	let mut report = Vec::new();
	checkpoints.sort();
	for (date, seq, hash) in &checkpoints {
		let (status, why) = if *seq < base {
			("pruned", "older than the retention; the chain's base moved past it".to_string())
		} else if *seq > last {
			("missing", format!("the bucket's checkpoint names line {seq}, but the chain ends at {last} — lines were removed from the end"))
		} else if chain["at"][seq.to_string()].as_str() == Some(hash.as_str()) {
			("ok", String::new())
		} else {
			("mismatch", format!("the chain at line {seq} is not what the bucket recorded on {date} — the trail was rewritten"))
		};
		if status == "missing" || status == "mismatch" {
			ok = false;
		}
		report.push(serde_json::json!({ "date": date, "seq": seq, "status": status, "why": why }));
	}
	Ok(serde_json::json!({ "ok": ok, "area": area, "chain": chain, "checkpoints": report }))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_chain_catches_an_edit_and_spells_one_way() {
		let l1 = canonical(1, "2026-10-14T00:00:00Z", "ana", "file.put", "f1", None, None);
		let l2 = canonical(2, "2026-10-14T00:01:00Z", "ana", "file.trash", "f1", Some("x"), None);
		let h1 = link(ZERO, &l1);
		let h2 = link(&h1, &l2);
		// Edit line 1's actor: its hash and every later link change.
		let h1x = link(ZERO, &canonical(1, "2026-10-14T00:00:00Z", "bo", "file.put", "f1", None, None));
		assert_ne!(h1, h1x);
		assert_ne!(h2, link(&h1x, &l2));
		// Length prefixes: moving a character between fields is another line.
		assert_ne!(canonical(1, "a", "bc", "d", "e", None, None), canonical(1, "ab", "c", "d", "e", None, None));
		// A missing details and an empty one are the same spelling (by design:
		// the column is optional; the hash does not distinguish NULL from "").
		assert_eq!(canonical(1, "a", "b", "c", "d", None, None), canonical(1, "a", "b", "c", "d", Some(""), None));
	}
}
