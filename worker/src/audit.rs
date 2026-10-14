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
	/// (commit 29i) The alarm that drains the SIEM queue, and the vars it reads.
	state: State,
	env: Env,
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

#[derive(serde::Deserialize, Clone)]
pub(crate) struct LineRow {
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
	fn new(state: State, env: Env) -> Self {
		let sql = state.storage().sql();
		let schema = crate::schema::migrate(&sql, MIGRATIONS);
		Self { sql, schema, state, env }
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

	/// The SIEM queue drains here (commit 29i), on its own clock: no
	/// request ever waits on a SIEM. A failed delivery re-arms with backoff
	/// (1 s, doubling, at most an hour); the lines stay — the chained trail
	/// IS the queue — and the cursor moves only on the collector's 2xx.
	async fn alarm(&self) -> Result<Response> {
		match self.siem_drain().await {
			Ok(d) => {
				self.set_meta("siem_backoff", "0")?;
				if d.pending > 0 {
					self.state.storage().set_alarm(100i64).await?;
				}
			}
			Err(e) => {
				let prev: i64 = self.meta("siem_backoff")?.and_then(|v| v.parse().ok()).unwrap_or(0);
				let next = (prev * 2).clamp(1_000, 3_600_000);
				self.set_meta("siem_backoff", &next.to_string())?;
				console_error!("gorani: SIEM delivery for {} failed, retrying in {next} ms: {e}", self.meta("area")?.unwrap_or_default());
				self.state.storage().set_alarm(next).await?;
			}
		}
		Response::ok("")
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
				// Which area this trail is (the SIEM's events name it).
				if let Some(area) = body.area.as_deref().filter(|a| !a.is_empty()) {
					if self.meta("area")?.as_deref() != Some(area) {
						self.set_meta("area", area)?;
					}
				}
				let resp = self.append(body.lines)?;
				self.arm_siem().await?;
				Ok(resp)
			}
			// The nightly pass's drain (cron.rs): now, and say what is left.
			// It names the area too — a trail whose lines all predate 29i
			// never had an append tell it.
			("POST", "siem") => {
				if let Some(area) = q.get("area").filter(|a| !a.is_empty()) {
					if self.meta("area")?.as_deref() != Some(area.as_str()) {
						self.set_meta("area", area)?;
					}
				}
				match self.siem_drain().await {
					Ok(d) => Response::from_json(&serde_json::json!({ "configured": siem_config(&self.env).is_some(), "delivered": d.delivered, "pending": d.pending })),
					Err(e) => json_error(502, &format!("SIEM delivery failed: {e}")),
				}
			}
			("GET", "lines") => {
				let limit = q.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(200).clamp(1, 1000);
				// `after=<seq>`: the whole trail, oldest first, a page at a time
				// (commit 29h: an export carries all of it). Without it: the
				// newest `limit`, newest first (the audit view).
				match q.get("after").and_then(|v| v.parse::<i64>().ok()) {
					Some(after) => self.page(after, limit),
					None => self.list(limit),
				}
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

	fn page(&self, after: i64, limit: i64) -> Result<Response> {
		let rows: Vec<LineRow> = self.sql.exec("SELECT seq, at, actor, action, target, details, details_sealed, hash FROM lines WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2", Some(vec![after.into(), limit.into()]))?.to_array()?;
		let next = (rows.len() as i64 == limit).then(|| rows.last().map(|r| r.seq)).flatten();
		// The chain's base: what the first line links to (ZERO, or the hash
		// of the last line a retention prune removed — stage 1).
		let base = serde_json::json!({ "seq": self.meta("base_seq")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0), "hash": self.meta("base_hash")?.unwrap_or_else(|| ZERO.into()) });
		Response::from_json(&serde_json::json!({
			"base": base,
			"lines": rows.into_iter().map(|a| serde_json::json!({ "id": a.seq, "at": a.at, "actor": a.actor, "action": a.action, "target": a.target, "details": a.details, "detailsSealed": a.details_sealed, "hash": a.hash })).collect::<Vec<_>>(),
			"next": next,
		}))
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
	#[serde(default)]
	area: Option<String>,
	lines: Vec<LineIn>,
}

// ── The SIEM feed (commit 29i, docs/CUSTODY.md › Stage 7, D5.4) ──────────
//
// The chained trail is the queue: a cursor (`meta › siem_cursor`) names the
// last line the collector acknowledged; delivery is at-least-once, and every
// event carries the line's sequence number and hash, so a SIEM can drop a
// duplicate and check continuity. Sealed details never leave — they are
// sealed; an event says only that the line had some.

/// Where and how to ship: SIEM_URL (unset: no feed), SIEM_FORMAT
/// (`ndjson` | `splunk-hec`), SIEM_TOKEN (a secret).
pub(crate) struct SiemConfig {
	url: String,
	format: String,
	token: Option<String>,
}

pub(crate) fn siem_config(env: &Env) -> Option<SiemConfig> {
	let var = |k: &str| env.var(k).ok().map(|v| v.to_string()).filter(|v| !v.is_empty());
	let url = var("SIEM_URL")?;
	let format = var("SIEM_FORMAT").unwrap_or_else(|| "ndjson".into());
	let token = env.secret("SIEM_TOKEN").ok().map(|v| v.to_string()).or_else(|| var("SIEM_TOKEN")).filter(|v| !v.is_empty());
	Some(SiemConfig { url, format, token })
}

/// One audit line as a SIEM event — readable fields only.
pub(crate) fn siem_event(area: &str, l: &LineRow) -> serde_json::Value {
	serde_json::json!({
		"@timestamp": l.at,
		"gorani": { "area": area, "seq": l.seq, "hash": l.hash },
		"actor": l.actor, "action": l.action, "target": l.target, "details": l.details,
		"sealed": l.details_sealed.is_some(),
	})
}

/// A batch, as the collector's format wants it: one event per line.
pub(crate) fn siem_body(format: &str, area: &str, rows: &[LineRow]) -> String {
	let mut out = String::new();
	for l in rows {
		let e = siem_event(area, l);
		let line = match format {
			// Splunk's HTTP Event Collector: an envelope per event.
			"splunk-hec" => serde_json::json!({ "time": epoch_seconds(&l.at), "host": "gorani", "source": format!("gorani:{area}"), "sourcetype": "gorani:audit", "event": e }),
			_ => e,
		};
		out.push_str(&line.to_string());
		out.push('\n');
	}
	out
}

/// `2026-10-14T16:50:58.973Z` → seconds since the epoch (Splunk's `time`).
pub(crate) fn epoch_seconds(at: &str) -> Option<f64> {
	let (date, time) = at.trim_end_matches('Z').split_once('T')?;
	let mut d = date.split('-').map(|p| p.parse::<i64>());
	let (y, m, dd) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
	let mut t = time.split(':');
	let (h, mi) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
	let s: f64 = t.next()?.parse().ok()?;
	// Days from the civil date (Howard Hinnant's algorithm).
	let y2 = if m <= 2 { y - 1 } else { y };
	let era = y2.div_euclid(400);
	let yoe = y2 - era * 400;
	let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + dd - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	let days = era * 146_097 + doe - 719_468;
	Some((days * 86_400 + h * 3_600 + mi * 60) as f64 + s)
}

pub(crate) struct Drained {
	delivered: i64,
	pending: i64,
}

impl GoraniAuditDO {
	/// Lines arrived: wake the drain soon, unless it is already set (a
	/// failing collector's backoff is never shortened by new lines).
	async fn arm_siem(&self) -> Result<()> {
		if siem_config(&self.env).is_some() && self.state.storage().get_alarm().await?.is_none() {
			self.state.storage().set_alarm(1_000i64).await?;
		}
		Ok(())
	}

	/// Deliver what the collector has not acknowledged, oldest first, up to
	/// 20 batches of 500 per run (the alarm re-arms for the rest).
	async fn siem_drain(&self) -> Result<Drained> {
		let Some(cfg) = siem_config(&self.env) else { return Ok(Drained { delivered: 0, pending: 0 }) };
		let area = self.meta("area")?.unwrap_or_else(|| "unknown".into());
		let base: i64 = self.meta("base_seq")?.and_then(|s| s.parse().ok()).unwrap_or(0);
		let mut cursor: i64 = self.meta("siem_cursor")?.and_then(|s| s.parse().ok()).unwrap_or(0).max(base);
		let mut delivered = 0;
		for _ in 0..20 {
			let rows: Vec<LineRow> = self.sql.exec("SELECT seq, at, actor, action, target, details, details_sealed, hash FROM lines WHERE seq > ?1 ORDER BY seq ASC LIMIT 500", Some(vec![cursor.into()]))?.to_array()?;
			let Some(last) = rows.last().map(|r| r.seq) else { break };
			let headers = Headers::new();
			let (content_type, auth) = match cfg.format.as_str() {
				"splunk-hec" => ("application/json", cfg.token.as_ref().map(|t| format!("Splunk {t}"))),
				_ => ("application/x-ndjson", cfg.token.as_ref().map(|t| format!("Bearer {t}"))),
			};
			headers.set("Content-Type", content_type)?;
			if let Some(a) = auth {
				headers.set("Authorization", &a)?;
			}
			let req = Request::new_with_init(&cfg.url, &RequestInit { method: Method::Post, headers, body: Some(siem_body(&cfg.format, &area, &rows).into()), ..Default::default() })?;
			let status = Fetch::Request(req).send().await?.status_code();
			if !(200..300).contains(&status) {
				return Err(Error::RustError(format!("the collector answered HTTP {status}")));
			}
			// The alarm and the nightly pass can both be mid-delivery (a DO
			// takes other events while it awaits a fetch): the cursor only
			// ever moves forward. A line both sent arrives twice — the event's
			// seq is how the SIEM drops it — never zero times.
			let stored: i64 = self.meta("siem_cursor")?.and_then(|s| s.parse().ok()).unwrap_or(0);
			cursor = last.max(stored);
			self.set_meta("siem_cursor", &cursor.to_string())?;
			delivered += rows.len() as i64;
		}
		#[derive(serde::Deserialize)]
		struct N {
			n: i64,
		}
		let pending = self.sql.exec("SELECT COUNT(*) AS n FROM lines WHERE seq > ?1", Some(vec![cursor.into()]))?.one::<N>()?.n;
		Ok(Drained { delivered, pending })
	}
}

/// The stub of an area's audit DO (`audit:<area>`; `registry` for the registry).
pub(crate) fn stub(env: &Env, area: &str) -> Result<Stub> {
	env.durable_object("AUDIT")?.id_from_name(&format!("audit:{area}"))?.get_stub()
}

/// Ship lines to an area's audit DO; the highest outbox id it accepted.
pub(crate) async fn ship(env: &Env, area: &str, lines: &[LineIn]) -> Result<i64> {
	let headers = Headers::new();
	headers.set("Content-Type", "application/json")?;
	let req = Request::new_with_init("https://do.internal/append", &RequestInit { method: Method::Post, headers, body: Some(serde_json::json!({ "area": area, "lines": lines }).to_string().into()), ..Default::default() })?;
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

/// A page of an area's chained trail, oldest first, after `after` (commit 29h).
pub(crate) async fn page(env: &Env, area: &str, after: i64, limit: i64) -> Result<serde_json::Value> {
	let req = Request::new_with_init(&format!("https://do.internal/lines?after={after}&limit={limit}"), &RequestInit { method: Method::Get, ..Default::default() })?;
	let mut resp = stub(env, area)?.fetch_with_request(req).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("audit page {area}: HTTP {}", resp.status_code())));
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

/// Today in UTC, `YYYY-MM-DD`.
pub(crate) fn today() -> String {
	civil((Date::now().as_millis() / 86_400_000) as i64)
}

/// A day number (days since 1970-01-01) as `YYYY-MM-DD` (civil-from-days,
/// Howard Hinnant's algorithm).
fn civil(days: i64) -> String {
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
	let key = format!("{}{date}.json", checkpoint_prefix(area));
	let bytes = body.to_string().into_bytes();
	crate::s3::put(env, &key, bytes.clone()).await?;
	// Write-once, when the bucket can (D6, commit 29c): a checkpoint is what
	// makes a rewritten trail detectable — only if it cannot be rewritten too.
	let lock = env.var("OBJECT_LOCK").map(|v| v.to_string()).unwrap_or_default() == "on";
	let until = format!("{}T00:00:00Z", civil((Date::now().as_millis() / 86_400_000) as i64 + RETENTION_DAYS));
	if lock {
		crate::s3::put_retention(env, &key, &until).await?;
	}
	// And a third party's word for WHEN (commit 29j, tsa.rs): an RFC 3161
	// token over SHA-256 of these exact bytes, beside them as `<date>.tsr`.
	// The checkpoint names the chain's head, so the token dates every line
	// up to it — a trail cannot be rewritten and re-checkpointed in the past.
	// A TSA that fails fails the pass (reported); tomorrow's checkpoint and
	// its token cover these lines too, a day later.
	use sha2::Digest;
	let imprint: [u8; 32] = sha2::Sha256::digest(&bytes).into();
	if let Some(stamp) = crate::tsa::stamp(env, &imprint).await? {
		let tsr = format!("{}{date}.tsr", checkpoint_prefix(area));
		crate::s3::put(env, &tsr, stamp.token).await?;
		if lock {
			crate::s3::put_retention(env, &tsr, &until).await?;
		}
	}
	Ok(())
}

/// Drain an area's SIEM queue now (the nightly pass): an error while lines
/// stay undelivered — the pass fails loudly, as for a lock or a delete. (An
/// area is a member id, `case:<id>` or `registry`: nothing a query needs
/// escaped.)
pub(crate) async fn siem_drain(env: &Env, area: &str) -> Result<()> {
	if siem_config(env).is_none() {
		return Ok(());
	}
	let v = call(env, area, Method::Post, &format!("siem?area={area}")).await?;
	match v.get("pending").and_then(|p| p.as_i64()).unwrap_or(0) {
		0 => Ok(()),
		n => Err(Error::RustError(format!("{n} audit line(s) not yet delivered to the SIEM"))),
	}
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
	let tokens: std::collections::BTreeSet<&String> = keys.iter().filter(|k| k.ends_with(".tsr")).collect();
	// (date, seq, hash, the checkpoint's exact text, its timestamp token)
	let mut checkpoints: Vec<(String, i64, String, String, Option<String>)> = Vec::new();
	for key in keys.iter().filter(|k| k.ends_with(".json")) {
		let mut resp = crate::s3::stream_uncached(env, key).await?;
		if resp.status_code() != 200 {
			continue;
		}
		let text = resp.text().await?;
		let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
		if let (Some(date), Some(seq), Some(hash)) = (v["date"].as_str(), v["seq"].as_i64(), v["hash"].as_str()) {
			if v["area"].as_str() == Some(area) {
				// The token travels as the bucket holds it; the reader checks it
				// (web/src/vault/timestamp.ts) — the Worker vouches for nothing.
				let tsr = format!("{}.tsr", key.trim_end_matches(".json"));
				let token = if tokens.contains(&tsr) {
					let mut t = crate::s3::stream_uncached(env, &tsr).await?;
					if t.status_code() == 200 {
						use base64::Engine;
						Some(base64::engine::general_purpose::STANDARD.encode(t.bytes().await?))
					} else {
						None
					}
				} else {
					None
				};
				checkpoints.push((date.to_string(), seq, hash.to_string(), text, token));
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
	for (date, seq, hash, text, token) in &checkpoints {
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
		report.push(serde_json::json!({ "date": date, "seq": seq, "hash": hash, "status": status, "why": why, "body": text, "token": token }));
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

#[cfg(test)]
mod siem_tests {
	use super::*;

	fn row(seq: i64, at: &str, sealed: bool) -> LineRow {
		LineRow { seq, at: at.into(), actor: "bo@team.test".into(), action: "file.upload".into(), target: "f1".into(), details: Some("v1".into()), details_sealed: sealed.then(|| "GV04:secret".into()), hash: format!("{seq:064x}") }
	}

	#[test]
	fn epoch_seconds_matches_known_instants() {
		assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), Some(0.0));
		assert_eq!(epoch_seconds("2000-03-01T00:00:00Z"), Some(951_868_800.0), "the day after a leap day in a century leap year");
		assert_eq!(epoch_seconds("2026-10-14T16:50:58.5Z"), Some(1_791_996_658.5));
		assert_eq!(epoch_seconds("yesterday"), None);
	}

	#[test]
	fn ndjson_is_one_event_per_line_and_never_the_sealed_value() {
		let body = siem_body("ndjson", "case:ir-7", &[row(1, "2026-10-14T00:00:00Z", false), row(2, "2026-10-14T00:00:01Z", true)]);
		let lines: Vec<serde_json::Value> = body.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
		assert_eq!(lines.len(), 2);
		assert_eq!(lines[0]["gorani"]["seq"], 1);
		assert_eq!(lines[1]["gorani"]["area"], "case:ir-7");
		assert_eq!(lines[1]["sealed"], true);
		assert!(!body.contains("GV04:"), "a sealed value never leaves");
	}

	#[test]
	fn splunk_hec_wraps_each_event() {
		let body = siem_body("splunk-hec", "registry", &[row(7, "1970-01-01T00:01:00Z", false)]);
		let e: serde_json::Value = serde_json::from_str(body.trim_end()).unwrap();
		assert_eq!(e["time"], 60.0);
		assert_eq!(e["source"], "gorani:registry");
		assert_eq!(e["sourcetype"], "gorani:audit");
		assert_eq!(e["event"]["gorani"]["seq"], 7);
	}
}
