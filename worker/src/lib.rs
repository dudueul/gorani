// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The Gorani Worker: the thin, memory-safe hinge between three trust zones.
//!
//! ```text
//!  [ Browser SPA ]──sealed bytes──▶[ this Worker ]──ciphertext──▶[ MinIO / S3 ]
//!        ▲                                │
//!        └──────── wrapped keys ◀── GoraniMemberDO (SQLite) ◀──┘
//! ```
//!
//! Everything this program receives from a client is already sealed in the
//! client (GV02 content; keys and names sealed into their places, GV04). It verifies who the
//! caller is, checks shapes, stores and relays — and never holds a key that
//! can open content. This scaffold wires the entrypoint; routes arrive per
//! commit:
//!
//!   ⑥ GoraniMemberDO (member metadata, SQLite)   ⑦ files routes
//!   ⑧ vault/member/device routes                 ⑨+ the SPA's API
//!
//! Why Rust here? A bug that reads or corrupts bytes is a security bug in a
//! file vault. Rust removes the whole class (memory unsafety) and shares the
//! sealed-format code (`crates/formats`) with the native clients byte for
//! byte. Why not Rust in the *browser*? Because WebCrypto's non-extractable
//! keys — the property that stops a page script from reading the vault key —
//! only exists in the browser's crypto API; wasm crypto would hold raw key
//! bytes in linear memory. Each runtime gets the language its trust zone
//! needs; docs/COURSE.md → Lesson 2.

use worker::*;

mod area;
mod audit;
mod auth;
mod backup;
mod cache;
mod cron;
mod custody;
mod desktop;
mod devices;
mod drm;
mod drm_store;
mod family;
mod files_store;
mod inbox;
mod member;
mod malware;
mod requests;
mod routes;
mod s3;
mod schema;
mod stamps;
mod tsa;

/// The nightly maintenance pass (wrangler.jsonc › `triggers` › `crons`):
/// per member — retention housekeeping on the deployment defaults and
/// backup-manifest pruning. The fan-out lives in cron.rs; the DOs do the
/// work, the audit trail records it under the system actor `cron`.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
	if let Err(e) = cron::run(env).await {
		// A failed pass is loud in observability (an error, not a log line)
		// and retried by the next trigger; the deletion outbox keeps what it
		// could not finish (O10). The family's data never depends on it.
		console_error!("gorani cron failed: {e}");
	}
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
	// Liveness for the deploy and for tests. This route is PUBLIC (the Access
	// bypass in docs/PRODUCTION.md), so it says only whether storage is
	// configured — one bit. It used to name the bucket and echo the config
	// error ("missing S3_SECRET_KEY…"): reconnaissance for free, and the
	// kind of detail that belongs in observability logs, not on the open
	// internet (security review, commit 23).
	match (req.method(), req.path().as_str()) {
		(Method::Get, "/api/healthz") => {
			let configured = env.bucket("R2BUCKET").is_ok() || s3::config(&env).is_ok();
			harden(Response::from_json(&serde_json::json!({ "ok": true, "service": "gorani", "storage": { "configured": configured } }))?)
		}
		// /api/v1 is authenticated+routed in routes.rs; /s/* is the PUBLIC
		// share surface (the link's fragment secret is the credential).
		(_, p) if p.starts_with("/api/v1/") || p.starts_with("/s/") => {
			let req_is_api = p.starts_with("/api/v1/");
			match routes::route(req, env).await {
				Ok(resp) => harden(resp),
				// An unexpected fault (a storage outage, a malformed body the
				// route did not anticipate): logged in full for the operator,
				// answered generically to the caller — internal messages (object
				// keys, endpoints, SQL) are reconnaissance — and hardened like any
				// other response. Expected refusals never come this way: routes
				// answer those themselves with honest 4xx statuses.
				Err(e) => {
					let message = e.to_string();
					console_log!("gorani: unhandled error: {message}");
					// A storage refusal is not "internal": the caller is told
					// the status and the storage's own code (commit 39s) — never
					// the object key or the endpoint, which stay in the log —
					// and where a lead finds the rest. Only to signed-in callers:
					// /api/v1 is behind Access, the public share pages are not.
					match crate::s3::public_reason(&message).filter(|_| req_is_api) {
						Some(reason) => harden(Response::from_json(&serde_json::json!({ "error": format!("the storage refused this ({reason}) — anyone can run Team › Status › Test connection") }))?.with_status(502)),
						None => harden(Response::from_json(&serde_json::json!({ "error": "internal error" }))?.with_status(500)),
					}
				}
			}
		}
		// The asset layer handles static files and the SPA fallback; the
		// Worker only ever sees what `run_worker_first` names.
		_ => Response::error("Not Found", 404),
	}
}

/// The CSP for everything the Worker itself answers: JSON, ciphertext
/// streams, error pages. None of it is meant to render, so the policy allows
/// nothing at all — if a browser is ever tricked into displaying an API
/// response as a document, it can run no script, load nothing, and cannot be
/// framed. (The share page overrides this with its own, routes.rs.)
const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// Security headers on every Worker response (docs/SECURITY-REVIEW.md › O1).
///
/// Static assets get theirs from `web/public/_headers` (the platform serves
/// them without running this code); everything routed here passes through
/// this one function, so no route can forget a header. A header a route set
/// on purpose (the share page's own CSP, a download's Cache-Control) wins:
/// only absent headers are filled in.
///
/// The headers are COPIED and re-attached: responses relayed from a Durable
/// Object or the cache carry immutable header lists, and setting on those
/// throws (worker::Headers::clone makes a fresh, mutable list).
fn harden(resp: Response) -> Result<Response> {
	let headers = resp.headers().clone();
	let fill = |name: &str, value: &str| -> Result<()> {
		if headers.get(name)?.is_none() {
			headers.set(name, value)?;
		}
		Ok(())
	};
	fill("Content-Security-Policy", API_CSP)?;
	fill("X-Content-Type-Options", "nosniff")?;
	fill("Referrer-Policy", "no-referrer")?;
	fill("Cross-Origin-Resource-Policy", "same-origin")?;
	fill("Strict-Transport-Security", "max-age=63072000; includeSubDomains")?;
	// API answers are per-user and often secret-adjacent (wrapped keys ride
	// in x-gorani-ck): never stored by a browser or a shared proxy cache.
	// (The Worker's OWN edge cache, cache.rs, works below this layer and is
	// unaffected — it stores ciphertext under its own keys.)
	fill("Cache-Control", "no-store")?;
	Ok(resp.with_headers(headers))
}
