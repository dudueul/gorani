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
//! client (GV02 content, GV03-wrapped keys, sealed names). It verifies who the
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

mod auth;
mod backup;
mod cache;
mod cron;
mod devices;
mod family;
mod files_store;
mod member;
mod routes;
mod s3;

/// The nightly maintenance pass (wrangler.jsonc › `triggers` › `crons`):
/// per member — retention housekeeping on the deployment defaults and
/// backup-manifest pruning. The fan-out lives in cron.rs; the DOs do the
/// work, the audit trail records it under the system actor `cron`.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
	if let Err(e) = cron::run(env).await {
		// A failed pass is loud in observability and retried by the next
		// trigger; the family's data never depends on this having run.
		console_log!("gorani cron failed: {e}");
	}
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
	// Liveness for the deploy and for tests. The S3 line says whether the
	// storage backend is *configured* — never what is in it, and never a key.
	match (req.method(), req.path().as_str()) {
		(Method::Get, "/api/healthz") => {
			let s3 = s3::config(&env);
			Response::from_json(&serde_json::json!({
				"ok": true,
				"service": "gorani",
				"s3": match &s3 {
					Ok(cfg) => serde_json::json!({ "configured": true, "bucket": cfg.bucket }),
					Err(e) => serde_json::json!({ "configured": false, "error": e.to_string() }),
				},
			}))
		}
		// /api/v1 is authenticated+routed in routes.rs; /s/* is the PUBLIC
		// share surface (the link's fragment secret is the credential).
		(_, p) if p.starts_with("/api/v1/") || p.starts_with("/s/") => routes::route(req, env).await,
		// The asset layer handles static files and the SPA fallback; the
		// Worker only ever sees what `run_worker_first` names.
		_ => Response::error("Not Found", 404),
	}
}