// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The HTTP surface. One function, a small match, and three rules that never
//! bend:
//!
//! 1. **Authenticate first** (auth.rs) — before reading a body, before
//!    touching a DO.
//! 2. **Member scope is resolved through the registry**: a member acts for
//!    their own area and nobody else's — a lead included (the family's
//!    "parent acts for any child" rule went with the master key, commit
//!    27c: leads manage who holds which key, not other people's content);
//!    an external has no own area; leads and auditors read every audit.
//!    A **case** (`/api/v1/cases/<id>/…`, commit 26) is scoped by the
//!    caller's grant instead — route_case checks read / write / manage once
//!    and rewrites the request to the member routes for the area
//!    `case:<id>` (area.rs).
//!    The DOs re-check nothing about identity, only data rules; the routing
//!    layer owns who-may-call-whose.
//! 3. **Every error is JSON** `{ "error": … }` with an honest status.
//!
//! The Worker and the DOs split the file work: the Worker parses multipart,
//! checks sealed shapes, drives S3 and streams reads; the DO owns rows and
//! the change feed. See files_store.rs for the DO side.

use worker::*;

use crate::auth::{self, Identity};
use crate::family::json_error;
use crate::s3;

/// Who is calling (the registry's answer for the Access email), plus what
/// the registry says about the member the URL addresses.
struct Actor {
	/// The caller's member id — the upload paths record it as the owner.
	id: String,
	role: String,
	/// The Access email, forwarded to the DOs as the audit actor.
	email: String,
	target_exists: bool,
	target_active: bool,
}

/// Resolve the caller's registry row, then enforce the member scope: a
/// member acts for their own area only. The ORDER of the checks is the
/// lesson (security review, commit 23):
///
/// 1. **Shape** — the id becomes a DO instance name (`member:<id>`) and the
///    first segment of every object key (`files/<id>/…`), so it is held to
///    the registry's own id rule before anything else happens.
/// 2. **Identity** — the caller must be an active member.
/// 3. **Existence** — the addressed member must be in the registry. Before
///    this check, a parent's request for `members/<anything>/…` created a
///    fresh, empty Durable Object on first touch (a DO exists the moment it
///    is addressed): unbounded state, holding data for a member nobody can
///    see in the registry.
/// 4. **Scope** — the caller acts only for themselves, and only while
///    active. (A departed member's area is reached by a recovery ceremony,
///    docs/CASES.md — not by a lead's say-so; until commit 27c a parent
///    could act for anyone.)
///
/// It returns the whole Actor so no caller resolves the caller twice — the
/// upload paths used to make a second registry round trip just to learn
/// the owner's id.
async fn member_ctx(env: &Env, identity: &Identity, id: &str) -> std::result::Result<Actor, Response> {
	scope_ctx(env, identity, id, false).await
}

/// The vault settings of a member: their root's public halves and sealed
/// unlock methods. An external member has no own AREA, but they do have a
/// ROOT — a case grant is sealed to it (commit 26) — so their own vault is
/// theirs to set up and unlock, though no files live beside it.
async fn vault_ctx(env: &Env, identity: &Identity, id: &str) -> std::result::Result<Actor, Response> {
	scope_ctx(env, identity, id, true).await
}

async fn scope_ctx(env: &Env, identity: &Identity, id: &str, external_own_vault: bool) -> std::result::Result<Actor, Response> {
	// A case area (`case:<id>`, commit 26): its scope is the caller's grant.
	// The router already checked what THIS request needs (read, write,
	// manage — route_case) and left the answer on the identity; asking the
	// registry again would only double the round trips. (Member ids cannot
	// hold ':', so no members/… URL reaches this branch without the router.)
	if let Some(case) = crate::area::case_of(id) {
		return match &identity.granted {
			Some(g) if g.area == id => Ok(Actor { id: g.member.clone(), role: g.role.clone(), email: identity.email.clone(), target_exists: true, target_active: true }),
			_ => case_scope(env, identity, case, Need::Read).await,
		};
	}
	if !auth::valid_member_id(id) {
		return Err(json_error_raw(400, "member id: 2–32 chars of a–z, 0–9, dashes"));
	}
	let actor = match actor_of(env, &identity.email, Some(id)).await {
		Ok(Some(a)) => a,
		// (No echo of the email: error bodies end up in logs and screenshots.)
		Ok(None) => return Err(json_error_raw(403, "not a team member")),
		Err(e) => return Err(json_error_raw(500, &e.to_string())),
	};
	if !actor.target_exists {
		return Err(json_error_raw(404, "no such member"));
	}
	// (docs/CASES.md › Roles. Until commit 27c a lead could act for any
	// member's area — the family parent's rule. Gone: a lead reads another
	// member's content only through what the keys allow — a case grant, or
	// a recovery ceremony that several leads approve. An external member
	// has no own area at all — their work lives in the cases they are
	// granted; they keep a vault root, which grants are sealed to.)
	let own = actor.id == id && actor.target_active;
	if own && (actor.role != "external" || external_own_vault) {
		Ok(actor)
	} else if actor.role == "external" {
		Err(json_error_raw(403, "external members have no own area — only the cases they are granted"))
	} else {
		Err(json_error_raw(403, "members act only for their own area — another member's content is reached through a case grant or a recovery ceremony"))
	}
}

/// What a case request needs from the caller's grant.
#[derive(Clone, Copy, PartialEq)]
enum Need {
	Read,
	Write,
	Manage,
}

/// The caller's standing on a case (docs/CASES.md › Roles): a live grant
/// gives read / write / manage; a lead or auditor WITHOUT a grant may read
/// the case's audit and read log only (they hold no key, so content would
/// be ciphertext anyway — the refusal keeps it that way).
async fn case_scope(env: &Env, identity: &Identity, case: &str, need: Need) -> std::result::Result<Actor, Response> {
	if !crate::area::valid_case_id(case) {
		return Err(json_error_raw(400, "case id: 2–40 of a–z, 0–9, dashes"));
	}
	let namespace = env.durable_object("FAMILY").map_err(|e| json_error_raw(500, &e.to_string()))?;
	let stub = namespace.id_from_name("family").and_then(|i| i.get_stub()).map_err(|e| json_error_raw(500, &e.to_string()))?;
	let headers = Headers::new();
	let _ = headers.set("x-gorani-actor", &identity.email);
	let _ = headers.set("x-gorani-case", case);
	let request = Request::new_with_init("https://do.internal/case-access", &RequestInit { method: Method::Get, headers, ..Default::default() }).map_err(|e| json_error_raw(500, &e.to_string()))?;
	let v: serde_json::Value = match stub.fetch_with_request(request).await {
		Ok(mut r) => r.json().await.map_err(|e| json_error_raw(500, &e.to_string()))?,
		Err(e) => return Err(json_error_raw(500, &e.to_string())),
	};
	if v.is_null() {
		return Err(json_error_raw(403, "you are not on this case"));
	}
	let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
	let (role, permission) = (s("role"), s("permission"));
	let allowed = match need {
		Need::Read => permission != "audit",
		Need::Write => (permission == "write" || permission == "manage") && role != "auditor",
		Need::Manage => permission == "manage",
	};
	if !allowed {
		return Err(json_error_raw(
			403,
			match (need, permission.as_str()) {
				(_, "audit") => "leads and auditors read a case's audit, not its content — content needs a grant",
				(Need::Manage, _) => "only a manager of this case may do this",
				_ => "your grant on this case is read-only",
			},
		));
	}
	if need != Need::Read && v.get("closed").and_then(|c| c.as_bool()) == Some(true) {
		return Err(json_error_raw(409, "the case is closed — read-only"));
	}
	Ok(Actor { id: s("id"), role, email: identity.email.clone(), target_exists: true, target_active: true })
}

/// A case's audit and read log: any standing on the case (a grant, or a
/// lead's or auditor's audit view).
async fn case_scope_audit(env: &Env, identity: &Identity, case: &str) -> std::result::Result<Actor, Response> {
	match case_scope(env, identity, case, Need::Read).await {
		Ok(a) => Ok(a),
		// The one refusal Read gives a lead/auditor without a grant — the
		// audit view is exactly what they are allowed.
		Err(_) => {
			let (id, role) = match actor_of(env, &identity.email, None).await {
				Ok(Some(a)) => (a.id, a.role),
				_ => return Err(json_error_raw(403, "you are not on this case")),
			};
			if role == "lead" || role == "auditor" {
				Ok(Actor { id, role, email: identity.email.clone(), target_exists: true, target_active: true })
			} else {
				Err(json_error_raw(403, "you are not on this case"))
			}
		}
	}
}

/// The audit and the read log of a member's area: the member, and every
/// lead and auditor (docs/CASES.md › Roles — auditors read every audit).
async fn audit_ctx(env: &Env, identity: &Identity, id: &str) -> std::result::Result<Actor, Response> {
	// A case's audit: anyone with standing on the case (a grant, or a lead
	// or auditor's audit view).
	if let Some(case) = crate::area::case_of(id) {
		return case_scope_audit(env, identity, case).await;
	}
	if !auth::valid_member_id(id) {
		return Err(json_error_raw(400, "member id: 2–32 chars of a–z, 0–9, dashes"));
	}
	let actor = match actor_of(env, &identity.email, Some(id)).await {
		Ok(Some(a)) => a,
		Ok(None) => return Err(json_error_raw(403, "not a team member")),
		Err(e) => return Err(json_error_raw(500, &e.to_string())),
	};
	if !actor.target_exists {
		return Err(json_error_raw(404, "no such member"));
	}
	if actor.role == "lead" || actor.role == "auditor" || (actor.id == id && actor.role != "external") {
		Ok(actor)
	} else {
		Err(json_error_raw(403, "a member's audit is theirs, their leads' and the auditors'"))
	}
}

/// One registry round trip: the caller's row and (with `target`) whether
/// the addressed member exists and is active.
async fn actor_of(env: &Env, email: &str, target: Option<&str>) -> Result<Option<Actor>> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	let headers = Headers::new();
	headers.set("x-gorani-actor", email)?;
	if let Some(t) = target {
		headers.set("x-gorani-target", t)?;
	}
	let request = Request::new_with_init("https://do.internal/actor", &RequestInit { method: Method::Get, headers, ..Default::default() })?;
	let mut resp = stub.fetch_with_request(request).await?;
	let v: serde_json::Value = resp.json().await?;
	if v.is_null() {
		return Ok(None);
	}
	let flag = |k: &str| v.get("target").and_then(|t| t.get(k)).and_then(|b| b.as_bool()).unwrap_or(false);
	Ok(Some(Actor {
		id: v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
		role: v.get("role").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
		email: email.to_string(),
		target_exists: flag("exists"),
		target_active: flag("active"),
	}))
}

/// Does the registry know this member? (The device routes skip the member
/// scope — the device token is their authority — but they still must not
/// conjure a DO for a member that does not exist.)
async fn member_exists(env: &Env, id: &str) -> Result<bool> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	let request = Request::new_with_init(&format!("https://do.internal/member-exists/{id}"), &RequestInit { method: Method::Get, ..Default::default() })?;
	let mut resp = stub.fetch_with_request(request).await?;
	let v: serde_json::Value = resp.json().await?;
	Ok(v.get("exists").and_then(|b| b.as_bool()).unwrap_or(false))
}

/// A JSON error as a plain Response (for the `Err(Response)` channel).
fn json_error_raw(status: u16, message: &str) -> Response {
	Response::from_json(&serde_json::json!({ "error": message })).unwrap().with_status(status)
}

pub async fn route(req: Request, env: Env) -> Result<Response> {
	let path = req.path();
	if path.starts_with("/s/") {
		let segments: Vec<&str> = path.trim_start_matches("/s/").split('/').collect();
		return public_share(req, env, &segments).await;
	}
	if !path.starts_with("/api/v1/") {
		return Response::error("Not Found", 404);
	}
	let identity = match auth::authenticate(&env, &req).await {
		Ok(id) => id,
		Err(e) => return json_error(401, &e.to_string()),
	};
	let method = req.method().to_string();
	let rest = &path["/api/v1/".len()..];
	let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
	// One allow-list for every path segment (security review, commit 23).
	// Segments become DO paths (`files/<id>`), S3 key parts
	// (`files/<member>/<file>/…`) and audit targets; route words, uuids,
	// base64url share ids, hex stamps and part numbers all fit
	// `[A-Za-z0-9_-]{1,64}`. Anything else — dots, percent-escapes, unicode —
	// is refused here, once, instead of being trusted by forty handlers.
	if let Some(bad) = segments.iter().find(|s| !auth::valid_object_id(s)) {
		return json_error(400, &format!("bad path segment ({} chars) — ids are [A-Za-z0-9_-]", bad.len()));
	}
	if let Some(("cases", rest)) = segments.split_first().map(|(a, r)| (*a, r)) {
		return route_case(req, env, identity, &method, rest).await;
	}
	dispatch(req, env, &identity, &method, &segments).await
}

/// `/api/v1/cases/…` (commit 26, docs/CASES.md › Areas and their keys).
///
/// Two kinds of route:
///
/// - **management** — open, list, grant, revoke, rotate, close: forwarded
///   to the registry (family.rs › Cases and grants), which owns the policy;
/// - **content** — `/cases/<id>/files/…`, `/audit`, `/reads`, backups: a
///   case is a store exactly like a member's own (area.rs), so these are
///   REWRITTEN to the member routes with the area `case:<id>` — after ONE
///   check of what this request needs from the caller's grant.
///
/// What a case does NOT have, refused here as "no such route": devices and
/// vault settings (a case has no root — its key lives in the grants), vault
/// destruction (a case is closed, not destroyed), and public links (a case
/// shares by grant; D11 decides later whether working cases get links).
async fn route_case(mut req: Request, env: Env, identity: Identity, method: &str, rest: &[&str]) -> Result<Response> {
	match (method, rest) {
		("GET", []) => return forward_family(&env, &identity.email, "GET", "cases", None).await,
		("POST", []) => return case_open(req, env, &identity).await,
		("PUT", [case, "grants", member]) => {
			let body = req.json::<serde_json::Value>().await?;
			return forward_family(&env, &identity.email, "PUT", format!("case-grants/{case}/{member}"), Some(body)).await;
		}
		("DELETE", [case, "grants", member]) => return forward_family(&env, &identity.email, "DELETE", format!("case-grants/{case}/{member}"), None).await,
		("PUT", [case, "key"]) => {
			let body = req.json::<serde_json::Value>().await?;
			return forward_family(&env, &identity.email, "PUT", format!("case-key/{case}"), Some(body)).await;
		}
		("POST", [case, "key", "done"]) => return forward_family(&env, &identity.email, "POST", format!("case-key-done/{case}"), Some(serde_json::json!({}))).await,
		("POST", [case, "close"]) => return forward_family(&env, &identity.email, "POST", format!("case-close/{case}"), Some(serde_json::json!({}))).await,
		_ => {}
	}
	let Some((case, content)) = rest.split_first() else { return json_error(404, "no such route") };
	if !crate::area::valid_case_id(case) {
		return json_error(400, "case id: 2–40 of a–z, 0–9, dashes");
	}
	let Some(need) = case_need(method, content) else {
		return json_error(404, "no such case route — a case has files, audit, reads, storage and backups (no devices, no vault settings, no public links)");
	};
	let area = format!("case:{case}");
	let identity = match need {
		// The audit and the read log: audit_ctx decides (any standing on the
		// case — a grant, or a lead's or auditor's audit view).
		None => identity,
		Some(need) => match case_scope(&env, &identity, case, need).await {
			Ok(actor) => Identity { granted: Some(auth::Granted { area: area.clone(), member: actor.id, role: actor.role }), ..identity },
			Err(resp) => return Ok(resp),
		},
	};
	let mut segments = vec!["members", area.as_str()];
	segments.extend_from_slice(content);
	dispatch(req, env, &identity, method, &segments).await
}

/// What a case content route needs from the caller's grant: `Some(None)`
/// for the audit views (audit_ctx decides), `None` for a route a case does
/// not have. The default is WRITE: a route nobody classified is treated as
/// the strongest ordinary need, never as a read.
fn case_need(method: &str, content: &[&str]) -> Option<Option<Need>> {
	Some(match (method, content) {
		(_, ["files", "shares", ..]) => return None,
		("GET", ["audit"] | ["reads"] | ["audit", "verify"]) => None,
		("GET", ["files", ..] | ["vault-stats"] | ["storage", "pending"] | ["backups", ..]) => Some(Need::Read),
		// The wrapped keys of named files: a read, although it is a POST.
		("POST", ["files", "keys"]) => Some(Need::Read),
		// Rotation's reseal walk, the backup key and runs, restores and
		// retention: the case's managers.
		("PUT", ["files", "reseal"] | ["backup-key"] | ["backup", "restore", "object"]) | ("GET", ["backup-key"]) | ("POST", ["backup", "run"] | ["backup", "restore"] | ["housekeeping"]) => Some(Need::Manage),
		(_, ["files", ..]) => Some(Need::Write),
		_ => return None,
	})
}

/// Open a case: the registry row and the creator's grant first (the policy
/// lives there), then the case's store — settings that say only "on" and
/// whose store it is. A case has no root and no unlock methods: its key is
/// in the grants, sealed to each grantee's own root.
async fn case_open(mut req: Request, env: Env, identity: &Identity) -> Result<Response> {
	let body = req.json::<serde_json::Value>().await?;
	let Some(id) = body.get("id").and_then(|v| v.as_str()).filter(|i| crate::area::valid_case_id(i)).map(str::to_string) else {
		return json_error(400, "case id: 2–40 of a–z, 0–9, dashes");
	};
	let mut created = forward_family(&env, &identity.email, "POST", "cases", Some(body)).await?;
	if created.status_code() != 200 {
		return Ok(created);
	}
	let answer: serde_json::Value = created.json().await?;
	// The kind travels into the case's own store (commit 29b): an evidence
	// store refuses deletion and keeps every version without asking anyone.
	let kind = answer.get("kind").and_then(|k| k.as_str()).unwrap_or("working");
	let settings = serde_json::json!({ "settings": { "enabled": true, "case": id, "kind": kind } });
	let stored = forward_member(&env, &format!("case:{id}"), "PUT", "vault", Some(settings), identity.email.clone()).await?;
	if stored.status_code() >= 300 {
		return Ok(stored);
	}
	Response::from_json(&answer)
}

/// The member routes — a member's own area, or (rewritten by route_case) a
/// case's. `segments` are already held to the id allow-list.
async fn dispatch(mut req: Request, env: Env, identity: &Identity, method: &str, segments: &[&str]) -> Result<Response> {
	match (method, segments) {
		// ── The family registry (GoraniFamilyDO) ────────────────────────
		("GET", ["family"]) => forward_family(&env, &identity.email, "GET", "state", None).await,
		("POST", ["family", "members"]) => {
			// The bootstrap proof (O18) — decided here, where the secret is;
			// the registry applies it only while it has no members.
			let configured = env.secret("BOOTSTRAP_TOKEN").ok().map(|s| s.to_string()).or_else(|| env.var("BOOTSTRAP_TOKEN").ok().map(|v| v.to_string()));
			let presented = req.headers().get("x-gorani-bootstrap")?;
			let dev = env.var("GORANI_DEV").map(|v| v.to_string() == "1").unwrap_or(false);
			let proof = match auth::bootstrap_allowed(configured.as_deref(), presented.as_deref(), dev) {
				Ok(()) => "ok".to_string(),
				Err(why) => why.to_string(),
			};
			let mut body = req.json::<serde_json::Value>().await?;
			// (An object, or nothing: `body[..] =` on a JSON array or string
			// PANICS in serde_json — and a panicking wasm Worker hangs, O19.)
			let Some(fields) = body.as_object_mut() else { return json_error(400, "a member is a JSON object") };
			// Always the Worker's own verdict: a client-sent `__bootstrap`
			// is overwritten, never trusted.
			fields.insert("__bootstrap".into(), serde_json::json!(proof));
			forward_family(&env, &identity.email, "POST", "members", Some(body)).await
		}
		("PATCH", ["family", "members", id]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PATCH", format!("members/{id}"), Some(body)).await
		}
		("POST", ["family", "members", id, "deactivate"]) => {
			forward_family(&env, &identity.email, "POST", format!("members/{id}/deactivate"), Some(serde_json::json!({}))).await
		}
		// ── Identities (commit 27, docs/CASES.md › Member identity keys) ──
		("GET", ["family", "audit", "verify"]) => match actor_of(&env, &identity.email, None).await? {
			Some(a) if a.role == "lead" || a.role == "auditor" => Response::from_json(&crate::audit::verify_area(&env, "registry").await?),
			_ => json_error(403, "the registry's audit is verified by leads and auditors"),
		},
		("GET", ["family", "identities"]) => forward_family(&env, &identity.email, "GET", "identities", None).await,
		("PUT", ["family", "identity"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", "identity", Some(body)).await
		}
		("DELETE", ["family", "members", id, "identity"]) => forward_family(&env, &identity.email, "DELETE", format!("identity/{id}"), None).await,
		("PUT", ["family", "members", id, "cert"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", format!("certs/{id}"), Some(body)).await
		}
		// ── Team recovery (commit 27, docs/CASES.md › Recovery) ──
		("GET", ["recovery"]) => forward_family(&env, &identity.email, "GET", "recovery", None).await,
		("PUT", ["recovery"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", "recovery", Some(body)).await
		}
		("GET", ["recovery", "copies"]) => forward_family(&env, &identity.email, "GET", "recovery-copies", None).await,
		("PUT", ["recovery", "copies"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", "recovery-copies", Some(body)).await
		}
		("PUT", ["recovery", "reenrol"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", "reenrol", Some(body)).await
		}
		("GET", ["recovery", "ceremonies"]) => forward_family(&env, &identity.email, "GET", "ceremonies", None).await,
		("POST", ["recovery", "ceremonies"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "POST", "ceremonies", Some(body)).await
		}
		("PUT", ["recovery", "ceremonies", id, "shares"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", format!("ceremony-shares/{id}"), Some(body)).await
		}
		("GET", ["recovery", "ceremonies", id, "material"]) => forward_family(&env, &identity.email, "GET", format!("ceremony-material/{id}"), None).await,
		("POST", ["recovery", "ceremonies", id, "complete"]) => ceremony_complete(req, &env, identity, id).await,
		("POST", ["recovery", "ceremonies", id, "cancel"]) => forward_family(&env, &identity.email, "POST", format!("ceremony-cancel/{id}"), Some(serde_json::json!({}))).await,

		// ── Member vault (settings; devices arrive in commit ⑧) ─────────
		("GET", ["members", id, "vault"]) => match vault_ctx(&env, &identity, id).await {
			Ok(actor) => forward_member(&env, id, "GET", "vault", None, actor.email).await,
			Err(resp) => Ok(resp),
		},
		("PUT", ["members", id, "vault"]) => match vault_ctx(&env, &identity, id).await {
			Ok(actor) => {
				let body = req.json::<serde_json::Value>().await?;
				forward_member(&env, id, "PUT", "vault", Some(body), actor.email).await
			}
			Err(resp) => Ok(resp),
		},
		// The trail verified (commit 29): the chain recomputed, every
		// checkpoint the bucket holds compared — the same audience as the audit.
		("GET", ["members", id, "audit", "verify"]) => match audit_ctx(&env, &identity, id).await {
			Ok(_) => Response::from_json(&crate::audit::verify_area(&env, id).await?),
			Err(resp) => Ok(resp),
		},
		("GET", ["members", id, "audit"]) => match audit_ctx(&env, &identity, id).await {
			Ok(actor) => forward_member(&env, id, "GET", "audit", None, actor.email).await,
			Err(resp) => Ok(resp),
		},
		// A member's root PUBLIC halves — what a case manager seals a grant
		// to (commit 26). Until stage 4's fingerprints, this is the server's
		// word for whose key it is: the trust-on-first-use gap of O3, now
		// named in docs/CASES.md › Member identity keys.
		("GET", ["members", id, "root"]) => member_root(&env, &identity, id).await,
		("GET", ["members", id, "vault-stats"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "stats", None, actor)).await,

		// ── Files ───────────────────────────────────────────────────────
		("POST", ["members", id, "files"]) => file_upload_whole(req, env, &identity, id).await,
		("POST", ["members", id, "files", "uploads"]) => upload_start(req, env, &identity, id).await,
		("PUT", ["members", id, "files", "uploads", upload, part]) => upload_part(req, env, &identity, id, upload, part).await,
		("POST", ["members", id, "files", "uploads", upload, "complete"]) => upload_complete(req, env, &identity, id, upload).await,
		("DELETE", ["members", id, "files", "uploads", upload]) => upload_abort(&env, &identity, id, upload).await,
		("POST", ["members", id, "files", "keys"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "files/keys", Some(body), actor)).await
		}
		("GET", ["members", id, "files", "list"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/list", &req, actor)).await,
		("GET", ["members", id, "files", "changes"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/changes", &req, actor)).await,
		("GET", ["members", id, "files", "music"]) => {
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "music/feed", None, actor)).await
		}
		("GET", ["members", id, "files", "match"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/match", &req, actor)).await,
		("GET", ["members", id, "files", "meta"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/meta", &req, actor)).await,
		("GET", ["members", id, "files", "secrets"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "files/secrets", None, actor)).await,
		("GET", ["members", id, "files", "trash"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "files/trash", None, actor)).await,
		// The deletion outbox (O10): what retention removed from the rows but
		// storage has not confirmed deleting yet — keys, attempts, last error.
		("GET", ["members", id, "storage", "pending"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "storage/pending", None, actor)).await,
		// The read log (O14): who read which file version, from what, when.
		("GET", ["members", id, "reads"]) => match audit_ctx(&env, &identity, id).await {
			Ok(actor) => forward_member_qs(&env, id, "GET", "reads", &req, actor.email).await,
			Err(resp) => Ok(resp),
		},
		("POST", ["members", id, "files", "trash", "restore"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "files/trash/restore", Some(body), actor)).await
		}
		// The rotation walk's input: every value sealed to the files store
		// key, by kind, paged (files_store.rs › sealed_page).
		("GET", ["members", id, "files", "sealed"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/sealed", &req, actor)).await,
		("PUT", ["members", id, "files", "reseal"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PUT", "files/reseal", Some(body), actor)).await
		}
		// ── Devices (docs/DESKTOP.md): enrolment needs the member's unlocked
		// session; the device routes themselves authenticate with
		// the device token INSIDE the DO (the token is not the web session).
		("GET", ["members", id, "devices"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "devices", None, actor)).await,
		("POST", ["members", id, "devices"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "devices", Some(body), actor)).await
		}
		("POST", ["members", id, "devices", device, "unlock"]) => device_call(&env, &identity, id, device, "unlock", req).await,
		("POST", ["members", id, "devices", device, "check"]) => device_call(&env, &identity, id, device, "check", req).await,
		("PUT", ["members", id, "devices", device, "key"]) => device_call(&env, &identity, id, device, "key", req).await,
		("POST", ["members", id, "devices", device, "wiped"]) => device_call(&env, &identity, id, device, "wiped", req).await,
		("POST", ["members", id, "devices", device, "leave"]) => device_call(&env, &identity, id, device, "leave", req).await,
		("DELETE", ["members", id, "devices", device]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "DELETE", format!("devices/{device}"), None, actor)).await,
		// ── Share links (GS01): the client seals the copy; the worker stores
		// ciphertext and bookkeeping. See files_store.rs + s.html. ────────
		("POST", ["members", id, "files", "shares"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| share_create(&env, id, actor, body)).await
		}
		("GET", ["members", id, "files", "shares"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "files/shares", None, actor)).await,
		("PUT", ["members", id, "files", "shares", share, "parts", part]) => share_part(req, env, &identity, id, share, part).await,
		("POST", ["members", id, "files", "shares", share, "complete"]) => share_complete(req, env, &identity, id, share).await,
		("DELETE", ["members", id, "files", "shares", share]) => share_revoke(&env, &identity, id, share).await,
		// ── Backups (GB1): the browser PUT the backup PUBLIC key (the private
		// bundle never leaves it as the key file); the DO job writes .gbak
		// containers the server cannot open. ──────────────────────────────
		("PUT", ["members", id, "backup-key"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PUT", "backup-key", Some(body), actor)).await
		}
		("GET", ["members", id, "backup-key"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "backup-key", None, actor)).await,
		("POST", ["members", id, "backup", "run"]) => {
			let body = req.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "backup/run", Some(body), actor)).await
		}
		("GET", ["members", id, "backups"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "backups", None, actor)).await,
		("GET", ["members", id, "backups", stamp]) => backup_download(&env, &identity, id, stamp).await,
		("POST", ["members", id, "housekeeping"]) => {
			let body = req.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "housekeeping", Some(body), actor)).await
		}
		("POST", ["members", id, "backup", "restore"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "backup/restore", Some(body), actor)).await
		}
		("PUT", ["members", id, "backup", "restore", "object"]) => backup_object_fill(req, env, &identity, id).await,
		// ── Crypto-shredding: the destroy secret must exist and the confirm
		// phrase must match, exactly. Without both: 403, always.
		("DELETE", ["members", id, "vault"]) => {
			match member_ctx(&env, &identity, id).await {
				Ok(actor) => {
					let confirm = req.url()?.query().unwrap_or("").contains("confirm=DESTROY%20VAULT%20KEY");
					let armed = env.secret("VAULT_DESTROY_ENABLED").is_ok();
					if !armed {
						json_error(403, "vault destruction is not enabled on this deployment (VAULT_DESTROY_ENABLED secret missing)")
					} else if !confirm {
						json_error(403, "confirm with ?confirm=DESTROY VAULT KEY")
					} else {
						forward_member(&env, id, "DELETE", "vault", None, &actor.email).await
					}
				}
				Err(resp) => Ok(resp),
			}
		}
		("PUT", ["members", id, "files", "secrets"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PUT", "files/secrets", Some(body), actor)).await
		}
		("POST", ["members", id, "files", "folders"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "files/folders", Some(body), actor)).await
		}
		("PATCH", ["members", id, "files", "folders", folder]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PATCH", format!("files-folders/{folder}"), Some(body), actor)).await
		}
		("DELETE", ["members", id, "files", "folders", folder]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "DELETE", format!("files-folders/{folder}"), None, actor)).await,
		("PATCH", ["members", id, "files", file]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PATCH", format!("files/{file}"), Some(body), actor)).await
		}
		("DELETE", ["members", id, "files", file]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "DELETE", format!("files/{file}"), None, actor)).await,
		("POST", ["members", id, "files", file, "versions"]) => file_version_upload(req, env, &identity, id, file).await,
		// The download: streamed from S3 with Range passthrough and the
		// wrapped content key in a header (the client opens it, never us).
		("GET", ["members", id, "files", file]) => file_download(req, env, &identity, id, file).await,

		_ => json_error(404, "no such route"),
	}
}

/// Complete a recovery ceremony. A case's outcome (a signed grant) is the
/// registry's alone. A member's needs three steps, in this order, each
/// safe to retry: the registry validates and hands back the new settings
/// (the ceremony waits in `applying`), the member's store takes them (the
/// one write that may change a root), the registry closes the ceremony. A
/// failure between the steps leaves the ceremony open, not half-applied.
async fn ceremony_complete(mut req: Request, env: &Env, identity: &Identity, id: &str) -> Result<Response> {
	let body = req.json::<serde_json::Value>().await?;
	let mut first = forward_family(env, &identity.email, "POST", format!("ceremony-complete/{id}"), Some(body)).await?;
	if first.status_code() != 200 {
		return Ok(first);
	}
	let v: serde_json::Value = first.json().await?;
	let Some(reroot) = v.get("reroot") else { return Response::from_json(&v) };
	let Some(member) = reroot.get("member").and_then(|m| m.as_str()).filter(|m| auth::valid_member_id(m)) else { return json_error(500, "the registry named no member to re-root") };
	let wrote = forward_member(env, member, "PUT", "vault-reroot", Some(serde_json::json!({ "settings": reroot["settings"] })), identity.email.clone()).await?;
	if wrote.status_code() >= 300 {
		return Ok(wrote);
	}
	forward_family(env, &identity.email, "POST", format!("ceremony-close/{id}"), Some(serde_json::json!({}))).await
}

/// The public halves of a member's vault root, for any active team member
/// who is not an external (they never manage a case, so never seal grants).
async fn member_root(env: &Env, identity: &Identity, id: &str) -> Result<Response> {
	if !auth::valid_member_id(id) {
		return json_error(400, "member id: 2–32 chars of a–z, 0–9, dashes");
	}
	match actor_of(env, &identity.email, Some(id)).await? {
		Some(a) if a.role != "external" && a.target_exists && a.target_active => {}
		Some(a) if a.role != "external" => return json_error(404, "no such active member"),
		_ => return json_error(403, "not a team member"),
	}
	let mut vault = forward_member(env, id, "GET", "vault", None, "internal").await?;
	let v: serde_json::Value = vault.json().await?;
	let (Some(key_id), Some(public_key), Some(pq)) = (v.get("keyId"), v.get("publicKey"), v.get("pqPublicKey")) else {
		return json_error(404, "this member has no vault yet — they set it up first");
	};
	Response::from_json(&serde_json::json!({ "member": id, "keyId": key_id, "publicKey": public_key, "pqPublicKey": pq }))
}

/// Run `f` with the acting email if the caller may act for this member.
async fn member_call<F, Fut>(env: &Env, identity: &Identity, id: &str, f: F) -> Result<Response>
where
	F: FnOnce(String) -> Fut,
	Fut: std::future::Future<Output = Result<Response>>,
{
	match member_ctx(env, identity, id).await {
		Ok(actor) => f(actor.email).await,
		Err(resp) => Ok(resp),
	}
}

/// A device call: the body passes through untouched. These routes skip the
/// member scope on purpose — the **device token** is the authority here (its
/// hash lives in exactly one member's DO, so a token from member A cannot
/// touch member B), and in production the perimeter is an Access service
/// token, not a member email.
async fn device_call(env: &Env, _identity: &Identity, member_id: &str, device: &str, what: &str, mut req: Request) -> Result<Response> {
	// Token checks are rate limited per caller and device (O13): a device
	// token is a 256-bit secret, so guessing is hopeless — but each guess
	// costs a DO round trip, and an unbounded loop of them is a cheap DoS.
	if let Some(limited) = rate_limited(env, "DEVICE_LIMITER", format!("device:{}:{member_id}:{device}", client_ip(&req))).await {
		return Ok(limited);
	}
	// The token decides — but only for a member the registry has (otherwise
	// any Access identity could conjure `member:<anything>` DOs here).
	if !auth::valid_member_id(member_id) || !member_exists(env, member_id).await? {
		return json_error(404, "no such member");
	}
	let token = req.headers().get("x-gorani-device-token")?;
	let body: serde_json::Value = req.json().await.unwrap_or(serde_json::json!({}));
	// The device token is forwarded as a header — the DO authenticates the
	// device with it (its hash lives in exactly one member's DO).
	let namespace = env.durable_object("MEMBER")?;
	let stub = namespace.id_from_name(&format!("member:{member_id}"))?.get_stub()?;
	let headers = Headers::new();
	headers.set("x-gorani-actor", "device")?;
	headers.set("Content-Type", "application/json")?;
	let Some(token) = token else { return json_error(401, "the device token header is required") };
	headers.set("x-gorani-device-token", &token)?;
	let request = Request::new_with_init(
		&format!("https://do.internal/devices/{device}/{what}"),
		&RequestInit {
			method: if what == "key" { Method::Put } else { Method::Post },
			headers,
			body: Some(body.to_string().into()),
			..Default::default()
		},
	)?;
	stub.fetch_with_request(request).await
}

// ── DO plumbing ─────────────────────────────────────────────────────

async fn forward_family(env: &Env, actor: &str, method: &str, path: impl Into<String>, body: Option<serde_json::Value>) -> Result<Response> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	do_request(&stub, method, path, body, Some(actor), None).await
}

async fn forward_member(env: &Env, member_id: &str, method: &str, path: impl Into<String>, body: Option<serde_json::Value>, actor: impl Into<String>) -> Result<Response> {
	let namespace = env.durable_object("MEMBER")?;
	// `member_id` is an AREA: a member id, or `case:<id>` (area.rs).
	let stub = namespace.id_from_name(&crate::area::do_name(member_id))?.get_stub()?;
	// The member DO is told whose database it is (`x-gorani-member`): a DO
	// cannot read its own instance name, and code that needs it (the restore
	// minting `files/<member>/…` keys) used to guess from the ACTOR — wrong
	// whenever the actor was not the area's own member (a parent acting for
	// a child, before commit 27c; a case, always).
	do_request(&stub, method, path, body, Some(actor.into().as_str()), Some(member_id)).await
}

/// Same, but carrying the caller's query string through (list/changes/match/meta).
async fn forward_member_qs(env: &Env, member_id: &str, method: &str, path: impl Into<String>, req: &Request, actor: impl Into<String>) -> Result<Response> {
	let qs = req.url()?.query().unwrap_or("").to_string();
	let path = path.into();
	let full = if qs.is_empty() { path } else { format!("{path}?{qs}") };
	forward_member(env, member_id, method, &full, None, actor.into().as_str()).await
}

async fn do_request(stub: &Stub, method: &str, path: impl Into<String>, body: Option<serde_json::Value>, actor: Option<&str>, member: Option<&str>) -> Result<Response> {
	let headers = Headers::new();
	if let Some(a) = actor {
		headers.set("x-gorani-actor", a)?;
	}
	if let Some(m) = member {
		headers.set("x-gorani-member", m)?;
	}
	if body.is_some() {
		headers.set("Content-Type", "application/json")?;
	}
	let request = Request::new_with_init(
		&format!("https://do.internal/{}", path.into()),
		&RequestInit { method: method_of(method)?, headers, body: body.map(|b| b.to_string().into()), ..Default::default() },
	)?;
	stub.fetch_with_request(request).await
}

fn method_of(name: &str) -> Result<Method> {
	Ok(match name {
		"GET" => Method::Get,
		"PUT" => Method::Put,
		"POST" => Method::Post,
		"PATCH" => Method::Patch,
		"DELETE" => Method::Delete,
		"HEAD" => Method::Head,
		_ => return Err(Error::RustError(format!("unsupported method {name}"))),
	})
}

// ── File upload plumbing (the Worker's half) ────────────────────────

/// Extract multipart fields (text + one file) the way mailflare's client and
/// browser upload: `file`, `ck`, `name`, `type`, `size`, `folder_id`, `tag`,
/// `base_version`, `key`, `chunk`, `parts`.
struct UploadForm {
	fields: std::collections::BTreeMap<String, String>,
	file: Option<Vec<u8>>,
}

async fn form_of(req: &mut Request) -> Result<UploadForm> {
	let form = req.form_data().await?;
	// The known text fields; FormData has no iteration in workers-rs, so we
	// ask for each by name (the upload contract is fixed anyway).
	// (`hash`: the uploader's signed content hash, sealed — commit 29d.
	// `sample`: "1" uploads a malware sample — commit 29e.)
	const KNOWN: [&str; 14] = ["name", "type", "size", "folder_id", "ck", "tag", "base_version", "key", "chunk", "parts", "file_id", "mmeta", "hash", "sample"];
	let mut fields = std::collections::BTreeMap::new();
	for k in KNOWN {
		if let Some(v) = form.get_field(k) {
			fields.insert(k.to_string(), v);
		}
	}
	let file = match form.get("file") {
		Some(FormEntry::File(f)) => Some(f.bytes().await?),
		_ => None,
	};
	Ok(UploadForm { fields, file })
}

/// GV02's fixed overhead: magic (4) ‖ nonce (12) ‖ … ‖ tag (16).
const GV02_OVERHEAD: u64 = 32;

/// The sealed-shape checks every upload must pass before anything is stored:
/// bytes start with the GV02 magic, the declared plaintext size is honest,
/// names and types are sealed text. This is the zero-trust boundary in
/// code — the Worker refuses anything else, with a 400, not a 500 (a
/// refusal is an expectation, not a fault).
///
/// The size rule (security review, commit 23) was drawn in
/// ARCHITECTURE-DEEP.md's upload diagram ("size honest") but never
/// written: the DO stored whatever `size` the form claimed. Sizes are the
/// one readable number per file — quotas, the duplicate check
/// (`files/match`) and the listings all trust it — so it must equal what
/// the bytes say: sealed length − 32.
fn check_sealed(file: &Option<Vec<u8>>, declared_size: Option<&String>, name: &Option<String>, type_sealed: &Option<String>) -> Result<(), String> {
	let bytes = file.as_ref().ok_or("missing file")?;
	if bytes.len() < GV02_OVERHEAD as usize || &bytes[..4] != gorani_formats::formats::MAGIC_V2 {
		return Err("content must be sealed (GV02) bytes".into());
	}
	let size: Option<u64> = declared_size.and_then(|s| s.parse().ok());
	if size != Some(bytes.len() as u64 - GV02_OVERHEAD) {
		return Err("size must be the plaintext length (the sealed bytes minus 32)".into());
	}
	if let Some(n) = name {
		if !gorani_formats::placed::is_placed_text(n) {
			return Err("name must be placed sealed text (GV04)".into());
		}
	}
	if let Some(t) = type_sealed {
		if !gorani_formats::placed::is_placed_text(t) {
			return Err("type must be placed sealed text (GV04)".into());
		}
	}
	Ok(())
}

async fn file_upload_whole(mut req: Request, env: Env, identity: &Identity, member_id: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let form = form_of(&mut req).await?;
	let name = form.fields.get("name").cloned();
	let type_sealed = form.fields.get("type").cloned();
	if let Err(msg) = check_sealed(&form.file, form.fields.get("size"), &name, &type_sealed) {
		return json_error(400, &msg);
	}
	// The client chose the file id (commit 25, O6): it sealed the name and
	// the content key into places that name this file, before uploading.
	// The id becomes a key segment, so the router's allow-list applies.
	let Some(file_id) = form.fields.get("file_id").filter(|f| auth::valid_object_id(f)).cloned() else {
		return json_error(400, "file_id is required: the client chooses it ([A-Za-z0-9_-], ≤ 64) and seals into it");
	};
	let version_id = crate::files_store::uuid();
	let object_key = format!("{}/{file_id}/v-{version_id}", crate::area::key_prefix(member_id));
	s3::put(&env, &object_key, form.file.clone().unwrap_or_default()).await?;
	let body = serde_json::json!({
		"id": file_id,
		"folderId": form.fields.get("folder_id"),
		"name": name,
		"type": type_sealed,
		"size": form.fields.get("size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
		"ck": form.fields.get("ck"),
		"tag": form.fields.get("tag"),
		"mmeta": form.fields.get("mmeta"),
		"hash": form.fields.get("hash"),
		"sample": form.fields.get("sample").is_some_and(|v| v == "1"),
		"objectKey": object_key,
		"bytesSealed": true,
		"owner": actor.id,
	});
	let resp = forward_member(&env, member_id, "POST", "files/put", Some(body), &actor.email).await?;
	if resp.status_code() >= 400 {
		// The DO refused the record — do not leave the object orphaned.
		let _ = s3::delete(&env, &object_key).await;
	}
	Ok(resp)
}

async fn file_version_upload(mut req: Request, env: Env, identity: &Identity, member_id: &str, file_id: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let form = form_of(&mut req).await?;
	let name = form.fields.get("name").cloned();
	let type_sealed = form.fields.get("type").cloned();
	if let Err(msg) = check_sealed(&form.file, form.fields.get("size"), &name, &type_sealed) {
		return json_error(400, &msg);
	}
	// (`file_id` is a path segment — the router's allow-list already held it
	// to [A-Za-z0-9_-] before this key is built.)
	let version_id = crate::files_store::uuid();
	let object_key = format!("{}/{file_id}/v-{version_id}", crate::area::key_prefix(member_id));
	s3::put(&env, &object_key, form.file.clone().unwrap_or_default()).await?;
	let body = serde_json::json!({
		"fileId": file_id,
		"baseVersion": form.fields.get("base_version").and_then(|s| s.parse::<u64>().ok()),
		"name": name,
		"type": type_sealed,
		"size": form.fields.get("size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
		"ck": form.fields.get("ck"),
		"tag": form.fields.get("tag"),
		"mmeta": form.fields.get("mmeta"),
		"hash": form.fields.get("hash"),
		"objectKey": object_key,
	});
	let resp = forward_member(&env, member_id, "POST", "files/versions", Some(body), &actor.email).await?;
	if resp.status_code() >= 400 {
		let _ = s3::delete(&env, &object_key).await;
	}
	Ok(resp)
}

async fn upload_start(mut req: Request, env: Env, identity: &Identity, member_id: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let body: serde_json::Value = req.json().await?;
	let chunk = body.get("chunk").and_then(|v| v.as_u64()).unwrap_or(8 * 1024 * 1024);
	let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
	// The backends' multipart rule (S3, MinIO and R2 alike): every part but
	// the last must be ≥ 5 MiB. One GC01 frame rides each part, so the
	// caller's chunk IS the part size — refuse a plan the backend would
	// reject at complete time (an honest 400 now beats a 500 after every
	// part has been paid for). Found by the R2 suite: the simulator enforces
	// what the dev S3 stub politely doesn't.
	const MIN_PART: u64 = 5 * 1024 * 1024;
	if chunk < MIN_PART {
		return json_error(400, &format!("chunk {chunk} is below the backend's minimum part size of {MIN_PART} bytes (every part but the last must be at least that)"));
	}
	// (div_ceil, not `(size + chunk - 1) / chunk`: a hostile `size` near
	// u64::MAX would wrap the sum in a release build.)
	let parts = size.div_ceil(chunk).max(1);
	if parts > 10_000 {
		return json_error(400, "this plan needs more than 10 000 parts (the backends' limit) — raise the chunk size");
	}
	// Which file (commit 25, O6): `fileId` names an EXISTING file (this is
	// a new version), `newFileId` the client-chosen id of a new one — chosen
	// before sealing, because the places name it. Exactly one; both become
	// key segments, so the router's allow-list applies.
	let version_of = body.get("fileId").and_then(|v| v.as_str());
	let new_file = body.get("newFileId").and_then(|v| v.as_str());
	let file_id = match (version_of, new_file) {
		(Some(f), None) | (None, Some(f)) if auth::valid_object_id(f) => f.to_string(),
		(Some(_), Some(_)) => return json_error(400, "fileId (a new version) or newFileId (a new file), not both"),
		(None, None) => return json_error(400, "newFileId is required for a new file (the client chooses it and seals into it); fileId for a new version"),
		_ => return json_error(400, "file ids are ids ([A-Za-z0-9_-], ≤ 64)"),
	};
	let object_key = format!("{}/{file_id}/u-{}", crate::area::key_prefix(member_id), crate::files_store::uuid());
	let started = forward_member(&env, member_id, "POST", "uploads/start", Some(serde_json::json!({ "objectKey": object_key, "fileId": version_of })), &actor.email).await?;
	if started.status_code() >= 400 {
		return Ok(started);
	}
	let mut started = started;
	let started_body: serde_json::Value = started.json().await?;
	let upload_id: String = started_body.get("uploadId").and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| Error::RustError("no uploadId".into()))?;
	let s3_upload_id = s3::multipart_init(&env, &object_key).await?;
	forward_member(&env, member_id, "PUT", format!("uploads/{upload_id}/s3"), Some(serde_json::json!({ "s3UploadId": s3_upload_id })), &actor.email).await?;
	Ok(Response::from_json(&serde_json::json!({ "uploadId": upload_id, "key": object_key, "parts": parts }))?)
}

async fn upload_part(mut req: Request, env: Env, identity: &Identity, member_id: &str, upload_id: &str, part: &str) -> Result<Response> {
	match member_ctx(&env, identity, member_id).await {
		Ok(_) => {}
		Err(resp) => return Ok(resp),
	}
	let meta = match upload_meta(&env, member_id, upload_id).await {
		Ok(m) => m,
		Err(resp) => return Ok(resp),
	};
	let Some(n) = part_number(part) else { return json_error(400, "part numbers are 1–10000") };
	let bytes = req.bytes().await?;
	let etag = s3::multipart_part(&env, &meta.object_key, &meta.s3_upload_id, n, bytes.to_vec()).await?;
	Response::from_json(&serde_json::json!({ "partNumber": n, "etag": etag }))
}

/// S3's part-number range (1-based, at most 10 000). Parsed before the body
/// is read, so a bad number costs nothing.
fn part_number(raw: &str) -> Option<u32> {
	raw.parse::<u32>().ok().filter(|n| (1..=10_000).contains(n))
}

async fn upload_complete(mut req: Request, env: Env, identity: &Identity, member_id: &str, upload_id: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let meta = match upload_meta(&env, member_id, upload_id).await {
		Ok(m) => m,
		Err(resp) => return Ok(resp),
	};
	let form = form_of(&mut req).await?;
	let parts: Vec<(u32, String)> = form
		.fields
		.get("parts")
		.and_then(|p| serde_json::from_str::<Vec<serde_json::Value>>(p).ok())
		.map(|list| {
			list
				.into_iter()
				.filter_map(|p| Some((p.get("partNumber")?.as_u64()? as u32, p.get("etag")?.as_str()?.to_string())))
				.collect()
		})
		.unwrap_or_default();
	let size: u64 = form.fields.get("size").and_then(|s| s.parse().ok()).unwrap_or(0);
	let chunk: u64 = form.fields.get("chunk").and_then(|s| s.parse().ok()).unwrap_or(0);
	if chunk == 0 {
		return json_error(400, "chunk is required (the GC01 frame size the parts were sealed with)");
	}
	s3::multipart_complete(&env, &meta.object_key, &meta.s3_upload_id, &parts).await?;
	// The completed object must add up: size + frames × 28 bytes (GC01).
	//
	// Fail CLOSED (security review, commit 23): this used to be
	// `if let Some(head) = …` — a HEAD that found nothing skipped the check
	// and the row was recorded anyway. And once a multipart upload is
	// complete there is nothing left to abort: a refused object must be
	// DELETED, or it lingers in the bucket with no row pointing at it.
	let expected = gorani_formats::chunked::sealed_size(size, chunk);
	let actual = s3::head(&env, &meta.object_key).await?.map(|h| h.size);
	if actual != Some(expected) {
		let _ = s3::delete(&env, &meta.object_key).await;
		return json_error(400, "the upload does not add up to its declared size");
	}
	let body = serde_json::json!({
		"ck": form.fields.get("ck"),
		"name": form.fields.get("name"),
		"type": form.fields.get("type"),
		"size": size,
		"chunkSize": chunk,
		"owner": actor.id, // the acting uploader (strict ownership, files_store.rs)
		"folderId": form.fields.get("folder_id"),
		"baseVersion": form.fields.get("base_version").and_then(|s| s.parse::<u64>().ok()),
		"tag": form.fields.get("tag"),
		"mmeta": form.fields.get("mmeta"),
		"hash": form.fields.get("hash"),
		// (A new file only: a version of a sample is a sample already.)
		"sample": form.fields.get("sample").is_some_and(|v| v == "1"),
		"key": form.fields.get("key"),
		// The Worker's attestation: the object added up to its declared size
		// (size + frames × 28). GC01 frames carry no magic — their sealing is
		// proven by opening, and the DO records what it was told after the
		// checks above passed.
		"bytesSealed": true,
	});
	let resp = forward_member(&env, member_id, "POST", format!("uploads/{upload_id}/complete"), Some(body), &actor.email).await?;
	if resp.status_code() >= 400 {
		// Refused (a 409 conflict, say). The upload is already complete, so
		// the object itself goes — nothing lingers without a row.
		let _ = s3::delete(&env, &meta.object_key).await;
	}
	Ok(resp)
}

async fn upload_abort(env: &Env, identity: &Identity, member_id: &str, upload_id: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let meta = match upload_meta(&env, member_id, upload_id).await {
		Ok(m) => m,
		Err(resp) => return Ok(resp),
	};
	if meta.s3_upload_id != "pending" {
		let _ = s3::multipart_abort(&env, &meta.object_key, &meta.s3_upload_id).await;
	}
	forward_member(&env, member_id, "DELETE", format!("uploads/{upload_id}"), None, &actor.email).await
}

struct UploadMeta {
	object_key: String,
	s3_upload_id: String,
}

async fn upload_meta(env: &Env, member_id: &str, upload_id: &str) -> std::result::Result<UploadMeta, Response> {
	let v = forward_member(env, member_id, "GET", format!("uploads/{upload_id}"), None, "internal").await;
	match v {
		Ok(mut resp) if resp.status_code() == 200 => {
			let j: serde_json::Value = resp.json().await.map_err(|e| json_error_raw(500, &e.to_string()))?;
			Ok(UploadMeta {
				object_key: j.get("objectKey").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
				s3_upload_id: j.get("s3UploadId").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
			})
		}
		Ok(resp) => Err(resp),
		Err(e) => Err(json_error_raw(500, &e.to_string())),
	}
}

/// The download: `GET /files/:id?version=n` — S3 object streamed through with
/// Range passthrough; the wrapped content key rides in `x-gorani-ck`, the
/// chunk size (if chunked) in `x-gorani-chunk`. The Worker never holds a key
/// that opens it.
async fn file_download(req: Request, env: Env, identity: &Identity, member_id: &str, file_id: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let version = crate::files_store::urlquery(req.url()?.query().unwrap_or("")).get("version").and_then(|v| v.parse::<i64>().ok());
	// The reader goes to the DO as the actor (O14, D10): the lookup records
	// one merged read event per reader × version × client × 5 minutes —
	// BEFORE the cache, so a cached read is still a read on record. The
	// client kind is a label the caller sets (`x-gorani-client`: web, media,
	// cli…); it describes, it does not authenticate.
	let client = req.headers().get("x-gorani-client")?.unwrap_or_else(|| "unknown".into());
	let meta = forward_member(&env, member_id, "GET", &format!("files-object/{file_id}?version={}&client={}", version.map(|v| v.to_string()).unwrap_or_default(), urlencode(&client)), None, &actor.email).await;
	let meta = match meta {
		Ok(mut r) if r.status_code() == 200 => r.json::<serde_json::Value>().await?,
		Ok(r) => return Ok(r),
		Err(e) => return json_error(500, &e.to_string()),
	};
	let object_key = meta.get("objectKey").and_then(|x| x.as_str()).unwrap_or_default().to_string();
	let range = parse_range(&req.headers().get("Range")?.unwrap_or_default());
	// The cache keys CHUNKED media by its frame span (docs/PRODUCTION.md ›
	// Object caching): the media worker requests whole frames, so the span
	// is the same bytes on every play — the deterministic half of the
	// design. A range that doesn't land on frame edges (a stray direct
	// client) skips the span layer honestly.
	let frame = meta
		.get("chunk")
		.and_then(|c| c.as_u64())
		.filter(|c| *c > 0)
		.map(|c| c + gorani_formats::chunked::FRAME_OVERHEAD as u64);
	let cache_span = range
		.zip(frame)
		.and_then(|((off, len), f)| {
			let end = off + len; // exclusive
			let size = meta.get("size").and_then(|x| x.as_u64());
			let aligned = off % f == 0 && (Some(end) == size || end % f == 0);
			aligned.then(|| (off / f, (end - 1) / f))
		});
	let mut s3_resp = s3::fetch_stream(&env, "GET", &object_key, range, &[], cache_span).await?;
	let status = s3_resp.status_code();
	if status != 200 && status != 206 {
		return Response::error("Not Found", 404);
	}
	let headers = Headers::new();
	headers.set("Content-Type", "application/octet-stream")?;
	headers.set("Accept-Ranges", "bytes")?;
	if let Some(ck) = meta.get("ck").and_then(|x| x.as_str()) {
		headers.set("x-gorani-ck", ck)?;
	}
	if let Some(kid) = meta.get("vaultKeyId").and_then(|x| x.as_str()) {
		headers.set("x-gorani-vault-key-id", kid)?;
	}
	// Which version these bytes are (commit 25): the client opens the key
	// in `x-gorani-ck` from the place `file.key(member, file, version)`, so
	// it must know the version even when it asked for "the current one".
	// A server lying here gains nothing: a key sealed into another
	// version's place does not open.
	if let Some(v) = meta.get("version").and_then(|x| x.as_i64()) {
		headers.set("x-gorani-version", &v.to_string())?;
	}
	if let Some(chunk) = meta.get("chunk").and_then(|x| x.as_u64()) {
		if chunk > 0 {
			headers.set("x-gorani-chunk", &chunk.to_string())?;
		}
	}
	// The uploader's signed content hash (commit 29d, D5.1), sealed into
	// this version's place: the reader opens it, checks the signature, and
	// compares it with SHA-256 of what it decrypted. Like the key above,
	// the server hands back a value it cannot read — and one moved here
	// from another version does not open.
	if let Some(h) = meta.get("hash").and_then(|x| x.as_str()) {
		headers.set("x-gorani-hash", h)?;
	}
	if let Some(len) = s3_resp.headers().get("Content-Length")? {
		headers.set("Content-Length", &len)?;
	}
	if let Some(cr) = s3_resp.headers().get("Content-Range")? {
		headers.set("Content-Range", &cr)?;
	}
	// The cache layer's observability rides through (worker/src/cache.rs).
	if let Some(c) = s3_resp.headers().get("x-gorani-cache")? {
		headers.set("x-gorani-cache", &c)?;
	}
	let stream = s3_resp.stream()?;
	Ok(Response::from_stream(stream)?.with_status(status).with_headers(headers))
}
// ── Public share routes (GS01) ──────────────────────────────────────────────
// /s/f/<id>          the sealed share page (served from the asset s.html)
// /s/f/<id>/meta     { metaSealed, kdf, expiresAt, downloadsLeft }
// /s/f/<id>/claim    one download — decrements the counter, returns a token
// /s/f/<id>/data     the sealed copy (GC1 frames under the link's data key),
//                    for the claim's token only (x-gorani-share-token, O12)
//
// Everything here is unauthenticated BY DESIGN: the link's fragment secret
// is the credential, the server holds only sealed bytes, and the owner's
// member DO is resolved through the registry's share index.
async fn public_share(req: Request, env: Env, segs: &[&str]) -> Result<Response> {
	let Some(id) = segs.get(1) else { return http_text(404, "no such share").await };
	let id = id.to_string();
	if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
		return http_text(404, "no such share").await;
	}
	// The only routes anyone on the internet can call without signing in
	// (O13): per caller and link, so a script hammering one link — draining
	// its claims, or its owner's bucket egress — is cut off, while the
	// recipient's handful of requests never notice.
	if let Some(limited) = rate_limited(&env, "SHARE_LIMITER", format!("share:{}:{id}", client_ip(&req))).await {
		return Ok(limited);
	}
	let member = {
		let namespace = env.durable_object("FAMILY")?;
		let stub = namespace.id_from_name("family")?.get_stub()?;
		let request = Request::new_with_init(&format!("https://do.internal/share-owner/{id}"), &RequestInit { method: Method::Get, ..Default::default() })?;
		let resp = stub.fetch_with_request(request).await?;
		let mut resp = resp;
		let v: serde_json::Value = resp.json().await?;
		match v.get("memberId").and_then(|m| m.as_str()).map(str::to_string) {
			Some(m) if !m.is_empty() => m,
			_ => return http_text(404, "no such share").await,
		}
	};
	let namespace = env.durable_object("MEMBER")?;
	let stub = namespace.id_from_name(&format!("member:{member}"))?.get_stub()?;
	let do_call = |path: String, body: Option<serde_json::Value>| {
		let stub = &stub;
		async move {
			let headers = Headers::new();
			headers.set("Content-Type", "application/json")?;
			let request = Request::new_with_init(
				&format!("https://do.internal/{path}"),
				&RequestInit {
					method: Method::Post,
					headers,
					body: body.map(|b| b.to_string().into()),
					..Default::default()
				},
			)?;
			stub.fetch_with_request(request).await
		}
	};
	match segs.get(2) {
		None => {
			// Serve the recipient page from the ASSETS binding (wrangler.jsonc ›
			// assets.binding) — an in-process read of the built s.html.
			//
			// Commit 24: this used to `fetch("<own origin>/s.html")` over the
			// network. A Worker's subrequest to its own hostname is refused
			// (workers.dev, wrangler dev's loopback) or loops back through the
			// Worker, so /s/f/<id> answered a bare 500 and the share page was
			// never served — the api suites only ever called /meta, /claim and
			// /data, and the e2e never opened a link. The binding is the
			// platform's own door to the static files.
			let mut page = env.assets("ASSETS")?.fetch("https://assets.internal/s.html", None).await?;
			if page.status_code() != 200 {
				return http_text(500, "the share page is missing from this deployment").await;
			}
			let body = page.bytes().await?;
			let headers = Headers::new();
			headers.set("Content-Type", "text/html; charset=utf-8")?;
			headers.set("Cache-Control", "no-store")?;
			// The page holds the link secret (in the fragment) while it runs:
			// never framed by another site, never leaking its URL in a Referer,
			// never MIME-sniffed — and since commit 24 a full script policy:
			// its code is /s.js + the vendored Argon2id (WebAssembly, hence
			// 'wasm-unsafe-eval'), nothing inline, and Trusted Types with NO
			// policy at all ('none'): the page writes the DOM only through
			// textContent/classList, so no string can ever become markup.
			// Kept in step with the /s.html rule in web/public/_headers.
			headers.set("Content-Security-Policy", SHARE_PAGE_CSP)?;
			headers.set("Referrer-Policy", "no-referrer")?;
			headers.set("X-Content-Type-Options", "nosniff")?;
			Ok(Response::from_bytes(body)?.with_headers(headers))
		}
		Some(&"meta") => {
			let resp = do_call(format!("shares/{id}/public-meta"), Some(serde_json::json!({}))).await?;
			let mut resp = resp;
			let status = resp.status_code();
			let v: serde_json::Value = resp.json().await?;
			Ok(Response::from_json(&v)?.with_status(status))
		}
		Some(&"claim") => {
			let resp = do_call(format!("shares/{id}/claim"), Some(serde_json::json!({}))).await?;
			let mut resp = resp;
			let status = resp.status_code();
			let v: serde_json::Value = resp.json().await?;
			Ok(Response::from_json(&v)?.with_status(status))
		}
		Some(&"data") => {
			// The claim's token (O12) and the share's state, checked by the DO;
			// then the sealed object streams from S3. A header, not a query
			// parameter: URLs end up in logs and histories, headers do not.
			let token = req.headers().get("x-gorani-share-token")?.unwrap_or_default();
			let resp = do_call(format!("shares/{id}/public-object"), Some(serde_json::json!({ "token": token }))).await?;
			let mut resp = resp;
			let status = resp.status_code();
			if status >= 400 {
				return Ok(resp);
			}
			let v: serde_json::Value = resp.json().await?;
			let object = v.get("objectKey").and_then(|x| x.as_str()).unwrap_or_default().to_string();
			let range_header = req.headers().get("Range")?.unwrap_or_default();
			let range = parse_range(&range_header);
			let s3_resp = s3::fetch_stream(&env, "GET", &object, range, &[], None).await?;
			let mut s3_resp = s3_resp;
			let headers = Headers::new();
			headers.set("Content-Type", "application/octet-stream")?;
			headers.set("Accept-Ranges", "bytes")?;
			if let Some(len) = s3_resp.headers().get("Content-Length")? {
				headers.set("Content-Length", &len)?;
			}
			if let Some(cr) = s3_resp.headers().get("Content-Range")? {
				headers.set("Content-Range", &cr)?;
			}
			let status = s3_resp.status_code();
			let stream = s3_resp.stream()?;
			Ok(Response::from_stream(stream)?.with_status(status).with_headers(headers))
		}
		_ => http_text(404, "no such share").await,
		}
}


/// `Range: bytes=a-b` → `(offset, length)` — the shape `s3::fetch_stream`
/// and the cache take. One parser for every route.
///
/// (Security review, commit 23: there used to be two parsers. The file
/// route's returned `(start, length)`; the public share route's returned
/// `(start, END)` into the same `(offset, length)` slot — so `bytes=2-9`
/// on a share link fetched bytes 2..=10 and `bytes=0-N` one byte short.
/// The share test only checked `bytes=0-…` and the 206 status, which is
/// why it survived. Two copies of a parser are two chances to be wrong.)
///
/// Only the closed form `a-b` is honoured; suffix (`-n`) and open (`a-`)
/// ranges and multi-range lists fall back to a whole read — correct, if
/// less efficient, and the media worker always sends `a-b`.
fn parse_range(header: &str) -> Option<(u64, u64)> {
	let r = header.trim().strip_prefix("bytes=")?;
	let (a, b) = r.split_once('-')?;
	let start: u64 = a.parse().ok()?;
	let end: u64 = b.parse().ok()?;
	(end >= start).then(|| (start, end - start + 1))
}

async fn http_text(status: u16, text: &str) -> Result<Response> {
	let h = Headers::new();
	h.set("Content-Type", "text/plain; charset=utf-8")?;
	let mut r = Response::from_bytes(text.as_bytes().to_vec())?;
	r = r.with_status(status).with_headers(h);
	Ok(r)
}

/// The share recipient page's CSP (also in web/public/_headers › /s.html).
const SHARE_PAGE_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

// ── Share plumbing (the Worker's half; the DO owns rows) ───────────────────

const SHARE_CHUNK: u64 = 8 * 1024 * 1024; // GC1 frames, one per part

/// Create a share. The ORDER is the security property (review, commit 23):
///
/// 1. validate the client-minted id (it becomes `shares/<id>` — ONE object
///    namespace for the whole deployment, not per member);
/// 2. **claim** the id in the registry's share index — write-once, so a
///    second claim (another member's, or a replay of our own) is a 409
///    before any S3 call happens;
/// 3. only then open the multipart upload and write the member's row;
///    if either fails, the claim is released so the id is not burned.
///
/// The old order was multipart → row → index `INSERT OR REPLACE`: a member
/// who had seen someone's link could mint a share with the same id,
/// re-point the public route to their own DO, and complete an upload over
/// the original sealed copy.
async fn share_create(env: &Env, member_id: &str, actor: String, mut body: serde_json::Value) -> Result<Response> {
	let Some(id) = body.get("id").and_then(|v| v.as_str()).map(str::to_string) else { return json_error(400, "id required") };
	// (The same shape rule the member DO and s.html apply: 22+ base64url.)
	if !(22..=64).contains(&id.len()) || !auth::valid_object_id(&id) {
		return json_error(400, "share id shape");
	}
	let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
	let frames = gorani_formats::chunked::frame_count(size, SHARE_CHUNK);
	let claim = forward_family(env, "internal", "POST", "shares-index", Some(serde_json::json!({ "id": id, "memberId": member_id }))).await?;
	if claim.status_code() >= 400 {
		return Ok(claim);
	}
	let object_key = format!("shares/{id}");
	let release = || async {
		let _ = do_request(&env.durable_object("FAMILY")?.id_from_name("family")?.get_stub()?, "DELETE", format!("shares-index/{id}"), None, Some("internal"), Some(member_id)).await;
		Ok::<(), Error>(())
	};
	let s3_upload_id = match s3::multipart_init(env, &object_key).await {
		Ok(u) => u,
		Err(e) => {
			release().await?;
			return Err(e);
		}
	};
	body["s3UploadId"] = serde_json::json!(s3_upload_id);
	let resp = forward_member(env, member_id, "POST", "files/shares", Some(body), actor).await?;
	if resp.status_code() >= 400 {
		let _ = s3::multipart_abort(env, &object_key, &s3_upload_id).await;
		release().await?;
		return Ok(resp);
	}
	Response::from_json(&serde_json::json!({ "parts": frames }))
}

async fn share_part(mut req: Request, env: Env, identity: &Identity, member_id: &str, share: &str, part: &str) -> Result<Response> {
	match member_ctx(&env, identity, member_id).await {
		Ok(_) => {}
		Err(resp) => return Ok(resp),
	}
	let meta = match share_obj(&env, member_id, share).await {
		Ok(m) => m,
		Err(resp) => return Ok(resp),
	};
	let Some(n) = part_number(part) else { return json_error(400, "part numbers are 1–10000") };
	let bytes = req.bytes().await?;
	let etag = s3::multipart_part(&env, &meta.object_key, &meta.s3_upload_id, n, bytes.to_vec()).await?;
	Response::from_json(&serde_json::json!({ "partNumber": n, "etag": etag }))
}

async fn share_complete(mut req: Request, env: Env, identity: &Identity, member_id: &str, share: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let meta = match share_obj(&env, member_id, share).await {
		Ok(m) => m,
		Err(resp) => return Ok(resp),
	};
	let body: serde_json::Value = req.json().await?;
	let parts: Vec<(u32, String)> = body
		.get("parts")
		.and_then(|p| serde_json::from_value(p.clone()).ok())
		.unwrap_or_default();
	s3::multipart_complete(&env, &meta.object_key, &meta.s3_upload_id, &parts).await?;
	// The same "must add up" rule as file uploads (review, commit 23): the
	// share was marked ready with whatever size the body claimed, and the
	// recipient's page trusts that size to know where the final frame is.
	let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
	let actual = s3::head(&env, &meta.object_key).await?.map(|h| h.size);
	if actual != Some(gorani_formats::chunked::sealed_size(size, SHARE_CHUNK)) {
		let _ = s3::delete(&env, &meta.object_key).await;
		return json_error(400, "the share copy does not add up to its declared size");
	}
	forward_member(&env, member_id, "POST", &format!("shares/{share}/complete"), Some(serde_json::json!({ "size": size })), &actor.email).await
}

async fn share_revoke(env: &Env, identity: &Identity, member_id: &str, share: &str) -> Result<Response> {
	let actor = match member_ctx(&env, identity, member_id).await {
		Ok(a) => a,
		Err(resp) => return Ok(resp),
	};
	let meta = match share_obj(&env, member_id, share).await {
		Ok(m) => m,
		Err(resp) => return Ok(resp),
	};
	let resp = forward_member(&env, member_id, "DELETE", &format!("shares/{share}"), None, &actor.email).await?;
	if resp.status_code() < 400 {
		let _ = s3::delete(env, &meta.object_key).await;
	}
	Ok(resp)
}

struct ShareObjMeta {
	object_key: String,
	s3_upload_id: String,
}

async fn share_obj(env: &Env, member_id: &str, share: &str) -> std::result::Result<ShareObjMeta, Response> {
	let resp = forward_member(env, member_id, "GET", &format!("shares/{share}/obj"), None, "internal").await;
	match resp {
		Ok(mut r) if r.status_code() == 200 => {
			let v: serde_json::Value = r.json().await.map_err(|e| json_error_raw(500, &e.to_string()))?;
			Ok(ShareObjMeta {
				object_key: v.get("objectKey").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
				s3_upload_id: v.get("s3UploadId").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
			})
		}
		Ok(r) => Err(r),
		Err(e) => Err(json_error_raw(500, &e.to_string())),
	}
}

// ── Backup plumbing ─────────────────────────────────────────────────────────

async fn backup_download(env: &Env, identity: &Identity, member_id: &str, stamp: &str) -> Result<Response> {
	match member_ctx(env, identity, member_id).await {
		Ok(_) => {}
		Err(resp) => return Ok(resp),
	}
	if !stamp.chars().all(|c| c.is_ascii_hexdigit()) {
		return json_error(400, "bad backup stamp");
	}
	// The DO answers from its manifest only (is this stamp ours?); the
	// bytes STREAM from storage straight to the caller. Before commit 23 the
	// DO downloaded the whole .gbak into memory, the router threw that copy
	// away and downloaded it again into memory — two full buffers of the
	// largest object in the system, inside a 128 MB isolate — and the read
	// also landed in the edge cache, where a pruned backup outlived its
	// retention by the cache's 30-day TTL.
	let manifest = forward_member(env, member_id, "GET", &format!("backups/{stamp}"), None, "internal").await?;
	if manifest.status_code() >= 400 {
		return Ok(manifest);
	}
	let mut origin = s3::stream_uncached(env, &format!("backups/{stamp}.gbak")).await?;
	if origin.status_code() != 200 {
		return json_error(404, "backup object missing");
	}
	let headers = Headers::new();
	headers.set("Content-Type", "application/octet-stream")?;
	headers.set("Content-Disposition", &format!("attachment; filename=\"gorani-{stamp}.gbak\""))?;
	headers.set("Cache-Control", "no-store")?;
	if let Some(len) = origin.headers().get("Content-Length")? {
		headers.set("Content-Length", &len)?;
	}
	Ok(Response::from_stream(origin.stream()?)?.with_headers(headers))
}

/// Fill a restored version's object: the client PUTs the SEALED bytes it
/// decrypted from the backup, to a key the restore call minted.
///
/// Three gates, each closing a hole the review found (commit 23):
///
/// 1. **Shape** — exactly `<area prefix>/<file id>/r-<id>` (the prefix is
///    `files/<member>` or `cases/<case>`, area.rs). The old
///    check was `starts_with("files/<member>/")`, which admitted every LIVE
///    object (`…/v-<uuid>`): a member — or any parent — could overwrite a
///    file's bytes in place, bypassing versions and the Trash, and (the
///    object keys being version-unique by design) the edge cache would go
///    on serving the old bytes while storage held new ones.
/// 2. **Minted** — the member DO must hold a version row pointing at this
///    exact key, i.e. the restore really created it.
/// 3. **Write-once** — an object that already exists is never replaced.
async fn backup_object_fill(mut req: Request, env: Env, identity: &Identity, member_id: &str) -> Result<Response> {
	if let Err(resp) = member_ctx(&env, identity, member_id).await {
		return Ok(resp);
	}
	let url = req.url()?;
	let raw = crate::files_store::urlquery(url.query().unwrap_or("")).get("k").cloned().unwrap_or_default();
	// (encodeURIComponent of a key in our alphabet only ever escapes '/'.)
	let key = raw.replace("%2F", "/").replace("%2f", "/");
	let prefix = format!("{}/", crate::area::key_prefix(member_id));
	let parts: Vec<&str> = key.strip_prefix(&prefix).map(|r| r.split('/').collect()).unwrap_or_default();
	let minted_shape = matches!(parts.as_slice(), [file, obj] if auth::valid_object_id(file) && obj.strip_prefix("r-").is_some_and(auth::valid_object_id));
	if !minted_shape {
		return json_error(403, "only objects a restore minted (<area>/<file>/r-…) can be filled");
	}
	let known = forward_member(&env, member_id, "GET", format!("restore-target/{}/{}", parts[0], parts[1]), None, "internal").await?;
	if known.status_code() != 200 {
		return json_error(403, "no restored version points at that key");
	}
	if s3::head(&env, &key).await?.is_some() {
		return json_error(409, "that restored object is already filled (write-once)");
	}
	let bytes = req.bytes().await?;
	s3::put(&env, &key, bytes.to_vec()).await?;
	Response::from_json(&serde_json::json!({ "ok": true }))
}

/// The caller's address as Cloudflare saw it (`CF-Connecting-IP`; absent
/// on the dev server, where every caller is "local").
fn client_ip(req: &Request) -> String {
	req.headers().get("CF-Connecting-IP").ok().flatten().unwrap_or_else(|| "local".into())
}

/// A 429 when `key` is over its limiter's budget (wrangler.jsonc ›
/// ratelimits), or None to proceed.
///
/// Fails OPEN — a missing binding or a limiter error lets the request
/// through — on purpose: the limiter is a mitigation against floods, not a
/// security boundary (that is the link secret, the claim token, the device
/// token). Cloudflare's limiter is also per location and eventually
/// consistent, so it bounds a flood, it does not count exactly; the WAF
/// rules in docs/PRODUCTION.md are the second layer.
async fn rate_limited(env: &Env, binding: &str, key: String) -> Option<Response> {
	let limiter = env.rate_limiter(binding).ok()?;
	match limiter.limit(key).await {
		Ok(outcome) if !outcome.success => {
			let resp = Response::from_json(&serde_json::json!({ "error": "too many requests — wait a minute" })).ok()?.with_status(429);
			let _ = resp.headers().set("Retry-After", "60");
			Some(resp)
		}
		_ => None,
	}
}

/// Percent-encode a query value (only what the read log's `client` needs).
fn urlencode(v: &str) -> String {
	v.bytes().map(|b| if b.is_ascii_alphanumeric() || b == b'-' || b == b':' { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}
