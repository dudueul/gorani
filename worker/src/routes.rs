// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The HTTP surface. One function, a small match, and two rules that never
//! bend:
//!
//! 1. **Authenticate first** (auth.rs) — before reading a body, before
//!    touching a DO. The authenticated email is forwarded to the DOs as
//!    `x-gorani-actor`; the DOs re-check role rules, so the routing layer
//!    cannot accidentally grant a parent's power to a child.
//! 2. **Every error is JSON** `{ "error": … }` with an honest status — the
//!    shape the SPA and the native clients parse.
//!
//! Routes land per commit: family registry (⑥), files (⑦), vault and
//! devices (⑧), shares (⑪).

use worker::*;

use crate::auth;
use crate::family::json_error;

pub async fn route(mut req: Request, env: Env) -> Result<Response> {
	let path = req.path();
	if !path.starts_with("/api/v1/") {
		return Response::error("Not Found", 404);
	}
	// Authenticate before anything else. Errors are 401 (or 503 for a
	// misconfigured deployment) as JSON, never HTML redirects.
	let identity = match auth::authenticate(&env, &req).await {
		Ok(id) => id,
		Err(e) => return json_error(401, &e.to_string()),
	};

	let rest = &path["/api/v1/".len()..];
	let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
	let method = req.method().to_string();

	match (method.as_str(), segments.as_slice()) {
		// ── The family registry (GoraniFamilyDO) ────────────────────────
		("GET", ["family"]) => forward_family(&env, &identity.email, "GET", "state", None).await,
		("POST", ["family", "members"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "POST", "members", Some(body)).await
		}
		("PATCH", ["family", "members", id]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PATCH", &format!("members/{id}"), Some(body)).await
		}
		("POST", ["family", "members", id, "deactivate"]) => {
			forward_family(&env, &identity.email, "POST", &format!("members/{id}/deactivate"), Some(serde_json::json!({}))).await
		}
		("PUT", ["family", "master"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", "master", Some(body)).await
		}
		_ => json_error(404, "no such route"),
	}
}

/// Call GoraniFamilyDO (`member:"family"`), forwarding the actor. The DO
/// returns complete responses (including its own 4xx JSON); this just
/// authenticates and relays.
async fn forward_family(env: &Env, actor: &str, method: &str, path: &str, body: Option<serde_json::Value>) -> Result<Response> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	let mut headers = Headers::new();
	headers.set("x-gorani-actor", actor)?;
	headers.set("Content-Type", "application/json")?;
	let request = Request::new_with_init(
		&format!("https://do.internal/{path}"),
		&RequestInit {
			method: method_of(method)?,
			headers,
			body: body.map(|b| b.to_string().into()),
			..Default::default()
		},
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