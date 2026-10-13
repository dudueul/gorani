// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The HTTP surface. One function, a small match, and three rules that never
//! bend:
//!
//! 1. **Authenticate first** (auth.rs) — before reading a body, before
//!    touching a DO.
//! 2. **Member scope is resolved through the registry**: a member acts for
//!    themselves; a **parent may act for any member** (the same one-way
//!    hierarchy the keys give, enforced at the API layer too — docs/FAMILY.md).
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

/// Which member an email belongs to (the registry's answer).
struct Actor {
	id: String,
	role: String,
	email: String,
}

/// Resolve the caller's registry row, then enforce the member scope:
/// themselves, or any member if they are a parent.
async fn member_ctx(env: &Env, identity: &Identity, id: &str) -> std::result::Result<String, Response> {
	let actor = match actor_of(env, &identity.email).await {
		Ok(Some(a)) => a,
		Ok(None) => return Err(json_error_raw(403, &format!("not a family member: {}", identity.email))),
		Err(e) => return Err(json_error_raw(500, &e.to_string())),
	};
	if actor.id == id || actor.role == "parent" {
		Ok(actor.email)
	} else {
		Err(json_error_raw(403, "children act only for themselves"))
	}
}

async fn actor_of(env: &Env, email: &str) -> Result<Option<Actor>> {
	let namespace = env.durable_object("FAMILY")?;
	let stub = namespace.id_from_name("family")?.get_stub()?;
	let mut headers = Headers::new();
	headers.set("x-gorani-actor", email)?;
	let request = Request::new_with_init("https://do.internal/actor", &RequestInit { method: Method::Get, headers, ..Default::default() })?;
	let resp = stub.fetch_with_request(request).await?;
	let mut resp = resp;
	let v: serde_json::Value = resp.json().await?;
	if v.is_null() {
		Ok(None)
	} else {
		Ok(Some(Actor {
			id: v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
			role: v.get("role").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
			email: email.to_string(),
		}))
	}
}

/// A JSON error as a plain Response (for the `Err(Response)` channel).
fn json_error_raw(status: u16, message: &str) -> Response {
	Response::from_json(&serde_json::json!({ "error": message })).unwrap().with_status(status)
}

pub async fn route(mut req: Request, env: Env) -> Result<Response> {
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

	match (method.as_str(), segments.as_slice()) {
		// ── The family registry (GoraniFamilyDO) ────────────────────────
		("GET", ["family"]) => forward_family(&env, &identity.email, "GET", "state", None).await,
		("POST", ["family", "members"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "POST", "members", Some(body)).await
		}
		("PATCH", ["family", "members", id]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PATCH", format!("members/{id}"), Some(body)).await
		}
		("POST", ["family", "members", id, "deactivate"]) => {
			forward_family(&env, &identity.email, "POST", format!("members/{id}/deactivate"), Some(serde_json::json!({}))).await
		}
		("PUT", ["family", "master"]) => {
			let body = req.json::<serde_json::Value>().await?;
			forward_family(&env, &identity.email, "PUT", "master", Some(body)).await
		}

		// ── Member vault (settings; devices arrive in commit ⑧) ─────────
		("GET", ["members", id, "vault"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "vault", None, actor)).await,
		("PUT", ["members", id, "vault"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PUT", "vault", Some(body), actor)).await
		}
		("GET", ["members", id, "audit"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "audit", None, actor)).await,

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
		("GET", ["members", id, "files", "match"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/match", &req, actor)).await,
		("GET", ["members", id, "files", "meta"]) => member_call(&env, &identity, id, |actor| forward_member_qs(&env, id, "GET", "files/meta", &req, actor)).await,
		("GET", ["members", id, "files", "secrets"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "files/secrets", None, actor)).await,
		("GET", ["members", id, "files", "trash"]) => member_call(&env, &identity, id, |actor| forward_member(&env, id, "GET", "files/trash", None, actor)).await,
		("POST", ["members", id, "files", "trash", "restore"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "POST", "files/trash/restore", Some(body), actor)).await
		}
		("PUT", ["members", id, "files", "reseal"]) => {
			let body = req.json::<serde_json::Value>().await?;
			member_call(&env, &identity, id, |actor| forward_member(&env, id, "PUT", "files/reseal", Some(body), actor)).await
		}
		// ── Devices (docs/DESKTOP.md): enrolment needs the member's unlocked
		// session or a parent; the device routes themselves authenticate with
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
						forward_member(&env, id, "DELETE", "vault", None, &actor).await
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

/// Run `f` with the acting email if the caller may act for this member.
async fn member_call<F, Fut>(env: &Env, identity: &Identity, id: &str, f: F) -> Result<Response>
where
	F: FnOnce(String) -> Fut,
	Fut: std::future::Future<Output = Result<Response>>,
{
	match member_ctx(env, identity, id).await {
		Ok(actor) => f(actor).await,
		Err(resp) => Ok(resp),
	}
}

/// A device call: the body passes through untouched. These routes skip the
/// member scope on purpose — the **device token** is the authority here (its
/// hash lives in exactly one member's DO, so a token from member A cannot
/// touch member B), and in production the perimeter is an Access service
/// token, not a member email.
async fn device_call(env: &Env, _identity: &Identity, member_id: &str, device: &str, what: &str, mut req: Request) -> Result<Response> {
	let token = req.headers().get("x-gorani-device-token")?;
	let body: serde_json::Value = req.json().await.unwrap_or(serde_json::json!({}));
	// The device token is forwarded as a header — the DO authenticates the
	// device with it (its hash lives in exactly one member's DO).
	let namespace = env.durable_object("MEMBER")?;
	let stub = namespace.id_from_name(&format!("member:{member_id}"))?.get_stub()?;
	let mut headers = Headers::new();
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
	do_request(&stub, method, path, body, Some(actor)).await
}

async fn forward_member(env: &Env, member_id: &str, method: &str, path: impl Into<String>, body: Option<serde_json::Value>, actor: impl Into<String>) -> Result<Response> {
	let namespace = env.durable_object("MEMBER")?;
	let stub = namespace.id_from_name(&format!("member:{member_id}"))?.get_stub()?;
	do_request(&stub, method, path, body, Some(actor.into().as_str())).await
}

/// Same, but carrying the caller's query string through (list/changes/match/meta).
async fn forward_member_qs(env: &Env, member_id: &str, method: &str, path: impl Into<String>, req: &Request, actor: impl Into<String>) -> Result<Response> {
	let qs = req.url()?.query().unwrap_or("").to_string();
	let path = path.into();
	let full = if qs.is_empty() { path } else { format!("{path}?{qs}") };
	forward_member(env, member_id, method, &full, None, actor.into().as_str()).await
}

async fn do_request(stub: &Stub, method: &str, path: impl Into<String>, body: Option<serde_json::Value>, actor: Option<&str>) -> Result<Response> {
	let mut headers = Headers::new();
	if let Some(a) = actor {
		headers.set("x-gorani-actor", a)?;
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
	const KNOWN: [&str; 11] = ["name", "type", "size", "folder_id", "ck", "tag", "base_version", "key", "chunk", "parts", "file_id"];
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

/// The sealed-shape checks every upload must pass before anything is stored:
/// bytes start with the GV02 magic, names and types are sealed text. This is
/// the zero-trust boundary in code — the Worker refuses anything else, with
/// a 400, not a 500 (a refusal is an expectation, not a fault).
fn check_sealed(file: &Option<Vec<u8>>, name: &Option<String>, type_sealed: &Option<String>) -> Result<(), String> {
	let bytes = file.as_ref().ok_or("missing file")?;
	if bytes.len() < 4 || &bytes[..4] != gorani_formats::formats::MAGIC_V2 {
		return Err("content must be sealed (GV02) bytes".into());
	}
	if let Some(n) = name {
		if !gorani_formats::formats::is_sealed_text(n) {
			return Err("name must be sealed text".into());
		}
	}
	if let Some(t) = type_sealed {
		if !gorani_formats::formats::is_sealed_text(t) {
			return Err("type must be sealed text".into());
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
	if let Err(msg) = check_sealed(&form.file, &name, &type_sealed) {
		return json_error(400, &msg);
	}
	let file_id = crate::files_store::uuid();
	let version_id = crate::files_store::uuid();
	let object_key = format!("files/{member_id}/{file_id}/v-{version_id}");
	s3::put(&env, &object_key, form.file.clone().unwrap_or_default()).await?;
	let body = serde_json::json!({
		"id": file_id,
		"folderId": form.fields.get("folder_id"),
		"name": name,
		"type": type_sealed,
		"size": form.fields.get("size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
		"ck": form.fields.get("ck"),
		"tag": form.fields.get("tag"),
		"objectKey": object_key,
		"bytesSealed": true,
	});
	let resp = forward_member(&env, member_id, "POST", "files/put", Some(body), &actor).await?;
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
	if let Err(msg) = check_sealed(&form.file, &name, &type_sealed) {
		return json_error(400, &msg);
	}
	let version_id = crate::files_store::uuid();
	let object_key = format!("files/{member_id}/{file_id}/v-{version_id}");
	s3::put(&env, &object_key, form.file.clone().unwrap_or_default()).await?;
	let body = serde_json::json!({
		"fileId": file_id,
		"baseVersion": form.fields.get("base_version").and_then(|s| s.parse::<u64>().ok()),
		"name": name,
		"type": type_sealed,
		"size": form.fields.get("size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
		"ck": form.fields.get("ck"),
		"tag": form.fields.get("tag"),
		"objectKey": object_key,
	});
	let resp = forward_member(&env, member_id, "POST", "files/versions", Some(body), &actor).await?;
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
	let file_id = body.get("fileId").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(crate::files_store::uuid);
	let object_key = format!("files/{member_id}/{file_id}/u-{}", crate::files_store::uuid());
	let started = forward_member(&env, member_id, "POST", "uploads/start", Some(serde_json::json!({ "objectKey": object_key, "fileId": body.get("fileId") })), &actor).await?;
	if started.status_code() >= 400 {
		return Ok(started);
	}
	let mut started = started;
	let started_body: serde_json::Value = started.json().await?;
	let upload_id: String = started_body.get("uploadId").and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| Error::RustError("no uploadId".into()))?;
	let s3_upload_id = s3::multipart_init(&env, &object_key).await?;
	forward_member(&env, member_id, "PUT", format!("uploads/{upload_id}/s3"), Some(serde_json::json!({ "s3UploadId": s3_upload_id })), &actor).await?;
	let chunk = body.get("chunk").and_then(|v| v.as_u64()).unwrap_or(8 * 1024 * 1024);
	let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
	let parts = ((size + chunk - 1) / chunk).max(1);
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
	let bytes = req.bytes().await?;
	let n: u32 = part.parse().map_err(|_| Error::RustError("bad part number".into()))?;
	let etag = s3::multipart_part(&env, &meta.object_key, &meta.s3_upload_id, n, bytes.to_vec()).await?;
	Response::from_json(&serde_json::json!({ "partNumber": n, "etag": etag }))
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
	s3::multipart_complete(&env, &meta.object_key, &meta.s3_upload_id, &parts).await?;
	// The completed object must add up: size + frames × 28 bytes (GC01).
	let size: u64 = form.fields.get("size").and_then(|s| s.parse().ok()).unwrap_or(0);
	let chunk: u64 = form.fields.get("chunk").and_then(|s| s.parse().ok()).unwrap_or(0);
	if let Some(head) = s3::head(&env, &meta.object_key).await? {
		let expected = gorani_formats::chunked::sealed_size(size, chunk.max(1));
		if head.size != expected {
			let _ = s3::multipart_abort(&env, &meta.object_key, &meta.s3_upload_id).await;
			return json_error(400, "the upload does not add up to its declared size");
		}
	}
	let body = serde_json::json!({
		"ck": form.fields.get("ck"),
		"name": form.fields.get("name"),
		"type": form.fields.get("type"),
		"size": size,
		"chunkSize": chunk,
		"folderId": form.fields.get("folder_id"),
		"baseVersion": form.fields.get("base_version").and_then(|s| s.parse::<u64>().ok()),
		"tag": form.fields.get("tag"),
		"key": form.fields.get("key"),
		// The Worker's attestation: the object added up to its declared size
		// (size + frames × 28). GC01 frames carry no magic — their sealing is
		// proven by opening, and the DO records what it was told after the
		// checks above passed.
		"bytesSealed": true,
	});
	let resp = forward_member(&env, member_id, "POST", format!("uploads/{upload_id}/complete"), Some(body), &actor).await?;
	if resp.status_code() >= 400 {
		// Refused (a 409 conflict, say) — abort the parts so nothing lingers.
		let _ = s3::multipart_abort(&env, &meta.object_key, &meta.s3_upload_id).await;
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
	forward_member(&env, member_id, "DELETE", format!("uploads/{upload_id}"), None, &actor).await
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
	match member_ctx(&env, identity, member_id).await {
		Ok(_) => {}
		Err(resp) => return Ok(resp),
	}
	let version = crate::files_store::urlquery(req.url()?.query().unwrap_or("")).get("version").and_then(|v| v.parse::<i64>().ok());
	let meta = forward_member(&env, member_id, "GET", &format!("files-object/{file_id}?version={}", version.map(|v| v.to_string()).unwrap_or_default()), None, "internal").await;
	let meta = match meta {
		Ok(mut r) if r.status_code() == 200 => r.json::<serde_json::Value>().await?,
		Ok(r) => return Ok(r),
		Err(e) => return json_error(500, &e.to_string()),
	};
	let object_key = meta.get("objectKey").and_then(|x| x.as_str()).unwrap_or_default().to_string();
	let range: Option<(u64, u64)> = req
		.headers()
		.get("Range")?
		.and_then(|r| {
			let r = r.trim().strip_prefix("bytes=")?;
			let mut it = r.split('-');
			let start: u64 = it.next()?.parse().ok()?;
			let end: u64 = it.next()?.parse().ok()?;
			if end < start {
				return None;
			}
			Some((start, end - start + 1))
		});
	let mut s3_resp = s3::fetch_stream(&env, "GET", &object_key, range, &[]).await?;
	let status = s3_resp.status_code();
	if status != 200 && status != 206 {
		return Response::error("Not Found", 404);
	}
	let mut headers = Headers::new();
	headers.set("Content-Type", "application/octet-stream")?;
	headers.set("Accept-Ranges", "bytes")?;
	if let Some(ck) = meta.get("ck").and_then(|x| x.as_str()) {
		headers.set("x-gorani-ck", ck)?;
	}
	if let Some(kid) = meta.get("vaultKeyId").and_then(|x| x.as_str()) {
		headers.set("x-gorani-vault-key-id", kid)?;
	}
	if let Some(chunk) = meta.get("chunk").and_then(|x| x.as_u64()) {
		if chunk > 0 {
			headers.set("x-gorani-chunk", &chunk.to_string())?;
		}
	}
	if let Some(len) = s3_resp.headers().get("Content-Length")? {
		headers.set("Content-Length", &len)?;
	}
	if let Some(cr) = s3_resp.headers().get("Content-Range")? {
		headers.set("Content-Range", &cr)?;
	}
	let stream = s3_resp.stream()?;
	Ok(Response::from_stream(stream)?.with_status(status).with_headers(headers))
}
// ── Public share routes (GS01) ──────────────────────────────────────────────
// /s/f/<id>          the sealed share page (served from the asset s.html)
// /s/f/<id>/meta     { metaSealed, kdf, expiresAt, downloadsLeft }
// /s/f/<id>/claim    one download — decrements the counter
// /s/f/<id>/data     the sealed copy (GC1 frames under the link's data key)
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
			let mut headers = Headers::new();
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
			// Serve the self-contained recipient page. s.html lives outside
			// /s/* (the asset server owns it), so this self-fetch cannot loop.
			let origin = { let url = req.url()?; format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()) };
			let page = Fetch::Url(Url::parse(&format!("{origin}/s.html")).map_err(|_| Error::RustError("page missing".into()))?).send().await?;
			let mut page = page;
			let body = page.bytes().await?;
			let mut headers = Headers::new();
			headers.set("Content-Type", "text/html; charset=utf-8")?;
			headers.set("Cache-Control", "no-store")?;
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
			// State check via the DO, then stream the sealed object from S3.
			let resp = do_call(format!("shares/{id}/public-object"), Some(serde_json::json!({}))).await?;
			let mut resp = resp;
			let status = resp.status_code();
			if status >= 400 {
				return Ok(resp);
			}
			let v: serde_json::Value = resp.json().await?;
			let object = v.get("objectKey").and_then(|x| x.as_str()).unwrap_or_default().to_string();
			let range_header = req.headers().get("Range")?.unwrap_or_default();
			let range = parse_range(&range_header);
			let mut s3_resp = s3::fetch_stream(&env, "GET", &object, range, &[]).await?;
			let mut s3_resp = s3_resp;
			let mut headers = Headers::new();
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


/// Range header → (start, end) for the S3 fetch (the plaintext is sealed
/// ciphertext; the recipient's ranges pass through verbatim).
fn parse_range(header: &str) -> Option<(u64, u64)> {
	let r = header.trim().strip_prefix("bytes=")?;
	let mut it = r.split('-');
	let start: u64 = it.next()?.parse().ok()?;
	let end: u64 = it.next()?.parse().ok()?;
	if end < start {
		return None;
	}
	Some((start, end))
}

async fn http_text(status: u16, text: &str) -> Result<Response> {
	let mut h = Headers::new();
	h.set("Content-Type", "text/plain; charset=utf-8")?;
	let mut r = Response::from_bytes(text.as_bytes().to_vec())?;
	r = r.with_status(status).with_headers(h);
	Ok(r)
}

// ── Share plumbing (the Worker's half; the DO owns rows) ───────────────────

const SHARE_CHUNK: u64 = 8 * 1024 * 1024; // GC1 frames, one per part

async fn share_create(env: &Env, member_id: &str, actor: String, mut body: serde_json::Value) -> Result<Response> {
	let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
	let frames = gorani_formats::chunked::frame_count(size, SHARE_CHUNK);
	let object_key = format!("shares/{}", body.get("id").and_then(|v| v.as_str()).unwrap_or_default());
	let s3_upload_id = s3::multipart_init(env, &object_key).await?;
	body["s3UploadId"] = serde_json::json!(s3_upload_id);
	let resp = forward_member(env, member_id, "POST", "files/shares", Some(body), actor).await?;
	if resp.status_code() >= 400 {
		let _ = s3::multipart_abort(env, &object_key, &s3_upload_id).await;
		return Ok(resp);
	}
	// The public /s/f/:id routes resolve the owner through the registry's
	// share index (the share id alone must find its member DO).
	let index = forward_family(env, "internal", "POST", "shares-index", Some(serde_json::json!({ "id": object_key.trim_start_matches("shares/"), "memberId": member_id }))).await?;
	if index.status_code() >= 400 {
		return Ok(index);
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
	let bytes = req.bytes().await?;
	let n: u32 = part.parse().map_err(|_| Error::RustError("bad part number".into()))?;
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
	let size = body.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
	forward_member(&env, member_id, "POST", &format!("shares/{share}/complete"), Some(serde_json::json!({ "size": size })), &actor).await
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
	let resp = forward_member(&env, member_id, "DELETE", &format!("shares/{share}"), None, &actor).await?;
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
