// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Seongwoo Hong's modified version; Apache 2.0, original © Cloudflare, Inc.); see NOTICE.

//! The HTTP layer: every endpoint of docs/DESKTOP.md, one method each. In
//! production the member signs in through Access — their token rides every
//! request as `cf-access-token` (commit 33a); in dev, the dev-email header.
//! Blocking ureq on the CLI's own thread.

use serde_json::{json, Value};

use crate::{DeviceProfile, Error};

pub use gorani_formats::unlock::UnlockMethod;

/// The vault settings as the client reads them (the subset it needs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
	#[serde(default)]
	pub enabled: bool,
	pub key_id: String,
	#[serde(default)]
	pub methods: Vec<gorani_formats::unlock::UnlockMethod>,
	#[serde(default)]
	pub stores: std::collections::BTreeMap<String, StoreKey>,
	/// The member's identity (commit 27; read by the CLI from commit 33c):
	/// their signing key sealed to the root, and the identities they pinned
	/// — MAC'd by the root (identity.rs). The web app creates it.
	#[serde(default)]
	pub identity: Option<crate::identity::IdentityRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreKey {
	pub key_id: String,
	pub public_key: Jwk,
	#[serde(default)]
	pub pq_public_key: Option<String>,
	pub private_key_sealed: String,
	/// The record's MAC under the member's root-derived record key
	/// (gorani_formats::records — docs/SECURITY-REVIEW.md › O3).
	#[serde(default)]
	pub mac: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Jwk {
	pub x: String,
	pub y: String,
	/// `EC` / `P-256` when present (identity.rs refuses any other).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub kty: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub crv: Option<String>,
}

pub struct Client {
	pub profile: DeviceProfile,
	/// Which store the file routes address (lib/area.ts' twin): the member's
	/// own (`<member>`, the default) or a case (`case:<id>`, commit 33c). The
	/// vault and the devices are always the member's own.
	area: String,
	agent: ureq::Agent,
	/// The member's Access token (commit 33a), with when it stops being
	/// good. Until 40a it was fetched once per process, so a shell left
	/// running past the Access session (a day, by default) was refused on
	/// every request until restarted. The desktop apps run for weeks at a
	/// time, so it is fetched again shortly before its `exp`.
	access_token: std::sync::Mutex<Option<CachedToken>>,
}

/// A fetched token and the moment to fetch the next one.
struct CachedToken {
	token: Option<String>,
	refresh_at: u64,
}

/// Fetch again this long before a token's `exp`, and at least this often
/// when its `exp` cannot be read (`cloudflared access token` only reads
/// its cached file, so asking is cheap).
const TOKEN_MARGIN_SECS: u64 = 120;
const TOKEN_RECHECK_SECS: u64 = 15 * 60;

fn now_secs() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A JWT's `exp`, read WITHOUT checking its signature. That is safe here:
/// it is only used to decide when to fetch the next token. Access and the
/// Worker check the token itself on every request.
pub fn jwt_exp(token: &str) -> Option<u64> {
	use base64::Engine;
	let payload = token.split('.').nth(1)?;
	let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
	serde_json::from_slice::<Value>(&bytes).ok()?.get("exp")?.as_u64()
}

/// When to fetch again after getting `token` at `now`.
fn refresh_at(token: Option<&str>, now: u64) -> u64 {
	match token.and_then(jwt_exp) {
		Some(exp) => exp.saturating_sub(TOKEN_MARGIN_SECS).clamp(now + 30, now + TOKEN_RECHECK_SECS),
		None => now + TOKEN_RECHECK_SECS,
	}
}

/// The member's Access token: `GORANI_ACCESS_TOKEN`, else the profile's
/// command's output (trimmed). None when neither is set — dev mode, or a
/// deployment that signs in some other way. A command that fails is an
/// error the caller sees on its first request, not a silent anonymous call.
pub fn access_token_from(env_token: Option<String>, cmd: Option<&str>) -> Result<Option<String>, Error> {
	if let Some(t) = env_token.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
		return Ok(Some(t));
	}
	let Some(cmd) = cmd.map(str::trim).filter(|c| !c.is_empty()) else { return Ok(None) };
	// Split as a command line, quotes grouping (scan.rs, no shell): the
	// Windows installer puts cloudflared under "C:\Program Files (x86)",
	// which a plain whitespace split cut in three (until 40a).
	let words = crate::scan::split_words(cmd).map_err(|_| Error::Config("the access token command has an unclosed quote".into()))?;
	let (program, args) = words.split_first().ok_or_else(|| Error::Config("the access token command is empty".into()))?;
	let mut command = std::process::Command::new(program);
	command.args(args);
	hide_console(&mut command);
	let out = command.output().map_err(|e| Error::Config(format!("the access token command ({program}) did not run: {e}")))?;
	if !out.status.success() {
		return Err(Error::Config(format!("the access token command failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
	}
	let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
	if token.is_empty() || token.contains(char::is_whitespace) {
		return Err(Error::Config("the access token command printed no token (sign in first: cloudflared access login <host>)".into()));
	}
	Ok(Some(token))
}

/// A program run from a window (the desktop apps) must not flash a console
/// window on Windows each time it asks for a token.
pub fn hide_console(command: &mut std::process::Command) {
	#[cfg(windows)]
	{
		use std::os::windows::process::CommandExt;
		const CREATE_NO_WINDOW: u32 = 0x0800_0000;
		command.creation_flags(CREATE_NO_WINDOW);
	}
	#[cfg(not(windows))]
	let _ = command;
}

impl Client {
	pub fn new(profile: DeviceProfile) -> Self {
		// (platform shells swap in the system TLS connector; the CLI uses rustls)
		// Timeouts are hygiene: a stuck request must FAIL (and say so) in
		// seconds, not hang the command for workerd's ~293 s wall clock —
		// the ureq multipart hang (live test) is exactly why this exists.
		let b = ureq::AgentBuilder::new()
			.redirects(0)
			.timeout_connect(std::time::Duration::from_secs(15))
			.timeout(std::time::Duration::from_secs(60));
		let area = profile.member.clone();
		Self { profile, area, agent: b.build(), access_token: std::sync::Mutex::new(None) }
	}

	/// The same client, its file routes addressing `area` (`case:<id>`).
	pub fn in_area(mut self, area: &str) -> Self {
		self.area = area.into();
		self
	}

	pub fn area(&self) -> &str {
		&self.area
	}

	fn server(&self) -> &str {
		self.profile.server.trim_end_matches('/')
	}

	/// The member's own routes (vault, devices).
	fn url(&self, rest: &str) -> String {
		format!("{}/api/v1/members/{}{rest}", self.server(), self.profile.member)
	}

	/// The area's routes (files): a case's are `/api/v1/cases/<id>/…`, where
	/// the Worker checks the caller's grant once and rewrites them to the
	/// same store routes a member's own area has.
	fn area_url(&self, rest: &str) -> String {
		match self.area.strip_prefix("case:") {
			Some(case) => format!("{}/api/v1/cases/{case}{rest}", self.server()),
			None => format!("{}/api/v1/members/{}{rest}", self.server(), self.area),
		}
	}

	/// The member's token: fetched on first use, and again shortly before
	/// it expires (40a). A failed fetch is not cached for long, so signing
	/// in again (`cloudflared access login`) is picked up within a minute.
	fn member_token(&self) -> Option<String> {
		let now = now_secs();
		let mut cached = self.access_token.lock().unwrap_or_else(|p| p.into_inner());
		if let Some(c) = cached.as_ref().filter(|c| now < c.refresh_at) {
			return c.token.clone();
		}
		let (token, refresh) = match access_token_from(std::env::var("GORANI_ACCESS_TOKEN").ok(), self.profile.access_token_cmd.as_deref()) {
			Ok(t) => {
				let at = refresh_at(t.as_deref(), now);
				(t, at)
			}
			Err(e) => {
				eprintln!("gorani: {e}");
				(None, now + 60)
			}
		};
		*cached = Some(CachedToken { token: token.clone(), refresh_at: refresh });
		token
	}

	fn req(&self, method: &str, url: &str) -> ureq::Request {
		let mut r = self.agent.request(method, url);
		// The CLI never wants compressed bodies: ciphertext passes through
		// unchanged and JSON answers are tiny. Asking for compression is also
		// measurably harmful against workerd — its streaming paths stall
		// ~5 s per request when the client sends `Accept-Encoding: deflate,
		// gzip` (ureq's default; bisected in the live-test session). Setting
		// `identity` explicitly both opts out and stops ureq adding its own.
		r = r.set("Accept-Encoding", "identity");
		// The member, signed in through Access (commit 33a): their token, which
		// Access validates and hands the Worker as the member's JWT.
		if let Some(token) = self.member_token() {
			r = r.set("cf-access-token", &token);
		}
		if let (Some(id), Some(secret)) = (&self.profile.access_id, &self.profile.access_secret) {
			r = r.set("CF-Access-Client-Id", id).set("CF-Access-Client-Secret", secret);
		}
		if let Some(email) = &self.profile.dev_email {
			// Dev mode only (GORANI_DEV=1 on the worker); ignored in production.
			r = r.set("x-gorani-dev-email", email);
		}
		r
	}

	fn json(&self, method: &str, rest: &str, body: Option<Value>) -> Result<Value, Error> {
		self.json_at(method, &self.url(rest), body)
	}

	fn area_json(&self, method: &str, rest: &str, body: Option<Value>) -> Result<Value, Error> {
		self.json_at(method, &self.area_url(rest), body)
	}

	/// A team route (`/api/v1/<path>`): the registry's identities, the cases.
	pub fn team_get(&self, path: &str) -> Result<Value, Error> {
		self.json_at("GET", &format!("{}/api/v1/{path}", self.server()), None)
	}

	fn json_at(&self, method: &str, url: &str, body: Option<Value>) -> Result<Value, Error> {
		let r = self.req(method, url);
		let res = match body {
			Some(b) => r.send_json(b),
			None => r.call(),
		}
		.map_err(|e| match e {
			ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
			other => Error::Config(other.to_string()),
		})?;
		res.into_json::<Value>().map_err(|e| Error::Config(format!("bad answer: {e}")))
	}

	// ── the vault ───────────────────────────────────────────────────────

	pub fn vault(&self) -> Result<VaultSettings, Error> {
		let v = self.json("GET", "/vault", None)?;
		serde_json::from_value(v.get("settings").cloned().unwrap_or(v)).map_err(|e| Error::Config(format!("settings: {e}")))
	}

	// ── devices ─────────────────────────────────────────────────────────

	pub fn enrol(&self, name: &str, platform: &str, key_id: &str, wrapped: &str, salt: &str, protection: &str) -> Result<(String, String), Error> {
		let v = self.json(
			"POST",
			"/devices",
			Some(json!({ "name": name, "platform": platform, "appVersion": env!("CARGO_PKG_VERSION"), "keyId": key_id, "wrapped": wrapped, "salt": salt, "protection": protection })),
		)?;
		let device_id = v["deviceId"].as_str().unwrap_or_default().to_string();
		let token = v["token"].as_str().unwrap_or_default().to_string();
		Ok((device_id, token))
	}

	/// This computer's wrapped root copy and its salt (only to this
	/// device's token), with the vault settings: `(keyId, wrapped, salt, settings)`.
	pub fn unlock(&self, device_id: &str, token: &str) -> Result<(String, String, String, VaultSettings), Error> {
		let res = self
			.req("POST", &self.url(&format!("/devices/{device_id}/unlock")))
			.set("x-gorani-device-token", token)
			.send_json(json!({ "appVersion": env!("CARGO_PKG_VERSION") }))
			.map_err(|e| match e {
				ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
				other => Error::Config(other.to_string()),
			})?;
		let v: Value = res.into_json().map_err(|e| Error::Config(e.to_string()))?;
		Ok((
			v["keyId"].as_str().unwrap_or_default().to_string(),
			v["wrapped"].as_str().unwrap_or_default().to_string(),
			v["salt"].as_str().unwrap_or_default().to_string(),
			serde_json::from_value(v["settings"].clone()).map_err(|e| Error::Config(format!("settings: {e}")))?,
		))
	}

	/// Who the server says is signed in (`GET /api/v1/me`): the Access email,
	/// and the team account it belongs to, or null. Needs no member id, so
	/// the desktop apps can fill it in for the person (40a).
	pub fn me(&self) -> Result<Value, Error> {
		self.team_get("me")
	}

	/// This computer leaves (`POST …/devices/<id>/leave`, with its own
	/// token): the server deletes its wrapped copy of the root. Sign out
	/// (settings.rs) calls it before forgetting the local parts.
	pub fn leave(&self, device_id: &str, token: &str) -> Result<(), Error> {
		self.req("POST", &self.url(&format!("/devices/{device_id}/leave")))
			.set("x-gorani-device-token", token)
			.send_json(json!({}))
			.map_err(|e| match e {
				ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
				other => Error::Config(other.to_string()),
			})?;
		Ok(())
	}

	/// The member's devices (`GET …/devices`): name, platform, protection, last seen.
	pub fn devices(&self) -> Result<Value, Error> {
		self.json("GET", "/devices", None)
	}

	/// Revoke a device: its wrapped copy is deleted, so it never unlocks
	/// again. The member's sign-in is enough — a lost laptop is revoked from
	/// any other one.
	pub fn revoke_device(&self, device_id: &str) -> Result<(), Error> {
		self.json("DELETE", &format!("/devices/{device_id}"), None).map(|_| ())
	}

	/// Replace this device's wrapped copy (after a root rotation, or when
	/// its secret moves to new protectors — commit 34). Only to its token.
	pub fn rekey(&self, device_id: &str, token: &str, key_id: &str, wrapped: &str, salt: &str, protection: &str) -> Result<(), Error> {
		self.req("PUT", &self.url(&format!("/devices/{device_id}/key")))
			.set("x-gorani-device-token", token)
			.send_json(json!({ "keyId": key_id, "wrapped": wrapped, "salt": salt, "protection": protection }))
			.map_err(|e| match e {
				ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
				other => Error::Config(other.to_string()),
			})?;
		Ok(())
	}

	// ── files ───────────────────────────────────────────────────────────

	pub fn changes(&self, since: u64) -> Result<(u64, Vec<Value>), Error> {
		let v = self.area_json("GET", &format!("/files/changes?since={since}&limit=1000"), None)?;
		Ok((v["cursor"].as_u64().unwrap_or(since), v["changes"].as_array().cloned().unwrap_or_default()))
	}

	/// One page of the change feed: `(cursor, more, changes)`. The feed is
	/// the "something changed" signal; `list` is the state (the journal is
	/// pruned after its retention, so it cannot rebuild a tree from 0).
	pub fn changes_page(&self, since: u64, limit: u32) -> Result<(u64, bool, Vec<Value>), Error> {
		let v = self.area_json("GET", &format!("/files/changes?since={since}&limit={limit}"), None)?;
		Ok((v["cursor"].as_u64().unwrap_or(since), v["more"].as_bool().unwrap_or(false), v["changes"].as_array().cloned().unwrap_or_default()))
	}

	/// One page of every living file, with every folder (`files/list?folder=all`).
	/// An area's sealed files secrets (`{fp, idx}`, placed into
	/// `store.secrets`) — None before any browser made them. The area is
	/// named, not taken from `in_area`: open_area asks before the client is
	/// scoped to the area it is opening.
	pub fn files_secrets_of(&self, area: &str) -> Result<Option<String>, Error> {
		let url = match area.strip_prefix("case:") {
			Some(case) => format!("{}/api/v1/cases/{case}/files/secrets", self.server()),
			None => format!("{}/api/v1/members/{area}/files/secrets", self.server()),
		};
		let v = self.json_at("GET", &url, None)?;
		Ok(v.get("sealed").and_then(|s| s.as_str()).map(str::to_string))
	}

	/// The live files of exactly `size` bytes, each with its duplicate tag,
	/// folder and sealed name (the duplicate check, commit 39n).
	pub fn files_match(&self, size: u64) -> Result<Vec<Value>, Error> {
		let v = self.area_json("GET", &format!("/files/match?size={size}"), None)?;
		Ok(v.get("files").and_then(|f| f.as_array()).cloned().unwrap_or_default())
	}

	pub fn list(&self, offset: u64, limit: u32) -> Result<Value, Error> {
		self.area_json("GET", &format!("/files/list?folder=all&offset={offset}&limit={limit}"), None)
	}

	/// A whole new version after `base_version` (in `fields`): 409 when the
	/// file moved on since — the caller decides what to do with its bytes.
	pub fn upload_version(&self, id: &str, fields: &UploadFields, sealed: &[u8]) -> Result<Value, Error> {
		self.post_form(&format!("/files/{id}/versions"), fields, Some(sealed))
	}

	/// Rename (a sealed name) and/or move (`folderId`, null = the top).
	pub fn patch_file(&self, id: &str, body: Value) -> Result<Value, Error> {
		self.area_json("PATCH", &format!("/files/{id}"), Some(body))
	}

	/// To the Trash (an evidence case refuses: evidence is not deleted).
	pub fn trash_file(&self, id: &str) -> Result<Value, Error> {
		self.area_json("DELETE", &format!("/files/{id}"), None)
	}

	/// A folder whose id the client chose (its name is sealed into a place naming it).
	pub fn create_folder(&self, id: &str, name_sealed: &str, parent: Option<&str>) -> Result<Value, Error> {
		self.area_json("POST", "/files/folders", Some(json!({ "id": id, "name": name_sealed, "parentId": parent })))
	}

	pub fn patch_folder(&self, id: &str, body: Value) -> Result<Value, Error> {
		self.area_json("PATCH", &format!("/files/folders/{id}"), Some(body))
	}

	pub fn trash_folder(&self, id: &str) -> Result<Value, Error> {
		self.area_json("DELETE", &format!("/files/folders/{id}"), None)
	}

	pub fn keys(&self, ids: &[String]) -> Result<Value, Error> {
		self.area_json("POST", "/files/keys", Some(json!({ "ids": ids })))
	}

	/// Fetch a version's sealed object (Range honoured; chunked objects are
	/// fetched frame-aligned by the caller).
	pub fn fetch(&self, id: &str, version: Option<u64>, range: Option<(u64, u64)>) -> Result<Vec<u8>, Error> {
		// No version → no query: the server serves the living version. (This
		// sent `?version=0` and only worked because the server ignored the
		// query entirely — the bug fixed in commit 23, S17.)
		let query = version.map(|v| format!("?version={v}")).unwrap_or_default();
		// `x-gorani-client`: what kind of client read this, for the read log
		// (O14) — a description, not a credential.
		let mut r = self.req("GET", &self.area_url(&format!("/files/{id}{query}"))).set("x-gorani-client", "cli");
		if let Some((a, b)) = range {
			r = r.set("Range", &format!("bytes={a}-{}", b.saturating_sub(1)));
		}
		let res = r.call().map_err(|e| match e {
			ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
			other => Error::Config(other.to_string()),
		})?;
		let mut out = Vec::new();
		res.into_reader().read_to_end(&mut out)?;
		Ok(out)
	}

	// ── a case's inbox (commit 37c, inbox.rs) ──────────────────────────

	/// The area's inbox (a case's): every item, sealed halves and all.
	pub fn inbox(&self) -> Result<Value, Error> {
		self.area_json("GET", "/inbox", None)
	}

	/// A member's own inbox keys (commit 38a): `GET members/<id>/inbox-keys`.
	pub fn area_inbox_keys(&self) -> Result<Value, Error> {
		self.area_json("GET", "/inbox-keys", None)
	}

	/// The area's upload links (commit 38b) — their labels sealed with the area's key.
	pub fn requests(&self) -> Result<Value, Error> {
		self.area_json("GET", "/requests", None)
	}

	/// A team route, POSTed (`/api/v1/<path>`): the opt-in hash lookup.
	pub fn team_post(&self, path: &str, body: Value) -> Result<Value, Error> {
		self.json_at("POST", &format!("{}/api/v1/{path}", self.server()), Some(body))
	}

	/// An inbox item's sealed bytes (Range honoured, as `fetch`).
	pub fn fetch_inbox(&self, item: &str, range: Option<(u64, u64)>) -> Result<Vec<u8>, Error> {
		let mut r = self.req("GET", &self.area_url(&format!("/inbox/{item}"))).set("x-gorani-client", "cli");
		if let Some((a, b)) = range {
			r = r.set("Range", &format!("bytes={a}-{}", b.saturating_sub(1)));
		}
		let res = r.call().map_err(|e| match e {
			ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
			other => Error::Config(other.to_string()),
		})?;
		let mut out = Vec::new();
		res.into_reader().read_to_end(&mut out)?;
		Ok(out)
	}

	/// `accept` or `reject` an inbox item.
	pub fn inbox_decide(&self, item: &str, decision: &str, body: Value) -> Result<Value, Error> {
		self.area_json("POST", &format!("/inbox/{item}/{decision}"), Some(body))
	}

	pub fn ck_of(&self, id: &str) -> Result<String, Error> {
		let keys = self.keys(&[id.to_string()])?;
		Ok(keys["keys"][id]["key"].as_str().unwrap_or_default().to_string())
	}

	/// Whole upload (≤ 48 MB plaintext): sealed GV02 under the file's content key.
	pub fn upload_whole(&self, fields: &UploadFields, sealed: &[u8]) -> Result<Value, Error> {
		self.post_form("/files", fields, Some(sealed))
	}

	/// A multipart upload's plan (D12, commit 33b): the Worker checks it
	/// against the limits (255 GiB, 64 MiB chunks, 10 000 parts).
	pub fn upload_start(&self, size: u64, chunk: u64, new_file_id: &str) -> Result<(String, String, u64), Error> {
		self.upload_start_for(size, chunk, new_file_id, false)
	}

	/// The same plan for a new file (`existing` false: the client chose its
	/// id) or a new VERSION of an existing one (commit 39a: a sync shell
	/// saves large files that were edited in place).
	pub fn upload_start_for(&self, size: u64, chunk: u64, file_id: &str, existing: bool) -> Result<(String, String, u64), Error> {
		let body = if existing { json!({ "size": size, "chunk": chunk, "fileId": file_id }) } else { json!({ "size": size, "chunk": chunk, "newFileId": file_id }) };
		let v = self.area_json("POST", "/files/uploads", Some(body))?;
		Ok((v["uploadId"].as_str().unwrap_or_default().to_string(), v["key"].as_str().unwrap_or_default().to_string(), v["parts"].as_u64().unwrap_or(0)))
	}

	/// One part (one GC01 frame). What the network lost is sent again —
	/// three tries, 1 s then 4 s apart, for a dropped connection, a 5xx or
	/// a 429; a refusal (any other 4xx) is the server's answer, at once.
	pub fn upload_part(&self, upload_id: &str, object_key: &str, n: u64, frame: &[u8]) -> Result<String, Error> {
		let url = self.area_url(&format!("/files/uploads/{upload_id}/{n}?key={}", percent(object_key)));
		let mut last = String::new();
		for attempt in 0..3u32 {
			if attempt > 0 {
				std::thread::sleep(std::time::Duration::from_secs(4u64.pow(attempt - 1)));
			}
			match self.req("PUT", &url).set("Content-Type", "application/octet-stream").send_bytes(frame) {
				Ok(res) => {
					let v: Value = res.into_json().map_err(|e| Error::Config(format!("bad answer: {e}")))?;
					return v["etag"].as_str().map(str::to_string).ok_or_else(|| Error::Config("the part's answer had no etag".into()));
				}
				Err(ureq::Error::Status(code, resp)) if code < 500 && code != 429 => return Err(Error::Http(code, resp.into_string().unwrap_or_default())),
				Err(e) => last = e.to_string(),
			}
		}
		Err(Error::Config(format!("part {n} failed three times: {last}")))
	}

	/// Complete a multipart upload: the Worker checks the object adds up.
	pub fn upload_complete(&self, upload_id: &str, fields: &UploadFields) -> Result<Value, Error> {
		self.post_form(&format!("/files/uploads/{upload_id}/complete"), fields, None)
	}

	fn post_form(&self, rest: &str, fields: &UploadFields, file: Option<&[u8]>) -> Result<Value, Error> {
		let boundary = format!("gorani{:032x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
		let mut body = Vec::new();
		for (k, v) in &fields.form {
			body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes());
		}
		if let Some(sealed) = file {
			body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sealed.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
			body.extend_from_slice(sealed);
			body.extend_from_slice(b"\r\n");
		}
		body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
		let res = self
			.req("POST", &self.area_url(rest))
			.set("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
			.send_bytes(&body)
			.map_err(|e| match e {
				ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
				other => Error::Config(other.to_string()),
			})?;
		let status = res.status();
		let v: Value = res.into_json().map_err(|e| Error::Config(e.to_string()))?;
		if status >= 400 {
			return Err(Error::Http(status, v.to_string()));
		}
		Ok(v)
	}
}

/// Percent-encode a query value (RFC 3986 unreserved characters pass).
fn percent(s: &str) -> String {
	s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub struct UploadFields {
	pub form: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
	use super::{access_token_from, jwt_exp, refresh_at, TOKEN_MARGIN_SECS, TOKEN_RECHECK_SECS};

	#[test]
	fn a_quoted_program_path_runs_whole() {
		// "C:\Program Files (x86)\cloudflared\cloudflared.exe" access token …
		// is one program: quotes group, as on a command line (40a).
		assert_eq!(access_token_from(None, Some("\"echo\" ey.quoted")).unwrap().as_deref(), Some("ey.quoted"));
		assert!(access_token_from(None, Some("\"echo ey.open")).unwrap_err().to_string().contains("unclosed quote"));
	}

	#[test]
	fn a_token_is_fetched_again_before_it_expires() {
		use base64::Engine;
		let b64 = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
		let token = |exp: u64| format!("{}.{}.sig", b64(r#"{"alg":"RS256"}"#), b64(&format!(r#"{{"exp":{exp},"email":"jinu@family.test"}}"#)));
		let now = 1_800_000_000;
		assert_eq!(jwt_exp(&token(now + 3600)), Some(now + 3600));
		assert_eq!(jwt_exp("not a jwt"), None);
		// An hour left: asked again at the latest after the recheck period.
		assert_eq!(refresh_at(Some(&token(now + 3600)), now), now + TOKEN_RECHECK_SECS);
		// Five minutes left: asked again two minutes before the end.
		assert_eq!(refresh_at(Some(&token(now + 300)), now), now + 300 - TOKEN_MARGIN_SECS);
		// Already expired: asked again soon, never in a busy loop.
		assert_eq!(refresh_at(Some(&token(now - 10)), now), now + 30);
		// No readable exp, or no token at all: the recheck period.
		assert_eq!(refresh_at(Some("opaque"), now), now + TOKEN_RECHECK_SECS);
		assert_eq!(refresh_at(None, now), now + TOKEN_RECHECK_SECS);
	}

	#[test]
	fn the_variable_wins_then_the_command_then_nothing() {
		assert_eq!(access_token_from(Some(" ey.tok ".into()), Some("false")).unwrap().as_deref(), Some("ey.tok"), "the variable, trimmed, and the command never runs");
		assert_eq!(access_token_from(None, Some("echo ey.from.cmd")).unwrap().as_deref(), Some("ey.from.cmd"));
		assert_eq!(access_token_from(None, None).unwrap(), None, "dev mode: no token, no header");
		assert_eq!(access_token_from(Some("  ".into()), None).unwrap(), None);
	}

	#[test]
	fn a_failing_or_silent_command_is_an_error_not_an_anonymous_call() {
		assert!(access_token_from(None, Some("false")).unwrap_err().to_string().contains("failed"));
		assert!(access_token_from(None, Some("true")).unwrap_err().to_string().contains("printed no token"));
		assert!(access_token_from(None, Some("no-such-program-gorani")).unwrap_err().to_string().contains("did not run"));
	}
}
