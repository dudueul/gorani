// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

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
	/// The member's Access token, fetched once per process (commit 33a).
	access_token: std::sync::OnceLock<Option<String>>,
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
	let mut parts = cmd.split_whitespace();
	let program = parts.next().unwrap_or_default();
	let out = std::process::Command::new(program).args(parts).output().map_err(|e| Error::Config(format!("the access token command ({program}) did not run: {e}")))?;
	if !out.status.success() {
		return Err(Error::Config(format!("the access token command failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
	}
	let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
	if token.is_empty() || token.contains(char::is_whitespace) {
		return Err(Error::Config("the access token command printed no token (sign in first: cloudflared access login <host>)".into()));
	}
	Ok(Some(token))
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
		Self { profile, area, agent: b.build(), access_token: std::sync::OnceLock::new() }
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

	/// The member's token for this process (fetched on first use).
	fn member_token(&self) -> Option<&str> {
		self.access_token
			.get_or_init(|| match access_token_from(std::env::var("GORANI_ACCESS_TOKEN").ok(), self.profile.access_token_cmd.as_deref()) {
				Ok(t) => t,
				Err(e) => {
					eprintln!("gorani: {e}");
					None
				}
			})
			.as_deref()
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
			r = r.set("cf-access-token", token);
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
		let v = self.area_json("POST", "/files/uploads", Some(json!({ "size": size, "chunk": chunk, "newFileId": new_file_id })))?;
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
	use super::access_token_from;

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
