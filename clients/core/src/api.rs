// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare's desktop core (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

//! The HTTP layer: every endpoint of docs/DESKTOP.md, one method each, with
//! the Access service-token headers when configured (production) and none
//! in dev. Blocking ureq on the CLI's own thread.

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
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreKey {
	pub key_id: String,
	pub public_key: Jwk,
	#[serde(default)]
	pub pq_public_key: Option<String>,
	pub private_key_sealed: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Jwk {
	pub x: String,
	pub y: String,
}

pub struct Client {
	pub profile: DeviceProfile,
	agent: ureq::Agent,
}

impl Client {
	pub fn new(profile: DeviceProfile) -> Self {
		// (platform shells swap in the system TLS connector; the CLI uses rustls)
		Self { profile, agent: ureq::AgentBuilder::new().redirects(0).build() }
	}

	fn url(&self, rest: &str) -> String {
		format!("{}/api/v1/members/{}{rest}", self.profile.server.trim_end_matches('/'), self.profile.member)
	}

	fn req(&self, method: &str, url: &str) -> ureq::Request {
		let mut r = self.agent.request(method, url);
		if let (Some(id), Some(secret)) = (&self.profile.access_id, &self.profile.access_secret) {
			r = r.set("CF-Access-Client-Id", id).set("CF-Access-Client-Secret", secret);
		}
		r
	}

	fn json(&self, method: &str, rest: &str, body: Option<Value>) -> Result<Value, Error> {
		let r = self.req(method, &self.url(rest));
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

	pub fn unlock(&self, device_id: &str, token: &str) -> Result<(String, String, VaultSettings), Error> {
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
			serde_json::from_value(v["settings"].clone()).map_err(|e| Error::Config(format!("settings: {e}")))?,
		))
	}

	// ── files ───────────────────────────────────────────────────────────

	pub fn changes(&self, since: u64) -> Result<(u64, Vec<Value>), Error> {
		let v = self.json("GET", &format!("/files/changes?since={since}&limit=1000"), None)?;
		Ok((v["cursor"].as_u64().unwrap_or(since), v["changes"].as_array().cloned().unwrap_or_default()))
	}

	pub fn keys(&self, ids: &[String]) -> Result<Value, Error> {
		self.json("POST", "/files/keys", Some(json!({ "ids": ids })))
	}

	/// Fetch a version's sealed object (Range honoured; chunked objects are
	/// fetched frame-aligned by the caller).
	pub fn fetch(&self, id: &str, version: Option<u64>, range: Option<(u64, u64)>) -> Result<Vec<u8>, Error> {
		let mut r = self.req("GET", &self.url(&format!("/files/{id}?version={}", version.unwrap_or(0))));
		if let Some((a, b)) = range {
			r = r.set("Range", &format!("bytes={a}-{}", b.saturating_sub(1)));
		}
		let res = r.call().map_err(|e| match e {
			ureq::Error::Status(code, resp) => Error::Http(code, resp.into_string().unwrap_or_default()),
			other => Error::Config(other.to_string()),
		})?;
		let mut res = res;
		let mut out = Vec::new();
		res.into_reader().read_to_end(&mut out)?;
		Ok(out)
	}

	pub fn ck_of(&self, id: &str) -> Result<String, Error> {
		let keys = self.keys(&[id.to_string()])?;
		Ok(keys["keys"][id]["key"].as_str().unwrap_or_default().to_string())
	}

	/// Whole upload (≤ 48 MB plaintext): seal in GV02, wrap the key GV03.
	pub fn upload_whole(&self, fields: &UploadFields, sealed: &[u8]) -> Result<Value, Error> {
		let boundary = format!("gorani{:032x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
		let mut body = Vec::new();
		for (k, v) in &fields.form {
			body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes());
		}
		body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sealed.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
		body.extend_from_slice(sealed);
		body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
		let res = self
			.req("POST", &self.url("/files"))
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

pub struct UploadFields {
	pub form: Vec<(String, String)>,
}

