// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Protected copies — the Worker's half (commit 40b, docs/DRM.md).
//!
//! Everywhere else the Worker moves ciphertext it cannot open. Here, by the
//! one exception docs/DRM.md states and the owner accepted, it holds keys:
//! a protected copy's content key must reach Apple's DRM module and nobody
//! else, so the license server — this file — has to be able to open it.
//! What keeps that small:
//!
//! - **Custody.** Each copy has its own random content key. It is stored in
//!   the area's database SEALED (AES-256-GCM) under a key derived from the
//!   Worker secret `DRM_KEY_SECRET`, and the seal names the area, the file,
//!   the version and the key id — a sealed key moved to another row does
//!   not open. A database dump without the secret opens nothing; the secret
//!   without the database opens nothing either.
//! - **Hand-off once.** The key is given out in the clear exactly once: to
//!   the lead's browser that packages the copy, in the answer that starts
//!   it. After that it leaves the Worker only inside a CKC, which only the
//!   DRM module of the session that asked can open.
//! - **Who gets the original.** For a protected file, [`original_allowed`]
//!   is the whole rule; routes.rs › file_download asks it before serving a
//!   byte of the original.
//! - **Who gets a license.** Anyone who may read the area (a member in
//!   their own area, anyone with a grant on a case), or a live viewing
//!   session of a view-only link. The SPC must name THIS copy's key id —
//!   a session for one video cannot unlock another. Every license is
//!   audited.
//!
//! Routes (members' and case grantees' under /api/v1/members/<area>/… and
//! /api/v1/cases/<case>/…; links' under /s/f/<id>/drm/…):
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `POST files/<f>/drm` {version} | a lead who may write the area | key made and sealed, upload opened; the key material back, once |
//! | `PUT files/<f>/drm/<v>/parts/<n>` | that lead | one part of the copy, streamed to storage |
//! | `POST files/<f>/drm/<v>/complete` {parts, layout, size} | that lead | upload completed, layout checked; ready |
//! | `GET files/<f>/drm` | readers | protected? which copies, in what state (no key material) |
//! | `DELETE files/<f>/drm` | a lead | protection off: copies and keys gone |
//! | `GET files/<f>/drm/<v>/playlist` | readers | the HLS playlist (byte ranges of the one object) |
//! | `GET files/<f>/drm/<v>/media` | readers | the copy's bytes, by Range |
//! | `POST files/<f>/drm/<v>/license` | readers | SPC in, CKC out |
//! | `GET /api/v1/drm/fairplay/certificate` | anyone signed in | the FPS certificate (public) |

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use worker::*;

use gorani_fairplay::{ContentKey, Credentials, HDCP_TYPE0};

use crate::family::json_error;
use crate::routes::{forward_member, parse_range, part_length, part_number, Actor};
use crate::s3;

/// The Worker secret every copy's key is sealed under: 32 bytes, as 64 hex
/// characters or base64. Without it, Protect is refused and nothing here
/// works — a deployment that never protects anything never needs it.
const KEY_SECRET: &str = "DRM_KEY_SECRET";

/// How big a SPC can be: Apple's are a few kilobytes.
const SPC_CAP: usize = 16 * 1024;

/// The keys derived from DRM_KEY_SECRET: one seals content keys, one signs
/// the media URLs of view-only links.
pub(crate) struct Custody {
	seal: Aes256Gcm,
	url: [u8; 32],
}

fn secret_text(env: &Env, name: &str) -> Option<String> {
	env.secret(name).map(|v| v.to_string()).ok().or_else(|| env.var(name).map(|v| v.to_string()).ok()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The custody keys, or None when DRM_KEY_SECRET is absent or malformed
/// (the operator is told which in the log, never the value).
pub(crate) fn custody(env: &Env) -> Option<Custody> {
	let raw = secret_text(env, KEY_SECRET)?;
	let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
		hex::decode(&raw).ok()
	} else {
		base64::engine::general_purpose::STANDARD.decode(&raw).ok()
	};
	let Some(bytes) = bytes.filter(|b| b.len() == 32) else {
		console_log!("gorani: {KEY_SECRET} is set but is not 32 bytes (64 hex characters or base64) — protected copies are off");
		return None;
	};
	let hk = hkdf::Hkdf::<Sha256>::new(Some(b"gorani drm"), &bytes);
	let (mut seal, mut url) = ([0u8; 32], [0u8; 32]);
	hk.expand(b"content-key seal v1", &mut seal).ok()?;
	hk.expand(b"view-only link urls v1", &mut url).ok()?;
	Some(Custody { seal: Aes256Gcm::new_from_slice(&seal).ok()?, url })
}

impl Custody {
	/// What a sealed key is bound to: its area, file, version and key id.
	fn aad(area: &str, file: &str, version: i64, kid: &str) -> String {
		format!("gorani-drm-key-v1|{area}|{file}|{version}|{kid}")
	}

	/// The content key and its constant IV, sealed: base64(nonce ‖ ct).
	fn seal(&self, area: &str, file: &str, version: i64, kid: &str, key: &[u8; 16]) -> Result<String> {
		let mut nonce = [0u8; 12];
		getrandom::getrandom(&mut nonce).map_err(|e| Error::RustError(format!("no randomness: {e}")))?;
		let aad = Self::aad(area, file, version, kid);
		let ct = self.seal.encrypt(&Nonce::from(nonce), Payload { msg: key, aad: aad.as_bytes() }).map_err(|_| Error::RustError("sealing a content key failed".into()))?;
		let mut out = nonce.to_vec();
		out.extend_from_slice(&ct);
		Ok(base64::engine::general_purpose::STANDARD.encode(out))
	}

	fn open(&self, area: &str, file: &str, version: i64, kid: &str, sealed: &str) -> Option<[u8; 16]> {
		let raw = base64::engine::general_purpose::STANDARD.decode(sealed).ok()?;
		if raw.len() < 12 + 16 {
			return None;
		}
		let aad = Self::aad(area, file, version, kid);
		let nonce: [u8; 12] = raw[..12].try_into().ok()?;
		let key = self.seal.decrypt(&Nonce::from(nonce), Payload { msg: &raw[12..], aad: aad.as_bytes() }).ok()?;
		key.try_into().ok()
	}

	/// A view-only link's media URL signature (HMAC-SHA256, hex).
	pub(crate) fn sign(&self, message: &str) -> String {
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.url).expect("any key length");
		mac.update(message.as_bytes());
		hex::encode(mac.finalize().into_bytes())
	}

	pub(crate) fn verify(&self, message: &str, signature: &str) -> bool {
		let Ok(sig) = hex::decode(signature) else { return false };
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.url).expect("any key length");
		mac.update(message.as_bytes());
		mac.verify_slice(&sig).is_ok()
	}
}

/// The FPS credentials, or which of the three secrets is missing (by name).
pub(crate) fn fairplay(env: &Env) -> std::result::Result<Credentials, String> {
	let (cert, key, ask) = (secret_text(env, "FAIRPLAY_CERT"), secret_text(env, "FAIRPLAY_PRIVATE_KEY"), secret_text(env, "FAIRPLAY_ASK"));
	let missing: Vec<&str> = [("FAIRPLAY_CERT", cert.is_none()), ("FAIRPLAY_PRIVATE_KEY", key.is_none()), ("FAIRPLAY_ASK", ask.is_none())].into_iter().filter(|(_, m)| *m).map(|(n, _)| n).collect();
	if !missing.is_empty() {
		return Err(format!("FairPlay is not configured on this deployment ({} not set) — protected copies can be made, not yet played (docs/PRODUCTION.md › FairPlay)", missing.join(", ")));
	}
	Credentials::parse(&cert.unwrap_or_default(), &key.unwrap_or_default(), &ask.unwrap_or_default()).map_err(|e| {
		console_log!("gorani: the FairPlay credentials do not parse: {e}");
		"the FairPlay credentials on this deployment do not parse — the operator's log says why".to_string()
	})
}

/// THE rule (docs/DRM.md › Who sees which copy): the original of a
/// protected video goes to a lead, and to the owner of a member's own area
/// (the only one who reads it at all). Everyone else — analysts, auditors
/// and externals on a case — gets the protected copy only.
pub(crate) fn original_allowed(actor: &Actor, area: &str) -> bool {
	actor.role == "lead" || actor.id == area
}

/// The refusal the original's routes give everyone else.
pub(crate) fn original_refused() -> Result<Response> {
	json_error(403, "this video is protected: it plays as a protected copy (in Safari on a Mac, iPhone or iPad), and only a lead downloads the original")
}

/// Where a copy's bytes go: beside the area's own objects, under `drm/`,
/// named by version and key id — a replaced copy never overwrites the
/// object of the one it replaces.
fn object_key(area: &str, file: &str, version: i64, kid: &str) -> String {
	format!("drm/{}/{file}/{version}-{}", crate::area::key_prefix(area), &kid[..8])
}

/// The playlist's byte ranges: the init, then each segment with its length
/// in seconds — `[[offset, length], [[offset, length, seconds], …]]`.
#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct Layout {
	init: (u64, u64),
	segments: Vec<(u64, u64, f64)>,
}

impl Layout {
	/// The ranges tile the object exactly — init first, segments after it
	/// in order, nothing missing, nothing past the end — and every length
	/// is a real one. A playlist built from anything else points players at
	/// bytes that are not what it says.
	fn check(&self, size: u64) -> std::result::Result<(), String> {
		if self.init.0 != 0 || self.init.1 == 0 {
			return Err("the init segment starts the object".into());
		}
		if self.segments.is_empty() || self.segments.len() > 200_000 {
			return Err("a copy has 1–200 000 segments".into());
		}
		let mut at = self.init.1;
		for (i, (offset, length, seconds)) in self.segments.iter().enumerate() {
			if *offset != at || *length == 0 {
				return Err(format!("segment {i} does not follow the one before it"));
			}
			if !seconds.is_finite() || *seconds <= 0.0 || *seconds > 600.0 {
				return Err(format!("segment {i} lasts {seconds} s"));
			}
			at += length;
		}
		if at != size {
			return Err(format!("the layout covers {at} bytes of a {size}-byte copy"));
		}
		Ok(())
	}
}

/// The media playlist (RFC 8216) of one copy: fMP4 in ONE object, every
/// part addressed by byte range, the key named by `skd://<key id>`.
/// `media` is the URI of the object (relative: it resolves against the
/// playlist's own URL). SAMPLE-AES's key line comes before the map, as in
/// Apple's examples: sample encryption never touches the init segment.
pub(crate) fn playlist(layout: &Layout, kid: &str, media: &str) -> String {
	let longest = layout.segments.iter().map(|s| s.2).fold(0.0f64, f64::max);
	let mut out = String::with_capacity(layout.segments.len() * 64 + 400);
	out.push_str("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXT-X-INDEPENDENT-SEGMENTS\n");
	out.push_str(&format!("#EXT-X-TARGETDURATION:{}\n#EXT-X-MEDIA-SEQUENCE:0\n", longest.ceil().max(1.0) as u64));
	out.push_str(&format!("#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"skd://{kid}\",KEYFORMAT=\"com.apple.streamingkeydelivery\",KEYFORMATVERSIONS=\"1\"\n"));
	out.push_str(&format!("#EXT-X-MAP:URI=\"{media}\",BYTERANGE=\"{}@{}\"\n", layout.init.1, layout.init.0));
	for (offset, length, seconds) in &layout.segments {
		out.push_str(&format!("#EXTINF:{seconds:.5},\n#EXT-X-BYTERANGE:{length}@{offset}\n{media}\n"));
	}
	out.push_str("#EXT-X-ENDLIST\n");
	out
}

/// Does an SPC's asset id name this key? Safari derives it from the
/// playlist's `skd://` URI — the whole URI or what follows the scheme,
/// depending on the API the page used — so both are this copy's.
pub(crate) fn asset_names(asset: &[u8], kid: &str) -> bool {
	let text = String::from_utf8_lossy(asset);
	let text = text.trim_matches(char::from(0)).trim();
	text.eq_ignore_ascii_case(kid) || text.strip_prefix("skd://").is_some_and(|k| k.eq_ignore_ascii_case(kid))
}

// ── The copy, from the area's database ─────────────────────────────────

/// One copy as `files-drm-copy` gives it to the Worker.
pub(crate) struct Copy {
	pub(crate) version: i64,
	pub(crate) current: i64,
	pub(crate) kid: String,
	key_sealed: String,
	iv: String,
	pub(crate) object_key: String,
	upload_id: Option<String>,
	pub(crate) state: String,
	layout: Option<Layout>,
}

impl Copy {
	fn from_json(v: &serde_json::Value) -> Option<Copy> {
		let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
		Some(Copy {
			version: v.get("version")?.as_i64()?,
			current: v.get("current").and_then(|x| x.as_i64()).unwrap_or(0),
			kid: s("kid")?,
			key_sealed: s("keySealed")?,
			iv: s("iv")?,
			object_key: s("objectKey")?,
			upload_id: s("uploadId"),
			state: s("state")?,
			layout: v.get("layout").and_then(|l| serde_json::from_value(l.clone()).ok()),
		})
	}

	/// The playable copy of the file's CURRENT version — an older copy is
	/// never shown in its place (the viewer would watch a superseded video).
	fn playable(&self) -> std::result::Result<&Layout, &'static str> {
		if self.version != self.current {
			return Err("this video has a newer version, and its protected copy is not made yet — a lead's browser makes it the next time a lead opens it");
		}
		match (&self.state[..], &self.layout) {
			("ready", Some(l)) => Ok(l),
			_ => Err("this video's protected copy is still being prepared"),
		}
	}
}

/// The copy of `version` ("current" for the current one), or the DO's own
/// answer when there is none.
async fn copy_of(env: &Env, area: &str, file: &str, version: &str, actor: &str) -> Result<std::result::Result<Copy, Response>> {
	let mut resp = forward_member(env, area, "GET", format!("files-drm-copy/{file}/{version}"), None, actor).await?;
	if resp.status_code() != 200 {
		return Ok(Err(resp));
	}
	let v: serde_json::Value = resp.json().await?;
	match Copy::from_json(&v) {
		Some(c) => Ok(Ok(c)),
		None => Ok(Err(json_error(500, "a protected copy's row is malformed")?)),
	}
}

fn valid_file_id(file: &str) -> bool {
	crate::auth::valid_object_id(file)
}

// ── Protect (a lead's browser packages; the Worker keeps the key) ──────

/// `POST files/<f>/drm` {version}: a lead starts a copy. The answer holds
/// the 48 bytes the packager needs — key, key id, constant IV — the only
/// time the key leaves the Worker in the clear.
pub(crate) async fn protect_start(env: &Env, actor: &Actor, area: &str, file: &str, body: serde_json::Value) -> Result<Response> {
	if actor.role != "lead" {
		return json_error(403, "only a lead protects a video (docs/DRM.md › Decisions)");
	}
	if !valid_file_id(file) {
		return json_error(400, "file id");
	}
	let Some(custody) = custody(env) else {
		return json_error(503, "protected copies are not set up on this deployment (DRM_KEY_SECRET is not set — docs/PRODUCTION.md › FairPlay)");
	};
	let Some(version) = body.get("version").and_then(|v| v.as_i64()).filter(|v| *v > 0) else {
		return json_error(400, "version required");
	};
	let mut material = [0u8; 48];
	getrandom::getrandom(&mut material).map_err(|e| Error::RustError(format!("no randomness: {e}")))?;
	let key: [u8; 16] = material[..16].try_into().unwrap();
	let kid = hex::encode(&material[16..32]);
	let iv = hex::encode(&material[32..48]);
	let key_sealed = custody.seal(area, file, version, &kid, &key)?;
	let object = object_key(area, file, version, &kid);
	let upload_id = s3::multipart_init(env, &object).await?;
	let mut started = forward_member(
		env,
		area,
		"POST",
		format!("files-drm/{file}"),
		Some(serde_json::json!({ "version": version, "kid": kid, "keySealed": key_sealed, "iv": iv, "objectKey": object, "uploadId": upload_id })),
		actor.email.as_str(),
	)
	.await?;
	if started.status_code() != 200 {
		let _ = s3::multipart_abort(env, &object, &upload_id).await;
		return Ok(started);
	}
	// The copy this one replaces: its upload aborted, its object deleted.
	let answer: serde_json::Value = started.json().await?;
	if let Some(old) = answer.get("replaced").filter(|r| !r.is_null()) {
		let old_key = old.get("objectKey").and_then(|k| k.as_str()).unwrap_or_default();
		if let Some(u) = old.get("uploadId").and_then(|u| u.as_str()) {
			let _ = s3::multipart_abort(env, old_key, u).await;
		}
		if !old_key.is_empty() {
			let _ = s3::delete(env, old_key).await;
		}
	}
	Response::from_json(&serde_json::json!({
		"version": version,
		"kid": kid,
		"material": base64::engine::general_purpose::STANDARD.encode(material),
	}))
}

/// `PUT files/<f>/drm/<v>/parts/<n>`: one part of the copy (every part but
/// the last at least 5 MiB — storage's rule), streamed through.
pub(crate) async fn protect_part(mut req: Request, env: &Env, actor: &Actor, area: &str, file: &str, version: &str, part: &str) -> Result<Response> {
	if actor.role != "lead" {
		return json_error(403, "only a lead protects a video");
	}
	let Some(n) = part_number(part) else { return json_error(400, "part numbers are 1–10000") };
	let len = match part_length(&req)? {
		Ok(len) => len,
		Err(resp) => return Ok(resp),
	};
	let copy = match copy_of(env, area, file, version, &actor.email).await? {
		Ok(c) => c,
		Err(resp) => return Ok(resp),
	};
	let (Some(upload_id), "packaging") = (copy.upload_id.as_deref(), copy.state.as_str()) else {
		return json_error(409, "this copy is not being uploaded");
	};
	let etag = s3::multipart_part_stream(env, &copy.object_key, upload_id, n, req.stream()?, len).await?;
	Response::from_json(&serde_json::json!({ "partNumber": n, "etag": etag }))
}

/// `POST files/<f>/drm/<v>/complete` {parts: [{partNumber, etag}], layout,
/// size}: the upload is completed, then the layout is checked against the
/// object storage actually holds — the playlist is built from it later.
pub(crate) async fn protect_complete(env: &Env, actor: &Actor, area: &str, file: &str, version: &str, body: serde_json::Value) -> Result<Response> {
	if actor.role != "lead" {
		return json_error(403, "only a lead protects a video");
	}
	let copy = match copy_of(env, area, file, version, &actor.email).await? {
		Ok(c) => c,
		Err(resp) => return Ok(resp),
	};
	let (Some(upload_id), "packaging") = (copy.upload_id.as_deref(), copy.state.as_str()) else {
		return json_error(409, "this copy is not being uploaded");
	};
	let Some(layout) = body.get("layout").and_then(|l| serde_json::from_value::<Layout>(l.clone()).ok()) else {
		return json_error(400, "layout: {init: [0, length], segments: [[offset, length, seconds], …]}");
	};
	let parts: Vec<(u32, String)> = body
		.get("parts")
		.and_then(|p| p.as_array())
		.map(|a| a.iter().filter_map(|p| Some((p.get("partNumber")?.as_u64()? as u32, p.get("etag")?.as_str()?.to_string()))).collect())
		.unwrap_or_default();
	if parts.is_empty() {
		return json_error(400, "parts required");
	}
	s3::multipart_complete(env, &copy.object_key, upload_id, &parts).await?;
	let size = match s3::head(env, &copy.object_key).await? {
		Some(h) => h.size,
		None => return json_error(502, "the storage does not have the copy it just completed"),
	};
	if let Err(why) = layout.check(size) {
		// A copy whose layout lies is not kept: it is deleted, and the lead
		// told why — packaging again makes a new one.
		let _ = s3::delete(env, &copy.object_key).await;
		return json_error(400, &format!("the copy's layout does not match what was uploaded: {why}"));
	}
	forward_member(env, area, "POST", format!("files-drm/{file}/{}/complete", copy.version), Some(serde_json::json!({ "layout": layout, "size": size })), actor.email.as_str()).await
}

/// `GET files/<f>/drm`: the file's protection state, for the app.
pub(crate) async fn state(env: &Env, actor: &Actor, area: &str, file: &str) -> Result<Response> {
	let mut resp = forward_member(env, area, "GET", format!("files-drm/{file}"), None, actor.email.as_str()).await?;
	if resp.status_code() != 200 {
		return Ok(resp);
	}
	let mut v: serde_json::Value = resp.json().await?;
	v["original"] = serde_json::json!(original_allowed(actor, area));
	v["canProtect"] = serde_json::json!(actor.role == "lead" && custody(env).is_some());
	v["playable"] = serde_json::json!(fairplay(env).is_ok());
	Response::from_json(&v)
}

/// `DELETE files/<f>/drm`: a lead turns protection off. The objects go now
/// (the DO also queued them, so a failure here is retried).
pub(crate) async fn unprotect(env: &Env, actor: &Actor, area: &str, file: &str) -> Result<Response> {
	if actor.role != "lead" {
		return json_error(403, "only a lead turns protection off");
	}
	forward_member(env, area, "DELETE", format!("files-drm/{file}"), None, actor.email.as_str()).await
}

// ── Playing (members and case grantees) ─────────────────────────────────

/// `GET files/<f>/drm/<v>/playlist`.
pub(crate) async fn playlist_route(env: &Env, actor: &Actor, area: &str, file: &str, version: &str) -> Result<Response> {
	let copy = match copy_of(env, area, file, version, &actor.email).await? {
		Ok(c) => c,
		Err(resp) => return Ok(resp),
	};
	let layout = match copy.playable() {
		Ok(l) => l,
		Err(why) => return json_error(409, why),
	};
	m3u8(playlist(layout, &copy.kid, "media"))
}

pub(crate) fn m3u8(text: String) -> Result<Response> {
	let headers = Headers::new();
	headers.set("Content-Type", "application/vnd.apple.mpegurl")?;
	headers.set("Cache-Control", "no-store")?;
	Ok(Response::ok(text)?.with_headers(headers))
}

/// `GET files/<f>/drm/<v>/media`: the copy's bytes, by Range (the
/// playlist's byte ranges). Ciphertext only a license opens.
pub(crate) async fn media(req: &Request, env: &Env, actor: &Actor, area: &str, file: &str, version: &str) -> Result<Response> {
	let copy = match copy_of(env, area, file, version, &actor.email).await? {
		Ok(c) => c,
		Err(resp) => return Ok(resp),
	};
	if let Err(why) = copy.playable() {
		return json_error(409, why);
	}
	media_bytes(req, env, &copy).await
}

pub(crate) async fn media_bytes(req: &Request, env: &Env, copy: &Copy) -> Result<Response> {
	let range = parse_range(&req.headers().get("Range")?.unwrap_or_default());
	let mut s3_resp = s3::fetch_stream(env, "GET", &copy.object_key, range, &[], None).await?;
	let status = s3_resp.status_code();
	if status != 200 && status != 206 {
		return json_error(if status == 416 { 416 } else { 502 }, &format!("the storage answered HTTP {status} for this copy"));
	}
	let headers = Headers::new();
	headers.set("Content-Type", "video/mp4")?;
	headers.set("Accept-Ranges", "bytes")?;
	headers.set("Cache-Control", "no-store")?;
	for h in ["Content-Length", "Content-Range"] {
		if let Some(v) = s3_resp.headers().get(h)? {
			headers.set(h, &v)?;
		}
	}
	Ok(Response::from_stream(s3_resp.stream()?)?.with_status(status).with_headers(headers))
}

/// The CKC for an SPC asking for this copy's key — or why not. `detail`
/// says whether the caller hears the precise reason (a signed-in reader)
/// or one generic refusal (a link's viewer, who is not signed in).
pub(crate) fn answer_spc(env: &Env, area: &str, file: &str, copy: &Copy, spc: &[u8], detail: bool) -> Result<std::result::Result<Vec<u8>, Response>> {
	if let Err(why) = copy.playable() {
		return Ok(Err(json_error(409, why)?));
	}
	let creds = match fairplay(env) {
		Ok(c) => c,
		Err(why) => return Ok(Err(json_error(503, &why)?)),
	};
	let Some(custody) = custody(env) else { return Ok(Err(json_error(503, "protected copies are not set up on this deployment (DRM_KEY_SECRET)")?)) };
	let Some(key) = custody.open(area, file, copy.version, &copy.kid, &copy.key_sealed) else {
		console_log!("gorani: the content key of {area}/{file} v{} does not open — DRM_KEY_SECRET changed?", copy.version);
		return Ok(Err(json_error(500, "this copy's key does not open on this deployment")?));
	};
	let iv: [u8; 16] = hex::decode(&copy.iv).ok().and_then(|v| v.try_into().ok()).unwrap_or([0u8; 16]);
	let kid = copy.kid.clone();
	match gorani_fairplay::respond_checked(&creds, spc, |asset| asset_names(asset, &kid).then_some(ContentKey { key, iv, lease_seconds: 0, hdcp: Some(HDCP_TYPE0) })) {
		Ok(ckc) => Ok(Ok(ckc)),
		Err(e) => {
			console_log!("gorani: a license for {area}/{file} v{} was refused: {e}", copy.version);
			Ok(Err(json_error(400, &if detail { format!("the license request was refused: {e}") } else { "the license request was refused".to_string() })?))
		}
	}
}

pub(crate) fn ckc_response(ckc: Vec<u8>) -> Result<Response> {
	let headers = Headers::new();
	headers.set("Content-Type", "application/octet-stream")?;
	headers.set("Cache-Control", "no-store")?;
	Ok(Response::from_bytes(ckc)?.with_headers(headers))
}

/// `POST files/<f>/drm/<v>/license`: SPC in, CKC out, audited.
pub(crate) async fn license(mut req: Request, env: &Env, actor: &Actor, area: &str, file: &str, version: &str) -> Result<Response> {
	let spc = req.bytes().await?;
	if spc.is_empty() || spc.len() > SPC_CAP {
		return json_error(400, "the body is the SPC FairPlay made (at most 16 KiB)");
	}
	let copy = match copy_of(env, area, file, version, &actor.email).await? {
		Ok(c) => c,
		Err(resp) => return Ok(resp),
	};
	match answer_spc(env, area, file, &copy, &spc, true)? {
		Ok(ckc) => {
			forward_member(env, area, "POST", format!("files-drm-license/{file}/{}", copy.version), Some(serde_json::json!({})), actor.email.as_str()).await?;
			ckc_response(ckc)
		}
		Err(resp) => Ok(resp),
	}
}

/// `GET drm/fairplay/certificate`: the FPS certificate's DER — public (it
/// is what Safari seals an SPC to), served so the page need not embed it.
pub(crate) fn certificate(env: &Env) -> Result<Response> {
	match fairplay(env) {
		Ok(c) => {
			let headers = Headers::new();
			headers.set("Content-Type", "application/octet-stream")?;
			headers.set("Cache-Control", "public, max-age=3600")?;
			Ok(Response::from_bytes(c.cert_der.clone())?.with_headers(headers))
		}
		Err(why) => json_error(503, &why),
	}
}

// ── Playing a view-only link (/s/f/<id>/drm/…) ──────────────────────────

/// The query a view-only link's playlist and media URLs carry: the
/// session's token HASH, when it ends (Unix seconds), and the Worker's
/// signature over the link, both. (routes.rs › public_share's claim makes it.)
pub(crate) fn session_query(session: &str, until: u64, sig: &str) -> String {
	format!("s={session}&e={until}&m={sig}")
}

/// Ask the link owner's DO (the stub public_share resolved).
async fn share_call(stub: &Stub, path: String, body: serde_json::Value) -> Result<Response> {
	let headers = Headers::new();
	headers.set("Content-Type", "application/json")?;
	let request = Request::new_with_init(&format!("https://do.internal/{path}"), &RequestInit { method: Method::Post, headers, body: Some(body.to_string().into()), ..Default::default() })?;
	stub.fetch_with_request(request).await
}

/// The copy a live viewing session of link `id` may play, with its file id.
async fn share_copy(stub: &Stub, id: &str, session: &str) -> Result<std::result::Result<(Copy, String), Response>> {
	let mut resp = share_call(stub, format!("shares/{id}/drm-copy"), serde_json::json!({ "session": session })).await?;
	if resp.status_code() != 200 {
		return Ok(Err(resp));
	}
	let v: serde_json::Value = resp.json().await?;
	match (Copy::from_json(&v), v.get("fileId").and_then(|f| f.as_str())) {
		(Some(c), Some(f)) => Ok(Ok((c, f.to_string()))),
		_ => Ok(Err(json_error(500, "a protected copy's row is malformed")?)),
	}
}

/// `/s/f/<id>/drm/{certificate, playlist, media, license}` — the only
/// DRM routes anyone can call without signing in (public_share rate limits
/// them per caller and link first). The playlist and media take a signed
/// session URL; the license takes the session's token itself, in a header
/// only the page's own script sends.
pub(crate) async fn public_drm(mut req: Request, env: &Env, id: &str, member: &str, action: Option<&str>, stub: &Stub) -> Result<Response> {
	match (req.method(), action) {
		(Method::Get, Some("certificate")) => certificate(env),
		(Method::Get, Some(what @ ("playlist" | "media"))) => {
			let Some(custody) = custody(env) else { return json_error(503, "protected copies are not set up on this deployment") };
			let q = crate::files_store::urlquery(req.url()?.query().unwrap_or(""));
			let (Some(session), Some(until), Some(sig)) = (q.get("s"), q.get("e").and_then(|e| e.parse::<u64>().ok()), q.get("m")) else {
				return json_error(403, "this address is not a viewing session — open the link again");
			};
			if until <= Date::now().as_millis() / 1000 || !custody.verify(&format!("{id}|{session}|{until}"), sig) {
				return json_error(403, "this viewing session has ended — open the link again");
			}
			let (copy, _) = match share_copy(stub, id, session).await? {
				Ok(c) => c,
				Err(resp) => return Ok(resp),
			};
			let layout = match copy.playable() {
				Ok(l) => l,
				Err(why) => return json_error(409, why),
			};
			if what == "playlist" {
				m3u8(playlist(layout, &copy.kid, &format!("media?{}", session_query(session, until, sig))))
			} else {
				media_bytes(&req, env, &copy).await
			}
		}
		(Method::Post, Some("license")) => {
			let token = req.headers().get("x-gorani-share-token")?.unwrap_or_default();
			if token.is_empty() {
				return json_error(403, "the license needs the viewing session's token");
			}
			let spc = req.bytes().await?;
			if spc.is_empty() || spc.len() > SPC_CAP {
				return json_error(400, "the body is the SPC FairPlay made (at most 16 KiB)");
			}
			let session = crate::files_store::token_hash(&token);
			let (copy, file) = match share_copy(stub, id, &session).await? {
				Ok(c) => c,
				Err(resp) => return Ok(resp),
			};
			match answer_spc(env, member, &file, &copy, &spc, false)? {
				Ok(ckc) => {
					share_call(stub, format!("shares/{id}/drm-license"), serde_json::json!({ "file": file, "version": copy.version })).await?;
					ckc_response(ckc)
				}
				Err(resp) => Ok(resp),
			}
		}
		_ => json_error(404, "no such route"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn layout() -> Layout {
		Layout { init: (0, 800), segments: vec![(800, 1000, 4.0), (1800, 700, 3.5)] }
	}

	#[test]
	fn a_layout_tiles_the_object_exactly() {
		assert!(layout().check(2500).is_ok());
		assert!(layout().check(2501).unwrap_err().contains("2500 bytes of a 2501"));
		let mut gap = layout();
		gap.segments[1].0 = 1801;
		assert!(gap.check(2501).unwrap_err().contains("segment 1"));
		let mut late = layout();
		late.init.0 = 4;
		assert!(late.check(2500).is_err(), "the init starts the object");
		let mut odd = layout();
		odd.segments[0].2 = f64::NAN;
		assert!(odd.check(2500).is_err(), "a duration is a real number of seconds");
		assert!(Layout { init: (0, 10), segments: vec![] }.check(10).is_err(), "at least one segment");
	}

	#[test]
	fn the_playlist_addresses_one_object_by_byte_range() {
		let p = playlist(&layout(), "00112233445566778899aabbccddeeff", "media");
		assert!(p.starts_with("#EXTM3U\n#EXT-X-VERSION:7\n"));
		assert!(p.contains("#EXT-X-TARGETDURATION:4\n"));
		let key = p.find("#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"skd://00112233445566778899aabbccddeeff\",KEYFORMAT=\"com.apple.streamingkeydelivery\"").unwrap();
		let map = p.find("#EXT-X-MAP:URI=\"media\",BYTERANGE=\"800@0\"").unwrap();
		assert!(key < map, "the key line comes before the map");
		assert!(p.contains("#EXTINF:4.00000,\n#EXT-X-BYTERANGE:1000@800\nmedia\n"));
		assert!(p.contains("#EXTINF:3.50000,\n#EXT-X-BYTERANGE:700@1800\nmedia\n"));
		assert!(p.ends_with("#EXT-X-ENDLIST\n"));
	}

	#[test]
	fn an_asset_id_names_this_key_or_no_other() {
		let kid = "00112233445566778899aabbccddeeff";
		assert!(asset_names(b"skd://00112233445566778899aabbccddeeff", kid));
		assert!(asset_names(b"00112233445566778899AABBCCDDEEFF", kid));
		assert!(!asset_names(b"skd://ffeeddccbbaa99887766554433221100", kid));
		assert!(!asset_names(b"skd://00112233445566778899aabbccddeeff/x", kid));
		assert!(!asset_names(b"", kid));
	}

	#[test]
	fn the_original_goes_to_leads_and_an_areas_owner() {
		let a = Actor::test;
		assert!(original_allowed(&a("ana", "lead"), "case:c1"));
		assert!(original_allowed(&a("bo", "analyst"), "bo"), "an own area's owner");
		assert!(!original_allowed(&a("bo", "analyst"), "case:c1"));
		assert!(!original_allowed(&a("eve", "external"), "case:c1"));
		assert!(!original_allowed(&a("cy", "auditor"), "case:c1"));
	}
}
