// Copyright 2026- Seongwoo Hong. All rights reserved.

//! Who is calling? Cloudflare Access sits in front of the Worker in
//! production: every request carries `CF-Access-JWT-Assertion`, an ES256
//! JWT signed by the team's keys. This module verifies it — issuer, audience
//! (the Access application's `POLICY_AUD`), expiry, and the signature against
//! the team's JWKS — and fails **closed**: if Access is not configured, no
//! production request passes.
//!
//! In local development (`GORANI_DEV=1` in .dev.vars) there is no Access; a
//! request identifies itself with `x-gorani-dev-email`. The var only exists
//! in `.dev.vars`, never in production vars, and the code refuses dev mode
//! the moment `POLICY_AUD` is set — the two are mutually exclusive by
//! construction, so a dev bypass can never leak to a deployment.
//!
//! Identity is the Access email. The team registry (GoraniFamilyDO) maps
//! emails to members; a member's email acts for their own area and for the
//! cases they are granted (routes.rs), never for another member's area.

// (No std::time: `SystemTime::now()` PANICS on wasm32-unknown-unknown —
// the platform has no clock std can reach. It was here until commit 33a,
// on the Access path only: every production request that carried a token
// panicked in the JWKS cache, and dev mode never reached it. The Workers
// clock is `worker::Date`, milliseconds since the epoch. Found by api:access,
// the first suite to run this path.)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use worker::*;

/// Who the request is. More claims exist; these are the ones gorani acts on.
#[derive(Debug, Clone)]
pub struct Identity {
	pub email: String,
	/// A COLLECTOR, not a member (commit 37a, docs/COLLECTORS.md): the
	/// `common_name` of an Access service token (its JWT carries no email).
	/// The router lets such an identity reach the drop routes and nothing
	/// else — `email` is empty, and no member rule ever sees it.
	pub collector: Option<String>,
	/// A case grant ALREADY CHECKED for this request (routes.rs ›
	/// route_case, commit 26), so the member-scope code reuses it instead of
	/// asking the registry a second time. Only the router sets it, from the
	/// registry's answer — never from anything the client sent.
	pub granted: Option<Granted>,
}

/// The registry's answer for one case and one caller.
#[derive(Debug, Clone)]
pub struct Granted {
	/// The area (`case:<id>`) the check was for.
	pub area: String,
	pub member: String,
	pub role: String,
}

/// One JWKS fetch, cached per isolate for ten minutes (a JWKS rotation
/// propagates within minutes; Access signs short-lived tokens).
struct JwksCache {
	/// When the keys were fetched, ms since the epoch (`worker::Date`).
	fetched_at: u64,
	keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
	kid: String,
	kty: String,
	crv: String,
	x: String,
	y: String,
	alg: Option<String>,
}

static CACHE: std::sync::OnceLock<std::sync::Mutex<Option<JwksCache>>> = std::sync::OnceLock::new();

fn cache() -> &'static std::sync::Mutex<Option<JwksCache>> {
	CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

/// The Workers clock, ms since the epoch.
fn now_ms() -> u64 {
	Date::now().as_millis()
}

/// The team's JWKS URL. `TEAM_DOMAIN` may be the team URL or the full certs
/// URL, as with Mailflare's setup.
fn certs_url(team_domain: &str) -> String {
	if team_domain.contains("/cdn-cgi/access/certs") {
		team_domain.to_string()
	} else {
		format!("{}/cdn-cgi/access/certs", team_domain.trim_end_matches('/'))
	}
}

async fn fetch_jwks(env: &Env) -> Result<Vec<Jwk>> {
	if let Ok(cached) = cache().lock() {
		if let Some(c) = cached.as_ref() {
			if now_ms().saturating_sub(c.fetched_at) < 600_000 {
				return Ok(c.keys.clone());
			}
		}
	}
	let team = env.var("TEAM_DOMAIN").map_err(|_| Error::RustError("TEAM_DOMAIN not configured".into()))?.to_string();
	let mut resp = Fetch::Url(certs_url(&team).parse().map_err(|_| Error::RustError("bad TEAM_DOMAIN".into()))?).send().await?;
	let body: serde_json::Value = resp.json().await?;
	let keys: Vec<Jwk> = body
		.get("keys")
		.and_then(|k| serde_json::from_value(k.clone()).ok())
		.ok_or_else(|| Error::RustError("bad JWKS".into()))?;
	if let Ok(mut cached) = cache().lock() {
		*cached = Some(JwksCache { fetched_at: now_ms(), keys: keys.clone() });
	}
	Ok(keys)
}

/// A compact JWT's three parts, base64url-decoded.
struct Token<'a> {
	header: serde_json::Value,
	claims: serde_json::Value,
	/// The raw bytes of `header.payload` (what the signature covers).
	signing_input: &'a [u8],
	signature: [u8; 64],
}

fn parse_token(token: &str) -> Result<Token<'_>> {
	let mut parts = token.split('.');
	let head_b64 = parts.next().ok_or_else(|| Error::RustError("no token header".into()))?;
	let claims_b64 = parts.next().ok_or_else(|| Error::RustError("no token claims".into()))?;
	let sig_b64 = parts.next().ok_or_else(|| Error::RustError("no token signature".into()))?;
	if parts.next().is_some() {
		return Err(Error::RustError("token has extra parts".into()));
	}
	let signing_input_len = head_b64.len() + 1 + claims_b64.len();
	// Rebuild the exact signed bytes: part1.part2 (the '.' between them).
	let full = token.as_bytes();
	if full.len() < signing_input_len + 1 {
		return Err(Error::RustError("token is too short".into()));
	}
	let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(head_b64).map_err(|_| Error::RustError("bad token header".into()))?)
		.map_err(|_| Error::RustError("bad token header JSON".into()))?;
	let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_b64).map_err(|_| Error::RustError("bad token claims".into()))?)
		.map_err(|_| Error::RustError("bad token claims JSON".into()))?;
	let sig = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| Error::RustError("bad token signature".into()))?;
	let signature: [u8; 64] = sig.try_into().map_err(|_| Error::RustError("signature is not 64 bytes".into()))?;
	Ok(Token { header, claims, signing_input: &full[..signing_input_len], signature })
}

/// Verify one request's Access token and return the identity. The chain is:
/// dev mode (explicitly enabled, and Access explicitly absent) → JWT present
/// → header alg ES256 → signature against the team JWKS → iss/aud/exp.
pub async fn authenticate(env: &Env, req: &Request) -> Result<Identity> {
	let dev_var = env.var("GORANI_DEV").map(|v| v.to_string()).ok();
	let dev_mode = dev_var.as_deref() == Some("1");
	let access_configured = env.var("POLICY_AUD").is_ok() && env.var("TEAM_DOMAIN").is_ok();

	if dev_mode && access_configured {
		return Err(Error::RustError("GORANI_DEV=1 but Access is configured: remove the dev var".into()));
	}
	if dev_mode {
		// (Dev mode's twin of a service token: `x-gorani-dev-collector`.)
		if let (None, Some(cn)) = (req.headers().get("x-gorani-dev-email")?, req.headers().get("x-gorani-dev-collector")?) {
			return Ok(Identity { email: String::new(), collector: Some(cn), granted: None });
		}
		let email = req.headers().get("x-gorani-dev-email")?.ok_or_else(|| Error::RustError("dev mode: set x-gorani-dev-email".into()))?;
		return Ok(Identity { email, collector: None, granted: None });
	}
	if !access_configured {
		// Fail closed: a production deployment without Access serves nothing.
		return Err(Error::RustError("Access is not configured (POLICY_AUD/TEAM_DOMAIN missing)".into()));
	}
	let aud = env.var("POLICY_AUD")?.to_string();
	let team = env.var("TEAM_DOMAIN")?.to_string();

	let token = req.headers().get("CF-Access-JWT-Assertion")?.ok_or_else(|| Error::RustError("missing Access token".into()))?;
	let t = parse_token(&token)?;
	if t.header.get("alg").and_then(|a| a.as_str()) != Some("ES256") {
		return Err(Error::RustError("token is not ES256".into()));
	}
	// The signature, against the team's P-256 keys.
	let kid = t.header.get("kid").and_then(|k| k.as_str()).unwrap_or("").to_string();
	let keys = fetch_jwks(env).await?;
	let jwk = keys.iter().find(|k| k.kid == kid).ok_or_else(|| Error::RustError("unknown token key".into()))?;
	// The key must be what the header claimed: P-256, and — when the JWKS
	// names an algorithm — ES256. (alg confusion is the classic JWT bug: a
	// verifier that lets the token pick its own algorithm.)
	if jwk.kty != "EC" || jwk.crv != "P-256" || jwk.alg.as_deref().is_some_and(|a| a != "ES256") {
		return Err(Error::RustError("token key is not an ES256 P-256 key".into()));
	}
	let x = URL_SAFE_NO_PAD.decode(jwk.x.trim_end_matches('=')).map_err(|_| Error::RustError("bad key x".into()))?;
	let y = URL_SAFE_NO_PAD.decode(jwk.y.trim_end_matches('=')).map_err(|_| Error::RustError("bad key y".into()))?;
	let mut point = vec![0x04u8];
	point.extend_from_slice(&x);
	point.extend_from_slice(&y);
	let vk = VerifyingKey::from_sec1_bytes(&point).map_err(|_| Error::RustError("bad team key".into()))?;
	vk.verify(t.signing_input, &Signature::from_slice(&t.signature).map_err(|_| Error::RustError("bad signature shape".into()))?)
		.map_err(|_| Error::RustError("bad signature".into()))?;

	// The claims, once the bytes are trusted.
	let now = now_ms() / 1000;
	let iss = t.claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
	let team_origin = {
		let trimmed = team.trim_end_matches('/');
		let base = trimmed.split("/cdn-cgi").next().unwrap_or(trimmed);
		base.to_string()
	};
	if !iss.starts_with(&team_origin) {
		return Err(Error::RustError(format!("token issuer {iss} is not the team")));
	}
	if t.claims.get("aud").and_then(|v| v.as_str()) != Some(aud.as_str()) {
		return Err(Error::RustError("token audience does not match POLICY_AUD".into()));
	}
	let exp = t.claims.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
	if exp < now {
		return Err(Error::RustError("token expired".into()));
	}
	// A member's token names their email. A SERVICE token's names a
	// `common_name` and no email (commit 37a): that is a collector — or no
	// one, if the registry has no active collector for it (routes.rs asks).
	if let Some(email) = t.claims.get("email").and_then(|v| v.as_str()).filter(|e| !e.is_empty()) {
		return Ok(Identity { email: email.to_string(), collector: None, granted: None });
	}
	match t.claims.get("common_name").and_then(|v| v.as_str()).filter(|c| !c.is_empty()) {
		Some(cn) => Ok(Identity { email: String::new(), collector: Some(cn.to_string()), granted: None }),
		None => Err(Error::RustError("token has no email".into())),
	}
}

/// A member id as the registry names it: a short slug, lowercase, no tricks
/// (it becomes a DO instance name and part of URLs).
pub fn valid_member_id(id: &str) -> bool {
	(2..=32).contains(&id.len()) && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') && !id.starts_with('-') && !id.ends_with('-')
}

/// An id that becomes a segment of an S3 object key or a DO route: file ids,
/// upload ids, device ids, folder ids. 1–64 characters of `[A-Za-z0-9_-]`
/// — the alphabet of the uuids and base64url ids the clients mint.
///
/// Why this exists (security review, commit 23): ids from the URL or the
/// body used to flow straight into keys like `files/<member>/<file>/v-…`
/// and were written to S3 *before* the DO checked anything. The S3 signer
/// keeps `.` unencoded (SigV4 requires it), so an id of `..` produced a
/// path the HTTP stack may normalise — today that only breaks the
/// signature, but "the signature happened to fail" is not a control. The
/// rule here is the allow-list, applied at the edge, before any write.
pub fn valid_object_id(id: &str) -> bool {
	(1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// SHA-256 hex (token hashes in the registry's audit lines).
pub fn sha256_hex(data: &[u8]) -> String {
	hex::encode(<sha2::Sha256 as sha2::Digest>::digest(data))
}

/// May THIS request create the family's first member? (commit 25,
/// docs/SECURITY-REVIEW.md › O18.)
///
/// Before: the first member was created by ANY authenticated caller — on a
/// fresh deploy, whoever got through Access first became a parent (a race
/// an attacker with any allowed identity, or a misconfigured Access policy,
/// would win). Now the operator sets a `BOOTSTRAP_TOKEN` secret and presents
/// it once (`x-gorani-bootstrap`); after the first member exists the token
/// is irrelevant — only parents add members.
///
/// - token configured: the presented value must match (constant time);
/// - not configured, dev server: allowed (the suites bootstrap freely);
/// - not configured, production: REFUSED — fail closed, with the fix named.
pub fn bootstrap_allowed(configured: Option<&str>, presented: Option<&str>, dev: bool) -> Result<(), &'static str> {
	match (configured.filter(|c| !c.is_empty()), presented) {
		(Some(c), Some(p)) if constant_time_eq(c.as_bytes(), p.as_bytes()) => Ok(()),
		(Some(_), _) => Err("the first member needs the bootstrap token (x-gorani-bootstrap)"),
		(None, _) if dev => Ok(()),
		(None, _) => Err("set the BOOTSTRAP_TOKEN secret (wrangler secret put BOOTSTRAP_TOKEN), then create the first parent with it"),
	}
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod bootstrap_tests {
	use super::bootstrap_allowed;

	#[test]
	fn the_first_member_needs_the_token() {
		assert!(bootstrap_allowed(Some("s3cret-token"), Some("s3cret-token"), false).is_ok());
		assert!(bootstrap_allowed(Some("s3cret-token"), Some("wrong"), false).is_err());
		assert!(bootstrap_allowed(Some("s3cret-token"), None, false).is_err());
		assert!(bootstrap_allowed(Some("s3cret-token"), None, true).is_err(), "a configured token binds the dev server too");
		assert!(bootstrap_allowed(None, None, true).is_ok(), "the dev server without a token bootstraps freely");
		assert!(bootstrap_allowed(None, Some("anything"), false).is_err(), "production without a token is closed");
		assert!(bootstrap_allowed(Some(""), None, false).is_err(), "an empty secret is no secret");
	}
}
