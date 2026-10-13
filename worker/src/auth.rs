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
//! Identity is the Access email. The family registry (GoraniFamilyDO) maps
//! emails to members; a parent's email may act for their children at the
//! API layer (the same one-way hierarchy the keys give them cryptographically).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::Digest;
use worker::*;

/// Who the request is. More claims exist; these are the ones gorani acts on.
#[derive(Debug, Clone)]
pub struct Identity {
	pub email: String,
}

/// One JWKS fetch, cached per isolate for ten minutes (a JWKS rotation
/// propagates within minutes; Access signs short-lived tokens).
struct JwksCache {
	fetched_at: SystemTime,
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
			if c.fetched_at.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(600) {
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
		*cached = Some(JwksCache { fetched_at: SystemTime::now(), keys: keys.clone() });
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
		let email = req.headers().get("x-gorani-dev-email")?.ok_or_else(|| Error::RustError("dev mode: set x-gorani-dev-email".into()))?;
		return Ok(Identity { email });
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
	if jwk.kty != "EC" || jwk.crv != "P-256" {
		return Err(Error::RustError("token key is not P-256".into()));
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
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
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
	let email = t.claims.get("email").and_then(|v| v.as_str()).ok_or_else(|| Error::RustError("token has no email".into()))?.to_string();
	Ok(Identity { email })
}

/// A member id as the registry names it: a short slug, lowercase, no tricks
/// (it becomes a DO instance name and part of URLs).
pub fn valid_member_id(id: &str) -> bool {
	(2..=32).contains(&id.len()) && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') && !id.starts_with('-') && !id.ends_with('-')
}

/// SHA-256 hex (token hashes in the registry's audit lines).
pub fn sha256_hex(data: &[u8]) -> String {
	hex::encode(<sha2::Sha256 as sha2::Digest>::digest(data))
}