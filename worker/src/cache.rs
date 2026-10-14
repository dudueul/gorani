// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The edge cache for encrypted blob reads (docs/PRODUCTION.md › Object
//! caching). The rules that make it safe and simple:
//!
//! - **Keys are storage spans, never member URLs.** Ciphertext is
//!   byte-identical for every recipient, so one entry serves the whole
//!   family and every share link; an HLS segment and a direct player
//!   request for the same frames share the entry.
//! - **Object keys are version-unique** (`v-<uuid>`): a cached copy can
//!   never go stale against new content, so the TTL is set-and-forget —
//!   and when content is deleted, crypto-shredding leaves any stale entry
//!   opening to nothing.
//! - **Ciphertext only**: the cache lives in the same trust zone as the
//!   Worker and R2; nothing here can read a plaintext byte.
//!
//! Two layers, keyed under one internal host:
//!   whole  = `https://cache.gorani.internal/<object key>`
//!   span   = `…/<object key>?frames=<a>-<b>`   (GC01 frame indices)
//!
//! The platform's `cache.get` honors a Range header on the request and
//! slices cached WHOLE entries itself (a stored Content-Length makes that
//! possible) — so small files get native range serving from one entry.
//! Span entries are stored with a 200 status (the Cache API refuses 206)
//! whose bytes are exactly the requested span; the caller frames the 206.
//! Bodies stream through `cache.put` — the worker never buffers a blob.

use worker::*;

const HOST: &str = "https://cache.gorani.internal";

/// The size gate. The edge holds the entry, so this protects the plan's
/// cacheable-object size — worker memory stays flat either way, because
/// bodies stream through `cache.put` instead of being buffered.
pub fn max_bytes(env: &Env) -> u64 {
	let mb = env.var("CACHE_MAX_OBJECT_MB").ok().and_then(|v| v.to_string().parse::<u64>().ok()).unwrap_or(256);
	mb.saturating_mul(1024 * 1024)
}

/// The entry TTL in seconds (docs: at least a month by default).
pub fn max_age(env: &Env) -> u64 {
	let days = env.var("CACHE_TTL_DAYS").ok().and_then(|v| v.to_string().parse::<u64>().ok()).unwrap_or(30);
	days.saturating_mul(86_400)
}

/// Whole entries and frame-span entries under one internal host; the span's
/// frame indices are the query string (part of the cache key, per the Cache
/// API's exact-match rule).
pub fn url(key: &str, span: Option<(u64, u64)>) -> String {
	match span {
		Some((a, b)) => format!("{HOST}/{key}?frames={a}-{b}"),
		None => format!("{HOST}/{key}"),
	}
}

/// A GET against the cache key. The caller's Range rides along so the
/// platform slices cached WHOLE entries itself; span lookups are asked
/// plain — their bytes are the requested span, framed by [`serve`].
pub fn request_of(url: &str, range: Option<(u64, u64)>) -> Result<Request> {
	let headers = Headers::new();
	if let Some((off, len)) = range {
		headers.set("Range", &format!("bytes={off}-{}", off + len - 1))?;
	}
	Request::new_with_init(url, &RequestInit { method: Method::Get, headers, ..Default::default() })
}

/// Tag a response with which path served it (`hit`, `miss`, `bypass`) —
/// the observability the tests and the curious read. Rebuilt rather than
/// mutated: fetched and cache-served responses carry immutable headers,
/// and the stream moves across unchanged.
pub fn mark(mut resp: Response, label: &str) -> Result<Response> {
	let status = resp.status_code();
	#[allow(unused_mut)]
	let mut headers = Headers::new();
	for name in ["Content-Length", "Content-Type", "Content-Range", "ETag"] {
		if let Ok(Some(v)) = resp.headers().get(name) {
			headers.set(name, &v)?;
		}
	}
	headers.set("x-gorani-cache", label)?;
	let stream = resp.stream()?;
	Ok(Response::from_stream(stream)?.with_status(status).with_headers(headers))
}

/// Frame a cache answer for the caller. Cache-served responses carry
/// immutable headers — the marker and the span's 206 framing go on through
/// a rebuild that copies what matters (length, type, range).
pub fn serve(mut resp: Response, range: Option<(u64, u64)>, span: bool, label: &str) -> Result<Response> {
	let status = resp.status_code();
	let headers = Headers::new();
	for name in ["Content-Length", "Content-Type", "Content-Range", "ETag"] {
		if let Ok(Some(v)) = resp.headers().get(name) {
			headers.set(name, &v)?;
		}
	}
	headers.set("x-gorani-cache", label)?;
	if span {
		if let Some((off, len)) = range {
			headers.set("Content-Range", &format!("bytes {off}-{}/*", off + len - 1))?;
		}
	}
	let stream = resp.stream()?;
	let out = Response::from_stream(stream)?.with_status(if span { 206 } else { status });
	Ok(out.with_headers(headers))
}
