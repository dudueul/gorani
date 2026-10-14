// Copyright 2026- Seongwoo Hong. All rights reserved.
// The transport follows the S3 adapter written for the stream-worker
// project; see NOTICE.

//! The S3 transport: gorani-s3's signatures (pure, tested) driven through
//! the Workers runtime's fetch. Five object operations and multipart — the
//! entire surface the file store needs; anything fancier belongs in an SDK,
//! not in a security-sensitive worker.
//!
//! ```text
//! caller ──▶ ops (this file) ──▶ R2 binding (when bound: in-process, no signing) ──▶ R2
//!                            └─▶ sign_request (gorani-s3) ──▶ Fetch ──▶ MinIO/S3
//! ```
//!
//! Every byte crossing this module is ciphertext (GV02/GC01 frames, sealed
//! sidecars, backup segments); the bucket is private and its keys are
//! Worker secrets. Nothing here inspects content beyond sizes and statuses.

use gorani_s3::{complete_multipart_body, sign_request, xml_val, S3Config, SignedRequest};
use worker::*;

use crate::cache;

/// A HEAD result: the size (what the "must add up" checks compare).
#[derive(Debug, Clone)]
pub struct HeadInfo {
	pub size: u64,
}

/// The R2 binding name (wrangler.jsonc › `r2_buckets`). **Storage priority**:
/// when the deployment binds an R2 bucket, every operation below takes the
/// binding instead of the signed S3 transport — an in-process call with no
/// signing, no HTTP hop and no egress fees (Cloudflare↔R2 is free and local
/// to the runtime). Any S3-compatible endpoint (MinIO &c.) keeps working
/// through the SigV4 path whenever the binding is absent.
///
/// Any error resolving the binding (absent, or misconfigured) means "not
/// bound": the S3 adapter then serves and reports its own, honest error.
async fn r2_bucket(env: &Env) -> Result<Option<Bucket>> {
	match env.bucket("R2BUCKET") {
		Ok(bucket) => Ok(Some(bucket)),
		Err(_) => Ok(None),
	}
}

/// Resolve the configuration: vars for endpoint/region/bucket, secrets (or
/// plain vars, in `wrangler dev`) for the credentials.
pub fn config(env: &Env) -> Result<S3Config> {
	let var = |name: &str| -> Result<String> {
		env.var(name).map(|v| v.to_string()).map_err(|_| Error::RustError(format!("missing {name} for the S3 backend")))
	};
	let secret = |name: &str| -> Result<String> {
		env.secret(name).map(|v| v.to_string()).or_else(|_| var(name))
	};
	let endpoint = var("S3_ENDPOINT")?.trim_end_matches('/').to_string();
	// TLS is part of the signing contract, not an option (security review,
	// commit 23). The signer uses UNSIGNED-PAYLOAD — the body is NOT covered
	// by the signature, only by the transport — so over plain http anyone
	// on the path could swap ciphertext in flight, and would see every
	// object key and access-key id. `wrangler dev` against the local stub
	// (GORANI_DEV=1, never set in production — auth.rs) is the one place a
	// plain-http endpoint is allowed.
	let dev = env.var("GORANI_DEV").map(|v| v.to_string() == "1").unwrap_or(false);
	if !endpoint.starts_with("https://") && !(dev && endpoint.starts_with("http://")) {
		return Err(Error::RustError("S3_ENDPOINT must be an https:// URL".into()));
	}
	Ok(S3Config {
		endpoint,
		region: var("S3_REGION")?,
		bucket: var("S3_BUCKET")?,
		access_key: secret("S3_ACCESS_KEY_ID")?,
		secret_key: secret("S3_SECRET_KEY")?,
	})
}

/// The wall clock in seconds (js_sys, because the Workers runtime is the
/// platform; injected here so the signer stays pure).
fn now_secs() -> i64 {
	(js_sys::Date::now() / 1000.0) as i64
}

fn method_of(name: &str) -> Result<Method> {
	Ok(match name {
		"GET" => Method::Get,
		"PUT" => Method::Put,
		"POST" => Method::Post,
		"DELETE" => Method::Delete,
		"HEAD" => Method::Head,
		_ => return Err(Error::RustError(format!("unsupported S3 method {name}"))),
	})
}

/// Sign (gorani-s3), build the Workers request, and send it.
async fn fetch_signed(cfg: &S3Config, method: &str, object_key: &str, query_pairs: &[(String, String)], range: Option<(u64, u64)>, body: Option<Vec<u8>>, content_type: Option<&str>) -> Result<Response> {
	let SignedRequest { url, headers, .. } =
		sign_request(cfg, method, object_key, query_pairs, now_secs()).map_err(|e| Error::RustError(format!("signing: {e}")))?;
	let wh = Headers::new();
	for (k, v) in &headers {
		wh.set(k, v)?;
	}
	// The Range header is unsigned by design ( UNSIGNED-PAYLOAD ): the
	// signature covers host;x-amz-content-sha256;x-amz-date only, and one
	// signature serves any range of one object.
	if let Some((off, len)) = range {
		wh.set("Range", &format!("bytes={off}-{}", off + len - 1))?;
	}
	if let Some(ct) = content_type {
		wh.set("Content-Type", ct)?;
	}
	let req = Request::new_with_init(&url, &RequestInit { method: method_of(method)?, headers: wh, body: body.map(|b| b.into()), ..Default::default() })?;
	Fetch::Request(req).send().await
}

// ── Object operations ───────────────────────────────────────────────

/// Full GET into memory; None on 404. **Uncached on purpose** (commit 23):
/// its only caller is the backup job, which reads EVERY object of a member
/// once — caching that walk filled the edge with the whole vault and cost
/// a full extra copy of each object in worker memory (the clone handed to
/// `cache.put`). Interactive reads go through [`fetch_stream`], which is
/// the path the cache was designed for.
pub async fn get(env: &Env, key: &str) -> Result<Option<Vec<u8>>> {
	if let Some(bucket) = r2_bucket(env).await? {
		return match bucket.get(key).execute().await? {
			Some(o) => match o.body() {
				Some(b) => Ok(Some(b.bytes().await?)),
				None => Ok(None),
			},
			None => Ok(None),
		};
	}
	let cfg = config(env)?;
	let mut resp = fetch_signed(&cfg, "GET", key, &[], None, None, None).await?;
	match resp.status_code() {
		200 => Ok(Some(resp.bytes().await?)),
		404 => Ok(None),
		s => Err(Error::RustError(format!("S3 get {key}: HTTP {s}"))),
	}
}

/// Full GET as a **streamable** Response (the file route pipes the body
/// through with a Range header); None-style errors surfaced via status.
///
/// The cache (crate::cache) wraps this: whole-object entries for small
/// reads (any later Range sliced by the platform itself), frame-span
/// entries for chunked media (`cache_span` vouched for by the route — the
/// media worker requests whole frames, so the span is deterministic).
/// Bodies stream through `cache.put`; the worker never buffers a blob.
pub async fn fetch_stream(env: &Env, method: &str, key: &str, range: Option<(u64, u64)>, query_pairs: &[(String, String)], cache_span: Option<(u64, u64)>) -> Result<Response> {
	// Every GET consults the cache: whole entries are asked WITH the
	// caller's Range so the platform slices them itself; span entries are
	// asked plain (their bytes are the span). A ranged MISS on the whole
	// key streams through — caching it would mean inflating the fetch to
	// the whole object, not worth it on external-S3 egress.
	if method != "GET" {
		return Ok(origin_stream(env, key, range, query_pairs).await?);
	}
	let cache = Cache::default();
	let url = cache::url(key, cache_span);
	let lookup = cache::request_of(&url, if cache_span.is_some() { None } else { range })?;
	if let Some(hit) = cache.get(&lookup, false).await? {
		return cache::serve(hit, range, cache_span.is_some(), "hit");
	}
	if range.is_some() && cache_span.is_none() {
		return cache::mark(origin_stream(env, key, range, query_pairs).await?, "bypass");
	}
	// ── miss: origin, then cache the copy when it fits the gate ────────
	let mut origin = origin_stream(env, key, range, query_pairs).await?;
	if origin.status_code() != 200 && origin.status_code() != 206 {
		return Ok(origin); // 404s and oddities are the caller's business
	}
	// The honest size: what the origin says it is sending (the route's
	// spans end at the object's end, so a span's length == its actual).
	let len: Option<u64> = origin.headers().get("Content-Length")?.and_then(|v| v.parse().ok());
	if len.map(|l| l > cache::max_bytes(env)).unwrap_or(true) {
		return cache::mark(origin, "bypass");
	}
	// Span copies are stored as 200 entries whose bytes are the span; whole
	// copies keep their origin headers. The entry is a REBUILD — fetched and
	// cache-served responses carry immutable headers — and the body streams
	// through `cache.put` untouched: no worker buffering, either way.
	let stream = origin.stream()?;
	let mut entry = Response::from_stream(stream)?;
	entry.headers_mut().set("Cache-Control", &format!("public, max-age={}, immutable", cache::max_age(env)))?;
	entry.headers_mut().set("Content-Length", &len.unwrap_or(0).to_string())?;
	entry.headers_mut().set("Content-Type", "application/octet-stream")?;
	cache.put(&url, entry).await?;
	match cache.get(&lookup, false).await? {
		Some(hit) => cache::serve(hit, range, cache_span.is_some(), "miss"),
		// The cache write vanished (plan limits, eviction mid-flight):
		// serve from origin rather than failing the read.
		None => origin_stream(env, key, range, query_pairs).await,
	}
}

/// A whole-object read that streams and never touches the edge cache — for
/// objects whose lifetime the cache must not extend (backups: pruned after
/// seven runs, they would otherwise live on at the edge for the TTL).
/// A 404 comes back as a 404 response.
pub async fn stream_uncached(env: &Env, key: &str) -> Result<Response> {
	origin_stream(env, key, None, &[]).await
}

/// The uncached origin read: the R2 binding when bound, the signed S3
/// transport otherwise.
async fn origin_stream(env: &Env, key: &str, range: Option<(u64, u64)>, query_pairs: &[(String, String)]) -> Result<Response> {
	if let Some(bucket) = r2_bucket(env).await? {
		// (query_pairs serve the S3 signed URL; the binding needs none. The
		// headers mirror what the S3 answer carries — length and an honest
		// Content-Range — so the file route's passthrough keeps working.)
		let mut g = bucket.get(key);
		if let Some((off, len)) = range {
			g = g.range(Range::OffsetWithLength { offset: off, length: len });
		}
		return match g.execute().await? {
			Some(o) => {
				let status = if range.is_some() { 206 } else { 200 };
				let headers = Headers::new();
				headers.set("Content-Type", "application/octet-stream")?;
				// The honest length: a span's bytes are its declared length
				// clamped by the object's end (the last frame may be short).
				let clen = range.map(|(off, len)| len.min(o.size().saturating_sub(off))).unwrap_or_else(|| o.size());
				headers.set("Content-Length", &clen.to_string())?;
				if let Some((off, len)) = range {
					headers.set("Content-Range", &format!("bytes {off}-{}/*", off + len - 1))?;
				}
				let body = o.body().ok_or_else(|| Error::RustError(format!("R2 stream {key}: no body")))?;
				Ok(Response::from_stream(body.stream()?)?.with_status(status).with_headers(headers))
			}
			None => Ok(Response::error("Not Found", 404)?),
		};
	}
	let cfg = config(env)?;
	fetch_signed(&cfg, "GET", key, query_pairs, range, None, None).await
}

/// Size + etag via HEAD. None on 404.
pub async fn head(env: &Env, key: &str) -> Result<Option<HeadInfo>> {
	if let Some(bucket) = r2_bucket(env).await? {
		return Ok(bucket.head(key).await?.map(|o| HeadInfo { size: o.size() }));
	}
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "HEAD", key, &[], None, None, None).await?;
	match resp.status_code() {
		200 => Ok(Some(HeadInfo { size: resp.headers().get("Content-Length")?.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) })),
		404 => Ok(None),
		s => Err(Error::RustError(format!("S3 head {key}: HTTP {s}"))),
	}
}

/// Simple PUT (small objects; big ones go through multipart).
pub async fn put(env: &Env, key: &str, bytes: Vec<u8>) -> Result<()> {
	if let Some(bucket) = r2_bucket(env).await? {
		bucket.put(key, bytes).execute().await?;
		return Ok(());
	}
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "PUT", key, &[], None, Some(bytes), Some("application/octet-stream")).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("S3 put {key}: HTTP {}", resp.status_code())));
	}
	Ok(())
}

/// DELETE; a missing object counts as deleted.
pub async fn delete(env: &Env, key: &str) -> Result<()> {
	if let Some(bucket) = r2_bucket(env).await? {
		// (R2's delete resolves even when the key is absent — the same
		// contract as the S3 path's 204|404.)
		bucket.delete(key).await?;
		return Ok(());
	}
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "DELETE", key, &[], None, None, None).await?;
	match resp.status_code() {
		204 | 404 => Ok(()),
		s => Err(Error::RustError(format!("S3 delete {key}: HTTP {s}"))),
	}
}

// ── Multipart upload (GC01 frames: one frame per part) ──────────────

/// Initiate: returns the S3 UploadId.
pub async fn multipart_init(env: &Env, key: &str) -> Result<String> {
	if let Some(bucket) = r2_bucket(env).await? {
		let upload = bucket.create_multipart_upload(key).execute().await?;
		return Ok(upload.upload_id().await);
	}
	let cfg = config(env)?;
	let mut resp = fetch_signed(&cfg, "POST", key, &[("uploads".to_string(), String::new())], None, None, None).await?;
	let status = resp.status_code();
	let body = resp.text().await?;
	if status != 200 {
		return Err(Error::RustError(format!("S3 multipart init: HTTP {status} {body}")));
	}
	xml_val(&body, "UploadId").ok_or_else(|| Error::RustError("S3 multipart init: no UploadId".into()))
}

/// Upload one part (1-based); returns its ETag (quoted, kept verbatim for the Complete request).
pub async fn multipart_part(env: &Env, key: &str, upload_id: &str, part: u32, bytes: Vec<u8>) -> Result<String> {
	if let Some(bucket) = r2_bucket(env).await? {
		// resume_* rebuilds the handle from the (key, uploadId) pair the DO
		// already stores for the S3 path — one shape of upload state for both
		// backends.
		let upload = bucket.resume_multipart_upload(key, upload_id)?;
		let uploaded = upload.upload_part(part as u16, bytes).await?;
		return Ok(uploaded.etag());
	}
	let cfg = config(env)?;
	let q = [("partNumber".to_string(), part.to_string()), ("uploadId".to_string(), upload_id.to_string())];
	let resp = fetch_signed(&cfg, "PUT", key, &q, None, Some(bytes), Some("application/octet-stream")).await?;
	let status = resp.status_code();
	let etag = resp.headers().get("ETag")?;
	if status != 200 {
		return Err(Error::RustError(format!("S3 part {part}: HTTP {status}")));
	}
	etag.ok_or_else(|| Error::RustError("S3 part: missing ETag".into()))
}

/// Complete: parts are (number, etag) in ascending order.
pub async fn multipart_complete(env: &Env, key: &str, upload_id: &str, parts: &[(u32, String)]) -> Result<()> {
	if let Some(bucket) = r2_bucket(env).await? {
		let upload = bucket.resume_multipart_upload(key, upload_id)?;
		upload
			.complete(parts.iter().map(|(n, etag)| UploadedPart::new(*n as u16, etag.clone())))
			.await?;
		return Ok(());
	}
	let cfg = config(env)?;
	let q = [("uploadId".to_string(), upload_id.to_string())];
	let mut resp = fetch_signed(&cfg, "POST", key, &q, None, Some(complete_multipart_body(parts)), Some("application/xml")).await?;
	let status = resp.status_code();
	let text = resp.text().await?;
	// S3's documented trap: CompleteMultipartUpload can answer **200 with an
	// `<Error>` body** (the status is sent before the server finishes
	// assembling). A 200 alone is not success.
	if status != 200 || xml_val(&text, "Code").is_some() {
		return Err(Error::RustError(format!("S3 multipart complete: HTTP {status} {}", xml_val(&text, "Code").unwrap_or_default())));
	}
	Ok(())
}

/// Abort (frees the stored parts; the daily housekeeping also calls this on
/// uploads that never finished).
pub async fn multipart_abort(env: &Env, key: &str, upload_id: &str) -> Result<()> {
	if let Some(bucket) = r2_bucket(env).await? {
		bucket.resume_multipart_upload(key, upload_id)?.abort().await?;
		return Ok(());
	}
	let cfg = config(env)?;
	let q = [("uploadId".to_string(), upload_id.to_string())];
	let resp = fetch_signed(&cfg, "DELETE", key, &q, None, None, None).await?;
	match resp.status_code() {
		204 | 404 => Ok(()),
		s => Err(Error::RustError(format!("S3 multipart abort: HTTP {s}"))),
	}
}
