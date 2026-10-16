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

use gorani_s3::{complete_multipart_body, md5, refusal_reason, retention_xml, sign_request, xml_val, xml_vals, S3Config, SignedRequest};
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
	// Every value trimmed (commit 39s): a secret pasted with its line's end
	// (`echo … | wrangler secret put`, a copied console field) carries a
	// newline or a space that no key, region or bucket name ever contains —
	// signed in, it fails every request as a bad signature, with nothing in
	// the dashboard to show it. Team › People › Check storage says when a
	// value had any (`settings_shape`).
	let var = |name: &str| -> Result<String> {
		env.var(name).map(|v| v.to_string().trim().to_string()).map_err(|_| Error::RustError(format!("missing {name} for the S3 backend")))
	};
	let secret = |name: &str| -> Result<String> {
		env.secret(name).map(|v| v.to_string().trim().to_string()).or_else(|_| var(name))
	};
	let raw = var("S3_ENDPOINT")?.trim_end_matches('/').to_string();
	// A bare host (`s3.eu-central-1.idrivee2.com`, as provider consoles show
	// it) means https — never http, which only `wrangler dev` may use.
	let endpoint = if raw.contains("://") { raw } else { format!("https://{raw}") };
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
		// (`S3_SECRET_ACCESS_KEY`, the AWS-style name, is accepted too.)
		secret_key: secret("S3_SECRET_KEY").or_else(|_| secret("S3_SECRET_ACCESS_KEY"))?,
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
	fetch_signed_js(cfg, method, object_key, query_pairs, range, body.map(|b| b.into()), content_type).await
}

/// The same, with any JS body — a stream of known length included (D12:
/// a part piped through, never buffered).
async fn fetch_signed_js(cfg: &S3Config, method: &str, object_key: &str, query_pairs: &[(String, String)], range: Option<(u64, u64)>, body: Option<wasm_bindgen::JsValue>, content_type: Option<&str>) -> Result<Response> {
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
	let req = Request::new_with_init(&url, &RequestInit { method: method_of(method)?, headers: wh, body, ..Default::default() })?;
	Fetch::Request(req).send().await
}

/// A storage refusal, explained (commit 39s): S3's own error code from the
/// answer's body and the `Server` header, read into words by
/// `gorani_s3::refusal_reason` — "HTTP 403" alone has five causes and five
/// different fixes. `what` names the operation and key for the operator's
/// log; the browser is told only the reason (lib.rs › `public_reason`).
async fn refused(what: &str, mut resp: Response) -> Error {
	let status = resp.status_code();
	let server = resp.headers().get("Server").ok().flatten().unwrap_or_default();
	let bodied = !what.starts_with("head ");
	let body = if bodied { resp.text().await.unwrap_or_default() } else { String::new() };
	Error::RustError(format!("S3 {what}: {}", refusal_reason(status, xml_val(&body, "Code").as_deref(), &server, bodied)))
}

/// What a caller may be told of a storage error: "HTTP 403 AccessDenied"
/// — the status and S3's code, never the object key or the endpoint the
/// operator's log line carries (lib.rs answers unhandled errors with this
/// when there is one, and "internal error" otherwise).
pub fn public_reason(message: &str) -> Option<String> {
	let rest = message.strip_prefix("S3 ")?;
	let at = rest.find(": HTTP ")?;
	let reason = &rest[at + 2..];
	let short = reason.split(" — ").next().unwrap_or(reason).split(" (").next().unwrap_or(reason);
	Some(short.trim().to_string())
}

// ── Object operations ───────────────────────────────────────────────

// (A whole-object `get` into memory lived here until commit 25: its only
// caller, the backup job, now streams every object through
// `stream_uncached` — O9. A helper that invites holding a 255 GB file in a
// 128 MB isolate is a helper to delete.)

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

/// Size + etag via HEAD. None when the key does not resolve to an object:
/// 404 — or, on a versioned bucket whose current version is a DELETE
/// MARKER, 405 (IDrive e2; AWS answers 404 with `x-amz-delete-marker`).
pub async fn head(env: &Env, key: &str) -> Result<Option<HeadInfo>> {
	if let Some(bucket) = r2_bucket(env).await? {
		return Ok(bucket.head(key).await?.map(|o| HeadInfo { size: o.size() }));
	}
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "HEAD", key, &[], None, None, None).await?;
	match resp.status_code() {
		200 => Ok(Some(HeadInfo { size: resp.headers().get("Content-Length")?.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) })),
		404 | 405 => Ok(None),
		_ => Err(refused(&format!("head {key}"), resp).await),
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
		return Err(refused(&format!("put {key}"), resp).await);
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
	// Only a key that still resolves is deleted. On a versioned bucket (every
	// Object Lock bucket is one) a DELETE adds a delete marker — and IDrive
	// e2 answers a SECOND plain DELETE by removing that marker: the object
	// comes back (found by the live run, 2026-10-15: a share link's copy,
	// deleted at revoke, deleted again by the nightly purge, was readable
	// in the bucket afterwards). AWS would add a second marker; checking
	// first makes "delete" mean the same on both.
	if head(env, key).await?.is_none() {
		return Ok(());
	}
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "DELETE", key, &[], None, None, None).await?;
	match resp.status_code() {
		204 | 404 => Ok(()),
		_ => Err(refused(&format!("delete {key}"), resp).await),
	}
}

/// Keys under a prefix (ListObjectsV2; R2's list), at most `max` — for
/// small listings only: the audit checkpoints of one area (audit.rs). The
/// verification reads the bucket's own word on which checkpoints exist,
/// not the database it is checking.
pub async fn list(env: &Env, prefix: &str, max: usize) -> Result<Vec<String>> {
	let mut out: Vec<String> = Vec::new();
	if let Some(bucket) = r2_bucket(env).await? {
		let mut cursor: Option<String> = None;
		loop {
			let mut b = bucket.list().prefix(prefix.to_string());
			if let Some(c) = cursor.take() {
				b = b.cursor(c);
			}
			let objects = b.execute().await?;
			out.extend(objects.objects().into_iter().map(|o| o.key()));
			if !objects.truncated() || out.len() >= max {
				break;
			}
			cursor = objects.cursor();
			if cursor.is_none() {
				break;
			}
		}
		out.truncate(max);
		return Ok(out);
	}
	let cfg = config(env)?;
	let mut token: Option<String> = None;
	loop {
		let mut q = vec![("list-type".to_string(), "2".to_string()), ("prefix".to_string(), prefix.to_string())];
		if let Some(t) = &token {
			q.push(("continuation-token".to_string(), t.clone()));
		}
		let mut resp = fetch_signed(&cfg, "GET", "", &q, None, None, None).await?;
		if resp.status_code() != 200 {
			return Err(refused(&format!("list {prefix}"), resp).await);
		}
		let xml = resp.text().await?;
		out.extend(xml_vals(&xml, "Key"));
		let truncated = xml_val(&xml, "IsTruncated").is_some_and(|t| t == "true");
		token = xml_val(&xml, "NextContinuationToken");
		if !truncated || token.is_none() || out.len() >= max {
			break;
		}
	}
	out.truncate(max);
	Ok(out)
}

/// How an object's retention was applied.
pub enum Lock {
	/// COMPLIANCE retention set on the object itself.
	Locked,
	/// R2: no per-object retention through the binding — the bucket's lock
	/// rules are the control (docs/PRODUCTION.md).
	BucketRule,
}

/// `PUT <key>?retention`: COMPLIANCE until `until` (docs/CUSTODY.md ›
/// Stage 3). Content-MD5 because S3 and MinIO demand an integrity check on
/// a retention write; it is not signed (only x-amz-* headers must be).
pub async fn put_retention(env: &Env, key: &str, until: &str) -> Result<Lock> {
	if r2_bucket(env).await?.is_some() {
		return Ok(Lock::BucketRule);
	}
	let cfg = config(env)?;
	let body = retention_xml(until);
	let SignedRequest { url, headers, .. } = sign_request(&cfg, "PUT", key, &[("retention".to_string(), String::new())], now_secs()).map_err(|e| Error::RustError(format!("signing: {e}")))?;
	let wh = Headers::new();
	for (k, v) in &headers {
		wh.set(k, v)?;
	}
	use base64::Engine;
	wh.set("Content-MD5", &base64::engine::general_purpose::STANDARD.encode(md5(&body)))?;
	wh.set("Content-Type", "application/xml")?;
	let req = Request::new_with_init(&url, &RequestInit { method: Method::Put, headers: wh, body: Some(body.into()), ..Default::default() })?;
	let resp = Fetch::Request(req).send().await?;
	match resp.status_code() {
		200 | 204 => Ok(Lock::Locked),
		_ => Err(refused(&format!("retention {key}"), resp).await),
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
	// (Until 39s this error echoed the WHOLE body — and a
	// SignatureDoesNotMatch body carries the string-to-sign and the access
	// key id into the log.)
	if resp.status_code() != 200 {
		return Err(refused(&format!("multipart init {key}"), resp).await);
	}
	let body = resp.text().await?;
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
	let etag = resp.headers().get("ETag")?;
	if resp.status_code() != 200 {
		return Err(refused(&format!("part {part} of {key}"), resp).await);
	}
	etag.ok_or_else(|| Error::RustError("S3 part: missing ETag".into()))
}

/// Upload one part AS IT ARRIVES (D12, docs/LARGE-FILES.md): `len` bytes
/// from the client's request, piped to the backend with the length fixed —
/// never held whole in the isolate. (`multipart_part` copied a part three
/// times on its way: request → Vec → copy → the outgoing body. At 8 MiB
/// that was 24 MB; at the 32 MiB a 255 GB file needs it would have been
/// most of the isolate's 128 MB.) S3 signs `UNSIGNED-PAYLOAD`, so nothing
/// needs the bytes before they go; the completion still checks that the
/// object adds up to its frames.
pub async fn multipart_part_stream(env: &Env, key: &str, upload_id: &str, part: u32, body: ByteStream, len: u64) -> Result<String> {
	let stream = FixedLengthStream::wrap(body, len);
	if let Some(bucket) = r2_bucket(env).await? {
		let upload = bucket.resume_multipart_upload(key, upload_id)?;
		return Ok(upload.upload_part(part as u16, stream).await?.etag());
	}
	let cfg = config(env)?;
	let q = [("partNumber".to_string(), part.to_string()), ("uploadId".to_string(), upload_id.to_string())];
	let resp = fetch_signed_js(&cfg, "PUT", key, &q, None, Some(Data::from(stream).into()), Some("application/octet-stream")).await?;
	let etag = resp.headers().get("ETag")?;
	if resp.status_code() != 200 {
		return Err(refused(&format!("part {part} of {key}"), resp).await);
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
		let server = resp.headers().get("Server").ok().flatten().unwrap_or_default();
		return Err(Error::RustError(format!("S3 multipart complete {key}: {}", refusal_reason(status, xml_val(&text, "Code").as_deref(), &server, true))));
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
		_ => Err(refused(&format!("multipart abort {key}"), resp).await),
	}
}

// ── Team › People › Check storage (commit 39s) ────────────────────

/// One probe step's outcome.
fn step(name: &str, ok: bool, status: u16, reason: Option<String>, server: &str) -> serde_json::Value {
	serde_json::json!({ "step": name, "ok": ok, "status": status, "reason": reason, "server": server })
}

/// The five settings as the deployment holds them — never their values
/// beyond what an operator needs to recognise them: the endpoint, region
/// and bucket (configuration, not credentials), the access key id's last
/// four characters (enough to tell WHICH key, as provider consoles list
/// them) and the secret's length only. `padded`: the stored value had
/// spaces or a line end around it (config() trims them now; the stored
/// secret still should be set again cleanly).
fn settings_shape(env: &Env) -> serde_json::Value {
	let raw = |name: &str| env.secret(name).map(|v| v.to_string()).ok().or_else(|| env.var(name).map(|v| v.to_string()).ok());
	let entry = |name: &str, show: &dyn Fn(&str) -> String| match raw(name) {
		Some(v) => serde_json::json!({ "name": name, "set": true, "padded": v != v.trim(), "shown": show(v.trim()) }),
		None => serde_json::json!({ "name": name, "set": false }),
	};
	let plain = |v: &str| v.to_string();
	let tail = |v: &str| format!("…{}", v.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<String>());
	let length = |v: &str| format!("{} characters", v.chars().count());
	let secret_name = if raw("S3_SECRET_KEY").is_some() { "S3_SECRET_KEY" } else { "S3_SECRET_ACCESS_KEY" };
	serde_json::json!([
		entry("S3_ENDPOINT", &plain),
		entry("S3_REGION", &plain),
		entry("S3_BUCKET", &plain),
		entry("S3_ACCESS_KEY_ID", &tail),
		entry(secret_name, &length),
	])
}

/// Mistakes the settings show by themselves, before a request is sent.
fn settings_warnings(cfg: &S3Config) -> Vec<String> {
	let mut out = Vec::new();
	let host = cfg.endpoint.split("//").nth(1).unwrap_or_default().split('/').next().unwrap_or_default().to_ascii_lowercase();
	// The bucket in the host: consoles show a "bucket endpoint" for
	// virtual-hosted addressing; gorani addresses by path, so the request
	// would name the bucket twice.
	if !cfg.bucket.is_empty() && host.starts_with(&format!("{}.", cfg.bucket.to_ascii_lowercase())) {
		out.push(format!("S3_ENDPOINT's host begins with the bucket's name — gorani puts the bucket in the path; use the host without \"{}.\"", cfg.bucket));
	}
	// A region named in the host (s3.eu-central-1.idrivee2.com) that is not
	// S3_REGION: signed into every request's scope, refused as a bad signature.
	let named = host.split('.').find(|label| {
		let parts: Vec<&str> = label.split('-').collect();
		parts.len() >= 3 && parts[0].len() == 2 && parts[0].chars().all(|c| c.is_ascii_lowercase()) && parts.last().is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
	});
	if let Some(region) = named {
		if region != cfg.region {
			out.push(format!("S3_ENDPOINT's host names the region {region}, but S3_REGION is \"{}\" — the request is signed for S3_REGION", cfg.region));
		}
	}
	out
}

/// A real round trip — write, read the size back, read the bytes back,
/// delete — on a probe object of 16 random bytes under `probe/`, each
/// step's answer explained. It stops at the first refusal (the later steps
/// would only repeat it). A lead runs it from Team › People; routes.rs ›
/// storage_probe checks the role.
///
/// On a versioned bucket (every Object Lock bucket is one) the delete
/// leaves a 16-byte noncurrent version and a delete marker, which the
/// bucket's noncurrent-version lifecycle rule removes (docs/PRODUCTION.md).
pub async fn probe(env: &Env) -> Result<serde_json::Value> {
	let mut id = [0u8; 8];
	getrandom::getrandom(&mut id).map_err(|e| Error::RustError(format!("no randomness: {e}")))?;
	let key = format!("probe/{}", hex::encode(id));
	let mut bytes = [0u8; 16];
	getrandom::getrandom(&mut bytes).map_err(|e| Error::RustError(format!("no randomness: {e}")))?;
	let mut steps = Vec::new();

	if let Some(bucket) = r2_bucket(env).await? {
		// The binding signs nothing and has no statuses: each step either
		// works or names the binding's error.
		let r2 = |name: &str, r: std::result::Result<bool, String>| match r {
			Ok(true) => step(name, true, 200, None, "r2"),
			Ok(false) => step(name, false, 0, Some("the binding answered, but not with the probe's bytes".into()), "r2"),
			Err(e) => step(name, false, 0, Some(e), "r2"),
		};
		let put = bucket.put(&key, bytes.to_vec()).execute().await.map(|_| true).map_err(|e| e.to_string());
		let ok = put.is_ok();
		steps.push(r2("write", put));
		if ok {
			let got = match bucket.get(&key).execute().await {
				Ok(Some(o)) => match o.body() {
					Some(b) => b.bytes().await.map(|v| v == bytes).map_err(|e| e.to_string()),
					None => Ok(false),
				},
				Ok(None) => Ok(false),
				Err(e) => Err(e.to_string()),
			};
			steps.push(r2("read", got));
			steps.push(r2("delete", bucket.delete(&key).await.map(|_| true).map_err(|e| e.to_string())));
		}
		let ok = steps.iter().all(|s| s["ok"].as_bool() == Some(true));
		return Ok(serde_json::json!({ "backend": "r2", "ok": ok, "steps": steps }));
	}

	let settings = settings_shape(env);
	let cfg = match config(env) {
		Ok(cfg) => cfg,
		Err(e) => return Ok(serde_json::json!({ "backend": "s3", "ok": false, "settings": settings, "warnings": [e.to_string()], "steps": [] })),
	};
	let warnings = settings_warnings(&cfg);
	let server_of = |r: &Response| r.headers().get("Server").ok().flatten().unwrap_or_default();

	// 1. write
	let mut resp = fetch_signed(&cfg, "PUT", &key, &[], None, Some(bytes.to_vec()), Some("application/octet-stream")).await?;
	let (status, server) = (resp.status_code(), server_of(&resp));
	if status != 200 {
		let body = resp.text().await.unwrap_or_default();
		steps.push(step("write", false, status, Some(refusal_reason(status, xml_val(&body, "Code").as_deref(), &server, true)), &server));
	} else {
		steps.push(step("write", true, status, None, &server));
		// 2. size
		let resp = fetch_signed(&cfg, "HEAD", &key, &[], None, None, None).await?;
		let (status, server) = (resp.status_code(), server_of(&resp));
		let size = resp.headers().get("Content-Length")?.and_then(|v| v.parse::<u64>().ok());
		let size_ok = status == 200 && size == Some(16);
		steps.push(step("size", size_ok, status, (!size_ok).then(|| if status == 200 { format!("the size read back is {size:?}, not 16") } else { refusal_reason(status, None, &server, false) }), &server));
		// 3. read
		let mut resp = fetch_signed(&cfg, "GET", &key, &[], None, None, None).await?;
		let (status, server) = (resp.status_code(), server_of(&resp));
		if status == 200 {
			let same = resp.bytes().await? == bytes;
			steps.push(step("read", same, status, (!same).then(|| "the bytes read back are not the ones written".to_string()), &server));
		} else {
			let body = resp.text().await.unwrap_or_default();
			steps.push(step("read", false, status, Some(refusal_reason(status, xml_val(&body, "Code").as_deref(), &server, true)), &server));
		}
		// 4. delete (tried even after a failed read: the probe cleans up)
		let mut resp = fetch_signed(&cfg, "DELETE", &key, &[], None, None, None).await?;
		let (status, server) = (resp.status_code(), server_of(&resp));
		let ok = status == 204 || status == 200;
		let reason = if ok { None } else { Some(refusal_reason(status, xml_val(&resp.text().await.unwrap_or_default(), "Code").as_deref(), &server, true)) };
		steps.push(step("delete", ok, status, reason, &server));
	}
	let ok = steps.iter().all(|s| s["ok"].as_bool() == Some(true));
	Ok(serde_json::json!({ "backend": "s3", "ok": ok, "settings": settings, "warnings": warnings, "steps": steps }))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cfg(endpoint: &str, region: &str, bucket: &str) -> S3Config {
		S3Config { endpoint: endpoint.into(), region: region.into(), bucket: bucket.into(), access_key: "k".into(), secret_key: "s".into() }
	}

	/// 39s: the settings' own mistakes, found before a request is sent.
	#[test]
	fn settings_warnings_name_the_mismatch() {
		assert!(settings_warnings(&cfg("https://s3.eu-central-1.idrivee2.com", "eu-central-1", "gorani")).is_empty());
		let w = settings_warnings(&cfg("https://s3.eu-central-1.idrivee2.com", "us-east-1", "gorani"));
		assert!(w.len() == 1 && w[0].contains("eu-central-1") && w[0].contains("us-east-1"), "{w:?}");
		let w = settings_warnings(&cfg("https://gorani.s3.eu-central-1.idrivee2.com", "eu-central-1", "gorani"));
		assert!(w.iter().any(|m| m.contains("bucket's name")), "{w:?}");
		// R2's host names no region ("auto"); MinIO's neither.
		assert!(settings_warnings(&cfg("https://abc123.r2.cloudflarestorage.com", "auto", "gorani")).is_empty());
		assert!(settings_warnings(&cfg("https://minio.example.com", "us-east-1", "gorani")).is_empty());
	}

	/// The caller hears the status and S3's code; the key stays in the log.
	#[test]
	fn public_reason_drops_the_key() {
		let m = format!("S3 put files/me/abc/v-1: {}", refusal_reason(403, Some("AccessDenied"), "", true));
		assert_eq!(public_reason(&m).as_deref(), Some("HTTP 403 AccessDenied"));
		assert_eq!(public_reason(&format!("S3 head files/x: {}", refusal_reason(403, None, "", false))).as_deref(), Some("HTTP 403"));
		assert_eq!(public_reason("no such member"), None);
	}
}
