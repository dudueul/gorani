// Copyright 2026- Seongwoo Hong. All rights reserved.
// The transport follows the S3 adapter written for the stream-worker
// project; see NOTICE.

//! The S3 transport: gorani-s3's signatures (pure, tested) driven through
//! the Workers runtime's fetch. Six object operations and multipart — the
//! entire surface the file store needs; anything fancier belongs in an SDK,
//! not in a security-sensitive worker.
//!
//! ```text
//! caller ──▶ ops (this file) ──▶ sign_request (gorani-s3) ──▶ Fetch ──▶ MinIO/S3
//! ```
//!
//! Every byte crossing this module is ciphertext (GV02/GC01 frames, sealed
//! sidecars, backup segments); the bucket is private and its keys are
//! Worker secrets. Nothing here inspects content beyond sizes and statuses.

use gorani_s3::{complete_multipart_body, sign_request, xml_unescape, xml_val, S3Config, SignedRequest};
use worker::*;

/// A HEAD result: size and etag (the store keeps etags for upload parts).
#[derive(Debug, Clone)]
pub struct HeadInfo {
	pub size: u64,
	pub etag: String,
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
	Ok(S3Config {
		endpoint: var("S3_ENDPOINT")?.trim_end_matches('/').to_string(),
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

/// Full GET; None on 404.
pub async fn get(env: &Env, key: &str) -> Result<Option<Vec<u8>>> {
	let cfg = config(env)?;
	let mut resp = fetch_signed(&cfg, "GET", key, &[], None, None, None).await?;
	match resp.status_code() {
		200 => Ok(Some(resp.bytes().await?)),
		404 => Ok(None),
		s => Err(Error::RustError(format!("S3 get {key}: HTTP {s}"))),
	}
}

/// Ranged read — S3 answers 206; a server may answer 200 when the range
/// covers the whole object, which is equally fine for a full read.
pub async fn read_range(env: &Env, key: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
	let cfg = config(env)?;
	let mut resp = fetch_signed(&cfg, "GET", key, &[], Some((offset, length)), None, None).await?;
	let status = resp.status_code();
	if status != 206 && status != 200 {
		return Err(Error::RustError(format!("S3 range read {key}: HTTP {status}")));
	}
	resp.bytes().await
}

/// Size + etag via HEAD. None on 404.
pub async fn head(env: &Env, key: &str) -> Result<Option<HeadInfo>> {
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "HEAD", key, &[], None, None, None).await?;
	match resp.status_code() {
		200 => Ok(Some(HeadInfo {
			size: resp.headers().get("Content-Length")?.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0),
			etag: resp.headers().get("ETag")?.unwrap_or_default(),
		})),
		404 => Ok(None),
		s => Err(Error::RustError(format!("S3 head {key}: HTTP {s}"))),
	}
}

/// Simple PUT (small objects; big ones go through multipart).
pub async fn put(env: &Env, key: &str, bytes: Vec<u8>) -> Result<()> {
	let cfg = config(env)?;
	let resp = fetch_signed(&cfg, "PUT", key, &[], None, Some(bytes), Some("application/octet-stream")).await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("S3 put {key}: HTTP {}", resp.status_code())));
	}
	Ok(())
}

/// DELETE; a missing object counts as deleted.
pub async fn delete(env: &Env, key: &str) -> Result<()> {
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
	let cfg = config(env)?;
	let q = [("uploadId".to_string(), upload_id.to_string())];
	let mut resp = fetch_signed(&cfg, "POST", key, &q, None, Some(complete_multipart_body(parts)), Some("application/xml")).await?;
	let status = resp.status_code();
	let text = resp.text().await?;
	if status != 200 {
		return Err(Error::RustError(format!("S3 multipart complete: HTTP {status} {text}")));
	}
	Ok(())
}

/// Abort (frees the stored parts; the daily housekeeping also calls this on
/// uploads that never finished).
pub async fn multipart_abort(env: &Env, key: &str, upload_id: &str) -> Result<()> {
	let cfg = config(env)?;
	let q = [("uploadId".to_string(), upload_id.to_string())];
	let resp = fetch_signed(&cfg, "DELETE", key, &q, None, None, None).await?;
	match resp.status_code() {
		204 | 404 => Ok(()),
		s => Err(Error::RustError(format!("S3 multipart abort: HTTP {s}"))),
	}
}

// ── Listing (the daily housekeeping: expired shares, stale uploads) ──

/// One listed object: key and size.
#[derive(Debug, Clone)]
pub struct Listed {
	pub key: String,
	pub size: u64,
}

/// ListObjectsV2 under a prefix, one page (up to `max_keys`, ≤ 1000).
/// Returns the objects and the continuation token, if any. Keys come back
/// XML-escaped and percent-relevant; they are unescaped here and the caller
/// treats them as the exact stored keys.
pub async fn list_page(env: &Env, prefix: &str, continuation: Option<&str>, max_keys: u32) -> Result<(Vec<Listed>, Option<String>)> {
	let cfg = config(env)?;
	let mut q = vec![
		("list-type".to_string(), "2".to_string()),
		("max-keys".to_string(), max_keys.to_string()),
		("prefix".to_string(), prefix.to_string()),
	];
	if let Some(c) = continuation {
		q.push(("continuation-token".to_string(), c.to_string()));
	}
	let mut resp = fetch_signed(&cfg, "GET", "", &q, None, None, None).await?;
	let status = resp.status_code();
	let body = resp.text().await?;
	if status != 200 {
		return Err(Error::RustError(format!("S3 list: HTTP {status} {body}")));
	}
	let keys: Vec<String> = gorani_s3::xml_vals(&body, "Key").into_iter().map(|k| xml_unescape(&k)).collect();
	let sizes: Vec<String> = gorani_s3::xml_vals(&body, "Size");
	let objects = keys
		.into_iter()
		.enumerate()
		.map(|(i, key)| Listed { key, size: sizes.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) })
		.collect();
	let truncated = xml_val(&body, "IsTruncated").as_deref() == Some("true");
	let next = if truncated { xml_val(&body, "NextContinuationToken") } else { None };
	Ok((objects, next))
}