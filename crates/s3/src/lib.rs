// Copyright 2026- Seongwoo Hong. All rights reserved.
// The signing rules follow the S3 adapter written for the stream-worker
// project; see NOTICE.

//! AWS Signature Version 4 for S3 — the pure, host-testable half.
//!
//! Gorani's object storage is *any* S3-compatible bucket (MinIO over public
//! HTTPS, B2, Wasabi, R2's own S3 API), reached from the Worker with path-style
//! addressing (`https://endpoint/bucket/key`). SigV4 is deliberately
//! hand-rolled here (~100 lines on top of `hmac`/`sha2`) instead of pulling
//! an SDK: gorani needs a dozen operations, an SDK brings megabytes of
//! codegen, and the signing math must be inspectable in a security review.
//!
//! ```text
//! canonical = METHOD \n /bucket/encoded-key \n canonical-query \n
//!             host:… \n x-amz-content-sha256:UNSIGNED-PAYLOAD \n x-amz-date:… \n \n
//!             host;x-amz-content-sha256;x-amz-date \n UNSIGNED-PAYLOAD
//! to_sign   = AWS4-HMAC-SHA256 \n <amzdate> \n <date>/<region>/s3/aws4_request \n hexsha(canonical)
//! key       = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), "s3"), "aws4_request")
//! signature = hexhmac(key, to_sign)
//! ```
//!
//! `UNSIGNED-PAYLOAD` is valid for every operation here because everything
//! moves over TLS (the transport layer's job); it spares us hashing 8 MiB
//! bodies. The `Range` header is *not* in the signed header set — like every
//! SigV4 S3 client that uses UNSIGNED-PAYLOAD, it need not be, and not
//! signing it lets the same signature serve any range of one object.
//!
//! Everything that touches time takes `now_secs` as a parameter: the
//! transport injects the wall clock, tests inject fixed values, and the
//! golden vectors in tests were computed independently (Python's
//! hashlib/hmac) so a signing bug cannot pass by agreeing with itself.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Active S3 endpoint configuration (env-side: vars + secrets).
///
/// `Debug` is written by hand (commit 25, docs/SECURITY-REVIEW.md › O16):
/// the derived one printed `secret_key` in full for any `{:?}` — a panic
/// message, a log line, a test failure. The keys show as `[redacted]`.
#[derive(Clone)]
pub struct S3Config {
	/// `https://minio.example.com` (no trailing slash).
	pub endpoint: String,
	pub region: String,
	pub bucket: String,
	pub access_key: String,
	pub secret_key: String,
}

impl std::fmt::Debug for S3Config {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("S3Config")
			.field("endpoint", &self.endpoint)
			.field("region", &self.region)
			.field("bucket", &self.bucket)
			.field("access_key", &"[redacted]")
			.field("secret_key", &"[redacted]")
			.finish()
	}
}

/// A signed request, ready for any transport: URL plus the headers to set.
#[derive(Debug, Clone)]
pub struct SignedRequest {
	pub method: String,
	pub url: String,
	/// Exactly the headers the signature covers — set these, and no others,
	/// or the server's recomputation will not match.
	pub headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum S3Error {
	BadEndpoint,
	BadKey,
}

impl std::fmt::Display for S3Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			S3Error::BadEndpoint => write!(f, "bad S3 endpoint"),
			S3Error::BadKey => write!(f, "bad object key"),
		}
	}
}

impl std::error::Error for S3Error {}

// ── primitives ──────────────────────────────────────────────────────

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
	let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
	mac.update(data);
	mac.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
	hex::encode(Sha256::digest(data))
}

/// RFC 3986 component encoding (space → %20, unreserved kept, `/` kept only
/// in object keys). SigV4 requires this exact form for canonical URIs and
/// query values.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
	let mut out = String::with_capacity(s.len() * 2);
	for b in s.as_bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*b as char),
			b'/' if keep_slash => out.push('/'),
			_ => out.push_str(&format!("%{b:02X}")),
		}
	}
	out
}

/// Canonical query string from pairs (sorted by encoded key then value).
pub fn canonical_query(pairs: &[(String, String)]) -> String {
	let mut enc: Vec<(String, String)> = pairs.iter().map(|(k, v)| (uri_encode(k, false), uri_encode(v, false))).collect();
	enc.sort();
	enc.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// Civil date from days-since-epoch (Howard Hinnant's algorithm) — the whole
/// reason no chrono dependency is needed for two formatted timestamps.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
	let z = z + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = (z - era * 146_097) as u64;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe as i64 + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
	(if m <= 2 { y + 1 } else { y }, m, d)
}

/// `(amzdate YYYYMMDDTHHMMSSZ, datestamp YYYYMMDD)` for epoch seconds.
pub fn stamps_from_epoch(secs: i64) -> (String, String) {
	let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
	let sod = secs.rem_euclid(86_400);
	let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
	(format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"), format!("{y:04}{mo:02}{d:02}"))
}

// ── the signer ──────────────────────────────────────────────────────

/// Sign one request. `object_key` is the raw S3 key (no bucket), `query_pairs`
/// is canonicalised inside, `now_secs` is the wall clock (injected).
pub fn sign_request(cfg: &S3Config, method: &str, object_key: &str, query_pairs: &[(String, String)], now_secs: i64) -> Result<SignedRequest, S3Error> {
	let host = cfg.endpoint.split("//").nth(1).ok_or(S3Error::BadEndpoint)?;
	if object_key.contains("//") || object_key.starts_with('/') {
		return Err(S3Error::BadKey);
	}
	let (amz_date, date_stamp) = stamps_from_epoch(now_secs);
	let path = format!("/{}/{}", uri_encode(&cfg.bucket, false), uri_encode(object_key, true));
	let cq = canonical_query(query_pairs);

	let canonical = format!(
		"{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:{}\n\nhost;x-amz-content-sha256;x-amz-date\nUNSIGNED-PAYLOAD",
		method, path, cq, host, amz_date
	);
	let string_to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}/s3/aws4_request\n{}", amz_date, date_stamp, sha256_hex(canonical.as_bytes()));
	let k_date = hmac_sha256(format!("AWS4{}", cfg.secret_key).as_bytes(), date_stamp.as_bytes());
	let k_region = hmac_sha256(&k_date, cfg.region.as_bytes());
	let k_service = hmac_sha256(&k_region, b"s3");
	let k_signing = hmac_sha256(&k_service, b"aws4_request");
	let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

	let mut url = format!("{}{}?{}", cfg.endpoint, path, cq);
	if url.ends_with('?') {
		url.pop();
	}
	Ok(SignedRequest {
		method: method.to_string(),
		url,
		headers: vec![
			(
				"Authorization".into(),
				format!(
					"AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={}",
					cfg.access_key, date_stamp, cfg.region, signature
				),
			),
			("x-amz-date".into(), amz_date),
			("x-amz-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
		],
	})
}

// ── S3 response parsing (pure; the transport calls these) ───────────

/// First `<tag>…</tag>` content. S3 responses are small and regular; a real
/// XML parser would outweigh what it parses here.
pub fn xml_val(xml: &str, tag: &str) -> Option<String> {
	let open = format!("<{tag}>");
	let close = format!("</{tag}>");
	let start = xml.find(&open)? + open.len();
	let end = xml[start..].find(&close)? + start;
	Some(xml[start..end].to_string())
}

/// Every `<tag>…</tag>` content, in order (ListObjectsV2 keys).
pub fn xml_vals(xml: &str, tag: &str) -> Vec<String> {
	let open = format!("<{tag}>");
	let close = format!("</{tag}>");
	let mut out = Vec::new();
	let mut rest = xml;
	while let Some(i) = rest.find(&open) {
		let after = &rest[i + open.len()..];
		match after.find(&close) {
			Some(j) => {
				out.push(after[..j].to_string());
				rest = &after[j + close.len()..];
			}
			None => break,
		}
	}
	out
}

/// Minimal XML text unescape for keys in ListObjects output.
pub fn xml_unescape(s: &str) -> String {
	s.replace("&lt;", "<")
		.replace("&gt;", ">")
		.replace("&quot;", "\"")
		.replace("&apos;", "'")
		.replace("&#39;", "'")
		.replace("&amp;", "&")
}

/// The XML body of a CompleteMultipartUpload request.
pub fn complete_multipart_body(parts: &[(u32, String)]) -> Vec<u8> {
	let mut body = String::from("<CompleteMultipartUpload>");
	for (n, etag) in parts {
		body.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"));
	}
	body.push_str("</CompleteMultipartUpload>");
	body.into_bytes()
}

#[cfg(test)]
mod tests {

	/// O16: a `{:?}` of the config never prints a key.
	#[test]
	fn debug_redacts_the_keys() {
		let cfg = super::S3Config { endpoint: "https://minio.example.com".into(), region: "us-east-1".into(), bucket: "gorani".into(), access_key: "AKIA-VISIBLE?".into(), secret_key: "very-secret-value".into() };
		let shown = format!("{cfg:?}");
		assert!(shown.contains("minio.example.com") && shown.contains("[redacted]"));
		assert!(!shown.contains("very-secret-value") && !shown.contains("AKIA-VISIBLE?"), "{shown}");
	}
	use super::*;

	const CFG: S3Config = S3Config {
		endpoint: String::new(), // const-able? no — build in the tests
		region: String::new(),
		bucket: String::new(),
		access_key: String::new(),
		secret_key: String::new(),
	};

	fn cfg() -> S3Config {
		S3Config {
			endpoint: "https://minio.example.com".into(),
			region: "us-east-1".into(),
			bucket: "gorani".into(),
			access_key: "AKIDEXAMPLE".into(),
			secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
		}
	}

	/// Golden vectors computed independently (Python hashlib/hmac, the same
	/// canonicalisation) so a self-consistent signing bug cannot pass.
	const NOW: i64 = 1_791_849_600; // 2026-10-13T00:00:00Z

	#[test]
	fn stamps() {
		assert_eq!(stamps_from_epoch(NOW), ("20261013T000000Z".into(), "20261013".into()));
		assert_eq!(stamps_from_epoch(NOW - 1), ("20261012T235959Z".into(), "20261012".into()));
		assert_eq!(stamps_from_epoch(0), ("19700101T000000Z".into(), "19700101".into()));
	}

	#[test]
	fn get_with_a_space_in_the_key() {
		let r = sign_request(&cfg(), "GET", "files/a/b c.txt", &[], NOW).unwrap();
		assert_eq!(r.url, "https://minio.example.com/gorani/files/a/b%20c.txt");
		let auth = &r.headers.iter().find(|(h, _)| h == "Authorization").unwrap().1;
		assert!(auth.ends_with("Signature=2dab9218f53afc3e75c83524523fe414b3c5e5850229c92fb797491497f48ab2"), "{auth}");
		assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261013/us-east-1/s3/aws4_request, "), "{auth}");
	}

	#[test]
	fn multipart_part_query_is_canonicalised_and_sorted() {
		let r = sign_request(
			&cfg(),
			"PUT",
			"files/x/y",
			&[("uploadId".into(), "abc123".into()), ("partNumber".into(), "1".into())],
			NOW,
		)
		.unwrap();
		assert!(r.url.ends_with("?partNumber=1&uploadId=abc123"), "{}", r.url);
		let auth = &r.headers.iter().find(|(h, _)| h == "Authorization").unwrap().1;
		assert!(auth.ends_with("Signature=5517186698dd98dc2b1220a44aa693d5f9cfd6aa475d5b447532e2e367c90767"), "{auth}");
	}

	#[test]
	fn the_range_header_is_not_signed_but_added_by_the_transport() {
		// The signature covers only host;x-amz-content-sha256;x-amz-date — a
		// Range header added later cannot break the server's recomputation.
		let r = sign_request(&cfg(), "GET", "files/x/y", &[], NOW).unwrap();
		assert_eq!(r.headers.len(), 3);
		assert!(!r.headers.iter().any(|(h, _)| h == "Range"));
	}

	#[test]
	fn keys_are_checked_and_slashes_kept() {
		assert!(matches!(sign_request(&cfg(), "GET", "/absolute", &[], NOW), Err(S3Error::BadKey)));
		assert!(matches!(sign_request(&cfg(), "GET", "a//b", &[], NOW), Err(S3Error::BadKey)));
		let r = sign_request(&cfg(), "GET", "files/가족/사진.png", &[], NOW).unwrap();
		assert!(r.url.contains("%EA%B0%80%EC%A1%B1"), "{}", r.url);
	}

	#[test]
	fn complete_body_shape() {
		let b = String::from_utf8(complete_multipart_body(&[(1, "\"a\"".into()), (2, "\"b\"".into())])).unwrap();
		assert!(b.starts_with("<CompleteMultipartUpload>") && b.ends_with("</CompleteMultipartUpload>"));
		assert!(b.contains("<PartNumber>2</PartNumber><ETag>\"b\"</ETag>"));
	}

	#[test]
	fn xml_helpers() {
		assert_eq!(xml_val("<R><UploadId>abc</UploadId></R>", "UploadId").as_deref(), Some("abc"));
		assert_eq!(xml_vals("<R><K>a</K><K>b</K></R>", "K"), vec!["a".to_string(), "b".to_string()]);
		assert_eq!(xml_unescape("a&amp;b&lt;c&gt;"), "a&b<c>");
	}

	#[test]
	fn unused_const_builds() {
		// (keeps the const CFG meaningful: it documents that S3Config is a
		// plain value type; the real configs come from env.)
		let _ = CFG;
	}
}