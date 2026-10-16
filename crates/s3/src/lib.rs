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
	// The credential scope — `<date>/<region>/s3/aws4_request` — exactly as
	// the Authorization header names it. (Until the IDrive e2 live run,
	// 2026-10-15, this line left the region out: every real S3 server
	// answered SignatureDoesNotMatch, and the golden vectors below, computed
	// with the same omission, agreed with the code. Only the S3 stub, which
	// checks no signature, and the R2 binding, which needs none, worked.)
	let string_to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}", amz_date, date_stamp, cfg.region, sha256_hex(canonical.as_bytes()));
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

// ── Object Lock (commit 29c, docs/CUSTODY.md › Stage 3) ─────────────

/// The body of `PUT <key>?retention`: a COMPLIANCE retention until `until`
/// (RFC 3339, UTC). COMPLIANCE: nobody — no credential, no root — shortens
/// or removes it before it ends.
pub fn retention_xml(until: &str) -> Vec<u8> {
	format!("<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>COMPLIANCE</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>").into_bytes()
}

/// MD5 (RFC 1321), for the `Content-MD5` header S3 and MinIO demand on a
/// retention write — an integrity check of the request body that the API
/// requires, NOT a security primitive (MD5 is broken for those). Written
/// here, small and tested against the RFC's own vectors, rather than
/// pulling a crate for one header.
pub fn md5(data: &[u8]) -> [u8; 16] {
	const S: [u32; 64] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
	// K[i] = floor(|sin(i + 1)| · 2^32) — written out, not computed: `sin`
	// may round differently on another platform's libm (wasm32 vs. the host).
	const K: [u32; 64] = [
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	];
	let (mut a0, mut b0, mut c0, mut d0) = (0x6745_2301u32, 0xefcd_ab89u32, 0x98ba_dcfeu32, 0x1032_5476u32);
	let mut msg = data.to_vec();
	let bit_len = (data.len() as u64).wrapping_mul(8);
	msg.push(0x80);
	while msg.len() % 64 != 56 {
		msg.push(0);
	}
	msg.extend_from_slice(&bit_len.to_le_bytes());
	for chunk in msg.chunks(64) {
		let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
		let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
		for i in 0..64 {
			let (f, g) = match i / 16 {
				0 => ((b & c) | (!b & d), i),
				1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
				2 => (b ^ c ^ d, (3 * i + 5) % 16),
				_ => (c ^ (b | !d), (7 * i) % 16),
			};
			let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
			a = d;
			d = c;
			c = b;
			b = b.wrapping_add(f.rotate_left(S[i]));
		}
		a0 = a0.wrapping_add(a);
		b0 = b0.wrapping_add(b);
		c0 = c0.wrapping_add(c);
		d0 = d0.wrapping_add(d);
	}
	let mut out = [0u8; 16];
	for (i, w) in [a0, b0, c0, d0].iter().enumerate() {
		out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
	}
	out
}

// ── Why a storage server said no (commit 39s) ───────────────────────

/// A storage refusal in words an operator can act on: the status, S3's own
/// error code when the answer carried one, and what usually causes it.
///
/// Until 39s the Worker said only "S3 put <key>: HTTP 403" — and a 403
/// has five common causes with five different fixes (a wrong secret, a
/// wrong region, an unknown key, a key without write rights, something in
/// front of the endpoint that is not S3 at all). S3 names its reason in
/// the error body's `<Code>`; this reads it. The `Server` header tells the
/// last case apart: an answer with no code from `cloudflare` was refused
/// by Cloudflare in front of the endpoint (Access, WAF, bot rules), never
/// by the storage server behind it.
///
/// Nothing here repeats the error body's `<Message>` or other elements:
/// a SignatureDoesNotMatch body carries the string-to-sign and the access
/// key id, and none of that belongs in a log line or a browser.
///
/// `bodied`: whether the answer could carry a reason at all — a HEAD
/// answer never has a body, so a missing code there says nothing about
/// who answered.
pub fn refusal_reason(status: u16, code: Option<&str>, server: &str, bodied: bool) -> String {
	let hint = match code {
		Some("SignatureDoesNotMatch") => "the endpoint rejects the signature: S3_SECRET_KEY is not this key's secret, or S3_REGION is not the region S3_ENDPOINT's host names",
		Some("AuthorizationHeaderMalformed") => "S3_REGION is not the region this endpoint expects",
		Some("InvalidAccessKeyId") => "the endpoint does not know S3_ACCESS_KEY_ID: a deleted or mistyped key, or one made for another provider or region",
		Some("AccessDenied") => "the key is valid but not allowed to do this: give it object read, write and delete (and multipart and list) on S3_BUCKET",
		Some("AllAccessDisabled") | Some("AccountProblem") => "the provider has disabled this account or bucket (billing, or a hold on the account)",
		Some("NoSuchBucket") => "S3_BUCKET does not exist at S3_ENDPOINT (a bucket in another region needs that region's host)",
		Some("PermanentRedirect") | Some("TemporaryRedirect") => "the bucket lives at another endpoint: use the host of the region it was created in",
		Some("RequestTimeTooSkewed") => "the request's clock and the server's disagree by more than 15 minutes",
		Some("InvalidRequest") => "the server refused the request's form (on an Object Lock bucket: is a default retention set? gorani needs none)",
		Some(other) => return format!("HTTP {status} {other}"),
		None if !bodied && !server.to_ascii_lowercase().contains("cloudflare") => return format!("HTTP {status} (a HEAD answer carries no reason — Team › Status › Test connection shows the write's)"),
		None if server.to_ascii_lowercase().contains("cloudflare") => "not an S3 answer: Cloudflare in front of S3_ENDPOINT refused the request (Access, WAF or bot rules on that host) — let the Worker's requests through, or use the storage's own host",
		None if (300..400).contains(&status) => "not an S3 answer: a redirect — S3_ENDPOINT is not the storage's S3 API host (some providers answer unknown requests with a redirect to their homepage)",
		None => "not an S3 answer (no error code): something in front of S3_ENDPOINT refused it — a reverse proxy, a login page, or the provider's web console instead of its S3 API host",
	};
	match code {
		Some(code) => format!("HTTP {status} {code} — {hint}"),
		None => format!("HTTP {status} — {hint}"),
	}
}

#[cfg(test)]
mod tests {

	/// 39s: each refusal says what S3 said and what to change; an answer
	/// that is not S3's is named as such, and Cloudflare's apart.
	#[test]
	fn refusals_are_explained() {
		let r = super::refusal_reason(403, Some("SignatureDoesNotMatch"), "", true);
		assert!(r.starts_with("HTTP 403 SignatureDoesNotMatch — ") && r.contains("S3_SECRET_KEY") && r.contains("S3_REGION"), "{r}");
		assert!(super::refusal_reason(403, Some("AccessDenied"), "MinIO", true).contains("write"));
		assert!(super::refusal_reason(403, Some("InvalidAccessKeyId"), "", true).contains("S3_ACCESS_KEY_ID"));
		assert_eq!(super::refusal_reason(409, Some("OperationAborted"), "", true), "HTTP 409 OperationAborted");
		let cf = super::refusal_reason(403, None, "cloudflare", true);
		assert!(cf.contains("not an S3 answer") && cf.contains("Cloudflare"), "{cf}");
		assert!(super::refusal_reason(302, None, "nginx", true).contains("redirect"));
		assert!(super::refusal_reason(403, None, "nginx", true).contains("not an S3 answer"));
		// A HEAD answer has no body: no code is not evidence of a proxy.
		let head = super::refusal_reason(403, None, "MinIO", false);
		assert!(head.starts_with("HTTP 403 (") && !head.contains("not an S3 answer"), "{head}");
		assert!(super::refusal_reason(403, None, "cloudflare", false).contains("Cloudflare"), "Cloudflare's own refusal is named on a HEAD too");
	}

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

	/// Golden vectors from an independent implementation — tests/lib/sigv4.mjs
	/// (Node's crypto), which a real S3 server (IDrive e2, 2026-10-15) accepts.
	/// The first vectors here were "independent" too, but were computed with
	/// the same missing region in the credential scope, and so agreed with
	/// the bug: a vector is only as independent as the formula it was
	/// computed from. A real server is the check that cannot share a mistake
	/// (tests/api/s3-live.test.mjs).
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
		assert!(auth.ends_with("Signature=90f30a47480a717f49877d2cfb44df75e2408e13cd782e38265b13d43d227b71"), "{auth}");
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
		assert!(auth.ends_with("Signature=a708a9aff73e1a6a8ac2a5a742f365195e3e12e0471cc325578f24f43f86b8fa"), "{auth}");
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
	fn md5_matches_rfc_1321() {
		// RFC 1321 › A.5, the test suite.
		for (input, hex_digest) in [
			("", "d41d8cd98f00b204e9800998ecf8427e"),
			("a", "0cc175b9c0f1b6a831c399e269772661"),
			("abc", "900150983cd24fb0d6963f7d28e17f72"),
			("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
			("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
			("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
			("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"),
		] {
			assert_eq!(hex::encode(md5(input.as_bytes())), hex_digest, "md5({input:?})");
		}
	}

	#[test]
	fn retention_body() {
		let b = String::from_utf8(retention_xml("2033-10-14T00:00:00Z")).unwrap();
		assert!(b.contains("<Mode>COMPLIANCE</Mode><RetainUntilDate>2033-10-14T00:00:00Z</RetainUntilDate>"));
	}

	#[test]
	fn unused_const_builds() {
		// (keeps the const CFG meaningful: it documents that S3Config is a
		// plain value type; the real configs come from env.)
		let _ = CFG;
	}
}