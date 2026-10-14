// Copyright 2026- Seongwoo Hong. All rights reserved.

//! RFC 3161 trusted timestamps (commit 29j, docs/CUSTODY.md › Stage 7, D5.5).
//!
//! The audit trail says WHEN a version was recorded — but the trail is the
//! deployment's own word. A timestamp authority (TSA) is a third party that
//! signs "I saw this hash at this time"; with its token beside a record,
//! "this existed by then" no longer rests on gorani's clock or honesty.
//!
//! ```text
//! request  TimeStampReq { v1, messageImprint { sha256, imprint }, nonce, certReq: TRUE }
//! reply    TimeStampResp { status, timeStampToken: ContentInfo(SignedData(TSTInfo)) }
//! TSTInfo  { v1, policy, messageImprint, serialNumber, genTime, … nonce … }
//! ```
//!
//! What the Worker does with a reply is deliberately little: it checks the
//! status, that the token is over the imprint it asked about, and that the
//! nonce is its own (so a reply cannot be replayed from another request),
//! then stores the token's bytes. It does NOT verify the TSA's signature:
//! a server's "I checked" is exactly the word this whole design avoids.
//! Clients do (web/src/vault/timestamp.ts), and so does the export's
//! verifier (tools/verify-export.mjs), each against a TSA certificate a
//! LEAD certified — not against one the server names.
//!
//! What is stamped never identifies content: for an evidence version, the
//! SHA-256 of its uploader's signature (a random-looking 64 bytes, which a
//! TSA cannot invert or guess); for an audit checkpoint, the SHA-256 of
//! the checkpoint's bytes. The TSA learns that gorani stamped something.

use worker::*;

/// The deployment's TSA, when it has one (`TSA_URL`; `TSA_AUTHORIZATION`, a
/// secret, is sent verbatim as the Authorization header — "Basic …" for
/// the commercial TSAs that want an account).
pub(crate) fn configured(env: &Env) -> Option<String> {
	env.var("TSA_URL").ok().map(|v| v.to_string()).filter(|v| !v.is_empty())
}

/// A token, as the TSA returned it, and the time it states (ISO 8601, UTC).
#[derive(Debug)]
pub(crate) struct Stamp {
	pub token: Vec<u8>,
	pub at: String,
}

/// Ask the TSA about a 32-byte imprint. `Ok(None)` when no TSA is set.
pub(crate) async fn stamp(env: &Env, imprint: &[u8; 32]) -> Result<Option<Stamp>> {
	let Some(url) = configured(env) else { return Ok(None) };
	let mut nonce = [0u8; 8];
	getrandom::getrandom(&mut nonce).map_err(|e| Error::RustError(format!("no randomness for the nonce: {e}")))?;
	let headers = Headers::new();
	headers.set("Content-Type", "application/timestamp-query")?;
	headers.set("Accept", "application/timestamp-reply")?;
	if let Some(auth) = env.secret("TSA_AUTHORIZATION").ok().map(|v| v.to_string()).filter(|v| !v.is_empty()) {
		headers.set("Authorization", &auth)?;
	}
	let body = request(imprint, &mut nonce);
	let req = Request::new_with_init(&url, &RequestInit { method: Method::Post, headers, body: Some(js_sys::Uint8Array::from(body.as_slice()).into()), ..Default::default() })?;
	let mut resp = Fetch::Request(req).send().await?;
	if resp.status_code() != 200 {
		return Err(Error::RustError(format!("the TSA answered HTTP {}", resp.status_code())));
	}
	let reply = resp.bytes().await?;
	token_of(&reply, imprint, &nonce).map(Some).map_err(|e| Error::RustError(format!("the TSA's reply: {e}")))
}

// ── DER, the small part of it RFC 3161 needs ─────────────────────────────

/// One TLV: its tag, its contents, and the whole encoding (tag ‖ length ‖ contents).
struct Tlv<'a> {
	tag: u8,
	body: &'a [u8],
	raw: &'a [u8],
}

/// Read the TLV at the front of `buf`; the rest follows it. Single-byte
/// tags only and definite lengths only — DER has nothing else here.
fn tlv(buf: &[u8]) -> std::result::Result<(Tlv<'_>, &[u8]), String> {
	let short = || "truncated DER".to_string();
	let tag = *buf.first().ok_or_else(short)?;
	if tag & 0x1f == 0x1f {
		return Err("a multi-byte DER tag".into());
	}
	let first = *buf.get(1).ok_or_else(short)?;
	let (len, head) = if first < 0x80 {
		(first as usize, 2)
	} else {
		let n = (first & 0x7f) as usize;
		if n == 0 || n > 4 {
			return Err("an indefinite or oversized DER length".into());
		}
		let mut len = 0usize;
		for i in 0..n {
			len = (len << 8) | *buf.get(2 + i).ok_or_else(short)? as usize;
		}
		(len, 2 + n)
	};
	let end = head.checked_add(len).filter(|&e| e <= buf.len()).ok_or_else(short)?;
	Ok((Tlv { tag, body: &buf[head..end], raw: &buf[..end] }, &buf[end..]))
}

/// Read a TLV that must carry `tag`.
fn expect<'a>(buf: &'a [u8], tag: u8, what: &str) -> std::result::Result<(Tlv<'a>, &'a [u8]), String> {
	let (t, rest) = tlv(buf)?;
	if t.tag != tag {
		return Err(format!("{what}: expected tag {tag:#04x}, found {:#04x}", t.tag));
	}
	Ok((t, rest))
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
	let mut out = vec![tag];
	match body.len() {
		n if n < 0x80 => out.push(n as u8),
		n if n < 0x100 => out.extend([0x81, n as u8]),
		n => out.extend([0x82, (n >> 8) as u8, n as u8]),
	}
	out.extend_from_slice(body);
	out
}

/// id-sha256, 2.16.840.1.101.3.4.2.1
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-signedData, 1.2.840.113549.1.7.2
const SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// id-ct-TSTInfo, 1.2.840.113549.1.9.16.1.4
const TST_INFO_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04];

/// The TimeStampReq for `imprint`. The nonce is made a positive INTEGER
/// with no leading zero (DER's minimal form: 0x40–0x7f in its first byte),
/// so the TSA's echo of it compares byte for byte.
fn request(imprint: &[u8; 32], nonce: &mut [u8; 8]) -> Vec<u8> {
	nonce[0] = (nonce[0] & 0x3f) | 0x40;
	let alg = der(0x30, &[der(0x06, SHA256_OID), vec![0x05, 0x00]].concat());
	let message_imprint = der(0x30, &[alg, der(0x04, imprint)].concat());
	der(0x30, &[vec![0x02, 0x01, 0x01], message_imprint, der(0x02, nonce), vec![0x01, 0x01, 0xff]].concat())
}

/// The token in a TimeStampResp, checked for what the Worker can check.
fn token_of(reply: &[u8], imprint: &[u8; 32], nonce: &[u8; 8]) -> std::result::Result<Stamp, String> {
	let (resp, _) = expect(reply, 0x30, "TimeStampResp")?;
	let (status_info, rest) = expect(resp.body, 0x30, "PKIStatusInfo")?;
	let (status, _) = expect(status_info.body, 0x02, "PKIStatus")?;
	// granted (0) or grantedWithMods (1); anything else is a refusal.
	if !matches!(status.body, [0] | [1]) {
		return Err(format!("the TSA refused (PKIStatus {:?})", status.body));
	}
	let (token, _) = expect(rest, 0x30, "TimeStampToken")?;
	let (oid, rest) = expect(token.body, 0x06, "contentType")?;
	if oid.body != SIGNED_DATA_OID {
		return Err("the token is not CMS SignedData".into());
	}
	let (explicit, _) = expect(rest, 0xa0, "content")?;
	let (signed, _) = expect(explicit.body, 0x30, "SignedData")?;
	let (_version, rest) = expect(signed.body, 0x02, "version")?;
	let (_digests, rest) = expect(rest, 0x31, "digestAlgorithms")?;
	let (encap, _) = expect(rest, 0x30, "encapContentInfo")?;
	let (ctype, rest) = expect(encap.body, 0x06, "eContentType")?;
	if ctype.body != TST_INFO_OID {
		return Err("the signed content is not a TSTInfo".into());
	}
	let (econtent, _) = expect(rest, 0xa0, "eContent")?;
	let (octets, _) = expect(econtent.body, 0x04, "eContent")?;
	let (tst, _) = expect(octets.body, 0x30, "TSTInfo")?;
	let (_v, rest) = expect(tst.body, 0x02, "TSTInfo version")?;
	let (_policy, rest) = expect(rest, 0x06, "policy")?;
	let (mi, rest) = expect(rest, 0x30, "messageImprint")?;
	let (alg, hashed) = expect(mi.body, 0x30, "hashAlgorithm")?;
	let (alg_oid, _) = expect(alg.body, 0x06, "hashAlgorithm")?;
	let (hashed, _) = expect(hashed, 0x04, "hashedMessage")?;
	if alg_oid.body != SHA256_OID || hashed.body != imprint {
		return Err("the token is over something other than what was asked".into());
	}
	let (_serial, rest) = expect(rest, 0x02, "serialNumber")?;
	let (gen_time, mut rest) = expect(rest, 0x18, "genTime")?;
	// The optional fields: accuracy (SEQUENCE), ordering (BOOLEAN), nonce (INTEGER).
	let mut echoed = None;
	while !rest.is_empty() {
		let (t, next) = tlv(rest)?;
		if t.tag == 0x02 {
			echoed = Some(t.body);
		}
		rest = next;
	}
	if echoed != Some(&nonce[..]) {
		return Err("the token does not carry this request's nonce — a replayed or crossed reply".into());
	}
	Ok(Stamp { token: token.raw.to_vec(), at: iso_time(gen_time.body)? })
}

/// GeneralizedTime `YYYYMMDDhhmmss[.f…]Z` → `YYYY-MM-DDThh:mm:ss[.f…]Z`.
fn iso_time(t: &[u8]) -> std::result::Result<String, String> {
	let s = std::str::from_utf8(t).map_err(|_| "genTime is not text".to_string())?;
	let ok = s.len() >= 15 && s.ends_with('Z') && s[..14].bytes().all(|b| b.is_ascii_digit());
	if !ok {
		return Err(format!("genTime {s:?} is not UTC GeneralizedTime"));
	}
	Ok(format!("{}-{}-{}T{}:{}:{}{}", &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14], &s[14..]))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_request_is_the_der_openssl_writes() {
		let mut nonce = [0xff, 1, 2, 3, 4, 5, 6, 7];
		let req = request(&[0xab; 32], &mut nonce);
		assert_eq!(nonce[0], 0x7f, "a positive, minimal INTEGER");
		let hex = hex::encode(&req);
		// SEQUENCE { 1, { {sha256, NULL}, OCTET STRING[32] }, nonce, TRUE }
		assert!(hex.starts_with("3043020101303130 0d0609608648016503040201050004 20".replace(' ', "").as_str()), "{hex}");
		assert!(hex.ends_with("02087f010203040506070101ff"), "{hex}");
		assert_eq!(req.len(), 0x45);
	}

	#[test]
	fn a_long_length_reads_back() {
		let body = vec![7u8; 300];
		let enc = der(0x04, &body);
		assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
		let (t, rest) = tlv(&enc).unwrap();
		assert_eq!((t.tag, t.body.len(), rest.len()), (0x04, 300, 0));
		assert!(tlv(&enc[..100]).is_err(), "truncated");
		assert!(tlv(&[0x30, 0x80, 0, 0]).is_err(), "indefinite lengths are BER, not DER");
	}

	/// A reply from OpenSSL's own TSA (`openssl ts -reply`, an EC P-256
	/// signer) to exactly the request above with imprint 0xab… and nonce
	/// 0x7f01…07 — an independent writer, so this parser is not checked
	/// against itself.
	const OPENSSL_REPLY: &[u8] = include_bytes!("testdata/tsa-reply-ec.der");

	#[test]
	fn an_openssl_reply_yields_its_token() {
		let nonce = [0x7f, 1, 2, 3, 4, 5, 6, 7];
		let stamp = token_of(OPENSSL_REPLY, &[0xab; 32], &nonce).expect("OpenSSL's reply parses");
		assert_eq!(stamp.at.len(), "2026-10-14T17:40:00Z".len());
		assert!(stamp.at.starts_with("20") && stamp.at.ends_with('Z'), "{}", stamp.at);
		assert_eq!(stamp.token[0], 0x30, "the token is the ContentInfo, whole");
		assert!(OPENSSL_REPLY.ends_with(&stamp.token), "and it is the reply's last element, byte for byte");
		// The checks the Worker can make: another imprint, another nonce.
		assert!(token_of(OPENSSL_REPLY, &[0xac; 32], &nonce).unwrap_err().contains("something other"));
		assert!(token_of(OPENSSL_REPLY, &[0xab; 32], &[0x7f, 1, 2, 3, 4, 5, 6, 8]).unwrap_err().contains("nonce"));
		// A refusal: PKIStatus rejection (2), no token.
		assert!(token_of(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02], &[0xab; 32], &nonce).unwrap_err().contains("refused"));
	}

	#[test]
	fn gen_time_becomes_iso() {
		assert_eq!(iso_time(b"20261014173804Z").unwrap(), "2026-10-14T17:38:04Z");
		assert_eq!(iso_time(b"20261014173804.25Z").unwrap(), "2026-10-14T17:38:04.25Z");
		assert!(iso_time(b"261014173804Z").is_err(), "UTCTime is not GeneralizedTime");
	}
}
