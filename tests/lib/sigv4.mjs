// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A minimal AWS SigV4 signer for the LIVE suite's own checks (tests/api/
 * s3-live.test.mjs) — the questions only the storage server can answer
 * directly: "does this object carry a COMPLIANCE retention?", "does the
 * server refuse to delete that version?". The Worker's signer (crates/s3)
 * is proven by golden vectors; this one is an independent second
 * implementation, used only to inspect a real bucket — UNSIGNED-PAYLOAD,
 * path-style, like the Worker.
 */

import { createHash, createHmac } from "node:crypto";

const hmac = (key, data) => createHmac("sha256", key).update(data).digest();
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** fetch() a signed S3 request. `key` "" for the bucket; `query` pairs. */
export async function s3fetch(cfg, method, key, query = {}, extraHeaders = {}) {
	const url = new URL(cfg.endpoint);
	const path = `/${enc(cfg.bucket)}${key ? `/${key.split("/").map(enc).join("/")}` : ""}`;
	const cq = Object.entries(query).map(([k, v]) => [enc(k), enc(v)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join("&");
	const now = new Date();
	const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
	const day = amzDate.slice(0, 8);
	const headers = { host: url.host, "x-amz-content-sha256": "UNSIGNED-PAYLOAD", "x-amz-date": amzDate };
	const signed = Object.keys(headers).sort();
	const canonical = [method, path, cq, ...signed.map((h) => `${h}:${headers[h]}`), "", signed.join(";"), "UNSIGNED-PAYLOAD"].join("\n");
	const scope = `${day}/${cfg.region}/s3/aws4_request`;
	const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, createHash("sha256").update(canonical).digest("hex")].join("\n");
	const kSigning = ["s3", "aws4_request"].reduce((k, d) => hmac(k, d), hmac(hmac(`AWS4${cfg.secretKey}`, day), cfg.region));
	const signature = createHmac("sha256", kSigning).update(toSign).digest("hex");
	const auth = `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${scope}, SignedHeaders=${signed.join(";")}, Signature=${signature}`;
	const { host, ...sent } = headers;
	void host;
	return fetch(`${cfg.endpoint}${path}${cq ? `?${cq}` : ""}`, { method, headers: { ...sent, ...extraHeaders, authorization: auth } });
}
