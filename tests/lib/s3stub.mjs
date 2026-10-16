// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A minimal S3-compatible server for the API suites, in memory. The Worker's
 * SigV4 signatures are proven against golden vectors in crates/s3; this stub
 * exists so the *routes* can be tested end to end without MinIO running.
 * It implements exactly what worker/src/s3.rs speaks:
 *
 *   PUT    /bucket/key              store
 *   GET    /bucket/key[?params]     read (Range → 206)
 *   HEAD   /bucket/key              size + etag
 *   DELETE /bucket/key[?uploadId]   delete / abort multipart
 *   POST   /bucket/key?uploads      create multipart → UploadId (XML)
 *   PUT    /bucket/key?partNumber…  upload part → ETag header
 *   POST   /bucket/key?uploadId…    complete multipart (concatenate)
 *   GET    /bucket?list-type=2…     ListObjectsV2 (minimal XML)
 *   PUT    /bucket/key?retention    Object Lock retention (commit 29c): the
 *                                   body's Content-MD5 checked, COMPLIANCE
 *                                   never shortened; a locked object
 *                                   refuses DELETE (403), as a locked
 *                                   version does in a real versioned bucket
 *   GET    /bucket/key?retention    the retention, or 404
 *
 * And one test-only control route (commit 25), for the suites that must see
 * the Worker meet a FAILING storage backend (docs/SECURITY-REVIEW.md › O10):
 *
 *   POST   /__fault  { method, prefix, status, count, query?, code?, server? }
 *          the next `count` requests with that method on keys under
 *          `prefix` (and, with `query`, whose query string contains it)
 *          answer `status` instead (count 0 clears the rule) — with S3's
 *          error body `<Error><Code>code</Code>…` when `code` is given, and
 *          a `Server` header when `server` is (commit 39s: the Worker reads
 *          both to say why a storage refused)
 *
 * Authorization headers are accepted and ignored here on purpose.
 */

import http from "node:http";
import { createHash } from "node:crypto";

export function startS3Stub({ port = 0, host = "0.0.0.0" } = {}) {
	const objects = new Map(); // key → Buffer
	const uploads = new Map(); // uploadId → { key, parts: Map<n, Buffer> }
	const retention = new Map(); // key → RetainUntilDate (ISO)
	let nextUploadId = 1;
	let faults = []; // { method, prefix, status, count }

	const server = http.createServer((req, res) => {
		const url = new URL(req.url, "http://stub");
		const raw = url.pathname.replace(/^\/[^/]+\/?/, ""); // strip /bucket/
		const key = decodeURIComponent(raw);
		const collect = () =>
			new Promise((resolve) => {
				const chunks = [];
				req.on("data", (c) => chunks.push(c));
				req.on("end", () => resolve(Buffer.concat(chunks)));
			});

		collect().then((body) => {
			const q = url.searchParams;
			if (url.pathname === "/__fault" && req.method === "POST") {
				const rule = JSON.parse(body.toString() || "{}");
				faults = faults.filter((f) => !(f.method === rule.method && f.prefix === rule.prefix && f.query === rule.query));
				if (rule.count > 0) faults.push(rule);
				res.writeHead(200).end("{}");
				return;
			}
			const fault = faults.find((f) => f.method === req.method && key.startsWith(f.prefix) && (f.query === undefined || url.search.includes(f.query)) && f.count > 0);
			if (fault) {
				fault.count--;
				const headers = fault.server ? { Server: fault.server } : {};
				if (fault.code) res.writeHead(fault.status, { ...headers, "Content-Type": "application/xml" }).end(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>${fault.code}</Code><Message>stub refusal</Message></Error>`);
				else res.writeHead(fault.status, headers).end();
				return;
			}
			// Object Lock retention (COMPLIANCE).
			if (q.has("retention")) {
				if (req.method === "PUT") {
					const md5 = createHash("md5").update(body).digest("base64");
					if (req.headers["content-md5"] !== md5) {
						res.writeHead(400, { "content-type": "application/xml" }).end("<Error><Code>InvalidDigest</Code></Error>");
						return;
					}
					if (!objects.has(key)) {
						res.writeHead(404).end();
						return;
					}
					const until = /<RetainUntilDate>([^<]+)<\/RetainUntilDate>/.exec(body.toString())?.[1];
					const mode = /<Mode>([^<]+)<\/Mode>/.exec(body.toString())?.[1];
					if (!until || mode !== "COMPLIANCE") {
						res.writeHead(400).end();
						return;
					}
					const was = retention.get(key);
					if (was && until < was) {
						res.writeHead(403, { "content-type": "application/xml" }).end("<Error><Code>AccessDenied</Code><Message>a COMPLIANCE retention cannot be shortened</Message></Error>");
						return;
					}
					retention.set(key, until);
					res.writeHead(200).end();
					return;
				}
				if (req.method === "GET") {
					const until = retention.get(key);
					if (!until) {
						res.writeHead(404).end();
						return;
					}
					res.writeHead(200, { "content-type": "application/xml" }).end(`<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>${until}</RetainUntilDate></Retention>`);
					return;
				}
			}
			if (req.method === "DELETE" && !q.has("uploadId") && retention.get(key) > new Date().toISOString()) {
				res.writeHead(403, { "content-type": "application/xml" }).end("<Error><Code>AccessDenied</Code><Message>object is WORM protected</Message></Error>");
				return;
			}
			// multipart create
			if (req.method === "POST" && q.has("uploads")) {
				const id = `upl-${nextUploadId++}`;
				uploads.set(id, { key, parts: new Map() });
				res.writeHead(200, { "content-type": "application/xml" });
				res.end(`<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
				return;
			}
			// multipart complete
			if (req.method === "POST" && q.has("uploadId")) {
				const u = uploads.get(q.get("uploadId"));
				if (!u) {
					res.writeHead(404).end();
					return;
				}
				// As S3 does: the object is the parts the body LISTS, in its order,
				// each with the ETag its upload answered — an empty or unknown
				// list is MalformedXML / InvalidPart (the stub used to concatenate
				// whatever it held, so a Worker that sent no parts passed here and
				// failed on every real server — the IDrive e2 live run, 2026-10-15).
				const listed = [...body.toString().matchAll(/<Part>\s*<PartNumber>(\d+)<\/PartNumber>\s*<ETag>([^<]*)<\/ETag>\s*<\/Part>/g)].map((m) => [Number(m[1]), m[2].replace(/&quot;/g, '"')]);
				const xmlError = (code) => {
					res.writeHead(400, { "content-type": "application/xml" });
					res.end(`<?xml version="1.0"?><Error><Code>${code}</Code></Error>`);
				};
				if (!listed.length) return xmlError("MalformedXML");
				if (listed.some(([pn, tag], i) => !u.parts.has(pn) || tag !== `"${u.key}-${pn}"` || (i > 0 && pn <= listed[i - 1][0]))) return xmlError("InvalidPart");
				objects.set(u.key, Buffer.concat(listed.map(([pn]) => u.parts.get(pn))));
				uploads.delete(q.get("uploadId"));
				res.writeHead(200, { "content-type": "application/xml" });
				res.end(`<?xml version="1.0"?><CompleteMultipartUploadResult><ETag>"done"</ETag></CompleteMultipartUploadResult>`);
				return;
			}
			// multipart part
			if (req.method === "PUT" && q.has("uploadId")) {
				const u = uploads.get(q.get("uploadId"));
				if (!u) {
					// What S3 says for an upload it does not know (39t).
					res.writeHead(404, { "Content-Type": "application/xml" }).end('<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchUpload</Code><Message>The specified upload does not exist.</Message></Error>');
					return;
				}
				u.parts.set(Number(q.get("partNumber")), body);
				const etag = `"${u.key}-${q.get("partNumber")}"`;
				res.writeHead(200, { etag });
				res.end();
				return;
			}
			// abort
			if (req.method === "DELETE" && q.has("uploadId")) {
				uploads.delete(q.get("uploadId"));
				res.writeHead(204).end();
				return;
			}
			switch (req.method) {
				case "PUT":
					objects.set(key, body);
					res.writeHead(200, { etag: `"${key.length}"` }).end();
					return;
				case "HEAD": {
					const o = objects.get(key);
					if (!o) {
						res.writeHead(404).end();
						return;
					}
					res.writeHead(200, { "content-length": String(o.length), etag: `"${key.length}"` }).end();
					return;
				}
				case "GET": {
					if (key === "" && q.get("list-type")) {
						const prefix = q.get("prefix") ?? "";
						const items = [...objects.entries()].filter(([k]) => k.startsWith(prefix));
						const xml = `<?xml version="1.0"?><ListBucketResult>${items.map(([k, v]) => `<Contents><Key>${k}</Key><Size>${v.length}</Size></Contents>`).join("")}${items.length ? `<IsTruncated>false</IsTruncated>` : `<IsTruncated>false</IsTruncated>`}</ListBucketResult>`;
						res.writeHead(200, { "content-type": "application/xml" }).end(xml);
						return;
					}
					const o = objects.get(key);
					if (!o) {
						res.writeHead(404).end();
						return;
					}
					const range = req.headers.range?.match(/bytes=(\d+)-(\d+)?/);
					if (range) {
						const start = Number(range[1]);
						const end = range[2] !== undefined ? Number(range[2]) : o.length - 1;
						res.writeHead(206, { "content-range": `bytes ${start}-${end}/${o.length}`, "content-length": String(end - start + 1) });
						res.end(o.subarray(start, end + 1));
						return;
					}
					res.writeHead(200, { "content-length": String(o.length) }).end(o);
					return;
				}
				case "DELETE":
					objects.delete(key);
					res.writeHead(204).end();
					return;
				default:
					res.writeHead(405).end();
			}
		});
	});

	return new Promise((resolve) => {
		server.listen(port, host, () => resolve({ server, address: server.address(), close: () => new Promise((r) => server.close(r)) }));
	});
}