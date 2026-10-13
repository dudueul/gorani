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
 *
 * Authorization headers are accepted and ignored here on purpose.
 */

import http from "node:http";

export function startS3Stub({ port = 0, host = "0.0.0.0" } = {}) {
	const objects = new Map(); // key → Buffer
	const uploads = new Map(); // uploadId → { key, parts: Map<n, Buffer> }
	let nextUploadId = 1;

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
				const n = [...u.parts.keys()].sort((a, b) => a - b);
				objects.set(u.key, Buffer.concat(n.map((k) => u.parts.get(k))));
				uploads.delete(q.get("uploadId"));
				res.writeHead(200, { "content-type": "application/xml" });
				res.end(`<?xml version="1.0"?><CompleteMultipartUploadResult><ETag>"done"</ETag></CompleteMultipartUploadResult>`);
				return;
			}
			// multipart part
			if (req.method === "PUT" && q.has("uploadId")) {
				const u = uploads.get(q.get("uploadId"));
				if (!u) {
					res.writeHead(404).end();
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