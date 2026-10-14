// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A stand-in SIEM collector for api:siem (commit 29i): an HTTP endpoint
 * that accepts what gorani ships — NDJSON or Splunk HEC lines — and keeps
 * every request for the suite to inspect. `failNext(n)` makes the next n
 * deliveries fail with a 503, the way a collector under maintenance does,
 * so a suite can prove nothing is lost and nothing skipped.
 *
 * Listens on all interfaces: `wrangler dev` (workerd) refuses loopback
 * fetches, so the Worker reaches it on the machine's LAN address, like the
 * S3 stub.
 */

import http from "node:http";
import os from "node:os";

export async function startSiemStub() {
	const requests = [];
	let failures = 0;
	const server = http.createServer((req, res) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => {
			const body = Buffer.concat(chunks).toString("utf8");
			if (failures > 0) {
				failures--;
				requests.push({ refused: true, path: req.url, headers: req.headers, body });
				res.writeHead(503, { "content-type": "application/json" }).end('{"text":"maintenance"}');
				return;
			}
			requests.push({ refused: false, path: req.url, headers: req.headers, body, events: body.split("\n").filter(Boolean).map((l) => JSON.parse(l)) });
			res.writeHead(200, { "content-type": "application/json" }).end('{"text":"Success","code":0}');
		});
	});
	await new Promise((resolve) => server.listen(0, "0.0.0.0", resolve));
	const lan = Object.values(os.networkInterfaces())
		.flatMap((xs) => xs ?? [])
		.find((x) => x && !x.internal && x.family === "IPv4")?.address ?? "127.0.0.1";
	return {
		url: `http://${lan}:${server.address().port}/ingest`,
		requests,
		/** Every event accepted, in arrival order. */
		events: () => requests.filter((r) => !r.refused).flatMap((r) => r.events),
		failNext(n) {
			failures = n;
		},
		close: () => new Promise((resolve) => server.close(resolve)),
	};
}
