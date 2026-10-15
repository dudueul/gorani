// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The dev server, with the Worker's OUTBOUND requests made by Node — for a
 * live suite on a machine whose only way out is an HTTPS proxy (a sandbox,
 * a locked-down CI runner). `wrangler dev`'s runtime (workerd) connects to
 * storage by itself, with its own DNS, and reads no HTTPS_PROXY; Node's
 * fetch reads it (NODE_USE_ENV_PROXY=1, Node ≥ 22.21). Wrangler's own
 * programmatic API hands every outbound request to `outboundService`, which
 * re-issues it here — same method, URL, headers and body, so the SigV4
 * signature the Worker computed is what the storage server checks.
 *
 *   node tests/lib/dev-outbound.mjs <port> <persist dir> [config]
 *
 * Started by tests/api/_dev.mjs when GORANI_DEV_OUTBOUND=node (and only
 * with a real bucket: the stub is on this machine). Nothing here changes
 * what the Worker does — only which program opens its sockets.
 */

import { appendFileSync } from "node:fs";
import { unstable_startWorker } from "wrangler";

/** One line per outbound request — method, host, outcome; never a header or a query. */
const trace = (line) => appendFileSync(process.env.GORANI_OUTBOUND_TRACE ?? "/dev/stderr", `[outbound] ${line}\n`);

const [port, persist, config = "wrangler.jsonc"] = process.argv.slice(2);
const worker = await unstable_startWorker({
	config,
	dev: {
		server: { hostname: "127.0.0.1", port: Number(port) },
		persist,
		testScheduled: true,
		watch: false,
		inspector: false,
		// (A streamed body — a multipart part — needs `duplex: "half"` to be re-sent.)
		outboundService: async (request) => {
			const u = new URL(request.url);
			// (The key's first segment — files/, cases/, shares/ — names what was touched; no ids.)
			const what = `${u.pathname.split("/")[2] ?? ""}/${u.searchParams.has("uploadId") ? " (multipart)" : ""}`;
			try {
				const r = await fetch(request.url, { method: request.method, headers: request.headers, body: request.body, duplex: "half", redirect: "manual" });
				// A refusal's S3 error code (`<Code>`) — never the rest of the body.
				const code = r.status >= 400 ? ((await r.clone().text()).match(/<Code>([A-Za-z]+)<\/Code>/)?.[1] ?? "") : "";
				trace(`${request.method} ${what} → ${r.status}${code ? ` ${code}` : ""}`);
				return r;
			} catch (e) {
				trace(`${request.method} ${what} → ${e?.cause?.code ?? e?.message ?? e}`);
				throw e;
			}
		},
	},
});
await worker.ready;
console.log(`[dev-outbound] ready on http://127.0.0.1:${port} — outbound requests through Node`);
const stop = async () => {
	await worker.dispose().catch(() => {});
	process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
