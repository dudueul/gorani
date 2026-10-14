// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * One `wrangler dev` server for the API suites: builds the web assets if
 * missing, writes a .dev.vars with dev-mode auth (GORANI_DEV=1 — the only
 * place that var may exist, see worker/src/auth.rs) and waits for
 * /api/healthz. The Rust worker build (worker-build) is cached after the
 * first run; the first start can take a minute.
 */

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/**
 * The R2 twin of wrangler.jsonc: the real config with the `R2BUCKET` binding
 * injected. Generated on demand from the real file — so the two cannot drift
 * — and gitignored. `wrangler dev` then backs the binding with its local R2
 * simulator, which is how the api:r2 suite exercises the storage layer's
 * R2-priority branch (worker/src/s3.rs) without a real bucket.
 */
export function r2Twin() {
	const raw = fs.readFileSync(path.join(ROOT, "wrangler.jsonc"), "utf8");
	const idx = raw.lastIndexOf("}");
	const twin = `${raw.slice(0, idx).trimEnd()},\n\n\t"r2_buckets": [\n\t\t{ "binding": "R2BUCKET", "bucket_name": "gorani-test" }\n\t]\n}\n`;
	fs.writeFileSync(path.join(ROOT, "wrangler.r2.jsonc"), twin);
	return "wrangler.r2.jsonc";
}

/**
 * `s3` (optional): a REAL S3-compatible target `{ endpoint, region, bucket,
 * accessKeyId, secretKey }` instead of the in-memory stub — the live suite
 * (tests/api/s3-live.test.mjs) uses it. The credentials go only into the
 * gitignored .dev.vars, exactly where `wrangler dev` reads secrets from.
 */
/** Is web/dist missing, or older than a file under web/src, web/public or a page? */
function webBuildStale() {
	const built = path.join(ROOT, "web/dist/index.html");
	if (!fs.existsSync(built)) return true;
	const at = fs.statSync(built).mtimeMs;
	const newer = (p) => {
		const st = fs.statSync(p);
		if (st.isDirectory()) return fs.readdirSync(p).some((f) => newer(path.join(p, f)));
		return st.mtimeMs > at;
	};
	return ["web/src", "web/public", "web/index.html", "web/s.html"].some((p) => fs.existsSync(path.join(ROOT, p)) && newer(path.join(ROOT, p)));
}

export async function startDev({ port = 8790 + Math.floor(Math.random() * 40), config, persist = "persist", s3, keepState = false, vars = {} } = {}) {
	// Build the web app when it is missing OR older than any of its sources.
	// (It used to build only when missing: the browser e2e then served a
	// stale bundle — and passed or failed for code that was not the code
	// under test. Commit 27's team screens were caught by exactly that.)
	if (webBuildStale()) {
		const b = spawnSync("npm", ["--prefix", "web", "run", "build"], { cwd: ROOT, encoding: "utf8" });
		if (b.status !== 0) throw new Error(`web build failed:\n${b.stdout}\n${b.stderr}`);
	}
	// The S3 stub, before anything fetches it (not needed against a real bucket).
	const { startS3Stub } = await import("../lib/s3stub.mjs");
	const stub = s3 ? { close: async () => {}, address: null } : await startS3Stub();
	// Dev vars: auth bypassed with a header, storage endpoints as placeholders
	// (the registry routes never touch S3; file-route suites replace these).
	// The S3 endpoint uses the machine's LAN IP, not loopback: `wrangler dev`
	// (workerd) refuses outbound fetches to localhost, LAN addresses work.
	const lan = Object.values(os.networkInterfaces())
		.flatMap((xs) => xs ?? [])
		.find((x) => x && !x.internal && x.family === "IPv4")?.address;
	const s3endpoint = s3 ? s3.endpoint : lan ? `http://${lan}:${stub.address.port}` : `http://127.0.0.1:${stub.address.port}`;
	fs.writeFileSync(
		path.join(ROOT, ".dev.vars"),
		// CACHE_MAX_OBJECT_MB=6: the cache suite exercises the size boundary
		// with whole-file/span pairs a few MB big instead of 256MB uploads
		// (the media span gate must fit a 5MiB GC01 frame).
		[
			"GORANI_DEV=1",
			`S3_ENDPOINT=${s3endpoint}`,
			`S3_REGION=${s3?.region ?? "us-east-1"}`,
			`S3_BUCKET=${s3?.bucket ?? "gorani-test"}`,
			`S3_ACCESS_KEY_ID=${s3?.accessKeyId ?? "test"}`,
			`S3_SECRET_KEY=${s3?.secretKey ?? "test"}`,
			"CACHE_MAX_OBJECT_MB=6",
			"VAULT_DESTROY_ENABLED=1",
			// Extra vars a suite needs on its own server (api:bootstrap's
			// BOOTSTRAP_TOKEN) — never secrets of a real deployment.
			...Object.entries(vars).map(([k, v]) => `${k}=${v}`),
			"",
		].join("\n"),
	);
	const out = fs.openSync(path.join(ROOT, "tests/output/wrangler-dev.log"), "w");
	// Fresh SQLite state per run: a private persist directory (created before
	// the server starts — workerd wants it present), cleared each run so the
	// suites stay independent; production state lives in the cloud. Suites
	// with their own config (the R2 twin) get their own directory — two live
	// servers must never share one SQLite home.
	// (`keepState`: the restart suite starts a second server on the SAME
	// directory — what a deploy or an evicted Durable Object does.)
	const persistDir = path.join(ROOT, "tests/output", persist);
	if (!keepState) fs.rmSync(persistDir, { recursive: true, force: true });
	fs.mkdirSync(persistDir, { recursive: true });
	const wr = ["wrangler", "dev"];
	if (config) wr.push("--config", config);
	wr.push("--port", String(port), "--ip", "127.0.0.1", "--persist-to", persistDir, "--test-scheduled");
	const child = spawn("npx", wr, {
		cwd: ROOT,
		detached: true, // own process group: close() kills wrangler AND its workerd children
		env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "true", PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}` },
		stdio: ["ignore", out, out],
	});
	const base = `http://127.0.0.1:${port}`;
	const deadline = Date.now() + 300_000;
	for (;;) {
		if (child.exitCode !== null) throw new Error(`wrangler dev exited (${child.exitCode}) — see tests/output/wrangler-dev.log`);
		try {
			const r = await fetch(`${base}/api/healthz`);
			if (r.ok) break;
			} catch (e) {
			void e; // not up yet
		}
		if (Date.now() > deadline) {
			child.kill("SIGKILL");
			throw new Error("wrangler dev did not come up in time — see tests/output/wrangler-dev.log");
		}
		await new Promise((r) => setTimeout(r, 1000));
	}
	return {
		base,
		// The storage the Worker talks to: the stub's URL (suites reach it
		// directly to remove an object or inject a fault — tests/lib/s3stub.mjs),
		// or null against a real bucket.
		s3: s3 ? null : `${s3endpoint}/${s3?.bucket ?? "gorani-test"}`,
		s3Root: s3 ? null : s3endpoint,
		close: async () => {
			try {
				process.kill(-child.pid, "SIGKILL"); // the whole group: workerd dies with wrangler
			} catch {
				child.kill("SIGKILL");
			}
			fs.closeSync(out);
			await stub.close();
		},
	};
}

/** A JSON API call against the dev server, with dev-mode identity headers. */
export async function api(base, method, path, { email = "mom@family.test", token, body } = {}) {
	const headers = { "content-type": "application/json" };
	if (email) headers["x-gorani-dev-email"] = email;
	if (token) headers["x-gorani-dev-token"] = token;
	const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
	const text = await r.text();
	let json = null;
	try {
		json = JSON.parse(text);
	} catch {
		// non-JSON (an error page) — reported as text
	}
	return { status: r.status, json, text };
}

/**
 * The suite's server: the runner (tests/run.mjs) starts one dev server for
 * the whole run and hands its URL in GORANI_URL — suites reuse it, because a
 * second server would clear the first one's SQLite state. A suite run
 * directly (node tests/api/…test.mjs) starts its own.
 */
export async function suiteDev() {
	if (process.env.GORANI_URL) return { base: process.env.GORANI_URL, s3: process.env.GORANI_S3 || null, s3Root: process.env.GORANI_S3_ROOT || null, close: async () => {} };
	return startDev();
}

/** Remove an object behind the Worker's back (a disk lost, a bucket rule). */
export async function stubDelete(dev, key) {
	const r = await fetch(`${dev.s3}/${key}`, { method: "DELETE" });
	if (r.status !== 204) throw new Error(`stub delete ${key}: ${r.status}`);
}

/** Make the next `count` `method` requests under `prefix` fail with `status`. */
export async function stubFault(dev, rule) {
	const r = await fetch(`${dev.s3Root}/__fault`, { method: "POST", body: JSON.stringify(rule) });
	if (!r.ok) throw new Error(`stub fault: ${r.status}`);
}