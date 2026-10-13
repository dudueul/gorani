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

export async function startDev({ port = 8790 + Math.floor(Math.random() * 40), config, persist = "persist" } = {}) {
	if (!fs.existsSync(path.join(ROOT, "web/dist/index.html"))) {
		const b = spawnSync("npm", ["--prefix", "web", "run", "build"], { cwd: ROOT, encoding: "utf8" });
		if (b.status !== 0) throw new Error(`web build failed:\n${b.stdout}\n${b.stderr}`);
	}
	// The S3 stub, before anything fetches it.
	const { startS3Stub } = await import("../lib/s3stub.mjs");
	const stub = await startS3Stub();
	// Dev vars: auth bypassed with a header, storage endpoints as placeholders
	// (the registry routes never touch S3; file-route suites replace these).
	// The S3 endpoint uses the machine's LAN IP, not loopback: `wrangler dev`
	// (workerd) refuses outbound fetches to localhost, LAN addresses work.
	const lan = Object.values(os.networkInterfaces())
		.flatMap((xs) => xs ?? [])
		.find((x) => x && !x.internal && x.family === "IPv4")?.address;
	const s3endpoint = lan ? `http://${lan}:${stub.address.port}` : `http://127.0.0.1:${stub.address.port}`;
	fs.writeFileSync(
		path.join(ROOT, ".dev.vars"),
		["GORANI_DEV=1", `S3_ENDPOINT=${s3endpoint}`, "S3_REGION=us-east-1", "S3_BUCKET=gorani-test", "S3_ACCESS_KEY_ID=test", "S3_SECRET_KEY=test", "VAULT_DESTROY_ENABLED=1", ""].join("\n"),
	);
	const out = fs.openSync(path.join(ROOT, "tests/output/wrangler-dev.log"), "w");
	// Fresh SQLite state per run: a private persist directory (created before
	// the server starts — workerd wants it present), cleared each run so the
	// suites stay independent; production state lives in the cloud. Suites
	// with their own config (the R2 twin) get their own directory — two live
	// servers must never share one SQLite home.
	const persistDir = path.join(ROOT, "tests/output", persist);
	fs.rmSync(persistDir, { recursive: true, force: true });
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
	if (process.env.GORANI_URL) return { base: process.env.GORANI_URL, close: async () => {} };
	return startDev();
}