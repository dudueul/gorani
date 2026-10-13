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
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export async function startDev({ port = 8790 + Math.floor(Math.random() * 40) } = {}) {
	if (!fs.existsSync(path.join(ROOT, "web/dist/index.html"))) {
		const b = spawnSync("npm", ["--prefix", "web", "run", "build"], { cwd: ROOT, encoding: "utf8" });
		if (b.status !== 0) throw new Error(`web build failed:\n${b.stdout}\n${b.stderr}`);
	}
	// Dev vars: auth bypassed with a header, storage endpoints as placeholders
	// (the registry routes never touch S3; file-route suites replace these).
	fs.writeFileSync(
		path.join(ROOT, ".dev.vars"),
		["GORANI_DEV=1", "S3_ENDPOINT=http://127.0.0.1:19000", "S3_REGION=us-east-1", "S3_BUCKET=gorani-test", "S3_ACCESS_KEY_ID=test", "S3_SECRET_KEY=test", ""].join("\n"),
	);
	const out = fs.openSync(path.join(ROOT, "tests/output/wrangler-dev.log"), "w");
	// Fresh SQLite state per run: the DOs keep their databases in this
	// directory, which the harness deletes after the run (tests stay
	// independent; production state lives in the cloud, never here).
	const persistDir = path.join(ROOT, "tests/output/persist");
	fs.rmSync(persistDir, { recursive: true, force: true });
	const child = spawn("npx", ["wrangler", "dev", "--port", String(port), "--ip", "127.0.0.1", "--persist-to", persistDir], {
		cwd: ROOT,
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
		} catch {
			// not up yet
		}
		if (Date.now() > deadline) {
			child.kill("SIGKILL");
			throw new Error("wrangler dev did not come up in time — see tests/output/wrangler-dev.log");
		}
		await new Promise((r) => setTimeout(r, 1000));
	}
	return {
		base,
		close() {
			child.kill("SIGTERM");
			fs.closeSync(out);
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