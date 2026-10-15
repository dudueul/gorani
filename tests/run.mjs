// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The one test runner. With no arguments: the unit tests.
 *
 *   node tests/run.mjs            everything that exists so far
 *   node tests/run.mjs unit       only the unit tests
 *   node tests/run.mjs rust       only the Rust crates' tests (cargo test)
 *
 * Kinds grow as the code does: api (the Worker under miniflare, commit ⑥+),
 * e2e (the browser, commit ⑨+), client (the native engines, commit ⑬+).
 * Every commit stays green; tests/README.md maps groups to lessons.
 */

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cargoCommand } from "./lib/cargo.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const kinds = args.filter((w) => ["unit", "rust", "api", "e2e"].includes(w));
const wantKind = (k) => !kinds.length || kinds.includes(k);
const failures = [];

if (wantKind("rust")) {
	// The crates with Rust tests. The worker runs as wasm under `wrangler
	// dev` (the API suites), but its pure helpers also build on the host —
	// `--lib` runs their unit tests (schema.rs's forgivable-error rule).
	const { cmd: cargo, env } = cargoCommand();
	let r = spawnSync(cargo, ["test", "-p", "gorani-formats", "-p", "gorani-s3", "-p", "gorani-client-core"], { cwd: ROOT, env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
	if (r.status === 0) r = spawnSync(cargo, ["test", "-p", "gorani-worker", "--lib"], { cwd: ROOT, env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
	// Build the native CLI too: api:client-live drives target/debug/gorani-sync,
	// and a binary left over from an older checkout would test old code while
	// reporting green (it happened during the commit-23 review: a CLI fix
	// "failed" because the suite ran yesterday's binary).
	// (…and the Linux shell, gorani-mount, which api:linux-shell drives — commit 33d.)
	if (r.status === 0) r = spawnSync(cargo, ["build", "-p", "gorani-client-core", "-p", "gorani-linux"], { cwd: ROOT, env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
	const ok = r.status === 0;
	if (!ok) failures.push("rust");
	const out = `${String(r.stdout ?? "")}${String(r.stderr ?? "")}`;
	console.log(`${ok ? "ok  " : "FAIL"} rust: cargo test -p gorani-formats -p gorani-s3 -p gorani-client-core -p gorani-worker; build gorani-sync, gorani-mount${ok ? "" : `\n${out.split("\n").filter((l) => /error|FAILED|panicked/.test(l)).slice(0, 12).join("\n")}`}`);
}

if (wantKind("unit")) {
	for (const f of fs.readdirSync(path.join(ROOT, "tests/unit")).filter((f) => f.endsWith(".test.mjs") || f.endsWith(".test.ts")).sort()) {
		const r = spawnSync(process.execPath, [path.join(ROOT, "tests/unit", f)], { cwd: ROOT, encoding: "utf8" });
		const ok = r.status === 0;
		if (!ok) failures.push(`unit:${f}`);
		const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
		const failLines = out.split("\n").filter((l) => /Error|error:|AssertionError|expected|actual/.test(l)).slice(0, 10).join("\n    ");
		console.log(`${ok ? "ok  " : "FAIL"} unit:${path.basename(f).replace(/\.test\.(mjs|ts)$/, "")}${ok ? "" : `\n    ${failLines}`}`);
	}
}

// API suites: one dev server per suite (fresh SQLite each time; the Rust
// worker build is cached after the first), URL handed over in GORANI_URL.
if (wantKind("api")) {
	const { suiteDev } = await import("./api/_dev.mjs");
	for (const f of fs.readdirSync(path.join(ROOT, "tests/api")).filter((f) => f.endsWith(".test.mjs") || f.endsWith(".test.ts")).sort()) {
		// Suites that bring their own server (the R2-bound twin config, the
		// live-S3 suite pointed at a real bucket, the restart suite that stops
		// and starts its own) don't get the runner's stub-configured one — it
		// would sit unused.
		const ownServer = f.startsWith("r2.") || f.startsWith("s3-live.") || f.startsWith("restart.") || f.startsWith("bootstrap.") || f.startsWith("objectlock.") || f.startsWith("siem.") || f.startsWith("timestamps.") || f.startsWith("access.") || f.startsWith("requests.");
		const dev = ownServer ? null : await suiteDev();
		try {
			// Async spawn on purpose: the parent owns the S3 stub's event
			// loop, and a spawnSync here would block it — the worker's
			// storage calls would never be accepted and the suite would hang
			// until its own timeout. (Found the fun way: an accept queue of 1.)
			const child = spawn(process.execPath, [path.join(ROOT, "tests/api", f)], {
				cwd: ROOT,
				env: { ...process.env, ...(ownServer ? {} : { GORANI_URL: dev.base, GORANI_S3: dev.s3 ?? "", GORANI_S3_ROOT: dev.s3Root ?? "" }) },
			});
			let out = "";
			child.stdout.on("data", (d) => (out += d));
			child.stderr.on("data", (d) => (out += d));
			const ok = await new Promise((resolve) => child.on("exit", (code) => resolve(code === 0)));
			if (!ok) failures.push(`api:${f}`);
			// A suite that opted out (missing tool or credentials) says "skip"
			// on a line of its own; report it as such — a skip shown as "ok" is a
			// test that lies about having run.
			const label = !ok ? "FAIL" : /^skip\b/m.test(out) ? "skip" : "ok  ";
			console.log(`${label} api:${path.basename(f, ".test.mjs")}${ok ? "" : `\n    ${out.split("\n").filter((l) => /Error|error:|AssertionError|expected|actual/.test(l)).slice(0, 10).join("\n    ")}`}`);
		} finally {
			if (dev) await dev.close();
		}
	}
}

// E2E suites: the real browser (Playwright's chromium). Each brings its own
// dev server; the suite itself prints a skip and exits 0 when playwright is
// not installed, so a browser-less checkout stays green.
if (wantKind("e2e")) {
	for (const f of fs.readdirSync(path.join(ROOT, "tests/e2e")).filter((f) => f.endsWith(".test.mjs") || f.endsWith(".test.ts")).sort()) {
		const child = spawn(process.execPath, [path.join(ROOT, "tests/e2e", f)], { cwd: ROOT });
		let out = "";
		child.stdout.on("data", (d) => (out += d));
		child.stderr.on("data", (d) => (out += d));
		const ok = await new Promise((resolve) => child.on("exit", (code) => resolve(code === 0)));
		if (!ok) failures.push(`e2e:${f}`);
		const label = !ok ? "FAIL" : /^skip\b/m.test(out) ? "skip" : "ok  ";
		console.log(`${label} e2e:${path.basename(f, ".test.mjs")}${ok ? "" : `\n    ${out.split("\n").filter((l) => /Error|error:|AssertionError|expected|actual/.test(l)).slice(0, 10).join("\n    ")}`}`);
	}
}

if (failures.length) {
	console.error(`\nfailed: ${failures.join(", ")}`);
	process.exit(1);
}
console.log("\nall green");