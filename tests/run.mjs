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
const kinds = args.filter((w) => ["unit", "rust", "api"].includes(w));
const wantKind = (k) => !kinds.length || kinds.includes(k);
const failures = [];

if (wantKind("rust")) {
	// The crates with Rust tests; the worker crate is wasm-only and joins via
	// miniflare API suites (commit ⑥+), not host `cargo test`.
	const { cmd: cargo, env } = cargoCommand();
	const r = spawnSync(cargo, ["test", "-p", "gorani-formats", "-p", "gorani-s3"], { cwd: ROOT, env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
	const ok = r.status === 0;
	if (!ok) failures.push("rust");
	const out = `${String(r.stdout ?? "")}${String(r.stderr ?? "")}`;
	console.log(`${ok ? "ok  " : "FAIL"} rust: cargo test -p gorani-formats -p gorani-s3${ok ? "" : `\n${out.split("\n").filter((l) => /error|FAILED|panicked/.test(l)).slice(0, 12).join("\n")}`}`);
}

if (wantKind("unit")) {
	for (const f of fs.readdirSync(path.join(ROOT, "tests/unit")).filter((f) => f.endsWith(".test.mjs")).sort()) {
		const r = spawnSync(process.execPath, [path.join(ROOT, "tests/unit", f)], { cwd: ROOT, encoding: "utf8" });
		const ok = r.status === 0;
		if (!ok) failures.push(`unit:${f}`);
		const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
		const failLines = out.split("\n").filter((l) => /Error|error:|AssertionError|expected|actual/.test(l)).slice(0, 10).join("\n    ");
		console.log(`${ok ? "ok  " : "FAIL"} unit:${path.basename(f, ".test.mjs")}${ok ? "" : `\n    ${failLines}`}`);
	}
}

// API suites: one dev server per suite (fresh SQLite each time; the Rust
// worker build is cached after the first), URL handed over in GORANI_URL.
if (wantKind("api")) {
	const { suiteDev } = await import("./api/_dev.mjs");
	for (const f of fs.readdirSync(path.join(ROOT, "tests/api")).filter((f) => f.endsWith(".test.mjs")).sort()) {
		const dev = await suiteDev();
		try {
			// Async spawn on purpose: the parent owns the S3 stub's event
			// loop, and a spawnSync here would block it — the worker's
			// storage calls would never be accepted and the suite would hang
			// until its own timeout. (Found the fun way: an accept queue of 1.)
			const child = spawn(process.execPath, [path.join(ROOT, "tests/api", f)], {
				cwd: ROOT,
				env: { ...process.env, GORANI_URL: dev.base },
			});
			let out = "";
			child.stdout.on("data", (d) => (out += d));
			child.stderr.on("data", (d) => (out += d));
			const ok = await new Promise((resolve) => child.on("exit", (code) => resolve(code === 0)));
			if (!ok) failures.push(`api:${f}`);
			console.log(`${ok ? "ok  " : "FAIL"} api:${path.basename(f, ".test.mjs")}${ok ? "" : `\n    ${out.split("\n").filter((l) => /Error|error:|AssertionError|expected|actual/.test(l)).slice(0, 10).join("\n    ")}`}`);
		} finally {
			await dev.close();
		}
	}
}

if (failures.length) {
	console.error(`\nfailed: ${failures.join(", ")}`);
	process.exit(1);
}
console.log("\nall green");