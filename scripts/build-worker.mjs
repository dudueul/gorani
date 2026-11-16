#!/usr/bin/env node
// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Build the Rust Worker (wrangler.jsonc › build.command, run by `wrangler
 * dev` and `wrangler deploy`): worker-build compiles worker/src/lib.rs to
 * wasm32-unknown-unknown, runs wasm-bindgen and writes worker/build/worker/.
 *
 * A script, not a shell line, so it runs the same on Windows: wrangler runs
 * a build command through cmd.exe there, where the bash line it replaced
 * (`cd worker && export PATH=… && …`) could not run at all.
 *
 *   PATH            rustup puts cargo in ~/.cargo/bin, which a login shell
 *                   has and wrangler's build shell may not: added here
 *   worker-build    pinned to the `worker` crate's minor version (0.8, as
 *                   in worker/Cargo.toml): each worker-build refuses a crate
 *                   of another minor, so an unpinned install broke the first
 *                   fresh build after 0.9 came out. Raise both together.
 */

import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKER_BUILD = "worker-build@^0.8";
const env = { ...process.env, PATH: [path.join(os.homedir(), ".cargo", "bin"), process.env.PATH ?? ""].join(path.delimiter) };

const run = (cmd, args) => {
	const r = spawnSync(cmd, args, { cwd: path.join(ROOT, "worker"), stdio: "inherit", env });
	if (r.error) {
		console.error(`build-worker: ${cmd} did not start (${r.error.message}) — is Rust installed? https://rustup.rs`);
		process.exit(1);
	}
	if (r.status !== 0) process.exit(r.status ?? 1);
};

// (cargo install does nothing when the pinned version is already there.)
run("cargo", ["install", "-q", WORKER_BUILD]);
run("worker-build", ["--release"]);
