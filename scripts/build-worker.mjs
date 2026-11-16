#!/usr/bin/env node
// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Build the Rust Worker (wrangler.jsonc › build.command, run by `wrangler
 * dev` and `wrangler deploy`): worker-build compiles worker/src/lib.rs to
 * wasm32-unknown-unknown, runs wasm-bindgen and writes worker/build/.
 *
 * A script, not a shell line, so it runs the same on Windows: wrangler runs
 * a build command through cmd.exe there, where the bash line it replaced
 * (`cd worker && export PATH=… && …`) could not run at all.
 *
 *   PATH            rustup puts cargo in $CARGO_HOME/bin (~/.cargo/bin when
 *                   unset), which a login shell has and wrangler's build
 *                   shell may not: added here
 *   worker-build    pinned to the `worker` crate's minor version (0.8, as
 *                   in worker/Cargo.toml): each worker-build refuses a crate
 *                   of another minor, so an unpinned install broke the first
 *                   fresh build after 0.9 came out. Raise both together.
 *
 * Installed only when the worker-build on the PATH is not a 0.8. Leaving
 * that to `cargo install` (a no-op when cargo installed the same version)
 * failed whenever the binary was there but cargo's record of installing it
 * (~/.cargo/.crates.toml) was not: a copied ~/.cargo/bin, cargo-binstall,
 * or a CI cache that kept the binary only. cargo will not overwrite a
 * binary it did not install ("already exists in destination"), so a
 * worker-build of another version is replaced with --force.
 */

import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKER_BUILD = { spec: "worker-build@^0.8", fits: /(^|\s)0\.8\.\d+/ };
const CARGO_BIN = path.join(process.env.CARGO_HOME || path.join(os.homedir(), ".cargo"), "bin");
const env = { ...process.env, PATH: [CARGO_BIN, process.env.PATH ?? ""].join(path.delimiter) };
const opts = { cwd: path.join(ROOT, "worker"), env };

const run = (cmd, args) => {
	const r = spawnSync(cmd, args, { ...opts, stdio: "inherit" });
	if (r.error) {
		console.error(`build-worker: ${cmd} did not start (${r.error.message}) — is Rust installed? https://rustup.rs`);
		process.exit(1);
	}
	if (r.status !== 0) process.exit(r.status ?? 1);
};

/** The worker-build on the PATH: its version line ("0.8.7"), or null when there is none. */
const installed = () => {
	const r = spawnSync("worker-build", ["--version"], { ...opts, encoding: "utf8" });
	return r.error || r.status !== 0 ? null : r.stdout.trim();
};

const have = installed();
if (have === null) run("cargo", ["install", "-q", WORKER_BUILD.spec]);
else if (!WORKER_BUILD.fits.test(have)) {
	console.log(`build-worker: worker-build ${have} cannot build a \`worker\` 0.8 crate; installing ${WORKER_BUILD.spec} over it`);
	run("cargo", ["install", "-q", "--force", WORKER_BUILD.spec]);
}
run("worker-build", ["--release"]);
