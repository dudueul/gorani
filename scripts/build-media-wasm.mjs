// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Build the video engine for the browser (commit 39p, docs/VIDEO.md):
 * crates/media-wasm → web/public/gorani-media.wasm, which Vite then copies
 * into the app as-is. Run by `npm run build` in web/ before Vite.
 *
 * Skipped when the .wasm is newer than every source of both crates (a
 * no-op build costs nothing then). Needs the target the Worker already
 * needs: `rustup target add wasm32-unknown-unknown` (docs/PRODUCTION.md › 0).
 * The file is a build output, not a source: web/public/gorani-media.wasm
 * is git-ignored.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "web/public/gorani-media.wasm");
const SOURCES = ["crates/media/src", "crates/media/Cargo.toml", "crates/media-wasm/src", "crates/media-wasm/Cargo.toml", "Cargo.lock"];

const newest = (p) => {
	const st = fs.statSync(p);
	return st.isDirectory() ? Math.max(0, ...fs.readdirSync(p).map((f) => newest(path.join(p, f)))) : st.mtimeMs;
};
const sourcesAt = Math.max(...SOURCES.map((s) => path.join(ROOT, s)).filter((p) => fs.existsSync(p)).map(newest));
if (fs.existsSync(OUT) && fs.statSync(OUT).mtimeMs >= sourcesAt) {
	process.exit(0);
}

const target = process.env.CARGO_TARGET_DIR ?? path.join(ROOT, "target");
const r = spawnSync("cargo", ["build", "-p", "gorani-media-wasm", "--target", "wasm32-unknown-unknown", "--release"], { cwd: ROOT, stdio: "inherit", env: { ...process.env, PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}` } });
if (r.status !== 0) {
	console.error("build-media-wasm: cargo failed — is the target installed? rustup target add wasm32-unknown-unknown");
	process.exit(r.status ?? 1);
}
fs.copyFileSync(path.join(target, "wasm32-unknown-unknown/release/gorani_media_wasm.wasm"), OUT);
console.log(`build-media-wasm: ${path.relative(ROOT, OUT)} (${fs.statSync(OUT).size} bytes)`);
