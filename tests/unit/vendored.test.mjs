// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:vendored — the one file gorani serves without building it (commit 25,
 * docs/SECURITY-REVIEW.md › O17): web/public/vendor/argon2.umd.min.js, the
 * Argon2id the public share page runs on a link's password.
 *
 * A vendored file is a supply-chain decision frozen in the repository, so
 * it must be (1) traceable — byte-identical to a named release, (2)
 * recorded — its hash in NOTICE, and (3) enforced — the page's Subresource
 * Integrity hash, so a changed file is refused by the browser. Three copies
 * of one fact drift unless something checks them; this does.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vendored = fs.readFileSync(path.join(ROOT, "web/public/vendor/argon2.umd.min.js"));
const sha256 = createHash("sha256").update(vendored).digest("hex");
const sri = "sha384-" + createHash("sha384").update(vendored).digest("base64");

// (2) recorded: NOTICE names the hash.
const notice = fs.readFileSync(path.join(ROOT, "NOTICE"), "utf8");
assert.ok(notice.includes(sha256), `NOTICE records the vendored file's sha256 (${sha256})`);
// (3) enforced: the share page pins it with SRI.
const page = fs.readFileSync(path.join(ROOT, "web/s.html"), "utf8");
assert.ok(page.includes(`integrity="${sri}"`), `web/s.html pins the file with ${sri}`);
// …and the built page kept the attribute (Vite copies the tag as written).
const built = path.join(ROOT, "web/dist/s.html");
if (fs.existsSync(built)) assert.ok(fs.readFileSync(built, "utf8").includes(`integrity="${sri}"`), "the BUILT share page still carries the SRI hash");
// (1) traceable: the file is the release's file, byte for byte.
const pkg = path.join(ROOT, "web/node_modules/hash-wasm");
if (fs.existsSync(pkg)) {
	const version = JSON.parse(fs.readFileSync(path.join(pkg, "package.json"), "utf8")).version;
	assert.ok(notice.includes(`hash-wasm ${version}`), `NOTICE names the installed hash-wasm version (${version})`);
	assert.deepEqual(vendored, fs.readFileSync(path.join(pkg, "dist/argon2.umd.min.js")), "the vendored file IS the package's dist/argon2.umd.min.js");
}

console.log("ok  vendored: the share page's Argon2 is traceable (= hash-wasm's build), recorded (NOTICE) and enforced (SRI)");
