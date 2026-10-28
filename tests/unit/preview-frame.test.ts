// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:preview-frame — the sandbox's rules, as files (commit 42a,
 * docs/PREVIEWS.md). The browser enforces them; this proves they say what
 * the design says, so an edit that weakens one fails here before any
 * browser runs:
 *
 *   1. the frame's one inline script is the one its CSP pins by hash
 *      (change a byte of it and the frame would not start — or, worse,
 *      someone "fixes" that by adding 'unsafe-inline');
 *   2. the frame's policy REPLACES the app's (detached, not merged) and
 *      lets nothing leave: no 'self', no http(s), no 'unsafe-eval', no
 *      frames, framed only by the app;
 *   3. the app's policy has frame-src 'self' — what also stops the frame
 *      navigating itself off this site to carry a file out;
 *   4. the frame is made with sandbox="allow-scripts" and no other flag;
 *   5. an asset request names a file of the reader's, never a path out.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { assetPath } from "../../web/src/ui/viewer/sandbox.ts";

const root = new URL("../../", import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root), "utf8");

// 1. The bootstrap and its hash.
const html = read("web/public/preview.html");
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]!);
assert.equal(scripts.length, 1, "one inline script: the bootstrap");
assert.doesNotMatch(html, /<script[^>]+src=/, "and no script loaded by URL");
const hash = createHash("sha256").update(scripts[0]!).digest("base64");
const headers = read("web/public/_headers");

/** The headers a path gets: its own block of the _headers file. */
function block(path: string): string[] {
	const lines = headers.split("\n");
	const at = lines.findIndex((l) => l === path);
	assert.ok(at >= 0, `_headers has a block for ${path}`);
	const out: string[] = [];
	for (const l of lines.slice(at + 1)) {
		if (!l.startsWith("  ")) break;
		out.push(l.trim());
	}
	return out;
}

for (const path of ["/preview.html", "/preview"]) {
	const b = block(path);
	const csp = b.find((l) => l.startsWith("Content-Security-Policy:"))?.slice("Content-Security-Policy:".length).trim() ?? "";
	assert.ok(csp.includes(`'sha256-${hash}'`), `${path}: the CSP pins the bootstrap's hash (sha256-${hash})`);
	// 2. Replaced, not merged: the app's own policy would forbid blob: scripts.
	for (const h of ["Content-Security-Policy", "X-Frame-Options", "Permissions-Policy"]) assert.ok(b.includes(`! ${h}`), `${path}: the app's ${h} is detached first`);
	const directives = new Map(csp.split(";").map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k!, v]));
	assert.deepEqual(directives.get("default-src"), ["'none'"]);
	for (const [name, values] of directives) {
		assert.ok(!values.includes("'self'") || name === "frame-ancestors", `${path}: ${name} does not allow 'self' — the frame fetches nothing, not even from this site`);
		assert.ok(!values.some((v) => /^(https?:|\*|wss?:)/.test(v)), `${path}: ${name} names no network source`);
		assert.ok(!values.includes("'unsafe-eval'"), `${path}: ${name} allows no eval`);
	}
	assert.deepEqual(directives.get("connect-src"), ["blob:", "data:"], "requests only for what is already in the frame");
	assert.deepEqual(directives.get("script-src"), [`'sha256-${hash}'`, "blob:", "'wasm-unsafe-eval'"], "the bootstrap, the readers it was handed, WebAssembly");
	assert.deepEqual(directives.get("frame-src"), ["'none'"]);
	assert.deepEqual(directives.get("frame-ancestors"), ["'self'"], "only the app frames it");
	assert.deepEqual(directives.get("form-action"), ["'none'"]);
	assert.deepEqual(directives.get("require-trusted-types-for"), ["'script'"]);
	assert.ok(b.includes("X-Frame-Options: SAMEORIGIN"));
}

// 3. The app's policy frames it — and holds it there.
const app = block("/*").find((l) => l.startsWith("Content-Security-Policy:")) ?? "";
assert.match(app, /frame-src 'self';/, "the app may frame its own preview page, and a frame may navigate nowhere else");
assert.match(app, /frame-ancestors 'none'/, "the app itself is still never framed");

// 4. The sandbox flags: scripts, and nothing else.
const sandbox = read("web/src/ui/viewer/sandbox.ts");
const flags = [...sandbox.matchAll(/setAttribute\("sandbox", "([^"]*)"\)/g)].map((m) => m[1]);
assert.deepEqual(flags, ["allow-scripts"], "allow-scripts only — never allow-same-origin, popups, forms, downloads or top navigation");

// 5. Asset names.
assert.equal(assetPath("pdf", "cmaps/UniKS-UCS2-H.bcmap"), "/readers/pdf/cmaps/UniKS-UCS2-H.bcmap");
assert.equal(assetPath("pdf", "standard_fonts/FoxitSerif.pfb"), "/readers/pdf/standard_fonts/FoxitSerif.pfb");
assert.equal(assetPath("pdf", "standard_fonts/LiberationSans-Bold.ttf"), "/readers/pdf/standard_fonts/LiberationSans-Bold.ttf");
assert.equal(assetPath("pdf", "wasm/openjpeg.wasm"), "/readers/pdf/wasm/openjpeg.wasm");
assert.equal(assetPath("pdf", "wasm/jbig2_nowasm_fallback.js"), "/readers/pdf/wasm/jbig2_nowasm_fallback.js");
for (const bad of ["../index.html", "cmaps/../../api/v1/family", "cmaps/a/b.bcmap", "/etc/passwd", "cmaps/x.bcmap?x=1", "standard_fonts/x.exe", "wasm/quickjs-eval.wasm", "https://evil.example/x", "", "cmaps/" + "a".repeat(300), 42, null]) {
	assert.equal(assetPath("pdf", bad), null, `refused: ${JSON.stringify(bad)}`);
}

console.log("ok  preview-frame: the bootstrap pinned by hash, a frame policy that replaces the app's and lets nothing leave, frame-src 'self' holding the frame, allow-scripts only, asset names that cannot climb out");
