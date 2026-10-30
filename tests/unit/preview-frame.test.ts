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
 *   5. an asset request names a file of the reader's, never a path out;
 *   6. Trusted Types: three named policies — ours, DOMPurify's, and the
 *      default that sanitises (42b) — and no others.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { assetPath, cleanFact, cleanName, visibleControls } from "../../web/src/ui/viewer/sandbox.ts";

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
	// Three policies, and no other can be made: ours (blob: script URLs),
	// DOMPurify's, and the default that sanitises every HTML string (42b).
	assert.deepEqual(directives.get("trusted-types"), ["gorani-preview", "dompurify", "default"]);
	assert.ok(!directives.get("trusted-types")!.includes("'allow-duplicates'"), "a policy name cannot be taken twice");
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

// 한글's reader asks for its WebAssembly, and nothing else; the readers
// that need nothing are sent nothing.
assert.equal(assetPath("hwp", "rhwp_bg.wasm"), "/readers/hwp/rhwp_bg.wasm");
for (const bad of ["LICENSE", "../pdf/wasm/openjpeg.wasm", "rhwp_bg.wasm.map", "cmaps/UniKS-UCS2-H.bcmap"]) assert.equal(assetPath("hwp", bad), null, `hwp refused: ${bad}`);
for (const reader of ["docx", "sheet", "pptx", "legacy", "email"] as const) assert.equal(assetPath(reader, "rhwp_bg.wasm"), null, `${reader} has no assets`);
// The image reader (42d) asks for libheif — its script and its WebAssembly — and nothing else.
assert.equal(assetPath("image", "libheif.js"), "/readers/image/libheif.js");
assert.equal(assetPath("image", "libheif.wasm"), "/readers/image/libheif.wasm");
for (const bad of ["LICENSE", "libheif.js.map", "../hwp/rhwp_bg.wasm", "libheif-bundle.js", "image.worker.js"]) assert.equal(assetPath("image", bad), null, `image refused: ${bad}`);
// The archive reader (42e) asks for 7-Zip — its script and WebAssembly — and nothing else.
assert.equal(assetPath("archive", "7zz.js"), "/readers/archive/7zz.js");
assert.equal(assetPath("archive", "7zz.wasm"), "/readers/archive/7zz.wasm");
for (const bad of ["License.txt", "unRarLicense.txt", "7zz.umd.js", "../image/libheif.wasm", "7zz.wasm.map"]) assert.equal(assetPath("archive", bad), null, `archive refused: ${bad}`);
// A name with a right-to-left override cannot reorder the fact it is quoted in.
assert.equal(visibleControls("invoice\u202efdp.exe"), "invoice[RLO]fdp.exe");
assert.equal(cleanFact({ level: "warn", text: "Entry “invoice\u202efdp.exe” pretends" }).text, "Entry “invoice[RLO]fdp.exe” pretends", "every reader's facts, cleaned in one place");

// A fact's Copy (42d): only words the fact shows, short, as text.
assert.deepEqual(cleanFact({ level: "warn", text: "Carries where it was taken: 37.56630° N, 126.97790° E · 38 m up", copy: "37.56630° N, 126.97790° E" }), { level: "warn", text: "Carries where it was taken: 37.56630° N, 126.97790° E · 38 m up", copy: "37.56630° N, 126.97790° E" });
assert.equal(cleanFact({ level: "info", text: "A photo", copy: "https://phish.example/paste-me" }).copy, undefined, "words the fact does not show are not offered");
assert.equal(cleanFact({ level: "info", text: "x".repeat(200), copy: "x".repeat(101) }).copy, undefined, "at most 100 characters");
assert.equal(cleanFact({ level: "info", text: "a b", copy: "   " }).copy, undefined);
assert.deepEqual(cleanFact({ level: "evil", text: { toString: () => "t" } }), { level: "info", text: "t" }, "a level it does not know is info; a text is text");

// 7. A name a reader hands over (an attachment, 42c) is made safe to show
// and store: no direction marks, no control characters, no path.
assert.equal(cleanName("invoice\u202Efdp.exe"), "invoicefdp.exe", "the right-to-left override is gone (the facts name the trick)");
assert.equal(cleanName("..\\..\\Windows\\evil.dll"), "evil.dll");
assert.equal(cleanName("a/b/c.txt"), "c.txt");
assert.equal(cleanName("bell\u0007.txt"), "bell.txt");
assert.equal(cleanName("   "), "attachment");
assert.equal(cleanName(null), "attachment");
assert.equal(cleanName("x".repeat(500)).length, 200);

console.log("ok  preview-frame: the bootstrap pinned by hash, a frame policy that replaces the app's and lets nothing leave, frame-src 'self' holding the frame, allow-scripts only, asset names that cannot climb out, three Trusted Types policies and no more, handed-over names cleaned, a fact's Copy only words it shows, direction controls shown and not obeyed, 7-Zip the archive reader's only asset");
