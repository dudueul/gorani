// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:source-hygiene — no invisible characters in the sources (commit 42j,
 * docs/SECURITY-REVIEW.md › 42j).
 *
 * A right-to-left override, an isolate, a zero-width space or a byte-order
 * mark inside code is invisible in review and in most diffs, yet changes
 * what the code says: "Trojan Source" (CVE-2021-42574) hides logic that way
 * — a comment that is really code, a string that is not the one shown. The
 * readers in this repository look for exactly these characters in hostile
 * files (an invoice[RLO]fdp.exe-style name, a value that hides its end); the
 * code that does so must spell them as escapes (\u202e), which a reviewer
 * can see. Raw control characters (other than tab and line ends) are
 * refused for the same reason.
 *
 * Every file git tracks with a text extension is read; the escapes are
 * what the hostile fixtures are built from at test time.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const TEXT = /\.(?:ts|tsx|mjs|cjs|js|rs|py|sh|swift|css|html|md|json|toml|yml|yaml|txt|svg)$|(?:^|\/)(?:NOTICE|LICENSE|Dockerfile)$/;
// Built files and other people's code are checked where they come from, not here.
const SKIP = /^(?:web\/public\/(?:vendor|readers)\/|.*\/node_modules\/|.*\.min\.js$|.*package-lock\.json$|Cargo\.lock$)/;
// Bidi embeddings, overrides and isolates; zero-width and direction marks;
// the BOM; C0 controls but tab, LF, CR; DEL.
const INVISIBLE = /[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

const files = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8" }).split("\0").filter((f) => f && TEXT.test(f) && !SKIP.test(f));
const found = [];
for (const f of files) {
	let text;
	try {
		text = fs.readFileSync(path.join(ROOT, f), "utf8");
	} catch {
		continue; // (deleted in the working tree, not yet in the index)
	}
	for (const m of text.matchAll(INVISIBLE)) {
		const line = text.slice(0, m.index).split("\n").length;
		found.push(`${f}:${line}: U+${m[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`);
		if (found.length > 50) break;
	}
}
assert.ok(files.length > 100, `read the tracked sources (${files.length})`);
assert.deepEqual(found, [], "invisible characters must be written as escapes (\\u202e), not as themselves");

console.log(`ok  source-hygiene: ${files.length} tracked text files, no direction controls, zero-width characters, BOMs or raw controls in any`);
