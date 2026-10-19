// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:zip-download — the pure half of Download as zip (commit 41a,
 * web/src/ui/files/zip-download.ts). What it proves:
 *
 *   1. a decrypted name becomes ONE safe path segment: no "/" or "\" to
 *      climb out with, nothing Windows refuses or silently changes, no
 *      device names, no "." / "..";
 *   2. paths are unique per folder WITHOUT case ("A.txt" and "a.txt" would
 *      overwrite each other unpacked on Windows or macOS), a file and a
 *      folder never share a name, and the report's name stays reserved;
 *   3. the report lists every file with its full SHA-256 and verdict,
 *      flags what does not verify, and names what was left out and why.
 *
 * (The model's half, the walk and the streaming, is in explorer.test.ts.)
 */

import assert from "node:assert/strict";
import { REPORT_NAME, ZipNames, checkReport, flagged, safeSegment, verdictOf, type ZipLine } from "../../web/src/ui/files/zip-download.ts";
import { describeHashCheck } from "../../web/src/vault/content-hash.ts";

// 1. One safe segment.
assert.equal(safeSegment("report.pdf"), "report.pdf", "an ordinary name is left alone");
assert.equal(safeSegment("보고서 2026.hwp"), "보고서 2026.hwp", "…in any script");
assert.equal(safeSegment("../../.bashrc"), ".._.._.bashrc", "no separator survives: a name cannot climb out");
assert.equal(safeSegment("a\\b/c"), "a_b_c");
assert.equal(safeSegment("what?.txt"), "what_.txt", "Windows refuses ?");
assert.equal(safeSegment('a<b>c:d"e|f*g'), "a_b_c_d_e_f_g");
assert.equal(safeSegment("tab\there\u0000"), "tab_here_", "control characters");
assert.equal(safeSegment("trailing. "), "trailing__", "Windows drops a trailing dot or space — two names would merge");
assert.equal(safeSegment(".."), "_");
assert.equal(safeSegment("."), "_");
assert.equal(safeSegment(""), "unnamed");
assert.equal(safeSegment("CON"), "_CON", "a Windows device name");
assert.equal(safeSegment("nul.txt"), "_nul.txt", "…with an extension too");
assert.equal(safeSegment("console.txt"), "console.txt", "…but not a name that merely starts like one");
assert.equal(safeSegment(".env"), ".env", "a dot file stays a dot file");
const long = safeSegment(`${"x".repeat(300)}.pdf`);
assert.equal(long.length, 120, "a very long name is shortened…");
assert.ok(long.endsWith(".pdf"), "…keeping its extension");
assert.equal(safeSegment("é.txt"), "é.txt", "composed (NFC), as macOS and Windows agree on");

// 2. Unique paths, without case.
const names = new ZipNames();
names.reserve(REPORT_NAME);
assert.equal(names.claim("", "gorani-check.txt"), "gorani-check (2).txt", "a file cannot take the report's name");
assert.equal(names.claim("", "Report.pdf"), "Report.pdf");
assert.equal(names.claim("", "report.PDF"), "report (2).PDF", "the same name in another case is the same file on Windows and macOS");
assert.equal(names.claim("", "Report.pdf"), "Report (3).pdf");
assert.equal(names.claim("", "Case"), "Case", "a folder…");
assert.equal(names.claim("", "case"), "case (2)", "…and a file of the same name cannot both be in one folder");
assert.equal(names.claim("Case", "Report.pdf"), "Case/Report.pdf", "another folder has its own names");
assert.equal(names.claim("CASE", "report.pdf"), "CASE/report (2).pdf", "…and a folder is the same folder in any case");
assert.equal(names.claim("", ".env"), ".env");
assert.equal(names.claim("", ".env"), ".env (2)", "a dot file numbers after its name");
assert.equal(names.claim("Case", "a/b"), "Case/a_b", "the name is made safe before it is placed");

// 3. The report.
const verified = { status: "verified" as const, signer: "bo", via: "team", active: true };
const lines: ZipLine[] = [
	{ path: "Case/disk.E01", size: 300_000, sha256: "a".repeat(64), check: verified },
	{ path: "Case/old.txt", size: 12, sha256: "b".repeat(64), check: { status: "unsigned" } },
	{ path: "Case/changed.bin", size: 9, sha256: "c".repeat(64), check: { status: "mismatch", signer: "bo", claimed: { sha256: "d".repeat(64), size: 9 }, actual: { sha256: "c".repeat(64), size: 9 } } },
	{ path: "Case/cut.bin", size: 4096, sha256: "e".repeat(64), check: null, error: "did not finish downloading (network) — the copy in this zip is incomplete (4096 of 8192 bytes)" },
	{ path: "unverified-name-f1", size: 3, sha256: "f".repeat(64), check: verified, nameUnverified: true },
];
assert.deepEqual(lines.map(verdictOf), ["OK", "UNSIGNED", "MISMATCH", "FAILED", "OK"]);
assert.deepEqual(lines.map(flagged), [false, false, true, true, false], "only what does not verify is flagged — an unsigned file has nothing to check against");
const made = new Date("2026-10-19T10:00:00Z");
const report = checkReport({ zipName: "Case.zip", area: "jinu", made, lines, leftOut: [{ path: "Case/dropper.exe", why: "a malware sample — download it on its own" }], detail: describeHashCheck });
assert.match(report, /^gorani — download check\n/);
assert.match(report, /Zip:   Case\.zip\nArea:  jinu\nMade:  2026-10-19T10:00:00\.000Z\nFiles: 5 in this zip, 1 left out\n       2 OK · 1 UNSIGNED · 1 MISMATCH · 1 FAILED\n/);
assert.match(report, new RegExp(`\\nOK         Case/disk\\.E01\\n  SHA-256  ${"a".repeat(64)}\\n  Size     300000 bytes\\n  Check    content verified — exactly the bytes bo signed\\n`), "each file: verdict, path, its full hash, size, and the check in words");
assert.match(report, /\nMISMATCH   Case\/changed\.bin\n[^]*?Check    ⚠ content does NOT match what bo signed/);
assert.match(report, /\nFAILED     Case\/cut\.bin\n[^]*?Problem  did not finish downloading/);
assert.match(report, /\nOK         unverified-name-f1\n[^]*?Name     its name did not open in its place/);
assert.match(report, /\nLeft out\n--------\nCase\/dropper\.exe — a malware sample — download it on its own\n$/);
assert.match(report, /sha256sum <file>[^]*shasum -a 256 <file>[^]*Get-FileHash <file>/, "how to check a file after unzipping, on each system");
assert.doesNotMatch(checkReport({ zipName: "x.zip", area: "a", made, lines: [], leftOut: [], detail: describeHashCheck }), /Left out/, "no Left out section when nothing was");

console.log("ok  zip-download: names made safe (no climbing out, nothing Windows refuses), unique per folder without case, the report's lines and verdicts");
