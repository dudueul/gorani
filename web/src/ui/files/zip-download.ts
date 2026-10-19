// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Download as zip (commit 41a, docs/DOWNLOADS.md): the pure half.
 *
 * The model (model.ts › downloadZip) walks the folders, decrypts, hashes
 * and streams. What is here takes plain data and returns plain data, so a
 * unit test can pin it without a server:
 *
 *   - `safeSegment`: a decrypted name as ONE path segment that unzips the
 *     same on Windows, macOS and Linux. Names are the uploader's, and a
 *     name is any text they typed: "a/b", "..", "CON", "report?.pdf".
 *   - `ZipNames`: unique paths per folder, compared without case, because
 *     Windows and macOS folders ignore case and "A.txt" would silently
 *     overwrite "a.txt" when the zip is unpacked there.
 *   - `checkReport`: the `gorani-check.txt` that rides inside the zip. It
 *     records each file's SHA-256 as hashed in this browser and the
 *     verdict against its uploader's signed hash, plus what was left out
 *     and why.
 *
 * Why a report and not just a toast: a zip leaves the vault. Once it is on
 * someone's disk, the only record of "were these the uploaders' bytes?" is
 * what travels with it.
 */

import type { HashCheck } from "../../vault/content-hash.ts";

/** The report's name inside the zip — reserved, so no file can take it. */
export const REPORT_NAME = "gorani-check.txt";

/** Windows device names: a file named `CON` (or `con.txt`) cannot be made there. */
const DEVICE = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$/i;

/** The longest segment kept, in UTF-16 units — most file systems allow 255 bytes. */
const MAX_SEGMENT = 120;

/**
 * One safe path segment. Replaced with `_`:
 *   - `/` and `\` — they would make a name a path ("../../.bashrc");
 *   - control characters, and `< > : " | ? *` — Windows refuses them;
 *   - a trailing dot or space — Windows strips them, so two names merge.
 * `.` and `..` become `_` too, a Windows device name gets a leading `_`,
 * an empty name becomes `unnamed`, and a very long name is shortened with
 * its extension kept.
 */
export function safeSegment(name: string): string {
	let s = name.normalize("NFC").replace(/[\u0000-\u001f\u007f<>:"|?*/\\]/g, "_");
	s = s.replace(/[. ]+$/, (tail) => "_".repeat(tail.length));
	if (s === "") return "unnamed";
	if (/^[.]+$/.test(name)) return "_"; // ".", "..": never a step up
	if (DEVICE.test(s)) s = `_${s}`;
	if (s.length > MAX_SEGMENT) {
		const dot = s.lastIndexOf(".");
		const ext = dot > 0 && s.length - dot <= 16 ? s.slice(dot) : "";
		s = s.slice(0, MAX_SEGMENT - ext.length) + ext;
	}
	return s;
}

/**
 * Hands out the zip's paths: each one unique in its folder, without case.
 * A second "Report.pdf" in a folder becomes "Report (2).pdf"; a file and a
 * folder may not share a name either (a zip cannot hold both). `reserve`
 * keeps a path for something added later (the report).
 */
export class ZipNames {
	private readonly taken = new Map<string, Set<string>>();

	reserve(path: string): void {
		const at = path.lastIndexOf("/");
		this.inDir(at < 0 ? "" : path.slice(0, at)).add(fold(at < 0 ? path : path.slice(at + 1)));
	}

	/** A unique path for `name` (made safe here) inside `dir` ("" is the top). */
	claim(dir: string, name: string): string {
		const set = this.inDir(dir);
		const safe = safeSegment(name);
		let pick = safe;
		for (let n = 2; set.has(fold(pick)); n++) pick = numbered(safe, n);
		set.add(fold(pick));
		return dir ? `${dir}/${pick}` : pick;
	}

	private inDir(dir: string): Set<string> {
		let set = this.taken.get(fold(dir));
		if (!set) this.taken.set(fold(dir), (set = new Set()));
		return set;
	}
}

/** How two names compare where case is ignored (and composed alike). */
function fold(s: string): string {
	return s.normalize("NFC").toLowerCase();
}

/** "a.pdf" → "a (2).pdf"; ".env" (a dot file, no extension) → ".env (2)". */
function numbered(name: string, n: number): string {
	const dot = name.lastIndexOf(".");
	return dot > 0 ? `${name.slice(0, dot)} (${n})${name.slice(dot)}` : `${name} (${n})`;
}

/** One file that went into the zip, as the report lists it. */
export interface ZipLine {
	path: string;
	/** Bytes written — the whole file's size unless `error`. */
	size: number;
	/** SHA-256 of the bytes written, hashed in this browser. */
	sha256: string;
	/** The verdict against the uploader's signed hash; null when the file did not finish. */
	check: HashCheck | null;
	/** Why the copy in the zip is incomplete (it did not finish downloading). */
	error?: string;
	/** The name did not open in its place (a server swapped it): saved under the file's id. */
	nameUnverified?: boolean;
}

/** One file that was NOT put in the zip, and why. */
export interface LeftOut {
	path: string;
	why: string;
}

export type Verdict = "OK" | "UNSIGNED" | "MISMATCH" | "UNTRUSTED" | "INVALID" | "FAILED";

/** The one-word verdict a line opens with. Only OK means "the signer's bytes". */
export function verdictOf(line: ZipLine): Verdict {
	if (line.error || !line.check) return "FAILED";
	switch (line.check.status) {
		case "verified":
			return "OK";
		case "unsigned":
			return "UNSIGNED";
		case "mismatch":
			return "MISMATCH";
		case "untrusted":
			return "UNTRUSTED";
		case "invalid":
			return "INVALID";
	}
}

/** A line the person must look at: anything but OK and UNSIGNED. */
export function flagged(line: ZipLine): boolean {
	const v = verdictOf(line);
	return v !== "OK" && v !== "UNSIGNED";
}

/**
 * The report. Plain text, one block per file, every hash in full (a
 * reader compares it with `sha256sum` / `Get-FileHash` / `shasum -a 256`
 * after unzipping — the zip's own CRC-32 only catches accidents).
 */
export function checkReport({ zipName, area, made, lines, leftOut, detail }: { zipName: string; area: string; made: Date; lines: ZipLine[]; leftOut: LeftOut[]; detail: (c: HashCheck) => string }): string {
	const count = (v: Verdict) => lines.filter((l) => verdictOf(l) === v).length;
	const out: string[] = [];
	out.push("gorani — download check");
	out.push("=======================");
	out.push("");
	out.push(`Zip:   ${zipName}`);
	out.push(`Area:  ${area}`);
	out.push(`Made:  ${made.toISOString()}`);
	out.push(`Files: ${lines.length} in this zip, ${leftOut.length} left out`);
	const tally = (["OK", "UNSIGNED", "MISMATCH", "UNTRUSTED", "INVALID", "FAILED"] as const).filter((v) => count(v)).map((v) => `${count(v)} ${v}`);
	if (tally.length) out.push(`       ${tally.join(" · ")}`);
	out.push("");
	out.push("Each file's SHA-256 was computed in the browser that made this zip, from");
	out.push("the bytes that went into it, and checked against the hash its uploader");
	out.push("signed when they uploaded it (docs/CUSTODY.md, stage 4).");
	out.push("");
	out.push("  OK         exactly the bytes the uploader signed");
	out.push("  UNSIGNED   the uploader signed no hash (an older upload): nothing to check against");
	out.push("  MISMATCH   NOT the bytes the uploader signed — do not rely on this copy");
	out.push("  UNTRUSTED  signed, but the signer's key is not one this team trusts");
	out.push("  INVALID    the signature itself does not verify");
	out.push("  FAILED     the file did not finish downloading; the copy in the zip is incomplete");
	out.push("");
	out.push("To check a file after unzipping, hash it and compare with the line below:");
	out.push("  Linux:   sha256sum <file>      macOS: shasum -a 256 <file>");
	out.push("  Windows: Get-FileHash <file>   (PowerShell; SHA-256 is its default)");
	out.push("");
	out.push("Files");
	out.push("-----");
	if (!lines.length) out.push("(none)");
	for (const l of lines) {
		out.push("");
		out.push(`${verdictOf(l).padEnd(9)}  ${l.path}`);
		out.push(`  SHA-256  ${l.sha256}`);
		out.push(`  Size     ${l.size} bytes`);
		if (l.error) out.push(`  Problem  ${l.error}`);
		else if (l.check) out.push(`  Check    ${detail(l.check)}`);
		if (l.nameUnverified) out.push("  Name     its name did not open in its place (the server may have swapped it), so it is saved under its id");
	}
	if (leftOut.length) {
		out.push("");
		out.push("Left out");
		out.push("--------");
		for (const l of leftOut) out.push(`${l.path} — ${l.why}`);
	}
	out.push("");
	return out.join("\n");
}
