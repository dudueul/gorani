// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What an archive says about itself before anything in it is opened
 * (commit 42e, docs/PREVIEWS.md › Archives) — the questions a malware
 * analyst and an incident responder ask of a ZIP that arrived by mail:
 *
 *   Can anyone see in?   entries encrypted (no scanner looked inside —
 *                        the password is usually in the message), names
 *                        encrypted too; the password "infected" (how
 *                        samples are swapped)
 *   Where would it       paths that climb out of the folder they are
 *     write?             unpacked into (Zip Slip), absolute paths,
 *                        symbolic links pointing elsewhere
 *   What is inside?      programs, scripts, shortcuts; a name that
 *                        pretends (invoice.pdf.exe, a right-to-left mark);
 *                        archives inside archives; disk images (whose
 *                        files lose Windows' internet mark)
 *   Is it honest?        the same path twice, a ZIP whose local header
 *                        names an entry differently from its directory,
 *                        data after its end, a bomb's ratio, a name that
 *                        is not the format
 *
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import type { Entry, Listing } from "../archive/types.ts";
import { partRisk } from "./mail.ts";
import { plural, shortUrl, some } from "../office.ts";

export interface ArchiveFindings {
	name: string;
	listing: Listing;
	/** The password it was opened with, if any. */
	password: string | null;
	/** Symbolic links' targets, read from their tiny bodies. */
	links: Map<number, string>;
	/** ZIP: entries whose local header names them otherwise. */
	twoNames?: { central: string; local: string }[];
}

/** "infected" (any case): the convention for swapping malware samples. */
export const isSamplePassword = (p: string | null) => p !== null && p.trim().toLowerCase() === "infected";

const size = (n: number) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(1)} GB`);
const q = (s: string, n = 60) => `“${shortUrl(s).slice(0, n)}${s.length > n ? "…" : ""}”`;

/** Where a path would write: out of the folder it is unpacked into, or anywhere at all. */
export function pathRisk(path: string): "traversal" | "absolute" | null {
	const p = path.replace(/\\/g, "/");
	if (/^\/|^[A-Za-z]:|^\/\/|^~\//.test(p)) return "absolute";
	if (p.split("/").some((s) => s === "..")) return "traversal";
	return null;
}

const ARCHIVE = /\.(zip|7z|rar|tar|tgz|gz|bz2|xz|zst|cab|iso|img|vhdx?|arj|lzh|alz|egg|jar|apk|msi|dmg|wim)$/i;
const DISK = /^(ISO 9660|UDF|VHD|VHDX|VMDK|VDI|QCOW|Apple disk|FAT|NTFS|ext|disk image)/i;
const EXPECT: [RegExp, RegExp][] = [
	[/\.(zip|jar|apk|xpi|ipa|war|ear|aab)$/i, /^ZIP/],
	[/\.7z$/i, /^7z/],
	[/\.rar$/i, /^RAR/],
	[/\.(tar)$/i, /TAR/],
	[/\.(gz|tgz)$/i, /^gzip/],
	[/\.(xz|txz)$/i, /^xz/],
	[/\.(bz2|tbz2?)$/i, /^bzip2/],
	[/\.cab$/i, /^CAB/],
	[/\.iso$/i, /^(ISO|UDF)/],
	[/\.alz$/i, /^ALZ/],
	[/\.egg$/i, /^EGG/],
];

export function archiveFacts(f: ArchiveFindings): Fact[] {
	const l = f.listing;
	const facts: Fact[] = [];
	const files = l.entries.filter((e) => !e.dir);
	const folders = l.entries.length - files.length;
	const unpacked = files.reduce((s, e) => s + (e.size ?? 0), 0);
	const packed = files.reduce((s, e) => s + (e.packed ?? 0), 0) || l.physicalSize;

	// ── the summary ──
	facts.push({
		level: "info",
		text: [
			l.format + (l.inner ? ` holding ${l.inner}` : ""),
			l.headersEncrypted && !l.entries.length ? "its contents hidden" : `${plural(files.length, "file")}${folders ? ` in ${plural(folders, "folder")}` : ""}`,
			unpacked ? `${size(unpacked)} unpacked from ${size(packed)}` : "",
			l.solid ? "solid" : "",
			l.encryption ? `encrypted (${l.encryption})` : "",
		].filter(Boolean).join(" · "),
	});
	const ext = f.name.toLowerCase();
	const expected = EXPECT.find(([n]) => n.test(ext));
	if (expected && !expected[1].test(l.format)) facts.push({ level: "info", text: `Named ${ext.slice(ext.lastIndexOf("."))}, but it is ${/^[AEIOU]/i.test(l.format) ? "an" : "a"} ${l.format} archive` });

	// ── can anyone see in ──
	if (l.headersEncrypted && !l.entries.length) facts.push({ level: "warn", text: "Even its names are encrypted: nothing is listed without the password, and no scanner could look inside" });
	const encrypted = files.filter((e) => e.encrypted);
	if (encrypted.length && !isSamplePassword(f.password)) facts.push({ level: "warn", text: `${encrypted.length === files.length ? "Every entry is" : `${plural(encrypted.length, "entry is", "entries are")}`} encrypted${l.encryption ? ` (${l.encryption})` : ""} — no scanner looked inside; a lure's password is usually in the message that brought it` });
	if (isSamplePassword(f.password)) facts.push({ level: "warn", text: "Opened with the password “infected” — how malware samples are swapped: its entries are treated as samples (saved only as samples, never opened here)" });

	// ── where would it write ──
	const out = l.entries.filter((e) => pathRisk(e.path) === "traversal");
	if (out.length) facts.push({ level: "warn", text: `${plural(out.length, "path climbs", "paths climb")} out of the folder ${out.length === 1 ? "it" : "they"} would be unpacked into (“Zip Slip”): ${some(out.map((e) => q(e.path)), 3)}` });
	const absolute = l.entries.filter((e) => pathRisk(e.path) === "absolute");
	if (absolute.length) facts.push({ level: "warn", text: `${plural(absolute.length, "absolute path")}, written wherever it names: ${some(absolute.map((e) => q(e.path)), 3)}` });
	const links = l.entries.filter((e) => e.link !== null);
	if (links.length) facts.push({ level: "warn", text: `${plural(links.length, "symbolic link")}: ${some(links.map((e) => `${q(e.path, 40)}${f.links.get(e.index) ? ` → ${q(f.links.get(e.index)!, 60)}` : ""}`), 3)} — unpacked, a link can point anywhere` });

	// ── what is inside ──
	const risky = files.map((e) => ({ e, risk: partRisk(e.path.split(/[\\/]/).pop() ?? e.path, new Uint8Array(0)) })).filter((x) => x.risk);
	if (risky.length) facts.push({ level: "warn", text: `${plural(risky.length, "entry", "entries")} that run${risky.length === 1 ? "s" : ""} or pretend${risky.length === 1 ? "s" : ""}: ${some(risky.map((x) => `${q(x.e.path, 40)} (${x.risk})`), 3)}` });
	const nested = files.filter((e) => ARCHIVE.test(e.path));
	if (nested.length) facts.push({ level: "info", text: `Holds ${plural(nested.length, "archive")} of its own: ${some(nested.map((e) => q(e.path, 40)), 3)} — open each to see inside` });
	if (DISK.test(l.format)) facts.push({ level: "warn", text: "A disk image: files taken out of it do not carry Windows' downloaded-from-the-internet mark — a common way past SmartScreen" });

	// ── is it honest ──
	const seen = new Map<string, number>();
	const lower = new Map<string, string>();
	const dupes = new Set<string>();
	const caseDupes = new Set<string>();
	for (const e of l.entries) {
		const k = e.path.replace(/\\/g, "/").replace(/\/+$/, "");
		seen.set(k, (seen.get(k) ?? 0) + 1);
		if ((seen.get(k) ?? 0) > 1) dupes.add(k);
		const lk = k.toLowerCase();
		if (lower.has(lk) && lower.get(lk) !== k) caseDupes.add(k);
		lower.set(lk, k);
	}
	if (dupes.size) facts.push({ level: "warn", text: `The same path more than once: ${some([...dupes].map((d) => q(d, 40)), 3)} — which one a tool unpacks is the tool's choice` });
	if (caseDupes.size) facts.push({ level: "info", text: `Paths that differ only in case (one file on Windows and macOS): ${some([...caseDupes].map((d) => q(d, 40)), 3)}` });
	for (const t of (f.twoNames ?? []).slice(0, 3)) facts.push({ level: "warn", text: `One entry, two names: the directory says ${q(t.central, 40)}, its own header ${q(t.local, 40)} — two tools would see two different files` });
	const ratio = packed ? unpacked / packed : 0;
	if (unpacked > 4 * 1073741824) facts.push({ level: "warn", text: `It claims to unpack to ${size(unpacked)} — more than any preview opens` });
	else if (ratio >= 100 && unpacked >= 8 * 1048576) facts.push({ level: "warn", text: `It unpacks to ${size(unpacked)} from ${size(packed)} (${Math.round(ratio)}×) — a ZIP bomb's ratio` });
	for (const w of l.warnings) facts.push({ level: "warn", text: `The reader notes ${w}` });
	const azo = files.filter((e) => /AZO/.test(e.method ?? ""));
	if (azo.length) facts.push({ level: "info", text: `${plural(azo.length, "entry is", "entries are")} compressed with AZO, ESTsoft's own method — listed, not opened (no decoder here)` });
	const lea = files.filter((e) => /LEA/.test(e.method ?? ""));
	if (lea.length) facts.push({ level: "info", text: `${plural(lea.length, "entry is", "entries are")} encrypted with LEA — listed, not opened` });
	const unreadable = l.entries.filter((e) => e.undecodable);
	if (unreadable.length) facts.push({ level: "info", text: `${plural(unreadable.length, "name")} could not be decoded — listed, not opened` });
	const setuid = l.entries.filter((e) => /setuid/.test(e.attributes ?? ""));
	if (setuid.length) facts.push({ level: "warn", text: `${plural(setuid.length, "entry is", "entries are")} set-user-ID (runs as its owner, root if unpacked by root): ${some(setuid.map((e) => q(e.path, 40)), 3)}` });
	if (l.comment) facts.push({ level: "info", text: `Comment: ${q(l.comment, 90)}` });
	if (l.truncated) facts.push({ level: "info", text: `Only the first ${l.entries.length.toLocaleString("en")} entries are listed` });
	return facts;
}

/** A tree of the listing, folders first (paths as written: ".." stays ".."). */
export interface Node {
	name: string;
	/** The folder's path from the top ("" at the root). */
	path: string;
	entry: Entry | null;
	children: Map<string, Node>;
}

export function treeOf(entries: Entry[]): Node {
	const root: Node = { name: "", path: "", entry: null, children: new Map() };
	for (const e of entries) {
		const raw = e.path.replace(/\\/g, "/");
		// An absolute path keeps its "/" as a folder of its own, to be seen.
		const clean = [...(raw.startsWith("/") ? ["/"] : []), ...raw.split("/").filter((s) => s !== "" && s !== ".")];
		if (!clean.length) continue;
		let at = root;
		for (let i = 0; i < clean.length; i++) {
			const part = clean[i]!;
			const last = i === clean.length - 1;
			let next = at.children.get(part);
			if (!next || (last && !e.dir && next.entry && !next.entry.dir)) {
				// The same path twice: both are shown (the second marked by its index).
				const key = next ? `${part}\u0000${e.index}` : part;
				next = { name: part, path: at.path ? `${at.path}/${part}` : part, entry: null, children: new Map() };
				at.children.set(key, next);
			}
			if (last) next.entry = e;
			at = next;
		}
	}
	return root;
}
