// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a 한글 file carries besides its pages (commit 42b, docs/PREVIEWS.md ›
 * 한글), read from its structure — HWP 5's OLE container, HWPX's ZIP.
 * Pure — no DOM, no rhwp — so unit:preview-facts runs it on the fixtures
 * in Node; readers/hwp.ts adds what only rhwp knows (pages, pictures
 * linked from outside).
 *
 * The first fact is always the "who and when" line (possibly empty); the
 * reader puts the page count and version in front of it.
 */

import type { Fact } from "../host.ts";
import { linkFact, plural, shortUrl, some, unxml } from "../office.ts";
import { Ole, propertySet, summaryWords } from "../ole.ts";
import { inflateCapped, type Zip } from "../zip.ts";

/** A 한글 script stream: length-prefixed UTF-16 strings (header, source,
 * pre-source, post-source), ended by 0xFFFFFFFF. Returns the code in it,
 * without comments and empty event handlers — "" for the usual empty one. */
export function scriptSource(b: Uint8Array | null): string {
	if (!b) return "(unreadable)";
	const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
	const parts: string[] = [];
	for (let o = 0; o + 4 <= b.length && parts.length < 8; ) {
		const n = v.getUint32(o, true);
		o += 4;
		if (n === 0xffffffff || n * 2 > b.length - o) break;
		parts.push(new TextDecoder("utf-16le").decode(b.subarray(o, o + n * 2)));
		o += n * 2;
	}
	return parts
		.join("\n")
		.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "")
		.replace(/function\s+\w+\s*\([^)]*\)\s*\{\s*\}/g, "")
		.replace(/\s+/g, " ")
		.trim();
}

/** The longest run of readable UTF-16 text in a stream. */
function longestText(b: Uint8Array | null): string {
	if (!b) return "";
	const text = new TextDecoder("utf-16le").decode(b.subarray(0, Math.min(b.length, 64 * 1024) & ~1));
	return (text.match(/[\x20-\x7e\u00a0-\ud7ff]{4,}/g) ?? []).reduce((a, x) => (x.length > a.length ? x : a), "");
}

// (HWP 5 keeps a hyperlink's address with its colon escaped — "https\://…;1;0;0;".)
const URL_RE = /\b(?:https?|ftp|file)\\?:\/\/[^\s"'<>;\u0000]+/gi;
const unescape = (u: string) => u.replace(/^([a-z]+)\\:/i, "$1:");

/** HWP 5: what its OLE container holds. */
export function hwpFacts(bytes: Uint8Array): Fact[] {
	const facts: Fact[] = [{ level: "info", text: "" }];
	const ole = Ole.open(bytes);
	if (!ole) return facts; // HWP 3, or not HWP: rhwp says which
	const header = ole.stream("FileHeader");
	const flags = header && header.length >= 40 ? new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(36, true) : 0;
	facts[0] = { level: "info", text: summaryWords(propertySet(ole.stream("\u0005HwpSummaryInformation"))).join(" · ") };
	if (flags & 0x04) facts.push({ level: "info", text: "A distribution document (배포용 문서): 한글 shows it read-only and blocks copying" });
	if (flags & 0x10) facts.push({ level: "warn", text: "Under DRM — 한글 limits who may open it" });
	if (flags & 0x80) facts.push({ level: "info", text: "Signed digitally — the signature was not checked here" });
	// Every 한글 file has Scripts/DefaultJScript — usually empty. Only a
	// script with something in it is worth a warning (and is quoted).
	const raw = ole.stream("Scripts/DefaultJScript");
	const script = raw ? scriptSource(flags & 0x01 ? inflateCapped(raw, 16 * 1024 * 1024) : raw) : "";
	if (script) facts.push({ level: "warn", text: `Contains a script that 한글 can run when the document opens: “${shortUrl(script)}” — not run here` });
	const bin = ole.find(/^BinData\/[^/]+$/i).map((p) => p.split("/").pop()!);
	const eps = bin.filter((b) => /\.(eps|ps)$/i.test(b));
	if (eps.length) facts.push({ level: "warn", text: `Embeds PostScript (${some(eps)}) — the way most 한글 malware got in, through its Ghostscript; not drawn` });
	const objects = bin.filter((b) => /\.ole$/i.test(b));
	if (objects.length) facts.push({ level: "warn", text: `Embeds ${plural(objects.length, "OLE object")}: ${some(objects)} — not opened` });
	const programs = bin.filter((b) => /\.(exe|dll|scr|js|jse|vbs|vbe|wsf|hta|bat|cmd|ps1|lnk)$/i.test(b));
	if (programs.length) facts.push({ level: "warn", text: `Carries program files: ${some(programs)} — not opened` });
	// DocOptions/_LinkDoc keeps a path from the computer that saved the
	// file — often with the user's Windows name in it. Evidence, for whoever
	// asks where a document came from.
	const path = longestText(ole.stream("DocOptions/_LinkDoc"));
	if (/[\\/]/.test(path)) facts.push({ level: "info", text: `Names a path from the computer it was saved on: ${shortUrl(path)}` });
	// Hyperlinks: each keeps its address, as text, in the body's records.
	const links: string[] = [];
	for (const p of ole.find(/^BodyText\/Section\d+$/i).slice(0, 64)) {
		const raw = ole.stream(p);
		if (!raw) continue;
		const body = flags & 0x01 ? inflateCapped(raw, 64 * 1024 * 1024) : raw;
		if (!body) continue;
		const text = new TextDecoder("utf-16le").decode(body.subarray(0, body.length & ~1));
		for (const m of text.matchAll(URL_RE)) links.push(unescape(m[0]));
		if (links.length > 200) break;
	}
	const link = linkFact(links);
	if (link) facts.push(link);
	return facts;
}

/** HWPX: what its ZIP holds. */
export function hwpxFacts(zip: Zip): Fact[] {
	const hpf = zip.text("Contents/content.hpf", 4 * 1024 * 1024) ?? "";
	const meta = (name: string) => unxml(new RegExp(`<opf:meta\\b[^>]*name="${name}"[^>]*>([^<]*)<`).exec(hpf)?.[1] ?? "").trim().slice(0, 80);
	const title = unxml(/<opf:title>([^<]*)</.exec(hpf)?.[1] ?? "").trim().slice(0, 80);
	const said = [title ? `title ${title}` : "", meta("creator") ? `author ${meta("creator")}` : "", meta("lastsaveby") && meta("lastsaveby") !== meta("creator") ? `last saved by ${meta("lastsaveby")}` : "", /^\d{4}-\d\d-\d\d/.test(meta("CreatedDate")) ? `made ${meta("CreatedDate").slice(0, 10)}` : "", /^\d{4}-\d\d-\d\d/.test(meta("ModifiedDate")) ? `changed ${meta("ModifiedDate").slice(0, 10)}` : ""];
	const facts: Fact[] = [{ level: "info", text: said.filter(Boolean).join(" · ") }];
	const names = zip.names();
	const scripts = names.filter((n) => /^Scripts\/[^/]+$/i.test(n));
	if (scripts.length) facts.push({ level: "warn", text: `Contains scripts (${some(scripts.map((n) => n.split("/").pop()!))}) — 한글 can run them when the document opens; not run here` });
	const bin = names.filter((n) => /^BinData\/[^/]+$/i.test(n)).map((n) => n.split("/").pop()!);
	const eps = bin.filter((b) => /\.(eps|ps)$/i.test(b));
	if (eps.length) facts.push({ level: "warn", text: `Embeds PostScript (${some(eps)}) — the way most 한글 malware got in, through its Ghostscript; not drawn` });
	const objects = bin.filter((b) => /\.(ole|bin)$/i.test(b));
	if (objects.length) facts.push({ level: "warn", text: `Embeds ${plural(objects.length, "object")}: ${some(objects)} — not opened` });
	if (/<odf:encryption-data\b|<encryption-data\b/.test(zip.text("META-INF/manifest.xml", 1024 * 1024) ?? "")) facts.push({ level: "warn", text: "Protected with a password — mail scanners could not look inside it" });
	const links: string[] = [];
	for (const n of names.filter((x) => /^Contents\/section\d+\.xml$/i.test(x)).slice(0, 64)) {
		const xml = (zip.text(n, 64 * 1024 * 1024) ?? "").replace(/\sxmlns(?::\w+)?="[^"]*"/g, "");
		for (const m of unxml(xml).matchAll(URL_RE)) links.push(m[0]);
	}
	const link = linkFact(links.map(shortUrl));
	if (link) facts.push(link);
	return facts;
}
