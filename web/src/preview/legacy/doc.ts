// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Word 97–2003 (.doc, .dot) — its text and its facts, read by this file
 * (commit 42b; the format is Microsoft's [MS-DOC], published).
 *
 * A .doc is an OLE container (ole.ts) whose WordDocument stream holds the
 * text, split into "pieces" listed by a table in the 0Table/1Table stream
 * (the CLX, found through the FIB at the stream's start). Each piece is
 * either 8-bit (Windows-1252) or UTF-16. This reads the main text only —
 * headers, notes and text boxes are elsewhere — which is what a preview
 * needs; the facts come from the container:
 *
 *   Macros/VBA            a macro project
 *   ObjectPool/…          embedded objects; \x01Ole10Native names a
 *                         packaged file (often a program); Equation
 *                         Native is Equation Editor 3.0 (CVE-2017-11882)
 *   \x05SummaryInformation  who and when; its template, if it is an address
 *   field codes            DDE, INCLUDEPICTURE … (office.ts › fieldFacts)
 */

import type { Fact } from "../host.ts";
import { fieldFacts, linkFact, plural, shortUrl, some } from "../office.ts";
import { codepageLabel, Ole, propertySet, summaryWords } from "../ole.ts";
import { paragraphs, type Legacy } from "./types.ts";
import { trimNul } from "../binary/read.ts";

export function readDoc(ole: Ole): Legacy {
	const kind = "a Word 97–2003 document";
	const facts: Fact[] = [];
	const summary = propertySet(ole.stream("\u0005SummaryInformation"));
	facts.push({ level: "info", text: summaryWords(summary).join(" · ") });
	facts.push(...containerFacts(ole, summary));

	const wd = ole.stream("WordDocument");
	if (!wd || wd.length < 0x200 || (wd[0]! | (wd[1]! << 8)) !== 0xa5ec) return { kind, sections: [], facts, refused: { title: "This Word document does not open.", why: "Its text stream is missing or damaged." } };
	const v = new DataView(wd.buffer, wd.byteOffset, wd.byteLength);
	const flags = v.getUint16(0x0a, true);
	if (flags & 0x0100) {
		facts.push({ level: "warn", text: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" });
		return { kind, sections: [], facts, refused: { title: "This Word document is protected with a password.", why: "It cannot be shown here." } };
	}
	const table = ole.stream(flags & 0x0200 ? "1Table" : "0Table");
	// The FIB: a fixed base, then three arrays whose lengths it states.
	let o = 0x20;
	const csw = v.getUint16(o, true);
	o += 2 + csw * 2;
	const cslw = v.getUint16(o, true);
	const ccpText = v.getUint32(o + 2 + 12, true);
	o += 2 + cslw * 4;
	const fcLcb = o + 2;
	const fcClx = v.getUint32(fcLcb + 66 * 4, true);
	const lcbClx = v.getUint32(fcLcb + 67 * 4, true);
	if (!table || !lcbClx || fcClx + lcbClx > table.length) return { kind, sections: [], facts, refused: { title: "This Word document does not open.", why: "Its table of text pieces is missing." } };

	const raw = pieces(wd, table.subarray(fcClx, fcClx + lcbClx), ccpText);
	const { text, codes } = fields(raw);
	const links: string[] = [];
	facts.push(...fieldFacts(codes, links));
	const link = linkFact(links);
	if (link) facts.push(link);
	return { kind, sections: [{ paras: paragraphs(clean(text)) }], facts };
}

/** The main text, piece by piece, up to ccpText characters. */
function pieces(wd: Uint8Array, clx: Uint8Array, ccpText: number): string {
	const v = new DataView(clx.buffer, clx.byteOffset, clx.byteLength);
	let o = 0;
	// Skip the Prc entries (formatting) to the Pcdt (the piece table).
	while (o < clx.length && clx[o] === 0x01) o += 3 + v.getInt16(o + 1, true);
	if (clx[o] !== 0x02) return "";
	const lcb = v.getUint32(o + 1, true);
	const plc = o + 5;
	const n = Math.floor((lcb - 4) / 12);
	const cp = (i: number) => v.getUint32(plc + i * 4, true);
	const cp1252 = new TextDecoder("windows-1252");
	const utf16 = new TextDecoder("utf-16le");
	let out = "";
	for (let i = 0; i < n && out.length < ccpText; i++) {
		const start = cp(i);
		const end = Math.min(cp(i + 1), ccpText);
		if (end <= start) continue;
		const pcd = plc + (n + 1) * 4 + i * 8;
		const fc = v.getUint32(pcd + 2, true);
		const count = end - start;
		if (fc & 0x40000000) {
			// "Compressed": one byte a character, at half the offset.
			const at = (fc & 0x3fffffff) / 2;
			out += cp1252.decode(wd.subarray(at, at + count));
		} else {
			out += utf16.decode(wd.subarray(fc, fc + count * 2));
		}
		if (out.length > 4_000_000) break;
	}
	return out;
}

/** Fields are \x13 code \x14 result \x15: the result is shown, the code kept. */
function fields(raw: string): { text: string; codes: string[] } {
	const codes: string[] = [];
	const stack: { code: string; inResult: boolean }[] = [];
	let text = "";
	for (const ch of raw) {
		if (ch === "\u0013") stack.push({ code: "", inResult: false });
		else if (ch === "\u0014") {
			const top = stack.at(-1);
			if (top) top.inResult = true;
		} else if (ch === "\u0015") {
			const top = stack.pop();
			if (top?.code.trim()) codes.push(top.code.trim());
		} else {
			const top = stack.at(-1);
			if (top && !top.inResult) top.code += ch;
			else text += ch;
		}
	}
	return { text, codes };
}

/** Word's control characters, as plain text. */
function clean(t: string): string {
	return t
		.replace(/\r/g, "\n")
		// A table: each cell ends in \x07, and so does each row (one more).
		.replace(/\u0007\u0007/g, "\n")
		.replace(/\u0007/g, "\t")
		.replace(/\u000b/g, "\n")
		.replace(/\u000c/g, "\n\n")
		.replace(/\u001e/g, "-")
		.replace(/[\u0000-\u0006\u0008\u000e-\u001d\u001f]/g, "");
}

/** What the container says: macros, objects, packaged files, the template. */
export function containerFacts(ole: Ole, summary: Map<number, string | number | Date>): Fact[] {
	const facts: Fact[] = [];
	if (ole.find(/^(Macros|_VBA_PROJECT_CUR)(\/|$)/i).length) facts.push({ level: "warn", text: "Contains macros (a VBA project) — none of it was run" });
	const objects = new Set(ole.find(/^(ObjectPool|MBD[0-9A-F]+)\/[^/]+$/i).map((p) => p.split("/").slice(0, 2).join("/")));
	const pool = ole.paths.filter((p) => /^ObjectPool\/[^/]+$/i.test(p));
	const count = pool.length || objects.size;
	if (count) {
		// Each embedded object's CompObj (not the document's own, at the root).
		const classes = ole.find(/^(ObjectPool|MBD[0-9A-F]+)\/.*\u0001CompObj$/i).map((p) => progId(ole.stream(p))).filter(Boolean);
		facts.push({ level: "warn", text: `Embeds ${plural(count, "object")}${classes.length ? ` (${some(classes)})` : ""} — not opened` });
	}
	const packaged = ole.find(/\u0001Ole10Native$/).map((p) => packagedName(ole.stream(p))).filter(Boolean);
	if (packaged.length) facts.push({ level: "warn", text: `Carries packaged files: ${some(packaged.map(shortUrl))} — the double-click-to-run trick; not opened` });
	if (ole.find(/Equation Native$/i).length) facts.push({ level: "warn", text: "Has an Equation Editor 3.0 object — the way CVE-2017-11882 is exploited (not opened)" });
	const template = summary.get(7);
	if (typeof template === "string" && /^(https?:|\\\\)/i.test(template.trim())) facts.push({ level: "warn", text: `Fetches its template from ${shortUrl(template)} when opened in Word — the "template injection" trick (not fetched)` });
	return facts;
}

/** \x01CompObj: the object's ProgID ("Equation.3", "Package", "Excel.Sheet.8"). */
function progId(b: Uint8Array | null): string {
	if (!b || b.length < 32) return "";
	const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
	// Header (28 bytes), then three length-prefixed ANSI strings: the user
	// type, the clipboard format, the ProgID.
	let o = 28;
	const read = () => {
		if (o + 4 > b.length) return "";
		const n = v.getUint32(o, true);
		o += 4;
		if (n === 0 || n > 0xffff) return "";
		const s = trimNul(new TextDecoder(codepageLabel(1252)).decode(b.subarray(o, Math.min(b.length, o + n))));
		o += n;
		return s;
	};
	const userType = read();
	// The clipboard format: -1 or -2 and a number, or a string (or none).
	const marker = o + 4 <= b.length ? v.getInt32(o, true) : 0;
	if (marker === -1 || marker === -2) o += 8;
	else read();
	return (read() || userType).slice(0, 40);
}

/** \x01Ole10Native (a packaged file): its size, then its label and the path it came from. */
function packagedName(b: Uint8Array | null): string {
	if (!b || b.length < 8) return "";
	const s = new TextDecoder("windows-1252").decode(b.subarray(6, Math.min(b.length, 2048)));
	const [label, path] = s.split("\0");
	return (path && /[\\/]/.test(path) ? path : label ?? "").trim();
}
