// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * RTF — its text and its facts, read by this file (commit 42b; Microsoft's
 * RTF 1.9.1 specification).
 *
 * RTF is a lure format of choice for one reason: Word opens it, and it can
 * carry OLE objects that Word starts by itself. CVE-2017-11882 and
 * CVE-2017-0199 arrived this way — an Equation Editor or a "Package"
 * object marked \objupdate, so Word refreshes (runs) it on opening — often
 * in a file named .doc. And RTF tolerates a mess that scanners do not:
 * unclosed groups, junk control words, objects split across hex runs.
 *
 * This is a small tokenizer: groups ({ }), control words (\par, 舒),
 * control symbols (\' a byte in the document's code page), and
 * destinations. Every group feeds one place — the body, a field's code, an
 * object's class, the template, the document info — or nothing (fonts,
 * colours, styles, pictures, an object's data), and the facts are read on
 * the way past:
 *
 *   \object \objclass \objupdate \objdata   embedded objects, their class,
 *                                           whether Word updates them by itself
 *   \fldinst                                field codes (office.ts › fieldFacts)
 *   \*\template                             a template fetched on opening
 *   \info \title \author \operator          who
 */

import type { Fact } from "../host.ts";
import { fieldFacts, linkFact, plural, shortUrl } from "../office.ts";
import { codepageLabel } from "../ole.ts";
import { paragraphs, type Legacy } from "./types.ts";

type Into = "body" | "fldinst" | "objclass" | "objdata" | "template" | "info" | null;

/** Destinations whose text is not the document's (skipped whole). */
const SKIP = new Set(["fonttbl", "colortbl", "stylesheet", "listtable", "listoverridetable", "rsidtbl", "generator", "xmlnstbl", "themedata", "colorschememapping", "datastore", "latentstyles", "header", "headerl", "headerr", "headerf", "footer", "footerl", "footerr", "footerf", "footnote", "annotation", "atnid", "atnauthor", "bkmkstart", "bkmkend", "objname", "result", "pgdsctbl", "revtbl", "mmathPr", "wgrffmtfilter", "listtext", "pntext", "pntxta", "pntxtb", "shpinst", "nonshppict", "datafield", "docvar", "panose", "falt", "leveltext", "levelnumbers", "filetbl", "protusertbl", "passwordhash", "userprops", "xe", "tc"]);
/** The destinations read for facts, and where their text goes. */
const READ: Record<string, Into> = { fldinst: "fldinst", objclass: "objclass", objdata: "objdata", template: "template", info: "info" };
const INFO = new Set(["title", "author", "operator", "company", "subject"]);
const SYMBOLS: Record<string, string> = { par: "\n", line: "\n", row: "\n", sect: "\n", page: "\n", tab: "\t", cell: "\t", emdash: "—", endash: "–", bullet: "•", lquote: "‘", rquote: "’", ldblquote: "“", rdblquote: "”" };

interface Obj {
	cls: string;
	update: boolean;
	link: boolean;
	hex: number;
}

export function readRtf(bytes: Uint8Array): Legacy {
	const kind = "an RTF document";
	// RTF is 7-bit text; anything else is a byte of the code page, written \'hh.
	const src = new TextDecoder("latin1").decode(bytes.subarray(0, 64 * 1024 * 1024));
	let decoder = new TextDecoder("windows-1252");
	let body = "";
	let field = "";
	const codes: string[] = [];
	const objects: Obj[] = [];
	const info: Record<string, string> = {};
	let template = "";
	let pictures = 0;
	let unknown = 0;
	let deepest = 0;

	interface State {
		into: Into;
		uc: number;
		info?: string;
	}
	const stack: State[] = [];
	let st: State = { into: "body", uc: 1 };
	let star = false; // the last token was \* — the next word is an optional destination
	let skipChars = 0; // characters to drop after \uN (its fallback)
	let bytesOut: number[] = []; // \'hh bytes, decoded together (a Korean character is two)

	const put = (s: string) => {
		switch (st.into) {
			case "body":
				body += s;
				break;
			case "fldinst":
				field += s;
				break;
			case "objclass":
				if (objects.length) objects.at(-1)!.cls += s;
				break;
			case "template":
				template += s;
				break;
			case "info":
				if (st.info) info[st.info] = (info[st.info] ?? "") + s;
				break;
		}
	};
	const flush = () => {
		if (!bytesOut.length) return;
		put(decoder.decode(new Uint8Array(bytesOut)));
		bytesOut = [];
	};

	let i = 0;
	while (i < src.length && body.length < 4_000_000) {
		const c = src[i]!;
		if (c === "{") {
			flush();
			stack.push(st);
			st = { ...st };
			deepest = Math.max(deepest, stack.length);
			if (stack.length > 5000) break; // not a document any more
			i++;
		} else if (c === "}") {
			flush();
			const was = st;
			st = stack.pop() ?? st;
			// Leaving a field's code (nested groups inside it stay in it).
			if (was.into === "fldinst" && st.into !== "fldinst") {
				if (field.trim()) codes.push(field.trim());
				field = "";
			}
			i++;
		} else if (c === "\\" && /[a-zA-Z]/.test(src[i + 1] ?? "")) {
			let j = i + 1;
			while (j < src.length && /[a-zA-Z]/.test(src[j]!) && j - i < 40) j++;
			const word = src.slice(i + 1, j);
			const num = /^-?\d{1,10}/.exec(src.slice(j, j + 11));
			const param = num ? Number(num[0]) : null;
			if (num) j += num[0].length;
			if (src[j] === " ") j++;
			i = j;
			if (word !== "u") flush();
			if (word in READ) {
				st.into = READ[word]!;
			} else if (word === "pict") {
				pictures++;
				st.into = null;
			} else if (SKIP.has(word)) {
				st.into = null;
			} else if (star) {
				// An optional destination this reader does not know: skipped.
				unknown++;
				st.into = null;
			} else if (INFO.has(word) && st.into === "info") {
				st.info = word;
			} else if (word === "object") {
				objects.push({ cls: "", update: false, link: false, hex: 0 });
				st.into = null;
			} else if (word === "objupdate" && objects.length) objects.at(-1)!.update = true;
			else if ((word === "objlink" || word === "objautlink") && objects.length) objects.at(-1)!.link = true;
			else if (word === "ansicpg" && param) decoder = new TextDecoder(codepageLabel(param));
			else if (word === "uc") st.uc = param ?? 1;
			else if (word === "u" && param !== null) {
				flush();
				put(String.fromCharCode(param < 0 ? param + 65536 : param));
				skipChars = st.uc;
			} else if (word === "bin") i += Math.max(0, param ?? 0); // raw bytes: skipped whole
			else if (SYMBOLS[word]) put(SYMBOLS[word]!);
			star = false;
		} else if (c === "\\") {
			const n = src[i + 1] ?? "";
			if (n === "'") {
				const hex = src.slice(i + 2, i + 4);
				i += 4;
				if (skipChars > 0) skipChars--;
				else if (/^[0-9a-fA-F]{2}$/.test(hex)) bytesOut.push(parseInt(hex, 16));
				continue;
			}
			flush();
			if (n === "*") star = true;
			else if (n === "~") put(" ");
			else if (n === "_") put("-");
			else if (n === "\\" || n === "{" || n === "}") put(n);
			else if (n === "\n" || n === "\r") put("\n");
			i += 2;
		} else if (c === "\r" || c === "\n") {
			i++;
		} else {
			if (skipChars > 0) skipChars--;
			else {
				flush();
				if (st.into === "objdata") {
					if (objects.length && /[0-9a-fA-F]/.test(c)) objects.at(-1)!.hex++;
				} else put(c);
			}
			i++;
		}
	}
	flush();

	const facts: Fact[] = [];
	const said = [info.title?.trim() ? `title ${info.title.trim().slice(0, 80)}` : "", info.author?.trim() ? `author ${info.author.trim().slice(0, 80)}` : "", info.operator?.trim() && info.operator.trim() !== info.author?.trim() ? `last saved by ${info.operator.trim().slice(0, 80)}` : ""];
	facts.push({ level: "info", text: said.filter(Boolean).join(" · ") });
	for (const o of objects.slice(0, 3)) {
		const cls = o.cls.trim() || "no class named";
		const why = /^Equation\.3/i.test(cls) ? " — Equation Editor 3.0, the way CVE-2017-11882 is exploited" : /^Package/i.test(cls) ? " — a packaged file" : /htmlfile|OLE2Link|Word\.Document/i.test(cls) ? " — the kind CVE-2017-0199 used" : "";
		facts.push({ level: "warn", text: `Embeds an object (${cls}${o.hex ? `, ${Math.max(1, Math.round(o.hex / 2048))} kB` : ""})${why}${o.update ? "; marked to update by itself when Word opens the file" : ""}${o.link ? "; linked to an outside source" : ""} — not opened` });
	}
	if (objects.length > 3) facts.push({ level: "warn", text: `Embeds ${plural(objects.length, "object")} in all — not opened` });
	if (template.trim()) facts.push({ level: "warn", text: `Fetches its template from ${shortUrl(template.trim())} when opened in Word — the "template injection" trick (not fetched)` });
	const links: string[] = [];
	facts.push(...fieldFacts(codes, links));
	const link = linkFact(links);
	if (link) facts.push(link);
	if (stack.length > 1) facts.push({ level: "warn", text: `Its RTF is malformed (${plural(stack.length, "group")} never closed) — a common way to confuse scanners` });
	if (deepest > 200) facts.push({ level: "warn", text: `Nests groups ${deepest} deep — no editor writes that; it is built to confuse a reader` });
	if (unknown > 100) facts.push({ level: "info", text: `Carries ${unknown} unknown sections, skipped` });
	if (pictures) facts.push({ level: "info", text: `Has ${plural(pictures, "picture")} — not shown (text only)` });
	return { kind, sections: [{ paras: paragraphs(body) }], facts };
}
