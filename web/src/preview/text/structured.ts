// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Structured text, read with limits (commit 42f, docs/PREVIEWS.md › Text):
 *
 *   JSON    its nesting is counted BEFORE it is parsed (a file of a million
 *           "[" is a stack exhausted); JSON Lines read line by line
 *   XML     a DOCTYPE that declares entities (the "billion laughs") or
 *           points at an outside DTD (XXE: the classic way an XML parser
 *           reads a file it should not, or calls out) is not parsed —
 *           the source is shown and the fact says why
 *   what    a file's kind and its highlighting language, by its name and,
 *           failing that, its first characters
 *
 * Pure: unit:preview-facts.
 */

export type TextKind = "markdown" | "json" | "jsonl" | "xml" | "html" | "code";

export const MAX_DEPTH = 512;

/** How deep its arrays and objects nest, strings skipped. */
export function jsonDepth(text: string): number {
	let depth = 0;
	let max = 0;
	let inStr = false;
	for (let i = 0; i < text.length; i++) {
		const c = text.charCodeAt(i);
		if (inStr) {
			if (c === 92) i++; // backslash: the next character is escaped
			else if (c === 34) inStr = false;
			continue;
		}
		if (c === 34) inStr = true;
		else if (c === 91 || c === 123) {
			if (++depth > max) max = depth;
			if (max > MAX_DEPTH) return max;
		} else if (c === 93 || c === 125) depth--;
	}
	return max;
}

export function parseJson(text: string): { value: unknown } | { error: string } {
	const depth = jsonDepth(text);
	if (depth > MAX_DEPTH) return { error: `it nests deeper than ${MAX_DEPTH} levels — not parsed` };
	try {
		return { value: JSON.parse(text.replace(/^﻿/, "")) };
	} catch (e) {
		return { error: e instanceof Error ? e.message.slice(0, 200) : "it is not valid JSON" };
	}
}

/** JSON Lines: one value a line (up to 100,000), and the lines that are not JSON. */
export function parseJsonLines(text: string): { values: unknown[]; bad: number } {
	const values: unknown[] = [];
	let bad = 0;
	for (const line of text.split(/\r?\n/)) {
		if (!line.trim()) continue;
		if (values.length >= 100_000) break;
		const r = parseJson(line);
		if ("value" in r) values.push(r.value);
		else bad++;
	}
	return { values, bad };
}

export interface XmlDanger {
	entities: boolean;
	/** The outside DTD or entity it points at (SYSTEM/PUBLIC). */
	external: string | null;
	xinclude: boolean;
	/** Code inside an XSLT stylesheet (msxsl:script). */
	xslScript: boolean;
}

export function xmlDanger(text: string): XmlDanger {
	const head = text.slice(0, 512 * 1024);
	const doctype = /<!DOCTYPE[\s\S]*?(?:\]\s*>|>)/i.exec(head)?.[0] ?? "";
	const external = /\b(?:SYSTEM|PUBLIC\s+"[^"]*")\s+["']([^"']+)["']/i.exec(doctype)?.[1] ?? /<!ENTITY\s+%?\s*\w+\s+(?:SYSTEM|PUBLIC)\s+["']([^"']+)["']/i.exec(head)?.[1] ?? null;
	return {
		entities: /<!ENTITY/i.test(head),
		external,
		xinclude: /<(?:\w+:)?include\b[^>]*\bhref=/i.test(head) && /XInclude/i.test(head),
		xslScript: /<(?:msxsl|xsl):script\b/i.test(head),
	};
}

/** Extensions to highlight.js languages (the ones bundled). */
export const LANGUAGES: Record<string, string> = {
	md: "markdown", markdown: "markdown", mdx: "markdown",
	json: "json", jsonl: "json", ndjson: "json", geojson: "json", har: "json", ipynb: "json", webmanifest: "json",
	xml: "xml", xsd: "xml", xsl: "xml", xslt: "xml", plist: "xml", rss: "xml", atom: "xml", csproj: "xml", vbproj: "xml", vcxproj: "xml", resx: "xml", config: "xml", manifest: "xml", wsf: "xml", sct: "xml", html: "xml", htm: "xml", xhtml: "xml", hta: "xml", svg: "xml",
	js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript", jse: "javascript", ts: "typescript", tsx: "typescript", mts: "typescript", cts: "typescript",
	py: "python", pyw: "python", sh: "bash", bash: "bash", zsh: "bash", ksh: "bash", command: "bash",
	ps1: "powershell", psm1: "powershell", psd1: "powershell", bat: "dos", cmd: "dos", vbs: "vbscript", vbe: "vbscript", vba: "vbscript", bas: "vbscript", cls: "vbscript", frm: "vbscript",
	css: "css", scss: "scss", less: "less", yaml: "yaml", yml: "yaml", toml: "ini", ini: "ini", cfg: "ini", conf: "ini", inf: "ini", reg: "ini", properties: "properties", env: "bash",
	sql: "sql", c: "c", h: "c", cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp", cs: "csharp", java: "java", kt: "kotlin", kts: "kotlin", swift: "swift", go: "go", rs: "rust",
	php: "php", phtml: "php", rb: "ruby", pl: "perl", pm: "perl", lua: "lua", r: "r", scala: "scala", groovy: "groovy", gradle: "groovy", dart: "dart", m: "objectivec", mm: "objectivec",
	dockerfile: "dockerfile", makefile: "makefile", mk: "makefile", diff: "diff", patch: "diff", yar: "plaintext", yara: "plaintext", ahk: "autohotkey", au3: "plaintext", nim: "nim", asm: "x86asm", s: "x86asm",
};

/** What a text file is, from its name (and, for a bare name, its start). */
export function textKind(name: string, text: string): { kind: TextKind; language: string } {
	const lower = name.toLowerCase();
	const base = lower.split(/[\\/]/).pop() ?? lower;
	const ext = base.includes(".") ? base.split(".").pop()! : base;
	const language = LANGUAGES[ext] ?? (base === "dockerfile" ? "dockerfile" : base === "makefile" ? "makefile" : "");
	if (language === "markdown") return { kind: "markdown", language };
	if (/^(jsonl|ndjson)$/.test(ext)) return { kind: "jsonl", language: "json" };
	if (language === "json") return { kind: "json", language };
	if (/^(html?|xhtml|hta)$/.test(ext)) return { kind: "html", language: "xml" };
	if (language === "xml") return { kind: "xml", language };
	if (language) return { kind: "code", language };
	const start = text.replace(/^﻿/, "").trimStart().slice(0, 200);
	if (/^[[{]/.test(start)) return { kind: "json", language: "json" };
	if (/^<\?xml|^<[a-zA-Z][\w:-]*[\s>]/.test(start)) return /^<!doctype html|^<html/i.test(start) ? { kind: "html", language: "xml" } : { kind: "xml", language: "xml" };
	if (/^#!.*\b(?:ba|z|k|da)?sh\b/.test(start)) return { kind: "code", language: "bash" };
	if (/^#!.*\bpython/.test(start)) return { kind: "code", language: "python" };
	return { kind: "code", language: "plaintext" };
}

/** A text file's bytes as text: its BOM, or UTF-8 if it is, else Korean
 * (CP949), else Western — and which. */
export function decodeText(b: Uint8Array): { text: string; encoding: string } {
	if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return { text: new TextDecoder("utf-8").decode(b.subarray(3)), encoding: "UTF-8 (with BOM)" };
	if (b[0] === 0xff && b[1] === 0xfe) return { text: new TextDecoder("utf-16le").decode(b.subarray(2)), encoding: "UTF-16 LE" };
	if (b[0] === 0xfe && b[1] === 0xff) return { text: new TextDecoder("utf-16be").decode(b.subarray(2)), encoding: "UTF-16 BE" };
	try {
		return { text: new TextDecoder("utf-8", { fatal: true }).decode(b), encoding: "UTF-8" };
	} catch {
		// not UTF-8
	}
	try {
		return { text: new TextDecoder("euc-kr", { fatal: true }).decode(b), encoding: "Korean (CP949)" };
	} catch {
		return { text: new TextDecoder("windows-1252").decode(b), encoding: "Western (Windows-1252)" };
	}
}
