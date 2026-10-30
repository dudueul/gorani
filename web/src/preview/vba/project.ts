// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A VBA project, read (commit 42h, docs/PREVIEWS.md › Macros) from
 * [MS-OVBA] — the storage every Office macro lives in, wherever the file
 * keeps it:
 *
 *   .docm .xlsm .pptm …   the part vbaProject.bin, itself an OLE file
 *   .doc                  the Macros/ storage of the Word file
 *   .xls                  _VBA_PROJECT_CUR/
 *   .ppt                  a zlib-compressed OLE object in the PowerPoint
 *                         stream (legacy/ppt.ts finds it)
 *
 * Inside: VBA/dir (compressed) lists the modules, their streams, the code
 * page; each module's stream is its COMPILED code (p-code, "the
 * performance cache") followed by its compressed SOURCE; PROJECT is the
 * text the VBA editor reads: which modules it shows, and whether a
 * password locks the project.
 *
 * What a responder needs from it, beyond the source:
 *   - a module the dir lists but PROJECT does not: hidden from the editor
 *     (a known trick — the code runs, the editor never shows it);
 *   - VBA stomping: Office runs the compiled code when its version
 *     matches, and never looks at the source — so a tool can replace the
 *     source with something harmless. The source gone (or only Attribute
 *     lines) beside real compiled code, or string literals in the compiled
 *     code that the source never mentions, give it away;
 *   - a project locked for viewing (DPB decrypts to a password hash) —
 *     locked in the editor only: the source is read here anyway.
 *
 * Pure: unit:preview-facts.
 */

import { codepageLabel, Ole } from "../ole.ts";
import { decompress, decryptValue } from "./ovba.ts";

export interface VbaModule {
	name: string;
	stream: string;
	kind: "module" | "class" | "document";
	source: string;
	/** Bytes of compiled code (p-code) before the source in its stream. */
	compiled: number;
	/** String literals in the compiled code that the source never mentions. */
	unseen: string[];
	hidden: boolean;
	/** The source is missing, or only Attribute lines, beside compiled code. */
	stomped: boolean;
	/** A form's controls: the text their properties hold (a payload's usual hiding place). */
	formText: string[];
}

export interface VbaProject {
	name: string;
	codepage: number;
	modules: VbaModule[];
	/** A password locks it in the VBA editor (the source is readable anyway). */
	locked: boolean;
	/** The project's stream names that are not the expected ones. */
	warnings: string[];
}

/** Where a file's VBA project is: the prefix of its storage, or null. */
export function vbaPrefix(ole: Ole): string | null {
	for (const p of ["", "Macros/", "_VBA_PROJECT_CUR/"]) if (ole.has(`${p}VBA/dir`)) return p;
	const any = ole.find(/(^|\/)VBA\/dir$/i)[0];
	return any ? any.replace(/VBA\/dir$/i, "") : null;
}

const MAX_MODULES = 500;

export function readVba(ole: Ole, prefix = vbaPrefix(ole) ?? ""): VbaProject | null {
	const dirStream = ole.stream(`${prefix}VBA/dir`);
	if (!dirStream) return null;
	const dir = decompress(dirStream, 4 * 1024 * 1024);
	if (!dir) return null;
	const warnings: string[] = [];
	const v = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
	let codepage = 1252;
	let name = "";
	const mods: { name: string; nameUnicode: string | null; stream: string; streamUnicode: string | null; offset: number; kind: VbaModule["kind"] }[] = [];
	let cur: (typeof mods)[number] | null = null;
	const raw = (a: number, n: number) => dir.subarray(a, Math.min(dir.length, a + n));
	const text = (a: number, n: number) => new TextDecoder(codepageLabel(codepage)).decode(raw(a, n));
	const utf16 = (a: number, n: number) => new TextDecoder("utf-16le").decode(raw(a, n));
	let at = 0;
	for (let guard = 0; at + 6 <= dir.length && guard < 20000; guard++) {
		const id = v.getUint16(at, true);
		let size = v.getUint32(at + 2, true);
		const data = at + 6;
		// PROJECTVERSION: its size field says 4, and six bytes follow.
		if (id === 0x0009) size = 6;
		if (data + size > dir.length) {
			warnings.push("its module directory is cut short");
			break;
		}
		switch (id) {
			case 0x0003:
				codepage = v.getUint16(data, true);
				break;
			case 0x0004:
				name = text(data, size);
				break;
			case 0x0019:
				if (mods.length < MAX_MODULES) {
					cur = { name: text(data, size), nameUnicode: null, stream: "", streamUnicode: null, offset: 0, kind: "module" };
					mods.push(cur);
				}
				break;
			case 0x0047:
				if (cur) cur.nameUnicode = utf16(data, size);
				break;
			case 0x001a:
				if (cur) cur.stream = text(data, size);
				break;
			case 0x0032:
				if (cur) cur.streamUnicode = utf16(data, size);
				break;
			case 0x0031:
				if (cur && size >= 4) cur.offset = v.getUint32(data, true);
				break;
			case 0x0021:
				if (cur) cur.kind = "module";
				break;
			case 0x0022:
				if (cur) cur.kind = "class";
				break;
			case 0x002b:
				cur = null;
				break;
		}
		at = data + size;
		if (id === 0x0010) break; // the directory's terminator
	}

	// PROJECT: what the editor shows, and the protection.
	const projectText = new TextDecoder(codepageLabel(codepage)).decode(ole.stream(`${prefix}PROJECT`) ?? new Uint8Array(0));
	const shown = new Set<string>();
	const documents = new Set<string>();
	let locked = false;
	for (const line of projectText.split(/\r?\n/)) {
		const m = /^(Module|Document|Class|BaseClass)=([^/\r\n]+)/.exec(line);
		if (m) {
			shown.add(m[2]!.trim().toLowerCase());
			if (m[1] === "Document") documents.add(m[2]!.trim().toLowerCase());
		}
		const dpb = /^DPB="([0-9A-Fa-f]+)"/.exec(line);
		if (dpb) {
			const d = decryptValue(dpb[1]!);
			// One zero byte: no password. Anything else: a password's hash.
			locked = !!d && !(d.length === 1 && d[0] === 0);
		}
	}
	const projectKnown = projectText.length > 0;

	const modules: VbaModule[] = [];
	for (const m of mods) {
		const streamName = m.streamUnicode || m.stream || m.name;
		const path = `${prefix}VBA/${streamName}`;
		const s = ole.stream(path);
		const displayName = m.nameUnicode || m.name;
		if (!s) {
			warnings.push(`module ${JSON.stringify(displayName)} names a stream that is not there`);
			continue;
		}
		const offset = Math.min(m.offset, s.length);
		const source = offset < s.length ? new TextDecoder(codepageLabel(codepage)).decode(decompress(s.subarray(offset)) ?? new Uint8Array(0)) : "";
		const code = source.replace(/\r\n?/g, "\n");
		const real = code.split("\n").filter((l) => l.trim() && !/^Attribute VB_/i.test(l.trim()));
		const literals = pcodeStrings(s.subarray(0, offset));
		const lower = code.toLowerCase();
		const unseen = literals.filter((x) => !lower.includes(x.toLowerCase())).slice(0, 20);
		const kind: VbaModule["kind"] = documents.has(displayName.toLowerCase()) ? "document" : m.kind;
		modules.push({
			name: displayName,
			stream: streamName,
			kind,
			source: code,
			compiled: offset,
			unseen,
			hidden: projectKnown && !shown.has(displayName.toLowerCase()),
			stomped: real.length === 0 && literals.length > 0,
			formText: kind === "class" ? formStrings(ole, prefix, displayName) : [],
		});
	}
	return { name, codepage, modules, locked, warnings };
}

/** String literals in compiled VBA: in p-code a literal is its length (two
 * bytes) and then its text, so every run of printable bytes preceded by
 * its own length is one. (Names of procedures and variables are kept in
 * the project's identifier table, not here, so what remains is what the
 * code says.) */
export function pcodeStrings(b: Uint8Array): string[] {
	const out = new Set<string>();
	for (let i = 2; i + 4 <= b.length && out.size < 200; i++) {
		const n = b[i - 2]! | (b[i - 1]! << 8);
		if (n < 4 || n > 2048 || i + n > b.length) continue;
		let ok = true;
		for (let k = 0; k < n; k++) {
			const c = b[i + k]!;
			if (c < 0x20 || c > 0x7e) {
				ok = false;
				break;
			}
		}
		if (!ok) continue;
		out.add(String.fromCharCode(...b.subarray(i, i + n)));
		i += n - 1;
	}
	return [...out];
}

/** A UserForm's controls keep their values in its "o" stream: the text in
 * it, in runs of eight or more characters. */
function formStrings(ole: Ole, prefix: string, form: string): string[] {
	const o = ole.stream(`${prefix}${form}/o`);
	if (!o) return [];
	const out: string[] = [];
	let run = "";
	for (const c of o) {
		if (c >= 0x20 && c <= 0x7e) run += String.fromCharCode(c);
		else {
			if (run.length >= 8) out.push(run);
			run = "";
		}
		if (out.length >= 30) break;
	}
	if (run.length >= 8) out.push(run);
	return out;
}
