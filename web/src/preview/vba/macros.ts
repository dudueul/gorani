// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Every macro an Office file carries, wherever it keeps them (commit 42h,
 * docs/PREVIEWS.md › Macros), as one list the readers show the same way:
 *
 *   OOXML (.docm .xlsm .pptm …)   word/, xl/ or ppt/vbaProject.bin — an OLE file
 *   Word 97 (.doc)                 Macros/
 *   Excel 97 (.xls)                _VBA_PROJECT_CUR/
 *   PowerPoint 97 (.ppt)           an ExOleObjStg record in the PowerPoint
 *                                  stream: zlib, then an OLE file
 *   OpenDocument (.odt .ods .odp)  Basic/<library>/<module>.xml — StarBasic,
 *                                  as text in XML
 *
 * Pure: unit:preview-facts.
 */

import { unzlibSync } from "fflate";
import { unxml } from "../office.ts";
import { Ole } from "../ole.ts";
import type { Zip } from "../zip.ts";
import { readVba, vbaPrefix, type VbaModule, type VbaProject } from "./project.ts";

export interface Macros {
	/** "a VBA project" or "LibreOffice Basic". */
	kind: string;
	modules: VbaModule[];
	locked: boolean;
	signed: boolean;
	warnings: string[];
}

/** Macros read without letting a damaged project take the reader down:
 * on any failure, none (and the generic "Contains macros" fact stays). */
export function safely(read: () => Macros | null): Macros | null {
	try {
		return read();
	} catch {
		return null;
	}
}

const fromProject = (p: VbaProject, signed = false): Macros => ({ kind: "a VBA project", modules: p.modules, locked: p.locked, signed, warnings: p.warnings });

function merge(list: Macros[]): Macros | null {
	if (!list.length) return null;
	if (list.length === 1) return list[0]!;
	return { kind: list[0]!.kind, modules: list.flatMap((m) => m.modules), locked: list.some((m) => m.locked), signed: list.some((m) => m.signed), warnings: list.flatMap((m) => m.warnings) };
}

/** OOXML's VBA parts, and OpenDocument's Basic. */
export function macrosInZip(zip: Zip): Macros | null {
	const names = zip.names();
	const found: Macros[] = [];
	const signed = names.some((n) => /vbaProjectSignature/i.test(n));
	for (const part of names.filter((n) => /(^|\/)vbaProject\.bin$/i.test(n)).slice(0, 4)) {
		const bytes = zip.bytesOf(part, 64 * 1024 * 1024);
		const ole = bytes ? Ole.open(bytes) : null;
		const p = ole ? readVba(ole) : null;
		if (p) found.push(fromProject(p, signed));
	}
	const basic = names.filter((n) => /^Basic\/[^/]+\/[^/]+\.xml$/i.test(n) && !/script-l[cb]\.xml$|dialog-lc\.xml$/i.test(n)).slice(0, 200);
	if (basic.length) {
		const modules: VbaModule[] = [];
		for (const n of basic) {
			const xml = zip.text(n, 8 * 1024 * 1024) ?? "";
			const m = /<script:module\b[^>]*?script:name="([^"]*)"[^>]*>([\s\S]*?)<\/script:module>/.exec(xml);
			if (!m) continue;
			modules.push({ name: `${n.split("/")[1]}.${unxml(m[1]!)}`, stream: n, kind: "module", source: unxml(m[2]!).replace(/\r\n?/g, "\n"), compiled: 0, unseen: [], hidden: false, stomped: false, formText: [] });
		}
		if (modules.length) found.push({ kind: "LibreOffice Basic", modules, locked: false, signed: false, warnings: [] });
	}
	return merge(found);
}

/** Word 97's and Excel 97's VBA storages. */
export function macrosInOle(ole: Ole): Macros | null {
	const prefix = vbaPrefix(ole);
	if (prefix === null) return null;
	const p = readVba(ole, prefix);
	return p ? fromProject(p) : null;
}

/** PowerPoint 97: the VBA project is an embedded OLE object, compressed,
 * in an ExOleObjStg record of the PowerPoint Document stream. Each such
 * record is inflated (capped at its declared size) and kept if it holds
 * a VBA project. */
export function macrosInPpt(ole: Ole): Macros | null {
	const doc = ole.stream("PowerPoint Document");
	if (!doc) return null;
	const v = new DataView(doc.buffer, doc.byteOffset, doc.byteLength);
	const found: Macros[] = [];
	let records = 0;
	const walk = (start: number, end: number, depth: number) => {
		if (depth > 64) return;
		let o = start;
		while (o + 8 <= end && records++ < 2_000_000 && found.length < 4) {
			const verInst = v.getUint16(o, true);
			const type = v.getUint16(o + 2, true);
			const len = v.getUint32(o + 4, true);
			const body = o + 8;
			const next = body + len;
			if (next > end || next < body) return;
			if ((verInst & 0xf) === 0xf) walk(body, next, depth + 1);
			else if (type === 0x1011 && verInst >> 4 === 1 && len > 4) {
				const size = v.getUint32(body, true);
				if (size > 0 && size <= 64 * 1024 * 1024) {
					try {
						const inner = Ole.open(unzlibSync(doc.subarray(body + 4, next), { out: new Uint8Array(size) }));
						const p = inner ? readVba(inner) : null;
						if (p) found.push(fromProject(p));
					} catch {
						// not zlib, or not what it claims: an object, not a project
					}
				}
			}
			o = next;
		}
	};
	walk(0, doc.length, 0);
	return merge(found);
}
