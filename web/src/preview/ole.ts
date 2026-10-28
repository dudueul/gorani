// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * OLE compound files for the preview frame (commit 42b, docs/PREVIEWS.md).
 *
 * Before OOXML, Office saved into a "compound file binary" (CFB): a small
 * FAT filesystem inside one file, with storages (folders) and streams
 * (files). .doc, .xls, .ppt are CFB; so is HWP 5 (한글); so is an OOXML
 * file once a password is set on it (the ZIP, encrypted, as one stream).
 * What is IN the container is most of what a security team needs to know:
 *
 *   Macros/VBA, _VBA_PROJECT_CUR   a macro project
 *   ObjectPool, \x01Ole10Native    embedded objects, packaged files
 *   Equation Native                Equation Editor 3.0 (CVE-2017-11882)
 *   EncryptedPackage               a password-protected OOXML file
 *   Scripts, BinData/*.eps         한글's scripts, embedded PostScript
 *
 * Parsing is SheetJS's `cfb` (Apache-2.0); this file adds the property sets
 * (\x05SummaryInformation: title, author, dates) on top.
 */

import * as CFB from "cfb";

const MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

export class Ole {
	/** Every stream and storage, as "Folder/Name" (no "Root Entry/"). */
	readonly paths: string[];
	private entries = new Map<string, CFB.CFB$Entry>();

	private constructor(c: CFB.CFB$Container) {
		const paths: string[] = [];
		c.FullPaths.forEach((full, i) => {
			const path = full.replace(/^[^/]*\//, "").replace(/\/$/, "");
			const e = c.FileIndex[i];
			if (!path || !e) return;
			paths.push(path);
			this.entries.set(path.toLowerCase(), e);
		});
		this.paths = paths;
	}

	static is(bytes: Uint8Array): boolean {
		return bytes.length >= 512 && MAGIC.every((b, i) => bytes[i] === b);
	}

	static open(bytes: Uint8Array): Ole | null {
		if (!Ole.is(bytes)) return null;
		try {
			return new Ole(CFB.parse(bytes));
		} catch {
			return null;
		}
	}

	/** A stream's bytes (names compare case-blind, as Windows does). */
	stream(path: string): Uint8Array | null {
		const e = this.entries.get(path.toLowerCase());
		if (!e || e.type !== 2 || !e.content) return null;
		const c = e.content as Uint8Array | number[];
		return c instanceof Uint8Array ? c.subarray(0, e.size) : Uint8Array.from(c.slice(0, e.size));
	}

	has(path: string): boolean {
		return this.entries.has(path.toLowerCase());
	}

	/** Paths matching `re`. */
	find(re: RegExp): string[] {
		return this.paths.filter((p) => re.test(p));
	}

	/** The size of a stream, in bytes. */
	sizeOf(path: string): number {
		return this.entries.get(path.toLowerCase())?.size ?? 0;
	}
}

/** A Windows code page, as TextDecoder names it. */
export function codepageLabel(cp: number): string {
	const known: Record<number, string> = { 949: "euc-kr", 932: "shift_jis", 936: "gbk", 950: "big5", 65001: "utf-8", 1200: "utf-16le", 10000: "macintosh", 20127: "us-ascii", 28591: "iso-8859-1" };
	if (known[cp]) return known[cp]!;
	if (cp >= 1250 && cp <= 1258) return `windows-${cp}`;
	return "windows-1252";
}

function decoder(label: string): TextDecoder {
	try {
		return new TextDecoder(label);
	} catch {
		return new TextDecoder("windows-1252");
	}
}

/**
 * Read an OLE property set stream (MS-OLEPS) — \x05SummaryInformation,
 * \x05DocumentSummaryInformation, 한글's \x05HwpSummaryInformation — into
 * id → value. Only the kinds documents use: numbers, strings, dates.
 */
export function propertySet(b: Uint8Array | null): Map<number, string | number | Date> {
	const out = new Map<number, string | number | Date>();
	if (!b || b.length < 48) return out;
	const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
	if (v.getUint16(0, true) !== 0xfffe) return out;
	const setAt = v.getUint32(44, true);
	if (setAt + 8 > b.length) return out;
	const count = Math.min(v.getUint32(setAt + 4, true), 200);
	const props: [number, number][] = [];
	for (let i = 0; i < count; i++) {
		const at = setAt + 8 + i * 8;
		if (at + 8 > b.length) break;
		props.push([v.getUint32(at, true), setAt + v.getUint32(at + 4, true)]);
	}
	// Property 1 is the code page the 8-bit strings are in (949 for Korean Office).
	let text = decoder("windows-1252");
	const cpAt = props.find(([id]) => id === 1)?.[1];
	if (cpAt !== undefined && cpAt + 6 <= b.length && v.getUint16(cpAt, true) === 2) text = decoder(codepageLabel(v.getUint16(cpAt + 4, true)));
	const utf16 = new TextDecoder("utf-16le");
	for (const [id, at] of props) {
		if (id <= 1 || at + 8 > b.length) continue;
		const type = v.getUint16(at, true);
		try {
			if (type === 2) out.set(id, v.getInt16(at + 4, true));
			else if (type === 3) out.set(id, v.getInt32(at + 4, true));
			else if (type === 0x1e) {
				const n = Math.min(v.getUint32(at + 4, true), 4096, b.length - at - 8);
				out.set(id, text.decode(b.subarray(at + 8, at + 8 + n)).replace(/\0+$/, ""));
			} else if (type === 0x1f) {
				const n = Math.min(v.getUint32(at + 4, true) * 2, 8192, b.length - at - 8);
				out.set(id, utf16.decode(b.subarray(at + 8, at + 8 + n)).replace(/\0+$/, ""));
			} else if (type === 0x40 && at + 12 <= b.length) {
				// FILETIME: 100 ns ticks since 1601. A zero means "not set".
				const ticks = v.getUint32(at + 4, true) + v.getUint32(at + 8, true) * 2 ** 32;
				if (ticks > 0) {
					const ms = ticks / 10_000 - 11_644_473_600_000;
					// SummaryInformation's "editing time" (id 10) is a duration in the same unit.
					out.set(id, id === 10 ? Math.round(ticks / 600_000_000) : new Date(ms));
				}
			}
		} catch {
			// one unreadable property does not spoil the rest
		}
	}
	return out;
}

/** SummaryInformation, as the words a fact uses: "title …", "author …", … */
export function summaryWords(p: Map<number, string | number | Date>): string[] {
	const said: string[] = [];
	const str = (id: number) => {
		const x = p.get(id);
		return typeof x === "string" && x.trim() ? x.trim().slice(0, 80) : "";
	};
	const day = (id: number) => {
		const x = p.get(id);
		return x instanceof Date && !Number.isNaN(x.getTime()) && x.getUTCFullYear() > 1980 ? x.toISOString().slice(0, 10) : "";
	};
	if (str(2)) said.push(`title ${str(2)}`);
	if (str(4)) said.push(`author ${str(4)}`);
	if (str(8) && str(8) !== str(4)) said.push(`last saved by ${str(8)}`);
	if (day(12)) said.push(`made ${day(12)}`);
	if (day(13)) said.push(`changed ${day(13)}`);
	if (str(18)) said.push(str(18));
	return said;
}
