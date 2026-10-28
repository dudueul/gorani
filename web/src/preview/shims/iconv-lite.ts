// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * iconv-lite, as far as msgreader needs it in the preview frame (commit
 * 42c): decoding an Outlook file's 8-bit strings in their code page. The
 * real package is built on Node's Buffer; the browser's TextDecoder knows
 * the same code pages. scripts/build-readers.mjs points `iconv-lite` here
 * for the frame's bundles; Node (the unit tests) uses the real one.
 */

const ALIASES: Record<string, string> = { binary: "latin1", ascii: "us-ascii", ucs2: "utf-16le", utf16le: "utf-16le", "utf-16": "utf-16le", cp949: "euc-kr", ks_c_5601: "euc-kr", "ks_c_5601-1987": "euc-kr", cp932: "shift_jis", cp936: "gbk", cp950: "big5" };

function label(encoding: string): string {
	const e = encoding.trim().toLowerCase();
	if (ALIASES[e]) return ALIASES[e]!;
	const cp = /^(?:cp|windows-?)(\d{3,5})$/.exec(e);
	if (cp) return `windows-${cp[1]}`;
	return e;
}

export function decode(bytes: Uint8Array, encoding: string): string {
	try {
		return new TextDecoder(label(encoding)).decode(bytes);
	} catch {
		return new TextDecoder("windows-1252").decode(bytes);
	}
}

export function encode(): never {
	throw new Error("the preview frame writes no Outlook files");
}

export function encodingExists(encoding: string): boolean {
	try {
		new TextDecoder(label(encoding));
		return true;
	} catch {
		return false;
	}
}

export default { decode, encode, encodingExists };
