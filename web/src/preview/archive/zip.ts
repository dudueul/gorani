// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * ZIP, read by our own code (commit 42e, docs/PREVIEWS.md › Archives) —
 * the archive security work meets most, and the one whose details decide
 * what a tool shows:
 *
 *   names       UTF-8 when flagged (or Info-ZIP's Unicode path field);
 *               otherwise the bytes decide — valid UTF-8, then Korean
 *               (CP949, as Korean Windows writes ZIPs), then the old DOS
 *               code page. 7-Zip's WebAssembly build has only UTF-8, and
 *               turns a Korean name into question marks
 *   two names   a local header whose name differs from the directory's:
 *               two tools, two different files — an evasion
 *   links       a Unix mode that says "symbolic link"
 *   ciphers     ZipCrypto and WinZip AES (crypto.ts); other methods are
 *               unpacked by 7-Zip (the caller's `fallback`)
 *   sizes       every entry inflated as a stream, counted, and stopped at
 *               what it claims (plus a little): a liar is caught, a bomb
 *               is never held
 *
 * Pure: unit:preview-facts.
 */

import { Inflate } from "fflate";
import { crc32, winzipAesDecrypt, zipDecrypt } from "./crypto.ts";
import { MAX_ENTRIES, type Entry, type Listing } from "./types.ts";

const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
const u64 = (b: Uint8Array, o: number) => u32(b, o) + u32(b, o + 4) * 2 ** 32;

export const METHODS: Record<number, string> = { 0: "Store", 1: "Shrink", 6: "Implode", 8: "Deflate", 9: "Deflate64", 12: "BZip2", 14: "LZMA", 19: "LZ77", 93: "Zstandard", 95: "xz", 96: "JPEG", 97: "WavPack", 98: "PPMd", 99: "AES" };

export interface ZipItem extends Entry {
	methodId: number;
	flags: number;
	crcValue: number;
	dosTime: number;
	/** Where its local header is. */
	at: number;
	/** AES: key size and the method under it. */
	aes: { bits: 128 | 192 | 256; method: number } | null;
	/** The local header's name, when it is not the directory's. */
	localName: string | null;
	/** How its name was decoded. */
	encoding: "utf-8" | "cp949" | "dos";
}

export interface ZipListing extends Listing {
	items: ZipItem[];
}

const utf8 = new TextDecoder("utf-8", { fatal: true });
const korean = new TextDecoder("euc-kr", { fatal: true });
const western = new TextDecoder("windows-1252");

/** A name's bytes as text, and how they were read. */
export function decodeName(bytes: Uint8Array, flagged: boolean): { text: string; encoding: ZipItem["encoding"] } {
	if (flagged || bytes.every((b) => b < 0x80)) return { text: new TextDecoder("utf-8").decode(bytes), encoding: "utf-8" };
	try {
		return { text: utf8.decode(bytes), encoding: "utf-8" };
	} catch {
		// not UTF-8
	}
	try {
		return { text: korean.decode(bytes), encoding: "cp949" };
	} catch {
		return { text: western.decode(bytes), encoding: "dos" };
	}
}

const dosDate = (time: number, date: number) => {
	const p = (n: number) => String(n).padStart(2, "0");
	return `${1980 + (date >> 9)}-${p((date >> 5) & 15)}-${p(date & 31)} ${p(time >> 11)}:${p((time >> 5) & 63)}:${p((time & 31) * 2)}`;
};

export function isZip(b: Uint8Array): boolean {
	return b.length >= 22 && (u32(b, 0) === 0x04034b50 || u32(b, 0) === 0x06054b50 || u32(b, 0) === 0x08074b50);
}

/** The central directory, read; null when there is none to read. */
export function listZip(b: Uint8Array): ZipListing | null {
	let eocd = -1;
	for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 0xffff); i--) {
		if (u32(b, i) === 0x06054b50) {
			eocd = i;
			break;
		}
	}
	if (eocd < 0) return null;
	let count = u16(b, eocd + 10);
	let dirAt = u32(b, eocd + 16);
	const commentLen = u16(b, eocd + 20);
	if ((count === 0xffff || dirAt === 0xffffffff) && eocd >= 20 && u32(b, eocd - 20) === 0x07064b50) {
		const z64 = u64(b, eocd - 12);
		if (z64 + 56 <= b.length && u32(b, z64) === 0x06064b50) {
			count = u64(b, z64 + 32);
			dirAt = u64(b, z64 + 48);
		}
	}
	const items: ZipItem[] = [];
	const warnings: string[] = [];
	let p = dirAt;
	const end = Math.min(eocd, b.length);
	for (let n = 0; n < count && items.length < MAX_ENTRIES; n++) {
		if (p + 46 > end || u32(b, p) !== 0x02014b50) {
			warnings.push("its directory is damaged: entries past this point are not listed");
			break;
		}
		const madeBy = u16(b, p + 4) >> 8;
		const flags = u16(b, p + 8);
		const method = u16(b, p + 10);
		const time = u16(b, p + 12);
		const date = u16(b, p + 14);
		const crc = u32(b, p + 16);
		let packed = u32(b, p + 20);
		let size = u32(b, p + 24);
		const nameLen = u16(b, p + 28);
		const extraLen = u16(b, p + 30);
		const cLen = u16(b, p + 32);
		const external = u32(b, p + 38);
		let at = u32(b, p + 42);
		const nameBytes = b.subarray(p + 46, p + 46 + nameLen);
		let { text: name, encoding } = decodeName(nameBytes, (flags & 0x800) !== 0);
		let aes: ZipItem["aes"] = null;
		for (let x = p + 46 + nameLen, xEnd = x + extraLen; x + 4 <= xEnd; ) {
			const id = u16(b, x);
			const len = u16(b, x + 2);
			const d = x + 4;
			if (id === 0x0001) {
				let q = d;
				if (size === 0xffffffff && q + 8 <= d + len) (size = u64(b, q)), (q += 8);
				if (packed === 0xffffffff && q + 8 <= d + len) (packed = u64(b, q)), (q += 8);
				if (at === 0xffffffff && q + 8 <= d + len) at = u64(b, q);
			} else if (id === 0x9901 && len >= 7) {
				const strength = b[d + 4];
				aes = { bits: strength === 1 ? 128 : strength === 2 ? 192 : 256, method: u16(b, d + 5) };
			} else if (id === 0x7075 && len > 5 && b[d] === 1 && u32(b, d + 1) === crc32(nameBytes)) {
				// Info-ZIP's Unicode path: the name in UTF-8, for this exact raw name.
				name = new TextDecoder("utf-8").decode(b.subarray(d + 5, d + len));
				encoding = "utf-8";
			}
			x = d + len;
		}
		const comment = cLen ? decodeName(b.subarray(p + 46 + nameLen + extraLen, p + 46 + nameLen + extraLen + cLen), (flags & 0x800) !== 0).text : undefined;
		const mode = madeBy === 3 ? external >>> 16 : 0;
		const isLink = (mode & 0o170000) === 0o120000;
		const dir = name.endsWith("/") || name.endsWith("\\") || (external & 0x10) !== 0 || (mode & 0o170000) === 0o040000;
		// The local header's own name (what a tool that reads front to back sees).
		let localName: string | null = null;
		if (at + 30 <= b.length && u32(b, at) === 0x04034b50) {
			const ln = u16(b, at + 26);
			const local = decodeName(b.subarray(at + 30, at + 30 + ln), (u16(b, at + 6) & 0x800) !== 0).text;
			if (local !== name && !(local === "" && ln === 0)) localName = local;
		} else warnings.push(`the entry “${name.slice(0, 60)}” points at no local header`);
		items.push({
			index: items.length,
			path: name,
			dir,
			size,
			packed,
			modified: dosDate(time, date),
			method: aes ? `AES-${aes.bits} ${METHODS[aes.method] ?? aes.method}` : (METHODS[method] ?? `method ${method}`),
			encrypted: (flags & 1) === 1,
			link: isLink ? "" : null,
			crc: crc.toString(16).toUpperCase().padStart(8, "0"),
			attributes: mode ? modeString(mode) : external & 0x10 ? "D" : null,
			comment,
			methodId: method,
			flags,
			crcValue: crc,
			dosTime: time,
			at,
			aes,
			localName,
			encoding,
		});
		p += 46 + nameLen + extraLen + cLen;
	}
	if (eocd + 22 + commentLen < b.length) warnings.push("there is data after the end of the archive");
	const first = items.reduce((m, i) => Math.min(m, i.at), Number.POSITIVE_INFINITY);
	if (items.length && first > 0 && first !== Number.POSITIVE_INFINITY) warnings.push(`there are ${first} bytes in front of the archive (a self-extracting program, or something hidden)`);
	const enc = items.find((i) => i.encrypted);
	return {
		format: "ZIP",
		engine: "zip",
		entries: items,
		items,
		truncated: count > items.length,
		solid: false,
		headersEncrypted: false,
		encryption: enc ? (enc.aes ? `AES-${enc.aes.bits}` : (enc.flags & 0x40) !== 0 ? "PKWARE strong encryption" : "ZipCrypto") : null,
		comment: commentLen ? decodeName(b.subarray(eocd + 22, eocd + 22 + commentLen), false).text : null,
		warnings,
		inner: null,
		physicalSize: b.length,
	};
}

export function modeString(mode: number): string {
	const t = (mode & 0o170000) === 0o040000 ? "d" : (mode & 0o170000) === 0o120000 ? "l" : "-";
	const rwx = (m: number) => `${m & 4 ? "r" : "-"}${m & 2 ? "w" : "-"}${m & 1 ? "x" : "-"}`;
	return `${t}${rwx(mode >> 6)}${rwx(mode >> 3)}${rwx(mode)}${mode & 0o4000 ? " setuid" : ""}`;
}

/** Why an entry was not given. */
export class Refusal extends Error {
	readonly kind: "password" | "too-big" | "liar" | "damaged" | "unsupported";
	constructor(kind: Refusal["kind"], message: string) {
		super(message);
		this.kind = kind;
	}
}

/** Raw DEFLATE, inflated as a stream and stopped past `cap`. */
export function inflateTo(data: Uint8Array, cap: number): Uint8Array {
	const chunks: Uint8Array[] = [];
	let total = 0;
	const inf = new Inflate((chunk) => {
		total += chunk.length;
		if (total > cap) throw new Refusal("liar", "it inflates past what it claims");
		chunks.push(chunk.slice());
	});
	const STEP = 64 * 1024;
	try {
		for (let i = 0; i < data.length || i === 0; i += STEP) inf.push(data.subarray(i, Math.min(data.length, i + STEP)), i + STEP >= data.length);
	} catch (e) {
		if (e instanceof Refusal) throw e;
		throw new Refusal("damaged", "its compressed data is damaged");
	}
	const out = new Uint8Array(total);
	let o = 0;
	for (const c of chunks) (out.set(c, o), (o += c.length));
	return out;
}

/** What unpacks a method our code does not have (7-Zip, in the worker). */
export type Fallback = (item: ZipItem, password: string | null) => Promise<Uint8Array>;

/**
 * One entry's bytes: decrypted with `password` if it needs one, unpacked,
 * capped at `limit`, and checked against its CRC.
 */
export async function extractZip(b: Uint8Array, item: ZipItem, password: string | null, limit: number, fallback: Fallback): Promise<Uint8Array> {
	if (item.dir) return new Uint8Array(0);
	if (item.size !== null && item.size > limit) throw new Refusal("too-big", "it is larger than the viewer opens");
	if (item.at + 30 > b.length || u32(b, item.at) !== 0x04034b50) throw new Refusal("damaged", "its local header is missing");
	const start = item.at + 30 + u16(b, item.at + 26) + u16(b, item.at + 28);
	let data = b.subarray(start, Math.min(b.length, start + (item.packed ?? 0)));
	let method = item.methodId;
	if (item.encrypted) {
		if ((item.flags & 0x40) !== 0) throw new Refusal("unsupported", "PKWARE strong encryption is not supported");
		if (password === null) throw new Refusal("password", "it is encrypted");
		if (item.aes) {
			const saltLen = item.aes.bits === 128 ? 8 : item.aes.bits === 192 ? 12 : 16;
			if (item.aes.bits === 192) throw new Refusal("unsupported", "AES-192 is not supported here");
			const out = winzipAesDecrypt(password, item.aes.bits, data.subarray(0, saltLen), data.subarray(saltLen, saltLen + 2), data.subarray(saltLen + 2, data.length - 10), data.subarray(data.length - 10));
			if (!out) throw new Refusal("password", "the password is wrong");
			data = out;
			method = item.aes.method;
		} else {
			const check = item.flags & 0x08 ? [(item.dosTime >> 8) & 0xff, item.crcValue >>> 24] : [item.crcValue >>> 24];
			const out = zipDecrypt(password, data.subarray(0, 12), data.subarray(12), check);
			if (!out) throw new Refusal("password", "the password is wrong");
			data = out;
		}
	}
	// What it claims, plus a little (a stored size can round): no more.
	const cap = Math.min(limit, (item.size ?? limit) + 64 * 1024);
	let out: Uint8Array;
	if (method === 0) out = data.slice(0, cap);
	else if (method === 8) out = inflateTo(data, cap);
	else return fallback(item, password);
	// AE-2 stores no CRC (the MAC protects it); everything else is checked.
	if (!(item.aes && item.crcValue === 0) && crc32(out) !== item.crcValue) {
		throw new Refusal(item.encrypted ? "password" : "damaged", item.encrypted ? "the password is wrong (its checksum does not match)" : "its checksum does not match: it is damaged");
	}
	if (item.size !== null && out.length !== item.size) throw new Refusal("liar", `it claims ${item.size} bytes and holds ${out.length}`);
	return out;
}
