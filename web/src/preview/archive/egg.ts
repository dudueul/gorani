// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * EGG, ALZip's newer archive (ESTsoft) — read from ESTsoft's published
 * "EGG Format Specification, Version 1.0" (2009–2016), cross-checked with
 * EggDotNet (MIT), commit 42e, docs/PREVIEWS.md › Archives. Little-endian
 * throughout; every header is a magic number, fixed fields, then "extra
 * fields" (magic, a flag byte — bit 0: a 4-byte size, else 2 — a size, the
 * data) until the end marker 0x08E28222:
 *
 *   EGG header   "EGGA" version(2) id(4) reserved(4); extra: split, solid,
 *                global encryption
 *   file header  0x0A8590E3 id(4) length(8); extra: filename (flags:
 *                0x04 the name is encrypted, 0x08 a code page follows —
 *                949 Korean, 932 Japanese — 0x10 a parent's id follows),
 *                comment, Windows info (FILETIME, attributes), POSIX info
 *                (mode, uid, gid, time), encryption (0 ZipCrypto: 12 bytes
 *                and a CRC; 1/2 AES-128/256: salt + check, and a 10-byte
 *                MAC — WinZip's scheme; 5/6 LEA)
 *   block header 0x02B50C13 method(1: 0 store, 1 deflate, 2 bzip2, 3 AZO,
 *                4 LZMA) hint(1) size(4) packed(4) CRC-32(4); the data
 *   a comment header after the files: the archive's comment
 *
 * Solid archives put every file header first, then the blocks of one
 * stream that holds them all, in order. AZO is ESTsoft's own method: no
 * open decoder is known whose licence allows it here, so AZO entries are
 * listed and not opened. A split archive's volume is listed alone.
 *
 * Pure: unit:preview-facts.
 */

import { crc32, winzipAesDecrypt, zipDecrypt } from "./crypto.ts";
import { decodeName, inflateTo, modeString, Refusal } from "./zip.ts";
import { MAX_ENTRIES, type Entry, type Listing } from "./types.ts";

const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
const u64 = (b: Uint8Array, o: number) => u32(b, o) + u32(b, o + 4) * 2 ** 32;

const M = {
	EGG: 0x41474745,
	END: 0x08e28222,
	FILE: 0x0a8590e3,
	BLOCK: 0x02b50c13,
	ENCRYPT: 0x08d1470f,
	FILENAME: 0x0a8591ac,
	WIN: 0x2c86950b,
	POSIX: 0x1ee922e5,
	COMMENT: 0x04c63672,
	SPLIT: 0x24f5a262,
	SOLID: 0x24e5a060,
	DUMMY: 0x07463307,
	SKIP: 0xffff0000,
	GLOBAL_ENCRYPT: 0x08d144a8,
} as const;

const METHOD: Record<number, string> = { 0: "Store", 1: "Deflate", 2: "BZip2", 3: "AZO", 4: "LZMA" };
const CIPHER: Record<number, string> = { 0: "ZipCrypto", 1: "AES-128", 2: "AES-256", 5: "LEA-128", 6: "LEA-256" };

export interface Block {
	method: number;
	size: number;
	packed: number;
	crc: number;
	at: number;
}

export interface EggItem extends Entry {
	id: number;
	blocks: Block[];
	cipher: { method: number; data: Uint8Array } | null;
	/** Its first byte in the solid stream. */
	solidAt: number;
}

export interface EggListing extends Listing {
	items: EggItem[];
	/** A solid archive's blocks (all files' data, one stream). */
	solidBlocks: Block[];
	split: boolean;
}

export const isEgg = (b: Uint8Array) => b.length >= 14 && u32(b, 0) === M.EGG;

/** One extra field at `p`: its magic, flags, data, and where the next starts. */
function field(b: Uint8Array, p: number): { magic: number; flags: number; data: Uint8Array; next: number } | null {
	if (p + 4 > b.length) return null;
	const magic = u32(b, p);
	if (magic === M.END) return { magic, flags: 0, data: b.subarray(0, 0), next: p + 4 };
	if (p + 7 > b.length) return null;
	const flags = b[p + 4]!;
	const wide = (flags & 1) === 1;
	const size = wide ? (p + 9 <= b.length ? u32(b, p + 5) : -1) : u16(b, p + 5);
	const start = p + (wide ? 9 : 7);
	if (size < 0 || start + size > b.length) return null;
	return { magic, flags, data: b.subarray(start, start + size), next: start + size };
}

const LOCALES: Record<number, string> = { 949: "euc-kr", 932: "shift_jis", 936: "gbk", 950: "big5", 1252: "windows-1252" };
const textIn = (bytes: Uint8Array, locale: number | null) => {
	if (locale === null) return new TextDecoder("utf-8").decode(bytes);
	// 0: "the system's" — ALZip's are Korean.
	try {
		return new TextDecoder(LOCALES[locale] ?? "euc-kr").decode(bytes);
	} catch {
		return decodeName(bytes, false).text;
	}
};

export function listEgg(b: Uint8Array): EggListing | null {
	if (!isEgg(b)) return null;
	const warnings: string[] = [];
	let solid = false;
	let split = false;
	let globalEncrypt = false;
	let p = 14;
	for (let n = 0; n < 64; n++) {
		const f = field(b, p);
		if (!f) return null;
		p = f.next;
		if (f.magic === M.END) break;
		if (f.magic === M.SOLID) solid = true;
		else if (f.magic === M.SPLIT) split = true;
		else if (f.magic === M.GLOBAL_ENCRYPT) globalEncrypt = true;
	}
	const items: EggItem[] = [];
	const solidBlocks: Block[] = [];
	const parents = new Map<number, number>();
	let comment: string | null = null;
	let ended = false;
	let solidAt = 0;
	while (p + 4 <= b.length && items.length < MAX_ENTRIES) {
		const magic = u32(b, p);
		if (magic === M.END) {
			ended = true;
			break;
		}
		if (magic === M.FILE) {
			if (p + 16 > b.length) break;
			const id = u32(b, p + 4);
			const length = u64(b, p + 8);
			p += 16;
			const item: EggItem = { index: items.length, path: "", dir: false, size: length, packed: 0, modified: null, method: null, encrypted: false, link: null, crc: null, attributes: null, id, blocks: [], cipher: null, solidAt };
			solidAt += length;
			for (let n = 0; n < 64; n++) {
				const f = field(b, p);
				if (!f) {
					warnings.push("a file header is cut off");
					break;
				}
				p = f.next;
				if (f.magic === M.END) break;
				const d = f.data;
				if (f.magic === M.FILENAME) {
					let q = 0;
					const locale = f.flags & 0x08 ? u16(d, q) : null;
					if (f.flags & 0x08) q += 2;
					if (f.flags & 0x10) {
						parents.set(item.index, u32(d, q));
						q += 4;
					}
					item.path = f.flags & 0x04 ? "(an encrypted name)" : textIn(d.subarray(q), locale);
					if (f.flags & 0x04) item.undecodable = true;
				} else if (f.magic === M.WIN && d.length >= 9) {
					const ft = u64(d, 0);
					item.modified = ft ? new Date(ft / 10000 - 11644473600000).toISOString().replace("T", " ").slice(0, 19) : null;
					const a = d[8]!;
					item.dir = (a & 0x80) !== 0;
					if (a & 0x08) item.link = "";
					item.attributes = [a & 1 ? "R" : "", a & 2 ? "H" : "", a & 4 ? "S" : "", a & 0x80 ? "D" : ""].join("") || null;
				} else if (f.magic === M.POSIX && d.length >= 20) {
					const mode = u32(d, 0);
					item.attributes = modeString(mode);
					if ((mode & 0o170000) === 0o120000) item.link = "";
					if ((mode & 0o170000) === 0o040000) item.dir = true;
					item.modified ??= new Date(u64(d, 12) * 1000).toISOString().replace("T", " ").slice(0, 19);
				} else if (f.magic === M.ENCRYPT && d.length >= 1) {
					item.cipher = { method: d[0]!, data: d.subarray(1) };
					item.encrypted = true;
				} else if (f.magic === M.COMMENT) {
					item.comment = textIn(d, f.flags & 0x08 ? 0 : null);
				}
			}
			items.push(item);
			continue;
		}
		if (magic === M.BLOCK) {
			if (p + 18 > b.length) break;
			const block: Block = { method: b[p + 4]!, size: u32(b, p + 6), packed: u32(b, p + 10), crc: u32(b, p + 14), at: 0 };
			p += 18;
			for (let n = 0; n < 64; n++) {
				const f = field(b, p);
				if (!f) break;
				p = f.next;
				if (f.magic === M.END) break;
			}
			block.at = p;
			p += block.packed;
			if (p > b.length) warnings.push("a block runs past the end of the file: cut off, or one part of a split archive");
			if (solid) solidBlocks.push(block);
			else items.at(-1)?.blocks.push(block);
			continue;
		}
		if (magic === M.COMMENT || magic === M.DUMMY || magic === M.SKIP) {
			const f = field(b, p);
			if (!f) break;
			if (magic === M.COMMENT) comment = textIn(f.data, f.flags & 0x08 ? 0 : null);
			p = f.next;
			continue;
		}
		warnings.push(`it has something unknown at byte ${p}: entries past it are not listed`);
		break;
	}
	if (!ended && !split && !warnings.length) warnings.push("it ends early (no end marker)");
	// Paths relative to a parent: the parent's path, then the name.
	const byId = new Map(items.map((i) => [i.id, i]));
	for (const [index, parent] of parents) {
		const chain: string[] = [];
		for (let at = byId.get(parent), n = 0; at && n < 64; at = parents.has(at.index) ? byId.get(parents.get(at.index)!) : undefined, n++) chain.unshift(at.path.replace(/[\\/]+$/, ""));
		if (chain.length) items[index]!.path = `${chain.join("/")}/${items[index]!.path}`;
	}
	for (const i of items) {
		const blocks = solid ? solidBlocks : i.blocks;
		i.packed = solid ? null : i.blocks.reduce((s, x) => s + x.packed, 0);
		i.method = blocks.length ? [...new Set(blocks.map((x) => METHOD[x.method] ?? `method ${x.method}`))].join(", ") : i.dir ? null : "Store";
		if (i.cipher) i.method = `${CIPHER[i.cipher.method] ?? `cipher ${i.cipher.method}`} ${i.method ?? ""}`.trim();
		i.crc = !solid && i.blocks.length === 1 ? i.blocks[0]!.crc.toString(16).toUpperCase().padStart(8, "0") : null;
		if (/[\\/]$/.test(i.path)) i.dir = true;
	}
	if (globalEncrypt) warnings.push("it uses global encryption, which this reader does not open");
	const enc = items.find((i) => i.cipher);
	return {
		format: `EGG (ALZip)${split ? ", one part of a split archive" : ""}`,
		engine: "egg",
		entries: items,
		items,
		truncated: false,
		solid,
		headersEncrypted: false,
		encryption: enc ? (CIPHER[enc.cipher!.method] ?? "encrypted") : null,
		comment,
		warnings,
		inner: null,
		physicalSize: b.length,
		solidBlocks,
		split,
	};
}

/** bzip2 and LZMA are unpacked by 7-Zip in the worker. */
export interface Unpackers {
	bzip2(stream: Uint8Array, cap: number): Promise<Uint8Array>;
	lzma(props: Uint8Array, data: Uint8Array, size: number, cap: number): Promise<Uint8Array>;
}

function decrypt(item: EggItem, data: Uint8Array, crc: number, password: string | null): Uint8Array {
	const c = item.cipher;
	if (!c) return data;
	if (password === null) throw new Refusal("password", "it is encrypted");
	if (c.method === 0) {
		const out = zipDecrypt(password, c.data.subarray(0, 12), data, [c.data[15] ?? crc >>> 24, crc >>> 24]);
		if (!out) throw new Refusal("password", "the password is wrong");
		return out;
	}
	if (c.method === 1 || c.method === 2) {
		const bits = c.method === 1 ? 128 : 256;
		const s = bits === 128 ? 8 : 16;
		const out = winzipAesDecrypt(password, bits, c.data.subarray(0, s), c.data.subarray(s, s + 2), data, c.data.subarray(s + 2, s + 12));
		if (!out) throw new Refusal("password", "the password is wrong");
		return out;
	}
	throw new Refusal("unsupported", `${CIPHER[c.method] ?? "this cipher"} is not supported here (LEA is a Korean national cipher no library here has)`);
}

async function unpack(b: Uint8Array, block: Block, item: EggItem, password: string | null, cap: number, u: Unpackers): Promise<Uint8Array> {
	if (block.size > cap) throw new Refusal("too-big", "it is larger than the viewer opens");
	const raw = decrypt(item, b.subarray(block.at, block.at + block.packed), block.crc, password);
	const limit = Math.min(cap, block.size + 64 * 1024);
	let out: Uint8Array;
	if (block.method === 0) out = raw.slice(0, limit);
	else if (block.method === 1) out = inflateTo(raw, limit);
	else if (block.method === 2) out = await u.bzip2(raw, limit);
	else if (block.method === 4) out = await u.lzma(raw.subarray(4, 9), raw.subarray(9), block.size, limit); // after 4 bytes ZIP-style (version, properties' size): the 5 LZMA properties
	else if (block.method === 3) throw new Refusal("unsupported", "it is compressed with AZO, ESTsoft's own method: no decoder here");
	else throw new Refusal("unsupported", `EGG method ${block.method} is not one this reader knows`);
	if (crc32(out) !== block.crc) throw new Refusal(item.cipher ? "password" : "damaged", item.cipher ? "the password is wrong (its checksum does not match)" : "its checksum does not match: it is damaged");
	if (out.length !== block.size) throw new Refusal("liar", `a block claims ${block.size} bytes and holds ${out.length}`);
	return out;
}

export async function extractEgg(b: Uint8Array, l: EggListing, item: EggItem, password: string | null, limit: number, u: Unpackers): Promise<Uint8Array> {
	if (item.dir || !item.size) return new Uint8Array(0);
	if (item.size > limit) throw new Refusal("too-big", "it is larger than the viewer opens");
	if (l.split) throw new Refusal("unsupported", "it is one part of a split archive: its data may be in the other parts");
	const parts: Uint8Array[] = [];
	if (l.solid) {
		// One stream for every file: unpacked up to this one's end, then cut.
		const want = item.solidAt + item.size;
		if (want > limit * 4) throw new Refusal("too-big", "it is too far into a solid archive to unpack here");
		let have = 0;
		for (const block of l.solidBlocks) {
			if (have >= want) break;
			const owner = l.items.find((i) => i.cipher) ?? item;
			const out = await unpack(b, block, owner, password, limit * 4, u);
			parts.push(out);
			have += out.length;
		}
		const all = concat(parts);
		return all.slice(item.solidAt, want);
	}
	for (const block of item.blocks) parts.push(await unpack(b, block, item, password, limit, u));
	const out = concat(parts);
	if (out.length !== item.size) throw new Refusal("liar", `it claims ${item.size} bytes and holds ${out.length}`);
	return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
	if (parts.length === 1) return parts[0]!;
	const out = new Uint8Array(parts.reduce((s, x) => s + x.length, 0));
	let o = 0;
	for (const x of parts) (out.set(x, o), (o += x.length));
	return out;
}
