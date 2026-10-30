// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * ALZ, ALZip's own archive (ESTsoft) — common in Korea, read by no
 * library 7-Zip or libarchive has (commit 42e, docs/PREVIEWS.md ›
 * Archives). It has no published specification; this follows unalz (the
 * reader Debian ships) and EggDotNet, and every fixture is checked with
 * unalz itself (tests/fixtures/preview/archives.py):
 *
 *   "ALZ\x01" version(2) id(2)
 *   per file "BLZ\x01":
 *     name length(2) attributes(1) DOS date and time(4)
 *     descriptor(1): bit 0 encrypted; bits 4–7 the width (1, 2, 4, 8
 *       bytes) of the two size fields — 0: no sizes (an empty entry)
 *     (1, unused)
 *     if sizes: method(1: 0 store, 1 bzip2, 2 deflate) (1) CRC-32(4)
 *       packed size(width) size(width)
 *     name (CP949 as ALZip writes it; UTF-8 if it decodes as such)
 *     if encrypted: a 12-byte ZipCrypto header, NOT counted in packed
 *     the packed data
 *   "CLZ\x01" … "CLZ\x02": the end
 *
 * Pure: unit:preview-facts.
 */

import { crc32, zipDecrypt } from "./crypto.ts";
import { decodeName, inflateTo, Refusal } from "./zip.ts";
import { MAX_ENTRIES, type Entry, type Listing } from "./types.ts";

const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
const uN = (b: Uint8Array, o: number, w: number) => (w === 1 ? b[o]! : w === 2 ? u16(b, o) : w === 4 ? u32(b, o) : u32(b, o) + u32(b, o + 4) * 2 ** 32);

const ALZ = 0x015a4c41;
const BLZ = 0x015a4c42;
const CLZ1 = 0x015a4c43;
const CLZ2 = 0x025a4c43;
const METHOD: Record<number, string> = { 0: "Store", 1: "BZip2", 2: "Deflate" };

export interface AlzItem extends Entry {
	methodId: number;
	crcValue: number;
	/** Where its 12-byte encryption header (if any), then its data, start. */
	dataAt: number;
}

export interface AlzListing extends Listing {
	items: AlzItem[];
}

export const isAlz = (b: Uint8Array) => b.length >= 8 && u32(b, 0) === ALZ;

export function listAlz(b: Uint8Array): AlzListing | null {
	if (!isAlz(b)) return null;
	const items: AlzItem[] = [];
	const warnings: string[] = [];
	let p = 8;
	let ended = false;
	while (p + 4 <= b.length && items.length < MAX_ENTRIES) {
		const sig = u32(b, p);
		if (sig === CLZ1 || sig === CLZ2) {
			ended = true;
			break;
		}
		if (sig !== BLZ) {
			warnings.push(`it has something unknown at byte ${p}: entries past it are not listed`);
			break;
		}
		const h = p + 4;
		if (h + 9 > b.length) break;
		const nameLen = u16(b, h);
		const attr = b[h + 2]!;
		const dos = u32(b, h + 3);
		const desc = b[h + 7]!;
		const width = (desc & 0xf0) >> 4;
		let q = h + 9;
		let methodId = 0;
		let crc = 0;
		let packed = 0;
		let size = 0;
		if (width) {
			if (![1, 2, 4, 8].includes(width) || q + 6 + 2 * width > b.length) {
				warnings.push("an entry's sizes cannot be read: entries past it are not listed");
				break;
			}
			methodId = b[q]!;
			crc = u32(b, q + 2);
			packed = uN(b, q + 6, width);
			size = uN(b, q + 6 + width, width);
			q += 6 + 2 * width;
		}
		const name = decodeName(b.subarray(q, q + nameLen), false).text;
		q += nameLen;
		const encrypted = (desc & 1) === 1;
		const time = dos & 0xffff;
		const date = dos >>> 16;
		const pad = (n: number) => String(n).padStart(2, "0");
		items.push({
			index: items.length,
			path: name,
			dir: (attr & 0x10) !== 0 || /[\\/]$/.test(name),
			size,
			packed,
			modified: `${1980 + (date >> 9)}-${pad((date >> 5) & 15)}-${pad(date & 31)} ${pad(time >> 11)}:${pad((time >> 5) & 63)}:${pad((time & 31) * 2)}`,
			method: METHOD[methodId] ?? `method ${methodId}`,
			encrypted,
			link: null,
			crc: crc.toString(16).toUpperCase().padStart(8, "0"),
			attributes: [attr & 1 ? "R" : "", attr & 2 ? "H" : "", attr & 4 ? "S" : "", attr & 0x10 ? "D" : "", attr & 0x20 ? "A" : ""].join("") || null,
			methodId,
			crcValue: crc,
			dataAt: q,
		});
		p = q + (encrypted ? 12 : 0) + packed;
	}
	if (!ended && !warnings.length) warnings.push("it ends early (no end record): cut off, or one part of a split archive");
	return {
		format: "ALZ (ALZip)",
		engine: "alz",
		entries: items,
		items,
		truncated: false,
		solid: false,
		headersEncrypted: false,
		encryption: items.some((i) => i.encrypted) ? "ZipCrypto" : null,
		comment: null,
		warnings,
		inner: null,
		physicalSize: b.length,
	};
}

/** bzip2 is unpacked by 7-Zip (the worker's), as a .bz2 stream. */
export type Bzip2 = (stream: Uint8Array, cap: number) => Promise<Uint8Array>;

export async function extractAlz(b: Uint8Array, item: AlzItem, password: string | null, limit: number, bzip2: Bzip2): Promise<Uint8Array> {
	if (item.dir || !item.packed) return new Uint8Array(0);
	if ((item.size ?? 0) > limit) throw new Refusal("too-big", "it is larger than the viewer opens");
	let data = b.subarray(item.dataAt + (item.encrypted ? 12 : 0), item.dataAt + (item.encrypted ? 12 : 0) + (item.packed ?? 0));
	if (item.encrypted) {
		if (password === null) throw new Refusal("password", "it is encrypted");
		const out = zipDecrypt(password, b.subarray(item.dataAt, item.dataAt + 12), data, item.crcValue >>> 24);
		if (!out) throw new Refusal("password", "the password is wrong");
		data = out;
	}
	const cap = Math.min(limit, (item.size ?? limit) + 64 * 1024);
	const out = item.methodId === 0 ? data.slice(0, cap) : item.methodId === 2 ? inflateTo(data, cap) : item.methodId === 1 ? await bzip2(data, cap) : null;
	if (!out) throw new Refusal("unsupported", `ALZ method ${item.methodId} is not one this reader knows`);
	if (crc32(out) !== item.crcValue) throw new Refusal(item.encrypted ? "password" : "damaged", item.encrypted ? "the password is wrong (its checksum does not match)" : "its checksum does not match: it is damaged");
	if (out.length !== item.size) throw new Refusal("liar", `it claims ${item.size} bytes and holds ${out.length}`);
	return out;
}
