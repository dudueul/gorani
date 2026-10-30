// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * TIFF directories, read with suspicion (commit 42d, docs/PREVIEWS.md ›
 * Images). TIFF is the skeleton of more formats than its own: a DNG, and
 * most cameras' RAW files (Canon's CR2, Nikon's NEF, Sony's ARW,
 * Olympus's ORF, Panasonic's RW2, Pentax's PEF…) are TIFF directories
 * ("IFDs") pointing at the sensor data and at the JPEG previews the
 * camera made. The RAW reader (raw.ts) and the TIFF facts walk them here.
 *
 * Every number in a TIFF is an offset someone wrote. So: every offset is
 * checked against the file, a directory is read once (a loop of IFDs
 * pointing at each other is the oldest trick), at most 64 directories and
 * 1000 entries each, and numeric values are kept only up to 64 per tag.
 * Pure: unit:preview-facts runs it on the fixtures in Node.
 */

export interface Tag {
	type: number;
	count: number;
	/** Where the value's bytes are (inline in the entry, or pointed at). */
	at: number;
	/** Numbers (SHORT, LONG, RATIONAL as a/b…), the first 64. */
	values: number[];
	/** ASCII text. */
	text?: string;
}

export interface Ifd {
	offset: number;
	tags: Map<number, Tag>;
	/** Found as a SubIFD of another (a RAW file's sensor data and previews). */
	sub: boolean;
}

export interface Tiff {
	little: boolean;
	/** The magic number: 42 for TIFF; 0x4F52 / 0x5352 Olympus; 0x55 Panasonic. */
	magic: number;
	ifds: Ifd[];
}

const SIZES: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4 };
const MAX_IFDS = 64;
const MAX_ENTRIES = 1000;

export const TAG = {
	NewSubfileType: 0x00fe,
	ImageWidth: 0x0100,
	ImageLength: 0x0101,
	Compression: 0x0103,
	Photometric: 0x0106,
	Make: 0x010f,
	Model: 0x0110,
	StripOffsets: 0x0111,
	Orientation: 0x0112,
	StripByteCounts: 0x0117,
	SubIFDs: 0x014a,
	JpegOffset: 0x0201,
	JpegLength: 0x0202,
	ExifIFD: 0x8769,
	DNGVersion: 0xc612,
	/** Panasonic RW2: the JPEG preview, inline as UNDEFINED bytes. */
	JpgFromRaw: 0x002e,
} as const;

/** The TIFF at `base` in `b` (a whole file, or the TIFF inside an EXIF
 * block), or null if it is not one. */
export function readTiff(b: Uint8Array, base = 0): Tiff | null {
	if (b.length < base + 8) return null;
	const order = String.fromCharCode(b[base]!, b[base + 1]!);
	if (order !== "II" && order !== "MM") return null;
	const little = order === "II";
	const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
	const u16 = (at: number) => v.getUint16(at, little);
	const u32 = (at: number) => v.getUint32(at, little);
	const magic = u16(base + 2);
	if (magic !== 42 && magic !== 0x4f52 && magic !== 0x5352 && magic !== 0x55) return null;

	const seen = new Set<number>();
	const ifds: Ifd[] = [];
	const inFile = (at: number, len: number) => at >= 0 && len >= 0 && at + len <= b.length;

	const readIfd = (rel: number, sub: boolean): Ifd | null => {
		const at = base + rel;
		if (rel === 0 || seen.has(at) || ifds.length >= MAX_IFDS || !inFile(at, 2)) return null;
		seen.add(at);
		const n = u16(at);
		if (n === 0 || n > MAX_ENTRIES || !inFile(at + 2, n * 12 + 4)) return null;
		const tags = new Map<number, Tag>();
		for (let i = 0; i < n; i++) {
			const e = at + 2 + i * 12;
			const tag = u16(e);
			const type = u16(e + 2);
			const count = u32(e + 4);
			const size = SIZES[type];
			if (!size || count > 0x10000000) continue;
			const bytes = size * count;
			const where = bytes <= 4 ? e + 8 : base + u32(e + 8);
			if (!inFile(where, Math.min(bytes, b.length))) continue;
			const values: number[] = [];
			const k = Math.min(count, 64);
			for (let j = 0; j < k && inFile(where + j * size, size); j++) {
				const p = where + j * size;
				if (type === 3 || type === 8) values.push(type === 8 ? v.getInt16(p, little) : u16(p));
				else if (type === 4 || type === 13) values.push(u32(p));
				else if (type === 9) values.push(v.getInt32(p, little));
				else if (type === 5) values.push(u32(p) / (u32(p + 4) || 1));
				else if (type === 10) values.push(v.getInt32(p, little) / (v.getInt32(p + 4, little) || 1));
				else if (type === 1 || type === 6 || type === 7) values.push(b[p]!);
			}
			const t: Tag = { type, count, at: where, values };
			if (type === 2) t.text = new TextDecoder("latin1").decode(b.subarray(where, where + Math.min(count, 4096))).replace(/\0[\s\S]*$/, "");
			tags.set(tag, t);
		}
		const ifd = { offset: at, tags, sub };
		ifds.push(ifd);
		// SubIFDs: a RAW file's sensor image and previews hang here.
		for (const off of tags.get(TAG.SubIFDs)?.values ?? []) readIfd(off, true);
		const next = u32(at + 2 + n * 12);
		if (!sub) readIfd(next, false);
		return ifd;
	};
	readIfd(u32(base + 4), false);
	return ifds.length ? { little, magic, ifds } : null;
}

export const num = (ifd: Ifd, tag: number): number | undefined => ifd.tags.get(tag)?.values[0];
export const text = (ifd: Ifd, tag: number): string | undefined => ifd.tags.get(tag)?.text;
