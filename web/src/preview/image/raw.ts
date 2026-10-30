// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The pictures a camera RAW file carries (commit 42d, docs/PREVIEWS.md ›
 * Images). A RAW file is the sensor's data, which takes a camera maker's
 * own knowledge to turn into a picture — and, beside it, the JPEGs the
 * camera itself made from it: a thumbnail, and usually a full-size or
 * near-full-size preview. The viewer shows the largest of those. Nothing
 * here decodes sensor data (LibRaw would be a large parser fed attacker
 * bytes, and seconds a photo).
 *
 *   TIFF-based (DNG, CR2, NEF, ARW, ORF, RW2, PEF…)  JPEGInterchangeFormat
 *       in any directory; JPEG-compressed strips in a reduced-size SubIFD;
 *       Panasonic's JpgFromRaw
 *   CR3 (ISO boxes)  the THMB box in Canon's uuid box, the PRVW box in the
 *       preview uuid box
 *   RAF (Fujifilm)   the JPEG its header points at (bytes 84 and 88)
 *   anything else    a scan for JPEG starts, each one walked (structure.ts)
 *
 * Every candidate is checked to be a JPEG a browser shows: a baseline or
 * progressive frame (a lossless one — SOF3 — is sensor data, not a
 * picture) with a size and an end. Pure: unit:preview-facts.
 */

import { jpegStructure, type ImageFormat } from "./structure.ts";
import { readTiff, num, TAG } from "./tiff.ts";

export interface Preview {
	offset: number;
	length: number;
	width: number;
	height: number;
}

const MAX_CANDIDATES = 64;
const ascii = (b: Uint8Array, at: number, n: number) => String.fromCharCode(...b.subarray(at, at + n));
const u32be = (b: Uint8Array, at: number) => ((b[at]! << 24) >>> 0) + ((b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!);

/** A JPEG at `offset`, if a browser could show it. */
function jpegAt(b: Uint8Array, offset: number, limit = b.length): Preview | null {
	if (offset < 0 || offset + 4 > limit || b[offset] !== 0xff || b[offset + 1] !== 0xd8 || b[offset + 2] !== 0xff) return null;
	const s = jpegStructure(b.subarray(0, limit), offset);
	if (s.end === null || !s.width || !s.height || s.sof === undefined || ![0, 1, 2].includes(s.sof)) return null;
	return { offset, length: s.end - offset, width: s.width, height: s.height };
}

/** Every preview, the largest first. */
export function rawPreviews(b: Uint8Array, format: ImageFormat | null): Preview[] {
	const found: Preview[] = [];
	const add = (p: Preview | null) => {
		if (p && !found.some((q) => q.offset === p.offset)) found.push(p);
	};
	if (format === "raf" && b.length > 92) add(jpegAt(b, u32be(b, 84), Math.min(b.length, u32be(b, 84) + u32be(b, 88))));
	else if (format === "cr3") cr3(b, add);
	else {
		const t = readTiff(b);
		for (const ifd of t?.ifds ?? []) {
			const off = num(ifd, TAG.JpegOffset);
			const len = num(ifd, TAG.JpegLength);
			if (off !== undefined && len) add(jpegAt(b, off, Math.min(b.length, off + len)));
			const compression = num(ifd, TAG.Compression);
			const strips = ifd.tags.get(TAG.StripOffsets);
			const counts = ifd.tags.get(TAG.StripByteCounts);
			if ((compression === 6 || compression === 7) && strips?.count === 1 && counts) add(jpegAt(b, strips.values[0]!, Math.min(b.length, strips.values[0]! + counts.values[0]!)));
			const inline = ifd.tags.get(TAG.JpgFromRaw);
			if (inline && inline.type === 7) add(jpegAt(b, inline.at, Math.min(b.length, inline.at + inline.count)));
		}
	}
	// Nothing where the format keeps them: look for JPEGs anywhere.
	if (!found.length) {
		for (let i = 0, n = 0; i + 4 < b.length && n < MAX_CANDIDATES; i++) {
			if (b[i] !== 0xff || b[i + 1] !== 0xd8 || b[i + 2] !== 0xff) continue;
			const p = jpegAt(b, i);
			n++;
			if (p && p.width >= 64 && p.height >= 64) {
				add(p);
				i = p.offset + p.length - 1;
			}
		}
	}
	return found.sort((p, q) => q.width * q.height - p.width * p.height);
}

/** Canon CR3: THMB (in moov's Canon uuid box) and PRVW (in the preview uuid box). */
function cr3(b: Uint8Array, add: (p: Preview | null) => void): void {
	const walk = (from: number, to: number, depth: number) => {
		let i = from;
		for (let n = 0; n < 4096 && i + 8 <= to; n++) {
			const size = u32be(b, i);
			const type = ascii(b, i + 4, 4);
			if (size < 8 || i + size > to) return;
			if (type === "THMB" || type === "PRVW") {
				// A few header fields (size, dimensions), then the JPEG.
				for (let j = i + 8; j < Math.min(i + 72, i + size - 3); j++) {
					if (b[j] === 0xff && b[j + 1] === 0xd8 && b[j + 2] === 0xff) {
						add(jpegAt(b, j, i + size));
						break;
					}
				}
			} else if (depth < 4 && (type === "moov" || type === "uuid")) {
				const skip = type === "uuid" ? 16 : 0;
				// The preview uuid box holds 8 bytes before its PRVW box.
				walk(i + 8 + skip, i + size, depth + 1);
				if (type === "uuid") walk(i + 8 + skip + 8, i + size, depth + 1);
			}
			i += size;
		}
	};
	walk(0, b.length, 0);
}

/** Canon CR3's metadata: its CMT1 box is a TIFF (IFD0: the camera, the
 * time) — what exifr, which does not read CR3, can read on its own. */
export function cr3Metadata(b: Uint8Array): Uint8Array[] {
	const out: Uint8Array[] = [];
	const walk = (from: number, to: number, depth: number) => {
		let i = from;
		for (let n = 0; n < 4096 && i + 8 <= to; n++) {
			const size = u32be(b, i);
			const type = ascii(b, i + 4, 4);
			if (size < 8 || i + size > to) return;
			if (type === "CMT1") out.push(b.subarray(i + 8, i + size));
			else if (depth < 3 && (type === "moov" || type === "uuid")) walk(i + 8 + (type === "uuid" ? 16 : 0), i + size, depth + 1);
			i += size;
		}
	};
	walk(0, b.length, 0);
	return out;
}
