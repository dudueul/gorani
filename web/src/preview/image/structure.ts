// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a picture's bytes are, and how they are put together (commit 42d,
 * docs/PREVIEWS.md › Images) — read by walking each format's own
 * structure, never by decoding it:
 *
 *   sniffImage    the format, from the first bytes (the name only breaks
 *                 ties: a TIFF named .nef is a Nikon RAW)
 *   structureOf   the size it DECLARES (checked before anything decodes
 *                 it: 60000×60000 pixels fit in 70 bytes), its frames,
 *                 its comments and text chunks, the blocks that carry
 *                 metadata — and where the picture really ENDS, so that
 *                 what comes after it can be named: a ZIP (a polyglot), a
 *                 program, a phone's motion-photo video
 *
 * Bounded everywhere (segments, chunks, boxes, text), and pure:
 * unit:preview-facts runs it on the fixtures in Node.
 */

import { unzlibSync } from "fflate";
import { readTiff, num, TAG } from "./tiff.ts";

export type ImageFormat =
	| "jpeg" | "png" | "gif" | "webp" | "avif" | "heic" | "bmp" | "ico" | "tiff" | "svg" | "svgz"
	| "dng" | "cr2" | "nef" | "arw" | "orf" | "rw2" | "pef" | "raw" | "cr3" | "raf"
	| "jxl" | "psd" | "jp2";

export interface Sniffed {
	format: ImageFormat | null;
	/** What it is, said plainly ("a JPEG photo", "a Nikon RAW file"). */
	label: string;
	/** Drawn by the browser itself (as an <img>, in the frame). */
	native: boolean;
	/** The mime the frame's <img> gets (native formats only). */
	mime: string | null;
	/** When it is not a picture at all: what it is. */
	other?: string;
}

/** Above this, nothing is drawn: 220 megapixels is more than any phone or
 * camera makes (a 200 MP phone photo is 16320×12240). */
export const MAX_PIXELS = 220_000_000;
/** Pictures our own decoders (TIFF, HEIF) draw: each pixel is 4 bytes in
 * memory, so 100 MP is 400 MB already. */
export const MAX_DECODED_PIXELS = 100_000_000;

/** Camera RAW formats, by extension: a TIFF named like one is one. */
export const RAW_EXTENSIONS = /^(dng|cr2|cr3|nef|nrw|arw|srf|sr2|orf|rw2|raw|rwl|pef|srw|raf|3fr|erf|kdc|dcr|mos|iiq|mef|x3f)$/;

const LABEL: Record<ImageFormat, string> = {
	jpeg: "a JPEG picture", png: "a PNG picture", gif: "a GIF picture", webp: "a WebP picture", avif: "an AVIF picture",
	heic: "a HEIF picture (HEIC)", bmp: "a BMP picture", ico: "an icon", tiff: "a TIFF picture", svg: "an SVG drawing", svgz: "a compressed SVG drawing",
	dng: "a DNG RAW file", cr2: "a Canon RAW file (CR2)", nef: "a Nikon RAW file (NEF)", arw: "a Sony RAW file (ARW)", orf: "an Olympus RAW file (ORF)",
	rw2: "a Panasonic RAW file (RW2)", pef: "a Pentax RAW file (PEF)", raw: "a camera RAW file", cr3: "a Canon RAW file (CR3)", raf: "a Fujifilm RAW file (RAF)",
	jxl: "a JPEG XL picture", psd: "a Photoshop document", jp2: "a JPEG 2000 picture",
};

const MIME: Partial<Record<ImageFormat, string>> = { jpeg: "image/jpeg", png: "image/png", gif: "image/gif", webp: "image/webp", avif: "image/avif", bmp: "image/bmp", ico: "image/x-icon", svg: "image/svg+xml", svgz: "image/svg+xml" };

const ascii = (b: Uint8Array, at: number, n: number) => String.fromCharCode(...b.subarray(at, at + n));
const u16be = (b: Uint8Array, at: number) => (b[at]! << 8) | b[at + 1]!;
const u32be = (b: Uint8Array, at: number) => ((b[at]! << 24) >>> 0) + ((b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!);
const u16le = (b: Uint8Array, at: number) => b[at]! | (b[at + 1]! << 8);
const u32le = (b: Uint8Array, at: number) => (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16)) + ((b[at + 3]! << 24) >>> 0);

/** Not a picture: what else the first bytes might be (a disguise). */
export function otherKind(b: Uint8Array): string | null {
	const a = ascii(b, 0, 8);
	if (a.startsWith("%PDF-")) return "a PDF";
	if (a.startsWith("PK\x03\x04")) return "a ZIP archive (or an Office document)";
	if (a.startsWith("Rar!")) return "a RAR archive";
	if (a.startsWith("7z\xbc\xaf")) return "a 7-Zip archive";
	if (b[0] === 0x1f && b[1] === 0x8b) return "a gzip archive";
	if (a.startsWith("MZ")) return "a Windows program";
	if (a.startsWith("\x7fELF")) return "a Linux program";
	if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return "an Office 97–2003 document";
	if (b.length > 8 && ascii(b, 4, 4) === "ftyp" && /^(isom|mp4|M4V|qt|avc1|iso)/.test(ascii(b, 8, 4))) return "a video";
	const head = new TextDecoder("utf-8", { fatal: false }).decode(b.subarray(0, 1024)).replace(/^\ufeff/, "").trimStart().toLowerCase();
	if (/^<\?php/.test(head)) return "a PHP script";
	if (/^(<!doctype html|<html|<head|<body|<script|<iframe)/.test(head)) return "a web page";
	return null;
}

export function sniffImage(b: Uint8Array, name = ""): Sniffed {
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	const is = (format: ImageFormat): Sniffed => ({ format, label: LABEL[format], native: !!MIME[format], mime: MIME[format] ?? null });
	const a = ascii(b, 0, 16);
	if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return is("jpeg");
	if (a.startsWith("\x89PNG\r\n\x1a\n")) return is("png");
	if (a.startsWith("GIF87a") || a.startsWith("GIF89a")) return is("gif");
	if (a.startsWith("RIFF") && ascii(b, 8, 4) === "WEBP") return is("webp");
	if (a.startsWith("FUJIFILMCCD-RAW")) return is("raf");
	if (a.startsWith("8BPS")) return is("psd");
	if ((b[0] === 0xff && b[1] === 0x0a) || ascii(b, 4, 8) === "JXL \r\n\x87\n") return is("jxl");
	if (ascii(b, 4, 8) === "jP  \r\n\x87\n" || (b[0] === 0xff && b[1] === 0x4f && b[2] === 0xff && b[3] === 0x51)) return is("jp2");
	if (b.length > 12 && ascii(b, 4, 4) === "ftyp") {
		const size = Math.min(u32be(b, 0), 256, b.length);
		const brands = [ascii(b, 8, 4)];
		for (let at = 16; at + 4 <= size; at += 4) brands.push(ascii(b, at, 4));
		if (brands[0] === "crx ") return is("cr3");
		if (brands.some((x) => x === "avif" || x === "avis")) return is("avif");
		if (brands.some((x) => /^(heic|heix|heim|heis|hevc|hevx|mif1|msf1|mif2)$/.test(x))) return is("heic");
	}
	if (a.startsWith("II*\0") || a.startsWith("MM\0*") || a.startsWith("IIRO") || a.startsWith("IIRS") || a.startsWith("MMOR") || a.startsWith("IIU\0")) {
		if (a.startsWith("IIRO") || a.startsWith("IIRS") || a.startsWith("MMOR")) return is("orf");
		if (a.startsWith("IIU\0")) return is("rw2");
		if (ascii(b, 8, 2) === "CR") return is("cr2");
		const t = readTiff(b);
		const ifd0 = t?.ifds[0];
		if (ifd0?.tags.has(TAG.DNGVersion)) return is("dng");
		const make = (ifd0 && ifd0.tags.get(TAG.Make)?.text?.toUpperCase()) ?? "";
		if (make.startsWith("NIKON")) return is("nef");
		if (make.startsWith("SONY")) return is("arw");
		if (make.startsWith("PENTAX") || make.startsWith("RICOH")) return is("pef");
		if (RAW_EXTENSIONS.test(ext)) return is("raw");
		return is("tiff");
	}
	if (a.startsWith("BM") && b.length > 26 && u32le(b, 14) >= 12 && u32le(b, 14) <= 124) return is("bmp");
	if (b[0] === 0 && b[1] === 0 && (b[2] === 1 || b[2] === 2) && b[3] === 0 && u16le(b, 4) > 0 && u16le(b, 4) < 256 && (ext === "ico" || ext === "cur")) return is("ico");
	if (b[0] === 0x1f && b[1] === 0x8b && ext === "svgz") return is("svgz");
	const head = new TextDecoder("utf-8", { fatal: false }).decode(b.subarray(0, 4096)).replace(/^\ufeff/, "").trimStart();
	if (/^(<\?xml[^>]*>\s*)?(<!--[\s\S]*?-->\s*)*(<!DOCTYPE svg[\s\S]*?>\s*)?<svg[\s>]/i.test(head)) return is("svg");
	const other = otherKind(b);
	return { format: null, label: other ?? "not a picture this viewer knows", native: false, mime: null, other: other ?? undefined };
}

// ── structure ─────────────────────────────────────────────────────────

export interface Trailing {
	offset: number;
	length: number;
	/** What the bytes after the picture are. */
	kind: string;
	/** Expected there, and harmless: a phone's motion photo, MPF pictures. */
	benign: boolean;
}

export interface Structure {
	width: number | null;
	height: number | null;
	/** Animation frames, or a TIFF's pages. */
	frames: number;
	/** Where the picture ends (null: a format whose end is not walked). */
	end: number | null;
	trailing: Trailing | null;
	/** JPEG and GIF comments. */
	comments: string[];
	/** PNG text chunks, by keyword. */
	texts: { key: string; value: string }[];
	/** Content Credentials (C2PA) blocks are present. */
	c2pa: boolean;
	/** More pictures declared by Multi-Picture Format (APP2 MPF). */
	mpf: number;
	/** The JPEG's process: lossless (SOF3) is a RAW file's sensor data, not a picture to show. */
	sof?: number;
	/** The JPEG's own EXIF Orientation (1 when none), or a TIFF's. */
	orientation?: number;
}

const MAX_TEXT = 2000;
const blank = (): Structure => ({ width: null, height: null, frames: 1, end: null, trailing: null, comments: [], texts: [], c2pa: false, mpf: 0 });
const latin1 = (b: Uint8Array) => new TextDecoder("latin1").decode(b);
const utf8 = (b: Uint8Array) => new TextDecoder("utf-8", { fatal: false }).decode(b);

export function structureOf(b: Uint8Array, format: ImageFormat | null): Structure {
	let s: Structure;
	switch (format) {
		case "jpeg":
			s = jpegStructure(b, 0);
			break;
		case "png":
			s = pngStructure(b);
			break;
		case "gif":
			s = gifStructure(b);
			break;
		case "webp":
			s = webpStructure(b);
			break;
		case "bmp": {
			s = blank();
			s.width = b.length > 26 ? Math.abs(new DataView(b.buffer, b.byteOffset).getInt32(18, true)) : null;
			s.height = b.length > 26 ? Math.abs(new DataView(b.buffer, b.byteOffset).getInt32(22, true)) : null;
			const size = u32le(b, 2);
			s.end = size >= 26 && size <= b.length ? size : null;
			break;
		}
		case "heic":
		case "avif":
		case "cr3":
			s = isoStructure(b);
			break;
		case "tiff":
		case "dng":
		case "cr2":
		case "nef":
		case "arw":
		case "orf":
		case "rw2":
		case "pef":
		case "raw":
			s = tiffStructure(b, format === "tiff");
			break;
		default:
			s = blank();
	}
	if (s.end !== null && s.end < b.length) s.trailing = classifyTrailing(b, s.end, s.mpf);
	return s;
}

/** A JPEG's segments, from `at` (a RAW file's preview is a JPEG inside it). */
export function jpegStructure(b: Uint8Array, at: number): Structure {
	const s = blank();
	s.orientation = 1;
	let i = at + 2;
	for (let n = 0; n < 20000 && i + 2 <= b.length; n++) {
		if (b[i] !== 0xff) return s; // not a marker where one must be: stop
		while (b[i] === 0xff && i < b.length) i++;
		const m = b[i]!;
		i++;
		if (m === 0xd9) {
			s.end = i;
			return s;
		}
		if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) continue;
		if (i + 2 > b.length) return s;
		const len = u16be(b, i);
		if (len < 2 || i + len > b.length) return s;
		const p = i + 2;
		const payload = b.subarray(p, i + len);
		if (((m >= 0xc0 && m <= 0xc3) || (m >= 0xc5 && m <= 0xc7) || (m >= 0xc9 && m <= 0xcb) || (m >= 0xcd && m <= 0xcf)) && s.width === null && payload.length >= 5) {
			s.sof = m - 0xc0;
			s.height = u16be(payload, 1);
			s.width = u16be(payload, 3);
		} else if (m === 0xe1 && ascii(payload, 0, 6) === "Exif\0\0") {
			const t = readTiff(payload, 6);
			const o = t?.ifds[0] ? num(t.ifds[0], TAG.Orientation) : undefined;
			if (o && o >= 1 && o <= 8) s.orientation = o;
		} else if (m === 0xe2 && ascii(payload, 0, 4) === "MPF\0") {
			const t = readTiff(payload, 4);
			const count = t?.ifds[0] ? num(t.ifds[0], 0xb001) : undefined;
			if (count && count > 1) s.mpf = Math.min(count - 1, 100);
		} else if (m === 0xeb && (ascii(payload, 0, 2) === "JP" || latin1(payload.subarray(0, 64)).includes("jumb")) && latin1(payload.subarray(0, 256)).includes("c2pa")) {
			s.c2pa = true;
		} else if (m === 0xfe && s.comments.length < 20) {
			s.comments.push(utf8(payload.subarray(0, MAX_TEXT)));
		}
		i += len;
		if (m === 0xda) {
			// Entropy-coded data: to the next marker that is not a stuffed
			// byte (FF00) or a restart (FFD0–D7).
			while (i + 1 < b.length && !(b[i] === 0xff && b[i + 1] !== 0 && !(b[i + 1]! >= 0xd0 && b[i + 1]! <= 0xd7))) i++;
		}
	}
	return s;
}

function pngStructure(b: Uint8Array): Structure {
	const s = blank();
	let i = 8;
	for (let n = 0; n < 100000 && i + 12 <= b.length; n++) {
		const len = u32be(b, i);
		const type = ascii(b, i + 4, 4);
		const p = i + 8;
		if (len > b.length - p - 4) return s;
		const data = b.subarray(p, p + len);
		if (type === "IHDR" && len >= 8) {
			s.width = u32be(data, 0);
			s.height = u32be(data, 4);
		} else if (type === "acTL" && len >= 4) {
			s.frames = Math.max(1, u32be(data, 0));
		} else if ((type === "tEXt" || type === "zTXt" || type === "iTXt") && s.texts.length < 50) {
			const nul = data.indexOf(0);
			if (nul > 0) {
				const key = latin1(data.subarray(0, nul));
				let value = "";
				try {
					if (type === "tEXt") value = latin1(data.subarray(nul + 1));
					else if (type === "zTXt") value = latin1(unzlibSync(data.subarray(nul + 2)).subarray(0, 64 * 1024));
					else {
						const compressed = data[nul + 1] === 1;
						let at = nul + 3;
						for (let z = 0; z < 2; z++) at = data.indexOf(0, at) + 1; // language, translated keyword
						const raw = data.subarray(at);
						value = utf8(compressed ? unzlibSync(raw).subarray(0, 256 * 1024) : raw);
					}
				} catch {
					value = "(could not be read)";
				}
				s.texts.push({ key: key.slice(0, 79), value: value.slice(0, key === "XML:com.adobe.xmp" ? 256 * 1024 : MAX_TEXT) });
			}
		} else if (type === "caBX") {
			s.c2pa = true;
		} else if (type === "IEND") {
			s.end = p + len + 4;
			return s;
		}
		i = p + len + 4;
	}
	return s;
}

function gifStructure(b: Uint8Array): Structure {
	const s = blank();
	if (b.length < 13) return s;
	s.width = u16le(b, 6);
	s.height = u16le(b, 8);
	let i = 13 + (b[10]! & 0x80 ? 3 * (1 << ((b[10]! & 7) + 1)) : 0);
	let frames = 0;
	const blocks = (from: number, keep?: (chunk: Uint8Array) => void) => {
		let j = from;
		for (let n = 0; n < 1_000_000 && j < b.length; n++) {
			const size = b[j]!;
			j++;
			if (size === 0) return j;
			keep?.(b.subarray(j, j + size));
			j += size;
		}
		return b.length + 1;
	};
	for (let n = 0; n < 100000 && i < b.length; n++) {
		const t = b[i]!;
		if (t === 0x3b) {
			s.end = i + 1;
			break;
		}
		if (t === 0x2c) {
			frames++;
			const packed = b[i + 9]!;
			i += 10 + (packed & 0x80 ? 3 * (1 << ((packed & 7) + 1)) : 0);
			i = blocks(i + 1); // the LZW minimum code size, then the data
		} else if (t === 0x21) {
			const label = b[i + 1]!;
			let comment = "";
			i = blocks(i + 2, label === 0xfe ? (c) => (comment += latin1(c)) : undefined);
			if (comment && s.comments.length < 20) s.comments.push(comment.slice(0, MAX_TEXT));
		} else break;
	}
	s.frames = Math.max(1, frames);
	return s;
}

function webpStructure(b: Uint8Array): Structure {
	const s = blank();
	// The RIFF size counts everything after its first 8 bytes.
	const size = u32le(b, 4);
	s.end = 8 + size <= b.length ? 8 + size : null;
	let i = 12;
	let frames = 0;
	for (let n = 0; n < 100000 && i + 8 <= Math.min(b.length, 8 + size); n++) {
		const type = ascii(b, i, 4);
		const len = u32le(b, i + 4);
		const p = i + 8;
		if (type === "VP8X" && len >= 10) {
			s.width = 1 + (b[p + 4]! | (b[p + 5]! << 8) | (b[p + 6]! << 16));
			s.height = 1 + (b[p + 7]! | (b[p + 8]! << 8) | (b[p + 9]! << 16));
		} else if (type === "VP8 " && len >= 10 && s.width === null) {
			s.width = u16le(b, p + 6) & 0x3fff;
			s.height = u16le(b, p + 8) & 0x3fff;
		} else if (type === "VP8L" && len >= 5 && s.width === null) {
			const bits = u32le(b, p + 1);
			s.width = (bits & 0x3fff) + 1;
			s.height = ((bits >>> 14) & 0x3fff) + 1;
		} else if (type === "ANMF") frames++;
		i = p + len + (len & 1);
	}
	s.frames = Math.max(1, frames);
	return s;
}

/** ISO boxes (HEIF, AVIF, CR3): the top level to its end; the largest
 * declared picture (ispe). */
function isoStructure(b: Uint8Array): Structure {
	const s = blank();
	let w = 0;
	let h = 0;
	const walk = (from: number, to: number, depth: number) => {
		let i = from;
		for (let n = 0; n < 10000 && i + 8 <= to; n++) {
			let size = u32be(b, i);
			const type = ascii(b, i + 4, 4);
			let head = 8;
			if (size === 1 && i + 16 <= to) {
				size = u32be(b, i + 8) * 2 ** 32 + u32be(b, i + 12);
				head = 16;
			} else if (size === 0) size = to - i;
			if (size < head || i + size > to) return depth === 0 ? null : i;
			if (type === "meta") walk(i + head + 4, i + size, depth + 1);
			else if (type === "iprp" || type === "ipco") walk(i + head, i + size, depth + 1);
			else if (type === "ispe" && size >= head + 12) {
				const pw = u32be(b, i + head + 4);
				const ph = u32be(b, i + head + 8);
				if (pw * ph > w * h) [w, h] = [pw, ph];
			}
			i += size;
		}
		return i;
	};
	const end = walk(0, b.length, 0);
	s.end = typeof end === "number" ? end : null;
	if (w) [s.width, s.height] = [w, h];
	return s;
}

function tiffStructure(b: Uint8Array, pages: boolean): Structure {
	const s = blank();
	const t = readTiff(b);
	if (!t) return s;
	// The pictures a TIFF holds: its top-level IFDs that are not reduced
	// copies (NewSubfileType bit 0) of another. For a RAW file, the
	// largest image anywhere (the sensor's).
	const full = t.ifds.filter((i) => (pages ? !i.sub : true) && !((num(i, TAG.NewSubfileType) ?? 0) & 1));
	const sizes = full.map((i) => [num(i, TAG.ImageWidth) ?? 0, num(i, TAG.ImageLength) ?? 0] as const).filter(([x, y]) => x > 0 && y > 0);
	const best = pages ? sizes[0] : [...sizes].sort((p, q) => q[0] * q[1] - p[0] * p[1])[0];
	if (best) [s.width, s.height] = best;
	s.frames = pages ? Math.max(1, full.length) : 1;
	const o = num(t.ifds[0]!, TAG.Orientation);
	s.orientation = o && o >= 1 && o <= 8 ? o : 1;
	return s;
}

/** What the bytes after a picture's end are. */
export function classifyTrailing(b: Uint8Array, end: number, mpf = 0): Trailing | null {
	const rest = b.subarray(end);
	if (rest.length === 0) return null;
	// Padding (zeros, or the 0xFF some cameras fill with) is no news.
	if (rest.every((x) => x === 0 || x === 0xff)) return null;
	const kind = otherKind(rest);
	const benign = (k: string) => ({ offset: end, length: rest.length, kind: k, benign: true });
	if (rest[0] === 0xff && rest[1] === 0xd8 && rest[2] === 0xff) return mpf ? benign(`${mpf === 1 ? "another picture" : `${mpf} more pictures`} (Multi-Picture Format: a phone's depth map or a second view)`) : { offset: end, length: rest.length, kind: "another JPEG picture, not declared anywhere", benign: false };
	if (kind === "a video") return benign("a video (a motion photo)");
	// Samsung's trailer ("SEFH"…"SEFT") holds a motion photo's video and edit data.
	if (latin1(rest.subarray(Math.max(0, rest.length - 8))).includes("SEFT")) return benign("a Samsung trailer (a motion photo, edit data)");
	if (kind) return { offset: end, length: rest.length, kind, benign: false };
	const sample = rest.subarray(0, 4096);
	const printable = sample.filter((x) => x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127)).length / sample.length;
	if (printable > 0.95) {
		const text = latin1(sample).trim();
		return { offset: end, length: rest.length, kind: /<\?php|<script|eval\(|powershell|cmd\.exe|base64_decode/i.test(text) ? `text that is code: “${text.slice(0, 60)}”` : `text: “${text.slice(0, 60)}”`, benign: false };
	}
	return { offset: end, length: rest.length, kind: "data of no known kind", benign: false };
}
