// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Music tag parsing, client-side only (docs/MUSIC.md). In a zero-trust NAS
 * the server sees sealed bytes — it can no more read an MP3's ID3 tag than
 * its name. So tags are parsed by whoever already holds the plaintext:
 * the uploading browser (which seals the result as a GV03 blob into
 * `music_meta`), and the library view (which opens the blobs and never
 * re-reads the audio). One parser, pure TypeScript, runs in the browser
 * and in Node's tests.
 *
 * Scope: ID3v2.3/2.4 (MP3) text frames and FLAC (STREAMINFO duration +
 * Vorbis comments). MP4/M4A metadata rides its own container grammar and
 * is a later bite — the library treats it as "unknown metadata", not an
 * error.
 */

export interface AudioMeta {
	title?: string;
	artist?: string;
	album?: string;
	/** The track number within its album, when the tag says so. */
	track?: number;
	durationSec?: number;
}

const ID3_MAGIC = [0x49, 0x44, 0x33]; // "ID3"
const FLAC_MAGIC = [0x66, 0x4c, 0x61, 0x43]; // "fLaC"

const decoder = (label: string) => new TextDecoder(label, { fatal: false });

/** ID3 text encodings: 0 latin-1, 1 UTF-16 with BOM, 2 UTF-16BE, 3 UTF-8. */
function decodeId3Text(raw: Uint8Array, encoding: number): string {
	if (encoding === 1 || encoding === 2) {
		// UTF-16: strip the BOM the tag carries, then decode the rest.
		if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) return decoder("utf-16le").decode(raw.subarray(2));
		if (raw.length >= 2 && raw[0] === 0xfe && raw[1] === 0xff) return decoder("utf-16be").decode(raw.subarray(2));
		return decoder(encoding === 1 ? "utf-16le" : "utf-16be").decode(raw);
	}
	return decoder(encoding === 3 ? "utf-8" : "windows-1252").decode(raw);
}

/** Cut a text value at its terminator (single NUL for 8-bit, double for UTF-16). */
function terminated(raw: Uint8Array, encoding: number): Uint8Array {
	const width = encoding === 1 || encoding === 2 ? 2 : 1;
	for (let i = 0; i + width <= raw.length; i++) {
		let end = true;
		for (let j = 0; j < width; j++) if (raw[i + j] !== 0) end = false;
		if (end) return raw.subarray(0, i);
	}
	return raw;
}

/** Synchsafe integers: 28 bits of value spread over four 7-bit bytes. */
const synchsafe = (b: Uint8Array, at: number) => ((b[at]! & 0x7f) << 21) | ((b[at + 1]! & 0x7f) << 14) | ((b[at + 2]! & 0x7f) << 7) | (b[at + 3]! & 0x7f);
const u32 = (b: Uint8Array, at: number) => (b[at]! << 24) | (b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!;

const ID3_FRAME_OF: Record<string, keyof AudioMeta> = { TIT2: "title", TPE1: "artist", TALB: "album", TRCK: "track" };

function parseId3(b: Uint8Array): AudioMeta | null {
	const major = b[3]!;
	if (major < 3 || major > 4) return null; // v2.2's 3-byte frame ids are another grammar
	const tagSize = synchsafe(b, 6);
	const out: AudioMeta = {};
	let at = 10;
	const end = Math.min(10 + tagSize, b.length);
	while (at + 10 <= end) {
		const id = String.fromCharCode(b[at]!, b[at + 1]!, b[at + 2]!, b[at + 3]!);
		if (!/^[A-Z0-9]{4}$/.test(id)) break; // padding or corruption
		const size = major === 4 ? synchsafe(b, at + 4) : u32(b, at + 4);
		if (size <= 0 || at + 10 + size > end) break;
		const kind = ID3_FRAME_OF[id];
		if (kind) {
			const body = b.subarray(at + 10, at + 10 + size);
			const enc = body[0] ?? 0;
			// UTF-16's NULs are character units — a byte-level terminator scan
			// would cut the last character's high byte. Decode whole, strip
			// the NULs after; the 8-bit encodings terminate on a real NUL.
			const raw = body.subarray(1);
			const text = (enc === 1 || enc === 2 ? decodeId3Text(raw, enc) : decodeId3Text(terminated(raw, enc), enc)).replace(/\u0000+$/, "").trim();
			if (text) {
				if (kind === "track") {
					const n = Number.parseInt(text.split("/")[0] ?? "", 10);
					if (Number.isFinite(n)) out.track = n;
				} else if (kind === "title" || kind === "artist" || kind === "album") out[kind] = text;
			}
		}
		at += 10 + size;
	}
	return Object.keys(out).length ? out : null;
}

function parseFlac(b: Uint8Array): AudioMeta | null {
	const out: AudioMeta = {};
	let at = 4;
	for (let guard = 0; guard < 64; guard++) {
		if (at + 4 > b.length) break;
		const header = b[at]!;
		const type = header & 0x7f;
		const last = (header & 0x80) !== 0;
		const len = (b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!;
		const body = b.subarray(at + 4, Math.min(at + 4 + len, b.length));
		if (type === 0 && body.length >= 18) {
			// STREAMINFO: 8 packed bytes carry sampleRate (20 bits), channels
			// (3), bits-per-sample (5), totalSamples (36) — the rate spans the
			// first two bytes and byte two's high nibble; the sample count's
			// high nibble sits in byte three's LOW bits, its low 32 bits follow.
			const sr = (body[10]! << 12) | (body[11]! << 4) | (body[12]! >> 4);
			const total = ((body[13]! & 0x0f) * 2 ** 32) + u32(body, 14);
			if (sr > 0 && total > 0) out.durationSec = Math.round((total / sr) * 10) / 10;
		} else if (type === 4) {
			// VORBIS_COMMENT: little-endian lengths, "KEY=value" lines.
			let p = 0;
			const u32le = () => ((p = p + 4) <= body.length ? body[p - 4]! | (body[p - 3]! << 8) | (body[p - 2]! << 16) | (body[p - 1]! << 24) : 0);
			const vendor = u32le();
			p += vendor;
			const count = u32le();
			for (let i = 0; i < count && p < body.length; i++) {
				const n = u32le();
				const line = decoder("utf-8").decode(body.subarray(p, Math.min(p + n, body.length)));
				p += n;
				const eq = line.indexOf("=");
				if (eq < 0) continue;
				const key = line.slice(0, eq).toUpperCase();
				const value = line.slice(eq + 1).trim();
				if (!value) continue;
				if (key === "TITLE") out.title = value;
				else if (key === "ARTIST") out.artist = value;
				else if (key === "ALBUM") out.album = value;
				else if (key === "TRACKNUMBER") {
					const n2 = Number.parseInt(value.split("/")[0] ?? "", 10);
					if (Number.isFinite(n2)) out.track = n2;
				}
			}
		}
		if (last) break;
		at += 4 + len;
	}
	return Object.keys(out).length ? out : null;
}

/** Parse the tags out of plaintext audio bytes; null when it isn't audio we read. */
export function parseAudioMeta(bytes: Uint8Array): AudioMeta | null {
	if (bytes.length < 16) return null;
	if (ID3_MAGIC.every((x, i) => bytes[i] === x)) return parseId3(bytes);
	if (FLAC_MAGIC.every((x, i) => bytes[i] === x)) return parseFlac(bytes);
	return null;
}