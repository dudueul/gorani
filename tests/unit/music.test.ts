// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The music tag parser (web/src/vault/music-meta.ts) — the client-side
 * half of docs/MUSIC.md. The server never sees tags; whoever holds the
 * plaintext parses them and seals the summary. These tests build tag
 * bytes by hand so the parser's contract is proven byte by byte: ID3v2.4
 * and v2.3 text frames (both encodings), FLAC duration + comments, and
 * the honest null for everything that isn't audio.
 */

import assert from "node:assert/strict";
import { parseAudioMeta } from "../../web/src/vault/music-meta.ts";

const enc = new TextEncoder();

/** An ID3v2.4 tag: synchsafe sizes everywhere, one encoding byte per frame. */
function id3v24(frames: { id: string; enc: number; text: string }[]): Uint8Array {
	const body: number[] = [];
	for (const f of frames) {
		// The payload's bytes match the declared encoding: UTF-16LE/BE carries
		// two bytes per character (the BOM rides before them), UTF-8/latin-1
		// one.
		const payload =
			f.enc === 1 || f.enc === 2
				? [...f.text].flatMap((c) => {
						const u = c.charCodeAt(0);
						return f.enc === 1 ? [u & 0xff, u >> 8] : [(u >> 8) & 0xff, u & 0xff];
					})
				: [...enc.encode(f.text)];
		const pre = f.enc === 1 ? [0xff, 0xfe] : f.enc === 2 ? [0xfe, 0xff] : [];
		// The frame body: encoding byte ‖ text ‖ its terminator (two NULs for
		// UTF-16, one for 8-bit encodings).
		const term = f.enc === 1 || f.enc === 2 ? [0, 0] : [0];
		const size = 1 + pre.length + payload.length + term.length;
		const synch = [(size >> 21) & 0x7f, (size >> 14) & 0x7f, (size >> 7) & 0x7f, size & 0x7f];
		body.push(...enc.encode(f.id), ...synch, 0, 0, f.enc, ...pre, ...payload, ...term);
	}
	const synchTag = [(body.length >> 21) & 0x7f, (body.length >> 14) & 0x7f, (body.length >> 7) & 0x7f, body.length & 0x7f];
	return new Uint8Array([...enc.encode("ID3"), 4, 0, 0, ...synchTag, ...body, ...new Array(64).fill(0)]);
}

const mp3 = id3v24([
	{ id: "TIT2", enc: 3, text: "Gorani Anthem" },
	{ id: "TPE1", enc: 1, text: "The Family" },
	{ id: "TALB", enc: 0, text: "Sealed Sounds" },
	{ id: "TRCK", enc: 0, text: "7/12" },
]);
const meta = parseAudioMeta(mp3);
assert.equal(meta?.title, "Gorani Anthem", "UTF-8 title");
assert.equal(meta?.artist, "The Family", `UTF-16LE artist: ${meta?.artist}`);
assert.equal(meta?.album, "Sealed Sounds", "latin-1 album");
assert.equal(meta?.track, 7, "track number from 7/12");

// v2.3: plain 32-bit frame sizes, same outcome.
const v23body: number[] = [];
for (const [id, text] of [["TIT2", "Old Format"], ["TPE1", "Legacy Band"]] as const) {
	// v2.3 frame size is a plain 32-bit count of the body AFTER the size
	// field: the encoding byte, the text, and its NUL.
	const payload = [...enc.encode(text)];
	const size = 1 + payload.length + 1;
	v23body.push(...enc.encode(id), size >>> 24, (size >>> 16) & 0xff, (size >>> 8) & 0xff, size & 0xff, 0, 0, 0, ...payload, 0);
}
const v23 = new Uint8Array([...enc.encode("ID3"), 3, 0, 0, v23body.length >>> 24, (v23body.length >>> 16) & 0xff, (v23body.length >>> 8) & 0xff, v23body.length & 0xff, ...v23body]);
const m23 = parseAudioMeta(v23);
assert.equal(m23?.title, "Old Format");
assert.equal(m23?.artist, "Legacy Band");

// ── FLAC: STREAMINFO duration + Vorbis comments (little-endian) ─────
const flacBody = (samples: number, sr: number) => {
	const packed = new Uint8Array(8);
	const srBits = sr.toString(2).padStart(20, "0");
	packed[0] = Number.parseInt(srBits.slice(0, 8), 2);
	packed[1] = Number.parseInt(srBits.slice(8, 16), 2);
	packed[2] = (Number.parseInt(srBits.slice(16, 20), 2) << 4) | 0x02; // sr tail ‖ channels−1 (001: stereo) ‖ bps top bit
	packed[3] = (0xf0 & (((16 - 1) & 0x0f) << 4)) | (Math.floor(samples / 2 ** 32) & 0x0f); // bps−1 (16-bit) ‖ totalSamples high nibble
	packed[4] = (samples >>> 24) & 0xff;
	packed[5] = (samples >>> 16) & 0xff;
	packed[6] = (samples >>> 8) & 0xff;
	packed[7] = samples & 0xff;
	return packed;
};
const comment = (k: string, v: string) => {
	const line = enc.encode(`${k}=${v}`);
	return [line.length & 0xff, (line.length >> 8) & 0xff, (line.length >> 16) & 0xff, (line.length >> 24) & 0xff, ...line];
};
const vendor = enc.encode("gorani");
const vcBody: number[] = [vendor.length & 0xff, (vendor.length >> 8) & 0xff, (vendor.length >> 16) & 0xff, (vendor.length >> 24) & 0xff, ...vendor, 3, 0, 0, 0, ...comment("TITLE", "Flac Song"), ...comment("ARTIST", "Free Lossless"), ...comment("TRACKNUMBER", "3")];
const vcLen = vcBody.length;
// STREAMINFO's body is 34 bytes: block/frame size bounds (10) ‖ the packed
// rate/channels/bps/totalSamples field (8) ‖ an MD5 signature (16, zeros here).
const streamInfo = new Uint8Array(34);
streamInfo.set(flacBody(44100 * 187, 44100), 10);
const flac = new Uint8Array([
	...enc.encode("fLaC"),
	0, 0, 0, 34, ...streamInfo, // STREAMINFO, not last: type byte + 3-byte big-endian length
	0x84, vcLen >>> 16, (vcLen >> 8) & 0xff, vcLen & 0xff, ...vcBody, // VORBIS_COMMENT, last (0x80|4)
]);
const fm = parseAudioMeta(flac);
assert.equal(fm?.title, "Flac Song");
assert.equal(fm?.artist, "Free Lossless");
assert.equal(fm?.track, 3);
assert.equal(fm?.durationSec, 187, "duration from STREAMINFO");

// ── Honest nulls ─────────────────────────────────────────────────────
assert.equal(parseAudioMeta(enc.encode("just some text file")), null);
assert.equal(parseAudioMeta(new Uint8Array(8)), null);
assert.equal(parseAudioMeta(new Uint8Array([...enc.encode("ID3"), 2, 0, 0, 0, 0, 0, 0, ...new Array(32).fill(0)])), null, "v2.2 is another grammar");

console.log("ok  unit:music — ID3v2.3/2.4 text frames, FLAC duration + comments, honest nulls");