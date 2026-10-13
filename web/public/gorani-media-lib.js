// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * GC01 frame math for the media service worker — plain ES module (no build
 * step: the worker imports it straight from /gorani-media-lib.js, served
 * raw), and the unit tests import the very same file in Node.
 *
 * ```text
 * object  = frame 0 ‖ frame 1 ‖ …          (every frame but the last: chunk + 28 bytes)
 * frame i = nonce (12) ‖ AES-GCM ct ‖ tag (16)     AAD = "GC01" ‖ i (8B BE) ‖ final (1B)
 * ```
 *
 * A plaintext byte range maps to whole frames; the worker fetches those
 * frames' ciphertext with ONE range request, decrypts, and serves the
 * plaintext slice — the browser's video element does the rest.
 */

export const FRAME_OVERHEAD = 28; // 12-byte nonce + 16-byte tag
export const MAGIC = "GC01";

/** The frames covering plaintext bytes [start, end] (inclusive). */
export function framesForRange(start, end, chunk, size) {
	const frames = Math.max(1, Math.ceil(size / chunk));
	const first = Math.min(Math.floor(start / chunk), frames - 1);
	const last = Math.min(Math.floor(Math.min(end, size - 1) / chunk), frames - 1);
	const frame = chunk + FRAME_OVERHEAD;
	return { first, last, ciphertextStart: first * frame, ciphertextEnd: (last + 1) * frame };
}

/** The AES-GCM AAD for frame i (the position is authenticated, not stored). */
export function frameAad(i, final, encoder = new TextEncoder()) {
	const a = new Uint8Array(13);
	a.set(encoder.encode(MAGIC), 0);
	const view = new DataView(a.buffer);
	view.setBigUint64(4, BigInt(i));
	a[12] = final ? 1 : 0;
	return a;
}

/** Split one ciphertext frame into { iv, body } for subtle.decrypt
 * (WebCrypto wants ct ‖ tag concatenated; the nonce rides in front). */
export function splitFrame(ciphertext, at, length) {
	return { iv: ciphertext.subarray(at, at + 12), body: ciphertext.subarray(at + 12, at + length) };
}

/** Open-ended Range requests cap the fetch window (the browser re-asks). */
export const OPEN_RANGE_WINDOW = 4 * 1024 * 1024;

export function resolveRange(header, size) {
	const m = /bytes=(\d*)-(\d*)/.exec(header ?? "");
	if (!m) return null;
	const [, a, b] = m;
	let start, end;
	if (a === "") {
		// suffix: last N bytes
		const n = Number(b);
		start = Math.max(0, size - n);
		end = size - 1;
	} else {
		start = Number(a);
		end = b === "" ? Math.min(size - 1, start + OPEN_RANGE_WINDOW) : Math.min(Number(b), size - 1);
	}
	if (start > end || start >= size) return null;
	return { start, end };
}