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
 * plaintext slice — the browser's video element does the rest. A whole
 * file downloads the same way, frame window by frame window, hashed as it
 * passes (`downloadStream`, D12).
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

/**
 * Exactly the bytes the browser asked for (commit 25, O11): the decrypted
 * frames cover [first frame start, last frame end]; the answer is the
 * requested [start, end] cut out of them, with a Content-Range that says
 * so. The worker used to answer with the whole frame span — a response
 * starting before the requested offset, which media stacks may reject.
 */
export function cutToRange(plainFrames, framesStart, start, end) {
	const from = start - framesStart;
	const to = Math.min(end - framesStart + 1, plainFrames.length);
	if (from < 0 || from >= to) throw new Error("range outside the decrypted frames");
	return plainFrames.subarray(from, to);
}

/**
 * SHA-256, incremental (FIPS 180-4), for the service worker's streamed
 * download (D12, 31c): WebCrypto's digest has no streaming form and the
 * worker imports nothing from the app bundle. Checked against node:crypto
 * in tests/unit/media-frames.test.mjs.
 */
const K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256Stream() {
	const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
	const w = new Uint32Array(64);
	const block = new Uint8Array(64);
	let filled = 0;
	let total = 0; // bytes (a Number: exact to 2^53, far past 255 GiB)
	const compress = (b, at) => {
		for (let i = 0; i < 16; i++) w[i] = (b[at + 4 * i] << 24) | (b[at + 4 * i + 1] << 16) | (b[at + 4 * i + 2] << 8) | b[at + 4 * i + 3];
		for (let i = 16; i < 64; i++) {
			const x = w[i - 15], y = w[i - 2];
			const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
			const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
		}
		let [a, bb, c, d, e, f, g, hh] = h;
		for (let i = 0; i < 64; i++) {
			const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
			const t1 = (hh + S1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
			const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
			const t2 = (S0 + ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
			hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
		}
		h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
	};
	return {
		update(bytes) {
			let i = 0;
			total += bytes.length;
			if (filled) {
				const take = Math.min(64 - filled, bytes.length);
				block.set(bytes.subarray(0, take), filled);
				filled += take;
				i = take;
				if (filled < 64) return;
				compress(block, 0);
				filled = 0;
			}
			for (; i + 64 <= bytes.length; i += 64) compress(bytes, i);
			if (i < bytes.length) {
				block.set(bytes.subarray(i), 0);
				filled = bytes.length - i;
			}
		},
		hex() {
			const bits = total * 8;
			const pad = new Uint8Array(((filled < 56 ? 56 : 120) - filled) + 8);
			pad[0] = 0x80;
			const view = new DataView(pad.buffer);
			view.setUint32(pad.length - 8, Math.floor(bits / 2 ** 32));
			view.setUint32(pad.length - 4, bits >>> 0);
			this.update(pad);
			return [...h].map((x) => x.toString(16).padStart(8, "0")).join("");
		},
	};
}

/**
 * A whole GC01 file as a stream of plaintext (D12, docs/LARGE-FILES.md ›
 * 31c) — the service worker's download. Frames are fetched a window at a
 * time (about 32 MiB of ciphertext, at least one frame), each opened in
 * its place (the AAD names its index and whether it is the last), and
 * hashed as it passes; the browser's own download writes the plaintext to
 * disk, and `onDone` hands the SHA-256 back to the page, which checks it
 * against the uploader's signed record. Pull-based (highWaterMark 0):
 * nothing is fetched faster than the disk takes it, so memory stays one
 * window however large the file.
 *
 * `fetchRange(start, end)` returns the ciphertext bytes [start, end).
 */
export function downloadStream({ fetchRange, key, chunk, size, onDone, subtle = crypto.subtle, windowBytes = 32 * 1024 * 1024 }) {
	const frames = Math.max(1, Math.ceil(size / chunk));
	const frame = chunk + FRAME_OVERHEAD;
	const sealed = size + frames * FRAME_OVERHEAD;
	const per = Math.max(1, Math.floor(windowBytes / frame));
	const hash = sha256Stream();
	const encoder = new TextEncoder();
	let next = 0;
	let sent = 0;
	let finished = false;
	const finish = (result) => {
		if (finished) return;
		finished = true;
		onDone?.(result);
	};
	return new ReadableStream(
		{
			async pull(controller) {
				try {
					if (next >= frames) {
						if (sent !== size) throw new Error(`the file opened to ${sent} bytes, not ${size}`);
						finish({ ok: true, sha256: hash.hex(), size: sent });
						controller.close();
						return;
					}
					const n = Math.min(per, frames - next);
					const start = next * frame;
					const end = Math.min(sealed, (next + n) * frame);
					const ct = await fetchRange(start, end);
					if (ct.length !== end - start) throw new Error(`the server answered ${ct.length} bytes for a ${end - start}-byte span`);
					for (let k = 0; k < n; k++) {
						const i = next + k;
						const at = k * frame;
						const { iv, body } = splitFrame(ct, at, Math.min(frame, ct.length - at));
						let plain;
						try {
							plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: frameAad(i, i === frames - 1, encoder) }, key, body));
						} catch {
							throw new Error(`frame ${i + 1} of ${frames} does not open — the file was altered, reordered or cut short`);
						}
						hash.update(plain);
						sent += plain.length;
						controller.enqueue(plain);
					}
					next += n;
				} catch (e) {
					finish({ ok: false, error: String(e?.message ?? e) });
					controller.error(e);
				}
			},
			cancel() {
				finish({ ok: false, error: "the download was cancelled" });
			},
		},
		{ highWaterMark: 0 },
	);
}
