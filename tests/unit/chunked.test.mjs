// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * GC01 in TypeScript: frame arithmetic, streamed opening, and the tamper
 * guarantees (reorder, drop, truncate all fail). The cross-language half
 * lives in formats.test.mjs (the vectors).
 */

import assert from "node:assert/strict";
import { importContentKey, newContentKey } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked, openChunked, openChunkedStream, FRAME_OVERHEAD, frameCount, sealedSize } from "../../web/src/vault/chunked-file.ts";

const key = await importContentKey(newContentKey());
const chunk = 64;
const plain = crypto.getRandomValues(new Uint8Array(200)); // four frames of 64, 64, 64, 8

// Arithmetic: one frame per chunk, 28 bytes of overhead each, at least one frame.
assert.equal(frameCount(200, chunk), 4);
assert.equal(sealedSize(200, chunk), 200 + 4 * FRAME_OVERHEAD);
assert.equal(frameCount(0, chunk), 1, "an empty file is one empty final frame");
assert.equal((await sealChunked(key, new Uint8Array(0), chunk)).length, 12 + 16, "empty file frame");

// Round trip.
const sealed = await sealChunked(key, plain, chunk);
assert.equal(sealed.length, sealedSize(200, chunk));
assert.deepEqual(await openChunked(key, sealed, chunk), plain);

// Streamed: frames open as they arrive, in order.
const seen = [];
const stream = new ReadableStream({
	start(controller) {
		for (let at = 0; at < sealed.length; at += 40) controller.enqueue(sealed.subarray(at, Math.min(sealed.length, at + 40)));
		controller.close();
	},
});
await openChunkedStream(key, stream, chunk, sealed.length, (p, i) => {
	seen.push([i, p.length]);
});
assert.deepEqual(
	seen.map(([, l]) => l),
	[64, 64, 64, 8],
	"frames in order",
);

// The last frame carries final=1: cut the file short and the open refuses.
await assert.rejects(() =>
	openChunkedStream(key, new ReadableStream({ start(c) { c.enqueue(sealed.subarray(0, sealed.length - 30)); c.close(); } }), chunk, sealed.length, () => {}),
);
// A reordered frame fails (the position is authenticated).
const f = chunk + FRAME_OVERHEAD;
const reordered = new Uint8Array(sealed);
reordered.set(sealed.subarray(0, f), f);
reordered.set(sealed.subarray(f, f * 2), 0);
await assert.rejects(() => openChunked(key, reordered, chunk));
// A dropped middle frame misaligns every later frame: refused.
await assert.rejects(() => openChunked(key, new Uint8Array([...sealed.subarray(0, f), ...sealed.subarray(f * 2)]), chunk));

console.log("ok  chunked: frames, stream, tamper");