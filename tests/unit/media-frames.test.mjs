// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The media service worker's frame math, imported from the very file the
 * worker runs (web/public/gorani-media-lib.js — plain ES module, no build
 * step). What it proves: a plaintext byte range maps to the right frames,
 * the ciphertext span covers them exactly, the AAD binds position and
 * finality, and open-ended ranges stay inside the object.
 */

import assert from "node:assert/strict";
import { framesForRange, frameAad, splitFrame, resolveRange, FRAME_OVERHEAD } from "../../web/public/gorani-media-lib.js";

const chunk = 64;
const size = 200; // four frames: 64, 64, 64, 8

// ── 1. ranges map to whole frames, aligned to frame boundaries ──────
const mid = framesForRange(100, 139, chunk, size);
assert.deepEqual(
	{ first: mid.first, last: mid.last },
	{ first: 1, last: 2 },
	"plaintext 100..139 lives in frames 1..2",
);
assert.equal(mid.ciphertextStart, 1 * (chunk + FRAME_OVERHEAD));
assert.equal(mid.ciphertextEnd, 3 * (chunk + FRAME_OVERHEAD));

// A range spanning the whole file: all four frames.
const all = framesForRange(0, size - 1, chunk, size);
assert.deepEqual({ first: all.first, last: all.last, ciphertextEnd: all.ciphertextEnd }, { first: 0, last: 3, ciphertextEnd: 4 * (chunk + FRAME_OVERHEAD) });

// Clamping: past-the-end ranges stay inside the object.
const over = framesForRange(150, 500, chunk, size);
assert.equal(over.last, 3);

// ── 2. the AAD binds index and finality ─────────────────────────────
const aad0 = frameAad(0, false);
assert.equal(aad0.length, 13);
assert.equal(new TextDecoder().decode(aad0.subarray(0, 4)), "GC01");
assert.equal(new DataView(aad0.buffer).getBigUint64(4), 0n);
assert.equal(aad0[12], 0);
const aadLast = frameAad(3, true);
assert.equal(aadLast[12], 1);
// A different index yields different bytes: frames cannot be swapped.
assert.notDeepEqual(frameAad(1, false), frameAad(2, false));

// ── 3. splitFrame: nonce front, body+tag behind ─────────────────────
const frame = new Uint8Array(chunk + FRAME_OVERHEAD);
crypto.getRandomValues(frame);
const { iv, body } = splitFrame(frame, 0, frame.length);
assert.equal(iv.length, 12);
assert.equal(body.length, chunk + 16, "ciphertext + tag");
assert.deepEqual(iv, frame.subarray(0, 12));

// ── 4. Range header resolution ──────────────────────────────────────
assert.deepEqual(resolveRange("bytes=100-139", size), { start: 100, end: 139 });
// Open-ended: capped at the window, still inside the object.
const open = resolveRange("bytes=100-", size);
assert.equal(open.start, 100);
assert.ok(open.end > 100 && open.end < size + 1);
// Suffix: the last N bytes.
assert.deepEqual(resolveRange("bytes=-50", size), { start: 150, end: 199 });
// Nonsense refused.
assert.equal(resolveRange("bytes=500-600", size), null, "past the end");
assert.equal(resolveRange(null, size), null);

console.log("ok  media frames: range mapping, AAD binding, split, range resolution");