// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:shamir — the team recovery key's M-of-N split (web/src/vault/shamir.ts,
 * docs/CASES.md › Recovery). What it proves:
 *
 *   the field is GF(2⁸) with AES's polynomial (FIPS-197's own worked
 *   examples) → every M-subset of N shares reconstructs → M−1 shares do
 *   not → shares from different splits, duplicates and short sets are
 *   refused → a tampered share yields a WRONG secret silently (the caller
 *   must verify — and the test shows the check that catches it).
 */

import assert from "node:assert/strict";
import { split, combine, gfMul, gfDiv, decode, encode } from "../../web/src/vault/shamir.ts";

// ── 1. The field ────────────────────────────────────────────────────
// FIPS-197 §4.2: {57} • {83} = {c1}, and {57} • {13} = {fe}.
assert.equal(gfMul(0x57, 0x83), 0xc1);
assert.equal(gfMul(0x57, 0x13), 0xfe);
for (let a = 1; a < 256; a++) {
	assert.equal(gfMul(a, gfDiv(1, a)), 1, `every nonzero element has an inverse (${a})`);
	assert.equal(gfDiv(gfMul(a, 0x1d), 0x1d), a);
}
assert.equal(gfMul(0, 0x53), 0);

// ── 2. Every M-subset reconstructs ──────────────────────────────────
const secret = crypto.getRandomValues(new Uint8Array(2400)); // about a hybrid key bundle
const shares = split(secret, 3, 5);
assert.equal(shares.length, 5);
const subsets = (xs: string[], k: number): string[][] => (k === 0 ? [[]] : xs.flatMap((x, i) => subsets(xs.slice(i + 1), k - 1).map((rest) => [x, ...rest])));
for (const subset of subsets(shares, 3)) assert.deepEqual(combine(subset), secret, "any 3 of 5");
assert.equal(subsets(shares, 3).length, 10);
// More than M is fine (the extra ones are ignored).
assert.deepEqual(combine(shares), secret);

// ── 3. M−1 shares are refused — and could not have helped ───────────
assert.throws(() => combine(shares.slice(0, 2)), /3 shares are needed/);
// Even forced past the count check (rewriting the threshold to 2), two
// points of a degree-2 polynomial give some other secret, not this one.
const forced = shares.slice(0, 2).map((s) => encode({ ...decode(s), threshold: 2 }));
assert.notDeepEqual(combine(forced), secret, "two points of a degree-2 polynomial say nothing about P(0)");

// ── 4. Mistakes refused ─────────────────────────────────────────────
const other = split(secret, 3, 5);
assert.throws(() => combine([shares[0], shares[1], other[2]]), /different splits/);
assert.throws(() => combine([shares[0], shares[0], shares[1]]), /twice/);
assert.throws(() => split(secret, 1, 3), /2 ≤ m/);
assert.throws(() => split(secret, 4, 3), /2 ≤ m/);
assert.throws(() => combine(["not a share"]), /not a share/);
// Two splits of the same secret look unrelated (fresh coefficients and ids).
assert.notEqual(shares[0], other[0]);

// ── 5. No integrity: a tampered share is a wrong answer, silently ───
const tampered = decode(shares[1]);
tampered.y[0] ^= 0x01;
const wrong = combine([shares[0], encode(tampered), shares[2]]);
assert.notDeepEqual(wrong, secret, "Shamir reconstructs whatever the points say");
assert.equal(wrong.length, secret.length);
// …which is why the recovery ceremony verifies the result against what it
// must be (the registry's key id for the recovery key). Here: a digest.
const digest = async (b: Uint8Array) => Buffer.from(await crypto.subtle.digest("SHA-256", b)).toString("hex");
const expected = await digest(secret);
assert.equal(await digest(combine(shares.slice(2))), expected);
assert.notEqual(await digest(wrong), expected, "the check catches the tampered share");

console.log("ok  shamir: GF(2^8) per FIPS-197, every 3-of-5 subset reconstructs, 2 do not, mistakes refused, tampering needs the caller's check");
