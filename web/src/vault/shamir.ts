// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Shamir secret sharing over GF(2⁸) — the team recovery key's M-of-N split
 * (docs/CASES.md › Recovery, docs/DECISIONS.md › D4).
 *
 * The idea in three lines: to share a byte s so that any M of N people can
 * recover it, pick a random polynomial P of degree M−1 with P(0) = s and give
 * person i the point (i, P(i)). M points determine a degree-(M−1) polynomial
 * exactly (Lagrange interpolation); M−1 points are consistent with EVERY
 * possible s, so they reveal nothing — not "hard to compute", nothing.
 * A secret of many bytes is shared byte by byte, with fresh coefficients
 * for every byte, all at the same x per person.
 *
 * The field is GF(2⁸) with AES's polynomial x⁸ + x⁴ + x³ + x + 1 (0x11B):
 * addition is XOR, multiplication goes through log/exp tables of the
 * generator 0x03. Everything here is bytes; there is no floating point and
 * no modular arithmetic on integers to get wrong.
 *
 * What Shamir does NOT give, stated so nobody assumes it:
 * - **Integrity.** A wrong or tampered share combines to a wrong secret,
 *   silently. The caller must verify the result — for the recovery key,
 *   the reconstructed bundle must reproduce the registry's key id.
 * - **Secrecy during the combine.** The M shares meet in one place and the
 *   whole secret exists there (docs/CASES.md › the honest limit).
 *
 * Share encoding (one string per person): "SH01:" + base64 of
 *   split id (16, random, the same for every share of one split)
 *   ‖ threshold M (1) ‖ x (1, 1..255) ‖ y (the secret's length)
 * The split id and threshold let `combine` refuse shares of different
 * splits or an insufficient set — mistakes, not attacks (see Integrity).
 */

import { fromBase64, toBase64 } from "../lib/encoding.ts";

// ── GF(2⁸) ───────────────────────────────────────────────────────────

const EXP = new Uint8Array(510);
const LOG = new Uint8Array(256);
{
	let v = 1;
	for (let i = 0; i < 255; i++) {
		EXP[i] = v;
		LOG[v] = i;
		// v × 0x03 = v × 0x02 ⊕ v; × 0x02 is a shift, reduced by 0x11B.
		v ^= (v << 1) ^ (v & 0x80 ? 0x11b : 0);
		v &= 0xff;
	}
	for (let i = 255; i < 510; i++) EXP[i] = EXP[i - 255]!;
}

/** a × b in GF(2⁸). */
export function gfMul(a: number, b: number): number {
	if (a === 0 || b === 0) return 0;
	return EXP[LOG[a]! + LOG[b]!]!;
}

/** a ÷ b in GF(2⁸) (b ≠ 0). */
export function gfDiv(a: number, b: number): number {
	if (b === 0) throw new Error("division by zero in GF(2^8)");
	if (a === 0) return 0;
	return EXP[LOG[a]! + 255 - LOG[b]!]!;
}

// ── split / combine ─────────────────────────────────────────────────

const PREFIX = "SH01:";

export interface Share {
	splitId: Uint8Array;
	threshold: number;
	x: number;
	y: Uint8Array;
}

/** Split `secret` into `n` shares, any `m` of which reconstruct it. */
export function split(secret: Uint8Array, m: number, n: number): string[] {
	if (!Number.isInteger(m) || !Number.isInteger(n) || m < 2 || n < m || n > 255) throw new Error("need 2 ≤ m ≤ n ≤ 255");
	if (secret.length === 0) throw new Error("nothing to share");
	const splitId = crypto.getRandomValues(new Uint8Array(16));
	const ys = Array.from({ length: n }, () => new Uint8Array(secret.length));
	const coeffs = new Uint8Array(m - 1);
	for (let i = 0; i < secret.length; i++) {
		crypto.getRandomValues(coeffs); // fresh coefficients for EVERY byte
		for (let p = 0; p < n; p++) {
			const x = p + 1;
			// Horner: P(x) = s + c1·x + … + c(m−1)·x^(m−1), from the top down.
			let acc = 0;
			for (let k = m - 2; k >= 0; k--) acc = gfMul(acc ^ coeffs[k]!, x);
			ys[p]![i] = acc ^ secret[i]!;
		}
	}
	coeffs.fill(0);
	return ys.map((y, p) => encode({ splitId, threshold: m, x: p + 1, y }));
}

/** Reconstruct the secret from at least `threshold` shares of one split.
 * Unverified by design: the caller checks what it got (see Integrity). */
export function combine(encoded: string[]): Uint8Array {
	const shares = encoded.map(decode);
	const first = shares[0];
	if (!first) throw new Error("no shares");
	const sameSplit = (s: Share) => s.splitId.length === first.splitId.length && s.splitId.every((b, i) => b === first.splitId[i]);
	if (!shares.every((s) => sameSplit(s) && s.threshold === first.threshold && s.y.length === first.y.length)) throw new Error("these shares come from different splits");
	if (new Set(shares.map((s) => s.x)).size !== shares.length) throw new Error("a share was given twice");
	if (shares.length < first.threshold) throw new Error(`${first.threshold} shares are needed, ${shares.length} were given`);
	const use = shares.slice(0, first.threshold);
	const out = new Uint8Array(first.y.length);
	// Lagrange at x = 0: s = Σ y_j · Π_{k≠j} x_k / (x_k − x_j); in GF(2⁸) "−" is XOR.
	for (let j = 0; j < use.length; j++) {
		let basis = 1;
		const sj = use[j]!;
		for (let k = 0; k < use.length; k++) if (k !== j) basis = gfMul(basis, gfDiv(use[k]!.x, use[k]!.x ^ sj.x));
		for (let i = 0; i < out.length; i++) out[i] = out[i]! ^ gfMul(sj.y[i]!, basis);
	}
	return out;
}

export function encode(s: Share): string {
	const bytes = new Uint8Array(16 + 2 + s.y.length);
	bytes.set(s.splitId, 0);
	bytes[16] = s.threshold;
	bytes[17] = s.x;
	bytes.set(s.y, 18);
	return PREFIX + toBase64(bytes);
}

export function decode(text: string): Share {
	if (!text.startsWith(PREFIX)) throw new Error("not a share");
	const bytes = fromBase64(text.slice(PREFIX.length));
	const threshold = bytes[16] ?? 0;
	const x = bytes[17] ?? 0;
	if (bytes.length < 19 || threshold < 2 || x < 1) throw new Error("not a share");
	return { splitId: bytes.slice(0, 16), threshold, x, y: bytes.slice(18) };
}
