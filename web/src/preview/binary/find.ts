// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Find in a binary (commit 42g): the hex reader's search, forward or back
 * from where the person is, wrapping round the file. `indexOf` on the
 * first byte (native, fast) and a compare for the rest: a 256 MB file is
 * searched in well under a second.
 *
 * Pure: unit:preview-facts.
 */

/** The next (or previous) place `needle` occurs at or after (before)
 * `from`, wrapping round the file; -1 when it is nowhere. */
export function findBytes(hay: Uint8Array, needle: Uint8Array, from: number, dir: 1 | -1): number {
	const n = needle.length;
	if (!n || n > hay.length) return -1;
	const first = needle[0]!;
	const matchAt = (i: number) => {
		for (let k = 1; k < n; k++) if (hay[i + k] !== needle[k]) return false;
		return true;
	};
	if (dir > 0) {
		for (const [a, z] of [[Math.max(0, from), hay.length - n], [0, Math.min(from - 1, hay.length - n)]] as const) {
			for (let i = hay.indexOf(first, a); i >= 0 && i <= z; i = hay.indexOf(first, i + 1)) if (matchAt(i)) return i;
		}
	} else {
		// (A negative start means "before the beginning": straight to the
		// wrap. lastIndexOf would read a negative index from the END.)
		const start = Math.min(from, hay.length - n);
		for (const [a, z] of [[start, 0], [hay.length - n, Math.max(0, start + 1)]] as const) {
			if (a < 0) continue;
			for (let i = hay.lastIndexOf(first, a); i >= z && i >= 0; i = i > 0 ? hay.lastIndexOf(first, i - 1) : -1) if (matchAt(i)) return i;
		}
	}
	return -1;
}
