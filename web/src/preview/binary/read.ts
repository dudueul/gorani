// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Reading a binary that may lie (commit 42g, docs/PREVIEWS.md › Programs):
 * every offset a file gives is checked before it is followed. A read past
 * the end throws `Short`, which each parser catches to say "truncated"
 * with what it had read so far; a loop a file controls (sections,
 * imports, load commands) is capped, so a header that claims a million
 * entries costs a million reads at most once and is said to.
 *
 * Pure: unit:preview-facts.
 */

export class Short extends Error {
	constructor(what: string) {
		super(`it ends before ${what}`);
	}
}

/** A string without the NULs that pad its end. Not `.replace(/\0+$/, "")`:
 * that regex tries every NUL as the start of the run, and a string of
 * thousands of NULs followed by anything else costs it millions of steps
 * (fuzzing the event-log reader found a second spent on one file). */
export function trimNul(s: string): string {
	let n = s.length;
	while (n > 0 && s.charCodeAt(n - 1) === 0) n--;
	return n === s.length ? s : s.slice(0, n);
}

/** A FILETIME (100 ns ticks since 1601) at `at`, as ISO 8601 to the tick:
 * "2016-07-08T18:16:31.1081031Z" — what Event Viewer and forensic tools
 * show. A number would lose the last digits (2^53 holds 9e15; FILETIMEs
 * are 1.3e17), so the arithmetic is BigInt. "" for zero or past 9999.
 * (Event logs, 42j; registry hives, 42k.) */
export function filetimeIso(r: Reader, at: number): string {
	const t = (BigInt(r.u32(at + 4)) << 32n) | BigInt(r.u32(at));
	if (!t) return "";
	const secs = Number(t / 10_000_000n) - 11_644_473_600;
	if (secs < -11_644_473_600 || secs > 253_402_300_799) return "";
	return `${new Date(secs * 1000).toISOString().slice(0, 19)}.${String(t % 10_000_000n).padStart(7, "0")}Z`;
}

/** Little- or big-endian reads over a byte array, each one bounds-checked. */
export class Reader {
	readonly b: Uint8Array;
	little: boolean;
	readonly length: number;
	private view: DataView;

	constructor(b: Uint8Array, little = true) {
		this.b = b;
		this.little = little;
		this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
		this.length = b.byteLength;
	}

	has(at: number, n: number): boolean {
		return Number.isInteger(at) && at >= 0 && n >= 0 && at + n <= this.length;
	}

	private need(at: number, n: number, what: string): void {
		if (!this.has(at, n)) throw new Short(what);
	}

	u8(at: number, what = "a byte"): number {
		this.need(at, 1, what);
		return this.b[at]!;
	}

	u16(at: number, what = "a 16-bit field"): number {
		this.need(at, 2, what);
		return this.view.getUint16(at, this.little);
	}

	u32(at: number, what = "a 32-bit field"): number {
		this.need(at, 4, what);
		return this.view.getUint32(at, this.little);
	}

	/** A 64-bit field as a number (exact up to 2^53; past it, near enough for an address shown). */
	u64(at: number, what = "a 64-bit field"): number {
		this.need(at, 8, what);
		return Number(this.view.getBigUint64(at, this.little));
	}

	/** A NUL-ended string of at most `max` bytes (Latin-1: names in headers are ASCII). */
	cstr(at: number, max = 256): string {
		if (!this.has(at, 1)) return "";
		let end = at;
		const stop = Math.min(this.length, at + max);
		while (end < stop && this.b[end] !== 0) end++;
		return latin1(this.b.subarray(at, end));
	}

	/** A fixed-width name padded with NULs (a PE section name, a Mach-O segment). */
	fixed(at: number, n: number): string {
		this.need(at, n, "a name");
		const s = this.b.subarray(at, at + n);
		const z = s.indexOf(0);
		return latin1(z >= 0 ? s.subarray(0, z) : s);
	}

	slice(at: number, n: number): Uint8Array {
		const from = Math.max(0, Math.min(this.length, at));
		return this.b.subarray(from, Math.max(from, Math.min(this.length, at + n)));
	}
}

export const latin1 = (b: Uint8Array): string => {
	let s = "";
	for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode(...b.subarray(i, i + 8192));
	return s;
};

/** Shannon entropy in bits per byte: 0 for one value repeated, 8 for noise.
 * Packed and encrypted code sits above 7.2; ordinary code near 6. */
export function entropy(b: Uint8Array): number {
	if (!b.length) return 0;
	const counts = new Uint32Array(256);
	for (let i = 0; i < b.length; i++) counts[b[i]!]!++;
	let h = 0;
	for (const c of counts) {
		if (!c) continue;
		const p = c / b.length;
		h -= p * Math.log2(p);
	}
	return h;
}

export const hex = (n: number, width = 0): string => `0x${n.toString(16).padStart(width, "0")}`;

/** The common names a PKCS#7 signature carries (its certificates' CNs):
 * every X.520 commonName (2.5.4.3) in the DER, read without parsing the
 * rest. Shown as "names in its signature", never as a verified signer. */
export function commonNames(der: Uint8Array, cap = 8): string[] {
	const out = new Set<string>();
	for (let i = 0; i + 7 < der.length && out.size < cap; i++) {
		if (der[i] !== 0x06 || der[i + 1] !== 0x03 || der[i + 2] !== 0x55 || der[i + 3] !== 0x04 || der[i + 4] !== 0x03) continue;
		const tag = der[i + 5]!;
		const len = der[i + 6]!;
		if (len & 0x80 || i + 7 + len > der.length) continue;
		const v = der.subarray(i + 7, i + 7 + len);
		let s = "";
		if (tag === 0x1e) for (let k = 0; k + 1 < v.length; k += 2) s += String.fromCharCode((v[k]! << 8) | v[k + 1]!);
		else if (tag === 0x0c) s = new TextDecoder().decode(v);
		else if (tag === 0x13 || tag === 0x16 || tag === 0x14) s = latin1(v);
		else continue;
		if (s.trim()) out.add(s.trim());
	}
	return [...out];
}
