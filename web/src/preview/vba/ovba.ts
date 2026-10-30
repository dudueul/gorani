// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * VBA's own compression and obfuscation (commit 42h, docs/PREVIEWS.md ›
 * Macros), from Microsoft's published specification [MS-OVBA]:
 *
 *   decompress   2.4.1: a signature byte (1), then chunks of at most 4096
 *                bytes, each a run of flag bytes and tokens — a literal
 *                byte, or a copy of earlier output (offset and length,
 *                their split depending on how far into the chunk it is)
 *   decrypt      2.4.3: the "encryption" of the PROJECT stream's CMG, DPB
 *                and GC values — a seed and an XOR chain, obfuscation
 *                rather than secrecy. DPB says whether a password locks
 *                the project in the VBA editor (it does not lock the
 *                source: the source is only compressed, and read here).
 *
 * Every read is bounds-checked and the output capped: a container that
 * claims more than it holds ends with what it held.
 * Pure: unit:preview-facts.
 */

/** The most a module's source may decompress to (a real one is kilobytes). */
export const MAX_SOURCE = 16 * 1024 * 1024;

export function decompress(b: Uint8Array, cap = MAX_SOURCE): Uint8Array | null {
	if (!b.length || b[0] !== 1) return null;
	const out = new Uint8Array(Math.min(cap, Math.max(4096, b.length * 8)));
	let size = 0;
	let buf = out;
	const put = (x: number) => {
		if (size === buf.length) {
			if (size >= cap) return false;
			const bigger = new Uint8Array(Math.min(cap, buf.length * 2));
			bigger.set(buf);
			buf = bigger;
		}
		buf[size++] = x;
		return true;
	};
	let at = 1;
	while (at + 2 <= b.length) {
		const header = b[at]! | (b[at + 1]! << 8);
		const chunkEnd = Math.min(b.length, at + (header & 0x0fff) + 3);
		const compressed = (header & 0x8000) !== 0;
		if (((header >> 12) & 7) !== 3) break; // not a chunk header: the container ends here
		at += 2;
		const chunkStart = size;
		if (!compressed) {
			// A raw chunk: 4096 bytes as they are.
			for (let i = 0; i < 4096 && at < b.length; i++) if (!put(b[at++]!)) return buf.subarray(0, size);
			continue;
		}
		while (at < chunkEnd) {
			const flags = b[at++]!;
			for (let bit = 0; bit < 8 && at < chunkEnd; bit++) {
				if (!(flags & (1 << bit))) {
					if (!put(b[at++]!)) return buf.subarray(0, size);
					continue;
				}
				if (at + 2 > chunkEnd) {
					at = chunkEnd;
					break;
				}
				const token = b[at]! | (b[at + 1]! << 8);
				at += 2;
				const difference = size - chunkStart;
				const bitCount = Math.max(4, Math.ceil(Math.log2(Math.max(1, difference))));
				const lengthMask = 0xffff >> bitCount;
				const length = (token & lengthMask) + 3;
				const offset = (token >> (16 - bitCount)) + 1;
				if (offset > difference) return buf.subarray(0, size); // points before the chunk: damaged
				for (let k = 0; k < length; k++) if (!put(buf[size - offset]!)) return buf.subarray(0, size);
			}
		}
		at = chunkEnd;
	}
	return buf.subarray(0, size);
}

/** [MS-OVBA] 2.4.3.3: a PROJECT stream value (CMG, DPB, GC) decrypted —
 * its data, or null when it does not decrypt (a version that is not 2). */
export function decryptValue(hex: string): Uint8Array | null {
	if (!/^(?:[0-9a-f]{2})+$/i.test(hex) || hex.length < 6) return null;
	const enc = Uint8Array.from(hex.match(/../g)!.map((x) => parseInt(x, 16)));
	const seed = enc[0]!;
	const versionEnc = enc[1]!;
	const projKeyEnc = enc[2]!;
	if ((seed ^ versionEnc) !== 2) return null;
	const projKey = seed ^ projKeyEnc;
	let unencrypted1 = projKey;
	let encrypted1 = projKeyEnc;
	let encrypted2 = versionEnc;
	let at = 3;
	const next = (): number | null => {
		if (at >= enc.length) return null;
		const byteEnc = enc[at++]!;
		const byte = byteEnc ^ ((encrypted2 + unencrypted1) & 0xff);
		encrypted2 = encrypted1;
		encrypted1 = byteEnc;
		unencrypted1 = byte;
		return byte;
	};
	for (let i = 0; i < (seed & 6) / 2; i++) if (next() === null) return null;
	let length = 0;
	for (let i = 0; i < 4; i++) {
		const x = next();
		if (x === null) return null;
		length |= x << (8 * i);
	}
	if (length < 0 || length > enc.length) return null;
	const data = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		const x = next();
		if (x === null) return null;
		data[i] = x;
	}
	return data;
}
