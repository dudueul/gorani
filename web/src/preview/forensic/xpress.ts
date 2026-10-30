// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Xpress Huffman ("LZ77+Huffman", [MS-XCA] 2.1–2.2; commit 42i): how Windows 10 and
 * later compress a Prefetch file (after a "MAM\x04" header and its size).
 *
 * The output comes in blocks of 65,536 bytes. Each block starts with its
 * Huffman table — 512 code lengths, four bits each — then a bit stream read
 * sixteen bits at a time (two words primed). A symbol below 256 is a
 * literal; 256 and up is a match: its low four bits a length (15: read a
 * byte, then 255: a 16-bit word, from the byte stream itself), its high
 * bits how many bits of offset follow.
 *
 * Every read is bounds-checked; the output stops at the declared size.
 * Pure: unit:preview-facts.
 */

/** Canonical Huffman decoding as a 32,768-entry lookup (codes are at most 15 bits). */
function table(lengths: Uint8Array): Uint16Array | null {
	const lookup = new Uint16Array(1 << 15).fill(0xffff);
	let code = 0;
	let any = false;
	for (let len = 1; len <= 15; len++) {
		for (let sym = 0; sym < 512; sym++) {
			if (lengths[sym] !== len) continue;
			any = true;
			const span = 1 << (15 - len);
			const start = code << (15 - len);
			if (start + span > lookup.length) return null; // more codes than the length allows: not a valid table
			lookup.fill(sym | (len << 9), start, start + span);
			code++;
		}
		code <<= 1;
	}
	return any ? lookup : null;
}

export function xpressHuffman(src: Uint8Array, size: number): Uint8Array | null {
	if (size < 0 || size > 512 * 1024 * 1024) return null;
	const out = new Uint8Array(size);
	let o = 0;
	let at = 0;
	const word = () => {
		if (at + 2 > src.length) {
			at = src.length + 2; // past the end: zeros, and the caller stops
			return 0;
		}
		const w = src[at]! | (src[at + 1]! << 8);
		at += 2;
		return w;
	};
	while (o < size) {
		if (at + 256 + 4 > src.length) return null;
		const lengths = new Uint8Array(512);
		for (let i = 0; i < 256; i++) {
			lengths[2 * i] = src[at + i]! & 15;
			lengths[2 * i + 1] = src[at + i]! >> 4;
		}
		at += 256;
		const lookup = table(lengths);
		if (!lookup) return null;
		let bits = ((word() << 16) | word()) >>> 0;
		let have = 32;
		const skip = (n: number) => {
			bits = (bits << n) >>> 0;
			have -= n;
			if (have < 16) {
				bits = (bits | (word() << (16 - have))) >>> 0;
				have += 16;
			}
		};
		const blockEnd = Math.min(size, o + 65536);
		while (o < blockEnd) {
			if (at > src.length + 4) return null; // read past the end: damaged
			const entry = lookup[bits >>> 17]!;
			if (entry === 0xffff) return null;
			const sym = entry & 511;
			skip(entry >> 9);
			if (sym < 256) {
				out[o++] = sym;
				continue;
			}
			let length = sym & 15;
			const offsetBits = (sym >> 4) & 15;
			const offset = ((1 << offsetBits) | (offsetBits ? bits >>> (32 - offsetBits) : 0)) >>> 0;
			if (length === 15) {
				if (at >= src.length) return null;
				length = src[at++]! + 15;
				if (length === 270) {
					if (at + 2 > src.length) return null;
					length = src[at]! | (src[at + 1]! << 8);
					at += 2;
				}
			}
			skip(offsetBits);
			length += 3;
			if (offset > o) return null;
			for (let k = 0; k < length && o < size; k++, o++) out[o] = out[o - offset]!;
		}
	}
	return out;
}
