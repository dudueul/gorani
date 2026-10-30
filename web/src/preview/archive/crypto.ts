// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The two ciphers archives use (commit 42e, docs/PREVIEWS.md › Archives),
 * for decrypting an entry the person gave a password for — inside the
 * preview frame's worker, never in the app:
 *
 *   ZipCrypto   PKWARE's traditional cipher (ZIP, ALZ, EGG "ZIP 2.0"): weak,
 *               and the one malware is still swapped in — "infected"
 *   WinZip AES  AES-128/256 in CTR mode with a little-endian counter from
 *               1, keys from PBKDF2-HMAC-SHA1 (1000 rounds), a two-byte
 *               password check and a 10-byte HMAC-SHA1 over the ciphertext
 *               (ZIP's AE-1/AE-2; EGG's AES uses the same scheme)
 *
 * AES and SHA-1 are @noble's (Paul Miller, MIT): pure code, synchronous,
 * the same in the worker and in Node. Pure: unit:preview-facts.
 */

import { ecb } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";

const CRC_TABLE = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();

export function crc32(data: Uint8Array, crc = 0): number {
	let c = ~crc >>> 0;
	for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
	return ~c >>> 0;
}

/** A password's bytes as archivers use them: UTF-8 (the ASCII "infected"
 * is the same in every encoding). */
export const passwordBytes = (p: string) => new TextEncoder().encode(p);

class ZipKeys {
	k0 = 0x12345678;
	k1 = 0x23456789;
	k2 = 0x34567890;
	constructor(password: Uint8Array) {
		for (const b of password) this.update(b);
	}
	update(b: number): void {
		this.k0 = CRC_TABLE[(this.k0 ^ b) & 0xff]! ^ (this.k0 >>> 8);
		this.k1 = (Math.imul((this.k1 + (this.k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
		this.k2 = CRC_TABLE[(this.k2 ^ (this.k1 >>> 24)) & 0xff]! ^ (this.k2 >>> 8);
	}
	byte(): number {
		const t = (this.k2 | 2) & 0xffff;
		return (Math.imul(t, t ^ 1) >>> 8) & 0xff;
	}
}

/**
 * ZipCrypto: decrypt the 12-byte header then the data. Returns the data,
 * or null when the header's check byte says the password is wrong
 * (`check` is the byte it must end in: the CRC's high byte, or the DOS
 * time's for an entry written with a data descriptor). A 1-in-256 wrong
 * password passes that check; the caller's CRC check of the result is
 * what finally proves it.
 */
export function zipDecrypt(password: string, header: Uint8Array, data: Uint8Array, check: number | number[]): Uint8Array | null {
	const keys = new ZipKeys(passwordBytes(password));
	let last = 0;
	for (const b of header.subarray(0, 12)) {
		last = b ^ keys.byte();
		keys.update(last);
	}
	if (!(Array.isArray(check) ? check : [check]).includes(last)) return null;
	const out = new Uint8Array(data.length);
	for (let i = 0; i < data.length; i++) {
		const p = data[i]! ^ keys.byte();
		keys.update(p);
		out[i] = p;
	}
	return out;
}

/**
 * WinZip AES: `salt` (8 bytes for AES-128, 16 for AES-256), the stored
 * 2-byte password verifier, the ciphertext and its 10-byte MAC. Returns
 * the plaintext; null for a wrong password; throws when the MAC does not
 * match (the data was changed, or the password collided with the check).
 */
export function winzipAesDecrypt(password: string, bits: 128 | 256, salt: Uint8Array, verifier: Uint8Array, data: Uint8Array, mac: Uint8Array | null): Uint8Array | null {
	const k = bits / 8;
	const derived = pbkdf2(sha1, passwordBytes(password), salt, { c: 1000, dkLen: 2 * k + 2 });
	if (derived[2 * k] !== verifier[0] || derived[2 * k + 1] !== verifier[1]) return null;
	const key = derived.subarray(0, k);
	if (mac) {
		const want = hmac(sha1, derived.subarray(k, 2 * k), data).subarray(0, 10);
		if (want.some((b, i) => b !== mac[i])) throw new Error("its authentication code does not match: the data was changed, or the password is wrong");
	}
	// CTR, the counter little-endian in the block's first bytes, from 1:
	// every counter block made at once, encrypted in one ECB pass.
	const blocks = Math.ceil(data.length / 16);
	const counters = new Uint8Array(blocks * 16);
	const view = new DataView(counters.buffer);
	for (let i = 0; i < blocks; i++) {
		const n = i + 1;
		view.setUint32(i * 16, n >>> 0, true);
		view.setUint32(i * 16 + 4, Math.floor(n / 2 ** 32), true);
	}
	const stream = ecb(key, { disablePadding: true }).encrypt(counters);
	const out = new Uint8Array(data.length);
	for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ stream[i]!;
	return out;
}
