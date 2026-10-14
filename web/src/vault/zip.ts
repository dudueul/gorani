// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A minimal ZIP writer (APPNOTE 6.3): stored entries (no compression),
 * UTF-8 names, and — per entry — optional "traditional PKWARE" encryption
 * (ZipCrypto). Two users: a malware sample's "infected" zip (samples.ts,
 * commit 29e) and the signed export package (export.ts, commit 29h).
 *
 * Why stored, never deflated: evidence must come out byte for byte, and a
 * recipient's `sha256sum` must work on what they unzip; compression would
 * add a decoder to trust and buy little on images that are already
 * compressed or encrypted.
 *
 * The honest limits: no ZIP64 — every entry and the whole archive stay
 * under 4 GiB (refused above, with a message); one disk; no data
 * descriptors (sizes and CRCs are known before writing, so each local
 * header is complete — which is also what lets ZipCrypto's check byte be
 * the CRC's high byte).
 */

// ── CRC-32 (IEEE 802.3, the zip one) ──────────────────────────────────

const CRC_TABLE = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();

/** One byte into a running (un-inverted) CRC register — ZipCrypto's step. */
const crcStep = (crc: number, b: number) => ((CRC_TABLE[(crc ^ b) & 0xff] ?? 0) ^ (crc >>> 8)) >>> 0;

/** CRC-32 of a whole buffer (the zip header's field). */
export function crc32(bytes: Uint8Array): number {
	let c = 0xffffffff;
	for (const b of bytes) c = crcStep(c, b);
	return (c ^ 0xffffffff) >>> 0;
}

// ── ZipCrypto (APPNOTE 6.1 "Traditional PKWARE Encryption") ───────────

class ZipCrypto {
	private k0 = 0x12345678;
	private k1 = 0x23456789;
	private k2 = 0x34567890;

	constructor(password: Uint8Array) {
		for (const b of password) this.update(b);
	}

	private update(b: number): void {
		this.k0 = crcStep(this.k0, b);
		this.k1 = (this.k1 + (this.k0 & 0xff)) >>> 0;
		this.k1 = (Math.imul(this.k1, 134775813) + 1) >>> 0;
		this.k2 = crcStep(this.k2, this.k1 >>> 24);
	}

	private keystream(): number {
		const t = (this.k2 | 2) & 0xffff;
		return ((t * (t ^ 1)) >>> 8) & 0xff;
	}

	/** Encrypt in place; the keys advance on the PLAINTEXT byte. */
	encrypt(buf: Uint8Array): void {
		for (let i = 0; i < buf.length; i++) {
			const p = buf[i] ?? 0;
			buf[i] = p ^ this.keystream();
			this.update(p);
		}
	}
}

/** MS-DOS date and time, as zip headers carry them (2-second resolution). */
function dosTime(d: Date): { time: number; date: number } {
	const year = Math.max(1980, d.getFullYear());
	return {
		time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
		date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
	};
}

/** Largest plaintext a non-ZIP64 encrypted entry can hold (size + 12-byte header ≤ 0xFFFFFFFF). */
export const MAX_ZIP_ENTRY = 0xffffffff - 12;

export interface ZipEntry {
	/** The path inside the archive ("evidence/abc/v1/disk.E01"); `/` separates folders. */
	name: string;
	data: Uint8Array;
	/** ZipCrypto under this password (the sample convention), or stored in the clear. */
	password?: string;
	modified?: Date;
}

/**
 * Write a zip. Returns its parts (a Blob of parts is not a copy).
 * `random` supplies each encrypted entry's 11 random header bytes (a test
 * passes a fixed one).
 */
export function zipEntries(entries: ZipEntry[], { random = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)) }: { random?: (n: number) => Uint8Array } = {}): Uint8Array[] {
	const enc = new TextEncoder();
	const parts: Uint8Array[] = [];
	const central: Uint8Array[] = [];
	let offset = 0;
	const seen = new Set<string>();
	for (const e of entries) {
		const name = e.name.replace(/\\/g, "/").replace(/^\/+/, "");
		if (!name || name.split("/").some((s) => s === ".." || s === "")) throw new Error(`a zip entry needs a plain relative name: “${e.name}”`);
		if (seen.has(name)) throw new Error(`two zip entries are named “${name}”`);
		seen.add(name);
		if (e.data.length > MAX_ZIP_ENTRY) throw new Error(`“${name}” is larger than a zip without ZIP64 can hold (4 GiB)`);
		const nameBytes = enc.encode(name);
		const crc = crc32(e.data);
		const { time, date } = dosTime(e.modified ?? new Date());
		let body: Uint8Array;
		let flags = 0x0800; // UTF-8 name
		if (e.password !== undefined) {
			// The 12-byte encryption header: 11 random bytes, then the CRC's
			// high byte — the check a reader uses to reject a wrong password.
			body = new Uint8Array(12 + e.data.length);
			body.set(random(11).subarray(0, 11));
			body[11] = crc >>> 24;
			body.set(e.data, 12);
			new ZipCrypto(enc.encode(e.password)).encrypt(body);
			flags |= 0x0001;
		} else {
			body = e.data;
		}
		const local = new Uint8Array(30 + nameBytes.length);
		const lv = new DataView(local.buffer);
		lv.setUint32(0, 0x04034b50, true);
		lv.setUint16(4, 20, true); // version needed: 2.0
		lv.setUint16(6, flags, true);
		lv.setUint16(8, 0, true); // method: stored
		lv.setUint16(10, time, true);
		lv.setUint16(12, date, true);
		lv.setUint32(14, crc, true);
		lv.setUint32(18, body.length, true);
		lv.setUint32(22, e.data.length, true);
		lv.setUint16(26, nameBytes.length, true);
		local.set(nameBytes, 30);

		const cd = new Uint8Array(46 + nameBytes.length);
		const cv = new DataView(cd.buffer);
		cv.setUint32(0, 0x02014b50, true);
		cv.setUint16(4, 20, true); // made by: 2.0, MS-DOS attributes
		cv.setUint16(6, 20, true);
		cv.setUint16(8, flags, true);
		cv.setUint16(12, time, true);
		cv.setUint16(14, date, true);
		cv.setUint32(16, crc, true);
		cv.setUint32(20, body.length, true);
		cv.setUint32(24, e.data.length, true);
		cv.setUint16(28, nameBytes.length, true);
		cv.setUint32(42, offset, true); // where its local header is
		cd.set(nameBytes, 46);

		parts.push(local, body);
		central.push(cd);
		offset += local.length + body.length;
		if (offset > 0xffffffff) throw new Error("this archive is larger than a zip without ZIP64 can hold (4 GiB)");
	}
	const cdSize = central.reduce((n, c) => n + c.length, 0);
	if (entries.length > 0xffff) throw new Error("too many entries for a zip without ZIP64 (65 535)");
	const end = new Uint8Array(22);
	const ev = new DataView(end.buffer);
	ev.setUint32(0, 0x06054b50, true);
	ev.setUint16(8, entries.length, true); // entries on this disk
	ev.setUint16(10, entries.length, true); // entries in all
	ev.setUint32(12, cdSize, true);
	ev.setUint32(16, offset, true); // where the directory starts
	return [...parts, ...central, end];
}
