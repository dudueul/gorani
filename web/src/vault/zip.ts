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
 * `zipEntries` writes whole buffers: no ZIP64 — every entry and the whole
 * archive stay under 4 GiB (refused above, with a message); no data
 * descriptors (sizes and CRCs are known before writing, so each local
 * header is complete — which is also what lets ZipCrypto's check byte be
 * the CRC's high byte). `ZipStream` (D12) writes what never fits in
 * memory: data descriptors and ZIP64, streamed.
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

// ── The streaming writer (D12, docs/LARGE-FILES.md › 31d) ─────────────

/** Where a streamed zip's bytes go, in order; awaited, so the reader sets the pace. */
export type ZipSink = (bytes: Uint8Array) => Promise<void>;

/** An entry's content, written through `write` as it is produced. */
export type ZipProducer = (write: (bytes: Uint8Array) => Promise<void>) => Promise<void>;

const U32 = 0xffffffff;

/**
 * A zip written as it goes — for archives that never fit in memory (a
 * case export of 255 GB images). Each entry's bytes stream through once;
 * its CRC and sizes follow it in a **data descriptor** (general-purpose
 * bit 3), and **ZIP64** fields appear wherever a size, an offset or the
 * entry count needs them (or always, with `forceZip64` — how the tests
 * prove the ZIP64 paths without writing 4 GiB).
 *
 * With bit 3, ZipCrypto's check byte is the high byte of the DOS time
 * (the CRC is not known when the encryption header is written) — the
 * convention Info-ZIP and Python's zipfile read.
 *
 * Nesting is composition: a ZipStream whose sink is an outer entry's
 * `write` is a zip inside a zip (a sample's "infected" zip in an export).
 */
export class ZipStream {
	private offset = 0;
	private central: Uint8Array[] = [];
	private count = 0;
	private names = new Set<string>();
	private finished = false;
	private readonly enc = new TextEncoder();

	private readonly sink: ZipSink;
	private readonly opts: { forceZip64?: boolean; random?: (n: number) => Uint8Array };

	// (Fields assigned by hand, not as parameter properties: Node runs this
	// module with types stripped, and parameter properties are not types.)
	constructor(sink: ZipSink, opts: { forceZip64?: boolean; random?: (n: number) => Uint8Array } = {}) {
		this.sink = sink;
		this.opts = opts;
	}

	private async emit(bytes: Uint8Array): Promise<void> {
		this.offset += bytes.length;
		await this.sink(bytes);
	}

	/**
	 * Add one stored entry. `size` (the plaintext's, when known) decides
	 * whether the local header announces ZIP64; unknown is treated as large.
	 * Returns the entry's CRC-32 and size, as written.
	 */
	async add(name: string, produce: ZipProducer, { password, modified = new Date(), size }: { password?: string; modified?: Date; size?: number } = {}): Promise<{ crc: number; size: number }> {
		if (this.finished) throw new Error("the zip is already finished");
		const clean = name.replace(/\\/g, "/").replace(/^\/+/, "");
		if (!clean || clean.split("/").some((s) => s === ".." || s === "")) throw new Error(`a zip entry needs a plain relative name: “${name}”`);
		if (this.names.has(clean)) throw new Error(`two zip entries are named “${clean}”`);
		this.names.add(clean);
		const nameBytes = this.enc.encode(clean);
		const { time, date } = dosTime(modified);
		const encrypted = password !== undefined;
		const zip64 = this.opts.forceZip64 === true || size === undefined || size + (encrypted ? 12 : 0) >= U32;
		const flags = 0x0800 | 0x0008 | (encrypted ? 0x0001 : 0); // UTF-8 · data descriptor · encrypted
		const localAt = this.offset;

		// The local header: CRC and sizes zero (they follow the data); with
		// ZIP64, 0xFFFFFFFF and a ZIP64 extra holding zeros for both sizes.
		const extra = zip64 ? new Uint8Array(20) : new Uint8Array(0);
		if (zip64) {
			const xv = new DataView(extra.buffer);
			xv.setUint16(0, 0x0001, true);
			xv.setUint16(2, 16, true);
		}
		const local = new Uint8Array(30 + nameBytes.length + extra.length);
		const lv = new DataView(local.buffer);
		lv.setUint32(0, 0x04034b50, true);
		lv.setUint16(4, zip64 ? 45 : 20, true);
		lv.setUint16(6, flags, true);
		lv.setUint16(8, 0, true); // stored
		lv.setUint16(10, time, true);
		lv.setUint16(12, date, true);
		lv.setUint32(14, 0, true);
		lv.setUint32(18, zip64 ? U32 : 0, true);
		lv.setUint32(22, zip64 ? U32 : 0, true);
		lv.setUint16(26, nameBytes.length, true);
		lv.setUint16(28, extra.length, true);
		local.set(nameBytes, 30);
		local.set(extra, 30 + nameBytes.length);
		await this.emit(local);

		// The data: CRC over the PLAINTEXT, sizes counted as it passes.
		let crc = 0xffffffff;
		let plainSize = 0;
		let cipher: ZipCrypto | null = null;
		if (encrypted) {
			cipher = new ZipCrypto(this.enc.encode(password));
			const head = new Uint8Array(12);
			head.set((this.opts.random ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n))))(11).subarray(0, 11));
			head[11] = (time >>> 8) & 0xff; // bit 3: the check byte is the time's high byte
			cipher.encrypt(head);
			await this.emit(head);
		}
		await produce(async (bytes) => {
			for (const b of bytes) crc = crcStep(crc, b);
			plainSize += bytes.length;
			if (cipher) {
				const out = bytes.slice();
				cipher.encrypt(out);
				await this.emit(out);
			} else {
				await this.emit(bytes);
			}
		});
		crc = (crc ^ 0xffffffff) >>> 0;
		const stored = plainSize + (encrypted ? 12 : 0);
		if (!zip64 && stored >= U32) throw new Error(`“${clean}” grew past what its header announced (4 GiB without ZIP64)`);

		// The data descriptor: what the local header could not say.
		const dd = new Uint8Array(zip64 ? 24 : 16);
		const dv = new DataView(dd.buffer);
		dv.setUint32(0, 0x08074b50, true);
		dv.setUint32(4, crc, true);
		if (zip64) {
			dv.setBigUint64(8, BigInt(stored), true);
			dv.setBigUint64(16, BigInt(plainSize), true);
		} else {
			dv.setUint32(8, stored, true);
			dv.setUint32(12, plainSize, true);
		}
		await this.emit(dd);

		// Its central directory entry, with ZIP64 fields for whatever overflows.
		const big = (n: number) => this.opts.forceZip64 === true || n >= U32;
		const fields: number[] = [];
		if (big(plainSize)) fields.push(plainSize);
		if (big(stored)) fields.push(stored);
		if (big(localAt)) fields.push(localAt);
		const cx = fields.length ? new Uint8Array(4 + 8 * fields.length) : new Uint8Array(0);
		if (fields.length) {
			const xv = new DataView(cx.buffer);
			xv.setUint16(0, 0x0001, true);
			xv.setUint16(2, 8 * fields.length, true);
			fields.forEach((v, i) => xv.setBigUint64(4 + 8 * i, BigInt(v), true));
		}
		const cd = new Uint8Array(46 + nameBytes.length + cx.length);
		const cv = new DataView(cd.buffer);
		cv.setUint32(0, 0x02014b50, true);
		cv.setUint16(4, 45, true);
		cv.setUint16(6, fields.length || zip64 ? 45 : 20, true);
		cv.setUint16(8, flags, true);
		cv.setUint16(12, time, true);
		cv.setUint16(14, date, true);
		cv.setUint32(16, crc, true);
		cv.setUint32(20, big(stored) ? U32 : stored, true);
		cv.setUint32(24, big(plainSize) ? U32 : plainSize, true);
		cv.setUint16(28, nameBytes.length, true);
		cv.setUint16(30, cx.length, true);
		cv.setUint32(42, big(localAt) ? U32 : localAt, true);
		cd.set(nameBytes, 46);
		cd.set(cx, 46 + nameBytes.length);
		this.central.push(cd);
		this.count++;
		return { crc, size: plainSize };
	}

	/** A whole buffer as an entry. */
	addBytes(name: string, data: Uint8Array, opts: { password?: string; modified?: Date } = {}): Promise<{ crc: number; size: number }> {
		return this.add(name, (write) => write(data), { ...opts, size: data.length });
	}

	/**
	 * A folder entry, `name/` with no data (41a, a Download as zip): an empty
	 * folder keeps its place in the tree. The MS-DOS directory attribute is
	 * set, as Explorer and Info-ZIP write folders. No data descriptor:
	 * nothing follows the header.
	 */
	async addFolder(name: string, { modified = new Date() }: { modified?: Date } = {}): Promise<void> {
		if (this.finished) throw new Error("the zip is already finished");
		const clean = name.replace(/\\/g, "/").replace(/^\/+/, "").replace(/\/+$/, "");
		if (!clean || clean.split("/").some((s) => s === ".." || s === "")) throw new Error(`a zip folder needs a plain relative name: “${name}”`);
		const key = `${clean}/`;
		if (this.names.has(key)) return;
		this.names.add(key);
		const nameBytes = this.enc.encode(key);
		const { time, date } = dosTime(modified);
		const localAt = this.offset;
		const local = new Uint8Array(30 + nameBytes.length);
		const lv = new DataView(local.buffer);
		lv.setUint32(0, 0x04034b50, true);
		lv.setUint16(4, 20, true);
		lv.setUint16(6, 0x0800, true); // UTF-8
		lv.setUint16(10, time, true);
		lv.setUint16(12, date, true);
		lv.setUint16(26, nameBytes.length, true);
		local.set(nameBytes, 30);
		await this.emit(local);
		const big = this.opts.forceZip64 === true || localAt >= U32;
		const cx = big ? new Uint8Array(12) : new Uint8Array(0);
		if (big) {
			const xv = new DataView(cx.buffer);
			xv.setUint16(0, 0x0001, true);
			xv.setUint16(2, 8, true);
			xv.setBigUint64(4, BigInt(localAt), true);
		}
		const cd = new Uint8Array(46 + nameBytes.length + cx.length);
		const cv = new DataView(cd.buffer);
		cv.setUint32(0, 0x02014b50, true);
		cv.setUint16(4, 45, true);
		cv.setUint16(6, big ? 45 : 20, true);
		cv.setUint16(8, 0x0800, true);
		cv.setUint16(12, time, true);
		cv.setUint16(14, date, true);
		cv.setUint16(28, nameBytes.length, true);
		cv.setUint16(30, cx.length, true);
		cv.setUint32(38, 0x10, true); // external attributes: MS-DOS directory
		cv.setUint32(42, big ? U32 : localAt, true);
		cd.set(nameBytes, 46);
		cd.set(cx, 46 + nameBytes.length);
		this.central.push(cd);
		this.count++;
	}

	/** The central directory and its end records (ZIP64 when anything overflows). */
	async finish(): Promise<void> {
		if (this.finished) return;
		this.finished = true;
		const cdAt = this.offset;
		for (const c of this.central) await this.emit(c);
		const cdSize = this.offset - cdAt;
		const zip64 = this.opts.forceZip64 === true || this.count > 0xffff || cdAt >= U32 || cdSize >= U32;
		if (zip64) {
			const eocd64At = this.offset;
			const r = new Uint8Array(56);
			const rv = new DataView(r.buffer);
			rv.setUint32(0, 0x06064b50, true);
			rv.setBigUint64(4, 44n, true); // the record's size after this field
			rv.setUint16(12, 45, true);
			rv.setUint16(14, 45, true);
			rv.setBigUint64(24, BigInt(this.count), true);
			rv.setBigUint64(32, BigInt(this.count), true);
			rv.setBigUint64(40, BigInt(cdSize), true);
			rv.setBigUint64(48, BigInt(cdAt), true);
			await this.emit(r);
			const loc = new Uint8Array(20);
			const lv = new DataView(loc.buffer);
			lv.setUint32(0, 0x07064b50, true);
			lv.setBigUint64(8, BigInt(eocd64At), true);
			lv.setUint32(16, 1, true);
			await this.emit(loc);
		}
		const end = new Uint8Array(22);
		const ev = new DataView(end.buffer);
		ev.setUint32(0, 0x06054b50, true);
		ev.setUint16(8, zip64 ? 0xffff : this.count, true);
		ev.setUint16(10, zip64 ? 0xffff : this.count, true);
		ev.setUint32(12, zip64 ? U32 : cdSize, true);
		ev.setUint32(16, zip64 ? U32 : cdAt, true);
		await this.emit(end);
	}
}
