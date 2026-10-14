// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Malware samples — docs/CUSTODY.md › Stage 5 (D8, commit 29e).
 *
 * Two jobs live here, both small and both pure (Node-testable):
 *
 * 1. **The client's own mark.** A sample's sealed type (each version's
 *    `file.type` place, GV04) is `application/x-gorani-sample;
 *    original=<the real mime>`. The server also keeps a readable flag
 *    (it enforces "no share links"), but a server can clear its own flag —
 *    it cannot re-seal a type. So the client treats a file as a sample when
 *    EITHER mark says so: the only direction a lying server can push is
 *    "more careful".
 *
 * 2. **The zip.** Samples leave this app only as a ZIP encrypted with the
 *    password `infected` — the industry's convention (MalwareBazaar,
 *    VirusShare, vendor exchanges), so desktop antivirus does not
 *    quarantine the sample mid-investigation and a double-click does not
 *    run it. The encryption is "traditional PKWARE" (ZipCrypto, APPNOTE
 *    6.1), stored (no compression): the one format every unzip tool and
 *    Windows Explorer open. It is NOT confidentiality — ZipCrypto is broken
 *    and the password is public — it is a seatbelt for the last metre.
 *
 * The honest limits: one file per zip, at most 4 GiB − 13 bytes (no ZIP64;
 * refused above, with a message). Samples are rarely large.
 */

export const SAMPLE_MIME = "application/x-gorani-sample";
export const SAMPLE_PASSWORD = "infected";

/** The sealed type of a sample's version, keeping the original for display. */
export function sampleType(original: string | null | undefined): string {
	return `${SAMPLE_MIME}; original=${encodeURIComponent(original || "application/octet-stream")}`;
}

/** Does an (opened) type mark a sample? */
export function isSampleType(type: string | null | undefined): boolean {
	return !!type && (type === SAMPLE_MIME || type.startsWith(`${SAMPLE_MIME};`));
}

/** The type the sample had before it was marked (display only — never used to render). */
export function originalType(type: string): string {
	const m = /;\s*original=([^;]*)/.exec(type);
	try {
		return m?.[1] ? decodeURIComponent(m[1]) : "application/octet-stream";
	} catch {
		return "application/octet-stream";
	}
}

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

/**
 * One file in a ZipCrypto zip under `password` (default "infected"), stored.
 * `random` supplies the 11 random bytes of the encryption header (a test
 * passes a fixed one). Returns the zip's parts — a Blob of parts is not a
 * copy of the sample.
 */
export function zipEncrypted(name: string, plain: Uint8Array, { password = SAMPLE_PASSWORD, modified = new Date(), random = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)) }: { password?: string; modified?: Date; random?: (n: number) => Uint8Array } = {}): Uint8Array[] {
	if (plain.length > MAX_ZIP_ENTRY) throw new Error("this sample is larger than a zip without ZIP64 can hold (4 GiB) — not zipped");
	const enc = new TextEncoder();
	const nameBytes = enc.encode(name.replace(/[\\/]/g, "_") || "sample");
	const crc = crc32(plain);
	const { time, date } = dosTime(modified);
	// The 12-byte encryption header: 11 random bytes, then the CRC's high
	// byte — the check a reader uses to reject a wrong password (no data
	// descriptor, so bit 3 is clear and the CRC is known up front).
	const header = new Uint8Array(12);
	header.set(random(11).subarray(0, 11));
	header[11] = crc >>> 24;
	const body = new Uint8Array(12 + plain.length);
	body.set(header);
	body.set(plain, 12);
	new ZipCrypto(enc.encode(password)).encrypt(body);

	const FLAGS = 0x0001 | 0x0800; // encrypted | UTF-8 name
	const local = new Uint8Array(30 + nameBytes.length);
	const lv = new DataView(local.buffer);
	lv.setUint32(0, 0x04034b50, true);
	lv.setUint16(4, 20, true); // version needed: 2.0
	lv.setUint16(6, FLAGS, true);
	lv.setUint16(8, 0, true); // method: stored
	lv.setUint16(10, time, true);
	lv.setUint16(12, date, true);
	lv.setUint32(14, crc, true);
	lv.setUint32(18, body.length, true); // compressed = header + data
	lv.setUint32(22, plain.length, true);
	lv.setUint16(26, nameBytes.length, true);
	lv.setUint16(28, 0, true); // no extra field
	local.set(nameBytes, 30);

	const central = new Uint8Array(46 + nameBytes.length);
	const cv = new DataView(central.buffer);
	cv.setUint32(0, 0x02014b50, true);
	cv.setUint16(4, 20, true); // made by: 2.0, MS-DOS attributes
	cv.setUint16(6, 20, true);
	cv.setUint16(8, FLAGS, true);
	cv.setUint16(10, 0, true);
	cv.setUint16(12, time, true);
	cv.setUint16(14, date, true);
	cv.setUint32(16, crc, true);
	cv.setUint32(20, body.length, true);
	cv.setUint32(24, plain.length, true);
	cv.setUint16(28, nameBytes.length, true);
	// extra 0, comment 0, disk 0, internal 0, external 0, local header at 0
	central.set(nameBytes, 46);

	const end = new Uint8Array(22);
	const ev = new DataView(end.buffer);
	ev.setUint32(0, 0x06054b50, true);
	ev.setUint16(8, 1, true); // entries on this disk
	ev.setUint16(10, 1, true); // entries in all
	ev.setUint32(12, central.length, true);
	ev.setUint32(16, local.length + body.length, true); // where the directory starts
	return [local, body, central, end];
}
