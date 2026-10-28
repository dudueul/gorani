// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A ZIP reader for the preview frame (commit 42b, docs/PREVIEWS.md).
 *
 * Word, Excel, PowerPoint (OOXML), HWPX and OpenDocument files are ZIP
 * archives of XML parts. The rendering libraries unzip them on their own
 * (JSZip, inside docx-preview and pptx-preview; SheetJS's own); this file is
 * how the READERS look inside first, for two reasons:
 *
 *   1. Facts. What a security team wants to know about an Office file is
 *      in its structure, not on its pages: a macro project, a template
 *      fetched from a server, an embedded object, a link to a credential
 *      page. Those are parts and relationships (office.ts reads them).
 *
 *   2. Bombs. A ZIP says, in its directory, how big each part is once
 *      inflated — and nothing makes it tell the truth. 42 kB that inflate
 *      to 4.5 PB is the classic. Before any library is handed the file,
 *      `check` inflates EVERY part as a stream, counting, and refuses the
 *      file if a part grows past what the directory said, or the whole
 *      past MAX_TOTAL. Memory stays small while counting: the input goes
 *      in 16 kB at a time, and each piece of output is counted and
 *      dropped. A refused file is never handed to the library, which
 *      would otherwise hold it all at once (and take the tab down).
 *
 * Only what Office and HWPX use is supported: stored (0) and deflate (8),
 * ZIP64 sizes, no encryption. Anything else is reported, not guessed at.
 */

import { Inflate } from "fflate";

/** One part, as the central directory describes it. */
export interface ZipEntry {
	name: string;
	method: number;
	/** Bytes in the file (compressed). */
	packed: number;
	/** Bytes once inflated, as the directory CLAIMS. */
	size: number;
	/** Where its local header starts. */
	at: number;
	encrypted: boolean;
}

/** The most a whole archive may inflate to here: 1 GiB. An honest 256 MB
 * Office file (the viewer's whole-read cap) inflates to a few times that
 * at most; SheetJS and JSZip could not hold more in a tab anyway. */
export const MAX_TOTAL = 1024 * 1024 * 1024;
/** And one part: V8's longest string is about 512 MiB, so no XML part
 * bigger than this could be read as text by any of the libraries. */
export const MAX_PART = 512 * 1024 * 1024;
/** No real document has this many parts; a ZIP that claims more is a trap. */
const MAX_ENTRIES = 50_000;

const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
const u64 = (b: Uint8Array, o: number) => u32(b, o) + u32(b, o + 4) * 2 ** 32;

export class Zip {
	readonly entries: ZipEntry[];
	private byName = new Map<string, ZipEntry>();
	private bytes: Uint8Array;

	private constructor(bytes: Uint8Array, entries: ZipEntry[]) {
		this.bytes = bytes;
		this.entries = entries;
		for (const e of entries) if (!this.byName.has(e.name)) this.byName.set(e.name, e);
	}

	/** Is this a ZIP at all? (The first bytes of a local header.) */
	static is(bytes: Uint8Array): boolean {
		return bytes.length >= 4 && u32(bytes, 0) === 0x04034b50;
	}

	/** Read the central directory; null when this is not a ZIP we can read. */
	static open(bytes: Uint8Array): Zip | null {
		if (bytes.length < 22) return null;
		// The end record is in the last 64 kB + 22 bytes (its comment is at most 64 kB).
		let eocd = -1;
		for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 0xffff); i--) {
			if (u32(bytes, i) === 0x06054b50) {
				eocd = i;
				break;
			}
		}
		if (eocd < 0) return null;
		let count = u16(bytes, eocd + 10);
		let dirAt = u32(bytes, eocd + 16);
		// ZIP64: the real numbers are in a record of their own, found by a locator just before.
		if ((count === 0xffff || dirAt === 0xffffffff) && eocd >= 20 && u32(bytes, eocd - 20) === 0x07064b50) {
			const z64 = u64(bytes, eocd - 12);
			if (z64 + 56 <= bytes.length && u32(bytes, z64) === 0x06064b50) {
				count = u64(bytes, z64 + 32);
				dirAt = u64(bytes, z64 + 48);
			}
		}
		if (count > MAX_ENTRIES) return null;
		const entries: ZipEntry[] = [];
		const utf8 = new TextDecoder("utf-8");
		const cp437ish = new TextDecoder("windows-1252");
		let p = dirAt;
		for (let n = 0; n < count; n++) {
			if (p + 46 > bytes.length || u32(bytes, p) !== 0x02014b50) return null;
			const flags = u16(bytes, p + 8);
			const method = u16(bytes, p + 10);
			let packed = u32(bytes, p + 20);
			let size = u32(bytes, p + 24);
			const nameLen = u16(bytes, p + 28);
			const extraLen = u16(bytes, p + 30);
			const commentLen = u16(bytes, p + 32);
			let at = u32(bytes, p + 42);
			const nameBytes = bytes.subarray(p + 46, p + 46 + nameLen);
			// Bit 11: the name is UTF-8. Otherwise it is in the old DOS code
			// page — Office always sets the bit; HWPX writers sometimes do not.
			const name = (flags & 0x800 ? utf8 : cp437ish).decode(nameBytes);
			// ZIP64's extra field holds whichever of the three was too big.
			let x = p + 46 + nameLen;
			const xEnd = x + extraLen;
			while (x + 4 <= xEnd) {
				const id = u16(bytes, x);
				const len = u16(bytes, x + 2);
				if (id === 0x0001) {
					let q = x + 4;
					if (size === 0xffffffff && q + 8 <= x + 4 + len) (size = u64(bytes, q)), (q += 8);
					if (packed === 0xffffffff && q + 8 <= x + 4 + len) (packed = u64(bytes, q)), (q += 8);
					if (at === 0xffffffff && q + 8 <= x + 4 + len) at = u64(bytes, q);
				}
				x += 4 + len;
			}
			entries.push({ name, method, packed, size, at, encrypted: (flags & 1) === 1 });
			p = xEnd + commentLen;
		}
		return new Zip(bytes, entries);
	}

	names(): string[] {
		return this.entries.map((e) => e.name);
	}

	has(name: string): boolean {
		return this.byName.has(name);
	}

	/** Where a part's data starts: after ITS OWN local header, whose name
	 * and extra field can differ in length from the directory's. */
	private dataAt(e: ZipEntry): number | null {
		if (e.at + 30 > this.bytes.length || u32(this.bytes, e.at) !== 0x04034b50) return null;
		const start = e.at + 30 + u16(this.bytes, e.at + 26) + u16(this.bytes, e.at + 28);
		return start + e.packed <= this.bytes.length ? start : null;
	}

	/**
	 * Inflate one part, handing each piece of output to `sink`; stops
	 * (throws) past `cap` bytes. Returns the true inflated size.
	 */
	private inflate(e: ZipEntry, cap: number, sink?: (chunk: Uint8Array) => void): number {
		if (e.encrypted) throw new ZipRefused(`${e.name} is encrypted`);
		const start = this.dataAt(e);
		if (start === null) throw new ZipRefused(`${e.name} is cut short`);
		const data = this.bytes.subarray(start, start + e.packed);
		if (e.method === 0) {
			if (data.length > cap) throw new ZipRefused(`${e.name} is too big`);
			sink?.(data);
			return data.length;
		}
		if (e.method !== 8) throw new ZipRefused(`${e.name} uses a compression this reader does not have (${e.method})`);
		let total = 0;
		const inf = new Inflate((chunk) => {
			total += chunk.length;
			if (total > cap) throw new ZipRefused(`${e.name} inflates past ${Math.round(cap / 1048576)} MB`);
			sink?.(chunk);
		});
		const STEP = 16 * 1024;
		for (let i = 0; i < data.length; i += STEP) inf.push(data.subarray(i, Math.min(data.length, i + STEP)), i + STEP >= data.length);
		if (data.length === 0) inf.push(new Uint8Array(0), true);
		return total;
	}

	/** A part's bytes, or null when it is missing, unreadable or over `cap`. */
	bytesOf(name: string, cap = 64 * 1024 * 1024): Uint8Array | null {
		const e = this.byName.get(name);
		if (!e || e.size > cap) return null;
		const chunks: Uint8Array[] = [];
		try {
			const n = this.inflate(e, cap, (c) => chunks.push(c.slice()));
			const out = new Uint8Array(n);
			let o = 0;
			for (const c of chunks) {
				out.set(c, o);
				o += c.length;
			}
			return out;
		} catch {
			return null;
		}
	}

	/** A part as UTF-8 text (the XML parts), or null. */
	text(name: string, cap = 64 * 1024 * 1024): string | null {
		const b = this.bytesOf(name, cap);
		return b ? new TextDecoder("utf-8").decode(b) : null;
	}

	/**
	 * Inflate everything, counting: null when the archive is what it says
	 * it is, or why it is refused. Run before any library sees the file.
	 */
	check(): string | null {
		let claimed = 0;
		for (const e of this.entries) claimed += e.size;
		if (claimed > MAX_TOTAL) return `it would inflate to ${Math.round(claimed / 1048576)} MB`;
		let total = 0;
		try {
			for (const e of this.entries) {
				if (e.name.endsWith("/") && e.packed === 0) continue;
				// A little slack over the claim (a few writers round), never more.
				const cap = Math.min(MAX_PART, e.size + 1024);
				total += this.inflate(e, cap);
				if (total > MAX_TOTAL) return `it inflates past ${MAX_TOTAL / 1048576} MB`;
			}
		} catch (err) {
			return err instanceof ZipRefused ? err.message : `it is damaged (${err instanceof Error ? err.message : String(err)})`;
		}
		return null;
	}
}

/** Why a part was not inflated (as opposed to a bug). */
class ZipRefused extends Error {}

/**
 * Raw DEFLATE data (no ZIP around it — a 한글 BodyText stream), inflated
 * as a stream and stopped past `cap`: null when it is damaged or too big.
 */
export function inflateCapped(data: Uint8Array, cap: number): Uint8Array | null {
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		const inf = new Inflate((chunk) => {
			total += chunk.length;
			if (total > cap) throw new ZipRefused("too big");
			chunks.push(chunk.slice());
		});
		const STEP = 16 * 1024;
		for (let i = 0; i < data.length; i += STEP) inf.push(data.subarray(i, Math.min(data.length, i + STEP)), i + STEP >= data.length);
	} catch {
		return null;
	}
	const out = new Uint8Array(total);
	let o = 0;
	for (const c of chunks) {
		out.set(c, o);
		o += c.length;
	}
	return out;
}
