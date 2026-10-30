// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A Windows registry hive (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT,
 * UsrClass.dat, Amcache.hve), read (commit 42k, docs/PREVIEWS.md ›
 * Forensic formats) from the format as libregf and Microsoft's own notes
 * describe it:
 *
 *   base block   "regf", two sequence numbers (unequal: Windows was still
 *                writing — the .LOG files hold the rest), the last write,
 *                the root key's offset, the file name it had, an XOR
 *                checksum of itself
 *   hive bins    "hbin", 4 KiB multiples, holding cells
 *   cells        a size (negative: in use; positive: free — and what a
 *                free cell still holds is what was deleted), then a record:
 *                nk (a key: its name, last write, subkey and value lists),
 *                vk (a value: name, type, data), lf / lh / li / ri (subkey
 *                lists: leaves with hashes, or an index of lists), db (big
 *                data, in segments), sk (security)
 *
 * Read lazily: a key's subkeys and values only when asked for, so a 40 MB
 * SOFTWARE hive of 200,000 keys opens at once. Every offset is checked
 * (it must land on a cell inside the bins); every list is capped; a list
 * that points back into itself is followed once.
 * Pure: unit:preview-facts.
 */

import { filetimeIso, Reader, Short, trimNul } from "../binary/read.ts";

export interface RegKey {
	/** Its cell's offset (from the first bin): what identifies it. */
	off: number;
	name: string;
	/** Its last write, ISO 8601 to Windows' 100 ns; "" when zero. */
	written: string;
	subkeyCount: number;
	valueCount: number;
	className: string;
	/** Its parent's offset, as the key says. */
	parent: number;
}

export interface RegValue {
	/** Its vk cell's offset (from the first bin). */
	off: number;
	/** "" for the key's default value. */
	name: string;
	type: number;
	/** REG_SZ, REG_DWORD…, or the number for a type Windows does not name. */
	typeName: string;
	/** The data's size as the value claims it. */
	size: number;
	/** The data (at most MAX_DATA bytes of it); null when it could not be read. */
	data: Uint8Array | null;
	/** The data as text, as regedit shows it. */
	text: string;
}

export interface DeletedKey {
	name: string;
	written: string;
	off: number;
}

export const isHive = (b: Uint8Array) => b.length >= 4096 && b[0] === 0x72 && b[1] === 0x65 && b[2] === 0x67 && b[3] === 0x66; // "regf"

const TYPES = ["REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD"];
/** Of a value's data, this much is kept (a value can be megabytes). */
export const MAX_DATA = 1024 * 1024;
const MAX_SUBKEYS = 100_000;
const MAX_VALUES = 20_000;
/** Where the first hive bin starts: cell offsets count from here. */
export const BIN = 4096;

const latin1 = new TextDecoder("latin1");
const utf16 = new TextDecoder("utf-16le");

export class Hive {
	readonly r: Reader;
	/** The name the hive had where Windows kept it ("\??\C:\Windows\System32\config\SYSTEM"…). */
	readonly fileName: string;
	readonly written: string;
	readonly version: string;
	/** The two sequence numbers differ: changes still in the .LOG files. */
	readonly dirty: boolean;
	readonly checksumOk: boolean;
	readonly root: RegKey;
	readonly warnings: string[] = [];
	/** Where the bins end (the base block's count, bounded by the file). */
	private readonly end: number;
	private readonly minor: number;

	constructor(b: Uint8Array) {
		const r = (this.r = new Reader(b));
		let x = 0;
		for (let i = 0; i < 508; i += 4) x ^= r.u32(i);
		x >>>= 0;
		const want = x === 0xffffffff ? 0xfffffffe : x === 0 ? 1 : x;
		this.checksumOk = want === r.u32(508);
		this.dirty = r.u32(4) !== r.u32(8);
		this.written = filetimeIso(r, 12);
		this.minor = r.u32(24);
		this.version = `${r.u32(20)}.${this.minor}`;
		this.fileName = trimNul(utf16.decode(r.slice(48, 64))).replace(/\0[\s\S]*$/, "");
		const size = r.u32(40);
		this.end = Math.min(b.length, BIN + (size > 0 && size % BIN === 0 ? size : b.length - BIN));
		if (BIN + size > b.length) this.warnings.push(`its bins should run to ${(BIN + size).toLocaleString("en")} bytes; the file has ${b.length.toLocaleString("en")} (cut short)`);
		if (!this.checksumOk) this.warnings.push("its base block does not match its checksum");
		this.root = this.key(r.u32(36));
	}

	/** A cell's data: where it starts and how long it is (throws Short when it is not a cell in use). */
	private cell(off: number): { at: number; len: number } {
		const at = BIN + off;
		if (!Number.isInteger(off) || off < 32 || at + 4 > this.end) throw new Short(`a cell at 0x${off.toString(16)}`);
		const size = new DataView(this.r.b.buffer, this.r.b.byteOffset + at, 4).getInt32(0, true);
		if (size >= 0) throw new Short(`a cell in use at 0x${off.toString(16)} (it is free)`);
		const len = -size - 4;
		if (at + 4 + len > this.end || len < 2) throw new Short(`a cell of ${-size} bytes at 0x${off.toString(16)}`);
		return { at: at + 4, len };
	}

	private sig(at: number): string {
		return String.fromCharCode(this.r.u8(at), this.r.u8(at + 1));
	}

	/** The key whose nk cell is at `off`. */
	key(off: number): RegKey {
		const { at, len } = this.cell(off);
		const r = this.r;
		if (this.sig(at) !== "nk" || len < 76) throw new Short(`a key at 0x${off.toString(16)}`);
		const flags = r.u16(at + 2);
		const nameLen = Math.min(r.u16(at + 72), len - 76);
		const raw = r.slice(at + 76, nameLen);
		const classLen = r.u16(at + 74);
		let className = "";
		if (classLen) {
			try {
				const c = this.cell(r.u32(at + 48));
				className = utf16.decode(r.slice(c.at, Math.min(classLen, c.len)));
			} catch (e) {
				if (!(e instanceof Short)) throw e;
			}
		}
		return {
			off,
			name: flags & 0x20 ? latin1.decode(raw) : utf16.decode(raw),
			written: filetimeIso(r, at + 4),
			subkeyCount: r.u32(at + 20),
			valueCount: r.u32(at + 36),
			className,
			parent: r.u32(at + 16),
		};
	}

	/** A key's subkeys, in the order their list holds them (Windows keeps them sorted). */
	subkeys(k: RegKey): RegKey[] {
		if (!k.subkeyCount) return [];
		const { at } = this.cell(k.off);
		const out: RegKey[] = [];
		const seen = new Set<number>();
		const walk = (listOff: number, depth: number) => {
			if (depth > 8 || seen.has(listOff) || out.length >= MAX_SUBKEYS) return;
			seen.add(listOff);
			const l = this.cell(listOff);
			const s = this.sig(l.at);
			const n = Math.min(this.r.u16(l.at + 2), MAX_SUBKEYS);
			const step = s === "lf" || s === "lh" ? 8 : s === "li" || s === "ri" ? 4 : 0;
			if (!step) throw new Short(`a subkey list at 0x${listOff.toString(16)}`);
			for (let i = 0; i < n && 4 + (i + 1) * step <= l.len && out.length < MAX_SUBKEYS; i++) {
				const o = this.r.u32(l.at + 4 + i * step);
				if (s === "ri") walk(o, depth + 1);
				else {
					try {
						out.push(this.key(o));
					} catch (e) {
						if (!(e instanceof Short)) throw e;
						this.warn(`a subkey of ${k.name} could not be read (${e.message})`);
					}
				}
			}
		};
		try {
			walk(this.r.u32(at + 28), 0);
		} catch (e) {
			if (!(e instanceof Short)) throw e;
			this.warn(`the subkeys of ${k.name} could not be read (${e.message})`);
		}
		return out;
	}

	/** A key's values. */
	values(k: RegKey): RegValue[] {
		if (!k.valueCount) return [];
		const out: RegValue[] = [];
		try {
			const { at } = this.cell(k.off);
			const list = this.cell(this.r.u32(at + 40));
			const n = Math.min(k.valueCount, MAX_VALUES, Math.floor(list.len / 4));
			for (let i = 0; i < n; i++) {
				try {
					out.push(this.value(this.r.u32(list.at + i * 4)));
				} catch (e) {
					if (!(e instanceof Short)) throw e;
					this.warn(`a value of ${k.name} could not be read (${e.message})`);
				}
			}
		} catch (e) {
			if (!(e instanceof Short)) throw e;
			this.warn(`the values of ${k.name} could not be read (${e.message})`);
		}
		return out;
	}

	private value(off: number): RegValue {
		const r = this.r;
		const { at, len } = this.cell(off);
		if (this.sig(at) !== "vk" || len < 20) throw new Short(`a value at 0x${off.toString(16)}`);
		const nameLen = Math.min(r.u16(at + 2), len - 20);
		const rawSize = r.u32(at + 4);
		const type = r.u32(at + 12);
		const flags = r.u16(at + 16);
		const rawName = r.slice(at + 20, nameLen);
		const name = flags & 1 ? latin1.decode(rawName) : utf16.decode(rawName);
		const size = rawSize & 0x7fffffff;
		let data: Uint8Array | null = null;
		try {
			data = this.data(at, rawSize);
		} catch (e) {
			if (!(e instanceof Short)) throw e;
		}
		return { off, name, type, typeName: TYPES[type] ?? `type 0x${type.toString(16)}`, size, data, text: data ? render(type, data) : "(could not be read)" };
	}

	/** A value's data: in its own offset field (4 bytes or fewer), in a cell, or in big-data segments. */
	private data(vk: number, rawSize: number): Uint8Array {
		const r = this.r;
		const size = rawSize & 0x7fffffff;
		if (rawSize & 0x80000000) return r.slice(vk + 8, Math.min(size, 4));
		if (!size) return new Uint8Array(0);
		const c = this.cell(r.u32(vk + 8));
		const want = Math.min(size, MAX_DATA);
		// Big data (hive 1.4 and later): a "db" cell listing segments of 16,344 bytes.
		if (size > 16344 && this.minor >= 4 && this.sig(c.at) === "db") {
			const count = r.u16(c.at + 2);
			const list = this.cell(r.u32(c.at + 4));
			const out = new Uint8Array(want);
			let got = 0;
			for (let i = 0; i < count && got < want && 4 * (i + 1) <= list.len; i++) {
				const seg = this.cell(r.u32(list.at + i * 4));
				const n = Math.min(seg.len, 16344, want - got);
				out.set(r.slice(seg.at, n), got);
				got += n;
			}
			return out.subarray(0, got);
		}
		return r.slice(c.at, Math.min(want, c.len));
	}

	/** A subkey by name (case-insensitively, as Windows looks them up). */
	child(k: RegKey, name: string): RegKey | null {
		const n = name.toLowerCase();
		return this.subkeys(k).find((s) => s.name.toLowerCase() === n) ?? null;
	}

	/** A key by its path from the root ("Microsoft\\Windows\\CurrentVersion\\Run"). */
	path(p: string): RegKey | null {
		let k: RegKey | null = this.root;
		for (const part of p.split("\\").filter(Boolean)) {
			k = k && this.child(k, part);
			if (!k) return null;
		}
		return k;
	}

	/** One of a key's values by name ("" for the default). */
	get(k: RegKey, name: string): RegValue | null {
		const n = name.toLowerCase();
		return this.values(k).find((v) => v.name.toLowerCase() === n) ?? null;
	}

	/** The keys still in the bins' free space: deleted, not yet overwritten. */
	deleted(max = 2000): DeletedKey[] {
		const out: DeletedKey[] = [];
		const r = this.r;
		const v = new DataView(r.b.buffer, r.b.byteOffset, r.b.byteLength);
		for (let bin = BIN; bin + 32 <= this.end && out.length < max; ) {
			if (String.fromCharCode(...r.slice(bin, 4)) !== "hbin") break;
			const binSize = r.u32(bin + 8);
			if (binSize < BIN || binSize % BIN || bin + binSize > this.end) break;
			for (let at = bin + 32; at + 8 <= bin + binSize && out.length < max; ) {
				const size = v.getInt32(at, true);
				const n = Math.abs(size);
				if (n < 8 || n % 8 || at + n > bin + binSize) break;
				if (size > 0 && n >= 80 && r.u8(at + 4) === 0x6e && r.u8(at + 5) === 0x6b) {
					const nameLen = r.u16(at + 4 + 72);
					if (nameLen && 80 + nameLen <= n) {
						const raw = r.slice(at + 4 + 76, nameLen);
						out.push({ name: r.u16(at + 6) & 0x20 ? latin1.decode(raw) : utf16.decode(raw), written: filetimeIso(r, at + 8), off: at - BIN });
					}
				}
				at += n;
			}
			bin += binSize;
		}
		return out;
	}

	private warn(w: string): void {
		if (this.warnings.length < 50 && !this.warnings.includes(w)) this.warnings.push(w);
	}
}

/** Data as regedit shows it. */
export function render(type: number, d: Uint8Array): string {
	const v = new DataView(d.buffer, d.byteOffset, d.byteLength);
	switch (type) {
		case 1:
		case 2:
		case 6: {
			// A string ends at its first NUL; what follows is said, not hidden.
			const s = utf16.decode(d.length % 2 ? d.subarray(0, d.length - 1) : d);
			const cut = s.indexOf("\0");
			const rest = cut < 0 ? "" : trimNul(s.slice(cut));
			return cut < 0 ? s : `${s.slice(0, cut)}${rest.length ? ` (and ${rest.length} more characters after its end)` : ""}`;
		}
		case 7: {
			const items = utf16.decode(d.length % 2 ? d.subarray(0, d.length - 1) : d).split("\0");
			while (items.length && items.at(-1) === "") items.pop();
			return items.join("\n");
		}
		case 4:
			return d.length >= 4 ? `${v.getUint32(0, true)} (0x${v.getUint32(0, true).toString(16).padStart(8, "0")})` : hexOf(d);
		case 5:
			return d.length >= 4 ? `${v.getUint32(0, false)} (0x${v.getUint32(0, false).toString(16).padStart(8, "0")})` : hexOf(d);
		case 11:
			return d.length >= 8 ? `${v.getBigUint64(0, true)} (0x${v.getBigUint64(0, true).toString(16).padStart(16, "0")})` : hexOf(d);
		default:
			return hexOf(d);
	}
}

const hexOf = (d: Uint8Array, max = 256) => [...d.subarray(0, max)].map((x) => x.toString(16).padStart(2, "0")).join(" ") + (d.length > max ? ` … (${d.length.toLocaleString("en")} bytes)` : "");

export function parseHive(b: Uint8Array): Hive | null {
	if (!isHive(b)) return null;
	try {
		return new Hive(b);
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		return null;
	}
}
