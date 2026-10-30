// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A Windows shortcut (.lnk), read from Microsoft's [MS-SHLLINK] (commit
 * 42i, docs/PREVIEWS.md › Forensic formats). Since Office blocked macros
 * from the internet, a shortcut in a ZIP or an ISO is how much malware
 * starts: its target is an interpreter (cmd, PowerShell, mshta), its
 * arguments the payload, its icon a PDF's. And every shortcut Windows
 * makes is evidence: the target's path and times, the volume's serial,
 * the machine's name and network card it was made on.
 *
 *   header        flags, the target's attributes, times and size, the
 *                 window it opens (minimized?), a hot key
 *   IDList        the target as shell items (drive, folders, file names)
 *   LinkInfo      the target as a path: local (drive type, serial, label)
 *                 or on a share (\\server\share)
 *   strings       name, relative path, working folder, ARGUMENTS, icon
 *   extra data    the environment-variable target, the tracker (machine
 *                 name, and in its object IDs the MAC address and time),
 *                 the special or known folder, a shim, a property store
 *   after the end anything appended (a payload riding the shortcut)
 *
 * Pure: unit:preview-facts.
 */

import { latin1, Reader, Short } from "../binary/read.ts";

export interface LnkInfo {
	flags: string[];
	target: string | null;
	/** The target as the shell items say (when LinkInfo is absent, or to compare). */
	idListPath: string | null;
	arguments: string | null;
	workingDir: string | null;
	relativePath: string | null;
	name: string | null;
	icon: string | null;
	iconIndex: number;
	envTarget: string | null;
	iconEnv: string | null;
	window: "normal" | "maximized" | "minimized" | `show ${number}`;
	hotKey: string | null;
	runAsAdmin: boolean;
	attributes: string[];
	times: { created: Date | null; accessed: Date | null; written: Date | null };
	size: number;
	volume: { type: string; serial: string; label: string } | null;
	share: { net: string; device: string | null } | null;
	tracker: { machine: string; mac: string | null; birthMac: string | null; time: Date | null; volumeId: string; fileId: string } | null;
	knownFolder: string | null;
	shim: string | null;
	blocks: string[];
	/** Bytes after the terminal block. */
	appended: { offset: number; size: number } | null;
	warnings: string[];
}

const CLSID = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
export const isLnk = (b: Uint8Array) => b.length >= 76 && b[0] === 0x4c && b[1] === 0 && b[2] === 0 && b[3] === 0 && CLSID.every((x, i) => b[4 + i] === x);

const FLAGS: [number, string][] = [
	[0x1, "has an ID list"], [0x2, "has link info"], [0x4, "has a name"], [0x8, "has a relative path"], [0x10, "has a working folder"], [0x20, "has arguments"], [0x40, "has an icon"],
	[0x80, "Unicode"], [0x100, "no link info"], [0x200, "has an environment target"], [0x400, "runs in a separate process"], [0x1000, "has a Darwin (MSI) ID"], [0x2000, "runs as administrator"],
	[0x4000, "has an environment icon"], [0x20000, "runs with a shim"], [0x40000, "no link tracking"], [0x80000, "target metadata"],
];
const ATTRS: [number, string][] = [[0x1, "read-only"], [0x2, "hidden"], [0x4, "system"], [0x10, "folder"], [0x20, "archive"], [0x80, "normal"], [0x100, "temporary"], [0x400, "reparse point"], [0x800, "compressed"], [0x2000, "not indexed"], [0x4000, "encrypted"]];
const DRIVES = ["unknown", "no root", "removable", "fixed", "network", "CD-ROM", "RAM disk"];
const BLOCKS: Record<number, string> = { 0xa0000001: "environment target", 0xa0000002: "console", 0xa0000003: "tracker", 0xa0000004: "console code page", 0xa0000005: "special folder", 0xa0000006: "Darwin (MSI)", 0xa0000007: "environment icon", 0xa0000008: "shim", 0xa0000009: "property store", 0xa000000b: "known folder", 0xa000000c: "Vista ID list" };

/** A FILETIME (100 ns since 1601) as a Date, or null for zero and the absurd. */
export function filetime(r: Reader, at: number): Date | null {
	const lo = r.u32(at);
	const hi = r.u32(at + 4);
	if (!lo && !hi) return null;
	const ms = (hi * 4294967296 + lo) / 10000 - 11644473600000;
	return ms > -2208988800000 && ms < 7258118400000 ? new Date(Math.round(ms)) : null;
}

const guidAt = (r: Reader, at: number) => {
	const h = (n: number, w: number) => n.toString(16).padStart(w, "0");
	const b = r.slice(at, 16);
	return `${h(r.u32(at), 8)}-${h(r.u16(at + 4), 4)}-${h(r.u16(at + 6), 4)}-${[...b.subarray(8, 10)].map((x) => h(x, 2)).join("")}-${[...b.subarray(10, 16)].map((x) => h(x, 2)).join("")}`;
};

/** A version-1 UUID's node is the MAC address of the machine that made it, and its time when. */
function uuidV1(r: Reader, at: number): { mac: string | null; time: Date | null } {
	const version = r.u16(at + 6) >> 12;
	if (version !== 1) return { mac: null, time: null };
	const mac = [...r.slice(at + 10, 6)].map((x) => x.toString(16).padStart(2, "0")).join(":");
	const ticks = (r.u16(at + 6) & 0x0fff) * 2 ** 48 + r.u16(at + 4) * 2 ** 32 + r.u32(at);
	const ms = ticks / 10000 - 12219292800000; // since 1582-10-15
	return { mac, time: ms > 0 && ms < 7258118400000 ? new Date(Math.round(ms)) : null };
}

export function parseLnk(b: Uint8Array): LnkInfo | null {
	if (!isLnk(b)) return null;
	const r = new Reader(b);
	const warnings: string[] = [];
	const flags = r.u32(20);
	const attrs = r.u32(24);
	const show = r.u32(60);
	const hk = r.u16(64);
	const info: LnkInfo = {
		flags: FLAGS.filter(([f]) => flags & f).map(([, n]) => n),
		target: null,
		idListPath: null,
		arguments: null,
		workingDir: null,
		relativePath: null,
		name: null,
		icon: null,
		iconIndex: r.u32(56) | 0,
		envTarget: null,
		iconEnv: null,
		window: show === 1 ? "normal" : show === 3 ? "maximized" : show === 7 ? "minimized" : `show ${show}`,
		hotKey: hk ? hotKey(hk) : null,
		runAsAdmin: !!(flags & 0x2000),
		attributes: ATTRS.filter(([f]) => attrs & f).map(([, n]) => n),
		times: { created: filetime(r, 28), accessed: filetime(r, 36), written: filetime(r, 44) },
		size: r.u32(52),
		volume: null,
		share: null,
		tracker: null,
		knownFolder: null,
		shim: null,
		blocks: [],
		appended: null,
		warnings,
	};
	let at = 76;
	try {
		if (flags & 0x1) {
			const size = r.u16(at);
			info.idListPath = idList(r, at + 2, at + 2 + size);
			at += 2 + size;
		}
		if (flags & 0x2 && !(flags & 0x100)) {
			const size = r.u32(at);
			linkInfo(r, at, info);
			at += size;
		}
		const unicode = !!(flags & 0x80);
		const str = (): string => {
			const n = r.u16(at);
			const bytes = n * (unicode ? 2 : 1);
			if (!r.has(at + 2, bytes)) throw new Short("a string");
			const s = unicode ? new TextDecoder("utf-16le").decode(r.slice(at + 2, bytes)) : latin1(r.slice(at + 2, bytes));
			at += 2 + bytes;
			return s;
		};
		if (flags & 0x4) info.name = str();
		if (flags & 0x8) info.relativePath = str();
		if (flags & 0x10) info.workingDir = str();
		if (flags & 0x20) info.arguments = str();
		if (flags & 0x40) info.icon = str();
		// Extra data blocks, until the terminal one (a size below 4).
		for (let i = 0; i < 64; i++) {
			const size = r.u32(at);
			if (size < 4) {
				at += 4;
				break;
			}
			const sig = r.u32(at + 4);
			info.blocks.push(BLOCKS[sig] ?? `block 0x${sig.toString(16)}`);
			if (!r.has(at, size)) {
				warnings.push("an extra data block runs past the end");
				break;
			}
			if ((sig === 0xa0000001 || sig === 0xa0000007) && size >= 0x314) {
				const ansi = r.cstr(at + 8, 260);
				const wide = new TextDecoder("utf-16le").decode(r.slice(at + 268, 520)).replace(/\0[\s\S]*$/, "");
				if (sig === 0xa0000001) info.envTarget = wide || ansi || null;
				else info.iconEnv = wide || ansi || null;
			} else if (sig === 0xa0000003 && size >= 0x60) {
				const born = uuidV1(r, at + 0x40 + 16);
				const now = uuidV1(r, at + 0x30);
				info.tracker = { machine: r.cstr(at + 16, 16), mac: now.mac, birthMac: born.mac, time: born.time ?? now.time, volumeId: guidAt(r, at + 0x20), fileId: guidAt(r, at + 0x30) };
			} else if (sig === 0xa000000b && size >= 0x1c) info.knownFolder = guidAt(r, at + 8);
			else if (sig === 0xa0000008) info.shim = new TextDecoder("utf-16le").decode(r.slice(at + 8, size - 8)).replace(/\0[\s\S]*$/, "") || null;
			at += size;
		}
		if (at < b.length) info.appended = { offset: at, size: b.length - at };
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		warnings.push(`it is cut short (${e.message})`);
	}
	info.target = info.target ?? info.envTarget ?? info.idListPath;
	return info;
}

function hotKey(hk: number): string {
	const key = hk & 0xff;
	const mods = hk >> 8;
	const name = key >= 0x30 && key <= 0x5a ? String.fromCharCode(key) : key >= 0x70 && key <= 0x87 ? `F${key - 0x6f}` : `key 0x${key.toString(16)}`;
	return [mods & 2 ? "Ctrl" : "", mods & 4 ? "Alt" : "", mods & 1 ? "Shift" : "", name].filter(Boolean).join("+");
}

function linkInfo(r: Reader, at: number, info: LnkInfo): void {
	const header = r.u32(at + 4);
	const flags = r.u32(at + 8);
	const volOff = r.u32(at + 12);
	const baseOff = r.u32(at + 16);
	const netOff = r.u32(at + 20);
	const suffixOff = r.u32(at + 24);
	const wide = (o: number) => {
		let s = "";
		for (let p = o; r.has(p, 2) && s.length < 1024; p += 2) {
			const c = r.u16(p);
			if (!c) break;
			s += String.fromCharCode(c);
		}
		return s;
	};
	const baseUni = header >= 0x24 ? r.u32(at + 28) : 0;
	const suffixUni = header >= 0x24 ? r.u32(at + 32) : 0;
	const suffix = suffixUni ? wide(at + suffixUni) : suffixOff ? r.cstr(at + suffixOff, 1024) : "";
	if (flags & 1 && volOff) {
		const v = at + volOff;
		const labelOff = r.u32(v + 12);
		const label = labelOff === 0x14 ? wide(v + r.u32(v + 16)) : r.cstr(v + labelOff, 256);
		const serial = r.u32(v + 8).toString(16).toUpperCase().padStart(8, "0");
		info.volume = { type: DRIVES[r.u32(v + 4)] ?? "unknown", serial: `${serial.slice(0, 4)}-${serial.slice(4)}`, label };
		const base = baseUni ? wide(at + baseUni) : r.cstr(at + baseOff, 1024);
		info.target = base + suffix;
	}
	if (flags & 2 && netOff) {
		const n = at + netOff;
		const nameOff = r.u32(n + 8);
		const devOff = r.u32(n + 12);
		const netUni = nameOff > 0x14 ? r.u32(n + 20) : 0;
		const devUni = nameOff > 0x14 ? r.u32(n + 24) : 0;
		const net = netUni ? wide(n + netUni) : r.cstr(n + nameOff, 1024);
		const dev = devUni ? wide(n + devUni) : devOff ? r.cstr(n + devOff, 64) : "";
		info.share = { net, device: dev || null };
		info.target ??= `${net}${suffix ? `\\${suffix}` : ""}`;
	}
}

/** The target as shell items: the drive, then each folder's and file's
 * name (its long name from the BEEF0004 extension when there is one). */
function idList(r: Reader, start: number, end: number): string | null {
	const parts: string[] = [];
	let at = start;
	for (let i = 0; i < 64 && at + 2 <= end; i++) {
		const size = r.u16(at);
		if (size < 2) break;
		const type = r.u8(at + 2);
		if ((type & 0x70) === 0x20 && size >= 5) {
			// A volume: "C:\".
			const s = r.cstr(at + 3, Math.min(20, size - 3));
			if (/^[A-Za-z]:\\?$/.test(s)) parts.push(s.replace(/\\?$/, ""));
		} else if ((type & 0x70) === 0x30 && size > 14) {
			// A file or folder: its 8.3 name, then (from Windows XP on) its long name.
			const short = r.cstr(at + 14, size - 14);
			parts.push(longName(r, at, size) ?? short);
		}
		at += size;
	}
	if (!parts.length) return null;
	return parts.join("\\").replace(/^\\+/, "");
}

function longName(r: Reader, item: number, size: number): string | null {
	// Find the BEEF0004 extension block inside the item; its long name is
	// the first UTF-16 string after its fixed fields.
	for (let p = item + 14; p + 8 <= item + size; p += 2) {
		if (r.u32(p + 4) !== 0xbeef0004) continue;
		const extSize = r.u16(p);
		const version = r.u16(p + 2);
		const nameAt = p + (version >= 9 ? 0x2e : version >= 7 ? 0x2a : version >= 3 ? 0x12 : 0x12);
		let s = "";
		for (let q = nameAt; q + 2 <= p + extSize && s.length < 260; q += 2) {
			const c = r.u16(q);
			if (!c) break;
			s += String.fromCharCode(c);
		}
		return s && /^[\x20-\uffff]+$/.test(s) ? s : null;
	}
	return null;
}
