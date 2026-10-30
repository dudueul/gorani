// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The ShimCache (AppCompatCache), read (commit 42k, docs/PREVIEWS.md ›
 * Forensic formats): SYSTEM › ControlSet › Control › Session Manager ›
 * AppCompatCache › AppCompatCache. Windows notes each program its
 * compatibility layer has looked at — the path and the file's own
 * modification time — so a program deleted long ago can still be named
 * here. On Windows 7 and 8 it also says whether the program ran.
 *
 *   Windows 7 / 2008 R2   magic 0xbadc0fee, a 128-byte header, entries of
 *                         48 bytes (x64) or 32 (x86) pointing at their path
 *   Windows 8 / 8.1       a 128-byte header, entries "00ts" / "10ts": the
 *                         path, a package name, flags, the time
 *   Windows 10 / 11       a header of 0x30 or 0x34 bytes, entries "10ts":
 *                         the path, the time, data
 *
 * Read from the layouts Mandiant's ShimCacheParser and libyal document; the
 * Windows 7 form was checked against regipy on a real SYSTEM hive. Every
 * offset is checked; at most MAX_ENTRIES entries.
 * Pure: unit:preview-facts.
 */

import { filetimeIso, Reader, Short } from "../binary/read.ts";

export interface ShimEntry {
	path: string;
	/** The file's last modification time as the cache kept it (not when it ran). */
	modified: string;
	/** Windows 7 and 8 say whether it ran; 10 and 11 do not (null). */
	executed: boolean | null;
}

export interface ShimCache {
	format: string;
	entries: ShimEntry[];
}

const MAX_ENTRIES = 4096;
const utf16 = new TextDecoder("utf-16le");

export function parseShimCache(d: Uint8Array): ShimCache | null {
	if (d.length < 16) return null;
	const r = new Reader(d);
	const entries: ShimEntry[] = [];
	try {
		const head = r.u32(0);
		if (head === 0xbadc0fee) {
			const count = Math.min(r.u32(4), MAX_ENTRIES);
			// x64 entries pad their 32-bit length pair to 8 bytes; x86 put the path's offset there.
			const x64 = r.u32(0x80 + 4) === 0;
			const size = x64 ? 48 : 32;
			for (let i = 0; i < count; i++) {
				const e = 0x80 + i * size;
				if (!r.has(e, size)) break;
				const len = r.u16(e);
				const off = x64 ? r.u32(e + 8) + r.u32(e + 12) * 2 ** 32 : r.u32(e + 4);
				const t = x64 ? e + 16 : e + 8;
				if (!r.has(off, len)) continue;
				entries.push({ path: utf16.decode(r.slice(off, len)), modified: filetimeIso(r, t), executed: !!(r.u32(t + 8) & 2) });
			}
			return { format: `Windows 7 (${x64 ? "x64" : "x86"})`, entries };
		}
		if (head === 0x30 || head === 0x34) {
			// Windows 10 / 11.
			for (let e = head; r.has(e, 12) && entries.length < MAX_ENTRIES; ) {
				if (String.fromCharCode(...r.slice(e, 4)) !== "10ts") break;
				const size = r.u32(e + 8);
				const len = r.u16(e + 12);
				const path = utf16.decode(r.slice(e + 14, len));
				entries.push({ path, modified: filetimeIso(r, e + 14 + len), executed: null });
				e += 12 + size;
			}
			return { format: "Windows 10/11", entries };
		}
		if (head === 0x80 && r.has(0x80, 4) && /^[01]0ts$/.test(String.fromCharCode(...r.slice(0x80, 4)))) {
			// Windows 8 / 8.1.
			const sig = String.fromCharCode(...r.slice(0x80, 4));
			for (let e = 0x80; r.has(e, 12) && entries.length < MAX_ENTRIES; ) {
				if (String.fromCharCode(...r.slice(e, 4)) !== sig) break;
				const size = r.u32(e + 8);
				let p = e + 12;
				const len = r.u16(p);
				const path = utf16.decode(r.slice(p + 2, len));
				p += 2 + len;
				p += 2 + r.u16(p); // the package name
				const flags = r.u32(p);
				entries.push({ path, modified: filetimeIso(r, p + 8), executed: !!(flags & 2) });
				e += 12 + size;
			}
			return { format: sig === "10ts" ? "Windows 8.1" : "Windows 8", entries };
		}
		return null;
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		return entries.length ? { format: "cut short", entries } : null;
	}
}
