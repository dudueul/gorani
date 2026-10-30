// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A Windows Prefetch file (.pf), read (commit 42i, docs/PREVIEWS.md ›
 * Forensic formats). Windows keeps one per program it has run, to start it
 * faster next time — which makes it the record of what ran: the program,
 * how many times, the last eight times, every file it touched in its first
 * seconds, and the volumes they were on. Evidence that outlives the
 * program it describes.
 *
 *   compressed    Windows 10 and 11: "MAM\x04", the size, then Xpress
 *                 Huffman (forensic/xpress.ts)
 *   SCCA          the header: format version (17 XP, 23 Vista/7, 26 8.1,
 *                 30 10, 31 11), the executable's name, the hash of its
 *                 path (the file's name repeats it)
 *   information   offsets and counts; the last run time(s); the run count
 *   metrics       one entry per file it loaded: its name's place
 *   volumes       device path, serial number, creation time, folders
 *
 * The layout follows the formats as dissect.target and libscca document
 * them. Every offset is checked; every list is capped.
 * Pure: unit:preview-facts.
 */

import { Reader, Short } from "../binary/read.ts";
import { filetime } from "./lnk.ts";
import { xpressHuffman } from "./xpress.ts";

export interface PrefetchInfo {
	version: number;
	compressed: boolean;
	exe: string;
	hash: string;
	runCount: number;
	runs: Date[];
	files: string[];
	volumes: { device: string; serial: string; created: Date | null; dirs: string[] }[];
	warnings: string[];
}

export const isPrefetch = (b: Uint8Array) => b.length >= 8 && ((b[0] === 0x4d && b[1] === 0x41 && b[2] === 0x4d && b[3] === 4) || (b[4] === 0x53 && b[5] === 0x43 && b[6] === 0x43 && b[7] === 0x41));

const MAX = 32 * 1024 * 1024;

export function parsePrefetch(input: Uint8Array): PrefetchInfo | null {
	if (!isPrefetch(input)) return null;
	let b = input;
	const compressed = input[0] === 0x4d;
	if (compressed) {
		const size = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(4, true);
		if (size > MAX) return null;
		const out = xpressHuffman(input.subarray(8), size);
		if (!out) return null;
		b = out;
	}
	const r = new Reader(b);
	const warnings: string[] = [];
	const version = r.u32(0);
	if (r.u32(4) !== 0x41434353) return null; // "SCCA"
	const info: PrefetchInfo = {
		version,
		compressed,
		exe: new TextDecoder("utf-16le").decode(r.slice(16, 60)).replace(/\0[\s\S]*$/, ""),
		hash: r.u32(76).toString(16).toUpperCase().padStart(8, "0"),
		runCount: 0,
		runs: [],
		files: [],
		volumes: [],
		warnings,
	};
	try {
		const fi = 84;
		const metricsAt = r.u32(fi);
		const metricsN = Math.min(r.u32(fi + 4), 10_000);
		const namesAt = r.u32(fi + 16);
		const namesSize = r.u32(fi + 20);
		const volAt = r.u32(fi + 24);
		const volN = Math.min(r.u32(fi + 28), 64);
		if (version === 17) {
			const t = filetime(r, fi + 36);
			if (t) info.runs.push(t);
			info.runCount = r.u32(fi + 44);
		} else if (version === 23) {
			const t = filetime(r, fi + 44);
			if (t) info.runs.push(t);
			info.runCount = r.u32(fi + 68);
		} else {
			// 26, 30, 31: the last eight run times, then the count.
			for (let i = 0; i < 8; i++) {
				const t = filetime(r, fi + 44 + i * 8);
				if (t) info.runs.push(t);
			}
			info.runCount = r.u32(fi + 124);
		}
		// The files: each metrics entry points into the filename strings.
		const entry = version === 17 ? 20 : 32;
		const names = r.slice(namesAt, namesSize);
		for (let i = 0; i < metricsN; i++) {
			const e = metricsAt + i * entry;
			if (!r.has(e, entry)) {
				warnings.push("its file list runs past the end");
				break;
			}
			const off = r.u32(e + (version === 17 ? 8 : 12));
			const chars = Math.min(r.u32(e + (version === 17 ? 12 : 16)), 1024);
			if (off + chars * 2 > names.length) continue;
			info.files.push(new TextDecoder("utf-16le").decode(names.subarray(off, off + chars * 2)));
		}
		// The volumes.
		const volSize = version === 17 ? 40 : version === 23 ? 104 : 96;
		for (let i = 0; i < volN; i++) {
			const v = volAt + i * volSize;
			if (!r.has(v, 40)) break;
			const devOff = r.u32(v);
			const devChars = Math.min(r.u32(v + 4), 512);
			const device = new TextDecoder("utf-16le").decode(r.slice(volAt + devOff, devChars * 2));
			const serial = r.u32(v + 16).toString(16).toUpperCase().padStart(8, "0");
			const dirsAt = volAt + r.u32(v + 28);
			const dirsN = Math.min(r.u32(v + 32), 1000);
			const dirs: string[] = [];
			for (let k = 0, p = dirsAt; k < dirsN && r.has(p, 2); k++) {
				const n = Math.min(r.u16(p), 1024);
				dirs.push(new TextDecoder("utf-16le").decode(r.slice(p + 2, n * 2)));
				p += 2 + (n + 1) * 2;
			}
			info.volumes.push({ device, serial: `${serial.slice(0, 4)}-${serial.slice(4)}`, created: filetime(r, v + 8), dirs });
		}
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		warnings.push(`it is cut short (${e.message})`);
	}
	return info;
}
