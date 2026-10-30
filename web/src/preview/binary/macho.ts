// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A macOS or iOS program's structure (commit 42g), read from the Mach-O
 * layout Apple publishes in <mach-o/loader.h> and <mach-o/fat.h>:
 *
 *   universal   the architectures it carries (each is a program of its own)
 *   header      32/64-bit, CPU, file type, flags (PIE, an executable stack)
 *   segments    and their sections: rights, entropy
 *   libraries   every dylib it loads (weak, re-exported, lazy), its RPATHs
 *   symbols     what it imports (undefined external symbols)
 *   signature   the code signature: ad hoc or with a certificate (its
 *               names, NOT verified), the identifier and Team ID the code
 *               directory carries, the hardened runtime
 *   the rest    encryption (App Store FairPlay), minimum OS, the entry
 *
 * Pure: unit:preview-facts.
 */

import { commonNames, entropy, Reader, Short } from "./read.ts";

export interface MachoSection {
	name: string;
	segment: string;
	offset: number;
	size: number;
	exec: boolean;
	write: boolean;
	entropy: number;
}

export interface MachoInfo {
	bits: 32 | 64;
	cpu: string;
	type: string;
	pie: boolean;
	execStack: boolean;
	sections: MachoSection[];
	libraries: { path: string; how: "" | "weak" | "re-exported" | "lazy" | "upward" }[];
	rpaths: string[];
	dylinker: string | null;
	imports: string[];
	signature: { adhoc: boolean; identifier: string | null; team: string | null; runtime: boolean; certificate: boolean; names: string[] } | null;
	encrypted: boolean;
	platform: string | null;
	minOs: string | null;
	entry: number | null;
	warnings: string[];
}

export interface MachoFile {
	/** The architectures of a universal file (one for a thin one). */
	archs: { cpu: string; offset: number; size: number }[];
	universal: boolean;
	programs: MachoInfo[];
}

const CPUS: Record<number, string> = { 7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000c: "arm64", 0x0200000c: "arm64_32", 18: "PowerPC", 0x01000012: "PowerPC 64" };
const TYPES: Record<number, string> = { 1: "object file", 2: "executable", 4: "core dump", 5: "preloaded executable", 6: "dynamic library", 7: "dynamic linker", 8: "bundle (plug-in)", 10: "debug symbols", 11: "kernel extension" };
const PLATFORMS: Record<number, string> = { 1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "Mac Catalyst", 7: "iOS simulator", 8: "tvOS simulator", 9: "watchOS simulator", 10: "DriverKit", 11: "visionOS" };

const MAGIC64 = 0xfeedfacf;
const MAGIC32 = 0xfeedface;

export function isMacho(b: Uint8Array): boolean {
	if (b.length < 28) return false;
	const be = (b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!;
	const m = be >>> 0;
	const le = ((b[3]! << 24) | (b[2]! << 16) | (b[1]! << 8) | b[0]!) >>> 0;
	if (m === 0xcafebabe) return b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7]! > 0 && b[7]! < 20; // not a Java class
	return le === MAGIC64 || le === MAGIC32 || m === MAGIC64 || m === MAGIC32;
}

export function parseMachoFile(b: Uint8Array): MachoFile | null {
	if (!isMacho(b)) return null;
	const r = new Reader(b, false);
	if (r.u32(0) === 0xcafebabe) {
		const n = r.u32(4);
		const archs: MachoFile["archs"] = [];
		for (let i = 0; i < n && r.has(8 + i * 20, 20); i++) {
			const at = 8 + i * 20;
			archs.push({ cpu: CPUS[r.u32(at)] ?? `CPU ${r.u32(at)}`, offset: r.u32(at + 8), size: r.u32(at + 12) });
		}
		const programs = archs.slice(0, 4).map((a) => parseMacho(r.slice(a.offset, a.size))).filter((p): p is MachoInfo => !!p);
		return { archs, universal: true, programs };
	}
	const p = parseMacho(b);
	return p ? { archs: [{ cpu: p.cpu, offset: 0, size: b.length }], universal: false, programs: [p] } : null;
}

const version = (v: number) => `${v >>> 16}.${(v >> 8) & 0xff}${v & 0xff ? `.${v & 0xff}` : ""}`;

export function parseMacho(b: Uint8Array): MachoInfo | null {
	if (b.length < 28) return null;
	const head = new Reader(b, true).u32(0);
	const little = head === MAGIC64 || head === MAGIC32;
	const r = new Reader(b, little);
	const magic = r.u32(0);
	if (magic !== MAGIC64 && magic !== MAGIC32) return null;
	const bits: 32 | 64 = magic === MAGIC64 ? 64 : 32;
	const warnings: string[] = [];
	const cpu = r.u32(4);
	const flags = r.u32(24);
	const info: MachoInfo = {
		bits,
		cpu: CPUS[cpu] ?? `CPU ${cpu}`,
		type: TYPES[r.u32(12)] ?? `file type ${r.u32(12)}`,
		pie: !!(flags & 0x200000),
		execStack: !!(flags & 0x20000),
		sections: [],
		libraries: [],
		rpaths: [],
		dylinker: null,
		imports: [],
		signature: null,
		encrypted: false,
		platform: null,
		minOs: null,
		entry: null,
		warnings,
	};
	const ncmds = r.u32(16);
	let at = bits === 64 ? 32 : 28;
	const str = (cmd: number, size: number) => r.cstr(cmd + r.u32(cmd + 8), Math.max(0, size - r.u32(cmd + 8)));
	try {
		for (let i = 0; i < Math.min(ncmds, 4096); i++) {
			const cmd = r.u32(at);
			const size = r.u32(at + 4);
			if (size < 8 || !r.has(at, size)) {
				warnings.push("a load command runs past the end of the file");
				break;
			}
			const lc = cmd & 0x7fffffff;
			if (lc === 0x19 || lc === 0x1) {
				// LC_SEGMENT(_64) and its sections
				const segment = r.fixed(at + 8, 16);
				const nsects = r.u32(at + (bits === 64 ? 64 : 48));
				const prot = r.u32(at + (bits === 64 ? 60 : 44)); // initprot
				for (let s = 0, p = at + (bits === 64 ? 72 : 56); s < Math.min(nsects, 256); s++, p += bits === 64 ? 80 : 68) {
					const sz = bits === 64 ? r.u64(p + 40) : r.u32(p + 36);
					const off = r.u32(p + (bits === 64 ? 48 : 40));
					const zerofill = (r.u32(p + (bits === 64 ? 64 : 56)) & 0xff) === 1;
					info.sections.push({ name: r.fixed(p, 16), segment, offset: off, size: sz, exec: !!(prot & 4), write: !!(prot & 2), entropy: zerofill ? 0 : entropy(r.slice(off, sz)) });
				}
			} else if (lc === 0xc || lc === 0x18 || lc === 0x1f || lc === 0x20 || lc === 0x23) {
				const how = ({ 0xc: "", 0x18: "weak", 0x1f: "re-exported", 0x20: "lazy", 0x23: "upward" } as const)[lc as 0xc];
				if (info.libraries.length < 500) info.libraries.push({ path: str(at, size), how });
			} else if (lc === 0x1c) info.rpaths.push(str(at, size));
			else if (lc === 0xe) info.dylinker = str(at, size);
			else if (lc === 0x28) info.entry = r.u64(at + 8); // LC_MAIN
			else if (lc === 0x21 || lc === 0x2c) info.encrypted ||= r.u32(at + 16) !== 0; // LC_ENCRYPTION_INFO(_64).cryptid
			else if (lc === 0x32) {
				info.platform = PLATFORMS[r.u32(at + 8)] ?? `platform ${r.u32(at + 8)}`;
				info.minOs = version(r.u32(at + 12));
			} else if (lc === 0x24 || lc === 0x25 || lc === 0x2f || lc === 0x30) {
				info.platform ??= ({ 0x24: "macOS", 0x25: "iOS", 0x2f: "tvOS", 0x30: "watchOS" } as Record<number, string>)[lc]!;
				info.minOs ??= version(r.u32(at + 8));
			} else if (lc === 0x2) symbols(r, at, bits, info);
			else if (lc === 0x1d) info.signature = signature(r.slice(r.u32(at + 8), r.u32(at + 12)));
			at += size;
		}
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		warnings.push(`its load commands are cut short (${e.message})`);
	}
	return info;
}

/** LC_SYMTAB's undefined external symbols: what the program imports. */
function symbols(r: Reader, at: number, bits: 32 | 64, info: MachoInfo): void {
	const symoff = r.u32(at + 8);
	const nsyms = r.u32(at + 12);
	const stroff = r.u32(at + 16);
	const size = bits === 64 ? 16 : 12;
	for (let i = 0; i < Math.min(nsyms, 100_000) && info.imports.length < 20_000; i++) {
		const e = symoff + i * size;
		if (!r.has(e, size)) break;
		const type = r.u8(e + 4);
		// N_EXT and N_UNDF, not a debugging (stab) entry.
		if (type & 0xe0 || (type & 0x0e) !== 0 || !(type & 1)) continue;
		const name = r.cstr(stroff + r.u32(e), 256);
		if (name) info.imports.push(name);
	}
}

/** The code signature's superblob (big-endian, whatever the program's
 * byte order): the code directory's identifier, Team ID and flags, and
 * whether a CMS signature (a certificate) is there. */
function signature(blob: Uint8Array): MachoInfo["signature"] {
	const r = new Reader(blob, false);
	try {
		if (r.u32(0) !== 0xfade0cc0) return null;
		const out: NonNullable<MachoInfo["signature"]> = { adhoc: false, identifier: null, team: null, runtime: false, certificate: false, names: [] };
		const count = r.u32(8);
		for (let i = 0; i < Math.min(count, 64); i++) {
			const type = r.u32(12 + i * 8);
			const off = r.u32(16 + i * 8);
			const magic = r.u32(off);
			if (type === 0 && magic === 0xfade0c02) {
				const v = r.u32(off + 8);
				const flags = r.u32(off + 12);
				out.adhoc = !!(flags & 0x2);
				out.runtime = !!(flags & 0x10000);
				out.identifier = r.cstr(off + r.u32(off + 20), 256) || null;
				if (v >= 0x20200 && r.u32(off + 48)) out.team = r.cstr(off + r.u32(off + 48), 64) || null;
			} else if (type === 0x10000 && magic === 0xfade0b01) {
				const len = r.u32(off + 4);
				out.certificate = len > 8;
				out.names = commonNames(r.slice(off + 8, len - 8));
			}
		}
		return out;
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		return null;
	}
}
