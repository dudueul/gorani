// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A Linux (or BSD, Android, router firmware) program's structure (commit
 * 42g), read from the System V ELF specification:
 *
 *   header     32/64-bit, byte order, machine, type (an executable, a
 *              position-independent one, a shared library, an object, a
 *              core dump), entry point, ABI
 *   segments   the loader's view: the interpreter it asks for, and any
 *              segment both writable and executable
 *   sections   name, size, rights, entropy (when the table is there:
 *              `strip` can remove it, a packer always does)
 *   dynamic    the libraries it needs (DT_NEEDED), its own name, RPATH
 *   symbols    what it imports (undefined dynamic symbols) and exports;
 *              whether a full symbol table is left (not stripped)
 *   notes      the GNU build ID, Go's build ID; a kernel module's .modinfo
 *
 * Pure: unit:preview-facts.
 */

import { entropy, Reader, Short } from "./read.ts";

export interface ElfSection {
	name: string;
	type: number;
	addr: number;
	offset: number;
	size: number;
	write: boolean;
	exec: boolean;
	entropy: number;
}

export interface ElfInfo {
	bits: 32 | 64;
	little: boolean;
	machine: string;
	type: "executable" | "position-independent executable" | "shared library" | "object file" | "core dump" | string;
	abi: string;
	entry: number;
	interpreter: string | null;
	sections: ElfSection[];
	/** PT_LOAD segments that are writable AND executable. */
	rwx: number;
	needed: string[];
	soname: string | null;
	rpath: string | null;
	imports: string[];
	exports: number;
	stripped: boolean;
	staticallyLinked: boolean;
	buildId: string | null;
	go: boolean;
	comment: string | null;
	modinfo: Record<string, string> | null;
	upx: boolean;
	warnings: string[];
}

const MACHINES: Record<number, string> = { 3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 20: "PowerPC", 21: "PowerPC 64", 22: "S/390", 2: "SPARC", 43: "SPARC V9", 243: "RISC-V", 258: "LoongArch", 50: "Itanium", 42: "SuperH", 164: "Hexagon", 94: "Xtensa", 92: "OpenRISC" };
const ABIS: Record<number, string> = { 0: "System V", 3: "Linux (GNU)", 6: "Solaris", 9: "FreeBSD", 12: "OpenBSD", 2: "NetBSD", 97: "ARM", 255: "standalone" };

export const isElf = (b: Uint8Array): boolean => b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;

export function parseElf(b: Uint8Array): ElfInfo | null {
	if (!isElf(b)) return null;
	const bits: 32 | 64 = b[4] === 2 ? 64 : 32;
	const little = b[5] !== 2;
	const r = new Reader(b, little);
	const warnings: string[] = [];
	const word = (at: number) => (bits === 64 ? r.u64(at) : r.u32(at));
	const type = r.u16(16);
	const info: ElfInfo = {
		bits,
		little,
		machine: MACHINES[r.u16(18)] ?? `machine ${r.u16(18)}`,
		type: ({ 1: "object file", 2: "executable", 3: "shared library", 4: "core dump" } as Record<number, string>)[type] ?? `type ${type}`,
		abi: ABIS[b[7]!] ?? `ABI ${b[7]}`,
		entry: 0,
		interpreter: null,
		sections: [],
		rwx: 0,
		needed: [],
		soname: null,
		rpath: null,
		imports: [],
		exports: 0,
		stripped: true,
		staticallyLinked: false,
		buildId: null,
		go: false,
		comment: null,
		modinfo: null,
		upx: false,
		warnings,
	};
	const loads: { vaddr: number; offset: number; filesz: number }[] = [];
	let dynamic: { offset: number; size: number } | null = null;
	try {
		info.entry = word(24);
		const phoff = word(bits === 64 ? 32 : 28);
		const shoff = word(bits === 64 ? 40 : 32);
		const phentsize = r.u16(bits === 64 ? 54 : 42);
		const phnum = r.u16(bits === 64 ? 56 : 44);
		const shentsize = r.u16(bits === 64 ? 58 : 46);
		const shnum = r.u16(bits === 64 ? 60 : 48);
		const shstrndx = r.u16(bits === 64 ? 62 : 50);

		// Program headers: the loader's view.
		for (let i = 0; i < Math.min(phnum, 256) && phoff; i++) {
			const p = phoff + i * phentsize;
			if (!r.has(p, bits === 64 ? 56 : 32)) {
				warnings.push("its program headers run past the end of the file");
				break;
			}
			const pt = r.u32(p);
			const flags = r.u32(bits === 64 ? p + 4 : p + 24);
			const offset = word(bits === 64 ? p + 8 : p + 4);
			const vaddr = word(bits === 64 ? p + 16 : p + 8);
			const filesz = word(bits === 64 ? p + 32 : p + 16);
			if (pt === 1) {
				loads.push({ vaddr, offset, filesz });
				if (flags & 1 && flags & 2) info.rwx++;
			} else if (pt === 3) info.interpreter = r.cstr(offset, Math.min(filesz, 256));
			else if (pt === 2) dynamic = { offset, size: filesz };
		}
		if (type === 3 && info.interpreter) info.type = "position-independent executable";
		info.staticallyLinked = type === 2 && !info.interpreter && !dynamic;

		// Section headers: names, rights, entropy; the symbol tables.
		const sh = (i: number) => shoff + i * shentsize;
		const okTable = shoff && shnum && shentsize >= (bits === 64 ? 64 : 40) && r.has(shoff, shnum * shentsize);
		if (shoff && !okTable) warnings.push("its section table points past the end of the file");
		const names = okTable && shstrndx < shnum ? word(bits === 64 ? sh(shstrndx) + 24 : sh(shstrndx) + 16) : -1;
		const raw: { name: string; type: number; flags: number; addr: number; offset: number; size: number; link: number; entsize: number }[] = [];
		for (let i = 0; okTable && i < Math.min(shnum, 1024); i++) {
			const s = sh(i);
			const nameOff = r.u32(s);
			const t = r.u32(s + 4);
			const flags = word(s + 8);
			const addr = word(bits === 64 ? s + 16 : s + 12);
			const offset = word(bits === 64 ? s + 24 : s + 16);
			const size = word(bits === 64 ? s + 32 : s + 20);
			const link = r.u32(bits === 64 ? s + 40 : s + 24);
			const entsize = word(bits === 64 ? s + 56 : s + 36);
			raw.push({ name: names >= 0 ? r.cstr(names + nameOff, 128) : "", type: t, flags, addr, offset, size, link, entsize });
		}
		for (const s of raw.slice(1)) {
			const inFile = s.type !== 8; // SHT_NOBITS (.bss) holds nothing in the file
			info.sections.push({ name: s.name, type: s.type, addr: s.addr, offset: s.offset, size: s.size, write: !!(s.flags & 1), exec: !!(s.flags & 4), entropy: inFile ? entropy(r.slice(s.offset, s.size)) : 0 });
		}
		if (raw.some((s) => s.type === 2)) info.stripped = false; // SHT_SYMTAB
		const dynsym = raw.find((s) => s.type === 11);
		if (dynsym && dynsym.link < raw.length) {
			const str = raw[dynsym.link]!;
			const ent = dynsym.entsize || (bits === 64 ? 24 : 16);
			for (let i = 1; i < Math.min(Math.floor(dynsym.size / ent), 50_000); i++) {
				const e = dynsym.offset + i * ent;
				if (!r.has(e, ent)) break;
				const name = r.cstr(str.offset + r.u32(e), 256);
				const shndx = r.u16(bits === 64 ? e + 6 : e + 14);
				if (!name) continue;
				if (shndx === 0) {
					if (info.imports.length < 20_000) info.imports.push(name);
				} else info.exports++;
			}
		}
		const note = (name: string) => raw.find((s) => s.name === name);
		const gnu = note(".note.gnu.build-id");
		if (gnu && r.has(gnu.offset, 16)) {
			const namesz = r.u32(gnu.offset);
			const descsz = r.u32(gnu.offset + 4);
			const desc = gnu.offset + 12 + ((namesz + 3) & ~3);
			info.buildId = [...r.slice(desc, Math.min(descsz, 64))].map((x) => x.toString(16).padStart(2, "0")).join("");
		}
		info.go = !!(note(".note.go.buildid") || note(".gopclntab") || note(".go.buildinfo"));
		const comment = note(".comment");
		if (comment) info.comment = r.cstr(comment.offset, Math.min(comment.size, 200)) || null;
		const mod = note(".modinfo");
		if (mod) {
			info.modinfo = {};
			for (const kv of new TextDecoder().decode(r.slice(mod.offset, Math.min(mod.size, 8192))).split("\0")) {
				const i = kv.indexOf("=");
				if (i > 0 && Object.keys(info.modinfo).length < 30) info.modinfo[kv.slice(0, i)] = kv.slice(i + 1).slice(0, 200);
			}
		}
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		warnings.push(`its headers are cut short (${e.message})`);
	}

	// The dynamic section, through the loader's own map (it works with the
	// section table stripped, as packed programs have it).
	try {
		if (dynamic) {
			const toOff = (vaddr: number) => {
				const l = loads.find((x) => vaddr >= x.vaddr && vaddr < x.vaddr + x.filesz);
				return l ? l.offset + (vaddr - l.vaddr) : -1;
			};
			const ent = bits === 64 ? 16 : 8;
			const tags: [number, number][] = [];
			for (let i = 0; i < Math.min(dynamic.size / ent, 1024); i++) {
				const tag = word(dynamic.offset + i * ent);
				const val = word(dynamic.offset + i * ent + ent / 2);
				if (tag === 0) break;
				tags.push([tag, val]);
			}
			const strtab = toOff(tags.find(([t]) => t === 5)?.[1] ?? -1);
			if (strtab >= 0) {
				for (const [t, v] of tags) {
					if (t === 1 && info.needed.length < 200) info.needed.push(r.cstr(strtab + v, 256));
					else if (t === 14) info.soname = r.cstr(strtab + v, 256);
					else if (t === 15 || t === 29) info.rpath = r.cstr(strtab + v, 512);
				}
			}
		}
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		warnings.push("its dynamic section is cut short");
	}
	// UPX leaves its name in the first kilobyte (and its sections nameless).
	const head = r.slice(0, 1024);
	for (let i = 0; i + 4 <= head.length; i++) if (head[i] === 0x55 && head[i + 1] === 0x50 && head[i + 2] === 0x58 && head[i + 3] === 0x21) info.upx = true;
	return info;
}
