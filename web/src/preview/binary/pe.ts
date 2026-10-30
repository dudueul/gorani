// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A Windows program's structure (commit 42g, docs/PREVIEWS.md › Programs),
 * read from the PE/COFF specification — never run, never mapped:
 *
 *   headers      machine, 32/64-bit, EXE/DLL/driver, subsystem, compile
 *                time, entry point and the section it falls in, ASLR/DEP
 *   sections     name, sizes, rights (read/write/execute), entropy
 *   imports      each DLL and the functions it asks for (delay-loaded
 *                too), and their imphash — pefile's, so it can be looked
 *                up where analysts share them
 *   exports      a DLL's own name and what it offers
 *   the rest     .NET (and its runtime), an Authenticode signature (its
 *                names, NOT verified), the overlay after the last
 *                section, the PDB path its build left, TLS callbacks, the
 *                version resource (who it says made it), the manifest's
 *                requested privilege
 *
 * Every RVA is mapped through the section table and checked; every loop
 * is capped. A file that lies ends in `warnings`, not in a crash.
 * Pure: unit:preview-facts.
 */

import { md5 } from "@noble/hashes/legacy.js";
import { commonNames, entropy, Reader, Short } from "./read.ts";

export interface PeSection {
	name: string;
	vaddr: number;
	vsize: number;
	raw: number;
	rawSize: number;
	read: boolean;
	write: boolean;
	exec: boolean;
	entropy: number;
}

export interface PeImport {
	dll: string;
	names: string[];
	delayed: boolean;
}

export interface PeInfo {
	bits: 32 | 64;
	machine: string;
	kind: "program" | "DLL" | "driver" | "EFI";
	subsystem: string;
	/** TimeDateStamp: seconds since 1970 (or a hash, in a reproducible build). */
	time: number;
	entry: number;
	entrySection: string | null;
	imageBase: number;
	security: string[];
	sections: PeSection[];
	imports: PeImport[];
	exports: { name: string | null; names: string[]; count: number };
	imphash: string | null;
	dotnet: { runtime: string | null } | null;
	signature: { offset: number; size: number; names: string[] } | null;
	overlay: { offset: number; size: number } | null;
	pdb: string | null;
	tls: number | null;
	version: Record<string, string> | null;
	manifestLevel: string | null;
	resources: { type: string; size: number; entropy: number }[];
	warnings: string[];
}

const MACHINES: Record<number, string> = { 0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c0: "ARM", 0x1c4: "ARM (Thumb-2)", 0x200: "Itanium", 0xebc: "EFI byte code", 0x5064: "RISC-V 64" };
const SUBSYSTEMS: Record<number, string> = { 1: "native (a driver)", 2: "windowed (GUI)", 3: "console", 5: "OS/2 console", 7: "POSIX console", 9: "Windows CE", 10: "EFI application", 11: "EFI boot driver", 12: "EFI runtime driver", 13: "EFI ROM", 14: "Xbox", 16: "boot application" };
const RESOURCE_TYPES: Record<number, string> = { 1: "cursor", 2: "bitmap", 3: "icon", 4: "menu", 5: "dialog", 6: "string table", 9: "accelerators", 10: "raw data (RCDATA)", 11: "message table", 12: "cursor group", 14: "icon group", 16: "version", 23: "HTML", 24: "manifest" };

/** Winsock's ordinals, named as pefile names them (its ordlookup), so an
 * imphash over a file that imports them by number matches pefile's. */
const WINSOCK: Record<number, string> = {
	1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname", 7: "getsockopt", 8: "htonl", 9: "htons", 10: "ioctlsocket",
	11: "inet_addr", 12: "inet_ntoa", 13: "listen", 14: "ntohl", 15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send", 20: "sendto",
	21: "setsockopt", 22: "shutdown", 23: "socket", 51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname", 54: "getprotobynumber",
	55: "getservbyname", 56: "getservbyport", 57: "gethostname", 111: "WSAGetLastError", 112: "WSASetLastError", 115: "WSAStartup", 116: "WSACleanup", 151: "__WSAFDIsSet",
};

export function isPeFile(b: Uint8Array): boolean {
	if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return false;
	const r = new Reader(b);
	const off = r.u32(0x3c);
	return r.has(off, 4) && r.u32(off) === 0x00004550;
}

export function parsePe(b: Uint8Array): PeInfo | null {
	if (!isPeFile(b)) return null;
	const r = new Reader(b);
	const warnings: string[] = [];
	const pe = r.u32(0x3c);
	const coff = pe + 4;
	// (Its COFF header cut short: a PE in name only — the sniffer still
	// calls it one, and the facts say there is nothing more to read.)
	if (!r.has(coff, 20)) return null;
	const machineId = r.u16(coff);
	const nSections = r.u16(coff + 2);
	const time = r.u32(coff + 4);
	const optSize = r.u16(coff + 16);
	const characteristics = r.u16(coff + 18);
	const opt = coff + 20;
	const magic = r.has(opt, 2) ? r.u16(opt) : 0;
	const bits: 32 | 64 = magic === 0x20b ? 64 : 32;
	if (magic !== 0x10b && magic !== 0x20b) warnings.push(`its optional header's magic is ${magic.toString(16)}, neither PE32 nor PE32+`);
	const info: PeInfo = {
		bits,
		machine: MACHINES[machineId] ?? `machine 0x${machineId.toString(16)}`,
		kind: characteristics & 0x2000 ? "DLL" : "program",
		subsystem: "",
		time,
		entry: 0,
		entrySection: null,
		imageBase: 0,
		security: [],
		sections: [],
		imports: [],
		exports: { name: null, names: [], count: 0 },
		imphash: null,
		dotnet: null,
		signature: null,
		overlay: null,
		pdb: null,
		tls: null,
		version: null,
		manifestLevel: null,
		resources: [],
		warnings,
	};
	let dirs: { rva: number; size: number }[] = [];
	try {
		info.entry = r.u32(opt + 16);
		info.imageBase = bits === 64 ? r.u64(opt + 24) : r.u32(opt + 28);
		const subsystem = r.u16(opt + 68);
		info.subsystem = SUBSYSTEMS[subsystem] ?? `subsystem ${subsystem}`;
		if (subsystem === 1) info.kind = "driver";
		else if (subsystem >= 10 && subsystem <= 13) info.kind = "EFI";
		const dll = r.u16(opt + 70);
		info.security = [dll & 0x40 ? "ASLR" : "no ASLR", dll & 0x100 ? "DEP" : "no DEP", ...(dll & 0x4000 ? ["Control Flow Guard"] : []), ...(dll & 0x80 ? ["integrity checked (signed code only)"] : [])];
		const nDirsAt = opt + (bits === 64 ? 108 : 92);
		const nDirs = Math.min(16, r.u32(nDirsAt));
		for (let i = 0; i < nDirs; i++) dirs.push({ rva: r.u32(nDirsAt + 4 + i * 8), size: r.u32(nDirsAt + 8 + i * 8) });
	} catch (e) {
		if (!(e instanceof Short)) throw e;
		warnings.push(`its optional header is cut short (${e.message})`);
	}

	// Sections (at most 96: the loader's own limit).
	const secAt = opt + optSize;
	if (nSections > 96) warnings.push(`it claims ${nSections} sections (Windows loads at most 96)`);
	for (let i = 0; i < Math.min(nSections, 96); i++) {
		const s = secAt + i * 40;
		if (!r.has(s, 40)) {
			warnings.push("its section table runs past the end of the file");
			break;
		}
		const flags = r.u32(s + 36);
		const raw = r.u32(s + 20);
		const rawSize = r.u32(s + 16);
		if (rawSize && raw + rawSize > b.length) warnings.push(`section ${JSON.stringify(r.fixed(s, 8))} runs past the end of the file`);
		info.sections.push({ name: r.fixed(s, 8), vsize: r.u32(s + 8), vaddr: r.u32(s + 12), rawSize, raw, read: !!(flags & 0x40000000), write: !!(flags & 0x80000000), exec: !!(flags & 0x20000000), entropy: entropy(r.slice(raw, rawSize)) });
	}
	const section = (rva: number) => info.sections.find((s) => rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawSize));
	/** An RVA as a file offset — or -1 when it points at nothing in the file. */
	const off = (rva: number): number => {
		const s = section(rva);
		if (!s) return rva < (info.sections[0]?.raw ?? 0x400) && rva < b.length ? rva : -1;
		const o = s.raw + (rva - s.vaddr);
		return rva - s.vaddr < s.rawSize && o < b.length ? o : -1;
	};
	info.entrySection = info.entry ? (section(info.entry)?.name ?? null) : null;
	const dir = (i: number) => (dirs[i] && dirs[i]!.rva && dirs[i]!.size ? dirs[i]! : null);
	const guard = (what: string, f: () => void) => {
		try {
			f();
		} catch (e) {
			if (!(e instanceof Short)) throw e;
			warnings.push(`its ${what} is cut short`);
		}
	};
	const ptr = bits === 64 ? 8 : 4;
	const thunks = (at: number): string[] => {
		const names: string[] = [];
		for (let t = at; t >= 0 && names.length < 4000; t += ptr) {
			// (Read as two halves: 2^63 + n is past what a JS number holds
			// exactly, and n — the ordinal — would round away.)
			const lo = r.u32(t);
			const hi = bits === 64 ? r.u32(t + 4) : 0;
			if (!lo && !hi) break;
			const byOrdinal = ((bits === 64 ? hi : lo) & 0x80000000) !== 0;
			if (byOrdinal) names.push(`#${lo & 0xffff}`);
			else {
				const h = off(lo & 0x7fffffff);
				names.push(h >= 0 ? r.cstr(h + 2, 512) : "?");
			}
		}
		return names;
	};

	// Imports, and delay-loaded imports.
	guard("import table", () => {
		const d = dir(1);
		if (!d) return;
		for (let i = 0, at = off(d.rva); at >= 0 && i < 1000; i++, at += 20) {
			const int = r.u32(at);
			const name = r.u32(at + 12);
			const iat = r.u32(at + 16);
			if (!int && !name && !iat) break;
			const n = off(name);
			const list = off(int || iat);
			info.imports.push({ dll: n >= 0 ? r.cstr(n, 256) : "?", names: list >= 0 ? thunks(list) : [], delayed: false });
		}
	});
	guard("delay-load table", () => {
		const d = dir(13);
		if (!d) return;
		for (let i = 0, at = off(d.rva); at >= 0 && i < 1000; i++, at += 32) {
			const attrs = r.u32(at);
			const name = r.u32(at + 4);
			const int = r.u32(at + 16);
			if (!name) break;
			// (Attribute bit 0: RVAs. Without it, VAs — Visual C++ 6.)
			const rva = (v: number) => (attrs & 1 ? v : v - info.imageBase);
			const n = off(rva(name));
			const list = off(rva(int));
			info.imports.push({ dll: n >= 0 ? r.cstr(n, 256) : "?", names: list >= 0 ? thunks(list) : [], delayed: true });
		}
	});
	info.imphash = imphash(info.imports.filter((i) => !i.delayed));

	// Exports.
	guard("export table", () => {
		const d = dir(0);
		if (!d) return;
		const at = off(d.rva);
		if (at < 0) return;
		const name = off(r.u32(at + 12));
		info.exports.name = name >= 0 ? r.cstr(name, 256) : null;
		info.exports.count = r.u32(at + 20);
		const nNames = Math.min(r.u32(at + 24), 5000);
		const names = off(r.u32(at + 32));
		for (let i = 0; names >= 0 && i < nNames; i++) {
			const p = off(r.u32(names + i * 4));
			if (p >= 0) info.exports.names.push(r.cstr(p, 256));
		}
	});

	// The PDB path a build leaves in its debug directory (CodeView).
	guard("debug directory", () => {
		const d = dir(6);
		if (!d) return;
		const at = off(d.rva);
		for (let i = 0; at >= 0 && i < Math.min(16, Math.floor(d.size / 28)); i++) {
			const e = at + i * 28;
			if (r.u32(e + 12) !== 2) continue;
			const raw = r.u32(e + 24);
			const sig = r.u32(raw);
			if (sig === 0x53445352) info.pdb = r.cstr(raw + 24, 512); // "RSDS"
			else if (sig === 0x3031424e) info.pdb = r.cstr(raw + 16, 512); // "NB10"
		}
	});

	// TLS callbacks: code the loader runs BEFORE the entry point.
	guard("TLS directory", () => {
		const d = dir(9);
		if (!d) return;
		const at = off(d.rva);
		if (at < 0) return;
		const callbacks = bits === 64 ? r.u64(at + 24) : r.u32(at + 12);
		let n = 0;
		const list = callbacks ? off(callbacks - info.imageBase) : -1;
		for (let p = list; p >= 0 && n < 64 && (bits === 64 ? r.u64(p) : r.u32(p)); p += ptr) n++;
		info.tls = n;
	});

	// .NET: the CLR header, and the runtime its metadata names.
	guard(".NET header", () => {
		const d = dir(14);
		if (!d) return;
		const at = off(d.rva);
		if (at < 0) return;
		const meta = off(r.u32(at + 8));
		info.dotnet = { runtime: meta >= 0 && r.u32(meta) === 0x424a5342 ? r.cstr(meta + 16, Math.min(255, r.u32(meta + 12))) || null : null };
	});

	// The signature: the security directory is a FILE offset, not an RVA.
	guard("signature", () => {
		const d = dir(4);
		if (!d) return;
		const len = r.u32(d.rva);
		const type = r.u16(d.rva + 6);
		if (len > d.size + 8 || len < 8) warnings.push("its signature's length does not match its directory");
		info.signature = { offset: d.rva, size: d.size, names: type === 2 ? commonNames(r.slice(d.rva + 8, Math.min(len, d.size) - 8)) : [] };
	});

	// The overlay: bytes after the last section (the signature aside) — an
	// installer's payload, a dropper's second stage, or padding.
	{
		const headers = r.has(opt + 60, 4) ? r.u32(opt + 60) : 0; // SizeOfHeaders
		const end = Math.max(headers, ...info.sections.map((s) => (s.rawSize ? s.raw + s.rawSize : 0)));
		const sig = info.signature;
		let size = b.length - end;
		if (sig && sig.offset >= end && sig.offset + sig.size >= b.length - 7) size = sig.offset - end;
		if (end > 0 && size > 0) info.overlay = { offset: end, size };
	}

	// Resources: the version strings, the manifest, and the biggest blobs.
	guard("resources", () => {
		const d = dir(2);
		if (!d) return;
		const base = off(d.rva);
		if (base < 0) return;
		let visited = 0;
		const entries = (at: number): { id: number; data: number; dir: boolean }[] => {
			const named = r.u16(at + 12);
			const ids = r.u16(at + 14);
			const out = [];
			for (let i = 0; i < Math.min(named + ids, 2000); i++) {
				const e = at + 16 + i * 8;
				const name = r.u32(e);
				const data = r.u32(e + 4);
				out.push({ id: name & 0x80000000 ? -1 : name, data: data & 0x7fffffff, dir: !!(data & 0x80000000) });
			}
			return out;
		};
		/** The leaves under a resource type (name → language → data), capped. */
		const leaves = (at: number, depth: number, out: { rva: number; size: number }[]) => {
			if (depth > 3 || ++visited > 4000) return;
			for (const e of entries(at)) {
				if (e.dir) leaves(base + e.data, depth + 1, out);
				else out.push({ rva: r.u32(base + e.data), size: r.u32(base + e.data + 4) });
			}
		};
		for (const t of entries(base)) {
			if (!t.dir) continue;
			const found: { rva: number; size: number }[] = [];
			leaves(base + t.data, 1, found);
			const type = t.id >= 0 ? (RESOURCE_TYPES[t.id] ?? `type ${t.id}`) : "named type";
			for (const f of found) {
				const o = off(f.rva);
				if (o < 0) continue;
				const bytes = r.slice(o, f.size);
				info.resources.push({ type, size: f.size, entropy: entropy(bytes) });
				if (t.id === 16 && !info.version) info.version = versionStrings(bytes);
				if (t.id === 24 && !info.manifestLevel) info.manifestLevel = /requestedExecutionLevel[^>]*level\s*=\s*["']([A-Za-z]+)["']/.exec(new TextDecoder().decode(bytes))?.[1] ?? null;
			}
		}
	});
	return info;
}

/** pefile's imphash: "dll.function" for every import, lower case, the DLL
 * without its extension, joined by commas, MD5. Ordinals become names
 * where pefile names them (Winsock); for oleaut32, whose table we do not
 * carry, an ordinal import means no imphash at all — a wrong one would
 * send an analyst after the wrong family. */
export function imphash(imports: PeImport[]): string | null {
	const parts: string[] = [];
	for (const i of imports) {
		const lib = i.dll.toLowerCase().replace(/\.(dll|ocx|sys)$/, "");
		for (const n of i.names) {
			let fn = n;
			if (n.startsWith("#")) {
				const ord = Number(n.slice(1));
				if (lib === "ws2_32" || lib === "wsock32") {
					if (!WINSOCK[ord]) return null;
					fn = WINSOCK[ord]!;
				} else if (lib === "oleaut32") return null;
				else fn = `ord${ord}`;
			}
			parts.push(`${lib}.${fn.toLowerCase()}`);
		}
	}
	if (!parts.length) return null;
	return [...md5(new TextEncoder().encode(parts.join(",")))].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** VS_VERSIONINFO's StringFileInfo: CompanyName, FileDescription,
 * OriginalFilename and the rest — what the file says about itself. */
export function versionStrings(b: Uint8Array): Record<string, string> | null {
	const r = new Reader(b);
	const out: Record<string, string> = {};
	const utf16 = (at: number, max: number): [string, number] => {
		let s = "";
		let p = at;
		while (p + 1 < Math.min(b.length, at + max * 2)) {
			const c = r.u16(p);
			p += 2;
			if (!c) break;
			s += String.fromCharCode(c);
		}
		return [s, p];
	};
	const align = (n: number) => (n + 3) & ~3;
	let budget = 400;
	const block = (at: number, end: number, depth: number) => {
		while (at + 6 <= end && budget-- > 0) {
			const len = r.u16(at);
			if (len < 6 || at + len > end + 3) return;
			const valueLen = r.u16(at + 2);
			const type = r.u16(at + 4);
			const [key, afterKey] = utf16(at + 6, 64);
			const value = align(afterKey);
			if (depth === 3 && type === 1 && valueLen) out[key] = utf16(value, valueLen)[0].trim();
			// StringFileInfo → StringTable → String; VarFileInfo and the fixed info are skipped.
			const children = depth === 0 ? align(value + valueLen) : depth === 3 ? at + len : value;
			if (depth === 0 || (depth === 1 && key === "StringFileInfo") || depth === 2) block(children, at + len, depth + 1);
			at = align(at + len);
			if (depth === 0) return;
		}
	};
	try {
		block(0, b.length, 0);
	} catch (e) {
		if (!(e instanceof Short)) throw e;
	}
	return Object.keys(out).length ? out : null;
}
