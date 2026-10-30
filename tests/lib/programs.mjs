// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A hostile Windows program, built when a test runs (commit 42g) — never
 * kept as a file, so no contributor's virus scanner quarantines the
 * repository. It is a structurally valid PE32+ (pefile and objdump read
 * it) that does nothing: its "code" is a RET and padding. What it carries
 * is what the hex reader must name:
 *
 *   - imports that inject code (VirtualAllocEx, WriteProcessMemory,
 *     CreateRemoteThread), watch the keyboard, download, read saved
 *     passwords; Winsock by ordinal (#23 socket, #4 connect, #115
 *     WSAStartup — named as pefile names them, for the imphash);
 *   - UPX's section names, the second one near-random, writable AND
 *     executable, with the entry point in it (the last section);
 *   - a compile time in the future; a PDB path in a user's folder;
 *   - an overlay that is a ZIP, then an "Authenticode" blob whose names
 *     are Microsoft's (it is not a signature: the reader must say NOT
 *     verified);
 *   - strings: a shadow-copy deletion, a Run key, a download address, a
 *     .onion and a Bitcoin address, a ransom note's words.
 *
 * Addresses are documentation ranges; nothing here works as malware.
 */

const j = (...p) => p.join("");
const enc = new TextEncoder();
const ascii = (s) => enc.encode(s);
const align = (n, a) => Math.ceil(n / a) * a;

/** A deterministic near-random run (xorshift), for the "packed" section. */
function noise(n, seed = 0x9e3779b9) {
	const out = new Uint8Array(n);
	let x = seed >>> 0;
	for (let i = 0; i < n; i++) {
		x ^= x << 13;
		x >>>= 0;
		x ^= x >>> 17;
		x ^= x << 5;
		x >>>= 0;
		out[i] = x & 0xff;
	}
	return out;
}

class Buf {
	constructor(n) {
		this.b = new Uint8Array(n);
		this.v = new DataView(this.b.buffer);
	}
	u16(at, x) {
		this.v.setUint16(at, x, true);
	}
	u32(at, x) {
		this.v.setUint32(at, x >>> 0, true);
	}
	u64(at, x) {
		this.v.setBigUint64(at, BigInt(x), true);
	}
	put(at, bytes) {
		this.b.set(bytes, at);
	}
}

/**
 * Build a PE32+ (x64). `sections`: [{name, data, exec, write}] in order;
 * an `.rdata` holding the import, export and debug directories is added
 * after them. `imports`: [{dll, names}] ("#n" for an ordinal).
 */
export function buildPe({ sections, imports = [], exports = null, pdb = null, time = 0, subsystem = 2, dll = false, entry = 0, overlay = null, signatureNames = null, dllChars = 0x8160 }) {
	const FA = 0x200;
	const SA = 0x1000;
	const all = [...sections];
	const rdataIndex = all.length;
	all.push({ name: ".rdata", data: null, exec: false, write: false });
	const rvaOf = (i) => SA * (i + 1) + all.slice(0, i).reduce((n, s) => n + Math.max(0, align(Math.max(s.data?.length ?? 0, 1), SA) - SA), 0);
	const rdataRva = rvaOf(rdataIndex);

	// .rdata: imports, then exports, then the debug directory.
	const parts = [];
	let at = 0;
	const reserve = (n, a = 8) => {
		at = align(at, a);
		const off = at;
		at += n;
		return off;
	};
	const desc = reserve((imports.length + 1) * 20);
	const ints = imports.map((i) => reserve((i.names.length + 1) * 8));
	const iats = imports.map((i) => reserve((i.names.length + 1) * 8));
	const hints = imports.map((i) => i.names.map((n) => (n.startsWith("#") ? null : reserve(2 + n.length + 1, 2))));
	const dllNames = imports.map((i) => reserve(i.dll.length + 1, 1));
	let exp = null;
	if (exports) {
		const dir = reserve(40, 4);
		const funcs = reserve(exports.names.length * 4, 4);
		const names = reserve(exports.names.length * 4, 4);
		const ords = reserve(exports.names.length * 2, 2);
		const strs = exports.names.map((n) => reserve(n.length + 1, 1));
		const own = reserve(exports.name.length + 1, 1);
		exp = { dir, funcs, names, ords, strs, own };
	}
	let dbg = null;
	if (pdb) dbg = { dir: reserve(28, 4), rsds: reserve(24 + pdb.length + 1, 4) };
	const rd = new Buf(align(at, 16));
	imports.forEach((imp, k) => {
		const d = desc + k * 20;
		rd.u32(d, rdataRva + ints[k]);
		rd.u32(d + 12, rdataRva + dllNames[k]);
		rd.u32(d + 16, rdataRva + iats[k]);
		rd.put(dllNames[k], ascii(imp.dll));
		imp.names.forEach((n, i) => {
			const v = n.startsWith("#") ? 2n ** 63n + BigInt(Number(n.slice(1))) : BigInt(rdataRva + hints[k][i]);
			rd.v.setBigUint64(ints[k] + i * 8, v, true);
			rd.v.setBigUint64(iats[k] + i * 8, v, true);
			if (!n.startsWith("#")) rd.put(hints[k][i] + 2, ascii(n));
		});
	});
	if (exp) {
		rd.u32(exp.dir + 12, rdataRva + exp.own);
		rd.u32(exp.dir + 16, 1);
		rd.u32(exp.dir + 20, exports.names.length);
		rd.u32(exp.dir + 24, exports.names.length);
		rd.u32(exp.dir + 28, rdataRva + exp.funcs);
		rd.u32(exp.dir + 32, rdataRva + exp.names);
		rd.u32(exp.dir + 36, rdataRva + exp.ords);
		exports.names.forEach((n, i) => {
			rd.u32(exp.funcs + i * 4, SA);
			rd.u32(exp.names + i * 4, rdataRva + exp.strs[i]);
			rd.u16(exp.ords + i * 2, i);
			rd.put(exp.strs[i], ascii(n));
		});
		rd.put(exp.own, ascii(exports.name));
	}
	all[rdataIndex].data = rd.b;

	// The file: headers, then each section at a file-aligned offset.
	const offs = [];
	let fileAt = 0x400;
	for (const s of all) {
		offs.push(fileAt);
		fileAt += align(s.data.length, FA);
	}
	const imageEnd = fileAt;
	const sizeOfImage = rvaOf(all.length - 1) + align(all.at(-1).data.length, SA);
	let cert = null;
	if (signatureNames) {
		const der = [0x30, 0x82, 0, 0, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]; // SEQUENCE, OID signedData
		for (const n of signatureNames) der.push(0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, n.length, ...ascii(n));
		const body = new Uint8Array(align(8 + der.length, 8));
		const v = new DataView(body.buffer);
		v.setUint32(0, body.length, true);
		v.setUint16(4, 0x200, true);
		v.setUint16(6, 2, true);
		body.set(der, 8);
		cert = body;
	}
	const total = imageEnd + (overlay?.length ?? 0) + (cert?.length ?? 0);
	const f = new Buf(total);
	f.put(0, ascii("MZ"));
	f.u32(0x3c, 0x80);
	f.put(0x40, ascii("This program cannot be run in DOS mode.\r\r\n$"));
	f.put(0x80, ascii("PE\0\0"));
	const coff = 0x84;
	f.u16(coff, 0x8664);
	f.u16(coff + 2, all.length);
	f.u32(coff + 4, time);
	f.u16(coff + 16, 240);
	f.u16(coff + 18, 0x0022 | (dll ? 0x2000 : 0));
	const opt = coff + 20;
	f.u16(opt, 0x20b);
	f.u32(opt + 16, entry || rvaOf(sections.findIndex((s) => s.exec)));
	f.u32(opt + 20, SA);
	f.u64(opt + 24, 0x140000000);
	f.u32(opt + 32, SA);
	f.u32(opt + 36, FA);
	f.u16(opt + 40, 6);
	f.u16(opt + 48, 6);
	f.u32(opt + 56, sizeOfImage);
	f.u32(opt + 60, 0x400);
	f.u16(opt + 68, subsystem);
	f.u16(opt + 70, dllChars);
	f.u64(opt + 72, 0x100000);
	f.u64(opt + 80, 0x1000);
	f.u64(opt + 88, 0x100000);
	f.u64(opt + 96, 0x1000);
	f.u32(opt + 108, 16);
	const dirs = opt + 112;
	if (exp) (f.u32(dirs + 0, rdataRva + exp.dir), f.u32(dirs + 4, 40));
	if (imports.length) (f.u32(dirs + 8, rdataRva + desc), f.u32(dirs + 12, (imports.length + 1) * 20));
	if (cert) (f.u32(dirs + 32, imageEnd + (overlay?.length ?? 0)), f.u32(dirs + 36, cert.length));
	if (dbg) (f.u32(dirs + 48, rdataRva + dbg.dir), f.u32(dirs + 52, 28));
	const secs = opt + 240;
	all.forEach((s, i) => {
		const h = secs + i * 40;
		f.put(h, ascii(s.name.slice(0, 8)));
		f.u32(h + 8, Math.max(s.data.length, 1));
		f.u32(h + 12, rvaOf(i));
		f.u32(h + 16, align(s.data.length, FA));
		f.u32(h + 20, offs[i]);
		f.u32(h + 36, 0x40000000 | (s.exec ? 0x20000020 : 0x40) | (s.write ? 0x80000000 : 0));
		f.put(offs[i], s.data);
	});
	if (dbg) {
		const rdOff = offs[rdataIndex];
		f.u32(rdOff + dbg.dir + 12, 2);
		f.u32(rdOff + dbg.dir + 16, 24 + pdb.length + 1);
		f.u32(rdOff + dbg.dir + 20, rdataRva + dbg.rsds);
		f.u32(rdOff + dbg.dir + 24, rdOff + dbg.rsds);
		f.put(rdOff + dbg.rsds, ascii("RSDS"));
		f.u32(rdOff + dbg.rsds + 20, 1);
		f.put(rdOff + dbg.rsds + 24, ascii(pdb));
	}
	if (overlay) f.put(imageEnd, overlay);
	if (cert) f.put(imageEnd + (overlay?.length ?? 0), cert);
	return f.b;
}

/** The strings a ransomware loader carries, assembled from pieces. */
const loot = [
	j("vssad", "min delete sha", "dows /all /quiet"),
	j("Software\\Microsoft\\Windows\\Current", "Version\\Run"),
	j("http://203.0.113.9/", "payload.bin"),
	j("gorani", "testonion", "a".repeat(41), ".onion"), // 56 of [a-z2-7]: a v3 address's shape
	j("bc1q", "w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), // BIP-173's own test vector
	j("YOUR FILES HAVE BEEN ", "ENCRYPTED"),
].join("\0");

/** The hostile program the hex reader is tested on (see the header). */
export function hostilePe() {
	const code = new Uint8Array(0x200);
	code[0] = 0xc3; // RET: it does nothing
	code.set(ascii(loot), 0x10);
	return buildPe({
		sections: [
			{ name: "UPX0", data: code, exec: true, write: true },
			{ name: "UPX1", data: noise(0x3000), exec: true, write: true },
		],
		entry: 0x2000, // in UPX1, the last of its own sections
		imports: [
			{ dll: "KERNEL32.dll", names: ["LoadLibraryA", "GetProcAddress", j("Virtual", "AllocEx"), j("Write", "ProcessMemory"), j("Create", "RemoteThread"), "ExitProcess"] },
			{ dll: "USER32.dll", names: [j("SetWindows", "HookExA"), "GetAsyncKeyState"] },
			{ dll: "urlmon.dll", names: [j("URLDownload", "ToFileW")] },
			{ dll: "CRYPT32.dll", names: [j("CryptUnprotect", "Data")] },
			{ dll: "WS2_32.dll", names: ["#115", "#23", "#4"] },
		],
		time: 4102444800, // 2100-01-01
		pdb: j("C:\\Users\\attacker\\source\\repos\\loader\\", "x64\\Release\\loader.pdb"),
		overlay: Uint8Array.from([0x50, 0x4b, 3, 4, ...noise(4092, 7)]),
		signatureNames: ["Microsoft Windows", "Microsoft Windows Production PCA 2011"],
	});
}
