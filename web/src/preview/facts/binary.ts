// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a binary is and what it could do (commit 42g, docs/PREVIEWS.md ›
 * Programs) — the first minute of triage, read from its structure and
 * never from running it:
 *
 *   what      the program it is (or the format, for any other binary),
 *             and a name that says otherwise; its SHA-256 and imphash, to
 *             look up
 *   who       the compile time, the signature's names (not verified), the
 *             version resource's maker and file name, the build path
 *   how       packers and high-entropy code, imports resolved at run
 *             time, an overlay, TLS callbacks, an executable stack
 *   what for  the capabilities its imports name; commands, addresses and
 *             registry paths in its strings
 *
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import { plural, some } from "../office.ts";
import type { Capability } from "../binary/capabilities.ts";
import { capabilities } from "../binary/capabilities.ts";
import type { ElfInfo } from "../binary/elf.ts";
import type { MachoFile } from "../binary/macho.ts";
import type { PeInfo } from "../binary/pe.ts";
import type { Identity } from "../binary/sniff.ts";
import type { StringFindings } from "../binary/strings.ts";

export interface BinaryFindings {
	name: string;
	size: number;
	sha256: string | null;
	id: Identity | null;
	pe: PeInfo | null;
	elf: ElfInfo | null;
	macho: MachoFile | null;
	strings: { total: number; findings: StringFindings } | null;
	entropy: number;
	/** A malware sample, opened for inspection (bytes only, on the record). */
	sample: boolean;
}

/** Names a program may honestly have. */
export const PROGRAM_EXTS = new Set(["exe", "macho", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi", "mui", "ax", "com", "so", "dylib", "bundle", "o", "obj", "ko", "elf", "bin", "axf", "out", "node", "pyd", "app", "msi", "mex", "xll", "wll", "tlb", "acm", "tsp", "rll", "dat", "tmp", "bak"]);

const kb = (n: number) => (n < 1024 ? `${n} byte${n === 1 ? "" : "s"}` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`);
const q = (s: string, n = 100) => `“${s.slice(0, n)}${s.length > n ? "…" : ""}”`;
const PACKERS: [RegExp, string][] = [
	[/^UPX\d?$/i, "UPX"], [/^\.aspack$|^\.adata$/i, "ASPack"], [/^\.MPRESS\d$/i, "MPRESS"], [/^\.themida$|^\.winlice$/i, "Themida"], [/^\.vmp\d$/i, "VMProtect"],
	[/^\.petite$/i, "Petite"], [/^\.nsp\d$/i, "NsPack"], [/^\.enigma\d$/i, "Enigma Protector"], [/^PEC2|^PECompact/i, "PECompact"], [/^\.packed$/i, "a packer"], [/^\.ndata$/i, "NSIS (an installer)"],
];

export function binaryFacts(f: BinaryFindings): Fact[] {
	const facts: Fact[] = [];
	const ext = f.name.includes(".") ? f.name.split(".").pop()!.toLowerCase() : "";

	// What it is.
	const p = f.pe;
	const e = f.elf;
	const m = f.macho;
	if (p) facts.push({ level: "info", text: [`A Windows ${p.kind === "program" ? "program" : p.kind === "DLL" ? "DLL" : p.kind === "driver" ? "driver" : "EFI program"} (${p.bits === 64 ? "PE32+" : "PE32"}, ${p.machine}${p.kind === "program" ? `, ${p.subsystem}` : ""}${p.dotnet ? `, .NET${p.dotnet.runtime ? ` ${p.dotnet.runtime}` : ""}` : ""})`, kb(f.size)].join(" · ") });
	else if (e) facts.push({ level: "info", text: [`A ${e.abi === "System V" || e.abi === "Linux (GNU)" ? "Linux" : e.abi} ${e.modinfo ? "kernel module" : e.type} (ELF ${e.bits}-bit, ${e.machine}${e.little ? "" : ", big-endian"}${e.staticallyLinked ? ", statically linked" : ""})`, kb(f.size)].join(" · ") });
	else if (m) {
		const first = m.programs[0];
		facts.push({ level: "info", text: [`A ${first?.platform ?? "macOS or iOS"} ${first?.type ?? "program"} (Mach-O${m.universal ? `, universal: ${m.archs.map((a) => a.cpu).join(", ")}` : `, ${first?.bits}-bit ${first?.cpu}`}${first?.minOs ? `, for ${first.platform ?? "the OS"} ${first.minOs} and later` : ""})`, kb(f.size)].join(" · ") });
	} else facts.push({ level: "info", text: [f.id ? `${f.id.what.charAt(0).toUpperCase()}${f.id.what.slice(1)}` : "Data of no format this reader knows", kb(f.size), `entropy ${f.entropy.toFixed(2)} bits a byte${f.entropy > 7.5 ? " (compressed or encrypted)" : ""}`].join(" · ") });
	if (f.sample) facts.push({ level: "warn", text: "A malware sample, shown as bytes only: nothing in it is run, drawn, or handed to another reader — and this inspection is in the audit trail" });
	if (f.sha256) facts.push({ level: "info", text: `SHA-256 ${f.sha256}`, copy: f.sha256 });
	const isProgram = !!(p || e || m);
	if (isProgram && ext && !PROGRAM_EXTS.has(ext)) facts.push({ level: "warn", text: `Named .${ext}, but it is a program — a disguise: opened by a double click, it would run` });
	else if (!isProgram && f.id && f.id.family === "program" && ext && !PROGRAM_EXTS.has(ext)) facts.push({ level: "warn", text: `Named .${ext}, but it is ${f.id.what}` });

	if (p) peFacts(p, f, facts);
	if (e) elfFacts(e, facts);
	if (m) machoFacts(m, facts);

	// The strings.
	const s = f.strings?.findings;
	if (s) {
		for (const c of s.commands.slice(0, 8)) facts.push({ level: "warn", text: `Its strings, at 0x${c.at.toString(16)}: it ${c.what} — ${q(c.text, 120)}` });
		if (s.marks.length) facts.push({ level: s.marks.some((x) => /ransom|Mimikatz|Cobalt|Meterpreter/.test(x)) ? "warn" : "info", text: `Its strings carry ${some(s.marks, 4)}` });
		if (s.onion.length) facts.push({ level: "warn", text: `Names a Tor (.onion) address: ${some(s.onion, 2)}` });
		if (s.bitcoin.length) facts.push({ level: "warn", text: `Names a Bitcoin address: ${some(s.bitcoin, 2)}` });
		if (s.registry.length) facts.push({ level: s.registry.some((x) => /\\Run|Winlogon|Image File Execution/i.test(x)) ? "warn" : "info", text: `Names registry places: ${some(s.registry.map((x) => q(x, 80)), 3)}` });
		if (s.userPaths.length) facts.push({ level: "info", text: `Names a user's folder (the machine it was built or meant for): ${some(s.userPaths.map((x) => q(x, 80)), 3)}` });
		if (s.urls.length) facts.push({ level: "info", text: `Names ${plural(s.urls.length, "address", "addresses")}: ${some(s.urls.map((u) => q(u, 90)), 4)}` });
		if (s.ips.length) facts.push({ level: "info", text: `Names ${plural(s.ips.length, "IP address", "IP addresses")}: ${some(s.ips, 5)}` });
	}
	if (f.strings) facts.push({ level: "info", text: `${plural(f.strings.total, "string")} of 5 or more characters (ASCII and UTF-16) — the Strings tab has them, by offset` });
	return facts;
}

function capabilityFacts(caps: Capability[], facts: Fact[]): void {
	for (const c of caps.filter((x) => x.strong)) facts.push({ level: "warn", text: `Its imports let it ${c.what}: ${some(c.calls, 5)}` });
	const weak = caps.filter((x) => !x.strong);
	if (weak.length) facts.push({ level: "info", text: `Its imports also let it ${weak.map((x) => x.what).join("; ")}` });
}

function peFacts(p: PeInfo, f: BinaryFindings, facts: Fact[]): void {
	// When.
	const now = Date.now() / 1000;
	if (!p.time) facts.push({ level: "info", text: "No compile time (zeroed)" });
	else if (p.time > now + 86400) facts.push({ level: "warn", text: `Its compile time is in the future (${new Date(p.time * 1000).toISOString().slice(0, 10)}) — forged, or a reproducible build's hash` });
	else if (p.time < 788918400) facts.push({ level: "info", text: `Its compile time says ${new Date(p.time * 1000).toISOString().slice(0, 10)} — forged, or a reproducible build's hash (Go, Delphi and Visual C++'s /Brepro write one)` });
	else facts.push({ level: "info", text: `Compiled ${new Date(p.time * 1000).toISOString().replace("T", " ").slice(0, 16)} UTC (as it says)` });

	// Who.
	if (p.signature) facts.push({ level: "info", text: `Carries an Authenticode signature — NOT checked here${p.signature.names.length ? `; the names in it: ${some(p.signature.names.map((n) => q(n, 60)), 4)}` : ""}` });
	else if (p.kind !== "EFI") facts.push({ level: "info", text: "Not signed" });
	const v = p.version;
	if (v) {
		const parts = [v.FileDescription && `“${v.FileDescription}”`, v.CompanyName && `by “${v.CompanyName}”`, v.OriginalFilename && `file name “${v.OriginalFilename}”`].filter(Boolean);
		if (parts.length) facts.push({ level: "info", text: `Says it is ${parts.join(", ")}` });
		if (/microsoft|google|apple|adobe|mozilla/i.test(`${v.CompanyName ?? ""} ${v.ProductName ?? ""}`) && !p.signature) facts.push({ level: "warn", text: `Claims to be ${q(v.CompanyName ?? v.ProductName ?? "", 40)}'s but carries no signature — their programs are signed` });
		const own = (v.OriginalFilename ?? v.InternalName ?? "").toLowerCase();
		if (own && f.name.toLowerCase() !== own && !own.startsWith(f.name.toLowerCase().replace(/\.[^.]+$/, ""))) facts.push({ level: "info", text: `Its own name for itself is “${v.OriginalFilename ?? v.InternalName}”, not “${f.name}”` });
	}
	if (p.pdb) facts.push({ level: /\\Users\\|\\Documents and Settings\\|\/home\//i.test(p.pdb) ? "warn" : "info", text: `Its build left its debug-symbol path: ${q(p.pdb, 140)}${/\\Users\\|\/home\//i.test(p.pdb) ? " — it names the builder's user folder" : ""}` });
	if (p.manifestLevel === "requireAdministrator") facts.push({ level: "warn", text: "Asks to run as administrator (its manifest: requireAdministrator)" });

	// How it is built.
	const packers = [...new Set(p.sections.flatMap((s) => PACKERS.filter(([re]) => re.test(s.name)).map(([, n]) => n)))];
	if (packers.length) facts.push({ level: packers.every((x) => /NSIS/.test(x)) ? "info" : "warn", text: `Packed or wrapped: ${packers.join(", ")} (by its section names)` });
	const dense = p.sections.filter((s) => s.rawSize > 1024 && s.entropy > 7.2);
	if (dense.length) facts.push({ level: dense.some((s) => s.exec) ? "warn" : "info", text: `${plural(dense.length, "section")} of near-random bytes (${dense.map((s) => `${s.name || "(no name)"} ${s.entropy.toFixed(2)}`).join(", ")}) — compressed or encrypted${dense.some((s) => s.exec) ? " code, unpacked only when it runs" : ""}` });
	const rwx = p.sections.filter((s) => s.write && s.exec);
	if (rwx.length) facts.push({ level: "warn", text: `${plural(rwx.length, "section")} both writable and executable (${rwx.map((s) => s.name).join(", ")}) — code that rewrites itself` });
	const entry = p.sections.find((s) => s.name === p.entrySection);
	if (p.entry && !p.entrySection && p.kind !== "DLL") facts.push({ level: "warn", text: `Its entry point (0x${p.entry.toString(16)}) is in no section` });
	else if (entry && !entry.exec) facts.push({ level: "warn", text: `Its entry point is in ${entry.name}, a section not marked executable` });
	else if (entry && p.sections.length > 2 && entry === p.sections.at(-1)) facts.push({ level: "warn", text: `Its entry point is in its last section (${entry.name}) — where packers put their stub` });
	if (p.tls) facts.push({ level: "info", text: `Runs ${plural(p.tls, "TLS callback")} before its entry point (compilers' runtime does; so do anti-debugging tricks)` });
	if (p.overlay) facts.push({ level: p.overlay.size > 1024 ? "warn" : "info", text: `${kb(p.overlay.size)} after its last section (an overlay, at 0x${p.overlay.offset.toString(16)}) — an installer's payload, or a second stage` });
	const nosec = p.security.filter((s) => s.startsWith("no "));
	if (nosec.length && p.kind !== "driver") facts.push({ level: "info", text: `Built without ${nosec.map((s) => s.slice(3)).join(" or ")} (old, or hand-made)` });
	const bigRaw = p.resources.filter((r) => r.size > 64 * 1024 && r.entropy > 7.2);
	if (bigRaw.length) facts.push({ level: "warn", text: `Carries ${plural(bigRaw.length, "large near-random resource")} (${bigRaw.map((r) => `${r.type}, ${kb(r.size)}`).join("; ")}) — an encrypted payload, likely` });

	// What it imports.
	const all = p.imports.flatMap((i) => i.names);
	if (p.imports.length) facts.push({ level: "info", text: `Imports ${plural(all.length, "function")} from ${plural(p.imports.length, "library", "libraries")}: ${some(p.imports.map((i) => `${i.dll}${i.delayed ? " (delayed)" : ""}`), 6)}${p.imphash ? ` · imphash ${p.imphash}` : ""}`, ...(p.imphash ? { copy: p.imphash } : {}) });
	else if (!p.dotnet) facts.push({ level: "warn", text: "Imports nothing — it finds everything at run time (packed, or shellcode in a program's clothes)" });
	if (all.length && all.length < 12 && all.some((n) => /^GetProcAddress$/.test(n)) && all.some((n) => /^LoadLibrary/.test(n))) facts.push({ level: "warn", text: `Imports only ${plural(all.length, "function")}, among them LoadLibrary and GetProcAddress — it looks the rest up at run time (packed)` });
	if (p.exports.names.length || p.exports.count) facts.push({ level: "info", text: `Exports ${plural(p.exports.count || p.exports.names.length, "function")}${p.exports.name ? ` as “${p.exports.name}”` : ""}: ${some(p.exports.names.slice(0, 20), 6)}` });
	capabilityFacts(capabilities(all, true), facts);
	for (const w of p.warnings.slice(0, 4)) facts.push({ level: "warn", text: `Malformed: ${w}` });
}

function elfFacts(e: ElfInfo, facts: Fact[]): void {
	if (e.interpreter && !/^\/(?:lib|lib64|usr\/lib|system\/bin)\/[\w./-]*ld[\w.-]*\.so[\w.]*$|^\/system\/bin\/linker(?:64)?$/.test(e.interpreter)) facts.push({ level: "warn", text: `Asks for an unusual loader: ${q(e.interpreter, 80)}` });
	if (e.upx) facts.push({ level: "warn", text: "Packed with UPX (its mark is in the first kilobyte) — what it does is unpacked only when it runs" });
	if (!e.sections.length && e.type !== "core dump") facts.push({ level: "warn", text: "Has no section table — removed, as packers and some malware do" });
	else if (e.stripped) facts.push({ level: "info", text: "Stripped: its symbol table is gone (common in released programs)" });
	if (e.rwx) facts.push({ level: "warn", text: `${plural(e.rwx, "segment")} both writable and executable — code that rewrites itself` });
	const dense = e.sections.filter((s) => s.size > 1024 && s.entropy > 7.2);
	if (dense.length) facts.push({ level: dense.some((s) => s.exec) ? "warn" : "info", text: `${plural(dense.length, "section")} of near-random bytes: ${dense.map((s) => `${s.name} ${s.entropy.toFixed(2)}`).join(", ")}` });
	if (e.go) facts.push({ level: "info", text: "Written in Go (its build ID and runtime tables are there)" });
	if (e.comment) facts.push({ level: "info", text: `Built with ${q(e.comment, 80)}` });
	if (e.buildId) facts.push({ level: "info", text: `GNU build ID ${e.buildId}`, copy: e.buildId });
	if (e.modinfo) facts.push({ level: "warn", text: `A kernel module: ${some(Object.entries(e.modinfo).filter(([k]) => /^(name|license|author|description|vermagic)$/.test(k)).map(([k, v]) => `${k} ${q(v, 60)}`), 5)}` });
	if (e.needed.length) facts.push({ level: "info", text: `Needs ${plural(e.needed.length, "library", "libraries")}: ${some(e.needed, 6)}${e.rpath ? ` · searches ${q(e.rpath, 60)} first` : ""}` });
	if (e.rpath && /(^|:)(\.|\/tmp|\/dev\/shm|\$ORIGIN\/\.\.)/.test(e.rpath)) facts.push({ level: "warn", text: `Loads its libraries from ${q(e.rpath, 60)} first — a place anyone can write` });
	if (e.imports.length) facts.push({ level: "info", text: `Imports ${plural(e.imports.length, "symbol")}: ${some(e.imports.filter((n) => !/^_ITM_|^__gmon_start__$|^__cxa_finalize$/.test(n)), 8)}` });
	capabilityFacts(capabilities(e.imports, false), facts);
	for (const w of e.warnings.slice(0, 4)) facts.push({ level: "warn", text: `Malformed: ${w}` });
}

function machoFacts(f: MachoFile, facts: Fact[]): void {
	// (A universal file's slices are signed one by one; the arm64 one
	// is the one an Apple silicon Mac checks.)
	const p = f.programs.find((x) => x.cpu === "arm64") ?? f.programs[0];
	if (!p) return;
	const sig = p.signature;
	const which = f.universal ? ` (its ${p.cpu} part)` : "";
	if (!sig) facts.push({ level: p.cpu === "arm64" ? "warn" : "info", text: p.cpu === "arm64" ? `Not signed${which} — an Apple silicon Mac runs no unsigned program, so someone must sign it first (or it is not meant to run there)` : `Not signed${which}` });
	else if (sig.adhoc && !sig.certificate) facts.push({ level: "info", text: `Signed ad hoc${which}${sig.identifier ? `, as “${sig.identifier}”` : ""} — no certificate, so no one vouches for it` });
	else facts.push({ level: "info", text: `Code-signed${which} — NOT checked here${sig.team ? `; Team ID ${sig.team}` : ""}${sig.identifier ? `, identifier “${sig.identifier}”` : ""}${sig.names.length ? `; the names in it: ${some(sig.names.map((n) => q(n, 60)), 3)}` : ""}${sig.runtime ? " · hardened runtime" : ""}` });
	if (p.encrypted) facts.push({ level: "info", text: "Encrypted by the App Store (FairPlay): its code is not readable here" });
	if (p.execStack) facts.push({ level: "warn", text: "Asks for an executable stack" });
	const dense = f.programs.flatMap((x) => x.sections).filter((s) => s.size > 1024 && s.entropy > 7.2);
	if (dense.length) facts.push({ level: dense.some((s) => s.exec) ? "warn" : "info", text: `${plural(dense.length, "section")} of near-random bytes: ${dense.map((s) => `${s.segment},${s.name} ${s.entropy.toFixed(2)}`).join(", ")}` });
	const odd = p.libraries.filter((l) => /^\/(?:tmp|private\/tmp|Users\/Shared|var\/tmp)\/|^@executable_path\/\.\.\/\.\./.test(l.path));
	if (odd.length) facts.push({ level: "warn", text: `Loads a library from a place anyone can write: ${some(odd.map((l) => q(l.path, 80)), 3)}` });
	if (p.libraries.length) facts.push({ level: "info", text: `Loads ${plural(p.libraries.length, "library", "libraries")}: ${some(p.libraries.map((l) => `${l.path.split("/").pop()}${l.how ? ` (${l.how})` : ""}`), 6)}` });
	if (p.imports.length) facts.push({ level: "info", text: `Imports ${plural(p.imports.length, "symbol")}: ${some(p.imports.filter((n) => n !== "dyld_stub_binder"), 8)}` });
	capabilityFacts(capabilities(f.programs.flatMap((x) => x.imports), false), facts);
	for (const w of p.warnings.slice(0, 4)) facts.push({ level: "warn", text: `Malformed: ${w}` });
}
