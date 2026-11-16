// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:registry-hives — the registry reader (commit 42k, docs/PREVIEWS.md ›
 * Forensic formats) on three real hives: regipy's test data, fetched once
 * and pinned by commit and SHA-256 (tests/lib/hives.mjs). Without them
 * (offline, no curl or xz) only the parts that need no hive run, and the
 * test says it skipped the rest.
 *
 *   1. the ShimCache's other layouts (Windows 7 x64, 8.1, 10), from entries
 *      naming ordinary programs; a program's path out of a command line;
 *      Windows' own dual-use tools in their own folder not flagged
 *   2. every key and value read as python-registry reads them: each
 *      hive's whole walk pinned as one digest (compared with
 *      python-registry key for key and byte for byte when this was
 *      written), the counts, big data assembled, deleted keys recovered
 *   3. the ShimCache and UserAssist as regipy reads them (all 660 and 29
 *      entries were compared when this was written; some are pinned here)
 *   4. what each hive says, and the keys its findings mark
 *   5. damaged hives — a checksum broken, a dirty one, one cut short, 60
 *      mutations — said, never thrown
 */

import assert from "node:assert/strict";
import { HIVES, REGIPY_COMMIT, sampleHive, unavailable, walkDigest } from "../lib/hives.mjs";
import { parseHive, type Hive, type RegKey } from "../../web/src/preview/forensic/regf.ts";
import { parseShimCache } from "../../web/src/preview/forensic/shimcache.ts";
import { hiveFindings, oddProgram, programOf, userAssist } from "../../web/src/preview/facts/regf.ts";

const said = (facts: { text: string }[]) => facts.map((f) => f.text).join("\n");

// ── 1. What needs no hive ────────────────────────────────────────────
const utf16 = (s: string) => Uint8Array.from([...s].flatMap((c) => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8]));
const ticks = (iso: string) => (BigInt(Date.parse(iso)) + 11_644_473_600_000n) * 10_000n;
const programs = [
	["C:\\Windows\\System32\\notepad.exe", "2024-03-01T10:00:00Z"],
	["C:\\Program Files\\Example\\app.exe", "2024-03-02T11:30:00Z"],
] as const;
/** Windows 10/11: a header of 0x34 bytes, then "10ts" entries. */
function win10(): Uint8Array {
	const parts: Uint8Array[] = [new Uint8Array(0x34)];
	new DataView(parts[0]!.buffer).setUint32(0, 0x34, true);
	for (const [path, when] of programs) {
		const p = utf16(path);
		const e = new Uint8Array(12 + 2 + p.length + 8 + 4);
		const v = new DataView(e.buffer);
		e.set([0x31, 0x30, 0x74, 0x73]); // "10ts"
		v.setUint32(8, e.length - 12, true);
		v.setUint16(12, p.length, true);
		e.set(p, 14);
		v.setBigUint64(14 + p.length, ticks(when), true);
		parts.push(e);
	}
	return Uint8Array.from(parts.flatMap((x) => [...x]));
}
/** Windows 7 x64: magic, count, a 128-byte header, 48-byte entries pointing at their paths. */
function win7x64(): Uint8Array {
	const paths = programs.map(([p]) => utf16(p));
	const start = 0x80 + programs.length * 48;
	const b = new Uint8Array(start + paths.reduce((n, p) => n + p.length, 0));
	const v = new DataView(b.buffer);
	v.setUint32(0, 0xbadc0fee, true);
	v.setUint32(4, programs.length, true);
	let at = start;
	programs.forEach(([, when], i) => {
		const e = 0x80 + i * 48;
		v.setUint16(e, paths[i]!.length, true);
		v.setUint16(e + 2, paths[i]!.length + 2, true);
		v.setBigUint64(e + 8, BigInt(at), true);
		v.setBigUint64(e + 16, ticks(when), true);
		v.setUint32(e + 24, i === 0 ? 2 : 0, true); // the first one ran
		b.set(paths[i]!, at);
		at += paths[i]!.length;
	});
	return b;
}
/** Windows 8.1: a 128-byte header, then "10ts" entries with a package name and flags. */
function win81(): Uint8Array {
	const parts: Uint8Array[] = [new Uint8Array(0x80)];
	new DataView(parts[0]!.buffer).setUint32(0, 0x80, true);
	for (const [path, when] of programs) {
		const p = utf16(path);
		const e = new Uint8Array(12 + 2 + p.length + 2 + 4 + 4 + 8 + 4);
		const v = new DataView(e.buffer);
		e.set([0x31, 0x30, 0x74, 0x73]);
		v.setUint32(8, e.length - 12, true);
		v.setUint16(12, p.length, true);
		e.set(p, 14);
		const q = 14 + p.length + 2; // (no package name)
		v.setUint32(q, 2, true); // ran
		v.setBigUint64(q + 8, ticks(when), true);
		parts.push(e);
	}
	return Uint8Array.from(parts.flatMap((x) => [...x]));
}
const expected = programs.map(([path, when]) => ({ path, modified: when.replace("Z", ".0000000Z") }));
assert.deepEqual(parseShimCache(win10())!.entries.map(({ path, modified }) => ({ path, modified })), expected, "Windows 10/11");
assert.deepEqual(parseShimCache(win10())!.entries.map((e) => e.executed), [null, null], "…which does not say whether a program ran");
const seven = parseShimCache(win7x64())!;
assert.deepEqual([seven.format, seven.entries.map(({ path, modified }) => ({ path, modified })), seven.entries.map((e) => e.executed)], ["Windows 7 (x64)", expected, [true, false]]);
const eight = parseShimCache(win81())!;
assert.deepEqual([eight.format, eight.entries.map(({ path, modified }) => ({ path, modified }))], ["Windows 8.1", expected]);
assert.equal(parseShimCache(new Uint8Array(64)), null, "not a ShimCache");
assert.deepEqual(parseShimCache(win10().subarray(0, 0x34 + 20))?.entries ?? [], [], "cut inside its first entry: nothing, not a crash");
assert.equal(programOf('"C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe" /run'), "C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe");
assert.equal(programOf("C:\\Program Files (x86)\\Jetico\\BCWipe\\BCWipeSvc.exe -s"), "C:\\Program Files (x86)\\Jetico\\BCWipe\\BCWipeSvc.exe", "unquoted, with spaces: up to its extension");
assert.equal(oddProgram("\\??\\C:\\Windows\\System32\\regsvr32.exe"), null, "Windows' own tools, where Windows keeps them, are not findings");
assert.match(oddProgram("c:\\windows\\system32\\dllhost\\svchost.exe") ?? "", /named like Windows' own svchost\.exe, but not where Windows keeps it/);

// ── The hives ────────────────────────────────────────────────────────
const bytes: Record<string, Uint8Array> = {};
for (const name of Object.keys(HIVES)) {
	const b = sampleHive(name);
	if (!b) {
		console.log(`ok  registry-hives: the ShimCache's layouts and the program rules; SKIPPED the sample hives — ${unavailable}`);
		process.exit(0);
	}
	bytes[name] = b;
}
const hive = (name: string) => parseHive(bytes[name]!)!;
const ntuser = hive("NTUSER.DAT");
const system = hive("SYSTEM");
const software = hive("SOFTWARE");

// ── 2. Every key and value, as python-registry reads them ────────────
for (const [h, kind, version, keys, values, digest] of [
	[ntuser, "NTUSER", "1.3", 1812, 4094, "64605f291bfad9a84ff30364f44f407170b8c79d5af40f0756d72964d5d4dae7"],
	[system, "SYSTEM", "1.5", 30756, 73456, "0c12234f4520c070cb8ac469a7de38474efcd6e92c2ef1a85cbd1661cf9fa290"],
	[software, "SOFTWARE", "1.5", 117488, 193870, "de9a6d4b78cc7d25744bd1a8df304eb8712fc6c522c05d100a744e4a3f532a7d"],
] as const) {
	assert.deepEqual([h.version, h.dirty, h.checksumOk, h.warnings], [version, false, true, []], `${kind}: the base block`);
	assert.deepEqual(walkDigest(h), { keys, values, digest }, `${kind}: every key and value as python-registry read them`);
	assert.equal(hiveFindings(h).kind, kind);
}
assert.equal(ntuser.root.name, "CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}");
assert.match(ntuser.fileName, /\\Users\\vibranium\\ntuser\.dat$/);
const run = ntuser.path("software\\microsoft\\windows\\currentversion\\run")!;
assert.deepEqual(ntuser.values(run).map((v) => [v.name, v.typeName, v.text]), [["Sidebar", "REG_EXPAND_SZ", "%ProgramFiles%\\Windows Sidebar\\Sidebar.exe /autoRun"]], "a path looked up as Windows does: case ignored");
assert.equal(run.written, "2012-04-03T21:19:54.8377168Z", "a key's last write to the tick");
// Big data: values past 16,344 bytes, assembled from their segments.
const big: [string, number][] = [];
const walk = (h: Hive, k: RegKey, p: string) => {
	for (const v of h.values(k)) if (v.size > 16344) big.push([`${p}|${v.name}`, v.data?.length ?? -1]);
	for (const s of h.subkeys(k)) walk(h, s, `${p}\\${s.name}`);
};
walk(system, system.root, "");
assert.equal(big.length, 8);
assert.ok(big.some(([n, len]) => n.endsWith("\\Control\\Session Manager\\AppCompatCache|AppCompatCache") && len === 56256), "the ShimCache, 56,256 bytes in segments");
// Deleted keys: still in the free space.
const deleted = software.deleted();
assert.deepEqual([deleted.length, deleted[0]?.name, deleted[0]?.written], [47, "InvertDependencies", "2011-09-14T07:00:43.4472500Z"]);

// ── 3. The ShimCache and UserAssist, as regipy reads them ────────────
const shim = parseShimCache(system.get(system.path("ControlSet001\\Control\\Session Manager\\AppCompatCache")!, "AppCompatCache")!.data!)!;
assert.deepEqual([shim.format, shim.entries.length, shim.entries.filter((e) => e.executed).length], ["Windows 7 (x86)", 330, 238]);
assert.deepEqual(shim.entries[0], { path: "\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe", modified: "2011-01-12T12:08:00.0000000Z", executed: true });
assert.deepEqual(shim.entries[100], { path: "\\??\\C:\\Windows\\Explorer.EXE", modified: "2011-02-25T05:30:54.9620000Z", executed: true });
const ua = userAssist(ntuser);
assert.equal(ua.length, 29);
assert.deepEqual(ua.find((u) => u.raw.endsWith("\\calc.exe")), { name: "%SystemRoot%\\SysWOW64\\calc.exe", raw: "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}\\calc.exe", runs: 12, focusMs: 340000, last: "2012-04-03T22:06:58.1242823Z" }, "ROT13 undone, the known folder named");

// ── 4. What each hive says ───────────────────────────────────────────
const nf = hiveFindings(ntuser);
for (const want of [
	/^A Windows registry hive: a user's NTUSER\.DAT \(version 1\.3\), last written 2012-04-07 18:50:45 UTC/m,
	/Starts at sign-in \(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\): “Sidebar” → “%ProgramFiles%\\Windows Sidebar\\Sidebar\.exe \/autoRun”/,
	/Searched for in Explorer \(newest first\): “alloy” · “test-plan” · “vibranium” · “accounts” · “myron maclain” · “adamantium”/,
	/Programs this person started \(UserAssist, 29\): most often “Microsoft\.Windows\.GettingStarted” ×14/,
]) assert.match(said(nf.facts), want);
assert.deepEqual(nf.facts.filter((f) => f.level === "warn"), [], "an ordinary user's hive: nothing to warn of");
const sf = hiveFindings(system);
for (const want of [
	/Service “PSEXESVC” runs “%SystemRoot%\\PSEXESVC\.EXE” — PsExec's: a command run from another computer/,
	/WDigest keeps passwords in memory in clear \(UseLogonCredential = 1\)/,
	/The ShimCache names “C:\\Windows\\TEMP\\a\.exe” \(it ran\), 47 times over, each time a file modified at another time/,
	/The ShimCache names “c:\\windows\\system32\\dllhost\\svchost\.exe” \(it ran\), .* — named like Windows' own svchost\.exe, but not where Windows keeps it/,
	/The ShimCache names “C:\\\$Recycle\.Bin\\.*\\\$RR3GW21\.exe”/,
	/The computer “WKS-WIN732BITA”, time zone “Eastern Standard Time”, last shut down 2012-04-04 01:58:40 UTC/,
	/Remote Desktop is on, on port 3389, without Network Level Authentication/,
	/USB storage devices plugged in: “HP v100w USB Device \(serial AA951D0000007252\)”/,
	/The ShimCache \(Windows 7 \(x86\)\) names 330 programs, 238 marked as run/,
]) assert.match(said(sf.facts), want);
assert.doesNotMatch(said(sf.facts), /regsvr32/, "Windows' own regsvr32 in the ShimCache is not a finding");
assert.ok(sf.places.some((p) => p.path === "ControlSet001\\Services\\PSEXESVC" && p.level === "warn"), "the service's key marked for the tree");
const wf = hiveFindings(software);
for (const want of [
	/Starts at every sign-in \(HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\): “svchost” → “c:\\windows\\system32\\dllhost\\svchost\.exe” — named like Windows' own svchost\.exe/,
	/Defender turned off \(DisableAntiSpyware = 1\)/,
	/Windows 7 Ultimate \(build 7601\), installed 2010-11-10 16:28:55 UTC/,
	/47 deleted keys still in its free space \(recoverable\): “InvertDependencies” \(2011-09-14 07:00:43\)/,
]) assert.match(said(wf.facts), want);
const runPlaces = wf.places.filter((p) => p.path === "Microsoft\\Windows\\CurrentVersion\\Run");
assert.deepEqual([runPlaces.length, runPlaces.filter((p) => p.level === "warn").map((p) => p.why.split(" — ")[0])], [7, ["Starts at every sign-in: svchost"]], "the disguise among six honest entries, every one kept for the tree");

// ── 5. Damaged hives: said, never thrown ─────────────────────────────
const fixSum = (b: Uint8Array) => {
	const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
	let x = 0;
	for (let i = 0; i < 508; i += 4) x ^= v.getUint32(i, true);
	v.setUint32(508, x >>> 0, true);
	return b;
};
const broken = bytes["NTUSER.DAT"]!.slice();
broken[100] ^= 0x20;
assert.match(said(hiveFindings(parseHive(broken)!).facts), /Malformed: its base block does not match its checksum/);
const dirty = bytes["NTUSER.DAT"]!.slice();
new DataView(dirty.buffer).setUint32(8, new DataView(dirty.buffer).getUint32(4, true) + 1, true);
const dh = parseHive(fixSum(dirty))!;
assert.deepEqual([dh.dirty, dh.checksumOk], [true, true]);
assert.match(said(hiveFindings(dh).facts), /Not every change was written into it .* the \.LOG1 and \.LOG2 files beside it hold the rest/);
const cut = parseHive(bytes["NTUSER.DAT"]!.subarray(0, 4096 + 8192))!;
assert.match(cut.warnings.join("\n"), /cut short/);
hiveFindings(cut);
// A walk that cannot loop: a key whose subkey list points back up is followed only so far.
const bounded = (h: Hive) => {
	let n = 0;
	const go = (k: RegKey, depth: number) => {
		if (depth > 64 || n > 20_000) return;
		n++;
		h.values(k);
		for (const s of h.subkeys(k)) go(s, depth + 1);
	};
	go(h.root, 0);
	return n;
};
let seed = 7;
const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
for (let i = 0; i < 60; i++) {
	const b = bytes["NTUSER.DAT"]!.slice();
	for (let k = 0, n = 1 + Math.floor(rnd() * 64); k < n; k++) b[rnd() < 0.9 ? 4096 + Math.floor(rnd() * (b.length - 4096)) : Math.floor(rnd() * 4096)] = Math.floor(rnd() * 256);
	const t = performance.now();
	const h = parseHive(b); // (never throws: a hive it cannot start reading is null)
	if (h) {
		bounded(h);
		h.deleted();
		hiveFindings(h);
	}
	assert.ok(performance.now() - t < 3000, `mutation ${i} read in time`);
}

console.log(`ok  registry-hives: three real hives (regipy ${REGIPY_COMMIT.slice(0, 7)}) read key for key as python-registry reads them — 150,056 keys, big data, 47 deleted keys; the ShimCache and UserAssist as regipy reads them, and its Windows 7 x64, 8.1 and 10 layouts; PsExec, WDigest, a replaced a.exe, a disguised svchost, Defender off named; a broken checksum, a dirty hive, one cut short, 60 mutations: said, never thrown`);
