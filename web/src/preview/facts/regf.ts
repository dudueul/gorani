// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a registry hive says (commit 42k, docs/PREVIEWS.md › Forensic
 * formats). The registry is where Windows keeps what should run — and so
 * where an intruder makes things run again; and it remembers what people
 * did. Each hive answers its own questions:
 *
 *   NTUSER.DAT   what starts when this person signs in (Run, RunOnce, a
 *                logon script, a user-level shell); hijacks only a user can
 *                plant (COM objects, the keys UAC-bypass tricks write);
 *                what they ran (UserAssist, decoded from ROT13), typed in
 *                Run, searched for, connected to by Remote Desktop, the
 *                Sysinternals tools whose licence they accepted, the
 *                documents whose macros they enabled
 *   SOFTWARE     what starts for everyone (Run keys, Winlogon's Shell and
 *                Userinit, Image File Execution Options — the sticky-keys
 *                backdoor —, AppInit_DLLs, scheduled tasks); Defender
 *                turned off or told to look away; remote-access software
 *                installed; the Windows version and its owner
 *   SYSTEM       the services (which run as SYSTEM: PsExec's, a shell, a
 *                DLL in a writable folder), the DLLs LSA loads (they see
 *                every password), WDigest keeping passwords in clear,
 *                Remote Desktop, the firewall, USB disks, and the
 *                ShimCache and BAM — programs that ran, even deleted ones
 *   SAM          the local accounts: hidden ones ending in $, when each
 *                last signed in
 *   SECURITY     the names of the LSA secrets (service passwords kept)
 *   Amcache.hve  programs that ran, with their SHA-1
 *   any hive     keys deleted but still in its free space; changes not yet
 *                written (the .LOG files hold them); a broken checksum
 *
 * Each finding names its key, so the reader's tree can mark it.
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import { plural, some } from "../office.ts";
import { scanScript } from "../text/script.ts";
import type { Hive, RegKey, RegValue } from "../forensic/regf.ts";
import { parseShimCache } from "../forensic/shimcache.ts";
import { shown } from "./evtx.ts";
import { toolNote } from "./forensic.ts";

export type HiveKind = "SYSTEM" | "SOFTWARE" | "SAM" | "SECURITY" | "NTUSER" | "UsrClass" | "Amcache" | "BCD" | "unknown";

/** A key worth a look, for the reader's tree. */
export interface Place {
	/** From the hive's root, without the root's own name. */
	path: string;
	why: string;
	level: "info" | "warn";
}

export interface HiveFindings {
	kind: HiveKind;
	facts: Fact[];
	places: Place[];
}

/** What the hive is, by the keys at its top (and the name it had). */
export function hiveKind(h: Hive): HiveKind {
	const top = new Set(h.subkeys(h.root).map((k) => k.name.toLowerCase()));
	if (top.has("select") && [...top].some((n) => n.startsWith("controlset"))) return "SYSTEM";
	if (top.has("policy") && top.has("rxact")) return "SECURITY";
	if (top.has("sam") && top.size <= 3) return "SAM";
	if (top.has("root") && (h.path("Root\\InventoryApplicationFile") || h.path("Root\\File"))) return "Amcache";
	if (top.has("microsoft") && (top.has("classes") || top.has("clients") || top.has("policies"))) return "SOFTWARE";
	if (top.has("software") && (top.has("control panel") || top.has("environment"))) return "NTUSER";
	if (top.has("local settings") || (top.has("clsid") && top.has("interface"))) return "UsrClass";
	if (top.has("objects") && top.has("description")) return "BCD";
	return "unknown";
}

/** How the key paths are written for a person: where Windows mounts the hive. */
export const MOUNT: Record<HiveKind, string> = { SYSTEM: "HKLM\\SYSTEM", SOFTWARE: "HKLM\\SOFTWARE", SAM: "HKLM\\SAM", SECURITY: "HKLM\\SECURITY", NTUSER: "HKCU", UsrClass: "HKCU\\Software\\Classes", Amcache: "Amcache", BCD: "BCD", unknown: "" };

const q = (s: string, n = 120) => `“${s.replace(/\s+/g, " ").slice(0, n)}${s.length > n ? "…" : ""}”`;
const when = (t: string) => (t ? t.slice(0, 19).replace("T", " ") : "?");
const dword = (v: RegValue | null): number | null => (v?.data && v.data.length >= 4 && (v.type === 4 || v.type === 3 || v.type === 11) ? new DataView(v.data.buffer, v.data.byteOffset, 4).getUint32(0, true) : null);
/** UTF-16 text up to its first NUL (the MRU lists keep strings as REG_BINARY, too). */
const utf16 = (v: RegValue | null): string => (v?.data ? new TextDecoder("utf-16le").decode(v.data.subarray(0, v.data.length & ~1)).replace(/\0[\s\S]*$/, "") : "");
/** A string value as Windows reads it: up to its first NUL (the tree shows what follows). */
const text = (v: RegValue | null): string => (!v ? "" : v.type === 7 ? v.text : v.type === 1 || v.type === 2 || v.type === 6 ? utf16(v) : "");

/** The program a command line runs: quoted, or up to its extension (paths have spaces). */
export function programOf(cmd: string): string {
	const c = cmd.trim();
	return /^"([^"]+)"/.exec(c)?.[1] ?? /^(.*?\.(?:exe|dll|sys|com|bat|cmd|ps1|vbs|js|hta|scr|cpl))\b/i.exec(c)?.[1] ?? c.split(/\s+/)[0] ?? "";
}

/** Folders any user can write to — where a program has no business starting from (unless it is one of the known per-user installs). */
const WRITABLE = /\\users\\[^\\]+\\(?:appdata|downloads|desktop|documents|music|pictures|videos)\\|\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\temp\\|\\\$recycle\.bin\\|\\perflogs\\|%(?:temp|tmp|appdata|localappdata|userprofile|public|programdata)%/i;
/** Programs that live in such folders by design: per-user installs, and Defender itself (Windows 10 runs it from ProgramData). */
const KNOWN_APPS = /\\(?:microsoft\\(?:onedrive|teams|edge\\application|windows defender(?: advanced threat protection)?)|discord|spotify|slack|zoom|dropbox|google\\(?:chrome|drive)|whatsapp|telegram desktop|programs\\(?:microsoft vs code|python|signal))\\/i;
/** Programs that run other code: started by themselves, they are how a script gets a foothold. */
const INTERPRETER = /^(cmd|powershell|pwsh|wscript|cscript|mshta|certutil|bitsadmin|wmic|schtasks|msbuild|installutil|regasm|regsvcs|cmstp|forfiles|bash|wsl)(?:\.exe)?$/i;
/** Loaders Windows itself uses all the time: suspect only when what they load is somewhere odd. */
const LOADER = /^(rundll32|regsvr32|msiexec|conhost)(?:\.exe)?$/i;

/** Windows' own programs, by where Windows keeps them: the same name anywhere else is a disguise. */
const SYSTEM_EXE = /^(?:svchost|lsass|csrss|winlogon|services|smss|wininit|lsm|spoolsv|taskhost|taskhostw|dllhost|conhost|rundll32|dwm|ctfmon|taskmgr|searchindexer|wuauclt|msiexec|regsvr32)\.exe$/i;
const SYSTEM_HOME = /^(?:"?(?:[a-z]:|%systemroot%|%windir%|\\systemroot)\\(?:windows\\)?(?:system32|syswow64)\\)[^\\]+$/i;

/** What is wrong with a program a list of what ran names (ShimCache, BAM, Amcache, UserAssist), if
 * anything: a tool by name (but not Windows' own dual-use tools in their own folder — every computer
 * has run regsvr32), a program in a folder anyone can write to, Windows' name somewhere else. */
export function oddProgram(path: string): string | null {
	const p = path.replace(/^\\\?\?\\/, "").replace(/^\\Device\\HarddiskVolume\d+/i, "C:");
	const exe = p.split("\\").pop() ?? "";
	const tool = toolNote(exe);
	if (tool && !(/misuse/.test(tool) && SYSTEM_HOME.test(p))) return tool;
	if (SYSTEM_EXE.test(exe) && p.includes("\\") && !SYSTEM_HOME.test(p)) return `named like Windows' own ${exe.toLowerCase()}, but not where Windows keeps it — a disguise`;
	if (WRITABLE.test(p) && /\.(?:exe|scr|bat|cmd|ps1|com|pif|vbs|js|hta|dll)$/i.test(p) && !KNOWN_APPS.test(p)) return "from a folder anyone can write to";
	return null;
}

/** How a command that starts by itself looks: what is wrong with it, if anything. */
export function judge(cmd: string): { level: "info" | "warn"; why: string } {
	const r = scanScript(cmd);
	if (r.decoded[0]) return { level: "warn", why: `it hides a PowerShell command — decoded: ${q(r.decoded[0].text, 120)}` };
	if (r.findings[0]) return { level: "warn", why: `it ${r.findings[0].what}` };
	const prog = programOf(cmd);
	const exe = prog.split("\\").pop() ?? "";
	const tool = toolNote(exe);
	if (tool) return { level: "warn", why: `${exe}: ${tool}` };
	if (SYSTEM_EXE.test(exe) && prog.includes("\\") && !SYSTEM_HOME.test(prog.replace(/^\\\?\?\\/, ""))) return { level: "warn", why: `named like Windows' own ${exe.toLowerCase()}, but not where Windows keeps it — a disguise` };
	const interp = INTERPRETER.exec(exe);
	if (interp) return { level: "warn", why: `it runs ${interp[1]!.toLowerCase()} — a program that runs other code` };
	const loader = LOADER.exec(exe);
	if (loader && ((WRITABLE.test(cmd) && !KNOWN_APPS.test(cmd)) || /https?:|\\\\/i.test(cmd))) return { level: "warn", why: `${loader[1]!.toLowerCase()} loads something from a folder anyone can write to, or from elsewhere` };
	if (WRITABLE.test(prog) && !KNOWN_APPS.test(prog)) return { level: "warn", why: "from a folder anyone can write to" };
	return { level: "info", why: "" };
}

const ROT13 = (s: string) => s.replace(/[a-z]/gi, (c) => String.fromCharCode(((c.charCodeAt(0) & 31) + 12) % 26 + (c.charCodeAt(0) & 96) + 1));
/** KNOWNFOLDERID → where it is, for UserAssist's names. */
const KNOWN: Record<string, string> = {
	"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%SystemRoot%\\System32",
	"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "%SystemRoot%\\SysWOW64",
	"{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%SystemRoot%",
	"{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
	"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
	"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "%ProgramFiles%",
	"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
	"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs",
	"{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%AppData%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
	"{374DE290-123F-4565-9164-39C4925E467B}": "%UserProfile%\\Downloads",
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%UserProfile%\\Desktop",
	"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%UserProfile%\\Documents",
	"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "%LocalAppData%",
	"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "%AppData%",
	"{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "%ProgramData%",
	"{DFDF76A2-C82A-4D63-906A-5644AC457385}": "%Public%",
};

export interface UserAssistEntry {
	/** The name as Windows meant it (ROT13 undone), known folders spelled out. */
	name: string;
	/** ROT13 undone, nothing else (what other tools print). */
	raw: string;
	runs: number;
	focusMs: number | null;
	last: string;
}

/** UserAssist: Explorer's count of what this person started, names in ROT13. */
export function userAssist(h: Hive): UserAssistEntry[] {
	const out: UserAssistEntry[] = [];
	const ua = h.path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
	if (!ua) return out;
	for (const g of h.subkeys(ua)) {
		const count = h.child(g, "Count");
		if (!count) continue;
		for (const v of h.values(count)) {
			if (!v.data) continue;
			const raw = ROT13(v.name);
			if (/^UEME_/.test(raw)) continue; // (Explorer's own counters)
			const d = new DataView(v.data.buffer, v.data.byteOffset, v.data.byteLength);
			let runs = 0;
			let focusMs: number | null = null;
			let last = "";
			if (v.data.length >= 72) {
				runs = d.getUint32(4, true);
				focusMs = d.getUint32(12, true);
				last = ftAt(v.data, 60);
			} else if (v.data.length >= 16) {
				// Windows XP: the count starts at 5.
				runs = Math.max(0, d.getUint32(4, true) - 5);
				last = ftAt(v.data, 8);
			} else continue;
			const name = raw.replace(/^\{[0-9A-F-]{36}\}/i, (gu) => KNOWN[gu.toUpperCase()] ?? gu);
			out.push({ name, raw, runs, focusMs, last });
			if (out.length >= 5000) return out;
		}
	}
	return out;
}

function ftAt(d: Uint8Array, at: number): string {
	if (d.length < at + 8) return "";
	const v = new DataView(d.buffer, d.byteOffset, d.byteLength);
	const t = (BigInt(v.getUint32(at + 4, true)) << 32n) | BigInt(v.getUint32(at, true));
	if (!t || t > 2650467743999999999n) return "";
	const secs = Number(t / 10_000_000n) - 11_644_473_600;
	return `${new Date(secs * 1000).toISOString().slice(0, 19)}.${String(t % 10_000_000n).padStart(7, "0")}Z`;
}

/** A Windows SYSTEMTIME (16 bytes: year, month, weekday, day, hour, minute, second, ms). */
function systemtime(d: Uint8Array | null): string {
	if (!d || d.length < 16) return "";
	const v = new DataView(d.buffer, d.byteOffset, 16);
	const [y, mo, , da, h, mi, s] = [0, 2, 4, 6, 8, 10, 12].map((o) => v.getUint16(o, true)) as number[];
	if (!y || !mo) return "";
	const p = (n: number) => String(n).padStart(2, "0");
	return `${y}-${p(mo!)}-${p(da!)} ${p(h!)}:${p(mi!)}:${p(s!)}`;
}

/** A scheduled task's actions (TaskCache › Tasks › {id} › Actions, Windows 8 and later): the commands it runs. */
export function taskActions(d: Uint8Array): string[] {
	const out: string[] = [];
	const v = new DataView(d.buffer, d.byteOffset, d.byteLength);
	const dec = new TextDecoder("utf-16le");
	let p = 0;
	const str = (): string => {
		if (p + 4 > d.length) throw new RangeError("end");
		const n = v.getUint32(p, true);
		p += 4;
		if (n > 65536 || p + n > d.length) throw new RangeError("length");
		const s = dec.decode(d.subarray(p, p + n));
		p += n;
		return s;
	};
	try {
		if (d.length < 2) return out;
		const version = v.getUint16(0, true);
		p = 2;
		if (version >= 2) str(); // the author (context)
		while (p + 2 <= d.length && out.length < 32) {
			const magic = v.getUint16(p, true);
			p += 2;
			if (magic === 0x6666) {
				str(); // its id
				const command = str();
				const args = str();
				str(); // its working folder
				if (version >= 3) p += 2;
				out.push(args ? `${command} ${args}` : command);
			} else if (magic === 0x7777) {
				p += 16; // a COM handler: its CLSID
				out.push("(a COM handler)");
				str();
			} else break;
		}
	} catch (e) {
		if (!(e instanceof RangeError)) throw e;
	}
	return out;
}

export interface SamUser {
	name: string;
	rid: number;
	lastLogon: string;
	passwordSet: string;
	logons: number;
	disabled: boolean;
}

/** The SAM's local accounts: names, RIDs, and the F value's times and flags (never the V value's hashes). */
export function samUsers(h: Hive): SamUser[] {
	const out: SamUser[] = [];
	const users = h.path("SAM\\Domains\\Account\\Users");
	const names = users && h.child(users, "Names");
	if (!users || !names) return out;
	for (const n of h.subkeys(names).slice(0, 2000)) {
		// The RID is the default value's TYPE (a quirk of the SAM).
		const rid = h.values(n).find((v) => v.name === "")?.type ?? -1;
		const k = rid >= 0 ? h.child(users, rid.toString(16).toUpperCase().padStart(8, "0")) : null;
		const f = k ? h.get(k, "F") : null;
		const d = f?.data;
		const ok = d && d.length >= 68;
		const dv = ok ? new DataView(d.buffer, d.byteOffset, d.byteLength) : null;
		out.push({ name: n.name, rid, lastLogon: ok ? ftAt(d, 8) : "", passwordSet: ok ? ftAt(d, 24) : "", logons: dv ? dv.getUint16(66, true) : 0, disabled: dv ? !!(dv.getUint16(56, true) & 1) : false });
	}
	return out;
}

export function hiveFindings(h: Hive): HiveFindings {
	const kind = hiveKind(h);
	const mount = MOUNT[kind];
	const warn: Fact[] = [];
	const info: Fact[] = [];
	const places: Place[] = [];
	const note = (path: string, level: "info" | "warn", text: string, why = text) => {
		(level === "warn" ? warn : info).push({ level, text });
		if (path && places.length < 500) places.push({ path, why, level });
	};
	const full = (p: string) => `${mount ? `${mount}\\` : ""}${p}`;

	// ── What runs by itself: a key of values, each a command ─────────────
	const runKey = (p: string, label: string) => {
		const k = h.path(p);
		if (!k) return;
		for (const v of h.values(k).slice(0, 200)) {
			const cmd = text(v);
			if (!cmd) continue;
			const j = judge(cmd);
			note(p, j.level, `${label} (${full(p)}): ${q(v.name || "(default)", 60)} → ${q(cmd, 160)}${j.why ? ` — ${j.why}` : ""}`, `${label}: ${v.name || "(default)"}${j.why ? ` — ${j.why}` : ""}`);
		}
	};

	if (kind === "NTUSER") {
		const RUN = "Software\\Microsoft\\Windows\\CurrentVersion";
		runKey(`${RUN}\\Run`, "Starts at sign-in");
		runKey(`${RUN}\\RunOnce`, "Starts once, at the next sign-in");
		runKey(`${RUN}\\Policies\\Explorer\\Run`, "Starts at sign-in (by policy)");
		const win = h.path("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
		for (const n of ["Load", "Run"]) {
			const c = win ? text(h.get(win, n)) : "";
			if (c) note("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "warn", `Starts at sign-in through the old “${n}” value: ${q(c, 160)}`);
		}
		const wl = h.path("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
		const shell = wl ? text(h.get(wl, "Shell")) : "";
		if (shell) note("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "warn", `Replaces this person's desktop shell: ${q(shell, 160)} (Winlogon › Shell for one user)`);
		const env = h.path("Environment");
		const script = env ? text(h.get(env, "UserInitMprLogonScript")) : "";
		if (script) note("Environment", "warn", `A logon script runs at every sign-in: ${q(script, 160)} (Environment › UserInitMprLogonScript)`);
		// What UAC-bypass tricks write: a command for a program Windows elevates by itself.
		for (const [p, how] of [
			["Software\\Classes\\ms-settings\\Shell\\Open\\command", "fodhelper.exe and ComputerDefaults.exe"],
			["Software\\Classes\\mscfile\\shell\\open\\command", "eventvwr.exe"],
			["Software\\Classes\\exefile\\shell\\open\\command", "every program started"],
			["Software\\Classes\\Folder\\shell\\open\\command", "sdclt.exe"],
		] as const) {
			const k = h.path(p);
			const c = k ? text(h.get(k, "")) : "";
			if (k && (c || h.get(k, "DelegateExecute"))) note(p, "warn", `A UAC bypass: ${full(p)} runs ${q(c || "(DelegateExecute)", 140)} when ${how} start — with administrator rights, without asking`);
		}
		comHijacks("Software\\Classes\\CLSID");
		// What the person did.
		const mru = h.path(`${RUN}\\Explorer\\RunMRU`);
		if (mru) {
			const order = text(h.get(mru, "MRUList"));
			const typed = [...order].map((c) => text(h.get(mru, c)).replace(/\\1$/, "")).filter(Boolean);
			if (typed.length) {
				const bad = typed.map((t) => [t, judge(t)] as const).filter(([, j]) => j.level === "warn");
				note(`${RUN}\\Explorer\\RunMRU`, bad.length ? "warn" : "info", `Typed in the Run box (newest first): ${some(typed.map((t) => q(t, 80)), 4)}${bad.length ? ` — ${q(bad[0]![0], 80)}: ${bad[0]![1].why}` : ""}`);
			}
		}
		const wq = h.path(`${RUN}\\Explorer\\WordWheelQuery`);
		if (wq) {
			const list = h.get(wq, "MRUListEx")?.data;
			const order: number[] = [];
			if (list) for (let i = 0; i + 4 <= list.length; i += 4) {
				const n = new DataView(list.buffer, list.byteOffset + i, 4).getUint32(0, true);
				if (n === 0xffffffff) break;
				order.push(n);
			}
			const terms = order.map((n) => utf16(h.get(wq, String(n)))).filter(Boolean);
			if (terms.length) note(`${RUN}\\Explorer\\WordWheelQuery`, "info", `Searched for in Explorer (newest first): ${some(terms.map((t) => q(t, 60)), 6)}`);
		}
		const tp = h.path(`${RUN}\\Explorer\\TypedPaths`);
		if (tp) {
			const paths = h.values(tp).filter((v) => /^url\d+$/i.test(v.name)).sort((a, b) => Number(a.name.slice(3)) - Number(b.name.slice(3))).map((v) => text(v));
			if (paths.length) note(`${RUN}\\Explorer\\TypedPaths`, "info", `Typed in Explorer's address bar (newest first): ${some(paths.map((t) => q(t, 80)), 4)}`);
		}
		const ua = userAssist(h);
		if (ua.length) {
			const ran = ua.filter((u) => u.runs > 0).sort((a, b) => b.runs - a.runs);
			const odd = ua.filter((u) => oddProgram(u.name));
			for (const o of odd.slice(0, 5)) note(`${RUN}\\Explorer\\UserAssist`, "warn", `Started ${q(o.name, 140)} ${plural(o.runs, "time")}${o.last ? `, last ${when(o.last)} UTC` : ""} (UserAssist) — ${oddProgram(o.name)}`);
			note(`${RUN}\\Explorer\\UserAssist`, "info", `Programs this person started (UserAssist, ${ua.length}): most often ${some(ran.slice(0, 4).map((u) => `${q(u.name.split("\\").pop() ?? u.name, 50)} ×${u.runs}`), 4)}`);
		}
		const rdp = h.path("Software\\Microsoft\\Terminal Server Client\\Servers");
		if (rdp) {
			const servers = h.subkeys(rdp).map((s) => `${s.name}${text(h.get(s, "UsernameHint")) ? ` as ${text(h.get(s, "UsernameHint"))}` : ""}`);
			if (servers.length) note("Software\\Microsoft\\Terminal Server Client\\Servers", "info", `Connected by Remote Desktop to: ${some(servers.map((s) => q(s, 80)), 5)}`);
		}
		const sys = h.path("Software\\Sysinternals");
		if (sys) {
			const used = h.subkeys(sys).filter((t) => dword(h.get(t, "EulaAccepted")) === 1);
			const named = used.map((t) => `${t.name} (${when(t.written)})`);
			const strong = used.filter((t) => /psexec|procdump|sdelete|psloggedon|pskill|psservice|accesschk/i.test(t.name));
			if (used.length) note("Software\\Sysinternals", strong.length ? "warn" : "info", `Sysinternals tools first run by this person (their licence accepted): ${some(named, 6)}${strong.length ? " — PsExec, ProcDump and SDelete are an intruder's favourites" : ""}`);
		}
		const office = h.path("Software\\Microsoft\\Office");
		if (office) {
			const enabled: string[] = [];
			for (const ver of h.subkeys(office).slice(0, 20)) for (const app of h.subkeys(ver).slice(0, 40)) {
				const tr = h.path(`Software\\Microsoft\\Office\\${ver.name}\\${app.name}\\Security\\Trusted Documents\\TrustRecords`);
				if (!tr) continue;
				for (const v of h.values(tr)) {
					const d = v.data;
					if (d && d.length >= 4 && d[d.length - 4] === 0xff && d[d.length - 3] === 0xff && d[d.length - 2] === 0xff && d[d.length - 1] === 0x7f) enabled.push(`${v.name} (${app.name})`);
				}
			}
			if (enabled.length) note("Software\\Microsoft\\Office", "warn", `Macros (“Enable Content”) were allowed in ${plural(enabled.length, "document")}: ${some(enabled.map((e) => q(e, 100)), 3)} — Office remembers the click`);
		}
	}

	if (kind === "UsrClass") comHijacks("CLSID");

	if (kind === "SOFTWARE") {
		const cv = h.path("Microsoft\\Windows NT\\CurrentVersion");
		if (cv) {
			const product = text(h.get(cv, "ProductName"));
			const build = text(h.get(cv, "CurrentBuildNumber")) || text(h.get(cv, "CurrentBuild"));
			const installed = dword(h.get(cv, "InstallDate"));
			const owner = text(h.get(cv, "RegisteredOwner"));
			if (product) info.push({ level: "info", text: `${product}${build ? ` (build ${build})` : ""}${installed ? `, installed ${new Date(installed * 1000).toISOString().slice(0, 19).replace("T", " ")} UTC` : ""}${owner ? `, registered to ${q(owner, 60)}` : ""}` });
		}
		for (const base of ["Microsoft", "Wow6432Node\\Microsoft"]) {
			runKey(`${base}\\Windows\\CurrentVersion\\Run`, "Starts at every sign-in");
			runKey(`${base}\\Windows\\CurrentVersion\\RunOnce`, "Starts once, at the next sign-in");
			runKey(`${base}\\Windows\\CurrentVersion\\RunServices`, "Starts with Windows");
			runKey(`${base}\\Windows\\CurrentVersion\\Policies\\Explorer\\Run`, "Starts at every sign-in (by policy)");
			const win = h.path(`${base}\\Windows NT\\CurrentVersion\\Windows`);
			const appinit = win ? text(h.get(win, "AppInit_DLLs")).trim() : "";
			if (appinit && dword(h.get(win!, "LoadAppInit_DLLs")) !== 0) note(`${base}\\Windows NT\\CurrentVersion\\Windows`, "warn", `AppInit_DLLs loads ${q(appinit, 140)} into every program that uses user32.dll`);
		}
		const wl = h.path("Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
		if (wl) {
			const shell = text(h.get(wl, "Shell")).trim();
			const userinit = text(h.get(wl, "Userinit")).trim();
			if (shell && !/^explorer\.exe,?$/i.test(shell)) note("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "warn", `Winlogon's Shell is ${q(shell, 140)}, not explorer.exe — it runs at every sign-in`);
			if (userinit && !/^[a-z]:\\windows\\system32\\userinit\.exe,?$/i.test(userinit)) note("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "warn", `Winlogon's Userinit is ${q(userinit, 140)} — anything after userinit.exe runs at every sign-in`);
			for (const n of ["Taskman", "AppSetup", "GinaDLL"]) {
				const c = text(h.get(wl, n));
				if (c) note("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "warn", `Winlogon › ${n} runs ${q(c, 140)}`);
			}
		}
		// Image File Execution Options: a "debugger" Windows starts instead of the program.
		const ifeo = h.path("Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
		if (ifeo) for (const k of h.subkeys(ifeo).slice(0, 5000)) {
			const dbg = text(h.get(k, "Debugger"));
			if (dbg) {
				const access = /^(?:sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)\.exe$/i.test(k.name);
				note(`Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\${k.name}`, "warn", access ? `The sticky-keys backdoor: starting ${k.name} (reachable at the sign-in screen, before anyone signs in) runs ${q(dbg, 120)} instead — as SYSTEM` : `Starting ${k.name} runs ${q(dbg, 120)} instead (Image File Execution Options › Debugger)`);
			}
			if ((dword(h.get(k, "GlobalFlag")) ?? 0) & 0x200) {
				const mon = h.path(`Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\${k.name}`);
				const m = mon ? text(h.get(mon, "MonitorProcess")) : "";
				if (m) note(`Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\${k.name}`, "warn", `When ${k.name} exits, Windows starts ${q(m, 120)} (SilentProcessExit)`);
			}
		}
		// Defender told to look away, or to stop.
		const exPaths: string[] = [];
		for (const kind2 of ["Paths", "Extensions", "Processes", "IpAddresses"]) for (const base of ["Microsoft\\Windows Defender\\Exclusions", "Policies\\Microsoft\\Windows Defender\\Exclusions"]) {
			const k = h.path(`${base}\\${kind2}`);
			if (k) for (const v of h.values(k)) exPaths.push(`${v.name} (${kind2.toLowerCase()})`);
		}
		if (exPaths.length) note("Microsoft\\Windows Defender\\Exclusions", "warn", `Defender is told not to look at: ${some(exPaths.map((e) => q(e, 80)), 4)}`);
		for (const [p, n, what] of [
			["Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", "Defender turned off by policy"],
			["Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", "Defender's real-time protection turned off by policy"],
			["Microsoft\\Windows Defender", "DisableAntiSpyware", "Defender turned off"],
			["Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", "Defender's real-time protection turned off"],
		] as const) {
			const k = h.path(p);
			if (k && dword(h.get(k, n)) === 1) note(p, "warn", `${what} (${n} = 1)`);
		}
		const sbl = h.path("Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging");
		if (sbl && dword(h.get(sbl, "EnableScriptBlockLogging")) === 0) note("Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "warn", "PowerShell script-block logging turned off by policy — the 4104 events will not be there");
		// Scheduled tasks (Windows 8 and later keep their actions here).
		const tasks = h.path("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks");
		if (tasks) {
			let n = 0;
			for (const t of h.subkeys(tasks).slice(0, 5000)) {
				n++;
				const path = text(h.get(t, "Path"));
				const actions = h.get(t, "Actions")?.data;
				for (const a of actions ? taskActions(actions) : []) {
					const j = judge(a);
					if (j.level === "warn") note(`Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\${t.name}`, "warn", `Scheduled task ${q(path || t.name, 80)} runs ${q(a, 140)} — ${j.why}`);
				}
			}
			if (n) info.push({ level: "info", text: `${plural(n, "scheduled task")} registered (TaskCache)` });
		}
		// Remote-access software installed, and what else is.
		const remote = /anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|rustdesk|ammyy|logmein|remotepc|supremo|ultraviewer|ngrok|radmin|dameware|netsupport|meshagent|tightvnc|realvnc|ultravnc/i;
		const apps: string[] = [];
		const remotes: string[] = [];
		for (const base of ["Microsoft\\Windows\\CurrentVersion\\Uninstall", "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"]) {
			const u = h.path(base);
			if (!u) continue;
			for (const k of h.subkeys(u).slice(0, 3000)) {
				const name = text(h.get(k, "DisplayName"));
				if (!name) continue;
				apps.push(name);
				if (remote.test(name)) remotes.push(`${name}${text(h.get(k, "InstallDate")) ? ` (installed ${text(h.get(k, "InstallDate"))})` : ""}`);
			}
		}
		if (remotes.length) note("Microsoft\\Windows\\CurrentVersion\\Uninstall", "warn", `Remote-access software installed: ${some(remotes.map((r) => q(r, 80)), 4)} — how intruders keep a hand in`);
		if (apps.length) info.push({ level: "info", text: `${plural(new Set(apps).size, "program")} installed (Uninstall)` });
		const pl = h.path("Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
		if (pl) {
			const profiles = h.subkeys(pl).map((k) => text(h.get(k, "ProfileImagePath"))).filter((p) => /\\users\\/i.test(p));
			if (profiles.length) info.push({ level: "info", text: `User profiles: ${some(profiles.map((p) => p.split("\\").pop()!), 8)}` });
		}
		const nl = h.path("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles");
		if (nl) {
			const nets = h.subkeys(nl).map((k) => `${text(h.get(k, "ProfileName"))}${systemtime(h.get(k, "DateLastConnected")?.data ?? null) ? ` (last ${systemtime(h.get(k, "DateLastConnected")!.data)})` : ""}`).filter((s) => s.trim());
			if (nets.length) info.push({ level: "info", text: `Networks it joined: ${some(nets.map((n) => q(n, 70)), 5)}` });
		}
	}

	if (kind === "SYSTEM") {
		const cur = dword(h.path("Select") && h.get(h.path("Select")!, "Current")) ?? 1;
		const CS = `ControlSet${String(cur).padStart(3, "0")}`;
		const cn = h.path(`${CS}\\Control\\ComputerName\\ComputerName`);
		const name = cn ? text(h.get(cn, "ComputerName")) : "";
		const tz = h.path(`${CS}\\Control\\TimeZoneInformation`);
		const zone = tz ? text(h.get(tz, "TimeZoneKeyName")) || text(h.get(tz, "StandardName")) : "";
		const wnd = h.path(`${CS}\\Control\\Windows`);
		const shutdown = wnd ? ftAt(h.get(wnd, "ShutdownTime")?.data ?? new Uint8Array(0), 0) : "";
		info.push({ level: "info", text: `The computer ${name ? q(name, 40) : "(no name)"}${zone ? `, time zone ${q(zone, 60)}` : ""}${shutdown ? `, last shut down ${when(shutdown)} UTC` : ""} (control set ${cur})` });
		// Services: they run as SYSTEM, start by themselves, and survive a reboot.
		const svc = h.path(`${CS}\\Services`);
		if (svc) {
			let count = 0;
			let auto = 0;
			const odd: { k: RegKey; cmd: string; why: string; dll: boolean }[] = [];
			for (const k of h.subkeys(svc).slice(0, 5000)) {
				count++;
				const start = dword(h.get(k, "Start"));
				if (start === 2) auto++;
				const image = text(h.get(k, "ImagePath"));
				const params = h.child(k, "Parameters");
				const dll = params ? text(h.get(params, "ServiceDll")) : "";
				for (const [cmd, isDll] of [[image, false], [dll, true]] as const) {
					if (!cmd) continue;
					const j = /^PSEXESVC$|^(?:PAEXEC|CSEXEC|REMCOM)/i.test(k.name) || /PSEXESVC/i.test(cmd) ? { level: "warn" as const, why: "PsExec's: a command run from another computer" } : judge(cmd);
					if (j.level === "warn") odd.push({ k, cmd, why: j.why, dll: isDll });
				}
			}
			for (const o of odd.slice(0, 6)) note(`${CS}\\Services\\${o.k.name}`, "warn", `Service ${q(o.k.name, 60)} ${o.dll ? "loads" : "runs"} ${q(o.cmd, 140)} — ${o.why} (written ${when(o.k.written)} UTC)`);
			if (odd.length > 6) warn.push({ level: "warn", text: `…and ${plural(odd.length - 6, "more service")} like them: ${some(odd.slice(6).map((o) => o.k.name), 4)}` });
			info.push({ level: "info", text: `${plural(count, "service and driver", "services and drivers")} (${auto} start automatically)` });
		}
		// The DLLs LSA loads: each one sees every password typed.
		const lsa = h.path(`${CS}\\Control\\Lsa`);
		if (lsa) {
			const known: Record<string, RegExp> = {
				"Authentication Packages": /^(?:msv1_0)$/i,
				"Notification Packages": /^(?:scecli|rassfm|kdcsvc)$/i,
				"Security Packages": /^(?:kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|livessp|cloudap|negoexts|""|)$/i,
			};
			for (const [n, ok] of Object.entries(known)) {
				const extra = text(h.get(lsa, n)).split(/\n/).map((s) => s.trim()).filter((s) => s && !ok.test(s));
				if (extra.length) note(`${CS}\\Control\\Lsa`, "warn", `LSA loads ${some(extra.map((e) => q(e, 60)), 4)} as ${n.toLowerCase().replace(/s$/, "")}s — a DLL there sees every password typed (a password filter or SSP)`);
			}
			if (dword(h.get(lsa, "RunAsPPL")) === 1) info.push({ level: "info", text: "LSASS runs protected (RunAsPPL) — harder to dump" });
			if (dword(h.get(lsa, "DisableRestrictedAdmin")) === 0) note(`${CS}\\Control\\Lsa`, "warn", "Restricted Admin is on (DisableRestrictedAdmin = 0): Remote Desktop accepts a password hash — pass-the-hash over RDP");
		}
		const wd = h.path(`${CS}\\Control\\SecurityProviders\\WDigest`);
		if (wd && dword(h.get(wd, "UseLogonCredential")) === 1) note(`${CS}\\Control\\SecurityProviders\\WDigest`, "warn", "WDigest keeps passwords in memory in clear (UseLogonCredential = 1) — set before Mimikatz is run, so it can read them");
		const ts = h.path(`${CS}\\Control\\Terminal Server`);
		if (ts && dword(h.get(ts, "fDenyTSConnections")) === 0) {
			const tcp = h.path(`${CS}\\Control\\Terminal Server\\WinStations\\RDP-Tcp`);
			const port = tcp ? dword(h.get(tcp, "PortNumber")) : null;
			const nla = tcp ? dword(h.get(tcp, "UserAuthentication")) : null;
			note(`${CS}\\Control\\Terminal Server`, port && port !== 3389 ? "warn" : "info", `Remote Desktop is on${port ? `, on port ${port}${port !== 3389 ? " (moved from 3389)" : ""}` : ""}${nla === 0 ? ", without Network Level Authentication" : ""}`);
		}
		const fw = h.path(`${CS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy`);
		if (fw) {
			const off = ["DomainProfile", "StandardProfile", "PublicProfile"].filter((p) => {
				const k = h.child(fw, p);
				return k && dword(h.get(k, "EnableFirewall")) === 0;
			});
			if (off.length) note(`${CS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy`, "warn", `The firewall is off for ${some(off.map((o) => o.replace("Profile", "").replace("Standard", "private")), 3)}`);
		}
		const sm = h.path(`${CS}\\Control\\Session Manager`);
		if (sm) {
			const boot = text(h.get(sm, "BootExecute")).split("\n").map((s) => s.trim()).filter((s) => s && !/^autocheck autochk \*$/i.test(s));
			if (boot.length) note(`${CS}\\Control\\Session Manager`, "warn", `Runs before Windows starts (BootExecute): ${some(boot.map((b) => q(b, 80)), 3)}`);
			const acd = h.child(sm, "AppCertDlls");
			if (acd && h.values(acd).length) note(`${CS}\\Control\\Session Manager\\AppCertDlls`, "warn", `AppCertDlls loads ${some(h.values(acd).map((v) => q(text(v), 80)), 3)} into every program that starts another`);
		}
		const usb = h.path(`${CS}\\Enum\\USBSTOR`);
		if (usb) {
			const disks = h.subkeys(usb).flatMap((d) => h.subkeys(d).slice(0, 20).map((s) => `${text(h.get(s, "FriendlyName")) || d.name.replace(/^Disk&/, "").replace(/&/g, " ")} (serial ${s.name.replace(/&\d$/, "")})`));
			if (disks.length) note(`${CS}\\Enum\\USBSTOR`, "info", `USB storage devices plugged in: ${some(disks.map((d) => q(d, 90)), 4)} — how files leave on foot`);
		}
		// The ShimCache: programs Windows looked at, even ones since deleted.
		const ac = h.path(`${CS}\\Control\\Session Manager\\AppCompatCache`);
		const blob = ac ? h.get(ac, "AppCompatCache")?.data : null;
		const shim = blob ? parseShimCache(blob) : null;
		if (shim) {
			const seen = new Map<string, number>();
			const flagged = shim.entries.filter((e) => {
				const k = e.path.toLowerCase();
				seen.set(k, (seen.get(k) ?? 0) + 1);
				return seen.get(k) === 1 && oddProgram(e.path) !== null;
			});
			for (const e of flagged.slice(0, 5)) note(`${CS}\\Control\\Session Manager\\AppCompatCache`, "warn", `The ShimCache names ${q(e.path.replace(/^\\\?\?\\/, ""), 140)}${e.executed ? " (it ran)" : ""}${(seen.get(e.path.toLowerCase()) ?? 1) > 1 ? `, ${seen.get(e.path.toLowerCase())} times over, each time a file modified at another time (replaced again and again); the first` : ","} modified ${when(e.modified)} UTC — ${oddProgram(e.path)}`);
			info.push({ level: "info", text: `The ShimCache (${shim.format}) names ${plural(shim.entries.length, "program")}${shim.entries.some((e) => e.executed) ? `, ${shim.entries.filter((e) => e.executed).length} marked as run` : ""}` });
		}
		// BAM (Windows 10 and later): what each account ran, and when.
		for (const base of [`${CS}\\Services\\bam\\State\\UserSettings`, `${CS}\\Services\\bam\\UserSettings`]) {
			const bam = h.path(base);
			if (!bam) continue;
			const ran: { path: string; t: string; sid: string }[] = [];
			for (const sid of h.subkeys(bam).slice(0, 200)) for (const v of h.values(sid)) if (v.type === 3 && v.data && v.data.length >= 8 && v.name.includes("\\")) ran.push({ path: v.name, t: ftAt(v.data, 0), sid: sid.name });
			const odd = ran.filter((r) => oddProgram(r.path));
			for (const r of odd.slice(0, 4)) note(base, "warn", `Ran ${q(r.path.replace(/^\\Device\\HarddiskVolume\d+/i, ""), 140)} at ${when(r.t)} UTC (BAM, account …${r.sid.split("-").pop()}) — ${oddProgram(r.path)}`);
			if (ran.length) info.push({ level: "info", text: `BAM records ${plural(ran.length, "program")} run by ${plural(h.subkeys(bam).length, "account")}` });
		}
	}

	if (kind === "SAM") {
		const users = samUsers(h);
		for (const u of users.filter((x) => x.name.endsWith("$"))) note("SAM\\Domains\\Account\\Users\\Names", "warn", `A local account named ${q(u.name, 40)} (RID ${u.rid}) — a name ending in $ hides it from “net user”`);
		if (users.length) info.push({ level: "info", text: `${plural(users.length, "local account")}: ${some(users.map((u) => `${u.name} (${u.rid}${u.disabled ? ", disabled" : ""}${u.lastLogon ? `, last in ${when(u.lastLogon)}` : ""}${u.logons ? `, ${u.logons}×` : ""})`), 6)}` });
	}

	if (kind === "SECURITY") {
		const s = h.path("Policy\\Secrets");
		if (s) {
			const names = h.subkeys(s).map((k) => k.name);
			const services = names.filter((n) => /^_SC_/i.test(n));
			if (names.length) info.push({ level: "info", text: `${plural(names.length, "LSA secret")}: ${some(names, 6)}${services.length ? ` — ${plural(services.length, "service")} keep a password here (${some(services.map((n) => n.slice(4)), 3)})` : ""}` });
			if (names.some((n) => /^DefaultPassword$/i.test(n))) note("Policy\\Secrets\\DefaultPassword", "warn", "An automatic sign-in password is kept (DefaultPassword)");
		}
	}

	if (kind === "Amcache") {
		const inv = h.path("Root\\InventoryApplicationFile");
		if (inv) {
			const files = h.subkeys(inv).slice(0, 20_000).map((k) => ({ path: text(h.get(k, "LowerCaseLongPath")), sha1: text(h.get(k, "FileId")).replace(/^0000/, ""), k }));
			const odd = files.filter((f) => f.path && oddProgram(f.path));
			for (const f of odd.slice(0, 5)) {
				(warn).push({ level: "warn", text: `Amcache names ${q(f.path, 140)}${f.sha1 ? `, SHA-1 ${f.sha1}` : ""} — ${oddProgram(f.path)}`, ...(f.sha1 ? { copy: f.sha1 } : {}) });
				if (places.length < 500) places.push({ path: `Root\\InventoryApplicationFile\\${f.k.name}`, why: oddProgram(f.path) ?? "", level: "warn" });
			}
			info.push({ level: "info", text: `Amcache records ${plural(files.length, "program file")}, each with its SHA-1` });
		}
	}

	// ── Any hive: what was deleted, what is not yet written ──────────────
	const deleted = h.deleted();
	if (deleted.length) info.push({ level: "info", text: `${plural(deleted.length, "deleted key")} still in its free space (recoverable): ${some(deleted.map((d) => `${q(d.name, 40)} (${when(d.written)})`), 4)}` });
	if (h.dirty) warn.push({ level: "warn", text: "Not every change was written into it (its sequence numbers differ): the .LOG1 and .LOG2 files beside it hold the rest — collect them too" });
	for (const w of h.warnings.slice(0, 4)) warn.push({ level: "warn", text: `Malformed: ${w}` });

	const name = kind === "unknown" ? "A Windows registry hive" : `A Windows registry hive: ${kind === "NTUSER" ? "a user's NTUSER.DAT" : kind === "UsrClass" ? "a user's UsrClass.dat" : kind === "Amcache" ? "Amcache.hve" : kind}`;
	const head: Fact = { level: "info", text: `${name} (version ${h.version}), last written ${when(h.written)} UTC${h.fileName ? `, kept at ${q(h.fileName, 80)}` : ""}` };
	return { kind, facts: [head, ...warn, ...info].map((f) => ({ ...f, text: shown(f.text) })), places };

	/** COM objects a user registers win over the machine's: a DLL in a writable folder is a hijack. */
	function comHijacks(base: string): void {
		const clsid = h.path(base);
		if (!clsid) return;
		let n = 0;
		for (const k of h.subkeys(clsid).slice(0, 5000)) {
			for (const s of ["InprocServer32", "LocalServer32"]) {
				const srv = h.child(k, s);
				const dll = srv ? text(h.get(srv, "")) : "";
				if (!dll) continue;
				const j = judge(dll);
				if (j.level === "warn" && n++ < 4) note(`${base}\\${k.name}\\${s}`, "warn", `A COM object registered for this user only: ${k.name} → ${q(dll, 140)} — ${j.why}; every program that asks for it gets this instead (COM hijacking)`);
			}
		}
	}
}
