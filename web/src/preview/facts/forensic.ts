// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a shortcut or a Prefetch file says (commit 42i, docs/PREVIEWS.md ›
 * Forensic formats):
 *
 *   a shortcut   what it runs and with what (an interpreter and its
 *                payload, pushed out of the Properties box by blanks),
 *                how it hides (minimized, a PDF's icon, run as
 *                administrator, a share it reaches for, bytes after its
 *                end) — and the evidence it carries about where it was
 *                made: the machine's name, its network card, the volume
 *   a Prefetch   which program ran, how often and when (the last eight),
 *                where it ran from, the files it touched in places anyone
 *                can write, and a name that no longer matches its header
 *
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import { plural, some } from "../office.ts";
import { scanScript } from "../text/script.ts";
import type { LnkInfo } from "../forensic/lnk.ts";
import type { PrefetchInfo } from "../forensic/prefetch.ts";

const q = (s: string, n = 120) => `“${s.slice(0, n)}${s.length > n ? "…" : ""}”`;
const iso = (d: Date) => d.toISOString().replace("T", " ").slice(0, 19);

/** Programs that run other code — the targets a malicious shortcut uses. */
const INTERPRETERS = /\\(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin|curl|wmic|forfiles|conhost|schtasks|bash|wsl|msbuild|installutil|regasm|regsvcs|hh|cmstp|scriptrunner|pcalua|odbcconf|msxsl|explorer)\.exe$/i;
/** Network cards' makers by their first three bytes: the virtual ones say "made in a VM". */
const OUI: Record<string, string> = { "00:0c:29": "VMware's", "00:50:56": "VMware's", "00:05:69": "VMware's", "08:00:27": "VirtualBox's", "00:15:5d": "Hyper-V's", "52:54:00": "QEMU/KVM's", "00:1c:42": "Parallels'", "0a:00:27": "VirtualBox's" };

export function lnkFacts(l: LnkInfo, name: string): Fact[] {
	const facts: Fact[] = [];
	const target = l.target ?? "(no target it names)";
	const args = l.arguments ?? "";
	const trimmed = args.trim();
	facts.push({ level: "info", text: `A Windows shortcut → ${q(target, 160)}${trimmed ? " with arguments" : ""}` });
	const interp = INTERPRETERS.test(target) || INTERPRETERS.test(l.envTarget ?? "");
	if (interp && trimmed) facts.push({ level: "warn", text: `Runs ${target.split("\\").pop()} — a program that runs other code — with: ${q(trimmed, 200)}` });
	else if (trimmed) facts.push({ level: "info", text: `Its arguments: ${q(trimmed, 200)}` });
	const lead = args.length - args.trimStart().length;
	if (args.length > 260 || lead >= 30) facts.push({ level: "warn", text: `Its arguments are ${args.length} characters${lead ? `, the first ${lead} blank` : ""} — Windows' Properties box shows 260: the command is pushed out of sight` });
	const s = scanScript(trimmed);
	for (const f of s.findings.slice(0, 4)) facts.push({ level: "warn", text: `Its arguments: it ${f.what}` });
	for (const d of s.decoded) facts.push({ level: "warn", text: `Its arguments hide a PowerShell command in base64 — decoded: ${q(d.text, 160)}` });
	if (l.window === "minimized") facts.push({ level: interp ? "warn" : "info", text: "Opens minimized, without focus — the window it starts stays out of sight" });
	if (l.runAsAdmin) facts.push({ level: "warn", text: "Asks to run as administrator" });
	if (l.icon && (interp || /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)$/i.test(l.icon) || /\\(?:msedge|chrome|firefox|acro\w*|winword|excel|powerpnt)\.exe$/i.test(l.icon))) facts.push({ level: interp ? "warn" : "info", text: `Shows the icon of ${q(l.icon, 100)} (index ${l.iconIndex})${interp ? ` while it runs ${target.split("\\").pop()} — dressed as something else` : ""}` });
	if (l.name) facts.push({ level: "info", text: `Its description: ${q(l.name, 120)}` });
	if (l.workingDir) facts.push({ level: /%temp%|\\temp\\|appdata|programdata|public/i.test(l.workingDir) ? "warn" : "info", text: `Starts in ${q(l.workingDir, 100)}` });
	if (l.share) facts.push({ level: "warn", text: `Points at a network share: ${q(l.share.net, 100)} — opening it, Windows reaches for that server (and offers it the user's sign-in hash)` });
	if (l.appended) facts.push({ level: "warn", text: `Carries ${plural(l.appended.size, "byte")} after its end (at 0x${l.appended.offset.toString(16)}) — a payload riding the shortcut; the Hex tab shows them` });
	if (l.envTarget && l.envTarget.toLowerCase() !== target.toLowerCase()) facts.push({ level: "info", text: `Its target with environment variables: ${q(l.envTarget, 120)}` });
	// Evidence: where it was made.
	if (l.tracker) {
		const maker = l.tracker.mac ? OUI[l.tracker.mac.slice(0, 8).toLowerCase()] : undefined;
		facts.push({ level: "info", text: `Made on the machine “${l.tracker.machine}”${l.tracker.mac ? ` (network card ${l.tracker.mac}${maker ? ` — ${maker}: a virtual machine` : ""})` : ""}${l.tracker.time ? `; its target first tracked ${iso(l.tracker.time)} UTC` : ""}` });
	}
	if (l.volume) facts.push({ level: "info", text: `Its target was on a ${l.volume.type} disk, serial ${l.volume.serial}${l.volume.label ? `, label “${l.volume.label}”` : ""}` });
	const t = l.times;
	if (t.created || t.written || t.accessed) facts.push({ level: "info", text: `Its target, when the shortcut was made: ${[t.created && `created ${iso(t.created)}`, t.written && `changed ${iso(t.written)}`, t.accessed && `opened ${iso(t.accessed)}`].filter(Boolean).join(", ")} UTC${l.size ? `, ${plural(l.size, "byte")}` : ""}` });
	else facts.push({ level: "info", text: "No target times or size — made by a tool, not by Windows when someone right-clicks \"Create shortcut\"" });
	if (l.hotKey) facts.push({ level: "info", text: `A hot key starts it: ${l.hotKey}` });
	if (/\.lnk$/i.test(name) === false) facts.push({ level: "warn", text: `Named ${q(name, 60)}, but it is a shortcut — Windows runs it as one` });
	for (const w of l.warnings) facts.push({ level: "warn", text: `Malformed: ${w}` });
	return facts;
}

const VERSIONS: Record<number, string> = { 17: "Windows XP/2003", 23: "Windows Vista/7", 26: "Windows 8/8.1", 30: "Windows 10/11", 31: "Windows 11" };
/** Programs whose running is itself a finding. */
const TOOLS: [RegExp, string][] = [
	[/^RCLONE\.EXE$/, "copies files to cloud storage — a data-theft favourite"],
	[/^(?:PSEXEC(?:64)?|PSEXESVC|PAEXEC|CSEXEC|REMCOM\w*)\.EXE$/, "runs commands on other computers (lateral movement)"],
	[/^PROCDUMP(?:64)?\.EXE$/, "dumps a process's memory (LSASS: the passwords in it)"],
	[/^MIMIKATZ\.EXE$|^MIMI\w*\.EXE$/, "Mimikatz — steals credentials"],
	[/^(?:NC|NC64|NCAT|NETCAT|SOCAT)\.EXE$/, "netcat — a raw network shell"],
	[/^PLINK\.EXE$/, "PuTTY's command-line SSH — tunnels out of the network"],
	[/^(?:ANYDESK|TEAMVIEWER\w*|SCREENCONNECT\w*|ATERA\w*|SPLASHTOP\w*|RUSTDESK|AMMYY\w*|LOGMEIN\w*)\.EXE$/, "remote-access software (how intruders keep a hand in)"],
	[/^(?:NGROK|CLOUDFLARED|CHISEL)\.EXE$/, "tunnels a port out to the internet"],
	[/^ADFIND\.EXE$|^SHARPHOUND\.EXE$|^BLOODHOUND\.EXE$/, "maps Active Directory — the reconnaissance before ransomware"],
	[/^(?:WEVTUTIL)\.EXE$/, "clears event logs"],
	[/^VSSADMIN\.EXE$/, "manages (and deletes) shadow copies"],
	[/^(?:SDELETE(?:64)?|BCWIPE\w*|ERASER\w*|WIPEFILE)\.EXE$/, "wipes files beyond recovery (destroys evidence)"],
	[/^NTDSUTIL\.EXE$/, "copies the Active Directory database"],
	[/^(?:CERTUTIL|BITSADMIN|MSHTA|REGSVR32|WMIC|CMSTP|INSTALLUTIL|MSBUILD)\.EXE$/, "a Windows tool attackers misuse to fetch or run code"],
];
/** What running a program says, for the programs whose running is a finding (shared with the event-log facts, 42j). */
export const toolNote = (exe: string): string | undefined => TOOLS.find(([re]) => re.test(exe.toUpperCase()))?.[1];
const WRITABLE = /\\(?:USERS\\[^\\]+\\(?:APPDATA|DOWNLOADS|DESKTOP|DOCUMENTS)|USERS\\PUBLIC|PROGRAMDATA|WINDOWS\\TEMP|\$RECYCLE\.BIN|PERFLOGS|TEMP)\\/i;

export function prefetchFacts(p: PrefetchInfo, name: string): Fact[] {
	const facts: Fact[] = [];
	facts.push({ level: "info", text: `A Windows Prefetch file (${VERSIONS[p.version] ?? `version ${p.version}`}${p.compressed ? ", compressed" : ""}): ${p.exe} ran ${plural(p.runCount, "time")}` });
	if (p.runs.length) facts.push({ level: "info", text: `Last ran ${iso(p.runs[0]!)} UTC${p.runs.length > 1 ? `; before that ${p.runs.slice(1).map(iso).join(", ")}` : ""}` });
	const m = /^(.+)-([0-9A-F]{8})\.pf$/i.exec(name);
	if (m && (m[1]!.toUpperCase() !== p.exe.toUpperCase() || m[2]!.toUpperCase() !== p.hash)) facts.push({ level: "warn", text: `Named for ${m[1]} (${m[2]!.toUpperCase()}), but its header says ${p.exe} (${p.hash}) — renamed, or moved from another machine` });
	const tool = toolNote(p.exe);
	if (tool) facts.push({ level: "warn", text: `${p.exe} ${tool}` });
	const self = p.files.find((f) => f.toUpperCase().endsWith(`\\${p.exe.toUpperCase()}`));
	if (self) facts.push({ level: WRITABLE.test(self) ? "warn" : "info", text: `It ran from ${q(self, 160)}${WRITABLE.test(self) ? " — a folder any user can write to" : ""}` });
	const odd = p.files.filter((f) => f !== self && WRITABLE.test(f));
	if (odd.length) facts.push({ level: odd.some((f) => /\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta)$/i.test(f)) ? "warn" : "info", text: `It touched ${plural(odd.length, "file")} in folders any user can write to: ${some(odd.map((f) => q(f.replace(/^\\VOLUME\{[^}]+\}/i, ""), 90)), 4)}` });
	facts.push({ level: "info", text: `Loaded ${plural(p.files.length, "file")} in its first seconds — the Prefetch tab lists them` });
	for (const v of p.volumes.slice(0, 4)) facts.push({ level: "info", text: `On volume ${q(v.device, 80)}, serial ${v.serial}${v.created ? `, created ${iso(v.created)} UTC` : ""} (${plural(v.dirs.length, "folder")})` });
	for (const w of p.warnings) facts.push({ level: "warn", text: `Malformed: ${w}` });
	return facts;
}
