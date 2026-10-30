// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a Windows event log says (commit 42j, docs/PREVIEWS.md › Forensic
 * formats) — the questions an incident responder asks of one first, each
 * answered from the events by ID:
 *
 *   was it tampered with   cleared (1102, 104), checksums that fail, record
 *                          numbers that skip, the audit policy changed (4719)
 *   who got in, and how    failed logons by address and account, then a
 *                          success from the same address (4625 → 4624);
 *                          one address trying many accounts (spraying); RDP
 *                          (type 10, 1149, 21/25); pass-the-hash's shape
 *                          (type 9 through seclogo)
 *   what they left behind  services (7045, 4697), scheduled tasks (4698,
 *                          4702, 106), WMI consumers (5861), accounts made
 *                          and put in admin groups (4720, 4732, 4728, 4756)
 *   what they ran          process creation (4688, Sysmon 1) and PowerShell
 *                          (4104, 4103, 800) through the script triage of
 *                          42f; known tools by name; Office starting a shell
 *   what they took         DCSync (4662 with replication rights), Kerberos
 *                          service tickets in RC4 (4769: Kerberoasting),
 *                          tickets without pre-authentication (4768:
 *                          AS-REP roasting), LSASS opened (Sysmon 10),
 *                          admin shares reached (5140)
 *   what stopped them      Defender's detections (1116/1117), its real-time
 *                          protection turned off (5001), exclusions (5007)
 *
 * Each finding names the records it came from: the reader marks them in
 * its table (`notable`) so the analyst can go straight to them. Every
 * event ID is matched with its provider, since IDs repeat across them.
 * Pure: unit:preview-facts.
 */

import type { Fact } from "../host.ts";
import { plural, some, unxml } from "../office.ts";
import { scanScript } from "../text/script.ts";
import type { EvtxEvent, EvtxLog } from "../forensic/evtx.ts";
import { toolNote } from "./forensic.ts";

const SEC = "Microsoft-Windows-Security-Auditing";
const LOG = "Microsoft-Windows-Eventlog";
const SCM = "Service Control Manager";
const SYSMON = "Microsoft-Windows-Sysmon";
const PS = "Microsoft-Windows-PowerShell";
const LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager";
const RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
const TASKS = "Microsoft-Windows-TaskScheduler";
const DEFENDER = "Microsoft-Windows-Windows Defender";
const WMI = "Microsoft-Windows-WMI-Activity";

/** The IDs an analyst knows by heart, by provider. */
const NAMES: Record<string, Record<number, string>> = {
	[SEC]: {
		4608: "Windows is starting up", 4616: "The system time was changed", 4624: "An account logged on", 4625: "An account failed to log on", 4634: "An account logged off", 4647: "User initiated logoff", 4648: "A logon with explicit credentials", 4657: "A registry value was modified", 4662: "An operation was performed on a directory object", 4663: "An object was accessed", 4672: "Special privileges assigned to a logon", 4688: "A process was created", 4689: "A process exited", 4697: "A service was installed", 4698: "A scheduled task was created", 4699: "A scheduled task was deleted", 4700: "A scheduled task was enabled", 4701: "A scheduled task was disabled", 4702: "A scheduled task was updated", 4719: "The audit policy was changed", 4720: "A user account was created", 4722: "A user account was enabled", 4723: "A password change was attempted", 4724: "A password reset was attempted", 4725: "A user account was disabled", 4726: "A user account was deleted", 4728: "A member was added to a global group", 4729: "A member was removed from a global group", 4731: "A local group was created", 4732: "A member was added to a local group", 4733: "A member was removed from a local group", 4735: "A local group was changed", 4738: "A user account was changed", 4739: "Domain policy was changed", 4740: "A user account was locked out", 4756: "A member was added to a universal group", 4757: "A member was removed from a universal group", 4902: "The per-user audit policy table was created", 4907: "An object's auditing settings were changed", 4768: "A Kerberos ticket (TGT) was requested", 4769: "A Kerberos service ticket was requested", 4771: "Kerberos pre-authentication failed", 4776: "Credentials were validated (NTLM)", 4778: "A session was reconnected", 4779: "A session was disconnected", 4798: "A user's groups were listed", 4799: "A group's members were listed", 4946: "A firewall rule was added", 5136: "A directory object was modified", 5140: "A network share was accessed", 5145: "A network share object was checked", 5156: "A connection was allowed", 5157: "A connection was blocked", 5058: "A key file was used", 5059: "A key was moved", 5061: "A cryptographic operation",
	},
	[LOG]: { 104: "A log was cleared", 105: "A full log was archived", 1100: "The event log service shut down", 1102: "The audit log was cleared", 1104: "The security log is full", 1105: "The log was archived" },
	EventLog: { 6005: "The event log service started", 6006: "The event log service stopped", 6008: "The previous shutdown was unexpected", 6009: "Windows version at boot", 6013: "System uptime" },
	[SCM]: { 7000: "A service failed to start", 7009: "A service timed out starting", 7034: "A service ended unexpectedly", 7036: "A service changed state", 7040: "A service's start type was changed", 7045: "A service was installed" },
	"Microsoft-Windows-Kernel-General": { 1: "The system time was changed", 12: "Windows started", 13: "Windows shut down" },
	"Microsoft-Windows-Kernel-Power": { 41: "Restarted without a clean shutdown", 42: "Going to sleep" },
	[SYSMON]: { 1: "Process created", 2: "A file's creation time was changed", 3: "Network connection", 5: "Process ended", 6: "Driver loaded", 7: "Image loaded", 8: "Remote thread created", 10: "A process was opened", 11: "File created", 12: "Registry key created or deleted", 13: "Registry value set", 14: "Registry key renamed", 15: "Alternate data stream created", 17: "Pipe created", 18: "Pipe connected", 22: "DNS query", 23: "File deleted", 25: "Process tampering" },
	[PS]: { 4103: "PowerShell pipeline (module logging)", 4104: "A PowerShell script block", 40961: "PowerShell console started", 40962: "PowerShell console ready" },
	PowerShell: { 400: "PowerShell engine started", 403: "PowerShell engine stopped", 600: "PowerShell provider started", 800: "PowerShell pipeline executed" },
	[LSM]: { 21: "Remote Desktop session logon", 22: "Remote Desktop shell started", 23: "Remote Desktop session logoff", 24: "Remote Desktop session disconnected", 25: "Remote Desktop session reconnected" },
	[RCM]: { 1149: "Remote Desktop authentication succeeded" },
	[TASKS]: { 106: "A scheduled task was registered", 140: "A scheduled task was updated", 141: "A scheduled task was deleted", 200: "A scheduled task's action started", 201: "A scheduled task's action completed" },
	[DEFENDER]: { 1006: "Malware found", 1116: "Malware detected", 1117: "Action taken on malware", 5001: "Real-time protection was turned off", 5007: "Defender's settings were changed" },
	[WMI]: { 5857: "A WMI provider was loaded", 5860: "A temporary WMI subscription", 5861: "A permanent WMI subscription" },
	"Microsoft-Windows-Bits-Client": { 59: "A BITS transfer started", 60: "A BITS transfer stopped" },
	"Microsoft-Windows-WinRM": { 6: "A WinRM session was created", 91: "A remote shell was created" },
};

/** What an event is, in a few words — when its provider and ID are known. */
export function describe(e: EvtxEvent): string | undefined {
	return NAMES[e.provider]?.[e.eventId];
}

/** One of an event's values by name ("" when it has none). */
export const field = (e: EvtxEvent, name: string): string => e.data.find(([k]) => k === name)?.[1] ?? "";

const LEVELS: Record<number, string> = { 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose" };

/** An event's level as Event Viewer names it: Security's events are all
 * level 0 ("log always"), and their keywords say success or failure. */
export function levelOf(e: EvtxEvent): string {
	if (!e.level || e.level === 4) {
		let k = 0n;
		try {
			k = BigInt(e.keywords || "0");
		} catch {
			// (a keywords value that is not a number: no audit bits)
		}
		if (k & 0x0010000000000000n) return "Audit failure";
		if (k & 0x0020000000000000n) return "Audit success";
	}
	return LEVELS[e.level] ?? (e.level ? `Level ${e.level}` : "Information");
}

const BIDI: Record<string, string> = { "\u202a": "[LRE]", "\u202b": "[RLE]", "\u202c": "[PDF]", "\u202d": "[LRO]", "\u202e": "[RLO]", "\u2066": "[LRI]", "\u2067": "[RLI]", "\u2068": "[FSI]", "\u2069": "[PDI]", "\u200e": "[LRM]", "\u200f": "[RLM]" };
/** A value as written, with what would hide or rearrange it made visible:
 * controls as their Unicode pictures (␃), direction marks by name. */
export const shown = (s: string) =>
	s.replace(/[\u202a-\u202e\u2066-\u2069\u200e\u200f]/g, (c) => BIDI[c] ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, (c) => String.fromCharCode(c === "\u007f" ? 0x2421 : 0x2400 + c.charCodeAt(0)));

const LOGON: Record<string, string> = { 2: "at the keyboard", 3: "over the network", 4: "as a batch job", 5: "as a service", 7: "to unlock", 8: "over the network in cleartext", 9: "with new credentials", 10: "by Remote Desktop", 11: "with cached credentials", 12: "by Remote Desktop with cached credentials", 13: "to unlock with cached credentials" };
const who = (e: EvtxEvent, prefix: "Subject" | "Target") => {
	const u = field(e, `${prefix}UserName`);
	const d = field(e, `${prefix}DomainName`);
	return u && u !== "-" ? (d && d !== "-" ? `${d}\\${u}` : u) : "";
};
const addr = (e: EvtxEvent) => {
	const a = field(e, "IpAddress").replace(/^::ffff:/, "");
	return a && a !== "-" ? a : "";
};

/** The line the table shows for an event: its few values that matter. */
export function brief(e: EvtxEvent): string {
	const s = e.provider === SEC;
	if (s && (e.eventId === 4624 || e.eventId === 4625)) return [who(e, "Target"), LOGON[field(e, "LogonType")] ?? `type ${field(e, "LogonType")}`, addr(e) && `from ${addr(e)}`, field(e, "WorkstationName") !== "-" && field(e, "WorkstationName")].filter(Boolean).join(" · ");
	if (s && e.eventId === 4688) return [field(e, "CommandLine") || field(e, "NewProcessName"), field(e, "ParentProcessName") && `← ${field(e, "ParentProcessName").split("\\").pop()}`].filter(Boolean).join("  ");
	if (e.provider === SYSMON && e.eventId === 1) return [field(e, "CommandLine") || field(e, "Image"), field(e, "ParentImage") && `← ${field(e, "ParentImage").split("\\").pop()}`].filter(Boolean).join("  ");
	if (e.provider === SCM && e.eventId === 7045) return `${field(e, "ServiceName")} → ${field(e, "ImagePath")}`;
	if (s && e.eventId === 4697) return `${field(e, "ServiceName")} → ${field(e, "ServiceFileName")}`;
	if (e.provider === PS && e.eventId === 4104) return field(e, "ScriptBlockText").replace(/\s+/g, " ").slice(0, 300);
	if (s && (e.eventId === 4698 || e.eventId === 4702)) return field(e, "TaskName");
	if (e.provider === LOG && (e.eventId === 1102 || e.eventId === 104)) return `by ${who(e, "Subject") || "?"}${field(e, "Channel") ? ` · ${field(e, "Channel")}` : ""}`;
	// Anything else: its first few values.
	return e.data
		.filter(([, v]) => v && v !== "-")
		.slice(0, 4)
		.map(([k, v]) => `${/^Data \d+$/.test(k) ? "" : `${k}: `}${v.replace(/\s+/g, " ").slice(0, 120)}`)
		.join(" · ");
}

const q = (s: string, n = 120) => `“${s.replace(/\s+/g, " ").slice(0, n)}${s.length > n ? "…" : ""}”`;
/** An ISO time from the log, to the second, for a sentence. */
const when = (t: string) => (t ? t.slice(0, 19).replace("T", " ") : "?");
const top = (m: Map<string, number>, n = 3) =>
	[...m]
		.sort((a, b) => b[1] - a[1])
		.slice(0, n)
		.map(([k, c]) => `${k} ×${c}`)
		.join(", ") + (m.size > n ? `, +${m.size - n} more` : "");
const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);
const isPrivate = (a: string) => /^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|f[cd][0-9a-f]{2}:|$)/i.test(a);
const ADMIN_GROUP = /admin|domain admins|enterprise admins|schema admins|account operators|backup operators|server operators|remote desktop users|remote management users|dnsadmins|group policy creator/i;
const OFFICE = /\\(?:winword|excel|powerpnt|outlook|msaccess|mspub|onenote|visio)\.exe$/i;
const SHELL = /\\(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|msbuild)\.exe$/i;
/** Who opens LSASS for a living (Windows itself, Defender). */
const LSASS_NORMAL = /\\(?:windows\\system32\\(?:svchost|wininit|csrss|services|lsm|wmiprvse|taskmgr|werfault|mrt|vmtoolsd)|msmpeng|mssense|sensecncproxy)\.exe$/i;
/** Characters of command lines and scripts the triage reads, in all. */
export const SCAN_CHARS = 16_000_000;
const REPLICATION = /1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c/i;

export interface EvtxFindings {
	facts: Fact[];
	/** Record number → why it is worth a look. */
	notable: Map<number, string>;
}

export function evtxFindings(log: EvtxLog): EvtxFindings {
	const notable = new Map<number, string>();
	const mark = (e: EvtxEvent, why: string) => {
		if (!notable.has(e.record)) notable.set(e.record, why);
	};
	const warn: Fact[] = [];
	const info: Fact[] = [];
	const ev = log.events;

	// ── One pass: tallies and the events each finding needs ──────────────
	const channels = new Map<string, number>();
	const ids = new Map<string, number>();
	const computers = new Set<string>();
	let first = "";
	let last = "";
	let lowest = Infinity;
	const cleared: EvtxEvent[] = [];
	const auditPolicy: EvtxEvent[] = [];
	const failed: EvtxEvent[] = [];
	const failedFrom = new Map<string, number>();
	const failedUser = new Map<string, number>();
	const usersFrom = new Map<string, Set<string>>();
	const logons: EvtxEvent[] = [];
	const rdp = new Map<string, number>();
	const pth: EvtxEvent[] = [];
	const services: { e: EvtxEvent; name: string; path: string; account: string }[] = [];
	const tasks: { e: EvtxEvent; name: string; command: string }[] = [];
	const wmi: EvtxEvent[] = [];
	const accounts: EvtxEvent[] = [];
	const groupAdds: { e: EvtxEvent; member: string; group: string }[] = [];
	const commands = new Map<string, EvtxEvent>(); // command line → its first event
	const scripts = new Map<string, EvtxEvent>(); // script text → its first event
	// What the script triage may read, in all: a log of 200,000 script
	// blocks of 32 KiB each would be 6 GB to hold and scan.
	let budget = SCAN_CHARS;
	let unscanned = 0;
	const keep = (m: Map<string, EvtxEvent>, text: string, e: EvtxEvent) => {
		if (!text || m.has(text)) return;
		if (text.length > budget) return void unscanned++;
		budget -= text.length;
		m.set(text, e);
	};
	let flaggedBlocks = 0;
	const tools = new Map<string, { note: string; n: number; e: EvtxEvent }>();
	const officeShell: { e: EvtxEvent; parent: string; child: string }[] = [];
	const dcsync: EvtxEvent[] = [];
	const rc4 = new Map<string, Set<string>>(); // who asked → services
	const asrep = new Map<string, EvtxEvent>();
	const lsass = new Map<string, EvtxEvent>();
	const shares: EvtxEvent[] = [];
	const defender: EvtxEvent[] = [];
	const defenderOff: EvtxEvent[] = [];
	const exclusions: EvtxEvent[] = [];
	const bits = new Set<string>();
	/** SIDs to the account names the log itself pairs them with (4720's
	 * TargetSid and TargetUserName, every Subject…), for the events that
	 * name only a SID. */
	const sidName = new Map<string, string>();

	for (const e of ev) {
		if (e.channel) bump(channels, e.channel);
		bump(ids, `${e.eventId}\u0000${e.provider}`);
		if (e.computer) computers.add(e.computer);
		if (e.time && (!first || e.time < first)) first = e.time;
		if (e.time && e.time > last) last = e.time;
		lowest = Math.min(lowest, e.record);
		for (const p of ["Subject", "Target"] as const) {
			const sid = field(e, `${p}UserSid`) || field(e, `${p}Sid`);
			const name = who(e, p);
			if (sid.startsWith("S-1-5-21-") && name && sidName.size < 10_000) sidName.set(sid, name);
		}
		const s = e.provider === SEC;
		const id = e.eventId;
		if (e.provider === LOG && (id === 1102 || id === 104)) cleared.push(e);
		else if (s && id === 4719) auditPolicy.push(e);
		else if (s && id === 4625) {
			failed.push(e);
			const a = addr(e) || "(no address)";
			const u = who(e, "Target") || "(no account)";
			bump(failedFrom, a);
			bump(failedUser, u);
			let set = usersFrom.get(a);
			if (!set) usersFrom.set(a, (set = new Set()));
			if (set.size < 1000) set.add(u.toLowerCase());
		} else if (s && id === 4624) {
			logons.push(e);
			const type = field(e, "LogonType");
			if (type === "10") bump(rdp, addr(e) || "(no address)");
			if (type === "9" && /seclogo/i.test(field(e, "LogonProcessName"))) pth.push(e);
		} else if (e.provider === RCM && id === 1149) bump(rdp, field(e, "Param3") || "(no address)");
		else if (e.provider === LSM && (id === 21 || id === 25)) {
			const a = field(e, "Address");
			if (a && !/^LOCAL$/i.test(a)) bump(rdp, a);
		} else if (e.provider === SCM && id === 7045) services.push({ e, name: field(e, "ServiceName"), path: field(e, "ImagePath"), account: field(e, "AccountName") });
		else if (s && id === 4697) services.push({ e, name: field(e, "ServiceName"), path: field(e, "ServiceFileName"), account: field(e, "ServiceAccount") });
		else if (s && (id === 4698 || id === 4702)) {
			const xml = field(e, id === 4698 ? "TaskContent" : "TaskContentNew");
			const cmd = [...xml.matchAll(/<(Command|Arguments)>([\s\S]*?)<\/\1>/g)].map((m) => unxml(m[2]!)).join(" ");
			tasks.push({ e, name: field(e, "TaskName"), command: cmd });
		} else if (e.provider === TASKS && id === 106) tasks.push({ e, name: field(e, "TaskName"), command: "" });
		else if (e.provider === WMI && id === 5861) wmi.push(e);
		else if (s && id === 4720) accounts.push(e);
		else if (s && (id === 4728 || id === 4732 || id === 4756)) {
			const m = field(e, "MemberName");
			groupAdds.push({ e, member: m && m !== "-" ? m.replace(/^CN=([^,]+).*$/i, "$1") : field(e, "MemberSid"), group: who(e, "Target") });
		} else if ((s && id === 4688) || (e.provider === SYSMON && id === 1)) {
			const image = field(e, s ? "NewProcessName" : "Image");
			const parent = field(e, s ? "ParentProcessName" : "ParentImage");
			const line = field(e, "CommandLine");
			keep(commands, line, e);
			const exe = image.split("\\").pop() ?? "";
			const note = toolNote(exe);
			if (note) {
				const t = tools.get(exe.toUpperCase());
				if (t) t.n++;
				else tools.set(exe.toUpperCase(), { note, n: 1, e });
				mark(e, `${exe}: ${note}`);
			}
			if (OFFICE.test(parent) && SHELL.test(image)) {
				officeShell.push({ e, parent: parent.split("\\").pop()!, child: exe });
				mark(e, `${parent.split("\\").pop()} started ${exe}`);
			}
		} else if ((e.provider === PS && (id === 4104 || id === 4103)) || (e.provider === "PowerShell" && (id === 400 || id === 800))) {
			const text = id === 4104 ? field(e, "ScriptBlockText") : id === 4103 ? field(e, "Payload") : e.data.map(([, v]) => v).join("\n");
			keep(scripts, text, e);
			// Windows logs a block as a Warning (level 3) when it finds it suspicious itself.
			if (id === 4104 && e.level === 3) {
				flaggedBlocks++;
				mark(e, "a script block Windows itself found suspicious");
			}
		} else if (s && id === 4662 && REPLICATION.test(field(e, "Properties")) && !field(e, "SubjectUserName").endsWith("$")) dcsync.push(e);
		else if (s && id === 4769 && /^0x(?:17|18)$/i.test(field(e, "TicketEncryptionType")) && /^0x0$/i.test(field(e, "Status") || "0x0")) {
			const svc = field(e, "ServiceName");
			if (svc && !svc.endsWith("$") && !/^krbtgt$/i.test(svc)) {
				const k = field(e, "TargetUserName") || addr(e) || "?";
				let set = rc4.get(k);
				if (!set) rc4.set(k, (set = new Set()));
				set.add(svc);
				mark(e, "a service ticket in RC4 — what Kerberoasting asks for");
			}
		} else if (s && id === 4768 && field(e, "PreAuthType") === "0" && /^0x0$/i.test(field(e, "Status") || "0x0")) {
			const u = field(e, "TargetUserName");
			if (u && !asrep.has(u)) asrep.set(u, e);
			mark(e, "a ticket without pre-authentication — AS-REP roasting");
		} else if (e.provider === SYSMON && id === 10 && /\\lsass\.exe$/i.test(field(e, "TargetImage")) && !LSASS_NORMAL.test(field(e, "SourceImage"))) {
			const src = field(e, "SourceImage");
			if (!lsass.has(src)) lsass.set(src, e);
			mark(e, `${src.split("\\").pop()} opened LSASS — where the passwords are`);
		} else if (s && id === 5140 && /\\(?:ADMIN|[A-Z])\$$/i.test(field(e, "ShareName"))) shares.push(e);
		else if (e.provider === DEFENDER && (id === 1116 || id === 1117 || id === 1006)) defender.push(e);
		else if (e.provider === DEFENDER && id === 5001) defenderOff.push(e);
		else if (e.provider === DEFENDER && id === 5007 && /exclusions|DisableAntiSpyware|DisableRealtimeMonitoring/i.test(field(e, "New Value"))) exclusions.push(e);
		else if (e.provider === "Microsoft-Windows-Bits-Client" && id === 59) {
			const u = field(e, "url");
			if (u && bits.size < 50) bits.add(u);
		}
	}

	// ── The summary ──────────────────────────────────────────────────────
	const channel = [...channels].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
	const head: Fact = { level: "info", text: `A Windows event log${channel ? ` (${channel})` : ""}: ${plural(ev.length, "event")}${first ? `, ${when(first)} to ${when(last)} UTC` : ""}${computers.size && computers.size <= 3 ? `, from ${[...computers].join(", ")}` : computers.size ? `, from ${computers.size} computers` : ""}` };

	// ── Was it tampered with ─────────────────────────────────────────────
	for (const e of cleared.slice(0, 4)) {
		mark(e, "the log was cleared");
		warn.push({ level: "warn", text: `The ${e.eventId === 1102 ? "Security" : field(e, "Channel") || "a"} log was cleared at ${when(e.time)} UTC by ${who(e, "Subject") || "an account it does not name"} — what an intruder does on the way out` });
	}
	if (log.badChecksums.length) warn.push({ level: "warn", text: `${plural(log.badChecksums.length, "chunk")} of records do not match their checksums — changed after Windows wrote them, or damaged` });
	for (const g of log.gaps.slice(0, 3)) warn.push({ level: "warn", text: `Record numbers skip ${plural(g.missing, "record")} after #${g.after} — records taken out of the log (what log-editing tools do)` });
	if (log.gaps.length > 3) warn.push({ level: "warn", text: `…and ${plural(log.gaps.length - 3, "more gap")} in the record numbers` });
	for (const w of log.warnings.slice(0, 4)) warn.push({ level: "warn", text: `Malformed: ${w}` });
	if (log.truncated) warn.push({ level: "warn", text: `Only the first ${ev.length.toLocaleString("en")} events are read` });
	if (auditPolicy.length) {
		for (const e of auditPolicy) mark(e, "the audit policy was changed");
		warn.push({ level: "warn", text: `The audit policy was changed ${plural(auditPolicy.length, "time")}, first at ${when(auditPolicy[0]!.time)} UTC by ${who(auditPolicy[0]!, "Subject") || "?"} — turning auditing off is how an intruder goes quiet` });
	}

	// ── What stopped them ────────────────────────────────────────────────
	if (defender.length) {
		for (const e of defender) mark(e, "Defender found malware");
		const threats = defender.map((e) => `${field(e, "Threat Name") || "?"}${field(e, "Path") ? ` in ${q(field(e, "Path").replace(/^file:_/i, ""), 80)}` : ""}`);
		warn.push({ level: "warn", text: `Defender found malware ${plural(defender.length, "time")}: ${some(threats, 3)}` });
	}
	if (defenderOff.length) {
		for (const e of defenderOff) mark(e, "Defender's real-time protection was turned off");
		warn.push({ level: "warn", text: `Defender's real-time protection was turned off ${plural(defenderOff.length, "time")}, first at ${when(defenderOff[0]!.time)} UTC` });
	}
	if (exclusions.length) {
		for (const e of exclusions) mark(e, "Defender's settings were weakened");
		warn.push({ level: "warn", text: `Defender's settings were weakened ${plural(exclusions.length, "time")}: ${some(exclusions.map((e) => q(field(e, "New Value"), 100)), 2)}` });
	}

	// ── Who got in, and how ──────────────────────────────────────────────
	if (failed.length >= 5) {
		for (const e of failed) mark(e, "a failed logon");
		warn.push({ level: "warn", text: `${plural(failed.length, "failed logon")}: from ${top(failedFrom)}; for ${top(failedUser)}` });
		for (const [a, users] of usersFrom) if (users.size >= 5 && a !== "(no address)") warn.push({ level: "warn", text: `${a} tried ${plural(users.size, "different account")} — password spraying` });
		// And then a success from an address that kept failing.
		const noisy = new Set([...failedFrom].filter(([a, n]) => n >= 5 && a !== "(no address)").map(([a]) => a));
		const after = new Map<string, EvtxEvent>();
		for (const e of logons) if (noisy.has(addr(e)) && !after.has(addr(e))) after.set(addr(e), e);
		for (const [a, e] of [...after].slice(0, 3)) {
			mark(e, `a logon from ${a}, which had failed ${failedFrom.get(a)} times`);
			warn.push({ level: "warn", text: `…then ${a} logged on as ${who(e, "Target") || "?"} ${LOGON[field(e, "LogonType")] ?? ""} at ${when(e.time)} UTC — after ${plural(failedFrom.get(a)!, "failure")}: guessed?` });
		}
	} else if (failed.length) info.push({ level: "info", text: `${plural(failed.length, "failed logon")}: from ${top(failedFrom)}` });
	if (rdp.size) {
		const outside = [...rdp.keys()].filter((a) => a !== "(no address)" && !isPrivate(a));
		(outside.length ? warn : info).push({ level: outside.length ? "warn" : "info", text: `Remote Desktop logons from ${top(rdp, 4)}${outside.length ? ` — ${some(outside, 3)} ${outside.length === 1 ? "is" : "are"} on the internet` : ""}` });
	}
	if (pth.length) {
		for (const e of pth) mark(e, "a logon with new credentials through seclogo");
		warn.push({ level: "warn", text: `${plural(pth.length, "logon")} with new credentials through seclogo (type 9), first at ${when(pth[0]!.time)} UTC by ${who(pth[0]!, "Subject") || "?"} — the shape of pass-the-hash (Mimikatz' sekurlsa::pth; runas /netonly looks the same)` });
	}

	// ── What they left behind ────────────────────────────────────────────
	// The ones most like an intruder's first: PsExec's, a script for a
	// program, a known tool, a folder anyone can write to.
	// (One line per service and path: PsExec installs itself every time it runs.)
	const once = new Map<string, (typeof services)[number] & { all: EvtxEvent[] }>();
	for (const s of services) {
		const k = `${s.name}\u0000${s.path}`;
		const seen = once.get(k);
		if (seen) seen.all.push(s.e);
		else once.set(k, { ...s, all: [s.e] });
	}
	const rated = [...once.values()].map((s) => {
		// The program: quoted, or up to its extension (paths have spaces).
		const exe = (/^"([^"]+)"/.exec(s.path)?.[1] ?? /^(.*?\.(?:exe|sys|dll|com|bat|cmd|ps1))\b/i.exec(s.path)?.[1] ?? s.path).split("\\").pop() ?? "";
		const why =
			/^PSEXESVC$|^(?:PAEXEC|CSEXEC|REMCOM)/i.test(s.name) || /PSEXESVC/i.test(s.path)
				? "PsExec's: a command run from another computer"
				: scanScript(s.path).findings[0]
					? `it ${scanScript(s.path).findings[0]!.what}`
					: toolNote(exe)
						? toolNote(exe)!
						: /%COMSPEC%|\\(?:cmd|powershell|pwsh|mshta|rundll32|regsvr32)\.exe/i.test(s.path)
							? "a shell run as a service — how remote-execution tools start"
							: /\\(?:users|programdata|windows\\temp|temp)\\|\\\\[^\\]+\\/i.test(s.path)
								? "from a folder anyone can write to, or another computer"
								: "";
		return { ...s, why };
	});
	rated.sort((a, b) => Number(!!b.why) - Number(!!a.why));
	for (const s of rated) for (const e of s.all) mark(e, s.why ? `a service was installed — ${s.why}` : "a service was installed");
	for (const s of rated.slice(0, 5)) {
		const times = s.all.length > 1 ? ` ${s.all.length} times, ${when(s.all[0]!.time)} to ${when(s.all.at(-1)!.time)} UTC` : ` at ${when(s.e.time)} UTC`;
		warn.push({ level: "warn", text: `Service ${q(s.name, 60)} installed${times}: ${q(s.path, 160)}${s.account ? ` as ${s.account}` : ""}${s.why ? ` — ${s.why}` : ""}` });
	}
	if (rated.length > 5) warn.push({ level: "warn", text: `…and ${plural(rated.length - 5, "more service")} installed: ${some(rated.slice(5).map((s) => s.name), 4)}` });
	for (const t of tasks.slice(0, 4)) {
		mark(t.e, "a scheduled task was created");
		const f = scanScript(t.command).findings[0];
		warn.push({ level: "warn", text: `Scheduled task ${q(t.name, 80)} ${t.e.eventId === 4702 ? "changed" : "created"} at ${when(t.e.time)} UTC${t.command ? `: runs ${q(t.command, 160)}` : ""}${f ? ` — it ${f.what}` : ""}` });
	}
	if (tasks.length > 4) warn.push({ level: "warn", text: `…and ${plural(tasks.length - 4, "more scheduled task")}: ${some(tasks.slice(4).map((t) => t.name), 4)}` });
	if (wmi.length) {
		for (const e of wmi) mark(e, "a permanent WMI subscription");
		warn.push({ level: "warn", text: `${plural(wmi.length, "permanent WMI subscription")} registered — code run on an event, kept where the Run keys are not: ${q(field(wmi[0]!, "PossibleCause") || field(wmi[0]!, "CONSUMER"), 160)}` });
	}
	for (const e of accounts.slice(0, 4)) {
		mark(e, "an account was created");
		warn.push({ level: "warn", text: `Account ${q(who(e, "Target"), 60)} created at ${when(e.time)} UTC by ${who(e, "Subject") || "?"}` });
	}
	const named = (sid: string) => (sidName.has(sid) ? `${sidName.get(sid)} (${sid})` : sid);
	const adminAdds = groupAdds.filter((g) => ADMIN_GROUP.test(g.group));
	for (const g of adminAdds.slice(0, 6)) {
		mark(g.e, `added to ${g.group}`);
		warn.push({ level: "warn", text: `${q(named(g.member), 100)} added to ${q(g.group, 60)} at ${when(g.e.time)} UTC by ${who(g.e, "Subject") || "?"} — a group that runs the computer` });
	}
	const otherAdds = groupAdds.filter((g) => !ADMIN_GROUP.test(g.group));
	if (otherAdds.length) info.push({ level: "info", text: `${plural(otherAdds.length, "other group membership")} added: ${some(otherAdds.map((g) => `${named(g.member).split(" (")[0]} → ${g.group}`), 3)}` });

	// ── What they ran ────────────────────────────────────────────────────
	const byWhat = new Map<string, { n: number; e: EvtxEvent; excerpt: string }>();
	const decoded: { e: EvtxEvent; text: string }[] = [];
	const scan = (text: string, e: EvtxEvent) => {
		const r = scanScript(text);
		for (const f of r.findings) {
			const k = byWhat.get(f.what);
			if (k) k.n++;
			else byWhat.set(f.what, { n: 1, e, excerpt: f.excerpt });
			mark(e, `it ${f.what}`);
		}
		for (const d of r.decoded) if (decoded.length < 3) decoded.push({ e, text: d.text });
	};
	for (const [line, e] of commands) scan(line, e);
	for (const [text, e] of scripts) scan(text, e);
	for (const [what, { n, e, excerpt }] of [...byWhat].slice(0, 6)) warn.push({ level: "warn", text: `A command that ${what} (${n === 1 ? "once" : `${n} different ones`}), first at ${when(e.time)} UTC: ${q(excerpt, 160)}` });
	for (const d of decoded) warn.push({ level: "warn", text: `A PowerShell -EncodedCommand at ${when(d.e.time)} UTC, decoded: ${q(d.text, 160)}` });
	if (flaggedBlocks) warn.push({ level: "warn", text: `${plural(flaggedBlocks, "PowerShell script block")} Windows itself logged as suspicious` });
	for (const [exe, t] of [...tools].slice(0, 4)) warn.push({ level: "warn", text: `${exe} ran ${plural(t.n, "time")} (first at ${when(t.e.time)} UTC): ${t.note}` });
	for (const o of officeShell.slice(0, 3)) warn.push({ level: "warn", text: `${o.parent} started ${o.child} at ${when(o.e.time)} UTC — a document running a command (a macro)` });

	// ── What they took ───────────────────────────────────────────────────
	if (dcsync.length) {
		for (const e of dcsync) mark(e, "replication rights used by an account that is not a domain controller — DCSync");
		warn.push({ level: "warn", text: `${who(dcsync[0]!, "Subject")} used directory replication rights at ${when(dcsync[0]!.time)} UTC — an account that is not a domain controller asking for every password hash: DCSync` });
	}
	for (const [k, svcs] of rc4) if (svcs.size >= 3) warn.push({ level: "warn", text: `${k} asked for RC4 service tickets for ${plural(svcs.size, "service")} (${some([...svcs], 3)}) — Kerberoasting: cracking service accounts' passwords offline` });
	const fewRc4 = [...rc4].filter(([, s]) => s.size < 3);
	if (fewRc4.length) info.push({ level: "info", text: `RC4 service tickets for ${some(fewRc4.flatMap(([, s]) => [...s]), 4)} — weak encryption; Kerberoasting asks for it` });
	if (asrep.size) warn.push({ level: "warn", text: `Tickets issued without pre-authentication for ${some([...asrep.keys()], 4)} — their password hashes can be cracked offline (AS-REP roasting)` });
	for (const [src, e] of [...lsass].slice(0, 3)) warn.push({ level: "warn", text: `${q(src, 100)} opened LSASS (access ${field(e, "GrantedAccess") || "?"}) at ${when(e.time)} UTC — where Windows keeps the passwords` });
	if (shares.length) {
		for (const e of shares) mark(e, "an administrative share was reached");
		const from = new Map<string, number>();
		for (const e of shares) bump(from, `${who(e, "Subject") || "?"} from ${addr(e) || "?"}`);
		const outside = shares.some((e) => addr(e) && !isPrivate(addr(e)));
		(outside ? warn : info).push({ level: outside ? "warn" : "info", text: `Administrative shares (C$, ADMIN$) reached ${plural(shares.length, "time")}: ${top(from)} — how tools like PsExec move between computers` });
	}
	if (bits.size) info.push({ level: "info", text: `BITS transferred from ${some([...bits].map((u) => q(u, 80)), 3)}` });

	// ── The overview ─────────────────────────────────────────────────────
	const commonest = [...ids]
		.sort((a, b) => b[1] - a[1])
		.slice(0, 5)
		.map(([k, n]) => {
			const [id, provider] = k.split("\u0000") as [string, string];
			const name = NAMES[provider]?.[Number(id)];
			return `${id}${name ? ` (${name})` : ""} ×${n}`;
		});
	if (commonest.length) info.push({ level: "info", text: `Most frequent: ${commonest.join(", ")}` });
	if (lowest > 1 && Number.isFinite(lowest)) info.push({ level: "info", text: `It begins at record #${lowest}: the ones before were overwritten (a full log wraps) or cleared` });
	if (log.dirty) info.push({ level: "info", text: "Not closed cleanly — copied from a running computer, or Windows stopped mid-write; the last records may be partial" });
	if (unscanned) info.push({ level: "info", text: `${plural(unscanned, "more command line or script", "more command lines and scripts")} not read by the script triage (it reads ${SCAN_CHARS / 1_000_000} million characters at most)` });
	if (log.full) info.push({ level: "info", text: "Marked full: Windows stopped writing to it (or overwrote the oldest records)" });
	// Every sentence quotes values the log's writer chose: what would hide
	// or reorder text in them is shown, not obeyed (an account named with a
	// right-to-left override reads as written).
	return { facts: [head, ...warn, ...info].map((f) => ({ ...f, text: shown(f.text) })), notable };
}
