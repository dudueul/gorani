// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A Windows event log (.evtx), read (commit 42j, docs/PREVIEWS.md ›
 * Forensic formats) from the format libevtx documents and Microsoft's own
 * descriptions of Binary XML:
 *
 *   file header   "ElfFile", chunk count, the next record's number, the
 *                 dirty and full flags, a CRC-32 of itself
 *   chunks        64 KiB each, "ElfChnk": the records' number range, a
 *                 CRC-32 of the chunk header and one of its records, a
 *                 table of the names and templates the records share
 *   records       "**", the record's number and write time, then Binary
 *                 XML — usually a template instance: a template (defined
 *                 once per chunk, inline the first time) and the values to
 *                 put in its holes ("substitutions")
 *
 * What is read out of each record is what an analyst filters on: the
 * System fields (provider, event ID, level, time, record ID, channel,
 * computer, user, process) and every EventData / UserData value by name.
 * The checksums are checked (a record edited after Windows wrote it
 * breaks them) and the record numbers too (a gap is records removed).
 *
 * Every offset is checked; every loop is capped.
 * Pure: unit:preview-facts.
 */

import { Reader, Short, trimNul } from "../binary/read.ts";

export interface EvtxEvent {
	record: number;
	/** Where the record starts in the file (its "**" signature). */
	offset: number;
	/** When the record was written, and when the event happened — ISO 8601
	 * to Windows' 100 ns ("2016-07-08T18:16:31.1081031Z"), "" when absent.
	 * Strings of one format sort as the times do. */
	written: string;
	provider: string;
	eventId: number;
	level: number;
	task: number;
	opcode: number;
	keywords: string;
	time: string;
	channel: string;
	computer: string;
	user: string;
	processId: number | null;
	threadId: number | null;
	/** EventData's (or UserData's) values, by name, in order. */
	data: [string, string][];
}

export interface EvtxLog {
	chunks: number;
	nextRecord: number;
	dirty: boolean;
	full: boolean;
	events: EvtxEvent[];
	/** Chunks whose header or records do not match their CRC-32. */
	badChecksums: number[];
	/** Record numbers missing between one record and the next. */
	gaps: { after: number; missing: number }[];
	truncated: boolean;
	warnings: string[];
}

export const isEvtx = (b: Uint8Array) => b.length >= 4096 && String.fromCharCode(...b.subarray(0, 8)) === "ElfFile\0";

const CRC = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();
export function crc32(...parts: Uint8Array[]): number {
	let c = 0xffffffff;
	for (const p of parts) for (let i = 0; i < p.length; i++) c = CRC[(c ^ p[i]!) & 0xff]! ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}

// ── Binary XML ───────────────────────────────────────────────────────

type Value = { kind: "text"; text: string } | { kind: "sub"; index: number; optional: boolean } | { kind: "tree"; nodes: Node[] };
interface Element {
	kind: "element";
	name: string;
	attrs: [string, Value[]][];
	children: Node[];
}
type Node = Element | Value;

const MAX_DEPTH = 32;
/** A record refused for its shape, not its length: nested too deep, or
 * built to expand past what a reader should spend on one record. */
class Refused extends Error {}
/** Nodes one record may expand to. A template is parsed once and copied
 * into every instance of it — so a record of 64 KiB holding a few
 * thousand tiny instances of one large template would grow to millions
 * of nodes (fuzzing found the slowdown). Real records have under a
 * hundred. */
export const MAX_NODES = 20_000;

/** One chunk: its bytes, its names and templates (parsed once). */
class Chunk {
	readonly r: Reader;
	readonly base: number;
	private names = new Map<number, string>();
	private templates = new Map<number, Node[]>();
	/** What the record being read may still expand to (MAX_NODES each). */
	budget = MAX_NODES;

	constructor(r: Reader, base: number) {
		this.r = r;
		this.base = base;
	}

	name(off: number): string {
		const cached = this.names.get(off);
		if (cached !== undefined) return cached;
		const at = this.base + off;
		const n = this.r.u16(at + 6);
		const s = new TextDecoder("utf-16le").decode(this.r.slice(at + 8, Math.min(n, 512) * 2));
		this.names.set(off, s);
		return s;
	}

	/** The size of a Name structure written inline. */
	nameSize(off: number): number {
		return 10 + this.r.u16(this.base + off + 6) * 2;
	}

	template(off: number, depth: number): Node[] {
		const cached = this.templates.get(off);
		if (cached) return cached;
		this.templates.set(off, []); // (a template that names itself: empty, not a loop)
		const at = this.base + off;
		const size = this.r.u32(at + 20);
		const nodes = this.parse(at + 24, at + 24 + size, depth + 1).nodes;
		this.templates.set(off, nodes);
		return nodes;
	}

	/** Parse Binary XML in [at, end): its nodes, and where it stopped. */
	parse(at: number, end: number, depth: number): { nodes: Node[]; at: number; instance?: { template: Node[]; values: Value[] } } {
		if (depth > MAX_DEPTH) throw new Refused(`its Binary XML nests deeper than ${MAX_DEPTH}`);
		const r = this.r;
		const nodes: Node[] = [];
		const stack: Element[] = [];
		const push = (n: Node) => (stack.length ? stack[stack.length - 1]!.children.push(n) : nodes.push(n));
		let guard = 0;
		while (at < end && guard++ < 100_000) {
			const token = r.u8(at);
			const t = token & 0x0f;
			if (t === 0x00) {
				at++;
				break;
			} else if (t === 0x0f) at += 4; // fragment header
			else if (t === 0x01) {
				// OpenStartElement: dependency id, data size, name offset (inline if it points here).
				const nameOff = r.u32(at + 7);
				at += 11;
				if (this.base + nameOff === at) at += this.nameSize(nameOff);
				const el: Element = { kind: "element", name: this.name(nameOff), attrs: [], children: [] };
				if (token & 0x40) {
					const attrEnd = at + 4 + r.u32(at);
					at += 4;
					while (at < attrEnd) {
						const a = r.u8(at);
						if ((a & 0x0f) !== 0x06) break;
						const an = r.u32(at + 1);
						at += 5;
						if (this.base + an === at) at += this.nameSize(an);
						const v = this.values(at, attrEnd, depth);
						at = v.at;
						el.attrs.push([this.name(an), v.values]);
					}
				}
				const close = r.u8(at) & 0x0f;
				at++;
				push(el);
				if (close === 0x02) stack.push(el);
				// 0x03: empty, nothing to close
			} else if (t === 0x02) at++;
			else if (t === 0x03 || t === 0x04) {
				at++;
				stack.pop();
			} else if (t === 0x05 || t === 0x0d || t === 0x0e || t === 0x07 || t === 0x08 || t === 0x09) {
				const v = this.values(at, end, depth);
				at = v.at;
				for (const x of v.values) push(x);
			} else if (t === 0x0c) {
				// A template instance: its definition (inline the first time), then its values.
				const defOff = r.u32(at + 6);
				at += 10;
				if (this.base + defOff === at) at += 24 + r.u32(at + 20);
				const template = this.template(defOff, depth);
				const n = Math.min(r.u32(at), 4096);
				at += 4;
				const desc: [number, number][] = [];
				for (let i = 0; i < n; i++) desc.push([r.u16(at + i * 4), r.u8(at + i * 4 + 2)]);
				at += n * 4;
				const values: Value[] = [];
				for (const [size, type] of desc) {
					values.push(this.value(at, size, type, depth));
					at += size;
				}
				return { nodes, at, instance: { template, values } };
			} else if (t === 0x0a || t === 0x0b) {
				at += t === 0x0a ? 5 : 3 + r.u16(at + 1) * 2;
			} else throw new Short(`a Binary XML token 0x${token.toString(16)}`);
		}
		return { nodes, at };
	}

	/** A run of value tokens (text, substitutions, references) up to the next structural token. */
	private values(at: number, end: number, depth: number): { values: Value[]; at: number } {
		const r = this.r;
		const values: Value[] = [];
		while (at < end) {
			const t = r.u8(at) & 0x0f;
			if (t === 0x05) {
				const type = r.u8(at + 1);
				if (type !== 0x01) throw new Short("a value token of an unexpected type");
				const n = r.u16(at + 2);
				values.push({ kind: "text", text: new TextDecoder("utf-16le").decode(r.slice(at + 4, n * 2)) });
				at += 4 + n * 2;
			} else if (t === 0x0d || t === 0x0e) {
				values.push({ kind: "sub", index: r.u16(at + 1), optional: t === 0x0e });
				at += 4;
			} else if (t === 0x07) {
				const n = r.u16(at + 1);
				values.push({ kind: "text", text: new TextDecoder("utf-16le").decode(r.slice(at + 3, n * 2)) });
				at += 3 + n * 2;
			} else if (t === 0x08) {
				values.push({ kind: "text", text: String.fromCharCode(r.u16(at + 1)) });
				at += 3;
			} else if (t === 0x09) {
				const ent = this.name(r.u32(at + 1));
				values.push({ kind: "text", text: ({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" } as Record<string, string>)[ent] ?? `&${ent};` });
				at += 5;
			} else break;
		}
		return { values, at };
	}

	/** A substitution value, by its type. */
	value(at: number, size: number, type: number, depth: number): Value {
		const r = this.r;
		const text = (s: string): Value => ({ kind: "text", text: s });
		if (!size) return text("");
		// Every value inside the file, and as wide as its type: a size that
		// lies (fuzzing found it) is refused before any read.
		if (!r.has(at, size)) throw new Short(`a value of ${size} bytes at 0x${at.toString(16)}`);
		const width = WIDTH[type] ?? (type === 0x10 ? 4 : 0);
		if (size < width) return text(`(a ${size}-byte value too short for its type 0x${type.toString(16)})`);
		const hex = (n: bigint | number, w: number) => `0x${n.toString(16).padStart(w, "0")}`;
		const v = new DataView(r.b.buffer, r.b.byteOffset + at, size);
		switch (type) {
			case 0x01:
				return text(trimNul(new TextDecoder("utf-16le").decode(r.slice(at, size))));
			case 0x02:
				return text(trimNul(new TextDecoder("windows-1252").decode(r.slice(at, size))));
			case 0x03:
				return text(String(v.getInt8(0)));
			case 0x04:
				return text(String(v.getUint8(0)));
			case 0x05:
				return text(String(v.getInt16(0, true)));
			case 0x06:
				return text(String(v.getUint16(0, true)));
			case 0x07:
				return text(String(v.getInt32(0, true)));
			case 0x08:
				return text(String(v.getUint32(0, true)));
			case 0x09:
				return text(String(v.getBigInt64(0, true)));
			case 0x0a:
				return text(String(v.getBigUint64(0, true)));
			case 0x0b:
				return text(String(v.getFloat32(0, true)));
			case 0x0c:
				return text(String(v.getFloat64(0, true)));
			case 0x0d:
				return text(v.getUint32(0, true) ? "true" : "false");
			case 0x0e:
				return text([...r.slice(at, Math.min(size, 4096))].map((x) => x.toString(16).padStart(2, "0").toUpperCase()).join(""));
			case 0x0f:
				return text(`{${guid(r, at)}}`);
			case 0x10:
				return text(size === 8 ? hex(v.getBigUint64(0, true), 16) : hex(v.getUint32(0, true), 8));
			case 0x11:
				return text(filetimeText(r, at));
			case 0x12: {
				const p2 = (n: number, w = 2) => String(v.getUint16(n, true)).padStart(w, "0");
				return text(`${p2(0, 4)}-${p2(2)}-${p2(6)}T${p2(8)}:${p2(10)}:${p2(12)}.${p2(14, 3)}Z`);
			}
			case 0x13:
				return text(sid(r, at, size));
			case 0x14:
				return text(hex(v.getUint32(0, true), 8));
			case 0x15:
				return text(hex(v.getBigUint64(0, true), 16));
			case 0x21:
				return { kind: "tree", nodes: this.render(this.parse(at, at + size, depth + 1)) };
			case 0x81: {
				// Strings, each ended by a NUL: the last NUL ends the list, so
				// only the empty string after it goes (empty items stay).
				const items = new TextDecoder("utf-16le").decode(r.slice(at, size)).split("\0");
				if (items.at(-1) === "") items.pop();
				return text(items.slice(0, 1000).join("\n"));
			}
			default: {
				// An array of a fixed-width type: its items, one per line.
				const w = WIDTH[type & 0x7f];
				if (type & 0x80 && w) {
					const items: string[] = [];
					for (let i = 0; i + w <= size && items.length < 1000; i += w) {
						const one = this.value(at + i, w, type & 0x7f, depth);
						items.push(one.kind === "text" ? one.text : "");
					}
					return text(items.join("\n"));
				}
				return text(`(${size} bytes of type 0x${type.toString(16)})`);
			}
		}
	}

	/** A parsed fragment with its template filled in. */
	render(p: { nodes: Node[]; instance?: { template: Node[]; values: Value[] } }): Node[] {
		if (!p.instance) return p.nodes;
		const { template, values } = p.instance;
		const fill = (ns: Node[]): Node[] =>
			ns.flatMap((n): Node[] => {
				if (--this.budget < 0) throw new Refused(`it expands past ${MAX_NODES.toLocaleString("en")} nodes — built to exhaust a reader`);
				if (n.kind === "sub") {
					// (A value that is Binary XML itself — EventData, usually — is
					// spliced in as the elements it holds.)
					const v = values[n.index];
					return v ? (v.kind === "tree" ? v.nodes : [v]) : [];
				}
				if (n.kind === "element") return [{ ...n, attrs: n.attrs.map(([k, vs]) => [k, fill(vs) as Value[]]), children: fill(n.children) }];
				return [n];
			});
		return fill(template);
	}
}

function guid(r: Reader, at: number): string {
	const h = (n: number, w: number) => n.toString(16).padStart(w, "0");
	const b = r.slice(at, 16);
	return `${h(r.u32(at), 8)}-${h(r.u16(at + 4), 4)}-${h(r.u16(at + 6), 4)}-${[...b.subarray(8, 10)].map((x) => h(x, 2)).join("")}-${[...b.subarray(10, 16)].map((x) => h(x, 2)).join("")}`;
}

function sid(r: Reader, at: number, size: number): string {
	if (size < 8) return "";
	const count = r.u8(at + 1);
	let auth = 0;
	for (let i = 0; i < 6; i++) auth = auth * 256 + r.u8(at + 2 + i);
	const subs: number[] = [];
	for (let i = 0; i < count && 8 + i * 4 + 4 <= size; i++) subs.push(r.u32(at + 8 + i * 4));
	return `S-${r.u8(at)}-${auth}${subs.map((s) => `-${s}`).join("")}`;
}

/** The widths of the fixed-width value types, for their arrays (type | 0x80). */
const WIDTH: Record<number, number> = { 0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0a: 8, 0x0b: 4, 0x0c: 8, 0x0d: 4, 0x0f: 16, 0x11: 8, 0x12: 16, 0x14: 4, 0x15: 8 };

/** A FILETIME (100 ns ticks since 1601) as ISO 8601 to the tick — a
 * number would lose the last digits (2^53 holds 9e15; FILETIMEs are
 * 1.3e17), so the arithmetic is BigInt. "" for zero or past 9999. */
function filetimeText(r: Reader, at: number): string {
	const t = (BigInt(r.u32(at + 4)) << 32n) | BigInt(r.u32(at));
	if (!t) return "";
	const secs = Number(t / 10_000_000n) - 11_644_473_600;
	if (secs < -11_644_473_600 || secs > 253_402_300_799) return "";
	return `${new Date(secs * 1000).toISOString().slice(0, 19)}.${String(t % 10_000_000n).padStart(7, "0")}Z`;
}

const textOf = (vs: Node[]): string => vs.map((v) => (v.kind === "text" ? v.text : v.kind === "tree" ? textOf(v.nodes) : v.kind === "element" ? textOf(v.children) : "")).join("");
const attr = (e: Element | undefined, name: string) => textOf(e?.attrs.find(([k]) => k === name)?.[1] ?? []);
const child = (e: Element | undefined, name: string) => e?.children.find((c): c is Element => c.kind === "element" && c.name === name);

/** The fields an analyst filters on, out of a rendered Event element. */
function eventOf(nodes: Node[], record: number, offset: number, written: string): EvtxEvent {
	const ev = nodes.find((n): n is Element => n.kind === "element" && n.name === "Event");
	const sys = child(ev, "System");
	const t = (name: string) => textOf(child(sys, name)?.children ?? []);
	const time = attr(child(sys, "TimeCreated"), "SystemTime");
	const data: [string, string][] = [];
	const evData = child(ev, "EventData");
	if (evData) {
		let i = 0;
		for (const c of evData.children) {
			if (c.kind !== "element") continue;
			data.push([attr(c, "Name") || `${c.name}${c.name === "Data" ? ` ${i++}` : ""}`, textOf(c.children)]);
			if (data.length >= 200) break;
		}
	}
	const userData = child(ev, "UserData");
	if (userData) {
		const walk = (e: Element, depth: number) => {
			for (const c of e.children) {
				if (c.kind !== "element") continue;
				if (c.children.some((x) => x.kind === "element") && depth < 4) walk(c, depth + 1);
				else if (data.length < 200) data.push([c.name, textOf(c.children)]);
			}
		};
		walk(userData, 0);
	}
	const exec = child(sys, "Execution");
	const num = (s: string) => (s && /^\d+$/.test(s) ? Number(s) : null);
	return {
		record,
		offset,
		written,
		provider: attr(child(sys, "Provider"), "Name") || attr(child(sys, "Provider"), "EventSourceName"),
		eventId: Number(t("EventID")) || 0,
		level: Number(t("Level")) || 0,
		task: Number(t("Task")) || 0,
		opcode: Number(t("Opcode")) || 0,
		keywords: t("Keywords"),
		time: time || written,
		channel: t("Channel"),
		computer: t("Computer"),
		user: attr(child(sys, "Security"), "UserID"),
		processId: num(attr(exec, "ProcessID")),
		threadId: num(attr(exec, "ThreadID")),
		data,
	};
}

export const MAX_EVENTS = 200_000;

/** Read every chunk's records (up to MAX_EVENTS). `onChunk` lets a reader
 * yield between chunks; it is called with the chunk's index. */
export async function parseEvtx(b: Uint8Array, onChunk?: (i: number) => Promise<void> | void): Promise<EvtxLog | null> {
	if (!isEvtx(b)) return null;
	const r = new Reader(b);
	const flags = r.u32(120);
	const log: EvtxLog = { chunks: 0, nextRecord: r.u64(24), dirty: !!(flags & 1), full: !!(flags & 2), events: [], badChecksums: [], gaps: [], truncated: false, warnings: [] };
	if (crc32(r.slice(0, 120)) !== r.u32(124)) log.warnings.push("its file header does not match its checksum");
	const chunks = Math.floor((b.length - 4096) / 65536);
	let last = -1;
	for (let c = 0; c < chunks; c++) {
		const base = 4096 + c * 65536;
		if (String.fromCharCode(...r.slice(base, 8)) !== "ElfChnk\0") continue;
		log.chunks++;
		await onChunk?.(c);
		const chunk = new Chunk(r, base);
		try {
			const lastRecordOff = r.u32(base + 44);
			const freeOff = r.u32(base + 48);
			const headerSum = crc32(r.slice(base, 120), r.slice(base + 128, 384));
			const recordsSum = crc32(r.slice(base + 512, Math.max(0, Math.min(freeOff, 65536) - 512)));
			if (headerSum !== r.u32(base + 124) || recordsSum !== r.u32(base + 52)) log.badChecksums.push(c);
			let at = base + 512;
			const end = base + Math.min(Math.max(freeOff, lastRecordOff + 24), 65536);
			while (at + 24 <= end) {
				if (r.u32(at) !== 0x00002a2a) break;
				const size = r.u32(at + 4);
				if (size < 28 || at + size > base + 65536) break;
				const record = r.u64(at + 8);
				try {
					chunk.budget = MAX_NODES;
					const parsed = chunk.parse(at + 24, at + size - 4, 0);
					const ev = eventOf(chunk.render(parsed), record, at, filetimeText(r, at + 16));
					if (last >= 0 && record > last + 1) log.gaps.push({ after: last, missing: record - last - 1 });
					last = record;
					log.events.push(ev);
				} catch (e) {
					if (!(e instanceof Short || e instanceof Refused)) throw e;
					log.warnings.push(`record ${record} could not be read (${e.message})`);
				}
				if (log.events.length >= MAX_EVENTS) {
					log.truncated = true;
					return log;
				}
				at += size;
			}
		} catch (e) {
			if (!(e instanceof Short)) throw e;
			log.warnings.push(`chunk ${c} is cut short`);
		}
	}
	return log;
}
