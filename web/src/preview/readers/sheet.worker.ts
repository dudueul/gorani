// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The spreadsheet reader's worker (commit 42b, docs/PREVIEWS.md › Excel):
 * SheetJS (Apache-2.0) parsing the workbook, off the frame's main thread.
 *
 * Why a worker: a workbook is the one format here whose parse can take
 * seconds (200,000 rows) — and on a browser that keeps a sandboxed frame
 * in the page's own process, a long parse in the frame stalls the whole
 * app. Here it stalls only this worker. The workbook then STAYS here: the
 * frame asks for the rows it is about to show, 200 at a time, and for the
 * cells that match a search — a million cells never cross over at once.
 *
 * The protocol (reader ⇄ worker, structured-cloned):
 *   → {t:"open", bytes, name}       ← {t:"book", sheets, facts} | {t:"refused", title, why, facts}
 *   → {t:"rows", id, sheet, from, to}  ← {t:"rows", id, rows, hidden}
 *   → {t:"find", id, q}             ← {t:"found", id, hits}
 *
 * Formulas are never computed: a cell shows the value the file saved with
 * it. That is also why nothing in a formula — a DDE call, WEBSERVICE —
 * can run here; the facts name them.
 */

import * as XLSX from "xlsx";
import type { Fact } from "../host.ts";
import { linkFact, packageFacts, plural, propsWords, rels, shortUrl, some, unxml } from "../office.ts";
import { withMacros } from "../facts/vba.ts";
import { macrosInOle, macrosInZip, safely, type Macros } from "../vba/macros.ts";
import { Ole, propertySet, summaryWords } from "../ole.ts";
import { Zip } from "../zip.ts";

/** Rows read per sheet (SheetJS's sheetRows) — beyond, the facts say so. */
const MAX_ROWS = 200_000;
/** Columns shown (Excel has 16,384; nothing legible has more than this). */
const MAX_COLS = 512;

export interface SheetInfo {
	name: string;
	/** 0 shown, 1 hidden, 2 "very hidden" (only a macro or an editor can show it). */
	hidden: 0 | 1 | 2;
	kind: "sheet" | "macro" | "chart" | "dialog";
	rows: number;
	cols: number;
	/** Rows in the sheet, when more than were read. */
	allRows: number;
	widths: (number | null)[];
	hiddenCols: number[];
	/** Merged cells, as their top-left cell and how far they span. */
	merges: { r: number; c: number; rs: number; cs: number }[];
}

/** One cell as the reader draws it: its text, its SheetJS type, formula, link. */
export type CellOut = [text: string, type: string, formula?: string, link?: string] | null;

const post = (m: unknown) => (globalThis as unknown as Worker).postMessage(m);
let book: XLSX.WorkBook | null = null;
let infos: SheetInfo[] = [];

// (globalThis, not self: in the worker they are the same object, and in
// Node — unit:preview-facts imports this file for `analyse` — there is no self.)
(globalThis as { onmessage?: unknown }).onmessage = (e: MessageEvent) => {
	const d = e.data as { t: string; id?: number; bytes?: ArrayBuffer; name?: string; sheet?: number; from?: number; to?: number; q?: string };
	try {
		if (d.t === "open" && d.bytes) post(analyse(new Uint8Array(d.bytes), d.name ?? ""));
		else if (d.t === "rows") post({ t: "rows", id: d.id, ...rows(d.sheet ?? 0, d.from ?? 0, d.to ?? 0) });
		else if (d.t === "find") post({ t: "found", id: d.id, hits: find(d.q ?? "") });
	} catch (err) {
		post({ t: "error", message: err instanceof Error ? err.message : String(err) });
	}
};

/** A CSV's text: by its byte-order mark, else UTF-8 if it is valid UTF-8,
 * else CP949 — the code page Korean Excel saves CSV in. */
function decodeText(b: Uint8Array): { text: string; encoding: string } {
	if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return { text: new TextDecoder("utf-8").decode(b.subarray(3)), encoding: "UTF-8" };
	if (b[0] === 0xff && b[1] === 0xfe) return { text: new TextDecoder("utf-16le").decode(b.subarray(2)), encoding: "UTF-16" };
	if (b[0] === 0xfe && b[1] === 0xff) return { text: new TextDecoder("utf-16be").decode(b.subarray(2)), encoding: "UTF-16" };
	try {
		return { text: new TextDecoder("utf-8", { fatal: true }).decode(b), encoding: "UTF-8" };
	} catch {
		return { text: new TextDecoder("euc-kr").decode(b), encoding: "CP949 (Korean Windows)" };
	}
}

export type Analysis = { t: "book"; sheets: SheetInfo[]; facts: Fact[]; macros: Macros | null } | { t: "refused"; title: string; why: string; facts: Fact[] };

/** Parse the workbook (kept here for the rows and searches that follow)
 * and say what it is. Pure apart from keeping it: unit:preview-facts. */
export function analyse(bytes: Uint8Array, name: string): Analysis {
	const ext = name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
	const facts: Fact[] = [];
	let zip: Zip | null = null;
	let ole: Ole | null = null;
	if (Zip.is(bytes)) {
		zip = Zip.open(bytes);
		const trap = zip ? zip.check() : "its ZIP directory is damaged";
		if (trap) return { t: "refused", title: "This workbook is not opened.", why: `Its ZIP is a trap: ${trap}.`, facts: [{ level: "warn", text: `Not opened: ${trap} — a "ZIP bomb"` }] };
	} else if (Ole.is(bytes)) {
		ole = Ole.open(bytes);
		if (ole?.has("EncryptedPackage")) return { t: "refused", title: "This workbook is protected with a password.", why: "It cannot be shown here.", facts: [{ level: "warn", text: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" }] };
	}
	const csv = !zip && !ole && /^(csv|tsv|txt|prn)$/.test(ext);
	let encoding = "";
	if (csv) {
		const t = decodeText(bytes);
		encoding = t.encoding;
		// raw: every cell stays the text the file has — no number or date
		// guessed from "1-2", and "=…" stays text (named below, not computed).
		book = XLSX.read(t.text, { type: "string", raw: true, dense: true, sheetRows: MAX_ROWS });
	} else {
		book = XLSX.read(bytes, { type: "array", dense: true, cellFormula: true, cellHTML: false, cellText: true, cellStyles: true, bookVBA: true, sheetRows: MAX_ROWS, WTF: false });
	}
	infos = book.SheetNames.map((n, i) => info(book!, n, i));
	facts.push(...bookFacts(book, infos, zip, ole, csv));
	const said = [plural(infos.length, "sheet"), encoding && encoding !== "UTF-8" ? `text in ${encoding}` : "", ...(zip ? propsWords(zip) : propWords(book, ole))].filter(Boolean);
	facts.unshift({ level: "info", text: said.join(" · ") });
	// Its VBA (42h): xl/vbaProject.bin, or _VBA_PROJECT_CUR/ in an .xls — read, never run.
	const macros = safely(() => (zip ? macrosInZip(zip) : ole ? macrosInOle(ole) : null));
	return { t: "book", sheets: infos, facts: withMacros(facts, macros), macros };
}

function info(wb: XLSX.WorkBook, name: string, i: number): SheetInfo {
	const ws = wb.Sheets[name] as XLSX.WorkSheet & { "!type"?: string; "!fullref"?: string };
	const meta = wb.Workbook?.Sheets?.[i] as { Hidden?: number } | undefined;
	const ref = ws?.["!ref"] ? XLSX.utils.decode_range(ws["!ref"]) : null;
	const full = ws?.["!fullref"] ? XLSX.utils.decode_range(ws["!fullref"]) : ref;
	const cols = ref ? Math.min(ref.e.c + 1, MAX_COLS) : 0;
	const colInfo = (ws?.["!cols"] ?? []) as ({ wpx?: number; hidden?: boolean } | null)[];
	const widths: (number | null)[] = [];
	const hiddenCols: number[] = [];
	for (let c = 0; c < cols; c++) {
		const ci = colInfo[c];
		widths.push(ci?.wpx ? Math.min(400, Math.max(24, Math.round(ci.wpx))) : null);
		if (ci?.hidden) hiddenCols.push(c);
	}
	const merges = ((ws?.["!merges"] ?? []) as XLSX.Range[]).slice(0, 5000).map((m) => ({ r: m.s.r, c: m.s.c, rs: m.e.r - m.s.r + 1, cs: m.e.c - m.s.c + 1 }));
	// (SheetJS's types say "sheet" | "chart"; its parser also sets "macro" and "dialog".)
	const type = (ws as { "!type"?: string } | undefined)?.["!type"];
	const kind = type === "macro" ? "macro" : type === "chart" ? "chart" : type === "dialog" ? "dialog" : "sheet";
	return { name, hidden: (meta?.Hidden === 2 ? 2 : meta?.Hidden ? 1 : 0) as 0 | 1 | 2, kind, rows: ref ? ref.e.r + 1 : 0, cols, allRows: full ? full.e.r + 1 : 0, widths, hiddenCols, merges };
}

type Cell = XLSX.CellObject & { l?: { Target?: string } };
const dataOf = (i: number): (Cell[] | undefined)[] => ((book?.Sheets[book.SheetNames[i] ?? ""] as { "!data"?: (Cell[] | undefined)[] } | undefined)?.["!data"] ?? []);

function text(cell: Cell): string {
	// A formula saved without its value is a "stub" (t "z"): SheetJS gives it
	// a 0 that the file never had. It has no text; the reader shows the formula.
	if (cell.t === "z") return "";
	if (cell.w !== undefined) return String(cell.w);
	if (cell.v === undefined || cell.v === null) return "";
	return cell.v instanceof Date ? cell.v.toISOString().slice(0, 10) : String(cell.v);
}

function rows(sheet: number, from: number, to: number): { rows: CellOut[][]; hidden: number[] } {
	const s = infos[sheet];
	const data = dataOf(sheet);
	const ws = book?.Sheets[book.SheetNames[sheet] ?? ""] as { "!rows"?: ({ hidden?: boolean } | null)[] } | undefined;
	const out: CellOut[][] = [];
	const hidden: number[] = [];
	for (let r = from; r < Math.min(to, s?.rows ?? 0); r++) {
		const row = data[r];
		const cells: CellOut[] = [];
		for (let c = 0; c < (s?.cols ?? 0); c++) {
			const cell = row?.[c];
			if (!cell) {
				cells.push(null);
				continue;
			}
			const t = text(cell);
			const link = cell.l?.Target;
			cells.push(cell.f || link ? [t.slice(0, 2000), cell.t, cell.f ? `=${cell.f}` : undefined, link] : t ? [t.slice(0, 2000), cell.t] : null);
		}
		out.push(cells);
		if (ws?.["!rows"]?.[r]?.hidden) hidden.push(r);
	}
	return { rows: out, hidden };
}

/** Every cell (in every sheet) whose text or formula holds `q`. */
function find(q: string): { s: number; r: number; c: number }[] {
	const needle = q.toLowerCase();
	const hits: { s: number; r: number; c: number }[] = [];
	if (!needle) return hits;
	infos.forEach((info, s) => {
		const data = dataOf(s);
		for (let r = 0; r < data.length && hits.length < 1000; r++) {
			const row = data[r];
			if (!row) continue;
			for (let c = 0; c < Math.min(row.length, info.cols); c++) {
				const cell = row[c];
				if (cell && (text(cell).toLowerCase().includes(needle) || (cell.f ?? "").toLowerCase().includes(needle))) hits.push({ s, r, c });
			}
		}
	});
	return hits;
}

const colName = (c: number) => {
	let s = "";
	for (let n = c + 1; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + ((n - 1) % 26)) + s;
	return s;
};

/** The workbook's own properties, for the formats without docProps/ (xls, ods, csv). */
function propWords(wb: XLSX.WorkBook, ole: Ole | null): string[] {
	if (ole) {
		const w = summaryWords(propertySet(ole.stream("\u0005SummaryInformation")));
		if (w.length) return w;
	}
	const p = (wb.Props ?? {}) as Record<string, unknown>;
	const said: string[] = [];
	const str = (k: string) => (typeof p[k] === "string" && p[k] ? String(p[k]).slice(0, 80) : "");
	if (str("Title")) said.push(`title ${str("Title")}`);
	if (str("Author")) said.push(`author ${str("Author")}`);
	if (str("LastAuthor") && str("LastAuthor") !== str("Author")) said.push(`last saved by ${str("LastAuthor")}`);
	const day = (k: string) => (p[k] instanceof Date ? (p[k] as Date).toISOString().slice(0, 10) : typeof p[k] === "string" && /^\d{4}-\d\d-\d\d/.test(p[k] as string) ? (p[k] as string).slice(0, 10) : "");
	if (day("CreatedDate")) said.push(`made ${day("CreatedDate")}`);
	if (day("ModifiedDate")) said.push(`changed ${day("ModifiedDate")}`);
	if (str("Application")) said.push(str("Application"));
	return said;
}

/** What a security team should know about this workbook. */
function bookFacts(wb: XLSX.WorkBook, sheets: SheetInfo[], zip: Zip | null, ole: Ole | null, csv: boolean): Fact[] {
	const facts: Fact[] = [];
	let links: string[] = [];
	if (zip) {
		const pf = packageFacts(zip, rels(zip), "Excel");
		facts.push(...pf.facts);
		links = pf.links;
	} else if (wb.vbaraw || ole?.has("_VBA_PROJECT_CUR")) facts.push({ level: "warn", text: "Contains macros (a VBA project) — none of it was run" });
	if (ole) {
		const objects = ole.find(/^MBD[0-9A-F]+$/i);
		if (objects.length) facts.push({ level: "warn", text: `Embeds ${plural(objects.length, "object")} — not opened` });
		if (ole.find(/Equation Native$/i).length) facts.push({ level: "warn", text: "Has an Equation Editor 3.0 object — the way CVE-2017-11882 is exploited (not opened)" });
	}

	const macro = sheets.filter((s) => s.kind === "macro");
	if (macro.length) {
		// SheetJS does not read a macro sheet's cells; its part is plain XML,
		// and its formulas ARE the macro — the first few are quoted.
		const code = zip ? zip.names().filter((n) => /^xl\/macrosheets\/[^/]+\.xml$/.test(n)).flatMap((n) => [...(zip.text(n, 8 * 1024 * 1024) ?? "").matchAll(/<f\b[^>]*>([^<]*)<\/f>/g)].map((m) => `=${unxml(m[1]!)}`)) : [];
		facts.push({ level: "warn", text: `Has ${plural(macro.length, "Excel 4.0 (XLM) macro sheet")}: ${some(macro.map((s) => s.name))} — the old macro language malware still uses; not run${code.length ? `. It says: ${some(code.map((c) => shortUrl(c)), 3)}` : ""}` });
	}
	const hidden = sheets.filter((s) => s.hidden && s.kind !== "macro");
	if (hidden.length) facts.push({ level: "warn", text: `Hides ${plural(hidden.length, "sheet")}: ${some(hidden.map((s) => `${s.name} (${s.hidden === 2 ? "very hidden — only a macro or an editor can show it" : "hidden"})`), 4)} — shown here, marked` });
	for (const n of (wb.Workbook?.Names ?? []) as { Name?: string; Ref?: string }[]) {
		const m = /^(?:_xlnm\.)?(auto_(?:open|close|activate|deactivate))/i.exec(n.Name ?? "");
		if (m) facts.push({ level: "warn", text: `Runs “${shortUrl(n.Ref ?? "?")}” when ${/close|deactivate/i.test(m[1]!) ? "closed" : "opened"} in Excel (${m[1]}) — not run` });
	}

	// Formulas: counted, and the kinds that run or fetch something named.
	let formulas = 0;
	const dde: string[] = [];
	const fetches = new Map<string, string>();
	const injected: string[] = [];
	const outside = new Set<string>();
	sheets.forEach((s, i) => {
		const data = dataOf(i);
		for (let r = 0; r < data.length; r++) {
			const row = data[r];
			if (!row) continue;
			for (let c = 0; c < row.length; c++) {
				const cell = row[c];
				if (!cell) continue;
				const at = `${s.name}!${colName(c)}${r + 1}`;
				if (cell.l?.Target && !cell.l.Target.startsWith("#")) links.push(cell.l.Target);
				if (csv && typeof cell.v === "string" && /^[=+\-@\t\r]/.test(cell.v) && !/^[-+]?\d[\d.,eE+-]*$/.test(cell.v)) injected.push(`${cell.v.slice(0, 60)} (${at})`);
				const f = cell.f;
				if (!f) continue;
				formulas++;
				if (/[A-Za-z0-9_.]+\|\s*'[^']*'\s*!/.test(f) || /^\s*[A-Za-z0-9_.]+\|/.test(f)) dde.push(`=${f.slice(0, 80)} (${at})`);
				for (const m of f.matchAll(/\b(WEBSERVICE|FILTERXML|CALL|REGISTER|REGISTER\.ID|EXEC|RTD|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMAGE)\s*\(/gi)) if (!fetches.has(m[1]!.toUpperCase())) fetches.set(m[1]!.toUpperCase(), at);
				const h = /\bHYPERLINK\s*\(\s*"([^"]+)"/i.exec(f);
				if (h) links.push(h[1]!);
				if (/\[\d+\]|'?\[[^\]]+\.[a-z]{3,4}\]/i.test(f)) outside.add(at);
			}
		}
	});
	if (dde.length) facts.push({ level: "warn", text: `Has ${plural(dde.length, "DDE formula")}, which ${dde.length === 1 ? "runs a program when Excel updates it" : "run a program when Excel updates them"}: ${some(dde, 2)} — not run` });
	if (fetches.size) facts.push({ level: "warn", text: `Has formulas that fetch or run something: ${some([...fetches].map(([fn, at]) => `${fn} (${at})`), 4)} — not computed` });
	if (injected.length) facts.push({ level: "warn", text: `${plural(injected.length, "cell starts", "cells start")} with =, +, − or @ — a spreadsheet would run ${injected.length === 1 ? "it" : "them"} as a formula (CSV injection): ${some(injected, 2)}` });
	if (formulas) facts.push({ level: "info", text: `Has ${plural(formulas, "formula")}${outside.size ? `, ${outside.size} of them reading other workbooks` : ""} — shown as last saved, never recalculated` });

	if (zip) {
		const conn = zip.text("xl/connections.xml", 4 * 1024 * 1024);
		if (conn) {
			const sources = [...conn.matchAll(/<connection\b([^>]*)>([\s\S]*?)<\/connection>/g)].map((m) => {
				const name = /\sname="([^"]*)"/.exec(m[1]!)?.[1] ?? "";
				const src = /\surl="([^"]*)"/.exec(m[2]!)?.[1] ?? /\sconnection="([^"]*)"/.exec(m[2]!)?.[1] ?? /\ssourceFile="([^"]*)"/.exec(m[2]!)?.[1] ?? "";
				return `${unxml(name)}${src ? ` ← ${shortUrl(unxml(src))}` : ""}`;
			});
			if (sources.length) facts.push({ level: "warn", text: `Refreshes data from outside: ${some(sources, 2)} (not fetched)` });
		}
		if (zip.names().some((n) => /^customXml\/item\d+\.xml$/.test(n) && (zip.text(n, 1024 * 1024) ?? "").includes("DataMashup"))) facts.push({ level: "warn", text: "Has Power Query queries — they fetch data when refreshed (not run)" });
		const books = rels(zip).filter((r) => r.type === "externalLinkPath" && r.external).map((r) => shortUrl(r.target));
		if (books.length) facts.push({ level: "warn", text: `Links to outside workbooks: ${some(books, 2)} — Excel asks to update them on opening (not fetched)` });
	}
	const link = linkFact(links);
	if (link) facts.push(link);
	const cut = sheets.filter((s) => s.allRows > s.rows);
	if (cut.length) facts.push({ level: "info", text: `Shows the first ${MAX_ROWS.toLocaleString("en")} rows of ${some(cut.map((s) => `${s.name} (${s.allRows.toLocaleString("en")} rows)`), 2)}` });
	return facts;
}
