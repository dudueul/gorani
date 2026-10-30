// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The spreadsheet reader (commit 42b, docs/PREVIEWS.md › Excel): Excel
 * (.xlsx .xlsm .xlsb .xls), OpenDocument (.ods) and CSV/TSV, inside the
 * preview frame. SheetJS parses in a worker (sheet.worker.ts); this file
 * draws the grid it describes.
 *
 * What it shows that Excel would not, on purpose:
 *   - hidden and VERY hidden sheets get a tab, marked: a very hidden sheet
 *     is where a lure keeps what it does not want the reader to see, and
 *     only a macro or a file editor can unhide one in Excel;
 *   - hidden rows and columns are drawn, striped;
 *   - a cell's formula is in the bar above the grid, as text — values are
 *     the ones the file saved, never recalculated.
 *
 * Every cell's text goes in as text (textContent): a cell that says
 * <script> shows those letters.
 */

import { boot, el, type Host } from "../host.ts";
import { addCss } from "../kit.ts";
import { refusal } from "../office.ts";
import type { CellOut, SheetInfo } from "./sheet.worker.ts";
import type { Macros } from "../vba/macros.ts";
import { macroButton } from "../vba/pane.ts";
import sheetCss from "./sheet.css?inline";

/** Rows asked of the worker at a time. */
const BLOCK = 200;

export const start = boot(async (host) => {
	addCss(sheetCss);
	const worker = host.worker();
	if (!worker) throw new Error("the spreadsheet reader came without its worker");
	const status = el("p", { class: "notice" }, "Opening the workbook…");
	host.root.append(status);

	let next = 1;
	const waiting = new Map<number, (d: unknown) => void>();
	const ask = <T>(m: Record<string, unknown>): Promise<T> =>
		new Promise((ok) => {
			const id = next++;
			waiting.set(id, ok as (d: unknown) => void);
			worker.postMessage({ ...m, id });
		});
	worker.onerror = (e) => host.fail(`the workbook did not open: ${e.message || "the parser stopped"}`);
	worker.onmessage = (e: MessageEvent) => {
		const d = e.data as { t: string; id?: number; sheets?: SheetInfo[]; facts?: []; title?: string; why?: string; message?: string; macros?: Macros | null };
		if (d.t === "book") {
			status.remove();
			new Grid(host, d.sheets ?? [], ask, macroButton(host, d.macros ?? null)).show();
			host.shown(d.facts ?? []);
		} else if (d.t === "refused") {
			refusal(host.root, d.title ?? "This workbook is not opened.", d.why ?? "");
			host.shown(d.facts ?? []);
		} else if (d.t === "error") {
			refusal(host.root, "This workbook does not open.", d.message ?? "");
			host.shown([{ level: "warn", text: "The workbook did not open: it may be damaged, or not a spreadsheet" }]);
		} else if (typeof d.id === "number") {
			waiting.get(d.id)?.(d);
			waiting.delete(d.id);
		}
	};
	// The bytes go on to the worker (transferred: the frame keeps no copy).
	worker.postMessage({ t: "open", bytes: host.file.bytes, name: host.file.name }, [host.file.bytes]);
});

const colName = (c: number) => {
	let s = "";
	for (let n = c + 1; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + ((n - 1) % 26)) + s;
	return s;
};

type Ask = <T>(m: Record<string, unknown>) => Promise<T>;

class Grid {
	private sheet = 0;
	private loaded = 0;
	private loading: Promise<void> | null = null;
	private scroller = el("div", { class: "scroll grid-scroll", "data-test": "sheet-grid" });
	private table = el("table", { class: "grid" });
	private body = el("tbody");
	private sentinel = el("div", { class: "sentinel" });
	private cellLabel = el("span", { class: "cellname", "data-test": "sheet-cell" });
	private formula = el("span", { class: "formula", "data-test": "sheet-formula" });
	private tabs = el("div", { class: "tabs", role: "tablist" });
	private search = el("input", { type: "search", placeholder: "Find in the workbook", "aria-label": "Find in the workbook", "data-test": "find" });
	private found = el("span", { class: "muted", "data-test": "found" });
	private hits: { s: number; r: number; c: number }[] = [];
	private hitAt = -1;
	private query = "";
	private selected: HTMLElement | null = null;
	private observer: IntersectionObserver;
	/** The cells of the rows drawn so far, for the formula bar. */
	private cells = new Map<string, CellOut>();

	constructor(private host: Host, private sheets: SheetInfo[], private ask: Ask, private macros: HTMLElement | null = null) {
		this.observer = new IntersectionObserver((entries) => {
			if (entries.some((e) => e.isIntersecting)) void this.more();
		}, { root: this.scroller, rootMargin: "600px 0px" });
		// The first sheet shown is the first one Excel would show.
		this.sheet = Math.max(0, sheets.findIndex((s) => !s.hidden));
	}

	show(): void {
		const bar = el("div", { class: "bar" }, this.cellLabel, this.formula, el("span", { class: "grow" }), ...(this.macros ? [this.macros] : []), this.search, this.found);
		this.sheets.forEach((s, i) => {
			const label = s.kind === "macro" ? `⚠ ${s.name} (macro)` : s.hidden === 2 ? `${s.name} (very hidden)` : s.hidden ? `${s.name} (hidden)` : s.name;
			const tab = el("button", { role: "tab", class: `tab${s.hidden || s.kind === "macro" ? " hid" : ""}`, "data-test": "sheet-tab", "aria-selected": String(i === this.sheet) }, label);
			tab.addEventListener("click", () => this.open(i));
			this.tabs.append(tab);
		});
		this.search.addEventListener("keydown", (e) => {
			if (e.key === "Enter") {
				e.preventDefault();
				void this.find(e.shiftKey ? -1 : 1);
			}
		});
		this.search.addEventListener("input", () => {
			this.hits = [];
			this.hitAt = -1;
			this.query = "";
			this.found.textContent = "";
		});
		window.addEventListener("keydown", (e) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
				e.preventDefault();
				this.search.focus();
				this.search.select();
			}
		});
		this.table.addEventListener("click", (e) => {
			const td = (e.target as HTMLElement).closest<HTMLElement>("td[data-c]");
			if (td) this.select(td);
		});
		this.scroller.append(this.table, this.sentinel);
		this.host.root.append(bar, this.scroller, this.tabs);
		this.observer.observe(this.sentinel);
		this.open(this.sheet);
	}

	private open(i: number): void {
		this.sheet = i;
		this.loaded = 0;
		this.loading = null;
		this.cells.clear();
		this.selected = null;
		this.cellLabel.textContent = "";
		this.formula.textContent = "";
		for (const [n, t] of [...this.tabs.children].entries()) t.setAttribute("aria-selected", String(n === i));
		const s = this.sheets[i]!;
		const cols = el("colgroup", {}, el("col", { class: "rowhead" }));
		const head = el("tr", {}, el("th", { class: "corner" }));
		for (let c = 0; c < s.cols; c++) {
			const hiddenCol = s.hiddenCols.includes(c);
			cols.append(el("col", { style: `width:${hiddenCol ? 24 : (s.widths[c] ?? 80)}px` }));
			head.append(el("th", { class: hiddenCol ? "hid" : "", title: hiddenCol ? "A hidden column" : "" }, colName(c)));
		}
		this.body = el("tbody");
		this.table.replaceChildren(cols, el("thead", {}, head), this.body);
		this.scroller.scrollTo({ top: 0, left: 0 });
		if (!s.rows) {
			this.body.append(el("tr", {}, el("td", { class: "empty", colspan: String(s.cols + 1) }, s.kind === "macro" ? "A macro sheet: its formulas are the macro (not run)." : "This sheet is empty.")));
			return;
		}
		void this.more();
	}

	/** The next block of rows, asked of the worker. */
	private more(): Promise<void> {
		const s = this.sheets[this.sheet]!;
		if (this.loading || this.loaded >= s.rows) return this.loading ?? Promise.resolve();
		const sheet = this.sheet;
		const from = this.loaded;
		this.loading = this.ask<{ rows: CellOut[][]; hidden: number[] }>({ t: "rows", sheet, from, to: from + BLOCK }).then(({ rows, hidden }) => {
			if (sheet !== this.sheet) return;
			this.draw(s, from, rows, new Set(hidden));
			this.loaded = from + rows.length;
			this.loading = null;
			// Still in view (a tall window): keep going.
			const v = this.scroller.getBoundingClientRect();
			if (this.sentinel.getBoundingClientRect().top < v.bottom + 600) void this.more();
		});
		return this.loading;
	}

	private draw(s: SheetInfo, from: number, rows: CellOut[][], hiddenRows: Set<number>): void {
		// Merged cells: the top-left one spans the columns (rows are drawn in
		// blocks, so only the sideways part of a merge is drawn as one).
		const spans = new Map<string, number>();
		const covered = new Set<string>();
		for (const m of s.merges) {
			if (m.cs < 2 || m.r < from || m.r >= from + rows.length) continue;
			spans.set(`${m.r}:${m.c}`, m.cs);
			for (let c = m.c + 1; c < m.c + m.cs; c++) covered.add(`${m.r}:${c}`);
		}
		const frag = document.createDocumentFragment();
		rows.forEach((row, i) => {
			const r = from + i;
			const tr = el("tr", { class: hiddenRows.has(r) ? "hid" : "" }, el("th", { title: hiddenRows.has(r) ? "A hidden row" : "" }, String(r + 1)));
			for (let c = 0; c < s.cols; c++) {
				const key = `${r}:${c}`;
				if (covered.has(key)) continue;
				const cell = row[c] ?? null;
				const td = el("td", { "data-r": String(r), "data-c": String(c) });
				const span = spans.get(key);
				if (span) td.colSpan = Math.min(span, s.cols - c);
				if (s.hiddenCols.includes(c)) td.classList.add("hid");
				if (cell) {
					const [text, type, f, link] = cell;
					// A formula saved without its value shows the formula, dimmed.
					td.textContent = text || (f ?? "");
					if (!text && f) td.classList.add("nocache");
					if (type === "n") td.classList.add("num");
					if (type === "e") td.classList.add("err");
					if (f) td.classList.add("f");
					if (link) td.classList.add("link");
					this.cells.set(key, cell);
				}
				tr.append(td);
			}
			frag.append(tr);
		});
		this.body.append(frag);
	}

	private select(td: HTMLElement): void {
		this.selected?.classList.remove("sel");
		td.classList.add("sel");
		this.selected = td;
		const r = Number(td.dataset.r);
		const c = Number(td.dataset.c);
		const cell = this.cells.get(`${r}:${c}`) ?? null;
		this.cellLabel.textContent = `${colName(c)}${r + 1}`;
		this.formula.textContent = cell ? (cell[2] ?? cell[0]) + (cell[3] ? `  → ${cell[3]}` : "") : "";
	}

	private async find(dir: 1 | -1): Promise<void> {
		const q = this.search.value.trim();
		if (!q) return;
		if (q !== this.query) {
			this.query = q;
			this.found.textContent = "Searching…";
			this.hits = (await this.ask<{ hits: { s: number; r: number; c: number }[] }>({ t: "find", q })).hits;
			this.hitAt = -1;
		}
		if (!this.hits.length) {
			this.found.textContent = "Not found";
			return;
		}
		this.hitAt = (this.hitAt + dir + this.hits.length) % this.hits.length;
		const hit = this.hits[this.hitAt]!;
		if (hit.s !== this.sheet) this.open(hit.s);
		while (this.loaded <= hit.r && this.loaded < (this.sheets[hit.s]?.rows ?? 0)) await this.more();
		const td = this.body.querySelector<HTMLElement>(`td[data-r="${hit.r}"][data-c="${hit.c}"]`);
		this.found.textContent = `${this.sheets[hit.s]?.name}!${colName(hit.c)}${hit.r + 1} · ${this.hitAt + 1} of ${this.hits.length}${this.hits.length >= 1000 ? "+" : ""}`;
		if (td) {
			this.select(td);
			td.scrollIntoView({ block: "center", inline: "nearest" });
		}
	}
}
