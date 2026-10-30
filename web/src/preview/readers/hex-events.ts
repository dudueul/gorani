// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The hex reader's Events tab (commit 42j, docs/PREVIEWS.md › Forensic
 * formats): a Windows event log as Event Viewer would list it — but
 * offline, inside the frame, and with the records that matter marked.
 *
 *   the table     time (UTC), record, event ID, level, provider, and what
 *                 the event is with its few values that matter (who, from
 *                 where, which command) — virtualized: 200,000 rows scroll
 *                 like 20
 *   the filters   free text over every value; "4624" for an event ID,
 *                 "#1234" for a record, "IpAddress=10.0.0.5" for a field;
 *                 by level, by event ID, newest first, and "Notable only"
 *                 — the records a finding above the preview names
 *   the details   every System field and every EventData value, as
 *                 written: controls and right-to-left marks made visible
 *                 (a value is data an attacker may have chosen), and the
 *                 record's bytes one click away in the Hex tab
 *
 * Every value reaches the page through textContent.
 */

import { el } from "../host.ts";
import type { EvtxEvent, EvtxLog } from "../forensic/evtx.ts";
import { brief, describe, levelOf, shown, type EvtxFindings } from "../facts/evtx.ts";
import eventsCss from "./hex-events.css?inline";
import { addCss } from "../kit.ts";

const RH = 22;
const shortTime = (t: string) => (t ? t.slice(0, 23).replace("T", " ") : "—");
const shortProvider = (p: string) => p.replace(/^Microsoft-Windows-/, "");

export class EventsPane {
	readonly pane: HTMLElement;
	private log: EvtxLog | null = null;
	private findings: EvtxFindings | null = null;
	/** The events shown, as indices into log.events, in the order shown. */
	private rows: number[] = [];
	/** The selected row (an index into rows), or -1. */
	private sel = -1;
	private readonly count = el("span", { class: "muted", "data-test": "hex-events-count" }, "Reading events…");
	private readonly filter = el("input", { type: "search", placeholder: "Filter: text, 4624, #record, Field=value", "aria-label": "Filter events", "data-test": "hex-events-filter", spellcheck: "false" });
	private readonly level = el("select", { "aria-label": "Level", "data-test": "hex-events-level" }, el("option", { value: "" }, "All levels"));
	private readonly id = el("select", { "aria-label": "Event ID", "data-test": "hex-events-id" }, el("option", { value: "" }, "All event IDs"));
	private readonly notable = el("input", { type: "checkbox", "data-test": "hex-events-notable" });
	private readonly newest = el("input", { type: "checkbox", "data-test": "hex-events-newest" });
	private readonly scroller = el("div", { class: "evscroll", tabindex: "0", "data-test": "hex-events" });
	private readonly spacer = el("div", { class: "spacer" });
	private readonly win = el("div", { class: "evwin" });
	private readonly detail = el("div", { class: "evdetail", "data-test": "hex-event" }, el("p", { class: "muted" }, "Choose an event to see all of it."));
	private readonly toHex: (offset: number, len: number) => void;
	private idKeys: string[] = [];
	private timer = 0;

	constructor(toHex: (offset: number, len: number) => void) {
		addCss(eventsCss);
		this.toHex = toHex;
		this.scroller.append(this.spacer, this.win);
		const head = el("div", { class: "evrow evhead" }, ...["", "Time (UTC)", "Record", "ID", "Level", "Provider", "What"].map((h) => el("span", {}, h)));
		const tools = el(
			"div",
			{ class: "bar tools evtools" },
			this.filter,
			this.level,
			this.id,
			el("label", { title: "Only the records a finding above names" }, this.notable, " Notable only"),
			el("label", {}, this.newest, " Newest first"),
			el("span", { class: "grow" }),
			this.count,
		);
		this.pane = el("div", { class: "pane evpane", "data-test": "hex-events-pane" }, tools, head, this.scroller, this.detail);
		for (const c of [this.filter]) c.addEventListener("input", () => this.later());
		for (const c of [this.level, this.id, this.notable, this.newest]) c.addEventListener("change", () => this.apply());
		this.scroller.addEventListener("scroll", () => this.draw(), { passive: true });
		this.scroller.addEventListener("click", (e) => {
			const r = (e.target as HTMLElement).closest?.("[data-i]")?.getAttribute("data-i");
			if (r !== null && r !== undefined) this.pick(Number(r));
		});
		this.scroller.addEventListener("keydown", (e) => {
			const page = Math.max(1, Math.floor(this.scroller.clientHeight / RH) - 1);
			const to = { ArrowDown: this.sel + 1, ArrowUp: this.sel - 1, PageDown: this.sel + page, PageUp: this.sel - page, Home: 0, End: this.rows.length - 1 }[e.key];
			if (to === undefined || !this.rows.length) return;
			e.preventDefault();
			this.pick(Math.max(0, Math.min(this.rows.length - 1, to)));
		});
		new ResizeObserver(() => this.draw()).observe(this.scroller);
	}

	/** While the log is read, a chunk at a time. */
	progress(chunk: number, chunks: number): void {
		this.count.textContent = `Reading events… chunk ${chunk + 1} of ${chunks}`;
	}

	fail(why: string): void {
		this.count.textContent = why;
	}

	fill(log: EvtxLog, findings: EvtxFindings): void {
		this.log = log;
		this.findings = findings;
		// The levels and IDs there are, commonest first.
		const levels = new Map<string, number>();
		const ids = new Map<string, number>();
		for (const e of log.events) {
			const l = levelOf(e);
			levels.set(l, (levels.get(l) ?? 0) + 1);
			const k = `${e.eventId}\u0000${e.provider}`;
			ids.set(k, (ids.get(k) ?? 0) + 1);
		}
		for (const [l, n] of [...levels].sort((a, b) => b[1] - a[1])) this.level.append(el("option", { value: l }, `${l} (${n.toLocaleString("en")})`));
		this.idKeys = [...ids].sort((a, b) => b[1] - a[1]).slice(0, 200).map(([k]) => k);
		for (const [i, k] of this.idKeys.entries()) {
			const [id, provider] = k.split("\u0000") as [string, string];
			const name = describe({ eventId: Number(id), provider } as EvtxEvent);
			this.id.append(el("option", { value: String(i) }, `${id}${name ? ` · ${name}` : ""} · ${shortProvider(provider)} (${ids.get(k)!.toLocaleString("en")})`));
		}
		this.notable.disabled = !findings.notable.size;
		this.apply();
	}

	private later(): void {
		clearTimeout(this.timer);
		this.timer = setTimeout(() => this.apply(), 150) as unknown as number;
	}

	/** The test the filters make, as one function over an event. */
	private test(): (e: EvtxEvent) => boolean {
		const text = this.filter.value.trim();
		const level = this.level.value;
		const key = this.id.value ? this.idKeys[Number(this.id.value)] : undefined;
		const only = this.notable.checked ? this.findings!.notable : null;
		let t: (e: EvtxEvent) => boolean = () => true;
		const m = /^([\w .-]+?)\s*=\s*(.*)$/.exec(text);
		if (/^\d+$/.test(text)) {
			const n = Number(text);
			t = (e) => e.eventId === n;
		} else if (/^#\d+$/.test(text)) {
			const n = Number(text.slice(1));
			t = (e) => e.record === n;
		} else if (m) {
			const name = m[1]!.toLowerCase();
			const want = m[2]!.toLowerCase();
			const system: Record<string, (e: EvtxEvent) => string> = { provider: (e) => e.provider, computer: (e) => e.computer, channel: (e) => e.channel, user: (e) => e.user, level: (e) => levelOf(e) };
			t = system[name] ? (e) => system[name]!(e).toLowerCase().includes(want) : (e) => e.data.some(([k, v]) => k.toLowerCase() === name && v.toLowerCase().includes(want));
		} else if (text) {
			const needle = text.toLowerCase();
			t = (e) => e.provider.toLowerCase().includes(needle) || e.computer.toLowerCase().includes(needle) || e.user.toLowerCase().includes(needle) || e.data.some(([, v]) => v.toLowerCase().includes(needle)) || (describe(e)?.toLowerCase().includes(needle) ?? false);
		}
		return (e) => (!level || levelOf(e) === level) && (!key || `${e.eventId}\u0000${e.provider}` === key) && (!only || only.has(e.record)) && t(e);
	}

	private apply(): void {
		const log = this.log;
		if (!log) return;
		const keep = this.sel >= 0 ? this.rows[this.sel] : undefined;
		const test = this.test();
		const rows: number[] = [];
		for (let i = 0; i < log.events.length; i++) if (test(log.events[i]!)) rows.push(i);
		if (this.newest.checked) rows.reverse();
		this.rows = rows;
		this.spacer.style.height = `${rows.length * RH}px`;
		this.count.textContent = `${rows.length.toLocaleString("en")} of ${log.events.length.toLocaleString("en")} events`;
		const at = keep === undefined ? -1 : rows.indexOf(keep);
		this.sel = at;
		if (at < 0) this.showDetail(null);
		this.draw();
	}

	private draw(): void {
		const log = this.log;
		if (!log || this.pane.hidden) return;
		const first = Math.floor(this.scroller.scrollTop / RH);
		const n = Math.ceil((this.scroller.clientHeight || 400) / RH) + 1;
		this.win.style.transform = `translateY(${first * RH}px)`;
		const notable = this.findings?.notable;
		const out: HTMLElement[] = [];
		for (let r = first; r < Math.min(this.rows.length, first + n); r++) {
			const e = log.events[this.rows[r]!]!;
			const why = notable?.get(e.record);
			const lvl = levelOf(e);
			const what = [describe(e), brief(e)].filter(Boolean).join(" — ");
			const row = el(
				"div",
				{ class: `evrow${r === this.sel ? " sel" : ""}${why ? " notable" : ""}`, "data-i": String(r), ...(why ? { title: why } : {}) },
				el("span", { class: "warn" }, why ? "⚠" : ""),
				el("span", {}, shortTime(e.time)),
				el("span", { class: "muted" }, String(e.record)),
				el("span", {}, String(e.eventId)),
				el("span", { class: /Error|Critical|failure/.test(lvl) ? "warn" : lvl === "Warning" ? "caution" : "muted" }, lvl),
				el("span", { class: "muted" }, shortProvider(e.provider)),
				el("span", {}, shown(what.replace(/\s+/g, " ").slice(0, 400))),
			);
			out.push(row);
		}
		this.win.replaceChildren(...out);
	}

	private pick(r: number): void {
		this.sel = r;
		const top = r * RH;
		if (top < this.scroller.scrollTop) this.scroller.scrollTop = top;
		else if (top + RH > this.scroller.scrollTop + this.scroller.clientHeight) this.scroller.scrollTop = top + RH - this.scroller.clientHeight;
		this.draw();
		this.showDetail(this.log!.events[this.rows[r]!]!);
	}

	private showDetail(e: EvtxEvent | null): void {
		if (!e) return void this.detail.replaceChildren(el("p", { class: "muted" }, this.rows.length ? "Choose an event to see all of it." : "No event matches."));
		const why = this.findings?.notable.get(e.record);
		const system: [string, string][] = [
			["Time (UTC)", e.time || "—"],
			["Written", e.written || "—"],
			["Record", `#${e.record} at 0x${e.offset.toString(16)}`],
			["Provider", e.provider || "—"],
			["Channel", e.channel || "—"],
			["Computer", e.computer || "—"],
			["Level", levelOf(e)],
			["Task · opcode", `${e.task} · ${e.opcode}`],
			["Keywords", e.keywords || "—"],
			["User", e.user || "—"],
			["Process · thread", `${e.processId ?? "—"} · ${e.threadId ?? "—"}`],
		];
		const data = el("table", { class: "kv", "data-test": "hex-event-data" });
		for (const [k, v] of e.data) data.append(el("tr", {}, el("th", {}, shown(k)), el("td", { class: "mono evval" }, v ? shown(v) : "—")));
		const bytes = el("button", {}, "Show its bytes in Hex");
		bytes.addEventListener("click", () => this.toHex(e.offset, 24));
		const t = el("table", { class: "kv" });
		for (const [k, v] of system) t.append(el("tr", {}, el("th", {}, k), el("td", { class: "mono" }, shown(v))));
		this.detail.replaceChildren(
			el("h3", {}, `${e.eventId}${describe(e) ? ` · ${describe(e)}` : ""}`),
			...(why ? [el("p", { class: "warn", "data-test": "hex-event-why" }, `⚠ ${why}`)] : []),
			t,
			el("h4", {}, e.data.length ? `Data (${e.data.length})` : "No data"),
			...(e.data.length ? [data] : []),
			bytes,
		);
	}

	/** When the tab is shown again (the grid was hidden while it scrolled). */
	shownAgain(): void {
		this.draw();
	}
}
