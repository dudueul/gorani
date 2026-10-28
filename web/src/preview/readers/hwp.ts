// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The 한글 reader (commit 42b, docs/PREVIEWS.md › 한글): HWP 5 (and the
 * older HWP 3) and HWPX, on rhwp (Edward Kim, MIT) — a parser and renderer
 * written in Rust, run as WebAssembly inside the preview frame.
 *
 * HWP is the format Korean public offices and companies exchange, and so
 * the one attackers in Korea send: an HWP lure has carried PostScript
 * (EPS) that exploited 한글's Ghostscript, scripts that run on opening, OLE
 * objects that drop programs. rhwp draws none of that — it lays out text,
 * tables and pictures and paints them on a canvas — and the facts NAME
 * what is there, read from the file's structure:
 *
 *   HWP 5   an OLE container (ole.ts): FileHeader's flags (password,
 *           distribution document, DRM, signature), Scripts/, BinData/
 *           (EPS, OLE objects), \x05HwpSummaryInformation (who, when), and
 *           the links in its text (hyperlink fields keep their address as
 *           text in the BodyText streams)
 *   HWPX    a ZIP of XML (zip.ts, its bomb check first): Scripts/,
 *           BinData/, Contents/content.hpf (who, when), the section XML
 *
 * Pages are drawn as they come into view, with a text layer over each (from
 * rhwp's own layout of the runs) so text can be selected and found.
 */

import init, { HwpDocument } from "@rhwp/core";
import { boot, el, type Host } from "../host.ts";
import { addCss, perFrame, Zoom } from "../kit.ts";
import { hwpFacts, hwpxFacts } from "../facts/hwp.ts";
import { plural, refusal } from "../office.ts";
import { Zip } from "../zip.ts";
import hwpCss from "./hwp.css?inline";

// rhwp lays out text by asking the page how wide a run is in a given font:
// it calls this global (its README: "필수"). One 2D context answers.
const measure = document.createElement("canvas").getContext("2d")!;
let lastFont = "";
(globalThis as { measureTextWidth?: (font: string, text: string) => number }).measureTextWidth = (font, text) => {
	if (font !== lastFont) {
		measure.font = font;
		lastFont = font;
	}
	return measure.measureText(text).width;
};

export const start = boot(async (host) => {
	addCss(hwpCss);
	const bytes = new Uint8Array(host.file.bytes);
	const status = el("p", { class: "notice" }, "Opening the 한글 document…");
	host.root.append(status);

	const zip = Zip.is(bytes) ? Zip.open(bytes) : null;
	if (zip) {
		const trap = zip.check();
		if (trap) {
			refusal(host.root, "This document is not opened.", `Its ZIP is a trap: ${trap}.`);
			host.shown([{ level: "warn", text: `Not opened: ${trap} — a "ZIP bomb"` }]);
			return;
		}
	}
	const facts = zip ? hwpxFacts(zip) : hwpFacts(bytes);

	// rhwp itself: 12 MB of WebAssembly, asked of the app (the frame fetches nothing).
	await init({ module_or_path: await host.asset("rhwp_bg.wasm") });
	let doc: HwpDocument;
	try {
		doc = new HwpDocument(bytes);
	} catch (e) {
		const why = String(e instanceof Error ? e.message : e);
		if (/비밀번호가 필요|password/i.test(why)) {
			facts.push({ level: "warn", text: "Protected with a password — it opens here only with it, and mail scanners could not look inside it" });
			host.shown(facts.filter((f) => f.text));
			const opened = await askPassword(status, bytes);
			if (!opened) return;
			doc = opened;
		} else {
			refusal(host.root, "This 한글 document does not open.", why);
			host.shown([{ level: "warn", text: "The document did not open: it may be damaged, or not a 한글 file" }, ...facts]);
			return;
		}
	}
	status.remove();
	const info = safeJson<{ version?: string; pageCount?: number; hwp3Variant?: boolean }>(() => doc.getDocumentInfo()) ?? {};
	const outside = safeJson<unknown[]>(() => doc.getExternalImageReferences()) ?? [];
	if (outside.length) facts.push({ level: "warn", text: `Links ${plural(outside.length, "picture")} from outside — not fetched` });
	const pages = doc.pageCount();
	facts.unshift({ level: "info", text: [plural(pages, "page"), zip ? "HWPX" : info.hwp3Variant ? "HWP 3" : info.version ? `HWP ${info.version}` : "HWP", ...(facts.shift()?.text.split(" · ").filter(Boolean) ?? [])].join(" · ") });
	await new Viewer(host, doc, pages).show();
	host.shown(facts);
});

function safeJson<T>(f: () => string): T | null {
	try {
		return JSON.parse(f()) as T;
	} catch {
		return null;
	}
}

/** Ask for the password, here in the frame (it goes no further than rhwp). */
function askPassword(status: HTMLElement, bytes: Uint8Array): Promise<HwpDocument | null> {
	return new Promise((done) => {
		const input = el("input", { type: "password", placeholder: "Password", autocomplete: "off", "aria-label": "The document's password", "data-test": "hwp-password" });
		const said = el("p", {}, "This 한글 document is protected with a password:");
		const open = el("button", { type: "button" }, "Open");
		// Not a <form>: the frame's sandbox has no allow-forms, and the browser
		// stops a sandboxed form's submission before its submit event fires.
		const form = el("div", { class: "pw", role: "form" }, said, input, open);
		const attempt = () => {
			try {
				const doc = HwpDocument.openWithPassword(bytes, input.value);
				form.remove();
				done(doc);
			} catch {
				said.textContent = "That password is not it. Try again:";
				input.select();
			}
		};
		open.addEventListener("click", attempt);
		input.addEventListener("keydown", (e) => {
			if (e.key === "Enter") {
				e.preventDefault();
				attempt();
			}
		});
		status.replaceChildren(form);
		queueMicrotask(() => input.focus());
	});
}

interface PageView {
	n: number;
	box: HTMLDivElement;
	width: number;
	height: number;
	drawn: number | null;
	text: string | null;
}

class Viewer {
	private pages: PageView[] = [];
	private scroller = el("div", { class: "scroll pages", "data-test": "hwp-pages" });
	private label = el("span", { class: "muted", "data-test": "hwp-page" });
	private search = el("input", { type: "search", placeholder: "Find in the document", "aria-label": "Find in the document", "data-test": "find" });
	private found = el("span", { class: "muted", "data-test": "found" });
	private zoom: Zoom;
	private observer: IntersectionObserver;
	private hits: number[] = [];
	private hitAt = -1;

	constructor(private host: Host, private doc: HwpDocument, private count: number) {
		this.observer = new IntersectionObserver((entries) => {
			for (const e of entries) if (e.isIntersecting) this.draw(Number((e.target as HTMLElement).dataset.n));
		}, { root: this.scroller, rootMargin: "800px 0px" });
		this.zoom = new Zoom({
			natural: () => Math.max(0, ...this.pages.map((p) => p.width)) + 24,
			room: () => this.scroller.clientWidth,
			apply: (s) => this.layout(s),
		}, 1.25);
	}

	async show(): Promise<void> {
		const prev = el("button", { title: "Previous page", "aria-label": "Previous page" }, "↑");
		const next = el("button", { title: "Next page", "aria-label": "Next page" }, "↓");
		prev.addEventListener("click", () => this.goto(this.current() - 1));
		next.addEventListener("click", () => this.goto(this.current() + 1));
		this.search.addEventListener("keydown", (e) => {
			if (e.key === "Enter") {
				e.preventDefault();
				this.find(e.shiftKey ? -1 : 1);
			}
		});
		this.search.addEventListener("input", () => {
			this.hits = [];
			this.hitAt = -1;
			this.found.textContent = "";
			this.mark("");
		});
		window.addEventListener("keydown", (e) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
				e.preventDefault();
				this.search.focus();
				this.search.select();
			}
		});
		const bar = el("div", { class: "bar" }, prev, next, this.label, el("span", { class: "sep" }), this.zoom.el, el("span", { class: "grow" }), this.search, this.found);
		this.host.root.append(bar, this.scroller);
		for (let n = 0; n < this.count; n++) {
			const pi = safeJson<{ width?: number; height?: number }>(() => this.doc.getPageInfo(n)) ?? {};
			const box = el("div", { class: "page", "data-n": String(n) }) as HTMLDivElement;
			this.pages.push({ n, box, width: pi.width ?? 794, height: pi.height ?? 1123, drawn: null, text: null });
			this.scroller.append(box);
		}
		this.zoom.update();
		for (const p of this.pages) this.observer.observe(p.box);
		new ResizeObserver(perFrame(() => this.zoom.update())).observe(this.scroller);
		this.scroller.addEventListener("scroll", perFrame(() => this.updateLabel()), { passive: true });
		this.updateLabel();
	}

	private scale = 1;

	private layout(s: number): void {
		this.scale = s;
		for (const p of this.pages) {
			p.box.style.width = `${Math.floor(p.width * s)}px`;
			p.box.style.height = `${Math.floor(p.height * s)}px`;
			if (p.drawn !== null && Math.abs(p.drawn - s) > 0.001) {
				p.drawn = null;
				p.box.replaceChildren();
			}
		}
		for (const p of this.pages) if (this.visible(p)) this.draw(p.n);
	}

	private visible(p: PageView): boolean {
		const r = p.box.getBoundingClientRect();
		const v = this.scroller.getBoundingClientRect();
		return r.bottom > v.top - 800 && r.top < v.bottom + 800;
	}

	private current(): number {
		const v = this.scroller.getBoundingClientRect();
		const mid = v.top + v.height / 3;
		const p = this.pages.find((x) => x.box.getBoundingClientRect().bottom >= mid);
		return p ? p.n : this.pages.length - 1;
	}

	private goto(n: number): void {
		const p = this.pages[Math.max(0, Math.min(this.pages.length - 1, n))];
		if (p) this.scroller.scrollTo({ top: p.box.offsetTop - 8, behavior: "smooth" });
	}

	private updateLabel(): void {
		this.label.textContent = `${this.current() + 1} / ${this.pages.length}`;
	}

	/** One page: rhwp paints the canvas (at the screen's density), then its text layer. */
	private draw(n: number): void {
		const p = this.pages[n];
		const s = this.scale;
		if (!p || (p.drawn !== null && Math.abs(p.drawn - s) < 0.001)) return;
		p.drawn = s;
		const dpr = Math.min(globalThis.devicePixelRatio || 1, this.host.phone ? 2 : 3);
		const canvas = el("canvas", { "aria-label": `Page ${n + 1}` });
		try {
			this.doc.renderPageToCanvas(n, canvas, s * dpr);
		} catch (e) {
			p.box.replaceChildren(el("p", { class: "notice" }, `Page ${n + 1} did not draw: ${e instanceof Error ? e.message : String(e)}`));
			return;
		}
		canvas.style.width = `${Math.floor(p.width * s)}px`;
		canvas.style.height = `${Math.floor(p.height * s)}px`;
		p.box.replaceChildren(canvas, this.textLayer(n, s));
		if (this.search.value.trim()) this.mark(this.search.value.trim(), p);
	}

	/** Transparent text over the canvas, run by run where rhwp laid it out. */
	private textLayer(n: number, s: number): HTMLElement {
		const layer = el("div", { class: "textLayer" });
		const runs = safeJson<{ runs?: { text: string; x: number; y: number; w: number; h: number; fontFamily?: string; fontSize?: number }[] }>(() => this.doc.getPageTextLayout(n))?.runs ?? [];
		for (const r of runs.slice(0, 20_000)) {
			if (!r.text?.trim()) continue;
			const size = (r.fontSize || r.h || 12) * s;
			const span = el("span", {}, r.text);
			span.style.left = `${r.x * s}px`;
			span.style.top = `${r.y * s}px`;
			span.style.fontSize = `${size}px`;
			span.style.fontFamily = `"${(r.fontFamily ?? "").replace(/"/g, "")}", sans-serif`;
			measure.font = `${size}px ${span.style.fontFamily}`;
			lastFont = "";
			const natural = measure.measureText(r.text).width;
			if (natural > 0) span.style.transform = `scaleX(${(r.w * s) / natural})`;
			layer.append(span);
		}
		return layer;
	}

	private textOf(p: PageView): string {
		if (p.text === null) {
			try {
				p.text = String(JSON.parse(this.doc.getPageText(p.n))).toLowerCase();
			} catch {
				p.text = "";
			}
		}
		return p.text;
	}

	/** The next page holding the query (Enter; Shift+Enter goes back). */
	private find(dir: 1 | -1): void {
		const q = this.search.value.trim().toLowerCase();
		if (!q) return;
		if (!this.hits.length) {
			this.hits = this.pages.filter((p) => this.textOf(p).includes(q)).map((p) => p.n);
			this.hitAt = -1;
		}
		if (!this.hits.length) {
			this.found.textContent = "Not found";
			return;
		}
		this.hitAt = (this.hitAt + dir + this.hits.length) % this.hits.length;
		const n = this.hits[this.hitAt]!;
		this.found.textContent = `Page ${n + 1} · ${this.hitAt + 1} of ${plural(this.hits.length, "page")}`;
		this.goto(n);
		this.mark(q);
	}

	private mark(q: string, only?: PageView): void {
		const query = q.toLowerCase();
		for (const p of only ? [only] : this.pages) for (const span of p.box.querySelectorAll<HTMLElement>(".textLayer span")) span.classList.toggle("hit", !!query && (span.textContent ?? "").toLowerCase().includes(query));
	}
}
