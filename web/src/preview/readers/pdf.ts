// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The PDF reader (commit 42a, docs/PREVIEWS.md › PDF), on pdf.js
 * (Mozilla, Apache-2.0), inside the preview frame.
 *
 * pdf.js parses in a worker; this file draws pages on canvases, with a
 * text layer over each for selecting and searching. What a hostile PDF
 * could try, and why it gets nothing:
 *
 *   - its JavaScript (an OpenAction, a field's script): pdf.js runs none
 *     of it — there is no scripting here (that is pdf.js's separate
 *     sandbox, never loaded) — and the frame's CSP has no 'unsafe-eval'.
 *     pdf.js itself compiles nothing any more: CVE-2024-4367 (a font
 *     whose matrix reached `new Function`) led to version 6 dropping the
 *     code path and its `isEvalSupported` option altogether;
 *   - its links: drawn as part of the page, never followed — the frame
 *     cannot navigate or open windows anyway. They are LISTED, as text,
 *     because a link in a PDF is evidence;
 *   - its embedded files: listed, never opened or saved from here;
 *   - a parser bug: it lands in a frame with no origin, no storage and no
 *     network, holding only this one file.
 *
 * What it found is reported to the viewer as facts ("contains JavaScript —
 * not run"), shown above the frame where the frame cannot fake them away.
 */

// pdf.js's LEGACY build: the same code with its newest built-ins polyfilled
// (Map.prototype.getOrInsertComputed, among others, which the modern build
// calls and many browsers in use — a year-old iPhone's — do not have yet).
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import type { PDFDocumentProxy } from "pdfjs-dist";
import { boot, el, type Fact, type Host } from "../host.ts";
import pdfCss from "./pdf.css?inline";

/** pdf.js reads its CMaps (CJK text), standard fonts and image decoders
 * through this — asking the app, over the port, instead of fetching. */
class AppBinaryData {
	static host: Host;
	cMapUrl: string | null;
	standardFontDataUrl: string | null;
	wasmUrl: string | null;
	constructor(o: { cMapUrl?: string | null; standardFontDataUrl?: string | null; wasmUrl?: string | null }) {
		this.cMapUrl = o.cMapUrl ?? null;
		this.standardFontDataUrl = o.standardFontDataUrl ?? null;
		this.wasmUrl = o.wasmUrl ?? null;
	}
	async fetch({ kind, filename }: { kind: "cMapUrl" | "standardFontDataUrl" | "wasmUrl"; filename: string }): Promise<Uint8Array> {
		const dir = { cMapUrl: "cmaps/", standardFontDataUrl: "standard_fonts/", wasmUrl: "wasm/" }[kind];
		if (!dir) throw new Error(`no ${kind} here`);
		return AppBinaryData.host.asset(`${dir}${filename}`);
	}
}

/** Zoom steps, as a share of the page's natural size (1 = 100 % at 96 dpi). */
const ZOOMS = [0.5, 0.67, 0.8, 1, 1.25, 1.5, 2, 3, 4];

export const start = boot(async (host) => {
	AppBinaryData.host = host;
	const style = document.createElement("style");
	style.textContent = pdfCss;
	document.head.append(style);

	const worker = host.worker();
	if (worker) pdfjs.GlobalWorkerOptions.workerPort = worker;

	const status = el("p", { class: "notice" }, "Opening the PDF…");
	host.root.append(status);

	const task = pdfjs.getDocument({
		data: new Uint8Array(host.file.bytes),
		cMapUrl: "cmaps/",
		cMapPacked: true,
		standardFontDataUrl: "standard_fonts/",
		wasmUrl: "wasm/",
		useWorkerFetch: false,
		BinaryDataFactory: AppBinaryData,
		enableXfa: false,
		// A PDF that names a font it does not carry: draw it from the standard
		// set we send, not from whatever this computer has installed.
		useSystemFonts: false,
		// Nothing fetched by range or streamed: the bytes are all here.
		disableRange: true,
		disableStream: true,
		disableAutoFetch: true,
		// Very large images are not decoded (a decompression bomb would
		// exhaust the tab): 50 megapixels is a poster scanned at 600 dpi.
		maxImageSize: 50_000_000,
	});

	// A password-protected PDF: ask, here, in the frame (the password goes
	// no further than pdf.js).
	task.onPassword = (update: (pw: string) => void, reason: number) => {
		status.replaceChildren(passwordForm(reason === pdfjs.PasswordResponses.INCORRECT_PASSWORD, update));
	};

	let doc: PDFDocumentProxy;
	try {
		doc = await task.promise;
	} catch (e) {
		status.replaceChildren(el("strong", {}, "This PDF does not open."), el("br"), String(e instanceof Error ? e.message : e));
		host.shown([{ level: "warn", text: "The PDF did not open: it may be damaged, or not a PDF" }]);
		return;
	}
	status.remove();
	await new Viewer(host, doc).show();
});

function passwordForm(wrong: boolean, update: (pw: string) => void): HTMLElement {
	const input = el("input", { type: "password", placeholder: "Password", autocomplete: "off", "aria-label": "The PDF's password" });
	const form = el("form", { class: "pw" }, el("p", {}, wrong ? "That password is not it. Try again:" : "This PDF is protected with a password:"), input, el("button", { type: "submit" }, "Open"));
	form.addEventListener("submit", (e) => {
		e.preventDefault();
		update(input.value);
	});
	queueMicrotask(() => input.focus());
	return form;
}

interface PageView {
	n: number;
	box: HTMLDivElement;
	width: number; // at scale 1, in CSS px
	height: number;
	drawn: number | null; // the scale it was drawn at
	text: string | null;
}

class Viewer {
	private host: Host;
	private doc: PDFDocumentProxy;
	private pages: PageView[] = [];
	private zoom = 1;
	private fit = true;
	private scroller = el("div", { class: "scroll pages", "data-test": "pdf-pages" });
	private sidebar = el("nav", { class: "thumbs", "aria-label": "Pages" });
	private pageLabel = el("span", { class: "muted", "data-test": "pdf-page" });
	private zoomLabel = el("span", { class: "muted zoomlabel" });
	private found = el("span", { class: "muted", "data-test": "pdf-found" });
	private search = el("input", { type: "search", placeholder: "Find in the PDF", "aria-label": "Find in the PDF", "data-test": "pdf-search" });
	private observer: IntersectionObserver;
	private thumbObserver: IntersectionObserver;
	private hits: number[] = [];
	private hitAt = -1;

	constructor(host: Host, doc: PDFDocumentProxy) {
		this.host = host;
		this.doc = doc;
		this.observer = new IntersectionObserver((entries) => {
			for (const e of entries) if (e.isIntersecting) void this.draw(Number((e.target as HTMLElement).dataset.n));
			this.updatePageLabel();
		}, { root: this.scroller, rootMargin: "800px 0px" });
		this.thumbObserver = new IntersectionObserver((entries) => {
			for (const e of entries) if (e.isIntersecting) void this.drawThumb(e.target as HTMLElement);
		}, { root: this.sidebar, rootMargin: "400px 0px" });
	}

	async show(): Promise<void> {
		const { host, doc } = this;
		const bar = el("div", { class: "bar" });
		const prev = el("button", { title: "Previous page", "aria-label": "Previous page" }, "↑");
		const next = el("button", { title: "Next page", "aria-label": "Next page" }, "↓");
		const out = el("button", { title: "Zoom out", "aria-label": "Zoom out" }, "−");
		const inn = el("button", { title: "Zoom in", "aria-label": "Zoom in" }, "+");
		const fitBtn = el("button", { title: "Fit the width", "aria-pressed": "true", "data-test": "pdf-fit" }, "Fit");
		const thumbsBtn = el("button", { title: "Page list", "aria-pressed": String(!host.phone), "data-test": "pdf-thumbs" }, "Pages");
		prev.addEventListener("click", () => this.goto(this.current() - 1));
		next.addEventListener("click", () => this.goto(this.current() + 1));
		out.addEventListener("click", () => this.setZoom(this.stepZoom(-1)));
		inn.addEventListener("click", () => this.setZoom(this.stepZoom(1)));
		fitBtn.addEventListener("click", () => {
			this.fit = true;
			this.layout();
		});
		thumbsBtn.addEventListener("click", () => {
			const open = this.sidebar.hidden;
			this.sidebar.hidden = !open;
			thumbsBtn.setAttribute("aria-pressed", String(open));
		});
		this.search.addEventListener("keydown", (e) => {
			if (e.key === "Enter") {
				e.preventDefault();
				void this.find(this.search.value, e.shiftKey ? -1 : 1);
			}
		});
		this.search.addEventListener("input", () => {
			this.hits = [];
			this.hitAt = -1;
			this.found.textContent = "";
			this.mark("");
		});
		bar.append(thumbsBtn, prev, next, this.pageLabel, el("span", { class: "sep" }), out, this.zoomLabel, inn, fitBtn, el("span", { class: "grow" }), this.search, this.found);
		const body = el("div", { class: "body" }, this.sidebar, this.scroller);
		host.root.append(bar, body);
		this.sidebar.hidden = host.phone;
		// Ctrl/Cmd+F finds in the PDF, not in the page around it.
		window.addEventListener("keydown", (e) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
				e.preventDefault();
				this.search.focus();
				this.search.select();
			}
			if (e.target === this.search) return;
			if (e.key === "PageDown" || e.key === " ") return; // the scroller's own
			if (e.key === "+" || e.key === "=") this.setZoom(this.stepZoom(1));
			if (e.key === "-") this.setZoom(this.stepZoom(-1));
		});
		// A page zoomed wider than the screen pans sideways: a swipe there is a pan, not "next file".
		host.setSwipeGuard(() => this.scroller.scrollWidth > this.scroller.clientWidth + 2);

		// Every page's size first (cheap: no drawing), so the scroll bar is
		// right from the start and a jump lands where it should.
		for (let n = 1; n <= doc.numPages; n++) {
			const page = await doc.getPage(n);
			const vp = page.getViewport({ scale: 1 });
			const box = el("div", { class: "page", "data-n": String(n), "data-test": "pdf-page-box" }) as HTMLDivElement;
			this.pages.push({ n, box, width: vp.width, height: vp.height, drawn: null, text: null });
			this.scroller.append(box);
			const thumb = el("button", { class: "thumb", "data-n": String(n), title: `Page ${n}` }, el("span", { class: "num" }, String(n)));
			thumb.addEventListener("click", () => this.goto(n));
			this.sidebar.append(thumb);
			page.cleanup();
		}
		this.layout();
		for (const p of this.pages) this.observer.observe(p.box);
		for (const t of this.sidebar.children) this.thumbObserver.observe(t);
		new ResizeObserver(() => this.fit && this.layout()).observe(this.scroller);
		// The page counter follows the scrolling (once a frame, not per event).
		let queued = false;
		this.scroller.addEventListener("scroll", () => {
			if (queued) return;
			queued = true;
			requestAnimationFrame(() => {
				queued = false;
				this.updatePageLabel();
			});
		}, { passive: true });
		this.updatePageLabel();
		host.shown(await this.facts());
	}

	/** The scale a page is drawn at: fitted to the width — but no bigger than
	 * 150 %, or a wide screen shows a letter page a foot and a half tall —
	 * or the zoom chosen. */
	private scale(p: PageView): number {
		if (!this.fit) return this.zoom;
		const room = Math.max(120, this.scroller.clientWidth - 24);
		return Math.min(1.5, room / p.width);
	}

	private layout(): void {
		for (const p of this.pages) {
			const s = this.scale(p);
			p.box.style.width = `${Math.floor(p.width * s)}px`;
			p.box.style.height = `${Math.floor(p.height * s)}px`;
			if (p.drawn !== null && Math.abs(p.drawn - s) > 0.001) {
				p.drawn = null;
				p.box.replaceChildren();
			}
		}
		const first = this.pages[0];
		this.zoomLabel.textContent = first ? `${Math.round(this.scale(first) * 100)}%` : "";
		// Pages already in view redraw at the new scale.
		for (const p of this.pages) if (this.visible(p)) void this.draw(p.n);
	}

	private stepZoom(dir: 1 | -1): number {
		const now = this.pages[0] ? this.scale(this.pages[0]) : this.zoom;
		const steps = dir > 0 ? ZOOMS.filter((z) => z > now + 0.01) : ZOOMS.filter((z) => z < now - 0.01).reverse();
		return steps[0] ?? now;
	}

	private setZoom(z: number): void {
		const at = this.current();
		this.fit = false;
		this.zoom = z;
		this.layout();
		this.goto(at, false);
	}

	private visible(p: PageView): boolean {
		const r = p.box.getBoundingClientRect();
		const v = this.scroller.getBoundingClientRect();
		return r.bottom > v.top - 800 && r.top < v.bottom + 800;
	}

	private current(): number {
		const v = this.scroller.getBoundingClientRect();
		const mid = v.top + v.height / 3;
		for (const p of this.pages) {
			const r = p.box.getBoundingClientRect();
			if (r.bottom >= mid) return p.n;
		}
		return this.pages.length;
	}

	private goto(n: number, smooth = true): void {
		const p = this.pages[Math.max(1, Math.min(this.pages.length, n)) - 1];
		if (!p) return;
		this.scroller.scrollTo({ top: p.box.offsetTop - 8, behavior: smooth ? "smooth" : "instant" });
	}

	private updatePageLabel(n = this.current()): void {
		this.pageLabel.textContent = `${n} / ${this.pages.length}`;
		for (const t of this.sidebar.children) (t as HTMLElement).classList.toggle("on", Number((t as HTMLElement).dataset.n) === n);
	}

	/** Draw one page: its canvas at the screen's pixel density, then its text layer. */
	private async draw(n: number): Promise<void> {
		const p = this.pages[n - 1];
		if (!p) return;
		const s = this.scale(p);
		if (p.drawn !== null && Math.abs(p.drawn - s) < 0.001) return;
		p.drawn = s;
		const page = await this.doc.getPage(n);
		const viewport = page.getViewport({ scale: s });
		// A phone's 3x screen would make a big page's canvas enormous: 2x is sharp enough.
		const dpr = Math.min(globalThis.devicePixelRatio || 1, this.host.phone ? 2 : 3);
		const canvas = el("canvas", { "aria-label": `Page ${n}` });
		canvas.width = Math.floor(viewport.width * dpr);
		canvas.height = Math.floor(viewport.height * dpr);
		canvas.style.width = `${Math.floor(viewport.width)}px`;
		canvas.style.height = `${Math.floor(viewport.height)}px`;
		const text = el("div", { class: "textLayer" });
		p.box.style.setProperty("--scale-factor", String(s));
		p.box.style.setProperty("--user-unit", "1");
		p.box.style.setProperty("--total-scale-factor", String(s));
		try {
			await page.render({ canvas, viewport, transform: dpr === 1 ? undefined : [dpr, 0, 0, dpr, 0, 0] }).promise;
			if (p.drawn !== s) return; // zoomed again meanwhile
			p.box.replaceChildren(canvas, text);
			await new pdfjs.TextLayer({ textContentSource: page.streamTextContent(), container: text, viewport }).render();
			if (this.search.value.trim()) this.mark(this.search.value.trim(), p);
		} catch (e) {
			if ((e as { name?: string })?.name !== "RenderingCancelledException") p.box.replaceChildren(el("p", { class: "notice" }, `Page ${n} did not draw: ${e instanceof Error ? e.message : String(e)}`));
		} finally {
			page.cleanup();
		}
	}

	private async drawThumb(t: HTMLElement): Promise<void> {
		if (t.querySelector("canvas")) return;
		const n = Number(t.dataset.n);
		const page = await this.doc.getPage(n);
		const vp1 = page.getViewport({ scale: 1 });
		const viewport = page.getViewport({ scale: 96 / vp1.width });
		const canvas = el("canvas");
		canvas.width = Math.floor(viewport.width);
		canvas.height = Math.floor(viewport.height);
		t.prepend(canvas);
		try {
			await page.render({ canvas, viewport }).promise;
		} catch {
			// a thumbnail is a convenience
		} finally {
			page.cleanup();
		}
	}

	/** Each page's text, once, for searching. */
	private async textOf(p: PageView): Promise<string> {
		if (p.text !== null) return p.text;
		const page = await this.doc.getPage(p.n);
		const content = await page.getTextContent();
		p.text = content.items.map((i) => ("str" in i ? i.str : "")).join(" ").toLowerCase();
		page.cleanup();
		return p.text;
	}

	/** Find the next page holding `q` (Enter; Shift+Enter goes back). */
	private async find(q: string, dir: 1 | -1): Promise<void> {
		const query = q.trim().toLowerCase();
		if (!query) return;
		if (!this.hits.length) {
			this.found.textContent = "Searching…";
			for (const p of this.pages) if ((await this.textOf(p)).includes(query)) this.hits.push(p.n);
			this.hitAt = -1;
		}
		if (!this.hits.length) {
			this.found.textContent = "Not found";
			return;
		}
		this.hitAt = (this.hitAt + dir + this.hits.length) % this.hits.length;
		const n = this.hits[this.hitAt]!;
		this.found.textContent = `Page ${n} · ${this.hitAt + 1} of ${this.hits.length} pages`;
		this.goto(n);
		this.mark(query);
	}

	/** Highlight the drawn text runs that hold the query. */
	private mark(q: string, only?: PageView): void {
		const query = q.toLowerCase();
		for (const p of only ? [only] : this.pages) {
			for (const span of p.box.querySelectorAll<HTMLElement>(".textLayer span")) span.classList.toggle("hit", !!query && (span.textContent ?? "").toLowerCase().includes(query));
		}
	}

	/** What a security team should know before trusting this PDF. */
	private async facts(): Promise<Fact[]> {
		const facts: Fact[] = [];
		const { doc } = this;
		const safely = async <T>(f: () => Promise<T>): Promise<T | null> => {
			try {
				return await f();
			} catch {
				return null;
			}
		};
		const js = await safely(() => doc.getJSActions());
		const open = await safely(() => doc.getOpenAction());
		let pageJs = 0;
		const links = new Set<string>();
		let forms = 0;
		for (const p of this.pages.slice(0, 300)) {
			const page = await doc.getPage(p.n);
			const acts = await safely(() => page.getJSActions());
			if (acts && acts.size) pageJs++;
			const annots = (await safely(() => page.getAnnotations())) ?? [];
			for (const a of annots as { subtype?: string; url?: string; unsafeUrl?: string; fieldType?: string; actions?: unknown }[]) {
				if (a.subtype === "Link" && (a.url || a.unsafeUrl)) links.add(String(a.url ?? a.unsafeUrl));
				if (a.subtype === "Widget") forms++;
				if (a.actions) pageJs++;
			}
			page.cleanup();
		}
		if ((js && js.size) || pageJs || (open && (open as Map<string, unknown>).size)) facts.push({ level: "warn", text: "Contains JavaScript or automatic actions — none of it was run" });
		const files = await safely(() => doc.getAttachments());
		if (files && files.size) facts.push({ level: "warn", text: `Embeds ${files.size} file${files.size === 1 ? "" : "s"}: ${[...files.values()].map((f) => (f as { filename?: string }).filename ?? "?").slice(0, 5).join(", ")} — not opened` });
		if (links.size) facts.push({ level: "warn", text: `Links to ${links.size} address${links.size === 1 ? "" : "es"} (not followed): ${[...links].slice(0, 3).join(" · ")}${links.size > 3 ? " · …" : ""}` });
		if (forms) facts.push({ level: "info", text: `Has ${forms} form field${forms === 1 ? "" : "s"}` });
		const meta = await safely(() => doc.getMetadata());
		const info = (meta?.info ?? {}) as Record<string, unknown>;
		const said = ["Title", "Author", "Creator", "Producer"].map((k) => (typeof info[k] === "string" && info[k] ? `${k.toLowerCase()} ${String(info[k]).slice(0, 80)}` : "")).filter(Boolean);
		const created = typeof info.CreationDate === "string" ? pdfjs.PDFDateString.toDateObject(info.CreationDate) : null;
		const changed = typeof info.ModDate === "string" ? pdfjs.PDFDateString.toDateObject(info.ModDate) : null;
		if (created) said.push(`made ${created.toISOString().slice(0, 10)}`);
		if (changed) said.push(`changed ${changed.toISOString().slice(0, 10)}`);
		facts.unshift({ level: "info", text: [`${doc.numPages} page${doc.numPages === 1 ? "" : "s"}`, typeof info.PDFFormatVersion === "string" ? `PDF ${info.PDFFormatVersion}` : "", info.IsEncrypted ? "encrypted" : "", ...said].filter(Boolean).join(" · ") });
		return facts;
	}
}
