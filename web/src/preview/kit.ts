// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Pieces the document readers share (commit 42b): the zoom buttons, and
 * Find for readers that draw a document as HTML (Word, PowerPoint, the
 * legacy text reader). The PDF and 한글 readers draw on canvases and find
 * by page, on their own.
 *
 * Find marks its matches with the CSS Custom Highlight API: the matches are
 * Ranges painted by the browser, and the document's own DOM is never
 * changed — no <mark> wrapped around a file's text, so nothing about what
 * was found can disturb what is shown.
 */

import { el } from "./host.ts";

export function addCss(...css: string[]): void {
	const style = document.createElement("style");
	style.textContent = css.join("\n");
	document.head.append(style);
}

/** Zoom steps, as a share of the natural size. */
export const ZOOMS = [0.25, 0.33, 0.5, 0.67, 0.8, 1, 1.25, 1.5, 2, 3];

export interface ZoomTarget {
	/** The content's width at 100 %, in CSS pixels. */
	natural(): number;
	/** The width there is to show it in. */
	room(): number;
	/** Show it at this scale. */
	apply(scale: number): void;
}

/** −, the scale, +, and Fit (to the width — no bigger than `maxFit`). */
export class Zoom {
	readonly el: HTMLElement;
	private fit = true;
	private scale = 1;
	private label = el("span", { class: "muted zoomlabel", "data-test": "zoom" });
	private fitBtn = el("button", { title: "Fit the width", "aria-pressed": "true", "data-test": "fit" }, "Fit");

	constructor(private target: ZoomTarget, private maxFit = 1.5) {
		const out = el("button", { title: "Zoom out", "aria-label": "Zoom out" }, "−");
		const inn = el("button", { title: "Zoom in", "aria-label": "Zoom in" }, "+");
		out.addEventListener("click", () => this.step(-1));
		inn.addEventListener("click", () => this.step(1));
		this.fitBtn.addEventListener("click", () => {
			this.fit = true;
			this.update();
		});
		this.el = el("span", { class: "zoom" }, out, this.label, inn, this.fitBtn);
		window.addEventListener("keydown", (e) => {
			if ((e.target as HTMLElement | null)?.closest?.("input, textarea")) return;
			if (e.key === "+" || e.key === "=") this.step(1);
			if (e.key === "-") this.step(-1);
		});
	}

	/** The scale now (fitted, or chosen). */
	now(): number {
		if (!this.fit) return this.scale;
		const natural = this.target.natural();
		return natural > 0 ? Math.min(this.maxFit, Math.max(0.1, (this.target.room() - 16) / natural)) : 1;
	}

	/** Re-apply (after a resize, or once the content is there). */
	update(): void {
		const s = this.now();
		this.target.apply(s);
		this.label.textContent = `${Math.round(s * 100)}%`;
		this.fitBtn.setAttribute("aria-pressed", String(this.fit));
	}

	private step(dir: 1 | -1): void {
		const now = this.now();
		const next = dir > 0 ? ZOOMS.find((z) => z > now + 0.01) : [...ZOOMS].reverse().find((z) => z < now - 0.01);
		if (next === undefined) return;
		this.fit = false;
		this.scale = next;
		this.update();
	}
}

interface HighlightRegistry {
	set(name: string, h: unknown): void;
	delete(name: string): void;
}
const highlights = (globalThis as { CSS?: { highlights?: HighlightRegistry } }).CSS?.highlights;
const HighlightCtor = (globalThis as { Highlight?: new (...r: Range[]) => unknown }).Highlight;

/** The highlight colours (the names are this file's). */
export const findCss = `
::highlight(gorani-find) { background-color: rgb(255 200 0 / 0.45); color: inherit; }
::highlight(gorani-find-now) { background-color: rgb(255 140 0 / 0.9); color: #000; }
`;

/**
 * Find in a document drawn as HTML: Enter for the next match, Shift+Enter
 * for the one before, Ctrl/⌘+F to get here.
 */
export class Finder {
	readonly input: HTMLInputElement;
	readonly found = el("span", { class: "muted", "data-test": "found" });
	private ranges: Range[] = [];
	private at = -1;
	private query = "";

	constructor(private root: () => HTMLElement | null, private scroller: HTMLElement, placeholder: string) {
		this.input = el("input", { type: "search", placeholder, "aria-label": placeholder, "data-test": "find" });
		this.input.addEventListener("keydown", (e) => {
			if (e.key !== "Enter") return;
			e.preventDefault();
			this.next(e.shiftKey ? -1 : 1);
		});
		this.input.addEventListener("input", () => this.clear());
		window.addEventListener("keydown", (e) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
				e.preventDefault();
				this.input.focus();
				this.input.select();
			}
		});
	}

	clear(): void {
		this.ranges = [];
		this.at = -1;
		this.query = "";
		this.found.textContent = "";
		highlights?.delete("gorani-find");
		highlights?.delete("gorani-find-now");
	}

	/** Every match of the query in the text that is SHOWN (hidden text is
	 * not searched: it is not on the page, and the facts name it). */
	private collect(q: string): Range[] {
		const root = this.root();
		if (!root) return [];
		const out: Range[] = [];
		const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
		const needle = q.toLowerCase();
		for (let n = walker.nextNode(); n && out.length < 5000; n = walker.nextNode()) {
			const text = (n.nodeValue ?? "").toLowerCase();
			if (!text.includes(needle)) continue;
			const parent = n.parentElement;
			if (parent && typeof parent.checkVisibility === "function" && !parent.checkVisibility()) continue;
			for (let i = text.indexOf(needle); i >= 0 && out.length < 5000; i = text.indexOf(needle, i + needle.length)) {
				const r = document.createRange();
				r.setStart(n, i);
				r.setEnd(n, i + needle.length);
				out.push(r);
			}
		}
		return out;
	}

	next(dir: 1 | -1): void {
		const q = this.input.value.trim();
		if (!q) return;
		if (q !== this.query) {
			this.query = q;
			this.ranges = this.collect(q);
			this.at = -1;
			if (highlights && HighlightCtor) highlights.set("gorani-find", new HighlightCtor(...this.ranges));
		}
		if (!this.ranges.length) {
			this.found.textContent = "Not found";
			return;
		}
		this.at = (this.at + dir + this.ranges.length) % this.ranges.length;
		const r = this.ranges[this.at]!;
		if (highlights && HighlightCtor) highlights.set("gorani-find-now", new HighlightCtor(r));
		else {
			const sel = getSelection();
			sel?.removeAllRanges();
			sel?.addRange(r);
		}
		this.found.textContent = `${this.at + 1} of ${this.ranges.length}`;
		const box = r.getBoundingClientRect();
		const view = this.scroller.getBoundingClientRect();
		this.scroller.scrollBy({ top: box.top - view.top - view.height / 3, left: box.left < view.left || box.right > view.right ? box.left - view.left - 40 : 0, behavior: "smooth" });
	}
}

/** Run `f` at most once a frame (scroll and resize handlers). */
export function perFrame(f: () => void): () => void {
	let queued = false;
	return () => {
		if (queued) return;
		queued = true;
		requestAnimationFrame(() => {
			queued = false;
			f();
		});
	};
}
