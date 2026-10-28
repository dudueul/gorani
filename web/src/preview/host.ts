// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The reader's side of the preview frame (commit 42a, docs/PREVIEWS.md).
 *
 * Every reader bundle (readers/*.ts, built by scripts/build-readers.mjs into
 * one self-contained file each) runs inside public/preview.html: a frame
 * with an opaque origin and no network. This file is what each of them
 * links in to talk to the app, over the one MessagePort the app handed the
 * frame with the file:
 *
 *   reader → app   asset (a reader's own file: a CMap, a font), key (Escape,
 *                  ←/→), step (a swipe), shown (what the reader found worth
 *                  saying: "contains JavaScript — not run"), error
 *   app → reader   the asset's bytes, or why not
 *
 * Nothing here can widen what the frame may do — the sandbox attribute and
 * the frame's CSP decide that — but it keeps each reader to the same small
 * vocabulary, so the app's side (ui/viewer/sandbox.ts) checks one thing.
 */

import frameCss from "./frame.css?inline";

/** What the app sends with the file. */
export interface OpenMessage {
	t: "open";
	code: string;
	/** A reader's worker, as code (pdf.js parses in a worker of its own). */
	worker?: string;
	file: { name: string; mime: string | null; size: number; bytes: ArrayBuffer };
	/** A phone-narrow window: readers start fitted to the width, panels closed. */
	phone: boolean;
}

/** A finding the viewer shows above the preview (a security fact about the file). */
export interface Fact {
	level: "info" | "warn";
	text: string;
}

export interface Host {
	readonly root: HTMLElement;
	readonly file: OpenMessage["file"];
	readonly phone: boolean;
	/** The reader's own asset (e.g. "cmaps/UniKS-UCS2-H.bcmap"), asked of the app. */
	asset(path: string): Promise<Uint8Array>;
	/** A Worker running the code the app sent, or null when none was sent. */
	worker(): Worker | null;
	/** The preview is up; `facts` are shown by the viewer, outside the frame. */
	shown(facts?: Fact[]): void;
	fail(message: string): void;
	/** Elements whose own horizontal scrolling a swipe must not override. */
	setSwipeGuard(guard: (target: EventTarget | null) => boolean): void;
}

/** Trusted Types in the frame (its CSP requires them): our only policy turns
 * the blob: URLs this file makes into script URLs — for the reader's worker —
 * and nothing else. A reader that renders HTML sanitises it first and uses
 * DOMPurify's own policy (allowed by name in the CSP). */
const policy = (globalThis as { trustedTypes?: { createPolicy(name: string, rules: { createScriptURL(u: string): string }): { createScriptURL(u: string): unknown } } }).trustedTypes?.createPolicy("gorani-preview", {
	createScriptURL: (u: string) => {
		if (!u.startsWith("blob:")) throw new TypeError("the preview frame runs only code it was handed");
		return u;
	},
});

/**
 * Wrap a reader: the bootstrap in preview.html calls the returned `start`
 * with the open message and the port.
 */
export function boot(run: (host: Host) => Promise<void>): (msg: OpenMessage, port: MessagePort) => Promise<void> {
	return async (msg, port) => {
		const style = document.createElement("style");
		style.textContent = frameCss;
		document.head.append(style);
		const root = document.getElementById("root") ?? document.body;
		document.documentElement.classList.toggle("phone", msg.phone);

		let next = 1;
		const waiting = new Map<number, { ok(b: Uint8Array): void; no(e: Error): void }>();
		port.onmessage = (e: MessageEvent) => {
			const d = e.data as { t?: string; id?: number; bytes?: ArrayBuffer; error?: string };
			if (d?.t !== "asset" || typeof d.id !== "number") return;
			const w = waiting.get(d.id);
			waiting.delete(d.id);
			if (!w) return;
			if (d.bytes) w.ok(new Uint8Array(d.bytes));
			else w.no(new Error(d.error ?? "the app did not send it"));
		};

		let worker: Worker | null | undefined;
		let guard: (target: EventTarget | null) => boolean = () => false;
		const host: Host = {
			root,
			file: msg.file,
			phone: msg.phone,
			asset(path) {
				const id = next++;
				return new Promise((ok, no) => {
					waiting.set(id, { ok, no });
					port.postMessage({ t: "asset", id, path });
				});
			},
			worker() {
				if (worker !== undefined) return worker;
				if (!msg.worker) return (worker = null);
				const url = URL.createObjectURL(new Blob([msg.worker], { type: "text/javascript" }));
				// Classic, not a module: an opaque-origin frame cannot start a
				// module worker from a blob: URL (scripts/build-readers.mjs
				// bundles the worker as an IIFE for that reason).
				worker = new Worker((policy ? policy.createScriptURL(url) : url) as string);
				return worker;
			},
			shown(facts = []) {
				port.postMessage({ t: "shown", facts: facts.slice(0, 20).map((f) => ({ level: f.level === "warn" ? "warn" : "info", text: String(f.text).slice(0, 300) })) });
			},
			fail(message) {
				port.postMessage({ t: "error", message: String(message).slice(0, 500) });
			},
			setSwipeGuard(g) {
				guard = g;
			},
		};

		// Keys the viewer owns — Escape closes, ← → move to the next file —
		// go out to it: a focused frame keeps every key to itself otherwise.
		// (Not from a field: there they edit the field.)
		window.addEventListener("keydown", (e) => {
			const t = e.target as HTMLElement | null;
			if (t?.closest?.("input, textarea, select, [contenteditable]")) {
				if (e.key === "Escape") (t as HTMLElement).blur();
				return;
			}
			if (e.key === "Escape" || ((e.key === "ArrowLeft" || e.key === "ArrowRight") && !e.altKey && !e.ctrlKey && !e.metaKey)) {
				e.preventDefault();
				port.postMessage({ t: "key", key: e.key });
			}
		});

		// A sideways swipe moves to the next file, as in the viewer itself —
		// unless the finger started on something that scrolls sideways (a
		// zoomed page), there were two fingers (a pinch), or the page is
		// zoomed in (panning).
		let touch: { x: number; y: number; skip: boolean } | null = null;
		window.addEventListener(
			"touchstart",
			(e) => {
				const t = e.touches[0];
				touch = t ? { x: t.clientX, y: t.clientY, skip: e.touches.length > 1 || guard(e.target) || (globalThis.visualViewport?.scale ?? 1) > 1.01 } : null;
			},
			{ passive: true },
		);
		window.addEventListener(
			"touchend",
			(e) => {
				const start = touch;
				touch = null;
				const t = e.changedTouches[0];
				if (!start || start.skip || !t) return;
				const dx = t.clientX - start.x;
				const dy = t.clientY - start.y;
				if (Math.abs(dx) >= 60 && Math.abs(dy) <= Math.abs(dx) * 0.6) port.postMessage({ t: "step", delta: dx < 0 ? 1 : -1 });
			},
			{ passive: true },
		);

		try {
			await run(host);
		} catch (e) {
			host.fail(e instanceof Error ? e.message : String(e));
		}
	};
}

/** An element, built without any HTML string (there is no HTML sink here). */
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
	const e = document.createElement(tag);
	for (const [k, v] of Object.entries(attrs)) {
		if (k === "class") e.className = v;
		else e.setAttribute(k, v);
	}
	for (const c of children) e.append(c);
	return e;
}
