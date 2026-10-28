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

import DOMPurify from "dompurify";
import frameCss from "./frame.css?inline";

/** What DOMPurify keeps of an HTML string a library writes (see the default
 * policy below): text, formatting and pictures — no forms, no <style> (a
 * slide's text must not restyle the reader around it), no <meta>/<link>/
 * <base>, no data-* attributes. Scripts and event handlers it removes
 * always; the frame's CSP would refuse them anyway. */
const SANITIZE = {
	FORBID_TAGS: ["style", "form", "input", "button", "textarea", "select", "meta", "link", "base", "iframe", "frame", "object", "embed"],
	ALLOW_DATA_ATTR: false,
};

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

/** At most this many facts are sent (an email's can run long — 42c). */
export const MAX_FACTS = 40;

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
	/** Elements whose own horizontal scrolling a swipe must not override
	 * (by default: anything scrolled sideways). */
	setSwipeGuard(guard: (target: EventTarget | null) => boolean): void;
	/**
	 * Hand a file found INSIDE this one (an email's attachment, 42c) to the
	 * app: "open" it in a preview of its own, or "save" it into the vault.
	 * A request, nothing more — the app opens it in a new frame, and asks
	 * the person before it saves anything. A copy of the bytes goes.
	 */
	handOver(action: "open" | "save", file: { name: string; mime: string | null; bytes: Uint8Array }): void;
}

interface TrustedTypesLike {
	createPolicy(name: string, rules: { createHTML?(s: string, type: string, sink: string): string; createScript?(s: string): string | null; createScriptURL?(u: string): string | null }): { createScriptURL(u: string): unknown };
}
const tt = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes;

/** Trusted Types in the frame (its CSP requires them). Three policies, each
 * named in the frame's CSP, and no other can be made:
 *
 *   gorani-preview  ours: turns the blob: URLs this file makes into script
 *                   URLs — for a reader's worker — and nothing else;
 *   dompurify       DOMPurify's own, which it uses to hand back what it
 *                   cleaned;
 *   default         what the browser calls when a library writes a plain
 *                   STRING into an HTML sink — the readers' libraries do:
 *                   pptx-preview sets each run of slide text with
 *                   innerHTML (42b). Every such string goes through
 *                   DOMPurify first, so a slide whose text is
 *                   `<img src=x onerror=…>` draws nothing that runs. One
 *                   sink is let through untouched: DOMParser, which
 *                   docx-preview uses to read the file's XML — a parsed
 *                   document is inert (nothing in it loads or runs), and
 *                   DOMPurify would strip the XML it does not know.
 *                   Strings as code (eval, setTimeout("…"), javascript:
 *                   URLs) and script URLs are refused outright.
 */
const policy = tt?.createPolicy("gorani-preview", {
	createScriptURL: (u: string) => {
		if (!u.startsWith("blob:")) throw new TypeError("the preview frame runs only code it was handed");
		return u;
	},
});
tt?.createPolicy("default", {
	createHTML: (s, _type, sink) => (sink === "DOMParser parseFromString" ? s : DOMPurify.sanitize(s, SANITIZE)),
	createScript: () => null,
	createScriptURL: () => null,
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
		let guard: (target: EventTarget | null) => boolean = scrollsSideways;
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
				// The first fact is the file's summary; then every warning, then
				// the rest — so what matters most survives the cap.
				const [first, ...rest] = facts.filter((f) => f.text);
				const ordered = first ? [first, ...rest.filter((f) => f.level === "warn"), ...rest.filter((f) => f.level !== "warn")] : [];
				port.postMessage({ t: "shown", facts: ordered.slice(0, MAX_FACTS).map((f) => ({ level: f.level === "warn" ? "warn" : "info", text: String(f.text).slice(0, 300) })) });
			},
			fail(message) {
				port.postMessage({ t: "error", message: String(message).slice(0, 500) });
			},
			setSwipeGuard(g) {
				guard = g;
			},
			handOver(action, file) {
				const copy = file.bytes.slice().buffer as ArrayBuffer;
				port.postMessage({ t: "handover", action, name: String(file.name).slice(0, 255), mime: file.mime ? String(file.mime).slice(0, 127) : null, bytes: copy }, [copy]);
			},
		};

		// Links in a file are evidence, not a way out: a click on one does
		// nothing (a jump within the document — href="#…" — still works).
		// The frame could not go anywhere anyway (sandbox, CSP, the app's
		// frame-src); this keeps it from even trying. The readers list a
		// file's links among its facts.
		// (composedPath: a link inside a shadow root — an email's body, 42c —
		// reaches this listener retargeted to the root's host.)
		const inert = (e: MouseEvent) => {
			const a = e.composedPath().find((n): n is Element => n instanceof Element && n.matches("a[href], area[href]"));
			if (a && !(a.getAttribute("href") ?? "").startsWith("#")) e.preventDefault();
		};
		document.addEventListener("click", inert, true);
		document.addEventListener("auxclick", inert, true);

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

/** The default swipe guard: a finger that starts on something scrolled
 * sideways — a wide sheet, a zoomed page — is panning it, not asking for
 * the next file. */
function scrollsSideways(target: EventTarget | null): boolean {
	for (let e = target instanceof Element ? target : null; e && e !== document.documentElement; e = e.parentElement) {
		if (e.scrollWidth > e.clientWidth + 2 && /(auto|scroll)/.test(getComputedStyle(e).overflowX)) return true;
	}
	return false;
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
