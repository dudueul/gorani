// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The app's side of the preview frame (commit 42a, docs/PREVIEWS.md).
 *
 * A file whose format needs a parser — PDF, Office, 한글; email and the
 * rest as they land — is shown in a frame of its own: /preview.html, framed with
 * sandbox="allow-scripts" and nothing else. That gives it an OPAQUE origin:
 *
 *   - no cookies, no localStorage or IndexedDB, no service worker of ours —
 *     nothing of the vault's;
 *   - no network: its CSP allows only blob: and data: for every kind of
 *     request, and this app's own CSP (frame-src 'self') stops it from
 *     navigating itself to anywhere else to carry something out;
 *   - no windows, no forms, no downloads, no top-level navigation (none of
 *     those sandbox flags are given).
 *
 * The frame is fresh for every file and thrown away with it, so a file
 * that exploits a reader holds, at most, itself.
 *
 * The protocol, over one MessagePort handed over with the file:
 *   app → frame   {t:"open", code, worker?, file:{name, mime, size, bytes}, phone}
 *                 (window.postMessage, once, with the port and the bytes
 *                 transferred), then answers to asset requests
 *   frame → app   ready (window), asset, key, step, shown, error (port)
 *
 * Everything the frame says is treated as data: an asset request is
 * answered only for names a reader is known to need (ASSETS), a key only
 * from a short list, a fact's text is shown as text.
 */

import { isPhone } from "../../lib/phone.ts";
import { MAX_INLINE } from "./mode.ts";

/** The readers that exist (web/src/preview/readers/<id>.ts):
 *   pdf     PDF (pdf.js)                                         42a
 *   docx    Word 2007+ (docx-preview)                            42b
 *   sheet   Excel, OpenDocument sheets, CSV (SheetJS, in a worker)
 *   pptx    PowerPoint 2007+ (pptx-preview)
 *   hwp     한글 HWP and HWPX (rhwp, WebAssembly)
 *   legacy  Word and PowerPoint 97–2003, RTF, OpenDocument text and
 *           slides: their text and their facts, read by our own code
 *   email   .eml (postal-mime) and Outlook .msg (msgreader)          42c
 *   image   every picture: the browser's own decoders, in the frame;
 *           TIFF (UTIF) and HEIF (libheif) in a worker; a RAW file's
 *           own JPEG preview; metadata (exifr)                        42d
 *   archive ZIP, ALZ, EGG (our own readers) and every other archive 7-Zip
 *           reads (WebAssembly, in a worker): listed, entries opened in
 *           previews of their own or saved                           42e
 *   text    Markdown (rendered, cleaned), JSON and XML (trees), web
 *           pages (as source), code (highlight.js); secrets and what a
 *           script would do, as facts. Plain text and logs stay in the
 *           app's page, escaped: they need no parser                 42f */
export type ReaderId = "pdf" | "docx" | "sheet" | "pptx" | "hwp" | "legacy" | "email" | "image" | "archive" | "text";

/** The asset names each reader may ask for — and nothing else is fetched for it. */
const ASSETS: Record<ReaderId, RegExp | null> = {
	pdf: /^(cmaps\/[A-Za-z0-9_-]+(\.bcmap)?|standard_fonts\/[A-Za-z0-9_-]+\.(pfb|ttf)|wasm\/[a-z0-9_]+(\.wasm|_nowasm_fallback\.js))$/,
	docx: null,
	sheet: null,
	pptx: null,
	// rhwp's parser and renderer, 12 MB of WebAssembly.
	hwp: /^rhwp_bg\.wasm$/,
	legacy: null,
	email: null,
	// libheif (LGPL-3.0): its script and its WebAssembly, asked for only
	// when a HEIF is opened.
	image: /^libheif\.(js|wasm)$/,
	// 7-Zip (LGPL + unRAR restriction): its script and WebAssembly, asked
	// for only when an archive is not one our own readers take.
	archive: /^7zz\.(js|wasm)$/,
	text: null,
};

/** Readers that run a worker of their own (its code is sent with theirs). */
const WORKERS: Partial<Record<ReaderId, true>> = { pdf: true, sheet: true, image: true, archive: true };

/** Is this a name the reader may be sent? (Exported for unit:preview-frame.) */
export function assetPath(reader: ReaderId, path: unknown): string | null {
	if (typeof path !== "string" || path.length > 200 || !ASSETS[reader]?.test(path)) return null;
	return `/readers/${reader}/${path}`;
}

/** A finding the frame reports, as the viewer shows it (text only). */
export interface Fact {
	level: "info" | "warn";
	text: string;
	/** Words of `text` the viewer offers to copy (a photo's coordinates). */
	copy?: string;
}

/** A fact from the frame, as the viewer will show it: text only, capped;
 * a `copy` kept only if it is words the fact shows (the frame cannot put
 * on the clipboard anything the person did not see). Pure: unit:preview-frame. */
export function cleanFact(f: unknown): Fact {
	const o = (f ?? {}) as { level?: unknown; text?: unknown; copy?: unknown };
	const text = String(o.text ?? "").slice(0, 300);
	const out: Fact = { level: o.level === "warn" ? "warn" : "info", text: visibleControls(text) };
	if (typeof o.copy === "string" && o.copy.trim() && o.copy.length <= 100 && text.includes(o.copy)) out.copy = o.copy;
	return out;
}

export interface PreviewHandlers {
	/** Escape, ← or → pressed inside the frame. */
	onKey(key: "Escape" | "ArrowLeft" | "ArrowRight"): void;
	/** A swipe inside the frame: the next (1) or previous (-1) file. */
	onStep(delta: 1 | -1): void;
	onShown(facts: Fact[]): void;
	onError(message: string): void;
	/** A file inside this one (an email's attachment, 42c) that the reader
	 * asks to have opened in a preview of its own, or saved into the vault.
	 * Its name is cleaned and its size capped here; it is still the file's
	 * own bytes, as untrusted as the file. */
	onHandover?(action: "open" | "save", file: HandedFile): void;
}

export interface HandedFile {
	name: string;
	mime: string | null;
	bytes: Uint8Array;
	/** It came out of an archive opened with "infected" (42e): a malware
	 * sample — never opened, saved only as a sample. (A reader can only
	 * make a file MORE restricted this way, never less.) */
	sample?: boolean;
}

/**
 * A name a reader handed over, made safe to show and to store: no control
 * or direction-changing characters (an attachment named
 * "invoice\u202Efdp.exe" would show as "invoiceexe.pdf" — the facts
 * already name the trick), no path, at most 200 characters.
 * Pure: unit:preview-frame.
 */
export function cleanName(name: unknown): string {
	const s = String(name ?? "")
		.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "")
		.split(/[\\/]/)
		.pop()!
		.replace(/^[.\s]+|[.\s]+$/g, "")
		.slice(0, 200)
		.trim();
	return s || "attachment";
}

/** Text that cannot reorder the line it is shown in: direction-changing
 * characters (a file named "invoice\u202Efdp.exe" — RLO) are shown as
 * [RLO], not obeyed. Pure: unit:preview-frame. */
export function visibleControls(s: string): string {
	const tag: Record<string, string> = { "\u202a": "[LRE]", "\u202b": "[RLE]", "\u202c": "[PDF]", "\u202d": "[LRO]", "\u202e": "[RLO]", "\u2066": "[LRI]", "\u2067": "[RLI]", "\u2068": "[FSI]", "\u2069": "[PDI]", "\u200e": "[LRM]", "\u200f": "[RLM]" };
	return s.replace(/[\u202a-\u202e\u2066-\u2069\u200e\u200f]/g, (c) => tag[c] ?? "");
}

/** A reader's code, fetched once per page load (it is the app's own code, not secret). */
const code = new Map<string, Promise<string>>();
function readerCode(file: string): Promise<string> {
	let c = code.get(file);
	if (!c) {
		c = fetch(`/readers/${file}`, { cache: "no-cache" }).then(async (r) => {
			if (!r.ok) throw new Error(`the ${file} reader is not on the server (HTTP ${r.status}) — rebuild the web app`);
			return r.text();
		});
		code.set(file, c);
		c.catch(() => code.delete(file));
	}
	return c;
}

/** Assets, fetched once each and kept for the page's life (CMaps are shared by many PDFs). */
const assets = new Map<string, Promise<ArrayBuffer>>();
function asset(url: string): Promise<ArrayBuffer> {
	let a = assets.get(url);
	if (!a) {
		a = fetch(url).then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(new Error(`HTTP ${r.status}`))));
		assets.set(url, a);
		a.catch(() => assets.delete(url));
	}
	return a;
}

export interface PreviewFrame {
	/** Remove the frame: its document, the reader and the bytes go with it. */
	close(): void;
}

/**
 * Show `file` with `reader` in a new sandboxed frame inside `container`.
 * Resolves once the frame has the file (the reader then draws on its own).
 */
export async function openPreview(container: HTMLElement, reader: ReaderId, file: { name: string; mime: string | null; bytes: Uint8Array }, on: PreviewHandlers, opts: { compact?: boolean } = {}): Promise<PreviewFrame> {
	const frame = document.createElement("iframe");
	frame.src = "/preview.html";
	// allow-scripts and NOTHING else — above all not allow-same-origin, which
	// would hand the frame this app's origin and everything stored under it.
	frame.setAttribute("sandbox", "allow-scripts");
	frame.setAttribute("referrerpolicy", "no-referrer");
	frame.setAttribute("allow", "");
	frame.setAttribute("data-preview", reader);
	frame.title = `Preview of ${file.name}`;
	frame.className = "block h-full w-full border-0 bg-neutral-950";
	// A small preview (Quick Look, a details pane — 42d) is a picture to
	// look at, not to use: clicks go to the app around it, and the frame
	// never takes the keyboard.
	if (opts.compact) {
		frame.style.pointerEvents = "none";
		frame.tabIndex = -1;
		frame.classList.replace("bg-neutral-950", "bg-transparent");
	}
	let closed = false;
	let port: MessagePort | null = null;
	const close = () => {
		if (closed) return;
		closed = true;
		port?.close();
		removeEventListener("message", onWindowMessage);
		frame.remove();
	};

	// The frame loads once. A second load means it navigated (to a page of
	// this site — the CSP allows no other): whatever it is now, it is not
	// the reader we opened, and it is removed.
	let loads = 0;
	frame.addEventListener("load", () => {
		if (++loads > 1) {
			close();
			on.onError("The preview tried to leave its frame and was closed");
		}
	});

	let ready!: () => void;
	const isReady = new Promise<void>((ok) => (ready = ok));
	const onWindowMessage = (e: MessageEvent) => {
		if (e.source === frame.contentWindow && (e.data as { t?: string })?.t === "ready") ready();
	};
	addEventListener("message", onWindowMessage);
	container.replaceChildren(frame);

	const [readerJs, workerJs] = await Promise.all([readerCode(`${reader}.js`), WORKERS[reader] ? readerCode(`${reader}.worker.js`) : Promise.resolve(undefined)]);
	await Promise.race([isReady, new Promise((_, no) => setTimeout(() => no(new Error("the preview frame did not start")), 15_000))]);
	if (closed) return { close };

	const channel = new MessageChannel();
	port = channel.port1;
	let lastHandover = 0;
	port.onmessage = (e: MessageEvent) => {
		if (closed) return;
		const d = e.data as { t?: string; id?: unknown; path?: unknown; key?: unknown; delta?: unknown; facts?: unknown; message?: unknown; action?: unknown; name?: unknown; mime?: unknown; bytes?: unknown };
		switch (d?.t) {
			case "asset": {
				const url = assetPath(reader, d.path);
				const id = typeof d.id === "number" ? d.id : -1;
				if (!url) {
					port?.postMessage({ t: "asset", id, error: "not an asset this reader has" });
					return;
				}
				asset(url).then(
					(buf) => {
						const copy = buf.slice(0);
						port?.postMessage({ t: "asset", id, bytes: copy }, [copy]);
					},
					(err: unknown) => port?.postMessage({ t: "asset", id, error: String(err instanceof Error ? err.message : err) }),
				);
				return;
			}
			case "key":
				if (d.key === "Escape" || d.key === "ArrowLeft" || d.key === "ArrowRight") on.onKey(d.key);
				return;
			case "step":
				if (d.delta === 1 || d.delta === -1) on.onStep(d.delta);
				return;
			case "shown":
				on.onShown(Array.isArray(d.facts) ? d.facts.slice(0, 40).map(cleanFact) : []);
				return;
			case "error":
				on.onError(String(d.message ?? "the reader failed").slice(0, 500));
				return;
			case "handover": {
				// A request, checked: a known action, real bytes under the cap,
				// and not more than one every half second (a reader gone wrong
				// cannot flood the app with "open this").
				if ((d.action !== "open" && d.action !== "save") || !(d.bytes instanceof ArrayBuffer) || d.bytes.byteLength > MAX_INLINE || !on.onHandover) return;
				const now = Date.now();
				if (now - lastHandover < 500) return;
				lastHandover = now;
				const mime = typeof d.mime === "string" && /^[\w.+-]+\/[\w.+-]+$/.test(d.mime) ? d.mime.toLowerCase().slice(0, 127) : null;
				on.onHandover(d.action, { name: cleanName(d.name), mime, bytes: new Uint8Array(d.bytes), sample: (d as { sample?: unknown }).sample === true });
				return;
			}
		}
	};
	// The bytes are TRANSFERRED, not copied: after this the app holds no
	// second plaintext copy of the file, and the frame's goes when it does.
	const bytes = file.bytes.byteOffset === 0 && file.bytes.byteLength === file.bytes.buffer.byteLength ? (file.bytes.buffer as ArrayBuffer) : file.bytes.slice().buffer;
	// Target "*": an opaque origin cannot be named as one ("null" is not a
	// target). What makes it safe is WHICH window gets it — the one that
	// just said ready, still running only our hash-pinned bootstrap (no
	// reader code has been sent yet), unable to navigate off this site
	// (frame-src 'self') and closed if it navigates at all (the load count).
	frame.contentWindow?.postMessage({ t: "open", code: readerJs, worker: workerJs, file: { name: file.name, mime: file.mime, size: bytes.byteLength, bytes }, phone: isPhone(), compact: opts.compact === true }, "*", [channel.port2, bytes]);
	return { close };
}
