// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The app's side of the preview frame (commit 42a, docs/PREVIEWS.md).
 *
 * A file whose format needs a parser — PDF now; Office, email and the rest
 * as they land — is shown in a frame of its own: /preview.html, framed with
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

/** The readers that exist (web/src/preview/readers/<id>.ts). */
export type ReaderId = "pdf";

/** The asset names each reader may ask for — and nothing else is fetched for it. */
const ASSETS: Record<ReaderId, RegExp> = {
	pdf: /^(cmaps\/[A-Za-z0-9_-]+(\.bcmap)?|standard_fonts\/[A-Za-z0-9_-]+\.(pfb|ttf)|wasm\/[a-z0-9_]+(\.wasm|_nowasm_fallback\.js))$/,
};

/** Readers that run a worker of their own (its code is sent with theirs). */
const WORKERS: Partial<Record<ReaderId, true>> = { pdf: true };

/** Is this a name the reader may be sent? (Exported for unit:preview-frame.) */
export function assetPath(reader: ReaderId, path: unknown): string | null {
	if (typeof path !== "string" || path.length > 200 || !ASSETS[reader]?.test(path)) return null;
	return `/readers/${reader}/${path}`;
}

/** A finding the frame reports, as the viewer shows it (text only). */
export interface Fact {
	level: "info" | "warn";
	text: string;
}

export interface PreviewHandlers {
	/** Escape, ← or → pressed inside the frame. */
	onKey(key: "Escape" | "ArrowLeft" | "ArrowRight"): void;
	/** A swipe inside the frame: the next (1) or previous (-1) file. */
	onStep(delta: 1 | -1): void;
	onShown(facts: Fact[]): void;
	onError(message: string): void;
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
export async function openPreview(container: HTMLElement, reader: ReaderId, file: { name: string; mime: string | null; bytes: Uint8Array }, on: PreviewHandlers): Promise<PreviewFrame> {
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
	port.onmessage = (e: MessageEvent) => {
		if (closed) return;
		const d = e.data as { t?: string; id?: unknown; path?: unknown; key?: unknown; delta?: unknown; facts?: unknown; message?: unknown };
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
				on.onShown(Array.isArray(d.facts) ? d.facts.slice(0, 20).map((f: { level?: unknown; text?: unknown }) => ({ level: f?.level === "warn" ? "warn" : "info", text: String(f?.text ?? "").slice(0, 300) })) : []);
				return;
			case "error":
				on.onError(String(d.message ?? "the reader failed").slice(0, 500));
				return;
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
	frame.contentWindow?.postMessage({ t: "open", code: readerJs, worker: workerJs, file: { name: file.name, mime: file.mime, size: bytes.byteLength, bytes }, phone: isPhone() }, "*", [channel.port2, bytes]);
	return { close };
}
