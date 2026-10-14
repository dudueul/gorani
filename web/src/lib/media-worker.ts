// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The page's side of the media service worker (web/public/sw-media.js).
 * One place that knows its URL, its scope and its messages — the shell,
 * the viewer and the files model used to each spell them out.
 *
 * Scope "/" (commit 25, docs/SECURITY-REVIEW.md › O11): a service worker
 * receives the fetches of the pages it CONTROLS, and the app page is "/".
 * Registered at "/media/" it controlled nothing the app ever showed, so the
 * `<video>` element's requests never reached it. The worker itself claims
 * only `/media/` paths and lets everything else through untouched.
 */

export const MEDIA_WORKER_URL = "/sw-media.js";
export const MEDIA_SCOPE = "/";

/** Register (idempotent), and retire the old "/media/"-scoped registration
 * a browser may still hold from before commit 25.
 *
 * `type: "module"`: the worker begins with `import … from
 * "/gorani-media-lib.js"`, and a CLASSIC service worker cannot use import
 * statements — registered without the type, the script failed to evaluate
 * and the worker never installed (the second reason streaming never
 * worked; found by e2e:app's streaming block). A browser without module
 * service workers rejects the registration, and the viewer falls back to a
 * decrypted blob. */
export async function registerMediaWorker(): Promise<void> {
	if (typeof navigator === "undefined" || !navigator.serviceWorker) return;
	const old = await navigator.serviceWorker.getRegistration("/media/");
	if (old && new URL(old.scope).pathname === "/media/") await old.unregister();
	await navigator.serviceWorker.register(MEDIA_WORKER_URL, { scope: MEDIA_SCOPE, type: "module" });
}

/** The active worker, once it CONTROLS this page — or null (no support, or
 * not in control within a few seconds: the caller falls back to a blob). */
export async function controllingMediaWorker(timeoutMs = 5000): Promise<ServiceWorker | null> {
	if (typeof navigator === "undefined" || !navigator.serviceWorker) return null;
	await Promise.race([navigator.serviceWorker.ready, new Promise((r) => setTimeout(r, timeoutMs))]);
	if (navigator.serviceWorker.controller) return navigator.serviceWorker.controller;
	// Activated but not yet claiming this page: `clients.claim()` fires
	// controllerchange — wait for it, briefly.
	await new Promise<void>((resolve) => {
		const t = setTimeout(resolve, timeoutMs);
		navigator.serviceWorker.addEventListener("controllerchange", () => (clearTimeout(t), resolve()), { once: true });
	});
	return navigator.serviceWorker.controller;
}

/** Hand the worker one file's content key and wait for its acknowledgement
 * (so the player's first request cannot race the registration). */
export async function registerMedia(worker: ServiceWorker, msg: { url: string; memberId: string; fileId: string; version: number; key: CryptoKey; chunk: number | null; size: number; mime: string | null; headers?: Record<string, string> }): Promise<void> {
	const channel = new MessageChannel();
	const acked = new Promise<void>((resolve, reject) => {
		const t = setTimeout(() => reject(new Error("the media worker did not answer")), 5000);
		channel.port1.onmessage = () => (clearTimeout(t), resolve());
	});
	worker.postMessage({ type: "media", ...msg }, [channel.port2]);
	await acked;
}

/** Forget one file's key (the viewer closed) or every key (Lock). */
/**
 * A streamed download (D12, 31c): the worker decrypts a chunked file frame
 * window by frame window into the browser's own download, so its size is
 * not bounded by the tab's memory. `done` settles when the last byte has
 * passed, with the plaintext's SHA-256 (or why it stopped).
 */
export async function registerDownload(worker: ServiceWorker, msg: { url: string; memberId: string; fileId: string; version: number; key: CryptoKey; chunk: number; size: number; name: string; headers?: Record<string, string> }): Promise<{ done: Promise<{ ok: boolean; sha256?: string; size?: number; error?: string }> }> {
	const ack = new MessageChannel();
	const result = new MessageChannel();
	const acked = new Promise<void>((resolve, reject) => {
		const t = setTimeout(() => reject(new Error("the media worker did not answer")), 5000);
		ack.port1.onmessage = () => (clearTimeout(t), resolve());
	});
	const done = new Promise<{ ok: boolean; sha256?: string; size?: number; error?: string }>((resolve) => {
		result.port1.onmessage = (e) => resolve(e.data as { ok: boolean; sha256?: string; size?: number; error?: string });
	});
	worker.postMessage({ type: "download", ...msg }, [ack.port2, result.port2]);
	await acked;
	return { done };
}

/**
 * A download this page writes as it goes (31d — the export package): the
 * media worker answers the browser's download with whatever `write` hands
 * it, one chunk per ask. `write` waits for the ask, so the producer runs
 * exactly as fast as the disk takes it. Navigate to `url` (not
 * <a download> — Chromium sends those past the worker) BEFORE writing.
 */
export async function pipeToDownload(worker: ServiceWorker, { url, name, mime = "application/octet-stream" }: { url: string; name: string; mime?: string }): Promise<{ write(bytes: Uint8Array): Promise<void>; close(): Promise<void>; fail(e: unknown): void }> {
	const ack = new MessageChannel();
	const pipe = new MessageChannel();
	const acked = new Promise<void>((resolve, reject) => {
		const t = setTimeout(() => reject(new Error("the media worker did not answer")), 5000);
		ack.port1.onmessage = () => (clearTimeout(t), resolve());
	});
	let asks = 0;
	let cancelled = false;
	let wake: (() => void) | null = null;
	pipe.port1.onmessage = (e) => {
		if (e.data?.cancel) cancelled = true;
		else if (e.data?.pull) asks++;
		const w = wake;
		wake = null;
		w?.();
	};
	const nextAsk = async () => {
		while (asks === 0 && !cancelled) await new Promise<void>((r) => (wake = r));
		if (cancelled) throw new Error("the download was cancelled");
		asks--;
	};
	worker.postMessage({ type: "pipe", url, name, mime }, [ack.port2, pipe.port2]);
	await acked;
	return {
		async write(bytes) {
			await nextAsk();
			const copy = bytes.slice();
			pipe.port1.postMessage({ chunk: copy.buffer }, [copy.buffer]);
		},
		async close() {
			await nextAsk();
			pipe.port1.postMessage({ done: true });
		},
		fail(e) {
			pipe.port1.postMessage({ error: e instanceof Error ? e.message : String(e) });
		},
	};
}

export async function forgetMedia(url?: string): Promise<void> {
	if (typeof navigator === "undefined" || !navigator.serviceWorker) return;
	try {
		const reg = await navigator.serviceWorker.getRegistration(MEDIA_SCOPE);
		reg?.active?.postMessage(url ? { type: "media-forget", url } : { type: "media-forget-all" });
	} catch {
		// no worker registered — nothing to forget
	}
}
