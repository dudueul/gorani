// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The media service worker: it answers the browser's native `<video>` /
 * `<audio>` Range requests for `/media/<id>` with DECRYPTED plaintext —
 *
 *   video: src=/media/<id>  ──Range: bytes=a-b──▶
 *     this worker: map [a,b] to GC01 frames ─▶ one ciphertext range fetch
 *     ─▶ decrypt frame by frame (the content key was handed over by the
 *     page as a cloned non-extractable CryptoKey) ─▶ 206, exactly bytes a..b
 *
 * The browser's own player parses the container and seeks natively. No
 * MSE, no box surgery, no DRM: the family's device decrypted it, the server
 * saw only ciphertext.
 *
 * # Scope "/" — and why that is not a pass-through (commit 25, O11)
 *
 * It used to be registered with scope "/media/". A service worker receives
 * the fetches of the PAGES it controls, and the app page lives at "/" —
 * outside "/media/" — so the `<video>` element's requests never reached
 * this worker at all: streaming had never worked, and every large video
 * hit the network for a path the Worker does not serve. Now the scope is
 * "/" (the page is controlled) and the fetch handler claims ONLY
 * `/media/` paths; for everything else it returns without `respondWith`,
 * so the browser handles the request exactly as if no worker existed.
 * (Mailflare's warning stands: a handler that `respondWith(fetch(req))`s
 * every request can blank an iOS home-screen app. This one never does.)
 *
 * The keys live in this worker's memory until the page forgets them: the
 * viewer sends `media-forget` when it closes, and LOCKING sends
 * `media-forget-all` (web/src/ui/shell.ts). Before commit 24 nothing ever
 * sent either.
 */

import { framesForRange, frameAad, splitFrame, resolveRange, cutToRange, OPEN_RANGE_WINDOW } from "/gorani-media-lib.js";

const registrations = new Map(); // pathname → { memberId, fileId, version, key, chunk, size, type }

self.addEventListener("install", () => self.skipWaiting());
// Claim the open app page right away: a page loaded before the worker
// existed is otherwise uncontrolled until its next navigation.
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("message", (event) => {
	const msg = event.data ?? {};
	if (msg.type === "media" && msg.url && msg.key) {
		registrations.set(new URL(msg.url, self.location.origin).pathname, {
			memberId: msg.memberId,
			fileId: msg.fileId,
			version: msg.version, // the version the key was opened for — fetch exactly that one
			key: msg.key, // a CryptoKey (non-extractable) for THIS version's content
			chunk: msg.chunk,
			size: msg.size,
			type: msg.mime || "application/octet-stream",
			// The dev server's identity header (the page's localStorage is out
			// of reach here); `{}` in production, where the Access cookie rides.
			headers: msg.headers && typeof msg.headers === "object" ? msg.headers : {},
		});
		event.ports?.[0]?.postMessage({ ok: true }); // the page may wait for this
	}
	if (msg.type === "media-forget" && msg.url) {
		registrations.delete(new URL(msg.url, self.location.origin).pathname);
	}
	if (msg.type === "media-forget-all") registrations.clear();
});

const encoder = new TextEncoder();

self.addEventListener("fetch", (event) => {
	const url = new URL(event.request.url);
	// Not ours: return WITHOUT respondWith — the browser proceeds natively.
	if (url.origin !== self.location.origin || !url.pathname.startsWith("/media/")) return;
	const reg = registrations.get(url.pathname);
	// A /media/ path with no key registered (locked, forgotten, never opened)
	// is a 404 — not a fall-through, which would fetch the app's HTML.
	if (!reg || event.request.method !== "GET") {
		event.respondWith(new Response("not available", { status: 404, headers: { "Cache-Control": "no-store" } }));
		return;
	}
	event.respondWith(serveMedia(event.request, reg).catch(() => new Response("cannot open", { status: 502, headers: { "Cache-Control": "no-store" } })));
});

async function serveMedia(request, reg) {
	const asked = resolveRange(request.headers.get("Range"), reg.size);
	// The key was opened for ONE version; the bytes must be that version's.
	const objectPath = `/api/v1/members/${reg.memberId}/files/${reg.fileId}?version=${reg.version}`;
	const headers = { "Content-Type": reg.type, "Accept-Ranges": "bytes", "Cache-Control": "no-store" };

	// A whole-file object (GV02, no chunking): decrypt fully, cut the range.
	// (Whole objects are < 48 MB by construction — chunking starts above.)
	if (!reg.chunk) {
		const res = await fetch(objectPath, { headers: reg.headers });
		if (!res.ok) return new Response("not found", { status: 404 });
		const sealed = new Uint8Array(await res.arrayBuffer());
		// GV02's AAD is the whole 16-byte header — "GV02" ‖ nonce. This used
		// `sealed.subarray(0, 4)` (the magic alone), so no whole-file media
		// could EVER decrypt here (O11).
		const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.subarray(4, 16), additionalData: sealed.subarray(0, 16) }, reg.key, sealed.subarray(16)));
		if (plain.length !== reg.size) return new Response("size mismatch", { status: 502 });
		if (!asked) return new Response(plain, { status: 200, headers: { ...headers, "Content-Length": String(plain.length) } });
		const body = cutToRange(plain, 0, asked.start, asked.end);
		return new Response(body, { status: 206, headers: { ...headers, "Content-Range": `bytes ${asked.start}-${asked.start + body.length - 1}/${reg.size}`, "Content-Length": String(body.length) } });
	}

	// Chunked (GC01): map the plaintext range to frames, fetch their
	// ciphertext with one ranged request, decrypt, cut exactly the range.
	// (No Range header — media elements always send one — is served as an
	// open-ended range from 0, honestly labelled 206.)
	const range = asked ?? { start: 0, end: Math.min(reg.size - 1, OPEN_RANGE_WINDOW) };
	const { first, last, ciphertextStart, ciphertextEnd } = framesForRange(range.start, range.end, reg.chunk, reg.size);
	const res = await fetch(objectPath, { headers: { ...reg.headers, Range: `bytes=${ciphertextStart}-${ciphertextEnd - 1}` } });
	if (!res.ok && res.status !== 206) return new Response("not found", { status: 404 });
	const ciphertext = new Uint8Array(await res.arrayBuffer());
	const frame = reg.chunk + 28;
	const frames = Math.max(1, Math.ceil(reg.size / reg.chunk));
	const plainFrames = new Uint8Array(Math.min((last + 1) * reg.chunk, reg.size) - first * reg.chunk);
	let writeAt = 0;
	for (let i = first; i <= last; i++) {
		const at = (i - first) * frame;
		const { iv, body } = splitFrame(ciphertext, at, Math.min(frame, ciphertext.length - at));
		const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: frameAad(i, i === frames - 1, encoder) }, reg.key, body));
		plainFrames.set(plain, writeAt);
		writeAt += plain.length;
	}
	const body = cutToRange(plainFrames.subarray(0, writeAt), first * reg.chunk, range.start, range.end);
	return new Response(body, {
		status: 206,
		headers: { ...headers, "Content-Range": `bytes ${range.start}-${range.start + body.length - 1}/${reg.size}`, "Content-Length": String(body.length) },
	});
}
