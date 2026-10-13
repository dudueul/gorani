// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The media service worker — scope /media/ ONLY (registered with
 * { scope: "/media/" }), so the app's own requests never pass through it:
 * Mailflare documented that a pass-through fetch handler can blank the iOS
 * home-screen app, and gorani wants none of that class of bug.
 *
 * What it does: for a registered media URL it answers the browser's native
 * `<video>` Range requests with DECRYPTED plaintext —
 *
 *   video: src=/media/<id>  ──Range: bytes=a-b──▶
 *     this worker: map [a,b] to GC01 frames ─▶ one ciphertext range fetch
 *     ─▶ decrypt frame by frame (the content key was handed over by the
 *     page as a cloned non-extractable CryptoKey) ─▶ 206, plaintext slice
 *
 * The browser's own player parses the MP4 (it issues the ranges it wants,
 * moov first or last — both work) and seeks natively. No MSE, no box
 * surgery, no DRM: the family's device decrypted it, the server saw only
 * ciphertext.
 *
 * The key lives in this worker's memory only while the page keeps it
 * registered; closing the tab drops it.
 */

import { framesForRange, frameAad, splitFrame, resolveRange } from "/gorani-media-lib.js";

const registrations = new Map(); // pathname → { memberId, fileId, key, chunk, size }

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("message", (event) => {
	const msg = event.data ?? {};
	if (msg.type === "media" && msg.url && msg.key) {
		registrations.set(new URL(msg.url, self.location.origin).pathname, {
			memberId: msg.memberId,
			fileId: msg.fileId,
			key: msg.key, // a CryptoKey (non-extractable) for THIS file's content
			chunk: msg.chunk,
			size: msg.size,
		});
	}
	if (msg.type === "media-forget" && msg.url) {
		registrations.delete(new URL(msg.url, self.location.origin).pathname);
	}
});

const encoder = new TextEncoder();

self.addEventListener("fetch", (event) => {
	const url = new URL(event.request.url);
	const reg = registrations.get(url.pathname);
	if (!reg || event.request.method !== "GET") return; // not ours — fall through
	event.respondWith(serveMedia(event.request, reg));
});

async function serveMedia(request, reg) {
	const rangeHeader = request.headers.get("Range");
	const range = resolveRange(rangeHeader, reg.size);
	const objectPath = `/api/v1/members/${reg.memberId}/files/${reg.fileId}`;

	// A whole-file object (no chunking): decrypt fully, slice in memory
	// (whole objects are < 48 MB by construction — chunking starts above).
	if (!reg.chunk) {
		const res = await fetch(objectPath);
		if (!res.ok) return new Response("not found", { status: 404 });
		const sealed = new Uint8Array(await res.arrayBuffer());
		const plain = new Uint8Array(await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: sealed.subarray(4, 16), additionalData: sealed.subarray(0, 4) },
			reg.key,
			sealed.subarray(16),
		));
		return sliceResponse(plain, range, reg.size);
	}

	// Chunked (GC1): map the plaintext range to frames, fetch their
	// ciphertext with one ranged request, decrypt, serve the slice.
	const range2 = range ?? { start: 0, end: Math.min(reg.size - 1, 1024 * 1024) };
	const { first, last, ciphertextStart, ciphertextEnd } = framesForRange(range2.start, range2.end, reg.chunk, reg.size);
	const res = await fetch(`${objectPath}`, {
		headers: { Range: `bytes=${ciphertextStart}-${ciphertextEnd - 1}` },
	});
	if (!res.ok && res.status !== 206) return new Response("not found", { status: 404 });
	const ciphertext = new Uint8Array(await res.arrayBuffer());
	const frame = reg.chunk + 28;
	const frames = Math.max(1, Math.ceil(reg.size / reg.chunk));
	const outStart = first * reg.chunk;
	const outEnd = Math.min((last + 1) * reg.chunk, reg.size);
	const out = new Uint8Array(outEnd - outStart);
	let writeAt = 0;
	for (let i = first; i <= last; i++) {
		const at = (i - first) * frame;
		const len = Math.min(frame, ciphertext.length - at);
		const { iv, body } = splitFrame(ciphertext, at, len);
		const plain = new Uint8Array(await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv, additionalData: frameAad(i, i === frames - 1, encoder) },
			reg.key,
			body,
		));
		out.set(plain, writeAt);
		writeAt += plain.length;
	}
	// Chunked answers are always 206 with honest Content-Range: the fetched
	// window is a prefix of the range when the browser asked without one.
	const served = { start: outStart, end: outStart + plaintextEnd(out, writeAt) - 1 };
	return new Response(out.subarray(0, writeAt), {
		status: 206,
		headers: {
			"Content-Type": "video/mp4",
			"Accept-Ranges": "bytes",
			"Cache-Control": "no-store",
			"Content-Range": `bytes ${served.start}-${served.end}/${reg.size}`,
			"Content-Length": String(writeAt),
		},
	});
}

function plaintextEnd(out, written) {
	void out;
	return written;
}

/** Serve [start,end] out of a plaintext buffer with honest 206 headers. */
function sliceResponse(plain, range, size, full = false) {
	const start = range ? range.start : 0;
	const end = range ? Math.min(range.end, start + plain.length - 1) : plain.length - 1;
	const body = plain.subarray(start, end + 1);
	const headers = {
		"Content-Type": "video/mp4",
		"Accept-Ranges": "bytes",
		"Cache-Control": "no-store",
	};
	if (range && !full) {
		headers["Content-Range"] = `bytes ${start}-${end}/${size}`;
		headers["Content-Length"] = String(body.length);
		return new Response(body, { status: 206, headers });
	}
	headers["Content-Length"] = String(body.length);
	return new Response(body, { status: 200, headers });
}