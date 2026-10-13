// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

/**
 * Chunked files (GC01, docs/ENCRYPTION.md): a file too large for one request
 * is sealed here, in the browser, in chunks of `chunk` bytes, each its own
 * AES-256-GCM frame under the file version's content key, and uploaded one
 * frame per multipart part. Each frame binds its position and whether it is
 * the last (AAD), so frames cannot be reordered, dropped, repeated or the
 * file cut short without opening failing.
 *
 *   object = frame 0 ‖ frame 1 ‖ … ‖ frame n−1   (every frame but the last exactly chunk + 28 bytes)
 *   frame i = nonce (12, random) ‖ AES-256-GCM(content key, chunk i, AAD) ‖ tag (16)
 *   AAD     = "GC01" ‖ i (8 bytes, big-endian) ‖ final (1 byte: 1 for the last frame, else 0)
 *
 * An empty file is one empty final frame. The Rust twin lives in
 * crates/formats/src/chunked.rs; the vectors keep them byte-identical.
 */

import { sealWith, openWith } from "./vault-crypto.ts";

const MAGIC = new TextEncoder().encode("GC01");
export const FRAME_OVERHEAD = 28;
/** Plain bytes per frame (and per uploaded part, which S3 wants at least 5 MiB and uniform). */
export const DEFAULT_CHUNK = 8 * 1024 * 1024;

export const frameCount = (size: number, chunk: number) => Math.max(1, Math.ceil(size / chunk));
/** The stored object's size for a plain size. */
export const sealedSize = (size: number, chunk: number) => size + frameCount(size, chunk) * FRAME_OVERHEAD;

function aad(i: number, final: boolean): Uint8Array {
	const a = new Uint8Array(MAGIC.length + 9);
	a.set(MAGIC);
	new DataView(a.buffer).setBigUint64(MAGIC.length, BigInt(i));
	a[MAGIC.length + 8] = final ? 1 : 0;
	return a;
}

export async function sealChunk(key: CryptoKey, plain: Uint8Array, i: number, final: boolean): Promise<Uint8Array> {
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad(i, final) as BufferSource }, key, plain as BufferSource));
	const out = new Uint8Array(12 + ct.length);
	out.set(nonce);
	out.set(ct, 12);
	return out;
}

export async function openChunk(key: CryptoKey, frame: Uint8Array, i: number, final: boolean): Promise<Uint8Array> {
	if (frame.length < FRAME_OVERHEAD) throw new Error("A chunk is too short");
	try {
		return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: frame.subarray(0, 12) as BufferSource, additionalData: aad(i, final) as BufferSource }, key, frame.subarray(12) as BufferSource));
	} catch {
		throw new Error(`Cannot open chunk ${i + 1}: wrong key, or the file was altered, reordered or cut short`);
	}
}

/** Seal a whole file into GC01 frames (the uploader reads one slice at a time). */
export async function sealChunked(key: CryptoKey, plain: Uint8Array, chunk: number): Promise<Uint8Array> {
	const n = frameCount(plain.length, chunk);
	const frames: Uint8Array[] = [];
	for (let i = 0; i < n; i++) {
		frames.push(await sealChunk(key, plain.subarray(i * chunk, Math.min(plain.length, (i + 1) * chunk)), i, i === n - 1));
	}
	const out = new Uint8Array(frames.reduce((s, f) => s + f.length, 0));
	let at = 0;
	for (const f of frames) {
		out.set(f, at);
		at += f.length;
	}
	return out;
}

/** A whole chunked object, opened. */
export async function openChunked(key: CryptoKey, sealed: Uint8Array, chunk: number): Promise<Uint8Array> {
	const frame = chunk + FRAME_OVERHEAD;
	const n = Math.max(1, Math.ceil(sealed.length / frame));
	const parts: Uint8Array[] = [];
	let total = 0;
	for (let i = 0; i < n; i++) {
		const p = await openChunk(key, sealed.subarray(i * frame, Math.min(sealed.length, (i + 1) * frame)), i, i === n - 1);
		parts.push(p);
		total += p.length;
	}
	const out = new Uint8Array(total);
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

/**
 * A chunked object read as it arrives: each frame opened as soon as it is
 * complete (the last one checked as final), handed to `sink` in order. For
 * downloads too large to hold in memory — and for the video player's
 * on-demand frames.
 */
export async function openChunkedStream(key: CryptoKey, body: ReadableStream<Uint8Array>, chunk: number, total: number, sink: (plain: Uint8Array, i: number) => Promise<void> | void): Promise<void> {
	const frame = chunk + FRAME_OVERHEAD;
	const n = Math.max(1, Math.ceil(total / frame));
	const reader = body.getReader();
	let buf = new Uint8Array(0);
	let i = 0;
	const take = async (len: number) => {
		const f = buf.subarray(0, len);
		const plain = await openChunk(key, f, i, i === n - 1);
		buf = buf.slice(len);
		await sink(plain, i);
		i++;
	};
	for (;;) {
		const { value, done } = await reader.read();
		if (value?.length) {
			const next = new Uint8Array(buf.length + value.length);
			next.set(buf);
			next.set(value, buf.length);
			buf = next;
			while (buf.length >= frame && i < n - 1) await take(frame);
		}
		if (done) break;
	}
	if (i !== n - 1) throw new Error("The file was cut short");
	await take(buf.length);
}