// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

/**
 * Upload-link cryptography (docs/REQUESTS.md, commit 38): the tokens and
 * the note key a link's secret derives. Kept from the original design
 * (commit ③), whose "seal to your files key" no longer fits — since GV04
 * (commit 25) sealing into a store takes its PRIVATE key, so the sender
 * seals to the area's INBOX key instead (inbox.ts, request-upload.ts).
 *
 *   link        = https://<host>/s/r/<id>#<secret>.<inbox key digest>   (requests.ts)
 *                 secret: 32 random bytes, base64url, in the fragment
 *   view token  = HKDF-SHA256(secret, "gorani-request" ‖ id, "gorani-request-view-v1")   reads the
 *                 link's note, limits and inbox key
 *   send token  = HKDF-SHA256(secret ‖ SHA-256(NFKC(password))?, "gorani-request" ‖ id, "gorani-request-send-v1")
 *                 allows uploads; a link always has a password (the server refuses send = view)
 *   note key    = HKDF-SHA256(secret, "gorani-request" ‖ id, "gorani-request-note-v1"): the owner's message to the
 *                 sender, sealed so the server cannot read it (GR01)
 *
 * The server keeps SHA-256 of each token (never the secret), checks the
 * send token on each upload, and locks a link after ten wrong passwords
 * (worker/src/requests.rs). The tokens only let someone add files; nothing
 * lists or downloads what was sent.
 */

import { fromBase64, toBase64 } from "../lib/encoding.ts";
import { fromB64Url, toB64Url } from "./share-crypto.ts";

const enc = new TextEncoder();
const MAGIC = enc.encode("GR01");

export const newRequestId = () => toB64Url(crypto.getRandomValues(new Uint8Array(16)));
export const newRequestSecret = () => toB64Url(crypto.getRandomValues(new Uint8Array(32)));
export const isRequestId = (s: string) => /^[A-Za-z0-9_-]{22}$/.test(s);
export const isRequestSecret = (s: string) => /^[A-Za-z0-9_-]{43}$/.test(s);

async function hkdf(ikm: Uint8Array, id: string, info: string): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
	return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: enc.encode(`gorani-request${id}`) as BufferSource, info: enc.encode(info) as BufferSource }, key, 256));
}

/** The tokens a visitor sends (base64url), and the note key. */
export async function requestKeys(id: string, secret: string, password?: string | null): Promise<{ view: string; send: string; note: CryptoKey }> {
	const s = fromB64Url(secret);
	if (s.length !== 32) throw new Error("This link is incomplete");
	const pw = password ? new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(password.normalize("NFKC")))) : new Uint8Array(0);
	const sendIkm = new Uint8Array(s.length + pw.length);
	sendIkm.set(s); sendIkm.set(pw, s.length);
	const noteRaw = await hkdf(s, id, "gorani-request-note-v1");
	const out = {
		view: toB64Url(await hkdf(s, id, "gorani-request-view-v1")),
		send: toB64Url(await hkdf(sendIkm, id, "gorani-request-send-v1")),
		note: await crypto.subtle.importKey("raw", noteRaw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]),
	};
	noteRaw.fill(0); sendIkm.fill(0); s.fill(0);
	return out;
}

/** What the server stores for a token: hex SHA-256. */
export async function tokenHash(token: string): Promise<string> {
	const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(token)));
	return [...d].map((x) => x.toString(16).padStart(2, "0")).join("");
}

const aad = (id: string) => { const a = new Uint8Array(MAGIC.length + id.length); a.set(MAGIC); a.set(enc.encode(id), MAGIC.length); return a; };

export async function sealRequestNote(key: CryptoKey, id: string, note: string): Promise<string> {
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad(id) as BufferSource }, key, enc.encode(note) as BufferSource));
	const out = new Uint8Array(4 + 12 + ct.length);
	out.set(MAGIC); out.set(nonce, 4); out.set(ct, 16);
	return toBase64(out);
}

export async function openRequestNote(key: CryptoKey, id: string, sealed: string): Promise<string> {
	const b = fromBase64(sealed);
	if (b.length < 32 || !MAGIC.every((x, i) => b[i] === x)) throw new Error("Not a request note");
	return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(4, 16) as BufferSource, additionalData: aad(id) as BufferSource }, key, b.subarray(16) as BufferSource));
}

export const isSealedRequestNote = (s: string) => { try { const b = fromBase64(s); return b.length >= 32 && MAGIC.every((x, i) => b[i] === x); } catch { return false; } };