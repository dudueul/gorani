// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Byte encodings shared by the vault, the app and the tests: base64,
 * base64url (JWTs, WebAuthn, link secrets), hex. Standard base64, chunked
 * so large buffers do not overflow the call stack (a 100 MB read as one
 * `String.fromCharCode.apply` would).
 */

const enc = new TextEncoder();

/** Standard base64 (chunked). */
export function toBase64(bytes: Uint8Array): string {
	let s = "";
	for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000) as unknown as number[]);
	return btoa(s);
}

/** Standard base64 to bytes; whitespace (as in MIME bodies) is ignored. */
export function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
	const bin = atob(b64.replace(/\s+/g, ""));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** base64url without padding; a string is encoded as its UTF-8 bytes. */
export function toBase64Url(bytes: Uint8Array | string): string {
	return toBase64(typeof bytes === "string" ? enc.encode(bytes) : bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url (padded or not) to bytes. */
export function fromBase64Url(s: string): Uint8Array<ArrayBuffer> {
	const unpadded = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
	return fromBase64(unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4));
}

/** Lowercase hex. */
export function toHex(bytes: Uint8Array | ArrayBuffer): string {
	return [...(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}