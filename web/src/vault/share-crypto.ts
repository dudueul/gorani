// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

/**
 * Share links for Files (docs/DECISIONS.md › D11, docs/SECURITY-REVIEW.md): one file shared with
 * anyone who has the link, still end to end encrypted.
 *
 *   link     = https://<host>/s/f/<id>#<secret>       secret: 32 random bytes, base64url; browsers never send
 *                                                     the part after "#" to a server, so it never reaches ours
 *   ikm      = secret                                 (no password)
 *            = secret ‖ Argon2id(NFKC(password), salt, 64 MiB, t = 3, p = 4)   (with a password: both are needed)
 *   data key = HKDF-SHA256(ikm, salt = "gorani-share" ‖ id, info = "gorani-share-data-v1")
 *   meta key = HKDF-SHA256(ikm, salt = "gorani-share" ‖ id, info = "gorani-share-meta-v1")
 *   object   = the file sealed again under the data key in GC01 frames (chunked-file.ts): a copy made for this
 *              link, so the link opens nothing else (not the file's other versions, not the vault)
 *   meta     = base64("GS01" ‖ nonce (12) ‖ AES-256-GCM(meta key, JSON { name, type, size, modified }))
 *              with AAD "GS01" ‖ id
 *
 * The id is in both keys' salt and in the meta's AAD: a share's object or
 * meta moved under another id opens nothing. The server keeps the object,
 * the meta, the Argon2id salt and cost, the expiry and the download count;
 * never the secret or the password.
 */

import { fromBase64, toBase64 } from "../lib/encoding.ts";
import { checkArgon2, checkSalt } from "./kdf-bounds.ts";

export const SHARE_ARGON2 = { m: 64 * 1024, t: 3, p: 4 } as const;
export interface ShareKdf { salt: string; m: number; t: number; p: number }
export interface ShareMeta { name: string; type: string | null; size: number; modified: string | null }

const enc = new TextEncoder();
const MAGIC = enc.encode("GS01");

export const toB64Url = (b: Uint8Array) => toBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromB64Url = (s: string) => fromBase64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

/** A new link secret (the part after "#"). */
export const newShareSecret = () => toB64Url(crypto.getRandomValues(new Uint8Array(32)));
/** A new share id (16 random bytes, base64url: unguessable). */
export const newShareId = () => toB64Url(crypto.getRandomValues(new Uint8Array(16)));
export const isShareId = (s: string) => /^[A-Za-z0-9_-]{22}$/.test(s);
export const isShareSecret = (s: string) => /^[A-Za-z0-9_-]{43}$/.test(s);

/** A fresh Argon2id setting for a password-protected link. */
export const newShareKdf = (): ShareKdf => ({ salt: toBase64(crypto.getRandomValues(new Uint8Array(16))), ...SHARE_ARGON2 });

async function passwordBytes(password: string, kdf: ShareKdf): Promise<Uint8Array> {
	// The SERVER serves this setting (the link's meta): bounded both ways —
	// never weaker than OWASP's floor, never enough to freeze the recipient's
	// phone (kdf-bounds.ts, O8).
	checkArgon2(kdf);
	const salt = fromBase64(kdf.salt);
	checkSalt(salt);
	const { argon2id } = await import("hash-wasm");
	return argon2id({ password: password.normalize("NFKC"), salt, memorySize: kdf.m, iterations: kdf.t, parallelism: kdf.p, hashLength: 32, outputType: "binary" });
}

/** The two keys of a share (the data key opens GC01 frames, the meta key the name and type). */
export async function shareKeys(id: string, secret: string, password?: string | null, kdf?: ShareKdf | null): Promise<{ data: CryptoKey; meta: CryptoKey }> {
	const s = fromB64Url(secret);
	if (s.length !== 32) throw new Error("This link is incomplete");
	if (kdf && !password) throw new Error("This link needs its password");
	const p = kdf && password ? await passwordBytes(password, kdf) : new Uint8Array(0);
	const ikmBytes = new Uint8Array(s.length + p.length);
	ikmBytes.set(s);
	ikmBytes.set(p, s.length);
	try {
		const subtle = crypto.subtle;
		const ikm = await subtle.importKey("raw", ikmBytes as BufferSource, "HKDF", false, ["deriveKey"]);
		const salt = enc.encode(`gorani-share${id}`);
		const derive = (info: string) => subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: enc.encode(info) as BufferSource }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
		return { data: await derive("gorani-share-data-v1"), meta: await derive("gorani-share-meta-v1") };
	} finally {
		ikmBytes.fill(0);
		s.fill(0);
		p.fill(0);
	}
}

const metaAad = (id: string) => { const a = new Uint8Array(MAGIC.length + id.length); a.set(MAGIC); a.set(enc.encode(id), MAGIC.length); return a; };

export async function sealShareMeta(metaKey: CryptoKey, id: string, meta: ShareMeta): Promise<string> {
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: metaAad(id) as BufferSource }, metaKey, enc.encode(JSON.stringify(meta)) as BufferSource));
	const out = new Uint8Array(MAGIC.length + 12 + ct.length);
	out.set(MAGIC); out.set(nonce, MAGIC.length); out.set(ct, MAGIC.length + 12);
	return toBase64(out);
}

export async function openShareMeta(metaKey: CryptoKey, id: string, sealed: string): Promise<ShareMeta> {
	const b = fromBase64(sealed);
	if (b.length < MAGIC.length + 12 + 16 || !MAGIC.every((x, i) => b[i] === x)) throw new Error("Not a share");
	try {
		const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(4, 16) as BufferSource, additionalData: metaAad(id) as BufferSource }, metaKey, b.subarray(16) as BufferSource);
		return JSON.parse(new TextDecoder().decode(plain)) as ShareMeta;
	} catch {
		throw new Error("Wrong password, or the link is incomplete");
	}
}

/** Is it a sealed meta value (as the server checks before keeping one)? */
export const isSealedShareMeta = (s: string) => { try { const b = fromBase64(s); return b.length >= 32 && MAGIC.every((x, i) => b[i] === x); } catch { return false; } };