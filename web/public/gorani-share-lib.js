// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * GS01 share-link crypto for the self-contained recipient page — the plain
 * ES module twin of web/src/vault/share-crypto.ts (which the SPA and the
 * unit tests import). No build step: the page imports it straight from
 * /gorani-share-lib.js, served raw, exactly like /gorani-media-lib.js. One
 * derivation, byte for byte (docs/APPS.md › Share links):
 *
 *   ikm      = secret                                  (no password)
 *            = secret ‖ Argon2id(NFKC(password), salt, m, t, p)   (password set: BOTH are needed)
 *   data key = HKDF-SHA256(ikm, salt = "gorani-share" ‖ id, info = "gorani-share-data-v1")
 *   meta key = HKDF-SHA256(ikm, salt = "gorani-share" ‖ id, info = "gorani-share-meta-v1")
 *   meta     = base64("GS01" ‖ nonce (12) ‖ AES-256-GCM(meta key, JSON)) with AAD "GS01" ‖ id
 *   claim    = base64url(HKDF-SHA256(ikm, salt = "gorani-share" ‖ id, info = "gorani-share-view-claim-v1"))
 *              a view-only link's claim proof (40c)
 *
 * Argon2id comes from the vendored UMD beside it (/vendor/argon2.umd.min.js,
 * hash-wasm, MIT — see NOTICE), which the page loads BEFORE this module; it
 * exposes globalThis.hashwasm. The server never sees the secret or the
 * password — both exist only in this tab's memory.
 */

const enc = new TextEncoder();
const MAGIC = enc.encode("GS01");

export const b64uToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
export const bytesToB64 = (b) => btoa(String.fromCharCode(...b));

/** Argon2id with the server-declared settings, bounded like the TS module bounds them. */
async function passwordBytes(password, kdf) {
	if (!globalThis.hashwasm?.argon2id) throw new Error("This link needs its password, but the key stretcher failed to load");
	if (!(kdf.m >= 19 * 1024 && kdf.m <= 1024 * 1024 && kdf.t >= 1 && kdf.t <= 20 && kdf.p >= 1 && kdf.p <= 16)) throw new Error("Unsupported password parameters");
	return globalThis.hashwasm.argon2id({ password: password.normalize("NFKC"), salt: b64uToBytes(kdf.salt), memorySize: kdf.m, iterations: kdf.t, parallelism: kdf.p, hashLength: 32, outputType: "binary" });
}

/** The two keys of a share (data opens GC01 frames, meta opens name and type). */
export async function shareKeys(id, secret, password, kdf) {
	const s = b64uToBytes(secret);
	if (s.length !== 32) throw new Error("This link is incomplete");
	const needsPw = !!kdf;
	if (needsPw && !password) throw new Error("This link needs its password");
	const p = needsPw ? await passwordBytes(password, kdf) : new Uint8Array(0);
	const ikmBytes = new Uint8Array(s.length + p.length);
	ikmBytes.set(s);
	ikmBytes.set(p, s.length);
	try {
		const subtle = crypto.subtle;
		const ikm = await subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveKey", "deriveBits"]);
		const salt = enc.encode(`gorani-share${id}`);
		const derive = (info) =>
			subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
		// A view-only link's claim proof (commit 40c): the page shows the
		// server it holds the link's secret and password, without either.
		const claim = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("gorani-share-view-claim-v1") }, ikm, 256));
		return { data: await derive("gorani-share-data-v1"), meta: await derive("gorani-share-meta-v1"), claim: bytesToB64(claim).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") };
	} finally {
		ikmBytes.fill(0);
		s.fill(0);
		p.fill(0);
	}
}

/** Open the sealed meta (GS01). A wrong password lands here as an AEAD failure. */
export async function openShareMeta(metaKey, id, sealedB64) {
	const b = b64uToBytes(sealedB64);
	if (b.length < MAGIC.length + 12 + 16 || !MAGIC.every((x, i) => b[i] === x)) throw new Error("Not a share");
	try {
		const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(4, 16), additionalData: new Uint8Array([...MAGIC, ...enc.encode(id)]) }, metaKey, b.subarray(16));
		return JSON.parse(new TextDecoder().decode(plain));
	} catch {
		throw new Error("Wrong password, or the link is incomplete");
	}
}