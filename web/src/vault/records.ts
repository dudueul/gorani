// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Authenticated store-key records (docs/SECURITY-REVIEW.md › O3).
 *
 * The attack this closes. A member's settings hold their store keys as
 * records — `{ keyId, publicKey, pqPublicKey, privateKeySealed }`, the
 * private half sealed to the member's root. Sealing needs only a PUBLIC key,
 * so a server (or anyone who can write the settings row) can mint a fresh
 * key pair, seal ITS private half to the victim's root, and swap the record.
 * The victim's client opens it without complaint — it really is sealed to
 * them — and from then on seals every new file's content key, name and type
 * to the attacker's public half. Zero-trust undone by one row write.
 *
 * Two checks, both cheap:
 *
 * 1. **Consistency** (`checkRecordMatches`): the opened private key must
 *    reproduce the record's public halves and its key id. A record that
 *    pairs someone's private key with another public key is refused.
 * 2. **Authenticity** (`macRecord` / `verifyRecord`): an HMAC over the
 *    record under a key derived from the member's ROOT alone — ECDH of the
 *    root with its own public half (taken from the decrypted bundle, never
 *    from the server's copy of the settings), mixed with a hash of the
 *    root's ML-KEM secret, through HKDF. Only the root's holder can make a
 *    record verify. The member's own files store gets its MAC the moment it
 *    is created (setup.ts).
 *
 * The honest limit: a record sealed to you by SOMEONE ELSE (the family
 * area's key, sealed by a parent) cannot carry your MAC when it arrives —
 * its creator does not hold your root. Such a record is pinned on first
 * open ("trust on first use", `session.ts`): from then on a swap is caught,
 * but a substitution BEFORE that first open is not. Closing that gap needs
 * member identity keys with verified fingerprints — the roles/cases/quorum
 * redesign (docs/DECISIONS.md › D2, D4).
 *
 * The encoding is length-prefixed bytes, not JSON (JSON has more than one
 * spelling of the same object; a MAC must have exactly one input). The
 * Rust client computes the identical bytes (crates/formats › records).
 */

import { fromBase64, toBase64 } from "../lib/encoding.ts";
import { hybridKeyId, isHybridPrivate, kemPublicOf, type VaultPrivateKey } from "./vault-crypto.ts";

const subtle = () => globalThis.crypto.subtle;
const enc = new TextEncoder();

/** The record fields the MAC covers — exactly the ones a client acts on. */
export interface StoreRecord {
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey?: string;
	privateKeySealed: string;
	/** base64 HMAC-SHA256 (records.ts) — absent until created/pinned. */
	mac?: string;
}

const DOMAIN = "gorani-store-record-v1";

/** The P-256 public key's uncompressed point (0x04 ‖ x ‖ y) from its JWK. */
export function ecRawOfJwk(jwk: JsonWebKey): Uint8Array {
	const b64url = (s: string) => fromBase64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
	if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) throw new Error("not a P-256 public key");
	const x = b64url(jwk.x);
	const y = b64url(jwk.y);
	if (x.length !== 32 || y.length !== 32) throw new Error("not a P-256 public key");
	const out = new Uint8Array(65);
	out[0] = 0x04;
	out.set(x, 1);
	out.set(y, 33);
	return out;
}

/** u32 BE length ‖ bytes, per field, in a fixed order. */
export function recordBytes(name: string, rec: StoreRecord): Uint8Array {
	const fields = [enc.encode(DOMAIN), enc.encode(name), enc.encode(rec.keyId), ecRawOfJwk(rec.publicKey), rec.pqPublicKey ? fromBase64(rec.pqPublicKey) : new Uint8Array(0), enc.encode(rec.privateKeySealed)];
	const total = fields.reduce((n, f) => n + 4 + f.length, 0);
	const out = new Uint8Array(total);
	const view = new DataView(out.buffer);
	let at = 0;
	for (const f of fields) {
		view.setUint32(at, f.length);
		out.set(f, at + 4);
		at += 4 + f.length;
	}
	return out;
}

/** The member's record key: HMAC-SHA256, non-extractable, from the root alone. */
export async function deriveRecordKey(root: VaultPrivateKey): Promise<CryptoKey> {
	if (!isHybridPrivate(root)) throw new Error("store records are authenticated with a hybrid root");
	const ownPublic = await subtle().importKey("raw", root.ecPublic as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
	const shared = new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: ownPublic }, root.ec, 256));
	const kemHash = new Uint8Array(await subtle().digest("SHA-256", root.kem as BufferSource));
	const ikmBytes = new Uint8Array(64);
	ikmBytes.set(shared, 0);
	ikmBytes.set(kemHash, 32);
	try {
		const ikm = await subtle().importKey("raw", ikmBytes as BufferSource, "HKDF", false, ["deriveKey"]);
		return await subtle().deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("gorani-records"), info: enc.encode("gorani-records-v1") }, ikm, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]);
	} finally {
		ikmBytes.fill(0);
		shared.fill(0);
	}
}

export async function macRecord(recordKey: CryptoKey, name: string, rec: StoreRecord): Promise<string> {
	return toBase64(new Uint8Array(await subtle().sign("HMAC", recordKey, recordBytes(name, rec) as BufferSource)));
}

/** Constant-time by construction: WebCrypto's HMAC verify. */
export async function verifyRecord(recordKey: CryptoKey, name: string, rec: StoreRecord): Promise<boolean> {
	if (!rec.mac) return false;
	let mac: Uint8Array;
	try {
		mac = fromBase64(rec.mac);
	} catch {
		return false;
	}
	return subtle().verify("HMAC", recordKey, mac as BufferSource, recordBytes(name, rec) as BufferSource);
}

/** The opened private key must BE the record's key: same public halves, same id. */
export async function checkRecordMatches(opened: VaultPrivateKey, rec: Pick<StoreRecord, "keyId" | "publicKey" | "pqPublicKey">): Promise<void> {
	if (!isHybridPrivate(opened)) throw new Error("store keys are hybrid");
	const ec = ecRawOfJwk(rec.publicKey);
	const kem = kemPublicOf(opened.kem);
	const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
	if (!same(opened.ecPublic, ec)) throw new Error("store key record: the public key does not belong to the sealed private key");
	if (!rec.pqPublicKey || !same(kem, fromBase64(rec.pqPublicKey))) throw new Error("store key record: the post-quantum public key does not belong to the sealed private key");
	if ((await hybridKeyId(opened.ecPublic, kem)) !== rec.keyId) throw new Error("store key record: the key id does not match the key");
}
