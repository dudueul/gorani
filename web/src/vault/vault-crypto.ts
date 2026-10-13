// Copyright 2026- Seongwoo Hong. All rights reserved.
// Portions derived from Mailflare (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

/**
 * Vault cryptography, as the browser and the tests run it.
 *
 * This is the TypeScript twin of `crates/formats` (the reference
 * implementation): the two must produce byte-identical output, and
 * `tests/unit/formats.test.mjs` proves it in both directions, every commit.
 * Web Crypto only, plus two audited byte-level helpers where no browser API
 * exists yet: `@noble/post-quantum` for ML-KEM-768 and `hash-wasm` for
 * Argon2id (docs/ENCRYPTION.md §Primitives).
 *
 * Model
 *  - A member's vault has one long-lived root key pair. The public half
 *    lives in settings; private halves exist only wrapped (GW1) under
 *    unlock-method secrets the server never sees.
 *  - Sealing is ECIES: a fresh ephemeral P-256 key per object, HKDF-SHA256
 *    to an AES-256-GCM key, random nonce; a hybrid key seals GV3 (P-256 and
 *    ML-KEM-768, both needed to open).
 *  - Content is GV2 under a fresh 32-byte content key per item; only that
 *    small key is sealed to a store key, so rotation re-wraps keys, never
 *    content.
 *
 * Why Web Crypto and not wasm crypto? `importKey` makes the root's P-256
 * half **non-extractable**: scripts in the page can use it to open content
 * but can never read its bytes. That property does not exist in wasm, where
 * key bytes sit in readable linear memory — so key handling stays here, in
 * the platform's crypto (docs/COURSE.md, Lesson 2).
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { fromBase64, toBase64 } from "../lib/encoding.ts";

const MAGIC = new TextEncoder().encode("GV01");
/** v2: symmetric AES-256-GCM under a per-item content key that is itself sealed (v1) to a store key. */
const MAGIC2 = new TextEncoder().encode("GV02");
const WRAP_MAGIC = new TextEncoder().encode("GW01");
/** v3: hybrid post-quantum sealing (P-256 ECDH and ML-KEM-768, both needed to open). */
const MAGIC3 = new TextEncoder().encode("GV03");
/** A hybrid private key's bytes as unlock methods and sealed keys hold them: "GK01" | len(pkcs8):2 | pkcs8 | ML-KEM seed (64) | P-256 public (65). */
const BUNDLE_MAGIC = new TextEncoder().encode("GK01");
const INFO_SEAL_V3 = new TextEncoder().encode("gorani-vault-v3");
const KEM_CT_LEN = 1088;
const KEM_SEED_LEN = 64;
const SEALED_TEXT_PREFIX_V3 = "GV03:";
const EPH_LEN = 65;
const NONCE_LEN = 12;
const INFO_SEAL = new TextEncoder().encode("gorani-vault-v1");
/** Text prefix marking a sealed value stored in a TEXT column (names, types). */
export const SEALED_TEXT_PREFIX = "GV01:";
const SEALED_TEXT_PREFIX_V2 = "GV02:";

const subtle = () => globalThis.crypto.subtle;

// ── byte helpers ────────────────────────────────────────────────────

function concat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
	if (bytes.length < prefix.length) return false;
	for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
	return true;
}

function randomBytes(n: number): Uint8Array {
	return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// ── member key pair ─────────────────────────────────────────────────

export interface MemberKeyPair {
	publicKey: JsonWebKey;
	/** PKCS#8 bytes of the private key; wrap it, never store it as is. */
	privateKeyPkcs8: Uint8Array;
	keyId: string;
}

export async function generateMemberKey(): Promise<MemberKeyPair> {
	const pair = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
	const publicKey = await subtle().exportKey("jwk", pair.publicKey);
	const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
	const raw = new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
	const digest = new Uint8Array(await subtle().digest("SHA-256", raw));
	return {
		publicKey: { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y },
		privateKeyPkcs8: pkcs8,
		keyId: toBase64(digest.slice(0, 12)).replace(/[+/=]/g, "").slice(0, 16),
	};
}

function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
	return subtle().importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

export function importPrivateKey(pkcs8: Uint8Array, extractable = false): Promise<CryptoKey> {
	return subtle().importKey("pkcs8", pkcs8 as BufferSource, { name: "ECDH", namedCurve: "P-256" }, extractable, ["deriveBits"]);
}

/**
 * The key for this device's encrypted search index, derived from the root
 * private key without its bytes (so it works with a non-extractable key):
 * ECDH of the root key with its own public key — which only the private
 * key's holder can compute — then HKDF.
 */
export async function deriveIndexKey(root: VaultPrivateKey, rootPublic: JsonWebKey): Promise<CryptoKey> {
	const hybrid = isHybridPrivate(root);
	const shared = new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: await importPublicKey(rootPublic) }, hybrid ? root.ec : root, 256));
	// A hybrid root mixes in its ML-KEM secret, so the index stays closed to someone who breaks P-256 alone.
	const ikmBytes = hybrid ? concat(shared, new Uint8Array(await subtle().digest("SHA-256", root.kem as BufferSource))) : shared;
	try {
		const ikm = await subtle().importKey("raw", ikmBytes as BufferSource, "HKDF", false, ["deriveKey"]);
		const text = new TextEncoder();
		return await subtle().deriveKey({ name: "HKDF", hash: "SHA-256", salt: text.encode("gorani-index"), info: text.encode(hybrid ? "gorani-index-v3" : "gorani-index-v2") }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
	} finally {
		ikmBytes.fill(0);
		shared.fill(0);
	}
}

async function sealingKey(ownKey: CryptoKey, otherPublic: CryptoKey, ephPubRaw: Uint8Array): Promise<CryptoKey> {
	const shared = await subtle().deriveBits({ name: "ECDH", public: otherPublic }, ownKey, 256);
	const ikm = await subtle().importKey("raw", shared, "HKDF", false, ["deriveKey"]);
	return subtle().deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: ephPubRaw as BufferSource, info: INFO_SEAL as BufferSource },
		ikm,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

// ── sealing / opening ───────────────────────────────────────────────

export function isSealed(bytes: Uint8Array): boolean {
	return startsWith(bytes, MAGIC) || startsWith(bytes, MAGIC2);
}

export function isSealedV2(bytes: Uint8Array): boolean {
	return startsWith(bytes, MAGIC2);
}

// ── v2: per-item content keys ───────────────────────────────────────
//
// Everything of one item (a file version's bytes, preview picture and
// extracted text) shares a random 256-bit content key. The key is sealed
// (GV1/GV3) to the store public key and stored beside the item, so rotating
// the store key re-wraps one small value per item instead of re-encrypting
// the content.

export function newContentKey(): Uint8Array {
	return randomBytes(32);
}

export function importContentKey(raw: Uint8Array): Promise<CryptoKey> {
	return subtle().importKey("raw", raw as BufferSource, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/**
 * Seal bytes under a content key: "GV02" | nonce (12) | AES-256-GCM ciphertext (header as AAD). `context`, when
 * given, is authenticated too without being stored (where a frame sits in a chunked file): opening needs the same.
 */
export async function sealWith(key: CryptoKey, plaintext: Uint8Array, context?: Uint8Array): Promise<Uint8Array> {
	const nonce = randomBytes(NONCE_LEN);
	const header = concat(MAGIC2, nonce);
	const aad = context ? concat(header, context) : header;
	const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource }, key, plaintext as BufferSource));
	return concat(header, ct);
}

export async function openWith(key: CryptoKey, sealed: Uint8Array, context?: Uint8Array): Promise<Uint8Array> {
	if (!isSealedV2(sealed) || sealed.length < MAGIC2.length + NONCE_LEN + 16) throw new Error("Not a v2 sealed object");
	const header = sealed.subarray(0, MAGIC2.length + NONCE_LEN);
	const nonce = sealed.subarray(MAGIC2.length, MAGIC2.length + NONCE_LEN);
	const ct = sealed.subarray(header.length);
	const aad = context ? concat(header, context) : header;
	try {
		return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource }, key, ct as BufferSource));
	} catch {
		throw new Error("Cannot open: wrong content key or corrupted object");
	}
}

export async function sealTextWith(key: CryptoKey, text: string): Promise<string> {
	return SEALED_TEXT_PREFIX_V2 + toBase64(await sealWith(key, new TextEncoder().encode(text)));
}

export function isSealedTextV2(value: string | null | undefined): boolean {
	return typeof value === "string" && value.startsWith(SEALED_TEXT_PREFIX_V2);
}

export async function openTextWith(key: CryptoKey, value: string): Promise<string> {
	if (!isSealedTextV2(value)) return value;
	return new TextDecoder().decode(await openWith(key, fromBase64(value.slice(SEALED_TEXT_PREFIX_V2.length))));
}

/** Seal a raw content key to a store public key (stored beside the item). */
export function wrapContentKey(storePublicKey: VaultPublicKey, raw: Uint8Array): Promise<string> {
	return sealText(storePublicKey, toBase64(raw));
}

/** Re-wrap a sealed content key from one sealing key to another (rotation). */
export async function rewrapContentKey(oldPrivateKey: VaultPrivateKey, newPublicKey: VaultPublicKey, sealedKey: string): Promise<string> {
	return sealText(newPublicKey, await openText(oldPrivateKey, sealedKey));
}

/** Recover a content key with a store private key. */
export async function unwrapContentKey(storePrivateKey: VaultPrivateKey, sealedKey: string): Promise<CryptoKey> {
	return importContentKey(fromBase64(await openText(storePrivateKey, sealedKey)));
}

/** Seal bytes to a public key. Anyone with the public key can seal; only the private key opens. A hybrid key seals GV3. */
export async function seal(publicKey: VaultPublicKey, plaintext: Uint8Array): Promise<Uint8Array> {
	if (isHybridPublic(publicKey)) return sealV3(publicKey, plaintext);
	const pub = publicKey instanceof CryptoKey ? publicKey : await importPublicKey(publicKey);
	const eph = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
	const ephPubRaw = new Uint8Array(await subtle().exportKey("raw", eph.publicKey));
	const key = await sealingKey(eph.privateKey, pub, ephPubRaw);
	const nonce = randomBytes(NONCE_LEN);
	const header = concat(MAGIC, ephPubRaw, nonce);
	const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: header as BufferSource }, key, plaintext as BufferSource));
	return concat(header, ct);
}

/** Open a sealed object with the private key (ECDH, deriveBits; GV3 needs the hybrid key). */
export async function open(privateKey: VaultPrivateKey, sealed: Uint8Array): Promise<Uint8Array> {
	if (startsWith(sealed, MAGIC3)) return openV3(privateKey, sealed);
	if (isHybridPrivate(privateKey)) privateKey = privateKey.ec;
	if (!isSealed(sealed) || sealed.length < MAGIC.length + EPH_LEN + NONCE_LEN + 16) throw new Error("Not a sealed object");
	const ephPubRaw = sealed.subarray(MAGIC.length, MAGIC.length + EPH_LEN);
	const nonce = sealed.subarray(MAGIC.length + EPH_LEN, MAGIC.length + EPH_LEN + NONCE_LEN);
	const header = sealed.subarray(0, MAGIC.length + EPH_LEN + NONCE_LEN);
	const ct = sealed.subarray(header.length);
	const ephPub = await subtle().importKey("raw", ephPubRaw as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
	const key = await sealingKey(privateKey, ephPub, new Uint8Array(ephPubRaw));
	try {
		return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: header as BufferSource }, key, ct as BufferSource));
	} catch {
		throw new Error("Cannot open: wrong key or corrupted object");
	}
}

export async function sealText(publicKey: VaultPublicKey, text: string): Promise<string> {
	const prefix = isHybridPublic(publicKey) ? SEALED_TEXT_PREFIX_V3 : SEALED_TEXT_PREFIX;
	return prefix + toBase64(await seal(publicKey, new TextEncoder().encode(text)));
}

/** True for GV1 (ECIES), GV2 (content key) and GV3 (hybrid) sealed text values. */
export function isSealedText(value: string | null | undefined): boolean {
	return typeof value === "string" && (value.startsWith(SEALED_TEXT_PREFIX) || value.startsWith(SEALED_TEXT_PREFIX_V2) || value.startsWith(SEALED_TEXT_PREFIX_V3));
}

export async function openText(privateKey: VaultPrivateKey, value: string): Promise<string> {
	const prefix = value.startsWith(SEALED_TEXT_PREFIX) ? SEALED_TEXT_PREFIX : value.startsWith(SEALED_TEXT_PREFIX_V3) ? SEALED_TEXT_PREFIX_V3 : null;
	if (!prefix) return value;
	return new TextDecoder().decode(await open(privateKey, fromBase64(value.slice(prefix.length))));
}

// ── v3: hybrid post-quantum sealing ─────────────────────────────────
//
// A key pair is P-256 (ECDH) plus ML-KEM-768 (FIPS 203). Sealing makes a
// fresh ephemeral P-256 key and an ML-KEM encapsulation; the two shared
// secrets go through HKDF-SHA256 together (salted with a hash of the
// ephemeral key, the ML-KEM ciphertext and both recipient public keys, so
// each binds the others) into an AES-256-GCM key. Opening needs both private
// halves: breaking P-256 (a large quantum computer) or ML-KEM (a flaw in the
// new scheme or its code) alone opens nothing.
// Layout: "GV03" | ephemeral P-256 public (65) | ML-KEM ciphertext (1088) |
// nonce (12) | ciphertext + tag, the header bound as AAD. Text: "GV03:"+b64.

/** A hybrid public key: P-256 (JWK) and ML-KEM-768 (base64, 1184 bytes). */
export interface HybridPublicKey { ec: JsonWebKey; kem: string }
/** A hybrid private key: P-256 (non-extractable), its public half (raw, 65 bytes) and the ML-KEM-768 secret key. */
export interface HybridPrivateKey { ec: CryptoKey; ecPublic: Uint8Array; kem: Uint8Array }
export type VaultPublicKey = JsonWebKey | CryptoKey | HybridPublicKey;
/** A public key as settings and the Durable Objects keep it (serialisable): P-256 alone, or hybrid. */
export type SealTarget = JsonWebKey | HybridPublicKey;
export type VaultPrivateKey = CryptoKey | HybridPrivateKey;

export const isHybridPublic = (k: unknown): k is HybridPublicKey => !!k && typeof k === "object" && !(k instanceof CryptoKey) && typeof (k as HybridPublicKey).kem === "string" && typeof (k as HybridPublicKey).ec === "object";
export const isHybridPrivate = (k: unknown): k is HybridPrivateKey => !!k && typeof k === "object" && !(k instanceof CryptoKey) && (k as HybridPrivateKey).kem instanceof Uint8Array;
/** The public key a sealing key seals to: hybrid when it has an ML-KEM half. */
export const sealingPublicKey = (k: { publicKey: JsonWebKey; pqPublicKey?: string | null }): SealTarget => (k.pqPublicKey ? { ec: k.publicKey, kem: k.pqPublicKey } : k.publicKey);

async function hybridAesKey(ecdh: ArrayBuffer, kemShared: Uint8Array, ephPubRaw: Uint8Array, kemCt: Uint8Array, recipientEcRaw: Uint8Array, recipientKem: Uint8Array): Promise<CryptoKey> {
	const salt = new Uint8Array(await subtle().digest("SHA-256", concat(ephPubRaw, kemCt, recipientEcRaw, recipientKem) as BufferSource));
	const ikmBytes = concat(new Uint8Array(ecdh), kemShared);
	try {
		const ikm = await subtle().importKey("raw", ikmBytes as BufferSource, "HKDF", false, ["deriveKey"]);
		return await subtle().deriveKey({ name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: INFO_SEAL_V3 as BufferSource }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
	} finally {
		ikmBytes.fill(0);
	}
}

async function sealV3(pub: HybridPublicKey, plaintext: Uint8Array): Promise<Uint8Array> {
	const ecPub = await importPublicKey(pub.ec);
	const recipientEcRaw = new Uint8Array(await subtle().exportKey("raw", ecPub));
	const kemPub = fromBase64(pub.kem);
	const eph = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
	const ephPubRaw = new Uint8Array(await subtle().exportKey("raw", eph.publicKey));
	const ecdh = await subtle().deriveBits({ name: "ECDH", public: ecPub }, eph.privateKey, 256);
	const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemPub);
	const key = await hybridAesKey(ecdh, sharedSecret, ephPubRaw, cipherText, recipientEcRaw, kemPub);
	sharedSecret.fill(0);
	const nonce = randomBytes(NONCE_LEN);
	const header = concat(MAGIC3, ephPubRaw, cipherText, nonce);
	const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: header as BufferSource }, key, plaintext as BufferSource));
	return concat(header, ct);
}

/** The ML-KEM-768 public key inside its secret key (FIPS 203: dk = dk_PKE (1152) | ek (1184) | H(ek) | z). */
const kemPublicOf = (secretKey: Uint8Array) => secretKey.subarray(1152, 1152 + 1184);

async function openV3(privateKey: VaultPrivateKey, sealed: Uint8Array): Promise<Uint8Array> {
	if (!isHybridPrivate(privateKey)) throw new Error("This object is sealed post-quantum: it needs the hybrid key");
	const headerLen = MAGIC3.length + EPH_LEN + KEM_CT_LEN + NONCE_LEN;
	if (sealed.length < headerLen + 16) throw new Error("Not a sealed object");
	const ephPubRaw = sealed.subarray(MAGIC3.length, MAGIC3.length + EPH_LEN);
	const kemCt = sealed.subarray(MAGIC3.length + EPH_LEN, MAGIC3.length + EPH_LEN + KEM_CT_LEN);
	const nonce = sealed.subarray(headerLen - NONCE_LEN, headerLen);
	const header = sealed.subarray(0, headerLen);
	const ephPub = await subtle().importKey("raw", ephPubRaw as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
	const ecdh = await subtle().deriveBits({ name: "ECDH", public: ephPub }, privateKey.ec, 256);
	const kemShared = ml_kem768.decapsulate(kemCt, privateKey.kem);
	const key = await hybridAesKey(ecdh, kemShared, new Uint8Array(ephPubRaw), new Uint8Array(kemCt), privateKey.ecPublic, kemPublicOf(privateKey.kem));
	kemShared.fill(0);
	try {
		return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: header as BufferSource }, key, sealed.subarray(headerLen) as BufferSource));
	} catch {
		throw new Error("Cannot open: wrong key or corrupted object");
	}
}

/** A new hybrid key pair: its public halves, and the private bundle (GK1) to seal or wrap. The caller wipes the bundle. */
export async function generateHybridKey(): Promise<{ keyId: string; publicKey: JsonWebKey; pqPublicKey: string; bundle: Uint8Array }> {
	const pair = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
	const jwk = await subtle().exportKey("jwk", pair.publicKey);
	const ecRaw = new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
	const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
	const seed = randomBytes(KEM_SEED_LEN);
	const { publicKey: kemPub } = ml_kem768.keygen(seed);
	const len = new Uint8Array([pkcs8.length >> 8, pkcs8.length & 0xff]);
	const bundle = concat(BUNDLE_MAGIC, len, pkcs8, seed, ecRaw);
	pkcs8.fill(0);
	seed.fill(0);
	const digest = new Uint8Array(await subtle().digest("SHA-256", concat(ecRaw, kemPub) as BufferSource));
	return {
		keyId: "pq" + toBase64(digest.slice(0, 12)).replace(/[+/=]/g, "").slice(0, 14),
		publicKey: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
		pqPublicKey: toBase64(kemPub),
		bundle,
	};
}

/** True for a hybrid private bundle (GK1), false for a plain P-256 PKCS#8. */
export const isHybridBundle = (bytes: Uint8Array) => startsWith(bytes, BUNDLE_MAGIC);

/**
 * A private key from its bytes, as unlock methods and sealed keys hold them: a hybrid bundle (GK1) or a plain P-256
 * PKCS#8. The P-256 half is imported non-extractable; the ML-KEM half has to stay bytes (no browser offers ML-KEM
 * keys yet), but on its own it opens nothing.
 */
export async function importVaultKey(bytes: Uint8Array): Promise<VaultPrivateKey> {
	if (!isHybridBundle(bytes)) return importPrivateKey(bytes);
	if (bytes.length < 6) throw new Error("Not a key bundle");
	const len = (bytes[4]! << 8) | bytes[5]!;
	const pkcs8 = bytes.subarray(6, 6 + len);
	const seed = bytes.subarray(6 + len, 6 + len + KEM_SEED_LEN);
	const ecPublic = bytes.slice(6 + len + KEM_SEED_LEN, 6 + len + KEM_SEED_LEN + EPH_LEN);
	if (seed.length !== KEM_SEED_LEN || ecPublic.length !== EPH_LEN) throw new Error("Not a key bundle");
	return { ec: await importPrivateKey(pkcs8), ecPublic, kem: ml_kem768.keygen(seed).secretKey };
}

// ── unlock methods: wrapping the private key ────────────────────────

export type UnlockKind = "password" | "passkey" | "recovery";

export interface UnlockMethod {
	id: string;
	kind: UnlockKind;
	label?: string;
	/** base64 of "GW01" | nonce | AES-GCM(private key bytes). */
	wrapped: string;
	/** base64 salt for the key derivation. */
	salt: string;
	/** Password only: the key derivation. Argon2id — the only password KDF gorani has. */
	kdf: "argon2id";
	/** Argon2id cost: memory in KiB, passes, lanes. */
	argon2?: { m: number; t: number; p: number };
	/** WebAuthn credential id, base64url (passkey only). */
	credentialId?: string;
	/** Salt handed to the PRF extension, base64 (passkey only). */
	prfSalt?: string;
	createdAt: string;
}

/**
 * Argon2id cost for passwords: RFC 9106's second recommended setting (64 MiB, 3 passes, 4 lanes). Each guess
 * needs 64 MiB of memory for its whole run, which is what makes graphics cards and custom chips far less effective
 * against it than against PBKDF2. About a quarter of a second on a laptop, around a second on a phone.
 */
export const ARGON2ID_PARAMS = { m: 64 * 1024, t: 3, p: 4 } as const;

async function kekFromArgon2id(password: string, salt: Uint8Array, a: { m: number; t: number; p: number }): Promise<CryptoKey> {
	// Bounds on what stored settings may ask for: never weaker than the RFC's minimum, never an absurd allocation.
	if (!(a.m >= 19 * 1024 && a.m <= 1024 * 1024 && a.t >= 1 && a.t <= 20 && a.p >= 1 && a.p <= 16)) throw new Error("Unsupported password parameters");
	const { argon2id } = await import("hash-wasm");
	const raw = await argon2id({ password: password.normalize("NFKC"), salt, memorySize: a.m, iterations: a.t, parallelism: a.p, hashLength: 32, outputType: "binary" });
	try {
		return await subtle().importKey("raw", raw as BufferSource, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
	} finally {
		raw.fill(0);
	}
}

/**
 * What is wrong with a new vault password, or null: at least 12 characters, and either 16 or more or three kinds of
 * character (lower case, upper case, digits, symbols). A passphrase of several random words passes on length.
 */
export function passwordProblem(password: string): string | null {
	const pw = password.normalize("NFKC");
	if ([...pw].length < 12) return "Use at least 12 characters";
	const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
	if ([...pw].length < 16 && kinds < 3) return "Use 16 or more characters, or mix three of: lower case, upper case, digits, symbols";
	if (/^(.)\1+$/.test(pw)) return "Use more than one repeated character";
	return null;
}

/** KEK from a high-entropy secret (passkey PRF output, recovery code bytes). */
async function kekFromSecret(secret: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
	const ikm = await subtle().importKey("raw", secret as BufferSource, "HKDF", false, ["deriveKey"]);
	return subtle().deriveKey({ name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: new TextEncoder().encode(info) as BufferSource }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function wrapPrivateKey(pkcs8: Uint8Array, kek: CryptoKey): Promise<string> {
	const nonce = randomBytes(NONCE_LEN);
	const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: WRAP_MAGIC as BufferSource }, kek, pkcs8 as BufferSource));
	return toBase64(concat(WRAP_MAGIC, nonce, ct));
}

async function unwrapPrivateKey(wrapped: string, kek: CryptoKey): Promise<Uint8Array> {
	const bytes = fromBase64(wrapped);
	if (!startsWith(bytes, WRAP_MAGIC)) throw new Error("Not a wrapped key");
	const nonce = bytes.subarray(WRAP_MAGIC.length, WRAP_MAGIC.length + NONCE_LEN);
	const ct = bytes.subarray(WRAP_MAGIC.length + NONCE_LEN);
	try {
		return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: WRAP_MAGIC as BufferSource }, kek, ct as BufferSource));
	} catch {
		throw new Error("Wrong password or key");
	}
}

// ── recovery codes ──────────────────────────────────────────────────

const B32 = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // Crockford-like, no 0/O/1/I/L/U

/** 8 groups of 5 characters ≈ 196 bits of entropy, easy to type. */
function generateRecoveryCode(): string {
	const bytes = randomBytes(40);
	let out = "";
	for (let i = 0; i < 40; i++) {
		out += B32[bytes[i]! % B32.length];
		if (i % 5 === 4 && i < 39) out += "-";
	}
	return out;
}

function normalizeRecoveryCode(code: string): string {
	return code.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
}

function recoveryCodeBytes(code: string): Uint8Array {
	return new TextEncoder().encode(normalizeRecoveryCode(code));
}

// ── method constructors (client side) ───────────────────────────────

function methodId(): string {
	return toBase64(randomBytes(9)).replace(/[+/=]/g, "").slice(0, 12);
}

export async function makePasswordMethod(keyBytes: Uint8Array, password: string, label = "Password"): Promise<UnlockMethod> {
	const salt = randomBytes(16);
	const kek = await kekFromArgon2id(password, salt, ARGON2ID_PARAMS);
	return { id: methodId(), kind: "password", label, wrapped: await wrapPrivateKey(keyBytes, kek), salt: toBase64(salt), kdf: "argon2id", argon2: { ...ARGON2ID_PARAMS }, createdAt: new Date().toISOString() };
}

export async function makeRecoveryMethod(keyBytes: Uint8Array): Promise<{ method: UnlockMethod; code: string }> {
	const code = generateRecoveryCode();
	const salt = randomBytes(16);
	const kek = await kekFromSecret(recoveryCodeBytes(code), salt, "gorani-recovery-v1");
	return { method: { id: methodId(), kind: "recovery", label: "Recovery code", wrapped: await wrapPrivateKey(keyBytes, kek), salt: toBase64(salt), kdf: "argon2id", createdAt: new Date().toISOString() }, code };
}

export async function makePasskeyMethod(keyBytes: Uint8Array, prfOutput: Uint8Array, credentialId: string, prfSalt: Uint8Array, label = "Passkey"): Promise<UnlockMethod> {
	const salt = randomBytes(16);
	const kek = await kekFromSecret(prfOutput, salt, "gorani-passkey-v1");
	return { id: methodId(), kind: "passkey", label, wrapped: await wrapPrivateKey(keyBytes, kek), salt: toBase64(salt), kdf: "argon2id", credentialId, prfSalt: toBase64(prfSalt), createdAt: new Date().toISOString() };
}

/**
 * A device copy: the same GW1 wrap under a KEK derived from a secret only
 * the enrolled device can produce (TPM behind Windows Hello, Secure Enclave,
 * keyring + TPM). The server keeps the wrapped copy and hands it back only
 * to that device's token; docs/DESKTOP.md.
 */
export async function makeDeviceCopy(keyBytes: Uint8Array, deviceSecret: Uint8Array): Promise<{ wrapped: string; salt: string }> {
	const salt = randomBytes(16);
	const kek = await kekFromSecret(deviceSecret, salt, "gorani-device-v1");
	return { wrapped: await wrapPrivateKey(keyBytes, kek), salt: toBase64(salt) };
}

export async function openDeviceCopy(wrapped: string, salt: string, deviceSecret: Uint8Array): Promise<Uint8Array> {
	return unwrapPrivateKey(wrapped, await kekFromSecret(deviceSecret, fromBase64(salt), "gorani-device-v1"));
}

/** Unwrap the private key with the secret matching the method kind. */
export async function unlockWithMethod(method: UnlockMethod, secret: string | Uint8Array): Promise<Uint8Array> {
	const salt = fromBase64(method.salt);
	if (method.kind === "password") {
		if (method.kdf !== "argon2id" || !method.argon2) throw new Error("Password method lacks Argon2id parameters");
		return unwrapPrivateKey(method.wrapped, await kekFromArgon2id(String(secret), salt, method.argon2));
	}
	if (method.kind === "recovery") return unwrapPrivateKey(method.wrapped, await kekFromSecret(recoveryCodeBytes(String(secret)), salt, "gorani-recovery-v1"));
	return unwrapPrivateKey(method.wrapped, await kekFromSecret(secret as Uint8Array, salt, "gorani-passkey-v1"));
}