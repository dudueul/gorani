// Copyright 2026- Seongwoo Hong. All rights reserved.
// Pattern after Mailflare's vector tooling (Apache 2.0, © Cloudflare, Inc.); see NOTICE.

/**
 * Generates `crates/formats/tests/vectors.json` with the TypeScript crypto
 * (web/src/vault/vault-crypto.ts): key pairs in every shape, sealed objects
 * in every format, unlock methods for every kind. The Rust tests open this
 * file (cargo test), and tests/unit/formats.test.mjs opens what Rust seals
 * back (GORANI_RUST_OUT). Both directions, byte for byte — the cross-language
 * guarantee the whole vault rests on.
 *
 * Run: node scripts/make-vectors.mjs
 *      node scripts/make-vectors.mjs --only-record   (add/refresh the store-record
 *        vector inside the EXISTING file, keyed to its hybrid root — so a new
 *        vector does not churn every other one)
 *      node scripts/make-vectors.mjs --only-placed   (the same for the GV04 vector)
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
	generateMemberKey,
	generateHybridKey,
	seal,
	sealText,
	sealWith,
	sealTextWith,
	wrapContentKey,
	newContentKey,
	importContentKey,
	makePasswordMethod,
	makeRecoveryMethod,
	makePasskeyMethod,
	makeDeviceCopy,
} from "../web/src/vault/vault-crypto.ts";
import { toBase64, fromBase64 } from "../web/src/lib/encoding.ts";
import { importVaultKey } from "../web/src/vault/vault-crypto.ts";
import { createStoreKey, sealStoreKeyToMember } from "../web/src/vault/family.ts";
import { deriveRecordKey, macRecord } from "../web/src/vault/records.ts";
import { sealPlacedText, wrapPlacedKey, storePsk } from "../web/src/vault/vault-crypto.ts";
import { places } from "../web/src/vault/places.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, "crates/formats/tests/vectors.json");

/**
 * The authenticated store-record vector (commit 24, web/src/vault/records.ts):
 * a store key sealed to the hybrid ROOT, and its MAC under that root's record
 * key. Rust must verify the MAC from the same bytes — the length-prefixed
 * encoding, the ECDH-with-itself + ML-KEM-secret derivation, HKDF, HMAC.
 */
async function recordVector(rootBundle, rootPublic) {
	const store = await createStoreKey();
	const record = await sealStoreKeyToMember(store, rootPublic);
	const mac = await macRecord(await deriveRecordKey(await importVaultKey(rootBundle.slice())), "files", record);
	return { name: "files", keyId: record.keyId, x: record.publicKey.x, y: record.publicKey.y, kem: record.pqPublicKey, privateKeySealed: record.privateKeySealed, mac };
}

/**
 * The placed-sealing vector (commit 25, GV04, docs/SECURITY-REVIEW.md › O6):
 * the hybrid key acts as a STORE; a name and a content key sealed into
 * their places. Rust must derive the same store PSK and open both — and
 * refuse them anywhere else.
 */
async function placedVector(storeBundle) {
	const store = await importVaultKey(storeBundle.slice());
	const contentKey = newContentKey();
	return {
		store: "jinu",
		file: "f-0001",
		version: 3,
		psk: toBase64(await storePsk(store)),
		name: "incident-2026-10.pcap",
		nameSealed: await sealPlacedText(store, places.fileName("jinu", "f-0001"), "incident-2026-10.pcap"),
		contentKey: toBase64(contentKey),
		keySealed: await wrapPlacedKey(store, places.fileKey("jinu", "f-0001", 3), contentKey),
	};
}

if (process.argv.includes("--only-placed")) {
	const vectors = JSON.parse(fs.readFileSync(out, "utf8"));
	vectors.placed = await placedVector(fromBase64(vectors.hybrid.bundle));
	fs.writeFileSync(out, JSON.stringify(vectors, null, "\t") + "\n");
	console.log(`placed vector written into ${path.relative(root, out)}`);
	process.exit(0);
}

if (process.argv.includes("--only-record")) {
	const vectors = JSON.parse(fs.readFileSync(out, "utf8"));
	const h = vectors.hybrid;
	vectors.record = await recordVector(fromBase64(h.bundle), { ec: { kty: "EC", crv: "P-256", x: h.x, y: h.y }, kem: h.kem });
	fs.writeFileSync(out, JSON.stringify(vectors, null, "\t") + "\n");
	console.log(`record vector written into ${path.relative(root, out)}`);
	process.exit(0);
}

// ── a P-256 key (the plain path, GV01) ───────────────────────────────
const p256 = await generateMemberKey();

// ── a hybrid key (the post-quantum path, GV03 + GK01) ─────────────────
const hybrid = await generateHybridKey();
const hybridPublic = { ec: hybrid.publicKey, kem: hybrid.pqPublicKey };

const vectors = {
	p256: {
		pkcs8: toBase64(p256.privateKeyPkcs8),
		x: p256.publicKey.x,
		y: p256.publicKey.y,
		keyId: p256.keyId,
		sealed: toBase64(await seal(p256.publicKey, new TextEncoder().encode("sealed to P-256"))),
		sealedText: await sealText(p256.publicKey, "a name, sealed (GV01)"),
	},
	hybrid: {
		bundle: toBase64(hybrid.bundle),
		x: hybrid.publicKey.x,
		y: hybrid.publicKey.y,
		kem: hybrid.pqPublicKey,
		keyId: hybrid.keyId,
		sealed: toBase64(await seal(hybridPublic, new TextEncoder().encode("sealed post-quantum"))),
		sealedText: await sealText(hybridPublic, "한국어 이름.pdf"),
	},
	content: {
		key: toBase64(newContentKey()),
		wrapped: await wrapContentKey(hybridPublic, new Uint8Array(0)),
	},
	unlock: {},
	device: {},
};

// The content-key part wants a real key under a real wrap; rebuild both.
{
	const key = newContentKey();
	vectors.content.key = toBase64(key);
	vectors.content.wrapped = await wrapContentKey(hybridPublic, key);
	vectors.content.wrappedP256 = await wrapContentKey(p256.publicKey, key);
	const ck = await importContentKey(key);
	vectors.content.sealed = toBase64(await sealWith(ck, new TextEncoder().encode("an attachment's bytes")));
	vectors.content.sealedText = await sealTextWith(ck, "한국어 문서");

	// A chunked file (GC01) under the same key, with a small chunk so there
	// are several frames: the Rust side opens it whole and by span.
	const { sealChunked, FRAME_OVERHEAD } = await import("../web/src/vault/chunked-file.ts");
	const chunk = 64;
	const plain = crypto.getRandomValues(new Uint8Array(200));
	vectors.chunked = {
		chunk,
		plain: toBase64(plain),
		sealed: toBase64(await sealChunked(ck, plain, chunk)),
		size: plain.length,
		chunkOverhead: FRAME_OVERHEAD,
	};
}

// ── unlock methods: the hybrid root wrapped by every kind ───────────
{
	const bundle = hybrid.bundle;
	const password = await makePasswordMethod(bundle, "correct horse battery staple", "Password");
	const recovery = await makeRecoveryMethod(bundle);
	const prf = crypto.getRandomValues(new Uint8Array(32));
	const prfSalt = crypto.getRandomValues(new Uint8Array(32));
	const passkey = await makePasskeyMethod(bundle, prf, "AAAAAAAAAAAAAAAAAAAAAA", prfSalt, "Passkey");
	const deviceSecret = crypto.getRandomValues(new Uint8Array(32));
	const device = await makeDeviceCopy(bundle, deviceSecret);
	vectors.unlock = { root: "hybrid", password, recoveryCode: recovery.code, recovery: recovery.method, passkeyPrf: toBase64(prf), passkey };
	vectors.device = { secret: toBase64(deviceSecret), wrapped: device.wrapped, salt: device.salt };
}

vectors.record = await recordVector(hybrid.bundle, hybridPublic);
vectors.placed = await placedVector(hybrid.bundle);

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(vectors, null, "\t") + "\n");
console.log(`vectors written: ${path.relative(root, out)}`);