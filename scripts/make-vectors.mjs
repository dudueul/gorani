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
import { toBase64 } from "../web/src/lib/encoding.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, "crates/formats/tests/vectors.json");

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

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(vectors, null, "\t") + "\n");
console.log(`vectors written: ${path.relative(root, out)}`);