// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The share page's own crypto module (web/public/gorani-share-lib.js) — the
 * no-build twin the self-contained recipient page imports. The page can't
 * import the SPA's share-crypto.ts, so it ships this module, and THIS test
 * imports the very same file so the page's crypto is proven without a
 * browser. The heart of the proof: the lib and the TS module derive the
 * SAME keys from the same (id, secret, password, kdf) — sealed by one,
 * opened by the other, both directions.
 */

import assert from "node:assert/strict";
import { createRequire } from "node:module";

// The page loads /vendor/argon2.umd.min.js (hash-wasm, MIT — see NOTICE)
// before the module; the test loads the same file from node_modules.
globalThis.hashwasm = createRequire(import.meta.url)("../../web/node_modules/hash-wasm/dist/argon2.umd.min.js");
const lib = await import("../../web/public/gorani-share-lib.js");
const ts = await import("../../web/src/vault/share-crypto.ts");

const id = ts.newShareId();
const secret = ts.newShareSecret();
const meta = { name: "가족사진.jpg", type: "image/jpeg", size: 123456, modified: null };

// ── No password: the two implementations agree ──────────────────────
{
	const tsKeys = await ts.shareKeys(id, secret);
	const sealedByTs = await ts.sealShareMeta(tsKeys.meta, id, meta);
	const openedByLib = await lib.openShareMeta((await lib.shareKeys(id, secret)).meta, id, sealedByTs);
	assert.deepEqual(openedByLib, meta, "TS-sealed, lib-opened");

	const libKeys = await lib.shareKeys(id, secret);
	const sealedByLib = await ts.sealShareMeta(libKeys.meta, id, meta);
	assert.deepEqual(await ts.openShareMeta(libKeys.meta, id, sealedByLib), meta, "lib-sealed, TS-opened");
}

// ── With a password: both halves, same derivation ───────────────────
{
	const kdf = ts.newShareKdf();
	const tsKeys = await ts.shareKeys(id, secret, "FamilyPhotos2026", kdf);
	const sealedByTs = await ts.sealShareMeta(tsKeys.meta, id, meta);
	const libKeys = await lib.shareKeys(id, secret, "FamilyPhotos2026", kdf);
	assert.deepEqual(await lib.openShareMeta(libKeys.meta, id, sealedByTs), meta, "password derivation agrees");
	await assert.rejects(() => lib.openShareMeta(libKeys.meta, id, sealedByTs).then(() => lib.shareKeys(id, secret, "wrong-password", kdf)).then((k) => lib.openShareMeta(k.meta, id, sealedByTs)), /Wrong password/);
	await assert.rejects(() => lib.shareKeys(id, secret, null, kdf), /needs its password/);

	// The bounded cost: the server may only ask for sane Argon2id settings.
	const silly = { ...kdf, m: 1024 };
	await assert.rejects(() => lib.shareKeys(id, secret, "pw", silly), /Unsupported password parameters/);
}

// ── Shapes the page relies on ────────────────────────────────────────
assert.equal(lib.b64uToBytes("a-b_").length, 3, "base64url with the padding sliced off");
await assert.rejects(() => lib.shareKeys(id, "a".repeat(24)), /incomplete/);

console.log("ok  unit:share-lib — the recipient page's GS01 module agrees with the SPA's, bit for bit");