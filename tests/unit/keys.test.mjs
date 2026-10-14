// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:keys — vaults and store keys, the compositions every area is built
 * from (web/src/vault/keys.ts; until commit 27c, unit:family, which also
 * walked the family edition's master key — gone, with the rule it served:
 * a parent opening a child's area. Who else may open an area is now a case
 * grant (api:cases) or a recovery ceremony (api:recovery)).
 *
 *   a vault: a hybrid root, unlocked by its password or its recovery code;
 *   a store key sealed to the member's root opens with that root only;
 *   a record whose halves do not belong together is refused;
 *   values sealed into an area's places open in that area only.
 */

import assert from "node:assert/strict";
import { createVault, createCodeVault, createStoreKey, sealStoreKeyToMember, openStoreKey } from "../../web/src/vault/keys.ts";
import { importVaultKey, importContentKey, unlockWithMethod, wrapPlacedKey, unwrapPlacedKey, sealPlacedText, openPlacedText, sealWith, openWith, newContentKey, passwordProblem } from "../../web/src/vault/vault-crypto.ts";
import { places } from "../../web/src/vault/places.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const hybridPublicOf = (v) => ({ ec: v.publicKey, kem: v.pqPublicKey });

// ── 1. Vaults ───────────────────────────────────────────────────────
const ana = await createVault("correct horse battery staple 42");
const bo = await createCodeVault();
assert.ok(passwordProblem("short1") && !passwordProblem("correct horse battery staple 42"));
assert.equal(ana.methods.length, 2, "a password and a recovery code");
assert.equal(bo.methods.length, 1, "a code vault: one 40-character code");
const viaPassword = await unlockWithMethod(ana.methods[0], "correct horse battery staple 42");
const viaCode = await unlockWithMethod(ana.methods[1], ana.recoveryCode);
assert.deepEqual(viaPassword, viaCode, "both methods open the same root");
await assert.rejects(() => unlockWithMethod(ana.methods[0], "wrong password, long enough"));
const anaRoot = await importVaultKey(viaPassword);
const boRoot = await importVaultKey(await unlockWithMethod(bo.methods[0], bo.recoveryCode));

// ── 2. A store key sealed to a member's root ────────────────────────
const store = await createStoreKey();
const own = await sealStoreKeyToMember(store, hybridPublicOf(bo));
const boStore = await openStoreKey(boRoot, own);
await assert.rejects(() => openStoreKey(anaRoot, own), "another member's root opens nothing — a lead's included");
// A record whose public halves are someone else's: refused (O3).
const other = await createStoreKey();
await assert.rejects(() => openStoreKey(boRoot, { ...own, publicKey: other.publicKey }), /does not belong/);
await assert.rejects(() => openStoreKey(boRoot, { ...own, privateKeySealed: "plain text" }), "an unsealed private key is refused");

// ── 3. Values live in their area's places ───────────────────────────
const sealer = await importVaultKey(store.bundle.slice());
const ck = newContentKey();
const keySealed = await wrapPlacedKey(sealer, places.fileKey("bo", "diary", 1), ck);
const nameSealed = await sealPlacedText(sealer, places.fileName("bo", "diary"), "diary.txt");
const key = await unwrapPlacedKey(boStore, places.fileKey("bo", "diary", 1), keySealed);
assert.equal(dec.decode(await openWith(key, await sealWith(await importContentKey(ck), enc.encode("2026-10-13")))), "2026-10-13");
assert.equal(await openPlacedText(boStore, places.fileName("bo", "diary"), nameSealed), "diary.txt");
await assert.rejects(() => openPlacedText(boStore, places.fileName("case:ir-1", "diary"), nameSealed), "the same key, another area's place: refused");
await assert.rejects(() => unwrapPlacedKey(boStore, places.fileKey("bo", "diary", 2), keySealed), "version 1's key is not version 2's");

console.log("ok  keys: vaults open by password or code, store keys by their member's root only, mismatched records refused, values stay in their area's places");
