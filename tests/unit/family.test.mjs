// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The family key hierarchy, end to end (docs/FAMILY.md, Lesson 6): two
 * parents, two children, one master key, one family shared area. The test
 * walks the whole life of the family — creation, a parent opening a child's
 * file, the denials that must stay denials, the rotations — because this is
 * the part of gorani that has no Mailflare ancestor to learn from.
 */

import assert from "node:assert/strict";
import {
	createParentVault,
	createChildVault,
	createParentsMaster,
	sealMasterToParent,
	openMaster,
	createStoreKey,
	sealStoreKeyToMember,
	sealStoreKeyToMaster,
	openStoreKey,
	openChildStoreKey,
	sealFamilyStoreKey,
	makeGuardianEnrolmentMethod,
	rotateMaster,
	rotateChildStoreKey,
	rotateFamilyStoreKey,
} from "../../web/src/vault/family.ts";
import {
	importVaultKey,
	importContentKey,
	unlockWithMethod,
	wrapContentKey,
	unwrapContentKey,
	rewrapContentKey,
	sealText,
	openText,
	sealWith,
	openWith,
	newContentKey,
	passwordProblem,
} from "../../web/src/vault/vault-crypto.ts";
import { fromBase64, toBase64 } from "../../web/src/lib/encoding.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const rootPrivateOf = async (v) => importVaultKey(v.rootBundle);
const hybridPublicOf = (v) => ({ ec: v.publicKey, kem: v.pqPublicKey });

// ── 1. The family is created ────────────────────────────────────────
const parentA = await createParentVault("correct horse battery staple 42");
const parentB = await createParentVault("a different long password!");
const kid1 = await createChildVault();
const kid2 = await createChildVault();
assert.ok(passwordProblem("short1") && !passwordProblem("correct horse battery staple 42"));

// Roots from the bundles (as an unlocked browser would hold them).
const aRoot = await rootPrivateOf(parentA);
const kid1Root = await rootPrivateOf(kid1);

// ── 2. The master key, sealed to each parent's root ─────────────────
const master = await createParentsMaster();
const aMasterSealed = await sealMasterToParent(master, hybridPublicOf(parentA));
const bMasterSealed = await sealMasterToParent(master, hybridPublicOf(parentB));

// ── 3. Store keys: each member's files; the children double-sealed ──
const k1Store = await createStoreKey();
const k2Store = await createStoreKey();
const k1Own = await sealStoreKeyToMember(k1Store, hybridPublicOf(kid1));
const k2Own = await sealStoreKeyToMember(k2Store, hybridPublicOf(kid2));
const k1Guardian = await sealStoreKeyToMaster(k1Store, master);
const k2Guardian = await sealStoreKeyToMaster(k2Store, master);
assert.equal(k1Guardian.masterKeyId, master.keyId);

// The family shared area: one key, a copy sealed to every member's root.
const familyStore = await createStoreKey();
const familyKeys = await sealFamilyStoreKey(familyStore, [hybridPublicOf(parentA), hybridPublicOf(parentB), hybridPublicOf(kid1), hybridPublicOf(kid2)]);

// ── 4. A file lands in kid1's area (sealed to kid1's store key) ─────
const fileKey = newContentKey();
const fileBytes = enc.encode("my diary for 2026-10-13");
const fileKeySealed = await wrapContentKey(hybridPublicOf({ publicKey: k1Store.publicKey, pqPublicKey: k1Store.pqPublicKey }), fileKey);
const fileNameSealed = await sealText(hybridPublicOf({ publicKey: k1Store.publicKey, pqPublicKey: k1Store.pqPublicKey }), "diary.txt");

// ── 5. Parent A opens kid1's file: root → master → kid store → key ──
const aOpenedMaster = await openMaster(aRoot, aMasterSealed);
const k1StoreByParent = await openChildStoreKey(aRoot, aMasterSealed, k1Guardian);
const openedKey = await unwrapContentKey(k1StoreByParent, fileKeySealed);
assert.equal(dec.decode(await openWith(openedKey, await sealWith(openedKey, fileBytes))), dec.decode(fileBytes));
assert.equal(await openText(k1StoreByParent, fileNameSealed), "diary.txt");
// The opened master is the same key either parent holds.
const bOpenedMaster = await openMaster(await rootPrivateOf(parentB), bMasterSealed);
const bStore = await openChildStoreKey(await rootPrivateOf(parentB), bMasterSealed, k1Guardian);
assert.deepEqual(await unwrapContentKey(bStore, fileKeySealed), openedKey);
void bOpenedMaster;

// ── 6. Kid1 opens their own file without any master ─────────────────
const k1StoreOwn = await openStoreKey(kid1Root, k1Own);
assert.deepEqual(await unwrapContentKey(k1StoreOwn, fileKeySealed), openedKey);

// ── 7. The denials that must stay denials ───────────────────────────
// kid1 cannot open parentA's store key (sealed to parentA's root).
const aStoreForA = await createStoreKey();
const aOwn = await sealStoreKeyToMember(aStoreForA, hybridPublicOf(parentA));
await assert.rejects(() => openStoreKey(kid1Root, aOwn));
// kid1 cannot open kid2's store — neither their own copy nor the guardianship copy.
await assert.rejects(() => openStoreKey(kid1Root, k2Own));
await assert.rejects(() => openStoreKey(kid1Root, k2Guardian));
// kid1 cannot open the master through their own root.
await assert.rejects(() => openMaster(kid1Root, aMasterSealed));

// ── 8. The family shared area: everyone reads ───────────────────────
const familyContent = enc.encode("family rules");
const familyKey = newContentKey();
const familyKeyImported = await importContentKey(familyKey);
const familyContentSealed = await wrapContentKey(hybridPublicOf({ publicKey: familyStore.publicKey, pqPublicKey: familyStore.pqPublicKey }), familyKey);
// A probe sealed under the raw key; each member's copy must open it.
const probe = await sealWith(familyKeyImported, familyContent);
for (const [name, vault, idx] of [["parent A", parentA, 0], ["parent B", parentB, 1], ["kid1", kid1, 2], ["kid2", kid2, 3]]) {
	const storePrivate = await openStoreKey(await rootPrivateOf(vault), familyKeys[idx]);
	const k = await unwrapContentKey(storePrivate, familyContentSealed);
	assert.equal(dec.decode(await openWith(k, probe)), dec.decode(familyContent), name);
}
// (kids *writing* there is stopped by the server's role policy, not crypto.)

// ── 9. The guardian enrolment code: a parent regains kid1's vault ───
const guardian = await makeGuardianEnrolmentMethod(kid1.rootBundle, "Mom's laptop");
const opened = await unlockWithMethod(guardian.method, guardian.code);
assert.deepEqual(opened, kid1.rootBundle, "the enrolment code opens kid1's root");
// …and the child's own code still works beside it.
assert.deepEqual(await unlockWithMethod(kid1.methods[0], kid1.recoveryCode), kid1.rootBundle);

// ── 10. kid1's store key rotated by a parent alone ──────────────────
const rotated = await rotateChildStoreKey(master, hybridPublicOf(kid1));
const newContentSealed = await wrapContentKey(hybridPublicOf({ publicKey: rotated.key.publicKey, pqPublicKey: rotated.key.pqPublicKey }), fileKey);
const k1StoreRotated = await openChildStoreKey(aRoot, aMasterSealed, rotated.guardian);
assert.deepEqual(await unwrapContentKey(k1StoreRotated, newContentSealed), openedKey, "parent opens the rotated key");
assert.deepEqual(await unwrapContentKey(await openStoreKey(kid1Root, rotated.own), newContentSealed), openedKey, "kid opens the rotated key");
// The old copy no longer exists in settings (the caller replaces both).

// ── 11. Parent B is revoked: the master rotates ─────────────────────
// The caller collects each child's store bundle with the OLD master first.
const bundles = [];
for (const g of [k1Guardian, k2Guardian]) {
	bundles.push(fromBase64(await openText(bOpenedMaster ?? (await openMaster(aRoot, aMasterSealed)), g.storeSealed)));
}
const rotation = await rotateMaster([hybridPublicOf(parentA)], bundles);
assert.equal(rotation.parentSealed.length, 1);
assert.equal(rotation.childGuardians.length, 2);
// Parent A re-sealed to the new master; the children re-sealed to its public half.
const aNewMaster = await openMaster(aRoot, rotation.parentSealed[0]);
const k1StoreAfter = await openChildStoreKey(aRoot, rotation.parentSealed[0], rotation.childGuardians[0]);
assert.deepEqual(await unwrapContentKey(k1StoreAfter, fileKeySealed), openedKey, "the chain still opens after rotation");
void aNewMaster;

// ── 12. A member leaves: the family shared area rotates ─────────────
// Deactivation alone closes nothing: the departing member's root holds
// their copy of the family store key, and new family-area files would
// stay readable to them. The rotation (docs/FAMILY.md › Removing a
// member) runs BEFORE deactivation — a fresh pair sealed to the remaining
// roots, every content key re-wrapped — and afterwards their material
// opens nothing at all.
const familyArea = await createStoreKey();
const familyCopies = await sealFamilyStoreKey(familyArea, [hybridPublicOf(parentA), hybridPublicOf(kid1), hybridPublicOf(kid2)]);
const familyPrivOld = await openStoreKey(aRoot, familyCopies[0]);
const areaKey = newContentKey();
const areaCk = await importContentKey(areaKey);
const areaSealed = await wrapContentKey(hybridPublicOf(familyArea), areaKey);
const areaPlain = enc.encode("family photo bytes");
const areaData = await sealWith(areaCk, areaPlain);
assert.deepEqual(dec.decode(await openWith(await unwrapContentKey(familyPrivOld, areaSealed), areaData)), dec.decode(areaPlain), "baseline: the family area opens");

// kid1 leaves. The parent rotates to a fresh pair sealed to the remaining roots…
const familyRotation = await rotateFamilyStoreKey([hybridPublicOf(parentA), hybridPublicOf(kid2)]);
assert.equal(familyRotation.copies.length, 2);
// …re-wraps the content key to the new public half — the canonical walk
// (`rewrapContentKey`: open the old wrap with the old private half, seal
// to the new public half; exactly what files/reseal stores)…
const areaRewrapped = await rewrapContentKey(familyPrivOld, hybridPublicOf(familyRotation.key), areaSealed);
// …and from here the departing member's material opens nothing:
await assert.rejects(() => openStoreKey(kid1Root, familyRotation.copies[0]), "their root opens none of the new copies");
await assert.rejects(() => unwrapContentKey(familyPrivOld, areaRewrapped), "their old store key unwraps no re-wrapped key");
// The remaining family keeps reading everything.
const familyPrivNew = await openStoreKey(aRoot, familyRotation.copies[0]);
assert.deepEqual(dec.decode(await openWith(await unwrapContentKey(familyPrivNew, areaRewrapped), areaData)), dec.decode(areaPlain), "the family keeps reading; the leaver does not");

console.log("ok  family: hierarchy, denials, enrolment code, rotations, member removal");