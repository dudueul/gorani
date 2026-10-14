// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:records — authenticated store-key records (docs/SECURITY-REVIEW.md ›
 * O3, web/src/vault/records.ts), written as the attack it stops.
 *
 * The attacker controls the settings row (a compromised server, a stolen DB
 * write) but not the member's root. Sealing needs only a public key, so the
 * attacker can mint a key pair and seal ITS private half to the victim's
 * root. Before commit 24 the client opened that record and sealed every new
 * upload to the attacker. Now each variant is refused:
 *
 *   1. full substitution (attacker pair, sealed to the victim) → MAC fails
 *   2. a pinned record, public half swapped → MAC fails
 *   3. the victim's own sealed private + the attacker's public → mismatch
 *   4. an unsealed "private key" → refused as plain text
 *   5. a MAC from ANOTHER root → fails
 * …while the honest paths work: a fresh record verifies, a record without a
 * MAC is pinned on first open and verifies thereafter.
 */

import assert from "node:assert/strict";
import { openSession } from "../../web/src/vault/session.ts";
import { createChildVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/family.ts";
import { deriveRecordKey, macRecord, verifyRecord, recordBytes } from "../../web/src/vault/records.ts";
import { importVaultKey } from "../../web/src/vault/vault-crypto.ts";
import { toBase64 } from "../../web/src/lib/encoding.ts";

const victim = await createChildVault();
const victimPublic = { ec: victim.publicKey, kem: victim.pqPublicKey };
const rootKey = await deriveRecordKey(await importVaultKey(victim.rootBundle.slice()));

const honestStore = await createStoreKey();
const honest = await sealStoreKeyToMember(honestStore, victimPublic);
honest.mac = await macRecord(rootKey, "files", honest);
assert.ok(await verifyRecord(rootKey, "files", honest), "an honest record verifies");
assert.ok(!(await verifyRecord(rootKey, "family", honest)), "the record name is bound: a files record cannot pose as another store");

const settingsWith = (files: unknown) => ({ enabled: true, keyId: victim.keyId, publicKey: victim.publicKey, pqPublicKey: victim.pqPublicKey, methods: victim.methods, stores: { files } }) as never;
const open = async (files: unknown) => (await openSession("jinu", settingsWith(structuredClone(files)), victim.rootBundle.slice())).openStoreKey("files");

await open(honest); // the honest path

// 1. Full substitution: the attacker's own pair, private sealed to the victim.
const attackerStore = await createStoreKey();
const forged = await sealStoreKeyToMember(attackerStore, victimPublic);
await assert.rejects(() => open({ ...forged, mac: honest.mac }), /failed authentication/, "1: an attacker key pair sealed to the victim is refused (MAC)");

// 2. A pinned record whose public half is swapped for the attacker's.
await assert.rejects(() => open({ ...honest, publicKey: attackerStore.publicKey, pqPublicKey: attackerStore.pqPublicKey }), /failed authentication/, "2: a swapped public half breaks the MAC");

// 3. No MAC at all (so the pin path runs) — the consistency check stands
// alone: the victim's real sealed private paired with the attacker's public.
const mixed = { keyId: honest.keyId, publicKey: attackerStore.publicKey, pqPublicKey: attackerStore.pqPublicKey, privateKeySealed: honest.privateKeySealed };
await assert.rejects(() => open(mixed), /does not belong to the sealed private key/, "3: a public half that is not the sealed private key's own is refused");
await assert.rejects(() => open({ ...honest, mac: undefined, keyId: "pqAAAAAAAAAAAAAA" }), /key id does not match/, "3b: a key id that is not the key's own is refused");

// 4. An unsealed "private key".
await assert.rejects(() => open({ ...honest, mac: undefined, privateKeySealed: toBase64(attackerStore.bundle) }), /plain text/, "4: an unsealed private key is refused");

// 5. A MAC computed by another root.
const other = await createChildVault();
const otherKey = await deriveRecordKey(await importVaultKey(other.rootBundle.slice()));
const foreignMac = await macRecord(otherKey, "files", honest);
await assert.rejects(() => open({ ...honest, mac: foreignMac }), /failed authentication/, "5: another root's MAC is refused");

// Pinning: a record sealed to us by someone else arrives without a MAC; the
// first open pins it, and the pinned settings verify under our root.
const fromParent = await sealStoreKeyToMember(await createStoreKey(), victimPublic);
const session = await openSession("jinu", settingsWith(structuredClone(fromParent)), victim.rootBundle.slice());
await session.openStoreKey("files");
const pinned = session.takePinned() as unknown as { stores: { files: typeof fromParent } } | null;
assert.ok(pinned?.stores.files.mac, "first open pins the record (trust on first use)");
assert.ok(await verifyRecord(rootKey, "files", pinned!.stores.files), "the pin verifies under the member's root");
assert.equal(session.takePinned(), null, "a pin is reported once");

// The encoding is length-prefixed and fixed — the Rust client computes the same bytes.
const bytes = recordBytes("files", honest);
assert.equal(new DataView(bytes.buffer).getUint32(0), "gorani-store-record-v1".length, "starts with the domain tag's length");

console.log("ok  records: substitution, swapped halves, mismatched pairs, unsealed keys and foreign MACs refused; first-use pinning");
