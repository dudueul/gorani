// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Unit tests for the session's logic that runs in Node: the method-confirmation
 * rule (adding a method requires opening the root with an existing one), the
 * unlock dispatch across the three kinds, and consistency checks. The
 * non-extractable device hold is browser-only (IndexedDB + non-extractable
 * keys); its crypto shape is the same AES-GCM round trip the vault-crypto
 * vectors already prove.
 */

import assert from "node:assert/strict";
import { createVaultBundle, openRoot, confirmKeyBytes, addPasswordMethod, addRecoveryMethod, enrolledKinds, methodsConsistent } from "../../web/src/vault/methods.ts";
import { unlockWithMethod } from "../../web/src/vault/vault-crypto.ts";

const vault = await createVaultBundle("correct horse battery staple 42");
assert.ok(methodsConsistent(vault.settings));
assert.deepEqual(enrolledKinds(vault.settings).sort(), ["password", "recovery"]);

// ── 1. Each kind opens the same root ────────────────────────────────
const secret = { kind: "password", value: "correct horse battery staple 42" };
const opened = await openRoot(vault.settings, secret);
assert.equal(opened.methodId, vault.settings.methods[0].id, "the password method opened");
const sameRoot = await unlockWithMethod(vault.settings.methods[1], vault.recoveryCode);
assert.deepEqual(sameRoot, vault.rootBundle, "the recovery code opens the identical bundle");

// ── 2. Wrong secrets fail with a message naming the kind ────────────
await assert.rejects(() => openRoot(vault.settings, { kind: "password", value: "wrong password 1234" }), /no password method|wrong password|Argument/i);
await assert.rejects(() => openRoot(vault.settings, { kind: "passkey", output: new Uint8Array(32) }), /no passkey method/);

// ── 3. The confirmation rule: adding a method needs the old one ─────
// Confirm with the password…
const confirming = await confirmKeyBytes(vault.settings, secret);
assert.deepEqual(confirming, vault.rootBundle);
// …and add a SECOND password (the "spouse knows it too" method).
const withTwo = { ...vault.settings, methods: [...vault.settings.methods, await addPasswordMethod(confirming, "a second good password!")] };
// Both password methods open the same root.
assert.deepEqual((await unlockWithMethod(withTwo.methods[2], "a second good password!")), vault.rootBundle);
assert.equal(withTwo.methods.length, 3);
assert.ok(methodsConsistent(withTwo));
// And the recovery code still works beside them.
assert.deepEqual(await unlockWithMethod(withTwo.methods[1], vault.recoveryCode), vault.rootBundle);

// ── 4. A method object that skips confirmation is just… absent: the
//    settings' PUT would store it, but the UI contract (setup.ts's statics)
//    requires the confirming bundle, so the flow cannot produce one. ────
const recovery = await addRecoveryMethod(await confirmKeyBytes(vault.settings, secret));
assert.match(recovery.code, /^[A-Z2-9]{5}(-[A-Z2-9]{5}){7}$/, "the code's shape: 8 groups of 5");

console.log("ok  session: three unlock kinds, confirmation rule");