// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:kdf-bounds — what a stored KDF setting may ask of this device
 * (web/src/vault/kdf-bounds.ts; docs/SECURITY-REVIEW.md › O8). The numbers
 * come from data the SERVER serves — a vault's password methods, a share
 * link's `kdf` — so they are bounded in both directions, and the list of
 * password methods tried per unlock is capped.
 *
 * Written as the attack: each refused setting is one a hostile server would
 * send, next to the honest one that must still work.
 */

import assert from "node:assert/strict";
import { checkArgon2, checkSalt, ARGON2_BOUNDS, MAX_PASSWORD_METHODS } from "../../web/src/vault/kdf-bounds.ts";
import { ARGON2ID_PARAMS, generateHybridKey, makePasswordMethod, unlockWithMethod } from "../../web/src/vault/vault-crypto.ts";
import { SHARE_ARGON2, shareKeys, newShareId, newShareSecret } from "../../web/src/vault/share-crypto.ts";
import { openRoot, type VaultSettings } from "../../web/src/vault/methods.ts";

// ── 1. The bounds, both ways ────────────────────────────────────────
// What gorani writes (vault passwords, share links) is inside.
checkArgon2(ARGON2ID_PARAMS);
checkArgon2(SHARE_ARGON2);
// OWASP's floor is 19 MiB with 2 passes: one pass at the floor — allowed
// before commit 25 — is now too weak.
checkArgon2({ m: ARGON2_BOUNDS.m.min, t: 2, p: 1 });
assert.throws(() => checkArgon2({ m: 19 * 1024, t: 1, p: 1 }), /Unsupported/, "one pass at 19 MiB is below the floor");
assert.throws(() => checkArgon2({ m: 8 * 1024, t: 10, p: 1 }), /Unsupported/, "8 MiB is too little memory, however many passes");
// The ceiling: a server must not be able to freeze a phone.
checkArgon2({ m: ARGON2_BOUNDS.m.max, t: ARGON2_BOUNDS.t.max, p: ARGON2_BOUNDS.p.max });
assert.throws(() => checkArgon2({ m: 1024 * 1024, t: 3, p: 4 }), /Unsupported/, "1 GiB (allowed before commit 25) is refused");
assert.throws(() => checkArgon2({ m: 64 * 1024, t: 20, p: 4 }), /Unsupported/, "20 passes is refused");
assert.throws(() => checkArgon2({ m: 64 * 1024, t: 3, p: 16 }), /Unsupported/, "16 lanes is refused");
// Shapes a JSON row can smuggle: fractions, strings, missing fields.
assert.throws(() => checkArgon2({ m: 65536.5, t: 3, p: 4 }));
assert.throws(() => checkArgon2({ m: "65536", t: 3, p: 4 } as unknown as { m: number; t: number; p: number }));
assert.throws(() => checkArgon2(undefined));
// Salts: 16–64 bytes.
checkSalt(new Uint8Array(16));
checkSalt(new Uint8Array(64));
assert.throws(() => checkSalt(new Uint8Array(8)), /salt/);
assert.throws(() => checkSalt(new Uint8Array(65)), /salt/);

// ── 2. Where they bite: a password method and a share link ──────────
const root = await generateHybridKey();
const honest = await makePasswordMethod(root.bundle, "correct horse battery staple");
assert.deepEqual(await unlockWithMethod(honest, "correct horse battery staple"), root.bundle, "the honest method opens");
await assert.rejects(unlockWithMethod({ ...honest, argon2: { m: 1024 * 1024, t: 20, p: 16 } }, "correct horse battery staple"), /Unsupported/, "a server-inflated cost is refused BEFORE any Argon2 run");
await assert.rejects(unlockWithMethod({ ...honest, salt: "AAAA" }, "correct horse battery staple"), /salt/, "a 3-byte salt is malformed");
const id = newShareId();
await assert.rejects(shareKeys(id, newShareSecret(), "pw", { salt: btoa("x".repeat(16)), m: 1024 * 1024, t: 3, p: 4 }), /Unsupported/, "a share link's kdf is bounded the same way (the recipient's phone)");

// ── 3. The cap: a row padded with decoy password methods ────────────
// Each try is a full Argon2 run; a server that pads the list with fifty
// methods must not buy fifty runs. The real method in 5th place is never
// reached; moved inside the cap, it opens.
const decoyRoot = await generateHybridKey();
const decoys = await Promise.all(Array.from({ length: MAX_PASSWORD_METHODS }, (_, i) => makePasswordMethod(decoyRoot.bundle, `decoy password number ${i}`)));
const settings = (methods: typeof decoys) => ({ methods }) as unknown as VaultSettings;
await assert.rejects(openRoot(settings([...decoys, honest]), { kind: "password", value: "correct horse battery staple" }), "the 5th password method is past the cap");
const opened = await openRoot(settings([...decoys.slice(0, MAX_PASSWORD_METHODS - 1), honest, ...decoys.slice(MAX_PASSWORD_METHODS - 1)]), { kind: "password", value: "correct horse battery staple" });
assert.equal(opened.methodId, honest.id, "within the cap it opens");

console.log("ok  kdf-bounds: Argon2 floor + ceiling, salts, share links, the password-method cap");
