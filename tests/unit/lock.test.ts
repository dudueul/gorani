// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:lock — what "locked" means (docs/SECURITY-REVIEW.md › O2,
 * docs/DECISIONS.md › D15), proven without a browser:
 *
 *   1. the auto-lock decision is a pure function of three numbers — idle
 *      15 minutes OR hidden 5 minutes, each boundary pinned both ways;
 *   2. a locked session is locked for good: every key request is refused,
 *      locking twice is one lock, listeners run exactly once, and only after
 *      the device hold is gone (here: after its deletion settles — Node has
 *      no IndexedDB, so the deletion fails and the lock must still finish).
 */

import assert from "node:assert/strict";
import { autoLockDue, AUTO_LOCK, openSession } from "../../web/src/vault/session.ts";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";

const MIN = 60_000;
const t0 = 1_000_000_000;

// ── 1. The rule, at its edges ───────────────────────────────────────
assert.deepEqual(AUTO_LOCK, { idleMinutes: 15, hiddenMinutes: 5 }, "D15's numbers");
assert.equal(autoLockDue(t0 + 15 * MIN - 1, t0, null), false, "14:59.999 idle, visible: still open");
assert.equal(autoLockDue(t0 + 15 * MIN, t0, null), true, "15:00 idle: locked");
assert.equal(autoLockDue(t0 + 5 * MIN - 1, t0 + 4 * MIN, t0), false, "hidden 4:59.999 (active a minute ago): open");
assert.equal(autoLockDue(t0 + 5 * MIN, t0 + 4 * MIN, t0), true, "hidden 5:00: locked, however recent the last activity");
assert.equal(autoLockDue(t0 + 60 * MIN, t0 + 60 * MIN, null), false, "an hour of steady use, visible: open");
assert.equal(autoLockDue(t0 + 2 * MIN, t0, null, { idleMinutes: 1, hiddenMinutes: 1 }), true, "rules are parameters (tests, future policy)");

// ── 2. The session's lock ───────────────────────────────────────────
const vault = await createCodeVault();
const store = await createStoreKey();
const settings = {
	enabled: true,
	keyId: vault.keyId,
	publicKey: vault.publicKey,
	pqPublicKey: vault.pqPublicKey,
	methods: vault.methods,
	stores: { files: await sealStoreKeyToMember(store, { ec: vault.publicKey, kem: vault.pqPublicKey }) },
} as never;
const session = await openSession("jinu", settings, vault.rootBundle.slice());
assert.equal(session.locked, false);
await session.openStoreKey("files"); // usable while unlocked

let calls = 0;
session.onLock(() => calls++);
const first = session.lock();
// Both checked synchronously, before anything awaits:
assert.equal(session.locked, true, "locked the instant lock() is called");
assert.equal(calls, 0, "listeners wait for the device-hold deletion to settle (it is asynchronous)");
const second = session.lock();
assert.equal(first, second, "locking twice is one lock");
await assert.rejects(() => session.openStoreKey("files"), /locked/, "no key after lock, not even a cached one");
await first;
assert.equal(calls, 1, "listeners ran exactly once");
await session.lock();
assert.equal(calls, 1, "…and never again");

console.log("ok  lock: 15 idle / 5 hidden at the boundaries; locked for good, keys refused, one lock, listeners after the hold is gone");
