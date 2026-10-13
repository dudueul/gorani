// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The local index: search quality, encrypted persistence, and the property
 * the user asked for — the snapshot is decryptable only through an unlock
 * ceremony, because its key is derived from the vault root:
 *
 *   different root's key ⇒ different AES key ⇒ the snapshot is noise.
 */

import assert from "node:assert/strict";
import { IndexEngine, type IndexEntry } from "../../web/src/vault/index-engine.ts";
import { generateHybridKey, importVaultKey, deriveIndexKey } from "../../web/src/vault/vault-crypto.ts";


const entry = (id: string, name: string, folderId: string | null = null, age = 0, size = 0): IndexEntry => ({
	id,
	kind: "file",
	folderId,
	name,
	updatedAt: Date.now() - age,
	size,
});

// ── 1. search scoring: prefix > word-start > substring ──────────────
const engine = new IndexEngine();
engine.upsert([
	entry("1", "Beach 2026.jpg", "f1", 1000),
	entry("2", "summer beach trip.jpg", "f1", 500),
	entry("3", "skybeach plans.txt", "f2", 100),
	entry("4", "beachhouse.pdf", "f2", 10),
]);
const hits = engine.search("beach");
assert.equal(hits[0]?.rank, 0, "prefix hits first");
assert.ok(hits.findIndex((h) => h.id === "1") < hits.findIndex((h) => h.id === "2"), "prefix before word-start");
assert.ok(hits.findIndex((h) => h.id === "2") < hits.findIndex((h) => h.id === "3"), "word-start beats mid-word");
assert.ok(hits.some((h) => h.id === "4"));
assert.equal(hits.every((h) => h.name.toLowerCase().includes("beach")), true);

// Case-insensitivity + the empty query.
assert.ok(engine.search("BEACH").length >= 3);
assert.equal(engine.search("").length, 0);

// ── 2. recents: newest first, files only ────────────────────────────
engine.upsert([entry("5", "newest.docx", "f1", 0), { ...entry("6", "some folder", "f1", 0), kind: "folder" }]);
const recents = engine.recents(2);
assert.equal(recents[0]?.id, "5", "the newest file");
assert.ok(recents.every((r) => r.kind === "file"), "folders stay out of recents");

// ── 3. remove (tombstones from the change feed) ─────────────────────
engine.remove(["1"]);
assert.equal(engine.search("beach").some((h) => h.id === "1"), false);

// ── 4. persistence: the snapshot round-trips UNDER THE RIGHT KEY ONLY ─
const vaultA = await generateHybridKey();
const vaultB = await generateHybridKey();
const rootA = await importVaultKey(vaultA.bundle);
const rootB = await importVaultKey(vaultB.bundle);
const keyA = await deriveIndexKey(rootA, vaultA.publicKey);
const keyB = await deriveIndexKey(rootB, vaultB.publicKey);
// The keys are non-extractable by construction (like every AES key the
// vault derives) — they're compared by what they can open, below.

const full = new IndexEngine();
full.upsert([entry("1", "비밀 계약서.pdf", "f9", 5), entry("2", "holiday.mp4", "f8", 6)]);
const plain = full.serialize();

// The worker's save: AES-256-GCM under the session's indexKey.
async function seal(key: CryptoKey, bytes: Uint8Array): Promise<Uint8Array> {
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes as BufferSource);
	const out = new Uint8Array(12 + ct.byteLength);
	out.set(iv, 0);
	out.set(new Uint8Array(ct), 12);
	return out;
}
async function unseal(key: CryptoKey, sealed: Uint8Array): Promise<Uint8Array> {
	const iv = sealed.subarray(0, 12);
	const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, sealed.subarray(12) as BufferSource);
	return new Uint8Array(pt);
}

const snapshot = await seal(keyA, plain);

// The SAME unlock (root A) reads it back perfectly…
const reopened = new IndexEngine();
reopened.load(await unseal(keyA, snapshot));
assert.equal(reopened.search("계약서")[0]?.id, "1", "Hangul survives the round trip");
assert.equal(reopened.search("holiday")[0]?.id, "2");

// …and a DIFFERENT member's unlock (root B) reads nothing but noise.
await assert.rejects(() => unseal(keyB, snapshot), /decrypt|operation|failed/i, "a foreign key opens nothing");
// …and a flipped byte in the stored snapshot is refused (GCM).
const tampered = snapshot.slice();
tampered[tampered.length - 5] ^= 0x08;
await assert.rejects(() => unseal(keyA, tampered));

console.log("ok  index: search scoring, recents, tombstones, unlock-gated encrypted snapshots");