// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:identity — member identity keys, pins, certificates and the one-hop
 * trust rule (web/src/vault/identity.ts, docs/CASES.md › Member identity
 * keys). Written as the server's attempts, each refused:
 *
 *   a pin the member never made → the record's MAC breaks;
 *   a registry entry with a swapped root digest → its self-signature fails;
 *   a certificate from someone the member never verified → ignored;
 *   a certificate two hops away → ignored (one hop, by design);
 *   a root that is not the one the identity names → refused before sealing;
 *   a grant signature replayed as a certificate → a different statement.
 */

import assert from "node:assert/strict";
import { buildTrust, certify, createIdentity, fingerprint, hybridDigest, identityKeyId, openIdentity, pin, statements, stmt, trustedRoot, type RegistryIdentity } from "../../web/src/vault/identity.ts";
import { createChildVault } from "../../web/src/vault/family.ts";
import { importVaultKey } from "../../web/src/vault/vault-crypto.ts";

/** A member with a root and an identity, as the registry would list them. */
async function member(id: string) {
	const vault = await createChildVault();
	const root = await importVaultKey(vault.rootBundle.slice());
	const rootPublic = { ec: vault.publicKey, kem: vault.pqPublicKey };
	const made = await createIdentity(id, root, rootPublic);
	const entry: RegistryIdentity = { member: id, ...made.registry, certs: [] };
	return { id, root, rootPublic, record: made.record, signer: made.signer, entry, vault };
}

// ── 1. Statements have one spelling, and domains never cross ────────
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
assert.ok(!eq(stmt("d", "ab", "c"), stmt("d", "a", "bc")), "length prefixes: (ab, c) and (a, bc) are two statements");
assert.ok(!eq(statements.grant("m", "k", "r"), statements.cert("m", "k", "r")), "a grant signature is never a certificate");
assert.ok(!eq(statements.cert("m", "k", "r"), statements.identity("m", "k", "r")), "a certificate is never a self-signature");

// ── 2. An identity: id, fingerprint, the sealed private half ────────
const lead = await member("ana");
assert.equal(lead.record.keyId, await identityKeyId(lead.record.publicKey));
assert.match(lead.record.keyId, /^[0-9a-f]{64}$/);
assert.match(fingerprint(lead.record.keyId), /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/, "eight groups of four, readable aloud");
assert.ok(lead.record.privateKeySealed.startsWith("GV0"), "the private half is sealed to the root");
assert.equal(lead.entry.rootDigest, await hybridDigest(lead.rootPublic.ec, lead.rootPublic.kem));
const reopened = await openIdentity("ana", lead.root, lead.record);
const probe = statements.grant("ir-1", "d".repeat(64), "bo");
assert.ok(await (await buildTrust("ana", lead.root, lead.record, [lead.entry])).of("ana")!.verify(probe, await reopened.sign(probe)), "the reopened key signs as the registered one");

// ── 3. Pins: the member's decision, MAC'd by their root ─────────────
const bo = await member("bo");
const forged = { ...bo.record, pins: [...bo.record.pins, { member: "mallory", keyId: "f".repeat(64) }] };
await assert.rejects(openIdentity("bo", bo.root, forged), /does not verify/, "a pin the member never made breaks the MAC");
await assert.rejects(buildTrust("bo", bo.root, forged, []), /does not verify/);
await assert.rejects(openIdentity("cy", bo.root, bo.record), /does not verify/, "a record is bound to its member");
const boPinned = await pin("bo", bo.root, bo.record, { member: "ana", keyId: lead.record.keyId }); // bo compared ana's fingerprint

// ── 4. Trust: pins, then ONE hop of certificates ────────────────────
const cy = await member("cy"); // certified by ana → trusted via ana
const dee = await member("dee"); // certified by an outsider → not trusted
const eve = await member("eve"); // certified by cy (two hops from bo) → not trusted
const out = await member("out"); // nobody vouches
cy.entry.certs.push({ by: "ana", ...(await certify(lead.signer, cy.entry)) });
dee.entry.certs.push({ by: "out", ...(await certify(out.signer, dee.entry)) });
eve.entry.certs.push({ by: "cy", ...(await certify(cy.signer, eve.entry)) });
const registry = [lead.entry, bo.entry, cy.entry, dee.entry, eve.entry, out.entry];
const trust = await buildTrust("bo", bo.root, boPinned, registry);
assert.equal(trust.of("bo")?.via, "pin", "yourself");
assert.equal(trust.of("ana")?.via, "pin", "the lead bo verified in person");
assert.equal(trust.of("cy")?.via, "cert:ana", "one hop: certified by a pinned lead");
assert.equal(trust.of("dee"), null, "a certificate from someone bo never verified counts for nothing");
assert.equal(trust.of("eve"), null, "two hops: cy is trusted, but only through a certificate — no chains");
assert.equal(trust.of("out"), null);

// ── 5. The server's swaps ───────────────────────────────────────────
// (a) Swap cy's root digest in the registry (to seal grants to its own root).
const swapped = { ...cy.entry, rootDigest: "0".repeat(64) };
assert.equal((await buildTrust("bo", bo.root, boPinned, [lead.entry, bo.entry, swapped])).of("cy"), null, "a swapped root breaks the self-signature");
// (b) …and with a fresh self-signature by a key of its own: a new identity
// key id, which ana's certificate does not name.
const impostor = await member("cy");
const forgedCy = { ...impostor.entry, certs: cy.entry.certs };
assert.equal((await buildTrust("bo", bo.root, boPinned, [lead.entry, bo.entry, forgedCy])).of("cy"), null, "a new identity needs a new certificate");
// (c) Offer a root that is not the one cy's identity names.
await trustedRoot(trust, { member: "cy", publicKey: cy.rootPublic.ec, pqPublicKey: cy.rootPublic.kem }); // the real one: fine
await assert.rejects(trustedRoot(trust, { member: "cy", publicKey: impostor.rootPublic.ec, pqPublicKey: impostor.rootPublic.kem }), /not the one their identity names/);
await assert.rejects(trustedRoot(trust, { member: "dee", publicKey: dee.rootPublic.ec, pqPublicKey: dee.rootPublic.kem }), /not verified/);
// (d) A certificate's signature re-labelled as a grant does not verify.
const certSig = cy.entry.certs[0]!.signature;
assert.equal(await trust.of("ana")!.verify(statements.grant(cy.entry.member, cy.entry.keyId, cy.entry.rootDigest), certSig), false);

console.log("ok  identity: one-spelling statements, MAC'd pins, self-signed entries, one-hop certificates, swapped roots and keys refused");
