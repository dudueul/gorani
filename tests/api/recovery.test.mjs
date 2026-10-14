// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:recovery — M-of-N leads recovery (commit 27, docs/CASES.md › Recovery
 * and › The protocol, concretely; web/src/vault/recovery.ts). The story:
 *
 *   1. a lead sets up the team recovery key: one Shamir share per lead,
 *      2-of-3; the registry insists on EVERY lead and M ≥ 2;
 *   2. area holders seal recovery copies — a member for their own area, a
 *      manager for a case — only to a recovery key whose signature verifies;
 *   3. the lead who managed a case leaves; a ceremony (coordinator + one
 *      more lead) recovers the case to a new manager. The server's swaps —
 *      the ceremony's key, a share — are caught by the leads' clients;
 *   4. an analyst loses every unlock method; they re-enrol a new root, a
 *      ceremony seals their own area to it after they read its fingerprint
 *      aloud, and their files open under the new root; their old identity
 *      and devices go;
 *   5. every completed ceremony marks the recovery key "rotation required";
 *      a rotation cancels open ceremonies and leaves old copies visibly stale.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, importVaultKey, openSealedText } from "../../web/src/vault/vault-crypto.ts";
import { createCodeVault, createStoreKey, sealStoreKeyToMember, openStoreKey } from "../../web/src/vault/keys.ts";
import { newCase, openCaseKey, openCaseTitle } from "../../web/src/vault/cases.ts";
import { buildTrust, certify, createIdentity, hybridDigest, pin } from "../../web/src/vault/identity.ts";
import { approveCeremony, combineCeremony, newCeremony, recoverCaseGrant, recoverMemberStore, sealRecoveryCopy, setupRecovery, trustedRecoveryKey } from "../../web/src/vault/recovery.ts";
import { decode, encode } from "../../web/src/vault/shamir.ts";
import { fromBase64, toBase64 } from "../../web/src/lib/encoding.ts";
import { storeSealer } from "../lib/placed.mjs";
import { signedHash, signedIntake } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();
const as = (who) => ({
	get: (path) => api(dev.base, "GET", path, { email: who.email }),
	send: (method, path, body) => api(dev.base, method, path, { email: who.email, body }),
});

/** A member with a root, an own files store and an identity. */
async function join(id, role, by, extra = {}) {
	const email = `${id}@team.test`;
	const added = await api(dev.base, "POST", "/api/v1/family/members", { email: by ?? email, body: { id, name: id, role, emails: [email], ...extra } });
	assert.equal(added.status, 200, `add ${id}: ${added.text}`);
	const vault = await createCodeVault();
	const root = await importVaultKey(vault.rootBundle.slice());
	const rootPublic = { ec: vault.publicKey, kem: vault.pqPublicKey };
	const store = await createStoreKey();
	const storeB64 = toBase64(store.bundle);
	const made = await createIdentity(id, root, rootPublic);
	const settings = { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, stores: { files: await sealStoreKeyToMember(store, rootPublic) }, identity: made.record };
	assert.equal((await api(dev.base, "PUT", `/api/v1/members/${id}/vault`, { email, body: { settings } })).status, 200);
	assert.equal((await api(dev.base, "PUT", "/api/v1/family/identity", { email, body: made.registry })).status, 200);
	return { id, email, root, rootPublic, settings, record: made.record, signer: made.signer, storeB64 };
}
const entryOf = async (by, id) => (await as(by).get("/api/v1/family/identities")).json.identities.find((e) => e.member === id);
async function pinIdentity(who, other) {
	who.record = await pin(who.id, who.root, who.record, { member: other.id, keyId: other.record.keyId });
	who.settings = { ...who.settings, identity: who.record };
	assert.equal((await api(dev.base, "PUT", `/api/v1/members/${who.id}/vault`, { email: who.email, body: { settings: who.settings } })).status, 200);
}
const trustOf = async (who) => buildTrust(who.id, who.root, who.record, (await as(who).get("/api/v1/family/identities")).json.identities);
const rootOf = async (by, id) => (await as(by).get(`/api/v1/members/${id}/root`)).json;
const recoveryAs = async (who) => (await as(who).get("/api/v1/recovery")).json;

async function upload(who, base, fields, file) {
	const boundary = `r${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, json: await r.json() };
}
async function putFile(who, base, sealer, name) {
	const ck = newContentKey();
	const f = await sealer.newFile(name, "text/plain", ck);
	// (Signed by the uploader: the case is evidence, commit 29d.)
	const r = await upload(who, base, { ...f.fields, size: "4", hash: await signedHash(who, sealer, f.id, 1, enc.encode("data")), intake: await signedIntake(who, sealer, f.id) }, await sealWith(await importContentKey(ck), enc.encode("data")));
	assert.equal(r.status, 200, JSON.stringify(r.json));
	return f.id;
}

try {
	// ── 0. The team: three leads, an analyst, an auditor, an external ────
	const ana = await join("ana", "lead");
	const lu = await join("lu", "lead", ana.email);
	const mo = await join("mo", "lead", ana.email);
	const bo = await join("bo", "analyst", ana.email);
	const cy = await join("cy", "auditor", ana.email);
	const ext = await join("ext", "external", ana.email, { expiresAt: new Date(Date.now() + 86_400_000).toISOString() });
	// Each member compares fingerprints with TWO leads (ana and lu): when one
	// leaves, the other still anchors their trust.
	for (const certifier of [ana, lu]) {
		for (const who of [ana, lu, mo, bo, cy, ext]) {
			if (who === certifier) continue;
			assert.equal((await as(certifier).send("PUT", `/api/v1/family/members/${who.id}/cert`, await certify(certifier.signer, await entryOf(certifier, who.id)))).status, 200);
			if (!who.record.pins.some((p) => p.member === certifier.id)) await pinIdentity(who, certifier);
		}
	}

	// ── 1. Setup: every lead holds a share, 2-of-3 ──────────────────────
	const leadRoots = await Promise.all(["ana", "lu", "mo"].map((id) => rootOf(ana, id)));
	const anaTrust = await trustOf(ana);
	const body = await setupRecovery(ana.signer, anaTrust, leadRoots, 2);
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery", body)).status, 403, "only a lead sets it up");
	assert.equal((await as(ana).send("PUT", "/api/v1/recovery", { ...(await setupRecovery(ana.signer, anaTrust, leadRoots.slice(0, 2), 2)) })).status, 409, "every lead gets a share — no hand-picked subset");
	assert.equal((await as(ana).send("PUT", "/api/v1/recovery", { ...body, threshold: 1 })).status, 400, "M ≥ 2: never one person");
	assert.equal((await as(ana).send("PUT", "/api/v1/recovery", { ...body, threshold: 4 })).status, 400, "M ≤ N");
	assert.equal((await as(ana).send("PUT", "/api/v1/recovery", body)).status, 200);
	let rec = (await recoveryAs(lu)).recovery;
	assert.equal(rec.threshold, 2);
	assert.deepEqual(rec.holders, ["ana", "lu", "mo"]);
	assert.ok((await recoveryAs(lu)).myShare, "a lead sees their own sealed share");
	assert.equal((await recoveryAs(bo)).myShare, null, "an analyst holds none");
	assert.equal((await as(ext).get("/api/v1/recovery")).status, 403, "externals hold no area key to recover");
	const share = decode(await openSealedText(lu.root, (await recoveryAs(lu)).myShare));
	assert.equal(share.threshold, 2, "lu's share opens with lu's root: an SH01 share of a 2-of-N split");

	// The server's swap: its own recovery public key under ana's record.
	const fakeKey = await createStoreKey();
	await assert.rejects(trustedRecoveryKey(await trustOf(bo), { ...rec, publicKey: { ec: fakeKey.publicKey, kem: fakeKey.pqPublicKey } }), /do not match its digest/);
	await assert.rejects(trustedRecoveryKey(await trustOf(bo), { ...rec, publicKey: { ec: fakeKey.publicKey, kem: fakeKey.pqPublicKey }, digest: await hybridDigest(fakeKey.publicKey, fakeKey.pqPublicKey) }), /signature does not verify/, "…with a matching digest: the signature fails");

	// ── 2. Recovery copies ──────────────────────────────────────────────
	const boCopy = await sealRecoveryCopy(await trustOf(bo), rec, bo.storeB64);
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery/copies", { area: "cy", ...boCopy })).status, 403, "a member writes only their own area's copy");
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery/copies", { area: "bo", ...boCopy, keyId: "old" })).status, 409, "a copy names the current recovery key");
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery/copies", { area: "bo", ...boCopy })).status, 200);
	const boSealer = await storeSealer(fromBase64(bo.storeB64), "bo");
	const boFile = await putFile(bo, "/api/v1/members/bo", boSealer, "notes.txt");

	// A case only ana manages.
	const opened = await newCase("ir-7", "evidence", "Wire fraud", ana.rootPublic, ana.signer);
	assert.equal((await as(ana).send("POST", "/api/v1/cases", opened.body)).status, 200);
	const caseRow = (await as(ana).get("/api/v1/cases")).json.cases[0];
	const caseB64 = await openSealedText(ana.root, caseRow.grant.keySealed);
	const caseSealer = await storeSealer(fromBase64(caseB64), "case:ir-7");
	const caseFile = await putFile(ana, "/api/v1/cases/ir-7", caseSealer, "wire-transfer.pdf");
	const caseCopy = await sealRecoveryCopy(anaTrust, rec, caseB64);
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery/copies", { area: "case:ir-7", ...caseCopy })).status, 403, "a case's copy is its manager's to write");
	assert.equal((await as(ana).send("PUT", "/api/v1/recovery/copies", { area: "case:ir-7", ...caseCopy })).status, 200);
	assert.equal((await as(lu).get("/api/v1/recovery/copies")).json.copies.length, 2, "leads see the coverage");
	assert.equal((await as(bo).get("/api/v1/recovery/copies")).status, 403);

	// ── 3. A ceremony for the case its manager left behind ──────────────
	assert.equal((await api(dev.base, "POST", "/api/v1/family/members/ana/deactivate", { email: lu.email })).status, 200);
	assert.equal((await as(lu).get("/api/v1/cases/ir-7/files/list")).status, 403, "nobody left on the case");
	rec = (await recoveryAs(lu)).recovery;
	assert.equal(rec.rotationRequired, true, "a holder left: the recovery key is owed a rotation (but still usable)");
	const cer = await newCeremony(lu.signer, rec, "case:ir-7", "ana left; ir-7 has no manager");
	assert.equal((await as(bo).send("POST", "/api/v1/recovery/ceremonies", cer.body)).status, 403, "only a lead coordinates");
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", { ...cer.body, target: "case:nope" })).status, 404);
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", cer.body)).status, 200);
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", { ...cer.body, id: "another" })).status, 409, "one open ceremony per target");
	const listed = async () => (await as(mo).get("/api/v1/recovery/ceremonies")).json.ceremonies.find((c) => c.id === cer.body.id);
	assert.equal((await as(cy).get("/api/v1/recovery/ceremonies")).status, 200, "auditors watch ceremonies");
	assert.equal((await as(lu).get(`/api/v1/recovery/ceremonies/${cer.body.id}/material`)).status, 409, "no material before M approvals");

	// mo approves — after checking the ceremony is lu's. The server's swap of
	// the ceremony key would have collected mo's share; mo's client refuses.
	const moShare = (await recoveryAs(mo)).myShare;
	const theirs = await createStoreKey();
	const swapped = { ...(await listed()), ephemeralPublic: { ec: theirs.publicKey, kem: theirs.pqPublicKey } };
	await assert.rejects(approveCeremony(mo.root, await trustOf(mo), swapped, rec, moShare), /does not match its digest/);
	await assert.rejects(approveCeremony(mo.root, await trustOf(mo), { ...swapped, ephemeralDigest: await hybridDigest(theirs.publicKey, theirs.pqPublicKey) }, rec, moShare), /signature does not verify/, "…a matching digest: lu's signature fails");
	assert.equal((await as(bo).send("PUT", `/api/v1/recovery/ceremonies/${cer.body.id}/shares`, await approveCeremony(mo.root, await trustOf(mo), await listed(), rec, moShare))).status, 403, "only share holders approve");
	assert.equal((await as(mo).send("PUT", `/api/v1/recovery/ceremonies/${cer.body.id}/shares`, await approveCeremony(mo.root, await trustOf(mo), await listed(), rec, moShare))).status, 200);
	assert.equal((await as(lu).get(`/api/v1/recovery/ceremonies/${cer.body.id}/material`)).status, 409, "1 of 2");
	assert.equal((await as(lu).send("PUT", `/api/v1/recovery/ceremonies/${cer.body.id}/shares`, await approveCeremony(lu.root, await trustOf(lu), await listed(), rec, (await recoveryAs(lu)).myShare))).status, 200, "the coordinator is a holder too");
	assert.deepEqual((await listed()).approvals, ["lu", "mo"]);
	assert.equal((await as(mo).get(`/api/v1/recovery/ceremonies/${cer.body.id}/material`)).status, 403, "the material goes to the coordinator only");
	const material = (await as(lu).get(`/api/v1/recovery/ceremonies/${cer.body.id}/material`)).json;
	assert.equal(material.shares.length, 2);

	// A wrong share combines to a wrong key — caught by the signed digest.
	const luTrust = await trustOf(lu);
	const bad = decode(await openSealedText(cer.ephemeral, material.shares[0]));
	bad.y[0] ^= 1;
	const { sealText } = await import("../../web/src/vault/vault-crypto.ts");
	await assert.rejects(combineCeremony(cer.ephemeral, [await sealText(cer.body.ephemeralPublic, encode(bad)), material.shares[1]], rec, luTrust), /do not make the recovery key/);
	const recoveryKey = await combineCeremony(cer.ephemeral, material.shares, rec, luTrust);
	const outcome = await recoverCaseGrant(recoveryKey, material.copy, material.case, await rootOf(lu, "lu"), lu.signer, luTrust);
	assert.equal((await as(mo).send("POST", `/api/v1/recovery/ceremonies/${cer.body.id}/complete`, outcome)).status, 403, "only the coordinator completes");
	assert.equal((await as(lu).send("POST", `/api/v1/recovery/ceremonies/${cer.body.id}/complete`, outcome)).status, 200);
	const luCase = (await as(lu).get("/api/v1/cases")).json.cases.find((c) => c.id === "ir-7");
	assert.equal(luCase.grant.permission, "manage", "lu manages the recovered case");
	const luCaseKey = await openCaseKey(lu.root, luCase, luTrust);
	assert.equal(await openCaseTitle(luCaseKey, luCase), "Wire fraud");
	const list = (await as(lu).get("/api/v1/cases/ir-7/files/list")).json.files;
	assert.equal(await caseSealer.openFileName(caseFile, list[0].name), "wire-transfer.pdf", "the evidence is reachable again");
	assert.equal((await listed()).state, "done");
	assert.deepEqual((await listed()).approvals, [], "the submitted shares are deleted");
	assert.equal((await recoveryAs(lu)).recovery.rotationRequired, true, "the key existed whole in lu's browser: rotation owed");

	// ── 4. bo lost every unlock method ──────────────────────────────────
	const fresh = await createCodeVault();
	const newRoot = await importVaultKey(fresh.rootBundle.slice());
	const newRootPublic = { ec: fresh.publicKey, kem: fresh.pqPublicKey };
	const newIdentity = await createIdentity("bo", newRoot, newRootPublic);
	const draft = { keyId: fresh.keyId, publicKey: fresh.publicKey, pqPublicKey: fresh.pqPublicKey, methods: fresh.methods, identity: newIdentity.record };
	const boDigest = await hybridDigest(fresh.publicKey, fresh.pqPublicKey); // what bo reads aloud to lu
	const c2 = await newCeremony(lu.signer, rec, "bo", "bo lost every unlock method");
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", c2.body)).status, 409, "the member re-enrols first");
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery/reenrol", { settings: draft, rootDigest: boDigest })).status, 200);
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", { ...(await newCeremony(lu.signer, rec, "lu", "self")).body })).status, 400, "nobody coordinates their own recovery");
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", c2.body)).status, 200);
	const ceremony2 = (await as(mo).get("/api/v1/recovery/ceremonies")).json.ceremonies.find((c) => c.id === c2.body.id);
	for (const holder of [mo, lu]) {
		const approval = await approveCeremony(holder.root, await trustOf(holder), ceremony2, rec, (await recoveryAs(holder)).myShare);
		assert.equal((await as(holder).send("PUT", `/api/v1/recovery/ceremonies/${c2.body.id}/shares`, approval)).status, 200);
	}
	const m2 = (await as(lu).get(`/api/v1/recovery/ceremonies/${c2.body.id}/material`)).json;
	assert.equal(m2.draft.rootDigest, boDigest);
	const key2 = await combineCeremony(c2.ephemeral, m2.shares, rec, luTrust);
	// The server swaps the enrolled root for one of its own: the digest bo read aloud does not match.
	const impostor = await createCodeVault();
	await assert.rejects(recoverMemberStore(key2, m2.copy, { ec: impostor.publicKey, kem: impostor.pqPublicKey }, boDigest), /not the one the member confirmed/);
	const out2 = await recoverMemberStore(key2, m2.copy, m2.draft.root, boDigest);
	assert.equal((await as(lu).send("POST", `/api/v1/recovery/ceremonies/${c2.body.id}/complete`, out2)).status, 200);
	const settings = (await as(bo).get("/api/v1/members/bo/vault")).json;
	assert.equal(settings.keyId, fresh.keyId, "bo's vault has the new root");
	const reopened = await openStoreKey(newRoot, settings.stores.files);
	const list2 = (await as(bo).get("/api/v1/members/bo/files/list")).json.files;
	const reSealer = await storeSealer(fromBase64(await openSealedText(newRoot, settings.stores.files.privateKeySealed)), "bo");
	assert.ok(reopened, "the area key opens under the new root");
	assert.equal(await reSealer.openFileName(boFile, list2[0].name), "notes.txt", "…and bo's files with it");
	assert.equal(await entryOf(lu, "bo"), undefined, "bo's old identity is gone (it was sealed to the lost root)");
	assert.equal((await as(bo).send("PUT", "/api/v1/recovery/reenrol", { settings: draft, rootDigest: boDigest })).status, 200, "(a draft can be posted again; the next ceremony would need it)");
	assert.equal((await as(bo).send("PUT", "/api/v1/members/bo/vault", { settings: { ...settings, keyId: "another-root" } })).status, 409, "outside a ceremony the root still cannot change");

	// ── 5. Rotate the recovery key ──────────────────────────────────────
	const c3 = await newCeremony(lu.signer, rec, "case:ir-7", "a ceremony a rotation will cancel");
	assert.equal((await as(lu).send("POST", "/api/v1/recovery/ceremonies", c3.body)).status, 200);
	const body2 = await setupRecovery(lu.signer, luTrust, await Promise.all(["lu", "mo"].map((id) => rootOf(lu, id))), 2);
	assert.equal((await as(lu).send("PUT", "/api/v1/recovery", body2)).status, 200);
	const after = (await recoveryAs(mo)).recovery;
	assert.equal(after.rotationRequired, false);
	assert.deepEqual(after.holders, ["lu", "mo"]);
	assert.equal((await as(mo).get("/api/v1/recovery/ceremonies")).json.ceremonies.find((c) => c.id === c3.body.id).state, "cancelled", "open ceremonies name the old key: cancelled");
	assert.ok((await as(lu).get("/api/v1/recovery/copies")).json.copies.every((c) => !c.current), "every copy is stale until its holder re-seals it");
	const caseCopy2 = await sealRecoveryCopy(luTrust, after, await openSealedText(lu.root, luCase.grant.keySealed));
	assert.equal((await as(lu).send("PUT", "/api/v1/recovery/copies", { area: "case:ir-7", ...caseCopy2 })).status, 200);
	assert.equal((await as(lu).get("/api/v1/recovery/copies")).json.copies.find((c) => c.area === "case:ir-7").current, true);

	const audit = (await as(lu).get("/api/v1/family")).json.audit.map((a) => a.action);
	for (const a of ["recovery.setup", "recovery.copy", "recovery.ceremony.open", "recovery.ceremony.approve", "recovery.ceremony.material", "recovery.ceremony.done", "recovery.reenrol"]) assert.ok(audit.includes(a), `the registry audit records ${a}`);
	const boAudit = (await as(bo).get("/api/v1/members/bo/audit")).json.map((a) => a.action);
	assert.ok(boAudit.includes("vault.reroot"), "bo's own audit records the re-root");

	console.log("ok  api:recovery — 2-of-3 leads; signed recovery key and ceremonies; swapped keys and a wrong share caught; a case and a member recovered; rotation owed and done");
} finally {
	await dev.close();
}
