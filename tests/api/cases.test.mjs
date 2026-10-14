// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:cases — cases and grants (commit 26, docs/CASES.md › stage 3). A case
 * is a store like a member's own (`case:<id>`, worker/src/area.rs), whose
 * key lives in its GRANTS — one copy per grantee, sealed to their root by
 * the manager's browser (web/src/vault/cases.ts). What it proves:
 *
 *   1. only a lead opens a case, and becomes its manager; the case's store
 *      takes files sealed into `case:<id>` places;
 *   2. content needs a grant — a lead or auditor WITHOUT one reads the
 *      audit, never the files; a member nobody granted sees nothing;
 *   3. grants: only a manager seals them; an auditor's is read-only (the
 *      server refuses their writes); an external's must expire, inside the
 *      external's own expiry, and they see only their own grant;
 *   4. a case has no devices, vault settings or public links;
 *   5. revoke → "rotation required" → rotate (commit first, then the
 *      reseal walk, then "done"): the old key opens nothing, every
 *      remaining grantee opens the new one, the revoked member is refused;
 *      a walk interrupted after the commit resumes from the grants; grants
 *      that end by themselves (a deactivated holder) count as a revoke, and
 *      a deactivated manager does not count as the case's last one;
 *   6. closing makes the case read-only;
 *   7. (commit 27) identities: every copy is SIGNED by its granter and
 *      verified by the grantee against an identity they trust — a copy the
 *      server substituted, or a valid signature replayed from another
 *      member's grant, is refused; a manager seals only to a root the
 *      grantee's trusted identity names; the registry keeps identities and
 *      certificates current (register once, reset drops certificates, only
 *      leads certify, certificates name the current key).
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, openWith, importVaultKey, openSealedText, sealText } from "../../web/src/vault/vault-crypto.ts";
import { createChildVault } from "../../web/src/vault/family.ts";
import { createStoreKey } from "../../web/src/vault/family.ts";
import { newCase, openCaseKey, openCaseTitle, sealCaseGrant, rotateCase } from "../../web/src/vault/cases.ts";
import { buildTrust, certify, createIdentity, hybridDigest, pin, statements } from "../../web/src/vault/identity.ts";
import { opensAnything } from "../../web/src/vault/rotation.ts";
import { fromBase64, toBase64 } from "../../web/src/lib/encoding.ts";
import { storeSealer } from "../lib/placed.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();
const CASE = "ir-2026-014";
const AREA = `case:${CASE}`;
const BASE = `/api/v1/cases/${CASE}`;
const inDays = (d) => new Date(Date.now() + d * 86_400_000).toISOString();

const as = (who) => ({
	get: (path) => api(dev.base, "GET", path, { email: who.email }),
	send: (method, path, body) => api(dev.base, method, path, { email: who.email, body }),
	/** The JSON API as the walk wants it — loud on refusals. */
	call: async (method, path, body) => {
		const r = await api(dev.base, method, path, { email: who.email, body });
		if (r.status >= 300) throw new Error(`${method} ${path}: ${r.status} ${r.text.slice(0, 200)}`);
		return r.json;
	},
});

/** A team member with a vault root (what grants are sealed to) and an
 * identity (what grants are signed with) — the record in their settings,
 * the public half in the registry. */
async function join(id, role, by, extra = {}) {
	const email = `${id}@team.test`;
	const added = await api(dev.base, "POST", "/api/v1/family/members", { email: by ?? email, body: { id, name: id, role, emails: [email], ...extra } });
	assert.equal(added.status, 200, `add ${id}: ${added.text}`);
	const vault = await createChildVault();
	const root = await importVaultKey(vault.rootBundle.slice());
	const rootPublic = { ec: vault.publicKey, kem: vault.pqPublicKey };
	const made = await createIdentity(id, root, rootPublic);
	const settings = { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, identity: made.record };
	const put = await api(dev.base, "PUT", `/api/v1/members/${id}/vault`, { email, body: { settings } });
	assert.equal(put.status, 200, `${id}'s vault: ${put.text}`);
	const reg = await api(dev.base, "PUT", "/api/v1/family/identity", { email, body: made.registry });
	assert.equal(reg.status, 200, `${id}'s identity: ${reg.text}`);
	return { id, email, root, rootPublic, settings, record: made.record, signer: made.signer, registry: made.registry };
}

/** `who` pins another member's identity (they compared fingerprints) and
 * saves the re-MAC'd record in their settings. */
async function pinIdentity(who, other) {
	who.record = await pin(who.id, who.root, who.record, { member: other.id, keyId: other.record.keyId });
	who.settings = { ...who.settings, identity: who.record };
	assert.equal((await api(dev.base, "PUT", `/api/v1/members/${who.id}/vault`, { email: who.email, body: { settings: who.settings } })).status, 200);
}

/** Whom `who` trusts, from the registry's identities and their own pins. */
const trustOf = async (who) => buildTrust(who.id, who.root, who.record, (await api(dev.base, "GET", "/api/v1/family/identities", { email: who.email })).json.identities);

async function upload(who, fields, file) {
	const boundary = `c${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${BASE}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, json: await r.json() };
}

/** A new sealed file in the case, uploaded by `who` holding `bundle`. */
async function putFile(who, sealer, name, text) {
	const ck = newContentKey();
	const f = await sealer.newFile(name, "text/plain", ck);
	const plain = enc.encode(text);
	const r = await upload(who, { ...f.fields, size: String(plain.length) }, await sealWith(await importContentKey(ck), plain));
	return { ...r, id: f.id, plain };
}

/** The case row as `who` sees it. */
const caseOf = async (who) => (await as(who).get("/api/v1/cases")).json.cases.find((c) => c.id === CASE);
/** The case bundle from `who`'s grant (a test needs the bytes for storeSealer). */
const bundleOf = async (who, c, field = "keySealed") => fromBase64(await openSealedText(who.root, c.grant[field]));
const rootOf = async (by, id) => (await as(by).get(`/api/v1/members/${id}/root`)).json;

try {
	// ── 0. The team ─────────────────────────────────────────────────────
	const ana = await join("ana", "lead");
	const lu = await join("lu", "lead", ana.email);
	const bo = await join("bo", "analyst", ana.email);
	const cy = await join("cy", "auditor", ana.email);
	const dee = await join("dee", "analyst", ana.email);
	const ext = await join("ext", "external", ana.email, { expiresAt: inDays(7) });

	// ── 0b. Identities: the lead certifies, everyone pins the lead ──────
	const entryOf = async (id) => (await as(ana).get("/api/v1/family/identities")).json.identities.find((e) => e.member === id);
	for (const who of [lu, bo, cy, dee, ext]) {
		const cert = await certify(ana.signer, await entryOf(who.id));
		assert.equal((await as(ana).send("PUT", `/api/v1/family/members/${who.id}/cert`, cert)).status, 200, `ana certifies ${who.id}`);
		await pinIdentity(who, ana); // …and each of them compared ana's fingerprint
	}
	assert.equal((await as(bo).send("PUT", "/api/v1/family/members/cy/cert", await certify(bo.signer, await entryOf("cy")))).status, 403, "only a lead certifies");
	assert.equal((await as(ana).send("PUT", "/api/v1/family/members/cy/cert", { ...(await certify(ana.signer, await entryOf("cy"))), rootDigest: "0".repeat(64) })).status, 409, "a certificate names the member's CURRENT root");
	assert.equal((await as(bo).send("PUT", "/api/v1/family/identity", bo.registry)).status, 200, "re-registering the same identity is a no-op");
	const other = await createIdentity("bo", bo.root, bo.rootPublic);
	assert.equal((await as(bo).send("PUT", "/api/v1/family/identity", other.registry)).status, 409, "a new identity needs a reset first");
	assert.equal((await as(ext).get("/api/v1/family/identities")).status, 200, "externals read identities (to verify who granted them) …");
	assert.ok(!(await as(ext).get("/api/v1/family/identities")).text.includes("@team.test"), "… which carry no emails");
	assert.equal((await trustOf(bo)).of("cy")?.via, "cert:ana", "bo trusts cy through ana's certificate");
	// A reset (lost device) drops the identity's certificates; until a lead
	// verifies the new one, nobody's client trusts it.
	const fay = await join("fay", "analyst", ana.email);
	assert.equal((await as(ana).send("PUT", "/api/v1/family/members/fay/cert", await certify(ana.signer, await entryOf("fay")))).status, 200);
	assert.equal((await trustOf(bo)).of("fay")?.via, "cert:ana");
	assert.equal((await as(dee).send("DELETE", "/api/v1/family/members/fay/identity")).status, 403, "a reset is the member's or a lead's");
	assert.equal((await as(fay).send("DELETE", "/api/v1/family/members/fay/identity")).json.certsDropped, 1);
	const fay2 = await createIdentity("fay", fay.root, fay.rootPublic);
	assert.equal((await as(fay).send("PUT", "/api/v1/family/identity", fay2.registry)).status, 200);
	assert.equal((await trustOf(bo)).of("fay"), null, "a re-enrolled identity is trusted again only once someone verifies it");

	// A member's root public halves: what a grant is sealed to.
	const boRoot = await rootOf(ana, "bo");
	assert.equal(boRoot.member, "bo");
	assert.ok(boRoot.keyId && boRoot.publicKey && boRoot.pqPublicKey);
	assert.equal((await as(ext).get("/api/v1/members/bo/root")).status, 403, "externals never seal grants, so never read roots");
	assert.equal((await as(ana).get("/api/v1/members/nobody/root")).status, 404);
	// An external has a vault (a root) but no files area.
	assert.equal((await as(ext).get("/api/v1/members/ext/vault")).status, 200, "an external's own vault: their root");
	assert.equal((await as(ext).get("/api/v1/members/ext/files/list")).status, 403, "…but no files beside it");

	// ── 1. Opening a case ───────────────────────────────────────────────
	const opened = await newCase(CASE, "evidence", "Phishing wave, October", ana.rootPublic, ana.signer);
	assert.equal((await as(ana).send("POST", "/api/v1/cases", { ...opened.body, signature: undefined })).status, 400, "an unsigned grant is refused");
	assert.equal((await as(bo).send("POST", "/api/v1/cases", opened.body)).status, 403, "only a lead opens a case");
	assert.equal((await as(ana).send("POST", "/api/v1/cases", { ...opened.body, id: "IR 14" })).status, 400, "case ids are readable codes: a–z, 0–9, dashes");
	assert.equal((await as(ana).send("POST", "/api/v1/cases", { ...opened.body, keySealed: "plain" })).status, 400, "the key copy must be sealed");
	const created = await as(ana).send("POST", "/api/v1/cases", opened.body);
	assert.equal(created.status, 200, created.text);
	assert.equal((await as(ana).send("POST", "/api/v1/cases", opened.body)).status, 409, "one case per id");

	let c = await caseOf(ana);
	assert.equal(c.grant.permission, "manage", "the opener manages the case");
	assert.equal(c.kind, "evidence");
	const anaKey = await openCaseKey(ana.root, c, await trustOf(ana));
	assert.equal(await openCaseTitle(anaKey, c), "Phishing wave, October", "the title opens in its place (case.title)");

	// The case's store takes files sealed into `case:<id>` places.
	const anaSealer = await storeSealer(await bundleOf(ana, c), AREA);
	const timeline = await putFile(ana, anaSealer, "timeline.txt", "09:14 first report");
	assert.equal(timeline.status, 200, JSON.stringify(timeline.json));
	const list = await as(ana).get(`${BASE}/files/list`);
	assert.equal(list.status, 200);
	assert.equal(await anaSealer.openFileName(timeline.id, list.json.files[0].name), "timeline.txt");
	// A member's store and a case's are separate: the same sealer's values
	// are bound to `case:<id>`, so the member store would refuse to open them.
	await assert.rejects((await storeSealer(await bundleOf(ana, c), "ana")).openFileName(timeline.id, list.json.files[0].name), "a case's names do not open as a member store's");

	// ── 2. Content needs a grant ────────────────────────────────────────
	assert.equal((await as(bo).get(`${BASE}/files/list`)).status, 403, "an analyst not on the case sees nothing");
	assert.equal((await as(lu).get(`${BASE}/files/list`)).status, 403, "a lead not on the case: no content (leads manage keys, not content)");
	assert.equal((await as(cy).get(`${BASE}/files/list`)).status, 403, "an auditor without a grant: no content");
	for (const who of [ana, lu, cy]) assert.equal((await as(who).get(`${BASE}/audit`)).status, 200, `${who.id} reads the case audit`);
	assert.equal((await as(bo).get(`${BASE}/audit`)).status, 403, "an analyst not on the case: not even the audit");
	assert.equal((await as(dee).get(`${BASE}/reads`)).status, 403);
	assert.ok((await as(lu).get("/api/v1/cases")).json.cases.some((x) => x.id === CASE && x.grant === null), "a lead lists every case's structure, without a key");
	assert.equal((await as(bo).get("/api/v1/cases")).json.cases.length, 0, "an analyst lists only their cases");
	assert.equal((await as(bo).get("/api/v1/members/case:ir-2026-014/files/list")).status, 400, "a case is not reachable through the member routes");

	// ── 3. Grants ───────────────────────────────────────────────────────
	const grant = async (by, who, permission, extra = {}) => as(by).send("PUT", `${BASE}/grants/${who.id}`, { permission, ...(await sealCaseGrant(by.root, await caseOf(by), await rootOf(by, who.id), by.signer, await trustOf(by))), ...extra });
	assert.equal((await grant(ana, bo, "write")).status, 200);
	assert.equal((await grant(bo, dee, "read")).status, 403, "only a manager grants");
	c = await caseOf(bo);
	const boKey = await openCaseKey(bo.root, c, await trustOf(bo));
	assert.equal(await openCaseTitle(boKey, c), "Phishing wave, October", "bo opens their copy");
	const boSealer = await storeSealer(await bundleOf(bo, c), AREA);
	const ioc = await putFile(bo, boSealer, "iocs.csv", "evil.test,203.0.113.7");
	assert.equal(ioc.status, 200, "a write grant writes");
	const dl = await fetch(`${dev.base}${BASE}/files/${timeline.id}`, { headers: { "x-gorani-dev-email": bo.email, "x-gorani-client": "test" } });
	assert.equal(dl.status, 200);
	const ck = dl.headers.get("x-gorani-ck");
	assert.deepEqual(await openWith(await boSealer.openFileKey(timeline.id, 1, ck), new Uint8Array(await dl.arrayBuffer())), timeline.plain, "bo reads ana's upload");

	assert.equal((await grant(ana, cy, "write")).status, 400, "an auditor's grant is read-only");
	assert.equal((await grant(ana, cy, "read")).status, 200);
	assert.equal((await as(cy).get(`${BASE}/files/list`)).status, 200, "the auditor reads with a grant");
	await openCaseKey(cy.root, await caseOf(cy), await trustOf(cy)); // signed by ana, whom cy pinned

	// ── 3b. What the signatures stop (commit 27) ────────────────────────
	// The server's move before stage 4: hand cy a case key of ITS OWN —
	// sealed to cy's root, under the current key id — with any signature.
	// (Played here through a manager's write; the registry cannot tell.)
	const fake = await createStoreKey();
	const fakeDigest = await hybridDigest(fake.publicKey, fake.pqPublicKey);
	const fakeCopy = await sealText(cy.rootPublic, toBase64(fake.bundle));
	const notAna = await createIdentity("ana", ana.root, ana.rootPublic); // a key that is not ana's registered one
	assert.equal((await as(ana).send("PUT", `${BASE}/grants/cy`, { permission: "read", keyId: c.keyId, keySealed: fakeCopy, signature: await notAna.signer.sign(statements.grant(CASE, fakeDigest, "cy")) })).status, 200, "the registry stores what it cannot check");
	await assert.rejects(async () => openCaseKey(cy.root, await caseOf(cy), await trustOf(cy)), /the signature on your copy of case ir-2026-014's key does not verify/, "a substituted key: refused before cy uses it");
	// …or replay a REAL signature of ana's — the one on bo's grant — over it.
	const boSig = (await caseOf(bo)).grant.signature;
	assert.equal((await as(ana).send("PUT", `${BASE}/grants/cy`, { permission: "read", keyId: c.keyId, keySealed: fakeCopy, signature: boSig })).status, 200);
	await assert.rejects(async () => openCaseKey(cy.root, await caseOf(cy), await trustOf(cy)), /the signature on your copy of case ir-2026-014's key does not verify/, "a replayed signature names another grantee and another key");
	// A manager never seals to a root the grantee's trusted identity does not name.
	const fakeRoot = await createChildVault();
	await assert.rejects(sealCaseGrant(ana.root, await caseOf(ana), { member: "cy", keyId: fakeRoot.keyId, publicKey: fakeRoot.publicKey, pqPublicKey: fakeRoot.pqPublicKey }, ana.signer, await trustOf(ana)), /not the one their identity names/);
	await assert.rejects(sealCaseGrant(ana.root, await caseOf(ana), await rootOf(ana, "fay"), ana.signer, await trustOf(ana)), /not verified/, "nor to a member whose identity nobody verified");
	assert.equal((await grant(ana, cy, "read")).status, 200, "the real grant back");
	await openCaseKey(cy.root, await caseOf(cy), await trustOf(cy));
	const cySealer = await storeSealer(await bundleOf(cy, await caseOf(cy)), AREA);
	assert.equal((await putFile(cy, cySealer, "note.txt", "x")).status, 403, "…and the server refuses their writes (the key would allow it: policy, not crypto)");

	assert.equal((await grant(ana, ext, "read")).status, 400, "an external's grant must expire");
	assert.equal((await grant(ana, ext, "read", { expiresAt: inDays(30) })).status, 400, "…no later than the external themselves");
	assert.equal((await grant(ana, ext, "manage", { expiresAt: inDays(3) })).status, 400, "an external never manages");
	assert.equal((await grant(ana, dee, "read", { expiresAt: inDays(3) })).status, 400, "only externals' grants expire");
	assert.equal((await grant(ana, ext, "write", { expiresAt: inDays(3) })).status, 200);
	const extView = await caseOf(ext);
	assert.equal(extView.grant.permission, "write");
	assert.deepEqual(extView.grantees, [], "an external sees their own grant, not who else is on the case");
	const extDl = await fetch(`${dev.base}${BASE}/files/${ioc.id}`, { headers: { "x-gorani-dev-email": ext.email, "x-gorani-client": "test" } });
	assert.equal(extDl.status, 200, "the external reads the case");
	await extDl.arrayBuffer();
	const reads = await as(cy).get(`${BASE}/reads`);
	assert.ok(reads.json.reads.some((r) => r.actor === ext.email && r.file === ioc.id), "…and the read log shows it to the auditor");

	// ── 4. What a case does not have ────────────────────────────────────
	assert.equal((await as(ana).get(`${BASE}/files/shares`)).status, 404, "no public links from a case (it shares by grant)");
	assert.equal((await as(ana).send("POST", `${BASE}/files/shares`, {})).status, 404);
	assert.equal((await as(ana).get(`${BASE}/devices`)).status, 404, "no devices");
	assert.equal((await as(ana).send("PUT", `${BASE}/vault`, { settings: { enabled: false } })).status, 404, "no vault settings to change");
	assert.equal((await as(ana).send("DELETE", `${BASE}/vault`)).status, 404, "a case is closed, not destroyed");
	assert.equal((await as(bo).send("PUT", `${BASE}/files/reseal`, { items: [] })).status, 403, "the reseal walk is a manager's");

	// ── 5. Revoke → rotate ──────────────────────────────────────────────
	assert.equal((await as(ana).send("DELETE", `${BASE}/grants/ana`)).status, 409, "the last manager stays");
	const revoked = await as(ana).send("DELETE", `${BASE}/grants/bo`);
	assert.equal(revoked.status, 200);
	c = revoked.json.cases.find((x) => x.id === CASE);
	assert.equal(c.rotationRequired, true, "bo kept the key: the case is owed a rotation");
	assert.equal((await as(bo).get(`${BASE}/files/list`)).status, 403, "bo is off the case at once");
	assert.ok(await opensAnything(as(ana).call, AREA, boKey) > 0, "…but bo's old key still opens what bo copied — until the rotation");

	const roots = async () => Promise.all(c.grantees.map((g) => rootOf(ana, g.member)));
	// A rotation names exactly the current grantees.
	const short = (await roots()).filter((r) => r.member !== "cy");
	await assert.rejects(rotateCase(as(ana).call, ana.root, c, short, ana.signer, await trustOf(ana)), /409/, "one grantee short is refused");
	// Interrupt a rotation after its commit (the tab "dies" before the walk).
	c = await caseOf(ana);
	const all = await roots();
	const interrupted = {
		...as(ana),
		call: async (method, path, body) => {
			if (method === "GET" && path.includes("/files/sealed")) throw new Error("the tab died");
			return as(ana).call(method, path, body);
		},
	};
	await assert.rejects(rotateCase(interrupted.call, ana.root, c, all, ana.signer, await trustOf(ana)), /the tab died/);
	c = await caseOf(ana);
	assert.ok(c.rotating, "the commit landed; the walk did not");
	assert.ok(c.grant.prevKeySealed, "…and the grant still holds the previous key");
	assert.equal((await as(ana).send("PUT", `${BASE}/key`, { keyId: "x", publicKey: {}, grants: [] })).status, 409, "no second rotation while one walks");
	// Resume from the grants alone — no key survived in "the tab".
	const done = await rotateCase(as(ana).call, ana.root, c, all, ana.signer, await trustOf(ana));
	assert.equal(done.report.resealed.version, 2, "both files' content keys");
	c = await caseOf(ana);
	assert.equal(c.rotating, null);
	assert.equal(c.rotationRequired, false);
	assert.equal(c.grant.prevKeySealed, null, "the previous copies are gone");
	assert.equal(await opensAnything(as(ana).call, AREA, boKey), 0, "bo's old key opens nothing in the case");
	const newKey = await openCaseKey(ana.root, c, await trustOf(ana));
	assert.equal(await openCaseTitle(newKey, c), "Phishing wave, October", "the title moved to the new key");
	for (const who of [cy, ext]) {
		const theirs = await caseOf(who);
		assert.equal(theirs.keyId, c.keyId);
		await openCaseKey(who.root, theirs, await trustOf(who)); // throws if their copy is not the new key, signed
	}
	assert.equal((await as(ana).send("PUT", `${BASE}/grants/bo`, { permission: "read", keySealed: c.grant.keySealed, keyId: "stale" })).status, 409, "a grant names the current key");

	// Grants that end by themselves count as a revoke: the holder kept the key.
	assert.equal((await grant(ana, dee, "read")).status, 200);
	assert.equal((await grant(ana, lu, "manage")).status, 200);
	for (const id of ["dee", "lu"]) assert.equal((await api(dev.base, "POST", `/api/v1/family/members/${id}/deactivate`, { email: ana.email })).status, 200, `deactivate ${id}`);
	c = await caseOf(ana);
	assert.equal(c.rotationRequired, true, "deactivated holders kept their copies: a rotation is owed");
	assert.deepEqual(c.grantees.map((g) => g.member).sort(), ["ana", "cy", "ext"], "ended grants are not listed (nobody seals the new key to them)");
	assert.equal((await as(ana).send("DELETE", `${BASE}/grants/ana`)).status, 409, "a deactivated manager does not count — ana stays the last one");
	await rotateCase(as(ana).call, ana.root, c, await Promise.all(c.grantees.map((g) => rootOf(ana, g.member))), ana.signer, await trustOf(ana));
	c = await caseOf(ana);
	assert.equal(c.rotationRequired, false, "the rotation dropped the ended grants with the old key");
	assert.equal((await as(dee).get(`${BASE}/files/list`)).status, 403);

	// ── 6. Closing ──────────────────────────────────────────────────────
	assert.equal((await as(cy).send("POST", `${BASE}/close`)).status, 403, "only a manager closes");
	assert.equal((await as(ana).send("POST", `${BASE}/close`)).status, 200);
	const newSealer = await storeSealer(await bundleOf(ana, await caseOf(ana)), AREA);
	assert.equal((await putFile(ana, newSealer, "late.txt", "too late")).status, 409, "a closed case takes no writes");
	assert.equal((await as(ext).get(`${BASE}/files/list`)).status, 200, "…and still reads");
	assert.equal((await grant(ana, bo, "read")).status, 409, "…and takes no new grants");
	const audit = (await as(cy).get(`${BASE}/audit`)).json.map((a) => a.action);
	assert.ok(audit.includes("files.reseal"), "the case audit records the walk");
	const registry = (await as(ana).get("/api/v1/family")).json.audit.map((a) => a.action);
	for (const action of ["case.create", "case.grant", "case.revoke", "case.rekey", "case.rekey.done", "case.close", "identity.register", "identity.certify", "identity.reset"]) assert.ok(registry.includes(action), `the registry audit records ${action}`);

	console.log("ok  api:cases — leads open, signed grants seal the key, substituted/replayed copies refused, read-only auditors, expiring externals, no links/devices, revoke → rotate (resumable), close");
} finally {
	await dev.close();
}
