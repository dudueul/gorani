// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A suite's team, built the way members' browsers build it (commit 27):
 * each member sets up THEIR OWN vault (a root, an own files store, an
 * identity), a lead certifies them after "comparing fingerprints", and they
 * pin the lead. Since commit 27c nobody sets up another member's vault and
 * no lead acts for another member's area — several people working in one
 * store is a CASE (cases.ts), opened and granted here.
 *
 *   const ana = await member(dev, "ana", "lead");
 *   const bo = await member(dev, "bo", "analyst", { by: ana });
 *   await vouch(dev, ana, [bo]);
 *   const kitchen = await openCase(dev, ana, "kitchen", "Shared docs", [[bo, "write"]]);
 *   kitchen.sealer   // tests/lib/placed.mjs sealer for `case:kitchen`
 */

import assert from "node:assert/strict";
import { api } from "../api/_dev.mjs";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
import { importVaultKey, openSealedText } from "../../web/src/vault/vault-crypto.ts";
import { buildTrust, certify, createIdentity, pin } from "../../web/src/vault/identity.ts";
import { newCase, sealCaseGrant } from "../../web/src/vault/cases.ts";
import { fromBase64, toBase64 } from "../../web/src/lib/encoding.ts";
import { storeSealer } from "./placed.mjs";

/** Add a member (by `by`, a lead — or the bootstrap for the first) who then
 * sets up their own vault, files store and identity. */
export async function member(dev, id, role, { by, email = `${id}@team.test`, extra = {} } = {}) {
	const added = await api(dev.base, "POST", "/api/v1/family/members", { email: by?.email ?? email, body: { id, name: id, role, emails: [email], ...extra } });
	assert.equal(added.status, 200, `add ${id}: ${added.text}`);
	const vault = await createCodeVault();
	const root = await importVaultKey(vault.rootBundle.slice());
	const rootPublic = { ec: vault.publicKey, kem: vault.pqPublicKey };
	const store = await createStoreKey();
	const storeB64 = toBase64(store.bundle);
	const made = await createIdentity(id, root, rootPublic);
	const settings = { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, stores: { files: await sealStoreKeyToMember(store, rootPublic) }, identity: made.record };
	const own = role === "external" ? { ...settings, stores: {} } : settings;
	const put = await api(dev.base, "PUT", `/api/v1/members/${id}/vault`, { email, body: { settings: own } });
	assert.equal(put.status, 200, `${id}'s vault: ${put.text}`);
	assert.equal((await api(dev.base, "PUT", "/api/v1/family/identity", { email, body: made.registry })).status, 200);
	return { id, email, root, rootPublic, settings: own, record: made.record, signer: made.signer, storeB64, sealer: await storeSealer(fromBase64(storeB64), id) };
}

/** `who` pins `other` (they compared fingerprints) and saves the record. */
export async function pinIdentity(dev, who, other) {
	who.record = await pin(who.id, who.root, who.record, { member: other.id, keyId: other.record.keyId });
	who.settings = { ...who.settings, identity: who.record };
	assert.equal((await api(dev.base, "PUT", `/api/v1/members/${who.id}/vault`, { email: who.email, body: { settings: who.settings } })).status, 200);
}

/** `lead` certifies each of `members`, and each of them pins `lead`. */
export async function vouch(dev, lead, members) {
	const all = (await api(dev.base, "GET", "/api/v1/family/identities", { email: lead.email })).json.identities;
	for (const who of members) {
		const entry = all.find((e) => e.member === who.id);
		assert.equal((await api(dev.base, "PUT", `/api/v1/family/members/${who.id}/cert`, { email: lead.email, body: await certify(lead.signer, entry) })).status, 200, `certify ${who.id}`);
		await pinIdentity(dev, who, lead);
	}
}

export const trustOf = async (dev, who) => buildTrust(who.id, who.root, who.record, (await api(dev.base, "GET", "/api/v1/family/identities", { email: who.email })).json.identities);

/** A lead opens a case and grants it; returns its sealer (`case:<id>`). */
export async function openCase(dev, lead, id, title, grants = [], kind = "working") {
	const opened = await newCase(id, kind, title, lead.rootPublic, lead.signer);
	const r = await api(dev.base, "POST", "/api/v1/cases", { email: lead.email, body: opened.body });
	assert.equal(r.status, 200, `open ${id}: ${r.text}`);
	const row = async () => (await api(dev.base, "GET", "/api/v1/cases", { email: lead.email })).json.cases.find((c) => c.id === id);
	for (const [who, permission, expiresAt] of grants) {
		const root = (await api(dev.base, "GET", `/api/v1/members/${who.id}/root`, { email: lead.email })).json;
		const sealed = await sealCaseGrant(lead.root, await row(), root, lead.signer, await trustOf(dev, lead));
		const g = await api(dev.base, "PUT", `/api/v1/cases/${id}/grants/${who.id}`, { email: lead.email, body: { permission, ...sealed, ...(expiresAt ? { expiresAt } : {}) } });
		assert.equal(g.status, 200, `grant ${who.id}: ${g.text}`);
	}
	const b64 = await openSealedText(lead.root, (await row()).grant.keySealed);
	return { id, area: `case:${id}`, base: `/api/v1/cases/${id}`, b64, sealer: await storeSealer(fromBase64(b64), `case:${id}`) };
}
