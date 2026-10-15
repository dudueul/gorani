// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:collectors — registering the machines that drop evidence (commit 37a,
 * docs/COLLECTORS.md). A collector is an Access service token (a JWT with a
 * `common_name`, no email — in dev mode, `x-gorani-dev-collector`) bound
 * to an identity key by two leads. What it proves:
 *
 *   1. only a lead asks; a key id that is not the key's is refused;
 *   2. a pending collector's token is refused, as is approval by the lead
 *      who asked — a second lead's approval makes it active;
 *   3. a collector identity reaches ONLY the drop routes — every member
 *      route refuses it, and a member cannot use the drop routes;
 *   4. a case manager (not an analyst) grants it a case;
 *   5. a member's client counts its key only when both leads' signatures
 *      verify under that member's own trust — a key swapped after the
 *      fact, or a forged approval, is named, not counted;
 *   6. one live collector per service token; one lead revokes, and the
 *      token is refused from the next request on.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { member, vouch, openCase, trustOf } from "../lib/team.mjs";
import { approveCollector, collectorStatements, collectorTrust, collectorVerdict, requestCollector } from "../../web/src/vault/collectors.ts";
import { identityKeyId } from "../../web/src/vault/identity.ts";

const dev = await suiteDev();
const call = (who) => async (method, path, body) => {
	const r = await api(dev.base, method, path, { email: who.email, body });
	if (r.status >= 400) throw new Error(`${r.status} ${r.text}`);
	return r.json;
};
const asCollector = (cn, path, method = "GET") => fetch(`${dev.base}${path}`, { method, headers: { "x-gorani-dev-collector": cn } }).then(async (r) => ({ status: r.status, text: await r.text() }));
const newKey = async () => {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
};

try {
	const ana = await member(dev, "ana", "lead");
	const cy = await member(dev, "cy", "lead", { by: ana });
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo, cy]); // ana certifies bo and cy; both pin ana
	await openCase(dev, ana, "ir-col", "Collected evidence", [[bo, "write"]], "evidence");
	const CN = "8d7e2a0b5c4d3e2f1a0b9c8d7e6f5a4b.access";
	const publicKey = await newKey();

	// ── 1. Only a lead asks, for the key it names ────────────────────────
	const shape = { id: "edr-drop", name: "EDR drop box", commonName: CN, publicKey };
	await assert.rejects(requestCollector(call(bo), bo.signer, shape), /403.*only a lead registers a collector/);
	const wrongId = await api(dev.base, "POST", "/api/v1/family/collectors", { email: ana.email, body: { ...shape, keyId: "a".repeat(64), signature: "AAAA" } });
	assert.equal(wrongId.status, 400);
	assert.match(wrongId.text, /keyId is not this key's id/);
	const requested = await requestCollector(call(ana), ana.signer, shape);
	assert.equal(requested.status, "pending");
	assert.equal(requested.keyId, await identityKeyId(publicKey));

	// ── 2. Pending is refused; the asker cannot approve; a second lead does ─
	const pending = await asCollector(CN, "/api/v1/collect/whoami");
	assert.equal(pending.status, 403);
	assert.match(pending.text, /not a registered, active collector/);
	await assert.rejects(approveCollector(call(ana), ana.signer, await trustOf(dev, ana), requested), /different lead/);
	const self = await api(dev.base, "POST", "/api/v1/family/collectors/edr-drop/approve", { email: ana.email, body: { signature: "AAAA" } });
	assert.equal(self.status, 403, "…and the registry refuses it too");
	const approved = await approveCollector(call(cy), cy.signer, await trustOf(dev, cy), requested);
	assert.equal(approved.status, "active");

	// ── 3. A collector reaches the drop routes, and only them ────────────
	const who = await asCollector(CN, "/api/v1/collect/whoami");
	assert.equal(who.status, 200, who.text);
	assert.deepEqual(JSON.parse(who.text), { id: "edr-drop", name: "EDR drop box", keyId: requested.keyId, cases: [] });
	for (const p of ["/api/v1/family", "/api/v1/cases", "/api/v1/members/ana/files/list", "/api/v1/cases/ir-col/files/list", "/api/v1/family/collectors"]) {
		const r = await asCollector(CN, p);
		assert.equal(r.status, 403, `${p}: ${r.text}`);
		assert.match(r.text, /only the drop routes/, p);
	}
	const memberOnDrop = await api(dev.base, "GET", "/api/v1/collect/whoami", { email: ana.email });
	assert.equal(memberOnDrop.status, 403);
	assert.match(memberOnDrop.text, /drop routes are for collectors/);
	assert.equal((await asCollector("someone-else.access", "/api/v1/collect/whoami")).status, 403, "an unregistered service token is no one here");

	// ── 4. A case manager grants it a case ───────────────────────────────
	assert.equal((await api(dev.base, "PUT", "/api/v1/cases/ir-col/collectors/edr-drop", { email: bo.email })).status, 403, "an analyst with write access does not decide what feeds the case");
	const granted = await api(dev.base, "PUT", "/api/v1/cases/ir-col/collectors/edr-drop", { email: ana.email });
	assert.equal(granted.status, 200, granted.text);
	assert.deepEqual(JSON.parse((await asCollector(CN, "/api/v1/collect/whoami")).text).cases, ["ir-col"]);

	// ── 5. Each member's client decides whether to count it ──────────────
	const rows = (await call(bo)("GET", "/api/v1/family/collectors")).collectors;
	const boTrust = await trustOf(dev, bo);
	const counted = await collectorTrust(boTrust, rows);
	assert.deepEqual(counted.get("edr-drop")?.vouchedBy, ["ana", "cy"], "bo pinned ana, ana certified cy: both signatures verify under bo's trust");
	const row = rows.find((r) => r.id === "edr-drop");
	// A server that swaps the key after the leads signed (and recomputes its id):
	const swapped = { ...row, publicKey: await newKey() };
	swapped.keyId = await identityKeyId(swapped.publicKey);
	assert.match(await collectorVerdict(boTrust, swapped), /registration's signature does not verify/);
	// A forged approval: a valid signature, but over another statement.
	const forged = { ...row, approveSignature: await cy.signer.sign(collectorStatements.approve("edr-drop", CN, row.keyId, "ana", "mallory")) };
	assert.match(await collectorVerdict(boTrust, forged), /approval's signature does not verify/);
	assert.equal(await collectorVerdict(boTrust, row), null);

	// ── 6. One live collector per token; one lead revokes ────────────────
	await assert.rejects(requestCollector(call(ana), ana.signer, { ...shape, id: "edr-twin" }), /409.*already collector edr-drop/, "one live collector per service token");
	assert.equal((await api(dev.base, "DELETE", "/api/v1/family/collectors/edr-drop", { email: cy.email })).status, 200);
	assert.equal((await asCollector(CN, "/api/v1/collect/whoami")).status, 403, "revoked: refused from the next request on");
	assert.match(await collectorVerdict(boTrust, (await call(bo)("GET", "/api/v1/family/collectors")).collectors.find((r) => r.id === "edr-drop")), /revoked/);
	const again = await requestCollector(call(ana), ana.signer, { ...shape, id: "edr-drop-2", publicKey: await newKey() });
	assert.equal(again.status, "pending", "the same token may be registered anew, with a new key");

	// Every step is on the registry's (chained) trail.
	const actions = (await api(dev.base, "GET", "/api/v1/family", { email: ana.email })).json.audit.map((l) => l.action);
	for (const a of ["collector.request", "collector.approve", "collector.grant", "collector.revoke"]) assert.ok(actions.includes(a), `${a} audited`);

	console.log("ok  api:collectors — two leads register a collector (only a lead asks, not the same lead approves, the key id must be the key's), a pending or revoked token is refused, a collector reaches only the drop routes (every member route refuses it), a case manager grants it a case, members count its key only when both leads' signatures verify under their own trust (a swapped key or a forged approval named), one live collector per service token");
} finally {
	await dev.close();
}
