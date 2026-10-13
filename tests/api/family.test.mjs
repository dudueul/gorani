// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:family — the registry (GoraniFamilyDO) through the real HTTP surface,
 * under `wrangler dev` with dev-mode auth. It walks the bootstrap and the
 * rules: the first member by anyone; after that parents only; the master
 * public set once; the last-parent guard; the audit trail.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";

const dev = await suiteDev();
try {
	// The health line: configured storage is a var question, not a secret.
	const health = await api(dev.base, "GET", "/api/healthz", { email: null });
	assert.equal(health.status, 200);
	assert.equal(health.json.service, "gorani");

	// No identity, no API.
	const anon = await api(dev.base, "GET", "/api/v1/family", { email: null });
	assert.equal(anon.status, 401);

	// Bootstrap: the first member (a parent) by any authenticated caller.
	const first = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	assert.equal(first.status, 200, JSON.stringify(first.json));
	assert.equal(first.json.members.length, 1);
	assert.equal(first.json.members[0].role, "parent");

	// After bootstrap, only a parent may add members.
	const denied = await api(dev.base, "POST", "/api/v1/family/members", { email: "stranger@family.test", body: { id: "zed", name: "Z", role: "child" } });
	assert.equal(denied.status, 403);

	// A parent adds the other parent and a child.
	const dad = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "dad", name: "Dad", role: "parent", emails: ["dad@family.test"] } });
	assert.equal(dad.status, 200);
	const kid = await api(dev.base, "POST", "/api/v1/family/members", { email: "dad@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	assert.equal(kid.status, 200);

	// Shape rules are the registry's, not the client's.
	const badId = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "BAD ID", name: "X", role: "child" } });
	assert.equal(badId.status, 400);
	const badRole = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "y", name: "Y", role: "grandparent" } });
	assert.equal(badRole.status, 400);
	const dupe = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu 2", role: "child" } });
	assert.equal(dupe.status, 409);

	// The master public half, set once.
	const master = await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: "pqTestMaster", publicKey: { ec: { kty: "EC", crv: "P-256", x: "A", y: "B" }, kem: "Cg==" } } });
	assert.equal(master.status, 200);
	assert.equal(master.json.master.keyId, "pqTestMaster");
	const again = await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: "pqOther", publicKey: { ec: {}, kem: "" } } });
	assert.equal(again.status, 409);

	// Rename by a parent; a child cannot run the registry.
	const rename = await api(dev.base, "PATCH", "/api/v1/family/members/jinu", { email: "dad@family.test", body: { name: "Jinu H." } });
	assert.equal(rename.status, 200);
	assert.ok(rename.json.members.find((m) => m.id === "jinu").name === "Jinu H.");
	const childDenial = await api(dev.base, "PATCH", "/api/v1/family/members/jinu", { email: "jinu@family.test", body: { name: "self-appointed" } });
	assert.equal(childDenial.status, 403);

	// Deactivate the child; the last-parent guard holds.
	const off = await api(dev.base, "POST", "/api/v1/family/members/jinu/deactivate", { email: "mom@family.test" });
	assert.equal(off.status, 200);
	assert.equal(off.json.members.find((m) => m.id === "jinu").active, false);
	const offMom = await api(dev.base, "POST", "/api/v1/family/members/mom/deactivate", { email: "dad@family.test" });
	assert.equal(offMom.status, 200);
	const lastGuard = await api(dev.base, "POST", "/api/v1/family/members/dad/deactivate", { email: "dad@family.test" });
	assert.equal(lastGuard.status, 409);

	// The audit trail records the registry's story.
	const state = await api(dev.base, "GET", "/api/v1/family", { email: "dad@family.test" });
	const actions = state.json.audit.map((a) => a.action);
	assert.ok(actions.includes("member.create") && actions.includes("member.deactivate") && actions.includes("master.set"), JSON.stringify(actions));
	console.log("ok  api:family — bootstrap, roles, master-once, guards, audit");
} finally {
	await dev.close();
}