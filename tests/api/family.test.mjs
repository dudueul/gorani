// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:family — the registry (GoraniFamilyDO) through the real HTTP surface,
 * under `wrangler dev` with dev-mode auth. It walks the bootstrap and the
 * rules: the first member (a lead) by anyone holding the bootstrap proof;
 * after that leads only; the last-lead guard; the audit trail. (The family
 * master key it once set is gone, commit 27c — and so is its route.)
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
	const first = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	assert.equal(first.status, 200, JSON.stringify(first.json));
	assert.equal(first.json.members.length, 1);
	assert.equal(first.json.members[0].role, "lead");

	// After bootstrap, only a lead may add members.
	const denied = await api(dev.base, "POST", "/api/v1/family/members", { email: "stranger@family.test", body: { id: "zed", name: "Z", role: "analyst" } });
	assert.equal(denied.status, 403);

	// A parent adds the other parent and a child.
	const dad = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "dad", name: "Dad", role: "lead", emails: ["dad@family.test"] } });
	assert.equal(dad.status, 200);
	const kid = await api(dev.base, "POST", "/api/v1/family/members", { email: "dad@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	assert.equal(kid.status, 200);

	// Shape rules are the registry's, not the client's.
	const badId = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "BAD ID", name: "X", role: "analyst" } });
	assert.equal(badId.status, 400);
	const badRole = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "y", name: "Y", role: "grandparent" } });
	assert.equal(badRole.status, 400);
	const dupe = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu 2", role: "analyst" } });
	assert.equal(dupe.status, 409);

	// The family master key is gone (commit 27c): no route, no state field.
	assert.equal((await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: "pqTestMaster" } })).status, 404);
	assert.equal("master" in (await api(dev.base, "GET", "/api/v1/family", { email: "mom@family.test" })).json, false);

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
	assert.ok(actions.includes("member.create") && actions.includes("member.deactivate"), JSON.stringify(actions));
	console.log("ok  api:family — bootstrap, roles, guards, audit (no master key)");
} finally {
	await dev.close();
}