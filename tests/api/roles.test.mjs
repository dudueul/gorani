// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:roles — the team's four roles (commit 26, docs/CASES.md › Roles):
 *
 *   lead     manages the registry; (transitional) may act for any area
 *   analyst  their own area only
 *   auditor  their own area, and every member's audit and read log
 *   external no own area, no registry view, and an expiry that ends access
 *
 * plus the guards: externals need an expiry (nobody else may have one),
 * the last lead cannot be demoted or deactivated, an expired external is
 * nobody. Each property is a success next to the refusal it implies.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";

const dev = await suiteDev();
const tomorrow = new Date(Date.now() + 86_400_000).toISOString();
const yesterday = new Date(Date.now() - 86_400_000).toISOString();
const add = (body, email = "ana@team.test") => api(dev.base, "POST", "/api/v1/family/members", { email, body });
const get = (path, email) => api(dev.base, "GET", path, { email });

try {
	// ── 1. The team ─────────────────────────────────────────────────────
	assert.equal((await add({ id: "ana", name: "Ana", role: "lead", emails: ["ana@team.test"] })).status, 200);
	assert.equal((await add({ id: "bo", name: "Bo", role: "analyst", emails: ["bo@team.test"] })).status, 200);
	assert.equal((await add({ id: "cy", name: "Cy", role: "auditor", emails: ["cy@team.test"] })).status, 200);
	assert.equal((await add({ id: "ext", name: "Partner CERT", role: "external", emails: ["ir@partner.test"], expiresAt: tomorrow })).status, 200);
	assert.equal((await add({ id: "ext2", name: "No end", role: "external", emails: ["x@partner.test"] })).status, 400, "an external member needs an expiry");
	assert.equal((await add({ id: "dee", name: "Dee", role: "analyst", emails: ["dee@team.test"], expiresAt: tomorrow })).status, 400, "only externals expire");
	assert.equal((await add({ id: "eve", name: "Eve", role: "analyst", emails: ["eve@team.test"] }, "bo@team.test")).status, 403, "only a lead adds members");
	const team = (await get("/api/v1/family", "ana@team.test")).json.members;
	assert.deepEqual(Object.fromEntries(team.map((m) => [m.id, m.role])), { ana: "lead", bo: "analyst", cy: "auditor", ext: "external" });

	// ── 2. Own areas ────────────────────────────────────────────────────
	assert.equal((await get("/api/v1/members/bo/files/list", "bo@team.test")).status, 200, "an analyst opens their own area");
	assert.equal((await get("/api/v1/members/ana/files/list", "bo@team.test")).status, 403, "…and nobody else's");
	assert.equal((await get("/api/v1/members/bo/files/list", "cy@team.test")).status, 403, "an auditor reads audits, not areas");
	assert.equal((await get("/api/v1/members/ext/files/list", "ir@partner.test")).status, 403, "an external has no own area");
	assert.equal((await get("/api/v1/members/bo/files/list", "ana@team.test")).status, 200, "a lead still may (the transitional parent rule, until stage 5)");

	// ── 3. Audits and read logs ─────────────────────────────────────────
	for (const path of ["/api/v1/members/bo/audit", "/api/v1/members/bo/reads"]) {
		assert.equal((await get(path, "bo@team.test")).status, 200, `${path}: the member's own`);
		assert.equal((await get(path, "cy@team.test")).status, 200, `${path}: the auditor reads every member's`);
		assert.equal((await get(path, "ana@team.test")).status, 200, `${path}: and so does a lead`);
		assert.equal((await get(path, "ir@partner.test")).status, 403, `${path}: not an external`);
	}
	assert.equal((await get("/api/v1/members/cy/audit", "bo@team.test")).status, 403, "an analyst reads only their own");

	// ── 4. The registry: not for externals ──────────────────────────────
	assert.equal((await get("/api/v1/family", "ir@partner.test")).status, 403, "the registry lists everyone's emails — externals do not see it");
	assert.equal((await get("/api/v1/family", "bo@team.test")).status, 200);

	// ── 5. Role changes and the last lead ───────────────────────────────
	const patch = (id, body, email = "ana@team.test") => api(dev.base, "PATCH", `/api/v1/family/members/${id}`, { email, body });
	assert.equal((await patch("bo", { role: "lead" })).status, 200, "a lead promotes");
	assert.equal((await patch("cy", { role: "lead" }, "cy@team.test")).status, 403, "nobody promotes themselves");
	assert.equal((await patch("ana", { role: "analyst" }, "bo@team.test")).status, 200, "one lead demotes another while one remains");
	assert.equal((await patch("bo", { role: "analyst" }, "bo@team.test")).status, 409, "the last lead cannot be demoted");
	assert.equal((await api(dev.base, "POST", "/api/v1/family/members/bo/deactivate", { email: "bo@team.test" })).status, 409, "…nor deactivated");
	assert.equal((await patch("cy", { role: "external" }, "bo@team.test")).status, 400, "becoming external needs an expiry");

	// ── 6. Expiry ends access by itself ─────────────────────────────────
	assert.equal((await add({ id: "old", name: "Last month's responder", role: "external", emails: ["old@partner.test"], expiresAt: yesterday }, "bo@team.test")).status, 200);
	assert.equal((await get("/api/v1/members/old/audit", "old@partner.test")).status, 403, "an expired external is nobody");
	// (A parent/child body still works — the aliases of the migration.)
	assert.equal((await add({ id: "kid", name: "Alias", role: "child", emails: ["kid@team.test"] }, "bo@team.test")).status, 200);
	assert.equal((await get("/api/v1/family", "bo@team.test")).json.members.find((m) => m.id === "kid").role, "analyst");

	console.log("ok  api:roles — lead/analyst/auditor/external scopes, audits for auditors, no registry for externals, last-lead guards, expiry, aliases");
} finally {
	await dev.close();
}
