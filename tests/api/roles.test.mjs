// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:roles — the team's four roles (commit 26, docs/CASES.md › Roles):
 *
 *   lead     manages the registry — and, since commit 27c, acts for no
 *            area but their own (content needs a grant or a ceremony)
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
	assert.equal((await get("/api/v1/members/bo/files/list", "ana@team.test")).status, 403, "…not even a lead (the family's parent rule is gone, commit 27c)");
	assert.equal((await api(dev.base, "PUT", "/api/v1/family/master", { email: "ana@team.test", body: {} })).status, 404, "the family master key is gone too");

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
	// The family's role names are gone with the master key (a clean break).
	assert.equal((await add({ id: "kid", name: "Old name", role: "child", emails: ["kid@team.test"] }, "bo@team.test")).status, 400, "parent/child are no longer roles");

	// ── 7. What a lead types (commit 39l: Team › People manages members) ─
	// Each field is checked the way it is used, and a change is all or
	// nothing.
	const member = async (id) => (await get("/api/v1/family", "bo@team.test")).json.members.find((m) => m.id === id);
	assert.equal((await add({ id: "fay", name: "  Fay  ", role: "analyst", emails: [" Fay@Team.Test ", "fay@team.test"] }, "bo@team.test")).status, 200);
	assert.deepEqual([(await member("fay")).name, (await member("fay")).emails], ["Fay", ["fay@team.test"]], "trimmed; addresses lower-cased (as Access compares them) and each once");
	assert.equal((await api(dev.base, "GET", "/api/v1/me", { email: "FAY@team.test" })).json.member?.id, "fay", "…and found whatever case the sign-in uses");
	for (const [body, what] of [
		[{ id: "gus", name: "Gus", role: "analyst", emails: [] }, "no sign-in address"],
		[{ id: "gus", name: "Gus", role: "analyst", emails: ["gus"] }, "not an address"],
		[{ id: "gus", name: "Gus", role: "analyst", emails: ["gus@team.test, ana@team.test"] }, "two addresses in one"],
		[{ id: "gus", name: "Gus\nlead: ana", role: "analyst", emails: ["gus@team.test"] }, "a control character in a name"],
		[{ id: "gus", name: "", role: "analyst", emails: ["gus@team.test"] }, "an empty name"],
		[{ id: "gus", name: "Gus", role: "external", emails: ["gus@team.test"], expiresAt: "never" }, "an expiry that is not a time"],
	]) assert.equal((await add(body, "bo@team.test")).status, 400, `${what} is refused`);
	assert.equal((await add({ id: "gus", name: "Gus", role: "external", emails: ["gus@partner.test"], expiresAt: "2099-12-31" }, "bo@team.test")).status, 200);
	assert.equal((await member("gus")).expiresAt, "2099-12-31T23:59:59.999Z", "a bare day means the end of that day, UTC");
	// All or nothing: the role change is not saved when the address is refused.
	assert.equal((await patch("fay", { role: "auditor", emails: ["bo@team.test"] }, "bo@team.test")).status, 409, "an address another member holds");
	assert.equal((await member("fay")).role, "analyst", "…and nothing of that change was saved");
	assert.equal((await patch("fay", { expiresAt: "2099-01-01" }, "bo@team.test")).status, 400, "only externals expire — said, not silently ignored");
	assert.equal((await patch("fay", { name: "Fay K.", emails: ["fay.k@team.test"] }, "bo@team.test")).status, 200);
	assert.deepEqual([(await member("fay")).name, (await member("fay")).emails], ["Fay K.", ["fay.k@team.test"]]);
	// A lead cannot sign themselves out of their own account.
	assert.equal((await patch("bo", { emails: ["bo.new@team.test"] }, "bo@team.test")).status, 409, "the address you are signed in with stays");
	assert.equal((await patch("bo", { emails: ["bo@team.test", "bo.new@team.test"] }, "bo@team.test")).status, 200, "…adding one is fine");
	// Deactivation is final, and an address stays with its account.
	assert.equal((await api(dev.base, "POST", "/api/v1/family/members/fay/deactivate", { email: "bo@team.test" })).status, 200);
	assert.equal((await patch("fay", { name: "Fay again" }, "bo@team.test")).status, 409, "a deactivated member is not edited back into use");
	const reuse = await add({ id: "fay2", name: "Fay", role: "analyst", emails: ["fay.k@team.test"] }, "bo@team.test");
	assert.equal(reuse.status, 409);
	assert.match(reuse.json.error, /deactivated/, "the refusal says why the address is not free");
	const update = (await get("/api/v1/family", "bo@team.test")).json.audit.find((l) => l.action === "member.update" && l.target === "fay");
	assert.match(update?.details ?? "", /fay\.k@team\.test/, "member.update records the new addresses — who can sign in AS the member");

	console.log("ok  api:roles — lead/analyst/auditor/external scopes, audits for auditors, no registry for externals, last-lead guards, expiry, no act-for, no family roles; (39l) member fields checked as they are used (names, sign-in addresses, one expiry shape), changes all or nothing, no signing yourself out, deactivation final and addresses never reused");
} finally {
	await dev.close();
}
