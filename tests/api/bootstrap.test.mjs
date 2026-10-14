// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:bootstrap — who may create the family's first member (commit 25,
 * docs/SECURITY-REVIEW.md › O18).
 *
 * Before: ANY authenticated caller. On a fresh deploy, whoever got through
 * Access first became a parent — a race that anyone with an allowed
 * identity (or a too-wide Access policy) wins. Now the operator sets a
 * `BOOTSTRAP_TOKEN` secret and presents it once; after that the token is
 * meaningless and only parents add members.
 *
 * Its own server (tests/run.mjs › ownServer): the token is configured here
 * and nowhere else — the other suites run on a dev server without one,
 * where bootstrapping stays free (worker/src/auth.rs › bootstrap_allowed,
 * whose production branch — no token, closed — is a Rust unit test).
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";

const TOKEN = "bootstrap-token-for-the-test-suite-only";
const dev = await startDev({ persist: "bootstrap", vars: { BOOTSTRAP_TOKEN: TOKEN } });
const create = (email, body, token) =>
	fetch(`${dev.base}/api/v1/family/members`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": email, ...(token ? { "x-gorani-bootstrap": token } : {}) },
		body: JSON.stringify(body),
	});
const mom = { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] };

try {
	// The race the token closes: the first caller through Access, no token.
	const raced = await create("stranger@elsewhere.test", { id: "eve", name: "Eve", role: "parent", emails: ["stranger@elsewhere.test"] });
	assert.equal(raced.status, 403, "without the token, nobody becomes the first parent");
	assert.equal((await create("stranger@elsewhere.test", { id: "eve", name: "Eve", role: "parent", emails: [] }, "a-guess")).status, 403, "nor with a guess");
	// A body that is not an object is refused, not a panic (O19's lesson).
	const notObject = await fetch(`${dev.base}/api/v1/family/members`, { method: "POST", headers: { "content-type": "application/json", "x-gorani-dev-email": "mom@family.test" }, body: "[]" });
	assert.equal(notObject.status, 400);
	// A client cannot forge the Worker's verdict.
	assert.equal((await create("stranger@elsewhere.test", { ...mom, id: "eve", emails: [], __bootstrap: "ok" })).status, 403, "a client-sent __bootstrap is overwritten");
	// The first member must be a parent.
	assert.equal((await create("kid@family.test", { id: "kid", name: "Kid", role: "child", emails: ["kid@family.test"] }, TOKEN)).status, 400);

	// The operator, with the token: the first parent.
	const first = await create("mom@family.test", mom, TOKEN);
	assert.equal(first.status, 200, await first.clone().text());
	// From here the token is irrelevant: a stranger holding it adds nobody…
	assert.equal((await create("stranger@elsewhere.test", { id: "eve", name: "Eve", role: "parent", emails: [] }, TOKEN)).status, 403, "the token opens the door once");
	// …and the parent needs none.
	const kid = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	assert.equal(kid.status, 200);
	const fam = await api(dev.base, "GET", "/api/v1/family", { email: "mom@family.test" });
	assert.deepEqual(fam.json.members.map((m) => m.id).sort(), ["jinu", "mom"]);

	console.log("ok  api:bootstrap — the first parent needs the operator's token, once; forged verdicts and odd bodies refused");
} finally {
	await dev.close();
}
