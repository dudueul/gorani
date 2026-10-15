// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:access — the production perimeter (worker/src/auth.rs), with dev mode
 * OFF: its own server whose TEAM_DOMAIN is a stub Access team (a JWKS on
 * this machine), and ES256 tokens signed here as Access would sign them.
 * Until commit 33a no suite ran the Worker in this mode at all. What it
 * proves:
 *
 *   1. a member's token (an Access *user* JWT — what `cloudflared access
 *      token` yields, and what the desktop client now sends) is the member:
 *      their email, their rules;
 *   2. a service token's JWT — Access's machine identity, with a
 *      `common_name` and NO email — is no member: the desktop client used
 *      to sign in this way, and every request it made was refused
 *      (docs/DESKTOP.md). Since commit 37a it is a COLLECTOR identity —
 *      refused on every member route, and on the drop routes until two
 *      leads registered it (api:collectors);
 *   3. the checks around them hold: no token, a wrong audience, an expired
 *      token, another issuer, a forged signature, an unknown key, `alg`
 *      other than ES256 — each refused.
 */

import assert from "node:assert/strict";
import { createSign, generateKeyPairSync } from "node:crypto";
import http from "node:http";
import os from "node:os";
import { startDev } from "./_dev.mjs";

// ── A stub Access team: one P-256 key behind /cdn-cgi/access/certs ────
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "gorani-test-key";
const jwks = http.createServer((req, res) => {
	if (req.url === "/team/cdn-cgi/access/certs") res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ keys: [{ kid: KID, kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, alg: "ES256" }] }));
	else res.writeHead(404).end();
});
await new Promise((r) => jwks.listen(0, "0.0.0.0", r));
const lan = Object.values(os.networkInterfaces()).flatMap((x) => x ?? []).find((x) => x && !x.internal && x.family === "IPv4")?.address ?? "127.0.0.1";
// (Under a prefix: `wrangler dev` answers a Worker's own fetch of any
// `/cdn-cgi/…` path itself — it hung there. auth.rs takes a full certs URL
// in TEAM_DOMAIN, and the issuer is that URL's base.)
const TEAM = `http://${lan}:${jwks.address().port}/team`;
const CERTS = `${TEAM}/cdn-cgi/access/certs`;
const AUD = "gorani-test-aud";
const BOOT = "a-bootstrap-token-for-the-access-suite";

const b64u = (b) => Buffer.from(b).toString("base64url");
/** A compact ES256 JWT, as Access mints them (P1363 signature). */
function jwt(claims, { key = privateKey, kid = KID, alg = "ES256" } = {}) {
	const head = b64u(JSON.stringify({ alg, kid, typ: "JWT" }));
	const body = b64u(JSON.stringify(claims));
	const sig = createSign("SHA256").update(`${head}.${body}`).sign({ key, dsaEncoding: "ieee-p1363" });
	return `${head}.${body}.${b64u(sig)}`;
}
const now = () => Math.floor(Date.now() / 1000);
const member = (email, extra = {}) => jwt({ iss: TEAM, aud: AUD, email, sub: `user-${email}`, iat: now(), exp: now() + 600, type: "app", ...extra });
// A service token's JWT: Access's machine identity — a common_name, no email.
const service = () => jwt({ iss: TEAM, aud: AUD, common_name: "8d7e2a0b.access", sub: "", iat: now(), exp: now() + 600, type: "app" });

const dev = await startDev({ persist: "access", vars: { GORANI_DEV: "0", POLICY_AUD: AUD, TEAM_DOMAIN: CERTS, BOOTSTRAP_TOKEN: BOOT } });
const call = (method, path, token, body, extra = {}) =>
	fetch(`${dev.base}${path}`, { method, headers: { ...(token ? { "CF-Access-JWT-Assertion": token } : {}), ...(body ? { "content-type": "application/json" } : {}), ...extra }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => ({ status: r.status, text: await r.text() }));

try {
	// ── 1. A member's token is the member ────────────────────────────────
	const first = await call("POST", "/api/v1/family/members", member("ana@team.test"), { id: "ana", name: "Ana", role: "lead", emails: ["ana@team.test"] }, { "x-gorani-bootstrap": BOOT });
	assert.equal(first.status, 200, `the first lead, bootstrapped with a member token: ${first.text}`);
	const state = await call("GET", "/api/v1/family", member("ana@team.test"));
	assert.equal(state.status, 200, state.text);
	assert.ok(JSON.parse(state.text).members.some((m) => m.id === "ana"), "ana's token reads ana's registry");
	assert.notEqual((await call("GET", "/api/v1/family", member("stranger@elsewhere.test"))).status, 200, "a valid token of someone the team never registered is no one here");

	// ── 2. A service token is not a member ─────────────────────────────
	// Since commit 37a it is a COLLECTOR identity (its JWT names a
	// common_name, no email): refused on every member route, and on the drop
	// routes too until two leads have registered it (api:collectors).
	const svc = await call("GET", "/api/v1/family", service());
	assert.equal(svc.status, 403, "a service token's JWT carries no email — it is no member");
	assert.match(svc.text, /only the drop routes/, `refused as a collector: ${svc.text}`);
	const unregistered = await call("GET", "/api/v1/collect/whoami", service());
	assert.equal(unregistered.status, 403);
	assert.match(unregistered.text, /not a registered, active collector/);
	const nobody = await call("GET", "/api/v1/family", jwt({ iss: TEAM, aud: AUD, sub: "", iat: now(), exp: now() + 600, type: "app" }));
	assert.match(nobody.text, /no email/, "a token naming neither an email nor a common_name is no one");

	// ── 3. Every check around them ───────────────────────────────────────
	const refused = async (token, why) => {
		const r = await call("GET", "/api/v1/family", token);
		assert.notEqual(r.status, 200, `${why}: ${r.text}`);
		return r.text;
	};
	assert.match(await refused(null, "no token"), /missing Access token/);
	assert.match(await refused(member("ana@team.test", { aud: "someone-elses-app" }), "another application's token"), /audience/);
	assert.match(await refused(member("ana@team.test", { exp: now() - 60 }), "an expired token"), /expired/);
	assert.match(await refused(member("ana@team.test", { iss: "https://evil.cloudflareaccess.com" }), "another team's issuer"), /issuer/);
	assert.match(await refused(jwt({ iss: TEAM, aud: AUD, email: "ana@team.test", exp: now() + 600 }, { key: other.privateKey }), "signed by a key the team does not hold"), /bad signature/);
	assert.match(await refused(jwt({ iss: TEAM, aud: AUD, email: "ana@team.test", exp: now() + 600 }, { kid: "unknown" }), "an unknown key id"), /unknown token key/);
	assert.match(await refused(jwt({ iss: TEAM, aud: AUD, email: "ana@team.test", exp: now() + 600 }, { alg: "HS256" }), "alg confusion"), /not ES256/);
	// A good token with one claim changed after signing: the signature covers the claims.
	const [h, , s] = member("ana@team.test").split(".");
	assert.match(await refused(`${h}.${b64u(JSON.stringify({ iss: TEAM, aud: AUD, email: "mallory@team.test", exp: now() + 600 }))}.${s}`, "claims edited after signing"), /bad signature/);

	console.log("ok  api:access — dev mode off: a member's Access token is the member; a service token (no email) refused on member routes and, unregistered, on the drop routes; missing, foreign-audience, expired, foreign-issuer, forged, unknown-key and non-ES256 tokens each refused by name");
} finally {
	await dev.close();
	await new Promise((r) => jwks.close(r));
}
