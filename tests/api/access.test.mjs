// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:access — the production perimeter (worker/src/auth.rs), with dev mode
 * OFF: its own server whose TEAM_DOMAIN is a stub Access team (a JWKS on
 * this machine, in the shape Access serves it), and RS256 tokens signed
 * here as Access signs them.
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
 *      other than RS256 (HS256, and an ES256 token as this suite once
 *      minted), a key of the wrong type under the token's key id — each
 *      refused.
 *
 * (Until commit 39k the stub team signed ES256 — the algorithm auth.rs
 * assumed. Access signs RS256, so every test here passed while no real
 * token could: the first deployment refused every request, "signature is
 * not 64 bytes". A stub is only as good as its likeness: this one now
 * serves RSA keys, Access's response shape included.)
 */

import assert from "node:assert/strict";
import { createSign, generateKeyPairSync } from "node:crypto";
import http from "node:http";
import os from "node:os";
import { startDev } from "./_dev.mjs";

// ── A stub Access team: RSA keys behind /cdn-cgi/access/certs ──────────
// As Access serves them: `keys` (JWKs, RS256) beside `public_cert` and
// `public_certs` (the same keys as PEM) — the Worker reads `keys` and must
// not trip over the rest. A P-256 key sits in the set under its own id: an
// ES256 token naming it, or an RS256 token claiming it, must be refused.
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const ecJwk = ec.publicKey.export({ format: "jwk" });
const KID = "gorani-test-key";
const EC_KID = "gorani-test-ec-key";
const pem = publicKey.export({ format: "pem", type: "spki" });
const certsBody = JSON.stringify({
	keys: [
		{ kid: KID, kty: "RSA", alg: "RS256", use: "sig", e: jwk.e, n: jwk.n },
		{ kid: EC_KID, kty: "EC", crv: "P-256", x: ecJwk.x, y: ecJwk.y },
	],
	public_cert: { kid: KID, cert: pem },
	public_certs: [{ kid: KID, cert: pem }],
});
const jwks = http.createServer((req, res) => {
	if (req.url === "/team/cdn-cgi/access/certs") res.writeHead(200, { "content-type": "application/json" }).end(certsBody);
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
/** A compact RS256 JWT, as Access mints them (PKCS #1 v1.5, SHA-256) — or,
 * with an EC key, an ES256 one (P1363 signature) for the refusals. */
function jwt(claims, { key = privateKey, kid = KID, alg = "RS256" } = {}) {
	const head = b64u(JSON.stringify({ alg, kid, typ: "JWT" }));
	const body = b64u(JSON.stringify(claims));
	const sig = createSign("SHA256").update(`${head}.${body}`).sign(key.asymmetricKeyType === "ec" ? { key, dsaEncoding: "ieee-p1363" } : key);
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
	const claims = { iss: TEAM, aud: AUD, email: "ana@team.test", exp: now() + 600 };
	assert.match(await refused(jwt(claims, { alg: "HS256" }), "alg confusion: HS256"), /not RS256/);
	assert.match(await refused(jwt(claims, { key: ec.privateKey, kid: EC_KID, alg: "ES256" }), "an ES256 token (what this suite minted until 39k)"), /not RS256/);
	assert.match(await refused(jwt(claims, { key: ec.privateKey, kid: EC_KID }), "an RS256 header over a key that is not RSA"), /not an RS256 RSA key/);
	// A good token with one claim changed after signing: the signature covers the claims.
	const [h, , s] = member("ana@team.test").split(".");
	assert.match(await refused(`${h}.${b64u(JSON.stringify({ iss: TEAM, aud: AUD, email: "mallory@team.test", exp: now() + 600 }))}.${s}`, "claims edited after signing"), /bad signature/);

	console.log("ok  api:access — dev mode off: a member's Access token is the member; a service token (no email) refused on member routes and, unregistered, on the drop routes; missing, foreign-audience, expired, foreign-issuer, forged, unknown-key, non-RS256 (HS256, ES256) and wrong-key-type tokens each refused by name — against a JWKS in Access's own shape");
} finally {
	await dev.close();
	await new Promise((r) => jwks.close(r));
}
