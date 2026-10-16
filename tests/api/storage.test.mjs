// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:storage — a storage refusal says why (commit 39s).
 *
 * Found in production: the first upload to gorani.at.day failed with
 * "internal error", and the Worker's log said "S3 put …: HTTP 403" and
 * nothing more. A 403 has five usual causes with five different fixes —
 * a wrong secret or region (SignatureDoesNotMatch), an unknown key
 * (InvalidAccessKeyId), a key without write rights (AccessDenied), or
 * something in front of the endpoint that is not S3 at all (Cloudflare
 * Access on a tunnel, a proxy's login page). S3 says which in the error
 * body's <Code>; the Worker threw it away. Its own server, so the stub's
 * faults and the settings below are this suite's alone:
 *
 *   1. a lead's Check storage: write, size, read and delete of a probe
 *      object, all passing — and the settings shown without the secret
 *      (its length only) and with only the access key id's last four;
 *   2. the same check against a refusing storage: the step that failed,
 *      S3's code, the hint — for SignatureDoesNotMatch, AccessDenied, and a
 *      code-less 403 from Cloudflare (named as not S3's answer at all);
 *   3. an upload the storage refuses: the member hears 502 with the code,
 *      never the object key;
 *   4. only a lead may run the check.
 */

import assert from "node:assert/strict";
import { startDev, api, stubFault } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { member } from "../lib/team.mjs";

// Credentials that look like a deployment's, so "never shown" can be checked.
const KEY_ID = "GORANIPROBEKEY7Q2X";
const SECRET = "probe-secret-must-never-be-shown-0123456789";
const dev = await startDev({ vars: { S3_ACCESS_KEY_ID: KEY_ID, S3_SECRET_KEY: SECRET } });
const enc = new TextEncoder();

/** A stub refusal shaped like S3's: the status, an <Error><Code> body, a Server header. */
const refuse = (prefix, status, code, server) => stubFault(dev, { method: "PUT", prefix, status, count: 1, code, server });

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const check = async (who = ana) => api(dev.base, "POST", "/api/v1/family/storage/probe", { email: who.email });

	// ── 1. The check passes, and shows no secret ──────────────────────
	const ok = await check();
	assert.equal(ok.status, 200, ok.text);
	assert.equal(ok.json.backend, "s3");
	assert.equal(ok.json.ok, true, ok.text);
	assert.deepEqual(ok.json.steps.map((s) => [s.step, s.ok]), [["write", true], ["size", true], ["read", true], ["delete", true]]);
	assert.ok(!ok.text.includes(SECRET), "the secret is never in the answer");
	assert.ok(!ok.text.includes(KEY_ID), "nor the whole access key id");
	const shown = Object.fromEntries(ok.json.settings.map((v) => [v.name, v]));
	assert.equal(shown.S3_ACCESS_KEY_ID.shown, `…${KEY_ID.slice(-4)}`, "the key id's last four characters");
	assert.equal(shown.S3_SECRET_KEY.shown, `${SECRET.length} characters`, "the secret's length only");
	assert.equal(shown.S3_BUCKET.shown, "gorani-test");
	assert.ok(ok.json.settings.every((v) => v.set && !v.padded), "all five set, none padded");
	const left = await fetch(`${dev.s3}?list-type=2&prefix=probe/`);
	assert.ok(!/<Key>/.test(await left.text()), "the probe deleted its object");

	// ── 2. A refusing storage, explained ──────────────────────────────
	await refuse("probe/", 403, "SignatureDoesNotMatch");
	let bad = await check();
	assert.equal(bad.json.ok, false);
	assert.equal(bad.json.steps.length, 1, "it stops at the first refusal");
	assert.equal(bad.json.steps[0].step, "write");
	assert.equal(bad.json.steps[0].status, 403);
	assert.match(bad.json.steps[0].reason, /SignatureDoesNotMatch — .*S3_SECRET_KEY.*S3_REGION/);

	await refuse("probe/", 403, "AccessDenied");
	bad = await check();
	assert.match(bad.json.steps[0].reason, /AccessDenied — the key is valid but not allowed/);

	await refuse("probe/", 403, undefined, "cloudflare");
	bad = await check();
	assert.match(bad.json.steps[0].reason, /not an S3 answer: Cloudflare/, "a code-less 403 from Cloudflare is not the storage's");
	assert.equal(bad.json.steps[0].server, "cloudflare");

	// ── 3. An upload the storage refuses tells the member why ─────────
	const ck = newContentKey();
	const f = await bo.sealer.newFile("notes.txt", "text/plain", ck);
	const plain = enc.encode("the first upload of a new deployment");
	const boundary = `s${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries({ ...f.fields, size: String(plain.length) }).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const sealed = await sealWith(await importContentKey(ck), plain);
	await refuse("files/bo/", 403, "AccessDenied");
	const r = await fetch(`${dev.base}/api/v1/members/bo/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": bo.email }, body: new Uint8Array([...head, ...sealed, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	const body = await r.text();
	assert.equal(r.status, 502, body);
	assert.match(JSON.parse(body).error, /the storage refused this \(HTTP 403 AccessDenied\) — a lead can run Team › People › Check storage/);
	assert.ok(!body.includes("files/bo/"), `the object key stays in the operator's log: ${body}`);

	// ── 4. Only a lead ────────────────────────────────────────────────
	const not = await check(bo);
	assert.equal(not.status, 403);

	console.log("ok  api:storage — Check storage: write/size/read/delete pass with no secret shown (its length, the key id's last four); SignatureDoesNotMatch, AccessDenied and Cloudflare's code-less 403 each explained at the step that failed; a refused upload tells the member the code, not the key; leads only");
} finally {
	await dev.close();
}
