// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:objectlock — write-once evidence (commit 29c, docs/CUSTODY.md › Stage
 * 3; docs/DECISIONS.md › D6). Its own server, with OBJECT_LOCK=on (the
 * runner's shared server keeps it off, as a deployment does until its
 * bucket has Object Lock). What it proves:
 *
 *   1. an evidence upload's object gets a COMPLIANCE retention until its
 *      creation + EVIDENCE_RETAIN_DAYS, in the same request;
 *   2. storage itself then refuses to delete it — a credential that skips
 *      the Worker cannot destroy evidence;
 *   3. a working case's objects are not locked (they have a Trash and a
 *      purge);
 *   4. a lock that fails is not lost: the version stays unlocked, visibly,
 *      and the next request locks it;
 *   5. the audit checkpoints (stage 1) are locked too.
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { member, vouch, openCase, signedHash } from "../lib/team.mjs";

const dev = await startDev({ vars: { OBJECT_LOCK: "on", EVIDENCE_RETAIN_DAYS: "30" } });
const enc = new TextEncoder();

async function upload(who, base, sealer, name) {
	const ck = newContentKey();
	const f = await sealer.newFile(name, "application/octet-stream", ck);
	const plain = enc.encode(`bytes of ${name}`);
	const boundary = `l${Math.random().toString(16).slice(2)}`;
	const fields = { ...f.fields, size: String(plain.length), hash: await signedHash(who, sealer, f.id, 1, plain) };
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const sealed = await sealWith(await importContentKey(ck), plain);
	const r = await fetch(`${dev.base}${base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...sealed, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	assert.equal(r.status, 200, await r.text());
	return f.id;
}
const keysUnder = async (prefix) => [...(await (await fetch(`${dev.s3}?list-type=2&prefix=${encodeURIComponent(prefix)}`)).text()).matchAll(/<Key>([^<]+)<\/Key>/g)].map((m) => m[1]);
const retentionOf = async (key) => {
	const r = await fetch(`${dev.s3}/${key}?retention`);
	return r.status === 200 ? /<RetainUntilDate>([^<]+)</.exec(await r.text())[1] : null;
};
const daysFromNow = (iso) => (new Date(iso) - Date.now()) / 86_400_000;

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo]);
	const evidence = await openCase(dev, ana, "ir-lock", "Locked evidence", [[bo, "write"]], "evidence");
	const working = await openCase(dev, ana, "wk-lock", "Working notes", [[bo, "write"]]);

	// ── 1. Locked in the same request ─────────────────────────────────
	await upload(bo, evidence.base, evidence.sealer, "image.E01");
	const [key] = await keysUnder("cases/ir-lock/");
	assert.ok(key, "the evidence object is in the bucket");
	const until = await retentionOf(key);
	assert.ok(until, "…with a retention");
	assert.ok(Math.abs(daysFromNow(until) - 30) < 1.1, `until creation + EVIDENCE_RETAIN_DAYS (30): ${until}`);

	// ── 2. Storage refuses to delete it ───────────────────────────────
	const del = await fetch(`${dev.s3}/${key}`, { method: "DELETE" });
	assert.equal(del.status, 403, "a credential that skips the Worker cannot destroy evidence");
	assert.equal((await fetch(`${dev.s3}/${key}`)).status, 200, "the object is still there");

	// ── 3. Working objects are not locked ─────────────────────────────
	await upload(bo, working.base, working.sealer, "notes.md");
	const [wkey] = await keysUnder("cases/wk-lock/");
	assert.equal(await retentionOf(wkey), null, "a working case keeps its Trash and purge");

	// ── 4. A failed lock is retried, not lost ─────────────────────────
	const fault = await fetch(`${dev.s3Root}/__fault`, { method: "POST", body: JSON.stringify({ method: "PUT", prefix: "cases/ir-lock/", query: "retention", status: 500, count: 1 }) });
	assert.ok(fault.ok);
	await upload(bo, evidence.base, evidence.sealer, "memory.raw");
	const second = (await keysUnder("cases/ir-lock/")).find((k) => k !== key);
	assert.equal(await retentionOf(second), null, "storage refused the lock: the upload still landed, unlocked for now");
	await api(dev.base, "GET", `${evidence.base}/files/list`, { email: bo.email }); // any request runs the lock pass
	assert.ok(await retentionOf(second), "the next request locked it");

	// ── 5. The audit checkpoints are locked too ───────────────────────
	assert.equal((await fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`)).status, 200);
	const today = new Date().toISOString().slice(0, 10);
	const cp = await retentionOf(`audit-checkpoints/cases/ir-lock/${today}.json`);
	assert.ok(cp && daysFromNow(cp) > 7 * 365, `the checkpoint is kept as long as the audit: ${cp}`);
	assert.equal((await fetch(`${dev.s3}/audit-checkpoints/cases/ir-lock/${today}.json`, { method: "DELETE" })).status, 403);

	console.log("ok  api:objectlock — evidence locked in the request (COMPLIANCE, created + retention), storage refuses its deletion, working objects unlocked, a failed lock retried, checkpoints locked");
} finally {
	await dev.close();
}
