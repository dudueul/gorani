// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:retention — retention by kind (commit 29b, docs/CUSTODY.md › Stage 2;
 * docs/DECISIONS.md › D7). What it proves:
 *
 *   1. a working area (a member's own; a working case) keeps a file's older
 *      versions for the retention window, then prunes them — objects
 *      through the deletion outbox, rows after — and NEVER the current one;
 *   2. an evidence case refuses to trash a file or a folder, and keeps every
 *      version through the same housekeeping that prunes a working area;
 *   3. the kind is fixed when the case is opened: there is no route that
 *      rewrites a case's settings.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { member, vouch, openCase } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();

async function post(who, path, fields, file) {
	const boundary = `r${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, json: await r.json() };
}

/** A file with two versions in `base`, sealed by `sealer`. */
async function twoVersions(who, base, sealer, name) {
	const ck1 = newContentKey();
	const f = await sealer.newFile(name, "text/plain", ck1);
	const v1 = enc.encode("first");
	assert.equal((await post(who, `${base}/files`, { ...f.fields, size: String(v1.length) }, await sealWith(await importContentKey(ck1), v1))).status, 200);
	const ck2 = newContentKey();
	const v2 = enc.encode("second");
	const r = await post(who, `${base}/files/${f.id}/versions`, { ck: await sealer.fileKey(f.id, 2, ck2), type: await sealer.fileType(f.id, 2, "text/plain"), size: String(v2.length), base_version: "1" }, await sealWith(await importContentKey(ck2), v2));
	assert.equal(r.status, 200, JSON.stringify(r.json));
	return f.id;
}

const versionsOf = async (who, base, id) => (await api(dev.base, "GET", `${base}/files/sealed?kind=version&after=0&limit=100`, { email: who.email })).json.items.filter((v) => v.a === id).map((v) => Number(v.b)).sort();
const download = (who, base, id, version) => fetch(`${dev.base}${base}/files/${id}?version=${version}`, { headers: { "x-gorani-dev-email": who.email } });

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo]);

	// ── 1. A working area: older versions age out; the current one never ─
	const own = "/api/v1/members/bo";
	const f1 = await twoVersions(bo, own, bo.sealer, "draft.txt");
	assert.deepEqual(await versionsOf(bo, own, f1), [1, 2]);
	const keep = await api(dev.base, "POST", `${own}/housekeeping`, { email: bo.email, body: {} });
	assert.equal(keep.json.versionsPruned, 0, "inside the year: both versions stay");
	const prune = await api(dev.base, "POST", `${own}/housekeeping`, { email: bo.email, body: { versionDays: 0 } });
	assert.equal(prune.json.versionsPruned, 1, JSON.stringify(prune.json));
	assert.ok(prune.json.objectsDeleted >= 1, "the old version's object left storage (the outbox drained)");
	assert.deepEqual(await versionsOf(bo, own, f1), [2], "version 1 is gone; the current version never ages out");
	assert.equal((await download(bo, own, f1, 1)).status, 404);
	assert.equal((await download(bo, own, f1, 2)).status, 200);

	// A working case behaves the same — and lets a file be trashed.
	const working = await openCase(dev, ana, "ops-notes", "Working notes", [[bo, "write"]]);
	const w1 = await twoVersions(bo, working.base, working.sealer, "runbook.md");
	assert.equal((await api(dev.base, "POST", `${working.base}/housekeeping`, { email: ana.email, body: { versionDays: 0 } })).json.versionsPruned, 1);
	assert.equal((await api(dev.base, "DELETE", `${working.base}/files/${w1}`, { email: bo.email })).status, 200, "a working case's file goes to the Trash");

	// ── 2. An evidence case: nothing leaves ────────────────────────────
	const evidence = await openCase(dev, ana, "ir-2026-099", "Evidence", [[bo, "write"]], "evidence");
	const e1 = await twoVersions(bo, evidence.base, evidence.sealer, "memory.dmp");
	const folderId = evidence.sealer.newId();
	assert.equal((await api(dev.base, "POST", `${evidence.base}/files/folders`, { email: bo.email, body: { id: folderId, name: await evidence.sealer.folderName(folderId, "Host A") } })).status, 200);
	const trash = await api(dev.base, "DELETE", `${evidence.base}/files/${e1}`, { email: bo.email });
	assert.equal(trash.status, 409, "evidence is never trashed");
	assert.match(trash.json.error, /evidence case/);
	assert.equal((await api(dev.base, "DELETE", `${evidence.base}/files/folders/${folderId}`, { email: ana.email })).status, 409, "…nor its folders — not even by its manager");
	const hk = await api(dev.base, "POST", `${evidence.base}/housekeeping`, { email: ana.email, body: { versionDays: 0, trashDays: 0 } });
	assert.equal(hk.json.evidence, true);
	assert.equal(hk.json.versionsPruned, 0, "the same housekeeping that pruned the working area keeps every evidence version");
	assert.deepEqual(await versionsOf(bo, evidence.base, e1), [1, 2]);
	assert.equal((await download(bo, evidence.base, e1, 1)).status, 200, "version 1 of evidence still downloads");
	// The nightly pass (no dev knobs: the deployment defaults) keeps it too.
	assert.equal((await fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`)).status, 200);
	assert.deepEqual(await versionsOf(bo, evidence.base, e1), [1, 2]);

	// ── 3. The kind is fixed at opening ────────────────────────────────
	assert.equal((await api(dev.base, "PUT", `${evidence.base}/vault`, { email: ana.email, body: { settings: { enabled: true, case: "ir-2026-099", kind: "working" } } })).status, 404, "no route rewrites a case's settings");
	assert.equal((await api(dev.base, "DELETE", `${evidence.base}/files/${e1}`, { email: bo.email })).status, 409, "still evidence");

	console.log("ok  api:retention — working areas prune older versions (never the current), evidence keeps every version and refuses deletion, the kind fixed at opening");
} finally {
	await dev.close();
}
