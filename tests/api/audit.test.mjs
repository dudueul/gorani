// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:audit — the tamper-evident trail (commit 29, docs/CUSTODY.md › Stage
 * 1; worker/src/audit.rs). What it proves:
 *
 *   1. every area's lines reach its chained trail (the outbox empties) and
 *      the chain recomputes HERE, in JavaScript, from the lines alone — one
 *      spelling across two languages, like every signed statement;
 *   2. no line cap: the old 500-line housekeeping prune is gone, a forced
 *      "keep 1" keeps everything;
 *   3. the nightly pass writes each area's checkpoint to the BUCKET, and
 *      verification compares the chain with every checkpoint it finds there;
 *   4. a checkpoint rewritten in the bucket (or one naming lines the chain
 *      no longer has) fails verification — the database and the bucket must
 *      agree, and changing one is caught by the other;
 *   5. the same for a case's trail and the registry's, each for its own
 *      audience.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { suiteDev, api } from "./_dev.mjs";
import { member, vouch, openCase } from "../lib/team.mjs";

const dev = await suiteDev();
const fire = () => fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`);
const ZERO = "0".repeat(64);
const lp = (...fields) => Buffer.concat(fields.map((f) => { const b = Buffer.from(String(f), "utf8"); const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); }));
const canonical = (l) => lp("gorani-audit-v1", l.id, l.at, l.actor, l.action, l.target, l.details ?? "", l.detailsSealed ?? "");
const link = (prev, l) => createHash("sha256").update(prev).update(canonical(l)).digest("hex");

/** Recompute a whole trail (lines newest first, from the API) from ZERO. */
function recompute(lines) {
	const asc = [...lines].reverse();
	let prev = ZERO;
	asc.forEach((l, i) => {
		assert.equal(l.id, i + 1, "sequence numbers run 1, 2, 3, … with no gap");
		assert.equal(link(prev, l), l.hash, `line ${l.id} hashes to its link`);
		prev = l.hash;
	});
	return prev;
}

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const cy = await member(dev, "cy", "auditor", { by: ana });
	await vouch(dev, ana, [bo, cy]);

	// ── 1. Lines ship and chain ──────────────────────────────────────────
	const folderId = bo.sealer.newId();
	assert.equal((await api(dev.base, "POST", "/api/v1/members/bo/files/folders", { email: bo.email, body: { id: folderId, name: await bo.sealer.folderName(folderId, "Reports") } })).status, 200);
	const trail = (await api(dev.base, "GET", "/api/v1/members/bo/audit", { email: bo.email })).json;
	assert.ok(trail.length >= 2, `bo's trail: ${trail.map((l) => l.action)}`);
	assert.ok(trail.every((l) => !l.pending && typeof l.hash === "string"), "every line has left the outbox and carries its link");
	recompute(trail);

	// ── 2. No cap ─────────────────────────────────────────────────────
	const before = trail.length;
	assert.equal((await api(dev.base, "POST", "/api/v1/members/bo/housekeeping", { email: bo.email, body: { auditKeep: 1 } })).status, 200);
	const after = (await api(dev.base, "GET", "/api/v1/members/bo/audit", { email: bo.email })).json;
	assert.ok(after.length >= before, "housekeeping keeps every line now (it used to cut to auditKeep)");
	recompute(after);

	// ── 3. Checkpoints in the bucket; verification ────────────────────
	const empty = (await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: cy.email })).json;
	assert.equal(empty.ok, true, JSON.stringify(empty));
	assert.equal(empty.checkpoints.length, 0, "no checkpoint before the first nightly pass");
	assert.equal((await fire()).status, 200);
	const today = new Date().toISOString().slice(0, 10);
	const key = `audit-checkpoints/members/bo/${today}.json`;
	const cp = await fetch(`${dev.s3}/${key}`);
	assert.equal(cp.status, 200, "the checkpoint is in the bucket, outside the database");
	const cpBody = await cp.json();
	assert.equal(cpBody.area, "bo");
	const verified = (await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: cy.email })).json;
	assert.equal(verified.ok, true, JSON.stringify(verified));
	assert.deepEqual(verified.checkpoints.map((c) => c.status), ["ok"]);
	assert.equal(verified.chain.lines, cpBody.seq + (verified.chain.lastSeq - cpBody.seq), "the chain covers the checkpoint");
	for (const who of [bo, cy, ana]) assert.equal((await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: who.email })).status, 200, `${who.id} may verify bo's trail (the audit's audience)`);
	const outsider = await member(dev, "dee", "analyst", { by: ana });
	assert.equal((await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: outsider.email })).status, 403);

	// ── 4. The bucket and the database must agree ─────────────────────
	const put = (k, body) => fetch(`${dev.s3}/${k}`, { method: "PUT", body: JSON.stringify(body) });
	await put(key, { ...cpBody, hash: "f".repeat(64) });
	const rewritten = (await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: cy.email })).json;
	assert.equal(rewritten.ok, false);
	assert.equal(rewritten.checkpoints[0].status, "mismatch", "a checkpoint that disagrees with the chain: one of the two was rewritten");
	// A checkpoint naming more lines than the chain has: lines removed from the end.
	await put(key, cpBody);
	await put(`audit-checkpoints/members/bo/2099-01-01.json`, { ...cpBody, date: "2099-01-01", seq: cpBody.seq + 1000 });
	const truncated = (await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: cy.email })).json;
	assert.equal(truncated.ok, false);
	assert.ok(truncated.checkpoints.some((c) => c.status === "missing" && /removed from the end/.test(c.why)));
	await fetch(`${dev.s3}/audit-checkpoints/members/bo/2099-01-01.json`, { method: "DELETE" });
	assert.equal((await api(dev.base, "GET", "/api/v1/members/bo/audit/verify", { email: cy.email })).json.ok, true, "restored: the trail verifies again");

	// ── 5. A case's trail, and the registry's ─────────────────────────
	const kase = await openCase(dev, ana, "ir-audit", "Audit test", [[bo, "write"]]);
	const fid = kase.sealer.newId();
	assert.equal((await api(dev.base, "POST", `${kase.base}/files/folders`, { email: bo.email, body: { id: fid, name: await kase.sealer.folderName(fid, "Evidence") } })).status, 200);
	const caseTrail = (await api(dev.base, "GET", `${kase.base}/audit`, { email: cy.email })).json;
	assert.ok(caseTrail.length >= 1);
	recompute(caseTrail);
	assert.equal((await fire()).status, 200);
	assert.equal((await fetch(`${dev.s3}/audit-checkpoints/cases/ir-audit/${today}.json`)).status, 200);
	assert.equal((await api(dev.base, "GET", `${kase.base}/audit/verify`, { email: cy.email })).json.ok, true);
	assert.equal((await api(dev.base, "GET", `${kase.base}/audit/verify`, { email: outsider.email })).status, 403);

	const registry = (await api(dev.base, "GET", "/api/v1/family", { email: ana.email })).json.audit;
	assert.ok(registry.some((l) => l.action === "case.create") && registry.every((l) => !l.pending));
	recompute(registry.map((l) => ({ ...l, detailsSealed: null })));
	assert.equal((await fetch(`${dev.s3}/audit-checkpoints/registry/${today}.json`)).status, 200);
	assert.equal((await api(dev.base, "GET", "/api/v1/family/audit/verify", { email: cy.email })).json.ok, true);
	assert.equal((await api(dev.base, "GET", "/api/v1/family/audit/verify", { email: bo.email })).status, 403, "the registry's trail: leads and auditors");

	console.log("ok  api:audit — lines leave the outbox and chain (recomputed in JS), no cap, checkpoints in the bucket, rewrites and truncation caught, cases and the registry too");
} finally {
	await dev.close();
}
