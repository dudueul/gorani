// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:siem — the audit, to the SIEM (commit 29i, docs/CUSTODY.md › Stage 7,
 * D5.4; worker/src/audit.rs › SIEM). Its own server, with SIEM_URL pointing
 * at tests/lib/siem-stub.mjs. What it proves:
 *
 *   1. every chained line reaches the collector by itself (the audit DO's
 *      alarm drains its queue — no request waits on the SIEM), in order,
 *      with the chain's own sequence number and hash on each event, and the
 *      token in the Authorization header;
 *   2. what is sealed stays sealed: no event carries a sealed value (GV04)
 *      or a `detailsSealed` field — a line with sealed details is sent with
 *      `sealed: true` and nothing else of them (no public route writes such
 *      a line today, so the unit test in worker/src/audit.rs › siem_tests
 *      proves that half);
 *   3. a collector that refuses loses nothing: the delivery is retried
 *      (with backoff) and every line arrives exactly once in its stream;
 *   4. the nightly pass drains every area too — the registry's trail
 *      included.
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";
import { startSiemStub } from "../lib/siem-stub.mjs";
import { member, vouch, openCase } from "../lib/team.mjs";

const siem = await startSiemStub();
const dev = await startDev({ vars: { SIEM_URL: siem.url, SIEM_FORMAT: "ndjson", SIEM_TOKEN: "test-siem-token" } });

/** Wait until `pred(events)` holds (the alarm runs on its own clock). */
async function until(pred, what, ms = 20_000) {
	const end = Date.now() + ms;
	for (;;) {
		if (pred(siem.events())) return;
		if (Date.now() > end) throw new Error(`timed out waiting for ${what}; got ${siem.events().length} events: ${JSON.stringify(siem.events().slice(-3))}`);
		await new Promise((r) => setTimeout(r, 250));
	}
}
const ofArea = (area) => siem.events().filter((e) => e.gorani.area === area);

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo]);

	// ── 1. Lines arrive on their own, in order, chained ──────────────────
	const folder = bo.sealer.newId();
	assert.equal((await api(dev.base, "POST", "/api/v1/members/bo/files/folders", { email: bo.email, body: { id: folder, name: await bo.sealer.folderName(folder, "Reports") } })).status, 200);
	const trail = (await api(dev.base, "GET", "/api/v1/members/bo/audit", { email: bo.email })).json;
	await until(() => ofArea("bo").length >= trail.length, "bo's lines");
	const got = ofArea("bo");
	assert.deepEqual(got.map((e) => e.gorani.seq), [...trail].reverse().map((l) => l.id), "every line, in chain order, no gap");
	assert.deepEqual(got.map((e) => e.gorani.hash), [...trail].reverse().map((l) => l.hash), "each with the chain's own hash — a SIEM can check continuity");
	assert.ok(got.some((e) => e.action === "folder.create" || e.action === "folder.put" || /folder/.test(e.action)), JSON.stringify(got.map((e) => e.action)));
	const first = siem.requests.find((r) => !r.refused);
	assert.equal(first.headers.authorization, "Bearer test-siem-token");
	assert.match(first.headers["content-type"], /application\/x-ndjson/);

	// ── 2. Nothing sealed leaves ─────────────────────────────────────────
	for (const e of siem.events()) assert.ok(!("detailsSealed" in e) && !JSON.stringify(e).includes("GV04:"), "no sealed value leaves");
	assert.ok(siem.events().every((e) => typeof e.sealed === "boolean"), "each event says whether its line had sealed details");

	// ── 3. A refusing collector loses nothing ───────────────────────────
	siem.failNext(2);
	const before = ofArea("bo").length;
	const second = bo.sealer.newId();
	assert.equal((await api(dev.base, "POST", "/api/v1/members/bo/files/folders", { email: bo.email, body: { id: second, name: await bo.sealer.folderName(second, "Timeline") } })).status, 200);
	await until(() => ofArea("bo").length > before, "the retried delivery", 30_000);
	assert.ok(siem.requests.filter((r) => r.refused).length >= 2, "the collector refused twice first");
	const seqs = ofArea("bo").map((e) => e.gorani.seq);
	assert.deepEqual(seqs, [...new Set(seqs)].sort((a, b) => a - b), "each line exactly once, in order — retried, not duplicated or skipped");

	// ── 4. The nightly pass drains every area, the registry's included ──
	await openCase(dev, ana, "ir-siem", "SIEM case", [[bo, "write"]]);
	assert.equal((await fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`)).status, 200);
	await until(() => ofArea("registry").some((e) => e.action === "case.create"), "the registry's case.create");
	await until(() => ofArea("case:ir-siem").length > 0, "the case's own lines");

	console.log("ok  api:siem — every chained line delivered by the audit DO's alarm, in order with its hash, sealed details never sent, a refusing collector retried without loss, the nightly pass drains the registry too");
} finally {
	await dev.close();
	await siem.close();
}
