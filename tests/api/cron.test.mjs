// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:cron — the nightly maintenance pass, triggered the way production
 * triggers it: wrangler dev's `--test-scheduled` exposes GET /__scheduled,
 * which fires the worker's scheduled handler exactly as a Cron Trigger
 * would. The fan-out (worker/src/cron.rs) walks the family registry and
 * knocks on every member DO as the system actor `cron`:
 *
 *   9 backup manifests → the pass prunes to the newest 7 (rows + S3 objects)
 *   every member's audit gains a `cron.pass` line — even members who never
 *   unlocked a browser (the DO exists to be maintained)
 *   (commit 25, O10) storage refuses the deletes → the rows still go, the
 *   object keys wait in the deletion outbox (not orphaned), the pass is
 *   reported failed; storage recovers → the next pass finishes the job
 */

import assert from "node:assert/strict";
import { suiteDev, api, stubFault } from "./_dev.mjs";
import { generateHybridKey, newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

async function uploadFile(fields, file) {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
	const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body });
	return { status: r.status, json: await r.json() };
}

try {
	// ── 0. The family: mom, jinu (vault + files), and sora (bare) ───────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "sora", name: "Sora", role: "analyst", emails: ["sora@family.test"] } });
	const kidVault = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own } } } });
	assert.equal(saved.status, 200);

	// A file so jinu's backups have content, and the backup PUBLIC key (the
	// private half stays in the test tab, exactly like the browser).
	const store = await storeSealer(filesStore.bundle, "jinu");
	const ck = newContentKey();
	const key = await importContentKey(ck);
	// (size: the plaintext's real length — commit 23's size-honesty rule; this
	// used to declare "30" for a 25-byte diary.)
	const diary = enc.encode("the cron tends the museum");
	const up = await uploadFile({ ...(await store.newFile("diary.txt", "text/plain", ck)).fields, size: String(diary.length) }, await sealWith(key, diary));
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const backup = await generateHybridKey();
	const put = await api(dev.base, "PUT", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test", body: { keyId: backup.keyId, publicKey: backup.publicKey, pqPublicKey: backup.pqPublicKey } });
	assert.equal(put.status, 200);

	// ── 1. Nine manifests, then the nightly pass prunes to seven ────────
	for (let i = 0; i < 9; i++) {
		const run = await api(dev.base, "POST", "/api/v1/members/jinu/backup/run", { email: "jinu@family.test", body: {} });
		assert.equal(run.status, 200, `run ${i}: ${JSON.stringify(run.json)}`);
	}
	const before = await api(dev.base, "GET", "/api/v1/members/jinu/backups", { email: "jinu@family.test" });
	assert.equal(before.json.length, 9);

	// wrangler dev's scheduled-test route (the one its docs print): a plain GET
	// with the cron expression. It invokes the worker's scheduled handler
	// exactly as a production Cron Trigger would. (The older /__scheduled
	// route is gone in wrangler v4, and with assets in play it fell through
	// to the SPA anyway.)
	const fired = await fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`);
	assert.equal(fired.status, 200, await fired.text());

	const after = await api(dev.base, "GET", "/api/v1/members/jinu/backups", { email: "jinu@family.test" });
	assert.equal(after.json.length, 7, "the newest seven survive; the two oldest (rows + S3 objects) are gone");
	// The survivors are the newest nine's tail: every remaining stamp is one
	// of the nine, and the two oldest stamps are gone.
	const stamps = new Set(after.json.map((b) => b.stamp));
	assert.equal(stamps.size, 7);
	assert.ok(!before.json.slice(-2).some((b) => stamps.has(b.stamp)), "the oldest two were the pruned ones");
	// …and their OBJECTS are gone from storage, not just their rows.
	for (const b of before.json.slice(-2)) {
		assert.equal((await fetch(`${dev.s3}/backups/${b.stamp}.gbak`)).status, 404, `backups/${b.stamp}.gbak deleted`);
	}
	const fire = () => fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`);

	// ── 2. The audit trail: the system actor is visible and honest ──────
	const audit = await api(dev.base, "GET", "/api/v1/members/jinu/audit", { email: "mom@family.test" });
	const cronLines = audit.json.filter((a) => a.actor === "cron");
	assert.ok(cronLines.some((a) => a.action === "cron.pass"), `cron.pass in the audit: ${JSON.stringify(cronLines)}`);
	// (housekeeping.run lines appear only when retention actually removed
	// something — the audit records outcomes, not heartbeats. Its purge
	// behavior is proven with forced clocks in api:housekeeping.)

	// ── 3. The fan-out reached the member who never opened a browser ────
	const soraAudit = await api(dev.base, "GET", "/api/v1/members/sora/audit", { email: "mom@family.test" });
	assert.ok(soraAudit.json.some((a) => a.actor === "cron" && a.action === "cron.pass"), `sora's DO was maintained too: ${JSON.stringify(soraAudit.json).slice(0, 200)}`);

	// ── 4. O10: storage refuses the deletes ─────────────────────────────
	// Before commit 25 the rows went, the S3 deletes failed silently
	// (`let _ =`), and the objects were orphaned forever — nothing pointed at
	// them any more. Now the keys wait in the outbox and the pass fails.
	for (let i = 0; i < 2; i++) assert.equal((await api(dev.base, "POST", "/api/v1/members/jinu/backup/run", { email: "jinu@family.test", body: {} })).status, 200);
	const nine = (await api(dev.base, "GET", "/api/v1/members/jinu/backups", { email: "jinu@family.test" })).json;
	assert.equal(nine.length, 9);
	await stubFault(dev, { method: "DELETE", prefix: "backups/", status: 503, count: 100 });
	assert.equal((await fire()).status, 200);
	assert.equal((await api(dev.base, "GET", "/api/v1/members/jinu/backups", { email: "jinu@family.test" })).json.length, 7, "the manifest rows are pruned on schedule");
	const pending = (await api(dev.base, "GET", "/api/v1/members/jinu/storage/pending", { email: "jinu@family.test" })).json.pending;
	assert.equal(pending.length, 2, `two deletes wait in the outbox: ${JSON.stringify(pending)}`);
	assert.ok(pending.every((p) => p.reason === "backup pruned" && p.attempts === 1 && /503/.test(p.lastError)), JSON.stringify(pending));
	for (const p of pending) assert.equal((await fetch(`${dev.s3}/${p.key}`)).status, 200, `${p.key}: still in storage, and still known`);
	const failedLine = (await api(dev.base, "GET", "/api/v1/members/jinu/audit", { email: "mom@family.test" })).json.find((a) => a.actor === "cron" && a.action === "cron.pass");
	assert.match(JSON.stringify(failedLine), /deletesFailed:2/, "the audit says the pass could not finish");

	// Storage recovers: the next night finishes the job.
	await stubFault(dev, { method: "DELETE", prefix: "backups/", status: 503, count: 0 });
	assert.equal((await fire()).status, 200);
	assert.deepEqual((await api(dev.base, "GET", "/api/v1/members/jinu/storage/pending", { email: "jinu@family.test" })).json.pending, [], "the outbox is empty");
	for (const p of pending) assert.equal((await fetch(`${dev.s3}/${p.key}`)).status, 404, `${p.key}: deleted on the retry`);

	console.log("ok  api:cron — nightly pass: housekeeping + backup prune, fan-out over the registry, cron audit trail, the deletion outbox under a failing backend");
} finally {
	await dev.close();
}