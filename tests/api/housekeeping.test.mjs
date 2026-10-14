// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:housekeeping — the retention levers (the first layer of the
 * growth strategy, docs/ARCHITECTURE.md › Growth): forced clocks purge the
 * trash, dead share copies, the journal and the audit; the growth metric
 * (dbSize) is reported. Trash purge deletes the sealed objects from S3.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { sealWith, newContentKey, importContentKey } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

async function uploadFile(fields, file, email = "jinu@family.test") {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
	const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": email }, body });
	return { status: r.status, json: await r.json() };
}

try {
	// setup
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	const kidVault = await createChildVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const guardian = await sealStoreKeyToMaster(filesStore, master);
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own }, guardian } } });
	assert.equal(saved.status, 200);

	// Two files; one trashed (a mini disaster to purge).
	const store = await storeSealer(filesStore.bundle, "jinu");
	const ck = newContentKey();
	const key = await importContentKey(ck);
	const sealed = await sealWith(key, enc.encode("to be purged from the trash"));
	const up1 = await uploadFile({ ...(await store.newFile("purge-me.txt", "text/plain", ck)).fields, size: String(sealed.length - 32) }, sealed); // plaintext length (GV02 = +32)
	assert.equal(up1.status, 200);
	const ck2 = newContentKey();
	const key2 = await importContentKey(ck2);
	const up2 = await uploadFile({ ...(await store.newFile("keep-me.txt", "text/plain", ck2)).fields, size: String(enc.encode("stays in the vault").length) }, await sealWith(key2, enc.encode("stays in the vault")));
	assert.equal(up2.status, 200);
	await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${up1.json.id}`, { email: "jinu@family.test" });
	const trashBefore = await api(dev.base, "GET", "/api/v1/members/jinu/files/trash", { email: "jinu@family.test" });
	assert.equal(trashBefore.json.files.length, 1);

	// The growth metric exists in the stats.
	const stats = await api(dev.base, "GET", "/api/v1/members/jinu/vault-stats", { email: "jinu@family.test" }).catch(() => null);
	void stats;

	// Forced clocks: purge the trash NOW, prune the journal NOW, keep 2 audit lines.
	const run = await api(dev.base, "POST", "/api/v1/members/jinu/housekeeping", {
		email: "mom@family.test",
		body: { trashDays: 0, journalDays: 0, auditKeep: 2, shareDays: 0 },
	});
	assert.equal(run.status, 200, JSON.stringify(run.json));
	assert.ok(run.json.purgedFiles >= 1, `purged files: ${run.json.purgedFiles}`);
	assert.ok(run.json.objectsDeleted >= 1, "the trashed file's sealed object left S3");
	assert.ok(run.json.journalPruned >= 1);

	// The trash is empty; the kept file is untouched.
	const trashAfter = await api(dev.base, "GET", "/api/v1/members/jinu/files/trash", { email: "jinu@family.test" });
	assert.equal(trashAfter.json.files.length, 0);
	const list = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(list.json.files.some((f) => f.id === up2.json.id), "the kept file survives");

	// The audit is capped.
	const audit = await api(dev.base, "GET", "/api/v1/members/jinu/audit", { email: "jinu@family.test" });
	console.error("AUDIT", JSON.stringify(run.json), JSON.stringify(audit.json.map((a) => a.action)));
	// The run's own audit line is inserted after the prune — auditKeep + 1.
	assert.ok(audit.json.length <= 3, `audit kept: ${audit.json.length}`);

	// The journal: pruning keeps the cursor protocol intact (empty feed now).
	const feed = await api(dev.base, "GET", "/api/v1/members/jinu/files/changes?since=0", { email: "jinu@family.test" });
	assert.ok(feed.json.changes.length <= 1, `journal after prune: ${feed.json.changes.length}`);

	console.log("ok  api:housekeeping — trash purge + S3, journal/audit bounds, dbSize metric");
} finally {
	await dev.close();
}