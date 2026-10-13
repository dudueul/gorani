// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:backup — the GB1 lifecycle against the real worker: the browser PUTs
 * the backup PUBLIC key (the key file's private bundle never leaves), the
 * job writes a .gbak of rows + sealed objects, the owner downloads it and
 * verifies/decrypts it with the key file — including the content round trip
 * (a version's object opens with the files store key to the exact bytes).
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { generateHybridKey, importVaultKey, sealText, sealWith, openWith, newContentKey, importContentKey, wrapContentKey, unwrapContentKey } from "../../web/src/vault/vault-crypto.ts";
import { readBackup } from "../../web/src/vault/backup.ts";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { toBase64, fromBase64 } from "../../web/src/lib/encoding.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

try {
	// ── 0. Family + kid vault ───────────────────────────────────────────
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

	// ── 1. The backup key: browser generates, downloads, PUTs public ───
	const backup = await generateHybridKey();
	const keyFile = { type: "gorani-backup-key", v: 1, keyId: backup.keyId, createdAt: new Date().toISOString(), key: toBase64(backup.bundle) };
	const put = await api(dev.base, "PUT", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test", body: { keyId: backup.keyId, publicKey: backup.publicKey, pqPublicKey: backup.pqPublicKey } });
	assert.equal(put.status, 200);
	const get = await api(dev.base, "GET", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test" });
	assert.equal(get.json.keyId, backup.keyId, "the public half is stored (the private bundle is not)");

	// ── 2. Two files to back up ─────────────────────────────────────────
	const storePublic = { ec: filesStore.publicKey, kem: filesStore.pqPublicKey };
	const files = [
		{ name: "diary.txt", bytes: enc.encode("a diary entry — sealed twice over in the backup") },
		{ name: "notes.md", bytes: enc.encode("## notes\n\nmore bytes for the second version row") },
	];
	const privStore = await importVaultKey(filesStore.bundle);
	for (const f of files) {
		const ck = newContentKey();
		const key = await importContentKey(ck);
		const sealed = await sealWith(key, f.bytes);
		const ckSealed = await wrapContentKey(storePublic, ck);
		const boundary = `t${Math.random().toString(16).slice(2)}`;
		const head = new TextEncoder().encode(
			[
				["ck", ckSealed],
				["name", await sealText(storePublic, f.name)],
				["type", await sealText(storePublic, "text/plain")],
				["size", String(f.bytes.length)],
			]
				.map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`)
				.join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`,
		);
		const body = new Uint8Array([...head, ...sealed, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body });
		assert.equal(r.status, 200, JSON.stringify(await r.json()));
	}

	// Files secrets exist once any device fingerprints an upload — simulate.
	const storePriv = await importVaultKey(filesStore.bundle);
	const secretsSealed = await sealText(storePublic, JSON.stringify({ fp: toBase64(new Uint8Array(32)), idx: toBase64(new Uint8Array(32)) }));
	const ps = await api(dev.base, "PUT", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test", body: { sealed: secretsSealed } });
	assert.equal(ps.status, 200);

	// ── 3. Run the backup ───────────────────────────────────────────────
	const run = await api(dev.base, "POST", "/api/v1/members/jinu/backup/run", { email: "jinu@family.test", body: {} });
	assert.equal(run.status, 200, JSON.stringify(run.json));
	assert.ok(run.json.stamp);
	assert.ok(run.json.entries >= 4, `folders+files+versions+secrets: ${run.json.entries}`);

	const list = await api(dev.base, "GET", "/api/v1/members/jinu/backups", { email: "jinu@family.test" });
	assert.equal(list.json.length, 1);
	assert.equal(list.json[0].stamp, run.json.stamp);

	// ── 4. Download + verify with the key file ──────────────────────────
	const dl = await fetch(`${dev.base}/api/v1/members/jinu/backups/${run.json.stamp}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
	assert.equal(dl.status, 200);
	const bytes = new Uint8Array(await dl.arrayBuffer());

	const parsed = await readBackup(bytes, keyFile);
	assert.equal(parsed.header.format, "gorani-backup");
	assert.equal(parsed.header.keyId, backup.keyId);
	const versionEntries = parsed.entries.filter((e) => e.json.kind === "version");
	assert.equal(versionEntries.length, 2, "both version rows with their sealed objects");
	const folderEntries = parsed.entries.filter((e) => e.json.kind === "folder");
	const fileEntries = parsed.entries.filter((e) => e.json.kind === "file");
	assert.ok(folderEntries.length >= 0 && fileEntries.length === 2);
	assert.ok(parsed.entries.some((e) => e.json.kind === "files-secrets"), "the sealed files secrets ride along");

	// The content round trip: a version's object opens with the files store
	// key to the exact plaintext (the backup carries the SEALED originals).
	for (const v of versionEntries) {
		const ck = await unwrapContentKey(storePriv, String(v.json.key));
		const plain = await openWith(ck, v.object);
		assert.ok(files.some((f) => Buffer.from(f.bytes).equals(Buffer.from(plain))), `the object's plaintext matches: ${v.json.file}`);
	}

	// Tamper: one flipped byte fails the container.
	const bad = bytes.slice();
	bad[bad.length - 3] ^= 0x10;
	await assert.rejects(() => readBackup(bad, keyFile));

	// ── 5. The private bundle never crossed the wire ────────────────────
	const keyGet2 = await api(dev.base, "GET", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test" });
	assert.ok(!JSON.stringify(keyGet2.json).includes(toBase64(backup.bundle).slice(0, 24)), "the private bundle is absent from the stored record");

	console.log("ok  api:backup — key file, run, download, decrypt, round trip, tamper, zero-trust");
} finally {
	await dev.close();
}