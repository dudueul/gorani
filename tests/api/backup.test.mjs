// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:backup — the GB1 lifecycle against the real worker: the browser PUTs
 * the backup PUBLIC key (the key file's private bundle never leaves), the
 * job writes a .gbak of rows + sealed objects, the owner downloads it and
 * verifies/decrypts it with the key file — including the content round trip
 * (a version's object opens with the files store key to the exact bytes).
 */

import assert from "node:assert/strict";
import { suiteDev, api, stubDelete } from "./_dev.mjs";
import { generateHybridKey, sealWith, openWith, newContentKey, importContentKey } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { readBackup } from "../../web/src/vault/backup.ts";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
import { toBase64, fromBase64 } from "../../web/src/lib/encoding.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

try {
	// ── 0. Family + kid vault ───────────────────────────────────────────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	const kidVault = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own } } } });
	assert.equal(saved.status, 200);

	// ── 1. The backup key: browser generates, downloads, PUTs public ───
	const backup = await generateHybridKey();
	const keyFile = { type: "gorani-backup-key", v: 1, keyId: backup.keyId, createdAt: new Date().toISOString(), key: toBase64(backup.bundle) };
	const put = await api(dev.base, "PUT", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test", body: { keyId: backup.keyId, publicKey: backup.publicKey, pqPublicKey: backup.pqPublicKey } });
	assert.equal(put.status, 200);
	const get = await api(dev.base, "GET", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test" });
	assert.equal(get.json.keyId, backup.keyId, "the public half is stored (the private bundle is not)");

	// ── 2. Two files to back up ─────────────────────────────────────────
	const store = await storeSealer(filesStore.bundle, "jinu");
	const files = [
		{ name: "diary.txt", bytes: enc.encode("a diary entry — sealed twice over in the backup") },
		{ name: "notes.md", bytes: enc.encode("## notes\n\nmore bytes for the second version row") },
	];
	for (const f of files) {
		const ck = newContentKey();
		const key = await importContentKey(ck);
		const sealed = await sealWith(key, f.bytes);
		const { fields } = await store.newFile(f.name, "text/plain", ck);
		const boundary = `t${Math.random().toString(16).slice(2)}`;
		const head = new TextEncoder().encode(
			[...Object.entries(fields), ["size", String(f.bytes.length)]]
				.map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`)
				.join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`,
		);
		const body = new Uint8Array([...head, ...sealed, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body });
		assert.equal(r.status, 200, JSON.stringify(await r.json()));
	}

	// Files secrets exist once any device fingerprints an upload — simulate.
	const secretsSealed = await store.secrets(JSON.stringify({ fp: toBase64(new Uint8Array(32)), idx: toBase64(new Uint8Array(32)) }));
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
	// key to the exact plaintext (the backup carries the SEALED originals —
	// still sealed into their places, so a restore must keep ids and version
	// numbers exactly; it does, backup.rs › backup_restore).
	for (const v of versionEntries) {
		const ck = await store.openFileKey(String(v.json.file), Number(v.json.version), String(v.json.key));
		const plain = await openWith(ck, v.object);
		assert.ok(files.some((f) => Buffer.from(f.bytes).equals(Buffer.from(plain))), `the object's plaintext matches: ${v.json.file}`);
	}

	// Tamper: one flipped byte fails the container.
	const bad = bytes.slice();
	bad[bad.length - 3] ^= 0x10;
	await assert.rejects(() => readBackup(bad, keyFile));

	// GB2 (commit 25, O7): the HEADER is authenticated too. Relabel when the
	// backup was made (same length, valid JSON — last year's backup now
	// claims to be tonight's) and nothing opens; GB1 had no time in the
	// header at all, and would have opened any relabelled field.
	assert.equal(parsed.header.v, 2);
	const createdAt = String(parsed.header.createdAt);
	assert.match(createdAt, /^\d{4}-\d{2}-\d{2}T/, "the header says when, sealed");
	const at = Buffer.from(bytes).indexOf(Buffer.from(createdAt));
	assert.ok(at > 0, "the time sits in the header");
	const relabelled = bytes.slice();
	relabelled.set(new TextEncoder().encode(createdAt.replace(/^\d{4}/, (y) => String(Number(y) - 1))), at);
	await assert.rejects(() => readBackup(relabelled, keyFile), /altered/, "a relabelled header fails every segment");
	// A container cut down to its header is a truncation, not an empty backup.
	const headerOnly = bytes.subarray(0, 10 + new DataView(bytes.buffer, bytes.byteOffset + 6, 4).getUint32(0));
	await assert.rejects(() => readBackup(headerOnly, keyFile), /no segments/);

	// ── 5. The private bundle never crossed the wire ────────────────────
	const keyGet2 = await api(dev.base, "GET", "/api/v1/members/jinu/backup-key", { email: "jinu@family.test" });
	assert.ok(!JSON.stringify(keyGet2.json).includes(toBase64(backup.bundle).slice(0, 24)), "the private bundle is absent from the stored record");

	// ── 6. Restore: decrypt the backup, replay rows + sealed objects ───
	// Trash one file first (a mini disaster), then restore everything.
	const victim = (await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" })).json.files[0];
	await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${victim.id}`, { email: "jinu@family.test" });
	const afterTrash = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(!afterTrash.json.files.some((f) => f.id === victim.id), "the victim is gone from the lists");

	const folders = parsed.entries.filter((e) => e.json.kind === "folder").map((e) => e.json);
	const restoredFiles = parsed.entries.filter((e) => e.json.kind === "file").map((e) => e.json);
	const versions = versionEntries.map((e) => e.json);
	const secretsEntry = parsed.entries.find((e) => e.json.kind === "files-secrets");
	const restore = await api(dev.base, "POST", "/api/v1/members/jinu/backup/restore", {
		email: "jinu@family.test",
		body: { folders, files: restoredFiles, versions, secrets: secretsEntry?.json.sealed ?? null },
	});
	assert.equal(restore.status, 200, JSON.stringify(restore.json));

	// Fill the fresh object keys with the sealed bytes from the backup.
	for (const o of restore.json.objects) {
		const v = versions.find((x) => `${x.file}:${x.version}` === o.ref);
		const entry = versionEntries.find((e) => e.json.file === v.file && e.json.version === v.version);
		const put = await fetch(`${dev.base}/api/v1/members/jinu/backup/restore/object?k=${encodeURIComponent(o.objectKey)}`, {
			method: "PUT",
			headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" },
			body: entry.object,
		});
		assert.equal(put.status, 200, `fill ${o.objectKey}: ${await put.text()}`);
	}

	// The lists are whole again, and the victim's bytes still open.
	const after = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(after.json.files.some((f) => f.id === victim.id), "the restored file is back");
	const ckBack = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [victim.id] } });
	const ckKey = await store.openFileKey(victim.id, ckBack.json.keys[victim.id].version, ckBack.json.keys[victim.id].key);
	const dlBack = await fetch(`${dev.base}/api/v1/members/jinu/files/${victim.id}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
	const got = new Uint8Array(await dlBack.arrayBuffer());
	// The download serves the SEALED object (GV02 = magic ‖ nonce ‖ ct ‖ tag);
	// decrypt with the restored content key and compare plaintexts.
	const gotPlain = await openWith(ckKey, got);
	const original = files.find((f) => Buffer.from(f.bytes).equals(Buffer.from(gotPlain)));
	assert.ok(original, "restored bytes match one of the uploads");

	// ── 7. O9: streamed, and honest about what it could not include ─────
	// A 9 MiB file pushes the container past one 8 MiB part: the job streams
	// rows and objects into a multipart upload (memory bounded by one part,
	// whatever the store's size) instead of holding the whole backup. And an
	// object removed behind the Worker's back (a lost disk, a bucket rule) is
	// RECORDED — the run used to abort with nothing written.
	const bigCk = newContentKey();
	const bigPlain = new Uint8Array(9 * 1024 * 1024).map((_, i) => i % 251);
	const big = await store.newFile("capture.pcap", "application/vnd.tcpdump.pcap", bigCk);
	const bigSealed = await sealWith(await importContentKey(bigCk), bigPlain);
	const boundary = `big${Date.now()}`;
	const bigHead = new TextEncoder().encode([...Object.entries(big.fields), ["size", String(bigPlain.length)]].map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const bigUp = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body: new Uint8Array([...bigHead, ...bigSealed, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]) });
	assert.equal(bigUp.status, 200, await bigUp.text());
	const lost = (await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" })).json.files.find((f) => f.id !== big.id && f.id !== victim.id);
	const lostKey = (await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [lost.id] } })).json.keys[lost.id].object;
	await stubDelete(dev, lostKey);

	const run2 = await api(dev.base, "POST", "/api/v1/members/jinu/backup/run", { email: "jinu@family.test", body: {} });
	assert.equal(run2.status, 200, `a missing object no longer aborts the run: ${run2.text.slice(0, 200)}`);
	assert.equal(run2.json.missing.length, 1, "…it is listed");
	assert.equal(run2.json.missing[0].file, lost.id);
	assert.ok(run2.json.size > 8 * 1024 * 1024, "the container spans more than one 8 MiB part");
	const manifest = (await api(dev.base, "GET", "/api/v1/members/jinu/backups", { email: "jinu@family.test" })).json.find((b) => b.stamp === run2.json.stamp);
	assert.equal(manifest.missing, 1, "the manifest row counts it (the first column added under the migration ledger)");
	const bytes2 = new Uint8Array(await (await fetch(`${dev.base}/api/v1/members/jinu/backups/${run2.json.stamp}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } })).arrayBuffer());
	assert.equal(bytes2.length, run2.json.size);
	const parsed2 = await readBackup(bytes2, keyFile);
	const lostEntry = parsed2.entries.find((e) => e.json.kind === "version" && e.json.file === lost.id);
	assert.equal(lostEntry.json.missing, true, "the entry says the object was missing when the backup ran");
	assert.equal(lostEntry.object.length, 0);
	const bigEntry = parsed2.entries.find((e) => e.json.kind === "version" && e.json.file === big.id);
	assert.deepEqual(await openWith(await store.openFileKey(big.id, 1, String(bigEntry.json.key)), bigEntry.object), bigPlain, "the streamed 9 MiB object round-trips byte for byte");
	// A restore never mints an empty object for a missing one: it says so.
	const restore2 = await api(dev.base, "POST", "/api/v1/members/jinu/backup/restore", {
		email: "jinu@family.test",
		body: { folders: [], files: [], versions: parsed2.entries.filter((e) => e.json.kind === "version").map((e) => e.json), secrets: null },
	});
	assert.equal(restore2.status, 200, restore2.text);
	assert.deepEqual(restore2.json.skipped.map((x) => x.file), [lost.id], "the missing version is skipped, by name");

	console.log("ok  api:backup — key file, run, download, decrypt, round trip, tamper, zero-trust, RESTORE, streamed + missing recorded");
} finally {
	await dev.close();
}