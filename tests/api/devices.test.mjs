// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:devices — the enrolment lifecycle a native client lives (commit ⑬
 * drives this exact surface from Rust), plus trash/restore and client-driven
 * key rotation:
 *
 *   enrol (token shown once) → unlock with the token → wrong token refused →
 *   check → rekey → the member's device list → revoke → 403 → trash
 *   list/restore → rotation reseal (old key no longer answers, the new one
 *   opens) → the last-parent guard for vault destruction … and, with the
 *   destroy secret armed in dev, crypto-shredding end to end.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, importVaultKey, openText, sealWith, openWith, generateHybridKey } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer, placedShape } from "../lib/placed.mjs";
import { createCodeVault, createStoreKey, openStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
import { toBase64, fromBase64 } from "../../web/src/lib/encoding.ts";
import { resealStore } from "../../web/src/vault/rotation.ts";

const dev = await suiteDev();
const enc = new TextEncoder();
const dec = new TextDecoder();

try {
	// ── 0. Family + kid vault (the setup files.test also walks) ────────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	const kidVault = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const settings = { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own } };
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings } });
	assert.equal(saved.status, 200);

	// ── 1. Enrol two devices; the token is returned once ───────────────
	const rootBundleB64 = toBase64(kidVault.rootBundle);
	const enrolA = await api(dev.base, "POST", "/api/v1/members/jinu/devices", {
		email: "jinu@family.test",
		body: { name: "Jinu's laptop", platform: "linux", appVersion: "0.1.0", keyId: kidVault.keyId, wrapped: rootBundleB64, salt: toBase64(new Uint8Array(16)), protection: "linux-keyring" },
	});
	assert.equal(enrolA.status, 200, `enrol: ${enrolA.status} ${enrolA.text.slice(0,300)}`);
	const tokenA = enrolA.json.token;
	assert.ok(tokenA.length >= 60);
	const enrolDevice = (email) => api(dev.base, "POST", "/api/v1/members/jinu/devices", {
		email,
		body: { name: "Family desktop", platform: "windows", keyId: kidVault.keyId, wrapped: rootBundleB64, salt: toBase64(new Uint8Array(16)), protection: "windows-hello" },
	});
	assert.equal((await enrolDevice("mom@family.test")).status, 403, "a lead enrols no device for another member (no act-for since 27c)");
	const enrolB = await enrolDevice("jinu@family.test");
	assert.equal(enrolB.status, 200);
	const idB = enrolB.json.deviceId;

	// A stale root is refused (the copy must be of the current root).
	const other = await generateHybridKey();
	const stale = await api(dev.base, "POST", "/api/v1/members/jinu/devices", {
		email: "jinu@family.test",
		body: { name: "old", keyId: other.keyId, wrapped: toBase64(other.bundle), salt: toBase64(new Uint8Array(16)) },
	});
	assert.equal(stale.status, 409);

	// ── 2. Unlock with the device token; wrong tokens refused ─────────
	// Without the token: refused.
	const noToken = await api(dev.base, "POST", `/api/v1/members/jinu/devices/${enrolA.json.deviceId}/unlock`, {
		email: "jinu@family.test",
		body: { appVersion: "0.1.0" },
	});
	assert.equal(noToken.status, 401, "the device token header is required");
	const unlockA = await fetch(`${dev.base}/api/v1/members/jinu/devices/${enrolA.json.deviceId}/unlock`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "jinu@family.test", "x-gorani-device-token": tokenA },
		body: JSON.stringify({ appVersion: "0.1.0" }),
	});
	assert.equal(unlockA.status, 200);
	const unlocked = await unlockA.json();
	assert.equal(unlocked.keyId, kidVault.keyId, "the current root's id");
	assert.equal(unlocked.wrapped, rootBundleB64, "the device's own wrapped copy comes back");
	assert.ok(unlocked.settings.stores.files.privateKeySealed.startsWith("GV03:"), "settings ride along, sealed private halves included");

	const badToken = await fetch(`${dev.base}/api/v1/members/jinu/devices/${enrolA.json.deviceId}/unlock`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "jinu@family.test", "x-gorani-device-token": "wrong-token" },
		body: "{}",
	});
	assert.equal(badToken.status, 403);

	// ── 3. Check + rekey + list ────────────────────────────────────────
	const check = await fetch(`${dev.base}/api/v1/members/jinu/devices/${enrolA.json.deviceId}/check`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "jinu@family.test", "x-gorani-device-token": tokenA },
		body: "{}",
	});
	assert.equal(check.status, 200);
	assert.equal((await check.json()).policy.unusedDays, 30);

	const newRoot = await generateHybridKey();
	const rekey = await fetch(`${dev.base}/api/v1/members/jinu/devices/${enrolA.json.deviceId}/key`, {
		method: "PUT",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "jinu@family.test", "x-gorani-device-token": tokenA },
		body: JSON.stringify({ keyId: newRoot.keyId, wrapped: toBase64(newRoot.bundle), salt: toBase64(new Uint8Array(16)), protection: "linux-keyring" }),
	});
	assert.equal(rekey.status, 200);
	const list = await api(dev.base, "GET", "/api/v1/members/jinu/devices", { email: "jinu@family.test" });
	assert.equal(list.status, 200);
	assert.ok(list.json.find((d) => d.id === enrolA.json.deviceId).keyId === newRoot.keyId, "the rekeyed copy is on the list");

	// ── 4. Leave (uninstall) → revoked → refused ───────────────────────
	const leave = await fetch(`${dev.base}/api/v1/members/jinu/devices/${idB}/leave`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "jinu@family.test", "x-gorani-device-token": enrolB.json.token },
		body: "{}",
	});
	assert.equal(leave.status, 200);
	const unlockB = await fetch(`${dev.base}/api/v1/members/jinu/devices/${idB}/unlock`, {
		method: "POST",
		headers: { "content-type": "application/json", "x-gorani-dev-email": "jinu@family.test", "x-gorani-device-token": enrolB.json.token },
		body: "{}",
	});
	assert.equal(unlockB.status, 403);
	assert.equal((await unlockB.json()).error, "revoked");

	// ── 5. Trash list + restore ────────────────────────────────────────
	const ck = newContentKey();
	const key = await importContentKey(ck);
	const store = await storeSealer(filesStore.bundle, "jinu");
	const trashme = await store.newFile("trashme.txt", "text/plain", ck);
	const plain = enc.encode("to be trashed");
	const sealed = await sealWith(key, plain);
	async function uploadFile(fields, file) {
		const boundary = `t${Math.random().toString(16).slice(2)}`;
		const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
		const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body });
		return { status: r.status, json: await r.json() };
	}
	const f1 = await uploadFile({ ...trashme.fields, size: String(plain.length) }, sealed);
	assert.equal(f1.status, 200, JSON.stringify(f1.json));
	const f = f1.json;
	assert.ok(f.id);
	const trashed = await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${f.id}`, { email: "jinu@family.test" });
	assert.equal(trashed.status, 200);
	const trash = await api(dev.base, "GET", "/api/v1/members/jinu/files/trash", { email: "jinu@family.test" });
	assert.ok(trash.json.files.some((x) => x.id === f.id));
	assert.equal((await api(dev.base, "POST", "/api/v1/members/jinu/files/trash/restore", { email: "mom@family.test", body: { files: [f.id], folders: [] } })).status, 403, "nor restores their trash");
	const restored = await api(dev.base, "POST", "/api/v1/members/jinu/files/trash/restore", { email: "jinu@family.test", body: { files: [f.id], folders: [] } });
	assert.equal(restored.status, 200);
	assert.equal(restored.json.files, 1);
	const after = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(after.json.files.some((x) => x.id === f.id), "back in the lists");

	// ── 6. Rotation: the client re-wraps; the server stores; both open ─
	const newStore = await createStoreKey();
	const newOwn = await sealStoreKeyToMember(newStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	// The client walks every sealed value (rotation.ts — commit 24 made it
	// every version, folder, tag and secret, not just living versions; the
	// full proof is api:rotation) — the raw keys stay in the client.
	const rootPriv = await importVaultKey(kidVault.rootBundle);
	const storePriv = await openStoreKey(rootPriv, settings.stores.files);
	const call = async (method, path, body) => {
		const r = await api(dev.base, method, path, { email: "jinu@family.test", body });
		assert.ok(r.status < 300, `${method} ${path}: ${r.status} ${r.text.slice(0, 200)}`);
		return r.json;
	};
	const walked = await resealStore(call, "jinu", storePriv, await importVaultKey(newStore.bundle.slice()));
	assert.ok(walked.resealed.version >= 1 && walked.resealed.file >= 1, JSON.stringify(walked));
	// Settings updated to the new store key…
	const updatedSettings = { ...settings, stores: { files: newOwn } };
	const save2 = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: updatedSettings } });
	assert.equal(save2.status, 200);
	// …and the keys endpoint now serves the new wrap, which opens.
	const keys = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [f.id] } });
	assert.ok(keys.json.keys[f.id].key.startsWith("GV04:"));
	const newSealer = await storeSealer(newStore.bundle, "jinu");
	const ck2 = await newSealer.openFileKey(f.id, keys.json.keys[f.id].version, keys.json.keys[f.id].key);
	assert.equal(dec.decode(await openWith(ck2, sealed)), dec.decode(plain), "the rotated key opens the content");

	// ── 7. Crypto-shredding: armed (dev secret), confirm phrase, gone ──
	assert.equal((await api(dev.base, "DELETE", "/api/v1/members/jinu/vault?confirm=DESTROY%20VAULT%20KEY", { email: "mom@family.test" })).status, 403, "a lead cannot shred another member's vault");
	const noConfirm = await api(dev.base, "DELETE", "/api/v1/members/jinu/vault", { email: "jinu@family.test" });
	assert.equal(noConfirm.status, 403);
	const destroyed = await api(dev.base, "DELETE", "/api/v1/members/jinu/vault?confirm=DESTROY%20VAULT%20KEY", { email: "jinu@family.test" });
	assert.equal(destroyed.status, 200);
	const gone = await api(dev.base, "GET", "/api/v1/members/jinu/vault", { email: "jinu@family.test" });
	assert.equal(gone.json, null);
	// Without the vault, uploads are refused: nothing lands in the clear.
	// (Every field is placed-SHAPED, so the 400 can only be the vault gate's —
	// a GV03 placeholder here would now be refused for its format and the
	// test would pass for the wrong reason.)
	const afterDestroy = await uploadFile({ file_id: store.newId(), ck: placedShape("ck"), name: placedShape("name"), type: placedShape("type"), size: String(plain.length) }, sealed);
	assert.equal(afterDestroy.status, 400, `afterDestroy: ${afterDestroy.status} ${JSON.stringify(afterDestroy)}`);
	assert.match(afterDestroy.json.error, /vault/, "refused by the vault gate, not by a shape check");

	console.log("ok  api:devices — enrol/unlock/rekey/leave/revoke, trash restore, reseal rotation, crypto-shredding");
} finally {
	await dev.close();
}
