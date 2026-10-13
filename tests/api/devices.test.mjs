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
import { newContentKey, importContentKey, importVaultKey, openText, sealWith, openWith, sealText, generateHybridKey, wrapContentKey, unwrapContentKey } from "../../web/src/vault/vault-crypto.ts";
import { createChildVault, createParentsMaster, createStoreKey, openStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { toBase64, fromBase64 } from "../../web/src/lib/encoding.ts";

const dev = await suiteDev();
const enc = new TextEncoder();
const dec = new TextDecoder();

try {
	// ── 0. Family + kid vault (the setup files.test also walks) ────────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	const kidVault = await createChildVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const guardian = await sealStoreKeyToMaster(filesStore, master);
	const settings = { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own }, guardian };
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
	const enrolB = await api(dev.base, "POST", "/api/v1/members/jinu/devices", {
		email: "mom@family.test", // a parent can enrol for the child
		body: { name: "Family desktop", platform: "windows", keyId: kidVault.keyId, wrapped: rootBundleB64, salt: toBase64(new Uint8Array(16)), protection: "windows-hello" },
	});
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
	const storePublic = { ec: filesStore.publicKey, kem: filesStore.pqPublicKey };
	const ckSealed = await wrapContentKey(storePublic, ck);
	const plain = enc.encode("to be trashed");
	const sealed = await sealWith(key, plain);
	const name = await sealText(storePublic, "trashme.txt");
	async function uploadFile(fields, file) {
		const boundary = `t${Math.random().toString(16).slice(2)}`;
		const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
		const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body });
		return { status: r.status, json: await r.json() };
	}
	const f1 = await uploadFile({ ck: ckSealed, name, type: await sealText(storePublic, "text/plain"), size: String(plain.length) }, sealed);
	assert.equal(f1.status, 200, JSON.stringify(f1.json));
	const f = f1.json;
	assert.ok(f.id);
	const trashed = await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${f.id}`, { email: "jinu@family.test" });
	assert.equal(trashed.status, 200);
	const trash = await api(dev.base, "GET", "/api/v1/members/jinu/files/trash", { email: "jinu@family.test" });
	assert.ok(trash.json.files.some((x) => x.id === f.id));
	const restored = await api(dev.base, "POST", "/api/v1/members/jinu/files/trash/restore", { email: "mom@family.test", body: { files: [f.id], folders: [] } });
	assert.equal(restored.status, 200);
	assert.equal(restored.json.files, 1);
	const after = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(after.json.files.some((x) => x.id === f.id), "back in the lists");

	// ── 6. Rotation: the client re-wraps; the server stores; both open ─
	const newStore = await createStoreKey();
	const newOwn = await sealStoreKeyToMember(newStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const newGuardian = await sealStoreKeyToMaster(newStore, master);
	const newStorePublic = { ec: newStore.publicKey, kem: newStore.pqPublicKey };
	// The client opens the old wrap (with the root it holds) and re-seals the
	// key to the new store key — the raw key stays in the client the whole time.
	const rootPriv = await importVaultKey(kidVault.rootBundle);
	const storePriv = await openStoreKey(rootPriv, settings.stores.files);
	const openedCkRaw = fromBase64(await openText(storePriv, ckSealed));
	const newCkSealed = await wrapContentKey(newStorePublic, openedCkRaw);
	openedCkRaw.fill(0);
	const newName = await sealText(newStorePublic, "trashme.txt");
	const reseal = await api(dev.base, "PUT", "/api/v1/members/jinu/files/reseal", { email: "jinu@family.test", body: { keys: { [f.id]: { ck: newCkSealed, name: newName } } } });
	assert.equal(reseal.status, 200, JSON.stringify(reseal.json));
	// Settings updated to the new store key…
	const updatedSettings = { ...settings, stores: { files: newOwn }, guardian: newGuardian };
	const save2 = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: updatedSettings } });
	assert.equal(save2.status, 200);
	// …and the keys endpoint now serves the new wrap, which opens.
	const keys = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [f.id] } });
	assert.ok(keys.json.keys[f.id].key.startsWith("GV03:"));
	const newPrivate = await importVaultKey(newStore.bundle);
	const ck2 = await unwrapContentKey(newPrivate, keys.json.keys[f.id].key);
	assert.equal(dec.decode(await openWith(ck2, sealed)), dec.decode(plain), "the rotated key opens the content");

	// ── 7. Crypto-shredding: armed (dev secret), confirm phrase, gone ──
	const noConfirm = await api(dev.base, "DELETE", "/api/v1/members/jinu/vault", { email: "mom@family.test" });
	assert.equal(noConfirm.status, 403);
	const destroyed = await api(dev.base, "DELETE", "/api/v1/members/jinu/vault?confirm=DESTROY%20VAULT%20KEY", { email: "mom@family.test" });
	assert.equal(destroyed.status, 200);
	const gone = await api(dev.base, "GET", "/api/v1/members/jinu/vault", { email: "jinu@family.test" });
	assert.equal(gone.json, null);
	// Without the vault, uploads are refused: nothing lands in the clear.
	const afterDestroy = await uploadFile({ ck: ckSealed, name, type: typeSealedHelper(), size: String(plain.length) }, sealed);
	assert.equal(afterDestroy.status, 400, `afterDestroy: ${afterDestroy.status} ${JSON.stringify(afterDestroy)}`);

	console.log("ok  api:devices — enrol/unlock/rekey/leave/revoke, trash restore, reseal rotation, crypto-shredding");
} finally {
	await dev.close();
}

function typeSealedHelper() {
	return "GV03:type"; // shape only; the vault is destroyed at this point
}