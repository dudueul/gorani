// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:rotation — a store rotation that leaves NOTHING behind
 * (docs/FAMILY.md › Removing a member, docs/SECURITY-REVIEW.md › O5).
 *
 * A departing member keeps their copy of the old store private key. After
 * the rotation walk (web/src/vault/rotation.ts) that key must open nothing
 * in the store — not the living versions only, as before commit 24, but
 * every version's content key and type, file and folder names, music tags,
 * share names and the files secrets. The new key opens all of it, an old
 * version still decrypts to its original bytes, and running the walk again
 * changes nothing.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, importVaultKey, sealText, sealWith, openWith, wrapContentKey, unwrapContentKey } from "../../web/src/vault/vault-crypto.ts";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { newShareId, newShareSecret, shareKeys, sealShareMeta } from "../../web/src/vault/share-crypto.ts";
import { resealStore, opensAnything } from "../../web/src/vault/rotation.ts";

const dev = await suiteDev();
const enc = new TextEncoder();
const email = "jinu@family.test";

/** The walk's API, as the browser bridge would give it — failing loudly on refusals. */
const call = async (method, path, body) => {
	const r = await api(dev.base, method, path, { email, body });
	if (r.status >= 300) throw new Error(`${method} ${path}: ${r.status} ${r.text.slice(0, 200)}`);
	return r.json;
};

async function upload(path, fields, file) {
	const boundary = `r${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}/api/v1/members/jinu${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": email }, body: new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, json: await r.json() };
}

try {
	// ── 0. A member whose store holds every sealed kind ────────────────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: [email] } });
	const vault = await createChildVault();
	const storeA = await createStoreKey();
	const pubA = { ec: storeA.publicKey, kem: storeA.pqPublicKey };
	const settings = { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, stores: { files: await sealStoreKeyToMember(storeA, { ec: vault.publicKey, kem: vault.pqPublicKey }) }, guardian: await sealStoreKeyToMaster(storeA, master) };
	assert.equal((await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email, body: { settings } })).status, 200);

	const folder = await api(dev.base, "POST", "/api/v1/members/jinu/files/folders", { email, body: { name: await sealText(pubA, "Incident 2026-10") } });
	assert.equal(folder.status, 200);
	const v1plain = enc.encode("timeline, first draft");
	const v2plain = enc.encode("timeline, second draft — the one to keep");
	const ck1 = newContentKey();
	const ck2 = newContentKey();
	const up = await upload("/files", { ck: await wrapContentKey(pubA, ck1), name: await sealText(pubA, "timeline.txt"), type: await sealText(pubA, "text/plain"), size: String(v1plain.length), folder_id: folder.json.id, mmeta: await sealText(pubA, JSON.stringify({ title: "not really audio" })) }, await sealWith(await importContentKey(ck1), v1plain));
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const fileId = up.json.id;
	const v2 = await upload(`/files/${fileId}/versions`, { ck: await wrapContentKey(pubA, ck2), type: await sealText(pubA, "text/plain"), size: String(v2plain.length), base_version: "1" }, await sealWith(await importContentKey(ck2), v2plain));
	assert.equal(v2.status, 200, JSON.stringify(v2.json));
	await call("PUT", "/api/v1/members/jinu/files/secrets", { sealed: await sealText(pubA, JSON.stringify({ fp: "fingerprint key", idx: "index key" })) });
	const shareId = newShareId();
	const sk = await shareKeys(shareId, newShareSecret());
	await call("POST", "/api/v1/members/jinu/files/shares", { id: shareId, fileId, version: 2, nameSealed: await sealText(pubA, "timeline.txt"), metaSealed: await sealShareMeta(sk.meta, shareId, { name: "timeline.txt", type: "text/plain", size: v2plain.length, modified: null }), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 1, size: v2plain.length });

	const privA = await importVaultKey(storeA.bundle);
	const before = await opensAnything(call, "jinu", privA);
	// 2 versions × (key + type) + file name + folder name + music + share name + secrets
	assert.equal(before, 9, "the old store key opens every sealed value before the rotation");

	// ── 1. The rotation walk ────────────────────────────────────────────
	const storeB = await createStoreKey();
	const privB = await importVaultKey(storeB.bundle);
	const pubB = { ec: storeB.publicKey, kem: storeB.pqPublicKey };
	const report = await resealStore(call, "jinu", privA, privB, pubB);
	assert.deepEqual(report.resealed, { version: 2, file: 1, folder: 1, music: 1, share: 1, secrets: 1 }, "every kind, every row — older versions included");

	// ── 2. The proof: the old key opens NOTHING; the new key everything ─
	assert.equal(await opensAnything(call, "jinu", privA), 0, "the departed member's old store key opens nothing in the store");
	assert.equal(await opensAnything(call, "jinu", privB), 9, "the new key opens all of it");

	// The OLD version still decrypts to its original bytes under the new key
	// (via ?version=1 — which, before commit 24, silently served version 2).
	const versions = (await call("GET", "/api/v1/members/jinu/files/sealed?kind=version&after=0&limit=10")).items;
	const v1row = versions.find((v) => v.a === fileId && v.b === "1");
	const dl = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}?version=1`, { headers: { "x-gorani-dev-email": email } });
	const opened = await openWith(await unwrapContentKey(privB, v1row.v1), new Uint8Array(await dl.arrayBuffer()));
	assert.deepEqual(opened, v1plain, "version 1 — re-wrapped, not re-encrypted — opens to its original bytes");

	// ── 3. Idempotent, and the old form is gone ─────────────────────────
	const again = await resealStore(call, "jinu", privA, privB, pubB);
	assert.deepEqual(again.resealed, { version: 0, file: 0, folder: 0, music: 0, share: 0, secrets: 0 }, "a second walk re-seals nothing");
	assert.equal(again.alreadyNew.version, 2);
	const oldForm = await api(dev.base, "PUT", "/api/v1/members/jinu/files/reseal", { email, body: { keys: { [fileId]: { ck: "GV03:x" } } } });
	assert.equal(oldForm.status, 400, "the living-version-only reseal form is refused (clean break)");
	const unsealed = await api(dev.base, "PUT", "/api/v1/members/jinu/files/reseal", { email, body: { items: [{ kind: "file", row: 1, v1: "plain text name" }] } });
	assert.equal(unsealed.status, 400, "reseal values must be sealed");

	console.log("ok  api:rotation — every version, name, folder, tag, share name and secret re-sealed; the old key opens nothing; v1 still opens; idempotent");
} finally {
	await dev.close();
}
