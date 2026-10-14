// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:security — the regression suite for the security review (commit 23).
 * Every block below was a real hole in the previous commit; each one is
 * written the house way (docs/TESTS.md): name the property, walk the real
 * path, and assert the refusal next to the success it protects.
 *
 *   1. the registry is for members — an authenticated stranger reads nothing
 *   2. member ids are validated and must exist before any DO or S3 key is made
 *   3. a share id belongs to the member who minted it — no re-pointing,
 *      no overwriting another member's copy object
 *   4. the public share data route serves the exact Range it was asked
 *   5. a device's wiped/leave report needs that device's token
 *   6. ids that become S3 key segments are validated BEFORE bytes are stored
 *   7. the restore fill is write-once and only for keys the restore minted
 *   8. the unauthenticated health line names no bucket
 *   9. (commit 25, O6) a sealed value opens only in its place, and only a
 *      holder of the store key can seal one — the server can neither move
 *      a key or a name to another file nor mint a file of its own
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealText, sealWith, openWith } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { sealChunked, DEFAULT_CHUNK } from "../../web/src/vault/chunked-file.ts";
import { newShareId, newShareSecret, shareKeys, sealShareMeta } from "../../web/src/vault/share-crypto.ts";
import { toBase64 } from "../../web/src/lib/encoding.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

/** A child member with an enabled vault and a files store; returns the store's sealer
 * (tests/lib/placed.mjs) and its public half (what the SERVER holds). */
async function childWithVault(id, master) {
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id, name: id, role: "child", emails: [`${id}@family.test`] } });
	const vault = await createChildVault();
	const store = await createStoreKey();
	const own = await sealStoreKeyToMember(store, { ec: vault.publicKey, kem: vault.pqPublicKey });
	const guardian = await sealStoreKeyToMaster(store, master);
	const saved = await api(dev.base, "PUT", `/api/v1/members/${id}/vault`, {
		email: `${id}@family.test`,
		body: { settings: { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, stores: { files: own }, guardian } },
	});
	assert.equal(saved.status, 200, `vault for ${id}: ${saved.text.slice(0, 200)}`);
	return { vault, store: await storeSealer(store.bundle, id), storePublic: { ec: store.publicKey, kem: store.pqPublicKey } };
}

/** A whole-file upload as the web app sends it (multipart, GV02 bytes). */
async function uploadWhole(member, path, fields, file) {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]);
	return fetch(`${dev.base}/api/v1/members/${member}${path}`, {
		method: "POST",
		headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": `${member}@family.test` },
		body,
	});
}

/** Create a share for `member` with a chosen id; returns the start response. */
async function shareStart(member, id, store, size) {
	const keys = await shareKeys(id, newShareSecret());
	const metaSealed = await sealShareMeta(keys.meta, id, { name: "n.txt", type: "text/plain", size, modified: null });
	const res = await api(dev.base, "POST", `/api/v1/members/${member}/files/shares`, {
		email: `${member}@family.test`,
		// (fileId: the server stores which file a share copies; it cannot check
		// the copy against it — the copy is sealed under the link's key.)
		body: { id, fileId: "shared-file", version: 1, nameSealed: await store.shareName(id, "n.txt"), metaSealed, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 5, size },
	});
	return { res, keys, metaSealed };
}

try {
	// ── 0. Family: mom (parent), jinu + sora (children with vaults) ────
	const first = await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	assert.equal(first.status, 200);
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	const jinu = await childWithVault("jinu", master);
	const sora = await childWithVault("sora", master);

	// ── 1. The registry is for members, not for every Access identity ──
	const stranger = await api(dev.base, "GET", "/api/v1/family", { email: "stranger@elsewhere.test" });
	assert.equal(stranger.status, 403, "an authenticated non-member must not read the registry (emails, audit)");
	const member = await api(dev.base, "GET", "/api/v1/family", { email: "jinu@family.test" });
	assert.equal(member.status, 200, "a member still reads it");

	// ── 2. Member ids: shape first, then existence ─────────────────────
	const badShape = await api(dev.base, "GET", "/api/v1/members/Not_A.Member/vault", { email: "mom@family.test" });
	assert.equal(badShape.status, 400, "a malformed member id never becomes a DO name or key prefix");
	const ghost = await api(dev.base, "GET", "/api/v1/members/ghost/vault", { email: "mom@family.test" });
	assert.equal(ghost.status, 404, "a parent cannot conjure a DO for a member the registry does not have");

	// ── 3. Share ids: first minting wins, nobody re-points it ──────────
	const id = newShareId();
	const plain = enc.encode("0123456789abcdef — the share whose id is coveted");
	const a = await shareStart("jinu", id, jinu.store, plain.length);
	assert.equal(a.res.status, 200, a.res.text.slice(0, 200));
	const copy = await sealChunked(a.keys.data, plain, DEFAULT_CHUNK);
	const part = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${id}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test" }, body: copy });
	assert.equal(part.status, 200);
	const { etag } = await part.json();
	const done = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${id}/complete`, { email: "jinu@family.test", body: { parts: [{ partNumber: 1, etag }], size: plain.length } });
	assert.equal(done.status, 200);

	const hijack = await shareStart("sora", id, sora.store, 4);
	assert.equal(hijack.res.status, 409, "another member reusing a live share id is refused");
	const again = await shareStart("jinu", id, jinu.store, 4);
	assert.equal(again.res.status, 409, "even the owner cannot mint the same id twice (the copy object is write-once)");
	const meta = await fetch(`${dev.base}/s/f/${id}/meta`);
	assert.equal(meta.status, 200);
	assert.equal((await meta.json()).metaSealed, a.metaSealed, "the public link still resolves to the original owner's share");

	// ── 4. The public data route honours the exact Range ───────────────
	const ranged = await fetch(`${dev.base}/s/f/${id}/data`, { headers: { Range: "bytes=2-9" } });
	assert.equal(ranged.status, 206);
	const slice = new Uint8Array(await ranged.arrayBuffer());
	assert.deepEqual(slice, copy.slice(2, 10), "bytes=2-9 is eight bytes starting at offset 2 (an inclusive end, not a length)");

	// ── 5. Device reports need the device's own token ──────────────────
	const enrol = await api(dev.base, "POST", "/api/v1/members/jinu/devices", {
		email: "jinu@family.test",
		body: { name: "laptop", platform: "linux", keyId: jinu.vault.keyId, wrapped: toBase64(jinu.vault.rootBundle), salt: toBase64(new Uint8Array(16)) },
	});
	assert.equal(enrol.status, 200);
	const devPath = `/api/v1/members/jinu/devices/${enrol.json.deviceId}`;
	const post = (what, token, email = "stranger@elsewhere.test") =>
		fetch(`${dev.base}${devPath}/${what}`, { method: "POST", headers: { "content-type": "application/json", "x-gorani-dev-email": email, "x-gorani-device-token": token }, body: "{}" });
	for (const what of ["wiped", "leave"]) {
		const forged = await post(what, "not-the-token");
		assert.equal(forged.status, 403, `${what} with a wrong token is refused (it used to revoke the device)`);
	}
	const stillWorks = await post("unlock", enrol.json.token, "jinu@family.test");
	assert.equal(stillWorks.status, 200, "the device survived the forged reports");

	// ── 6. Key segments are validated before a byte is stored ──────────
	const ck = newContentKey();
	const sealed = await sealWith(await importContentKey(ck), enc.encode("version bytes"));
	const vFile = await jinu.store.newFile("v.txt", "text/plain", ck);
	const fields = { ...vFile.fields, size: "13" };
	const badFile = await uploadWhole("jinu", "/files/not.a.file/versions", { ...fields, base_version: "1" }, sealed);
	assert.equal(badFile.status, 400, "a file id that is not an id never reaches S3");
	const badNewId = await uploadWhole("jinu", "/files", { ...fields, file_id: "../escape" }, sealed);
	assert.equal(badNewId.status, 400, "a client-chosen file id is held to the same allow-list");

	// ── 7. Restore fill: write-once, restore-minted keys only ──────────
	const up = await uploadWhole("jinu", "/files", fields, sealed);
	assert.equal(up.status, 200);
	const fileId = (await up.json()).id;
	const keys = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [fileId] } });
	const liveKey = keys.json.keys[fileId].object;
	assert.ok(liveKey.startsWith("files/jinu/"), "the live object key is member-scoped");
	const overwrite = await fetch(`${dev.base}/api/v1/members/jinu/backup/restore/object?k=${encodeURIComponent(liveKey)}`, {
		method: "PUT",
		headers: { "x-gorani-dev-email": "jinu@family.test" },
		body: enc.encode("GV02 not really"),
	});
	assert.equal(overwrite.status, 403, "a live object cannot be overwritten through the restore fill");

	// ── 8. The public health line names no bucket ──────────────────────
	const health = await api(dev.base, "GET", "/api/healthz", { email: null });
	assert.equal(health.status, 200);
	assert.ok(!health.text.includes("gorani-test"), "the unauthenticated health line does not disclose the bucket name");

	// ── 9. O6: moving and minting (commit 25) ───────────────────────────
	// The attacker is the server: it can write any row (here through
	// files/reseal, the server's own write path — the DO checks shapes, it
	// cannot check places). Two genuine files first.
	const sealedRows = async (kind) => (await api(dev.base, "GET", `/api/v1/members/jinu/files/sealed?kind=${kind}`, { email: "jinu@family.test" })).json.items;
	const invoiceCk = newContentKey();
	const invoice = await jinu.store.newFile("invoice.pdf", "application/pdf", invoiceCk);
	const invoiceBytes = await sealWith(await importContentKey(invoiceCk), enc.encode("%PDF-1.7 a real invoice"));
	assert.equal((await uploadWhole("jinu", "/files", { ...invoice.fields, size: String(23) }, invoiceBytes)).status, 200);
	const sampleCk = newContentKey();
	const sample = await jinu.store.newFile("malware-sample.bin", "application/octet-stream", sampleCk);
	const sampleBytes = await sealWith(await importContentKey(sampleCk), enc.encode("MZ… a live sample"));
	assert.equal((await uploadWhole("jinu", "/files", { ...sample.fields, size: String(enc.encode("MZ… a live sample").length) }, sampleBytes)).status, 200);

	// (a) MOVING. Present the sample under the invoice's name: copy the
	// sample's NAME into the invoice's file row, and the sample's KEY (with
	// its object) into the invoice's version row. Before GV04 every value
	// still opened — "invoice.pdf" now opened a malware sample.
	const fileRows = await sealedRows("file");
	const versionRows = await sealedRows("version");
	const rowOf = (rows, id) => rows.find((r) => r.a === id);
	const moved = await api(dev.base, "PUT", "/api/v1/members/jinu/files/reseal", {
		email: "jinu@family.test",
		body: { items: [
			{ kind: "file", row: rowOf(fileRows, invoice.id).row, v1: rowOf(fileRows, sample.id).v1 },
			{ kind: "version", row: rowOf(versionRows, invoice.id).row, v1: rowOf(versionRows, sample.id).v1 },
		] },
	});
	assert.equal(moved.status, 200, "the server CAN write the rows — the defence is in the client");
	const listed = (await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" })).json.files;
	const shownAsInvoice = listed.find((f) => f.id === invoice.id);
	await assert.rejects(jinu.store.openFileName(invoice.id, shownAsInvoice.name), /not sealed here/, "the sample's name does not open in the invoice's place");
	const invoiceKeyRow = (await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [invoice.id] } })).json.keys[invoice.id];
	await assert.rejects(jinu.store.openFileKey(invoice.id, invoiceKeyRow.version, invoiceKeyRow.key), /not sealed here/, "the sample's key does not open as the invoice's");
	// The sample itself still opens where it belongs — nothing genuine broke.
	const sampleKey = await jinu.store.openFileKey(sample.id, 1, rowOf(versionRows, sample.id).v1);
	assert.ok((await openWith(sampleKey, sampleBytes)).length > 0);

	// (b) MINTING. The server holds the store's PUBLIC key. Its best move:
	// seal a name to it the old way (GV03) — refused by the store, and by
	// the client — or GV04 bytes under a key schedule it can complete, i.e.
	// with a store key IT holds (sora's, standing in for any key that is not
	// jinu's). Both fail in jinu's place: the PSK is jinu's store's alone.
	const minted = await jinu.store.newId();
	const gv03Name = await sealText(jinu.storePublic, "totally-legit.exe");
	const mintGv03 = await uploadWhole("jinu", "/files", { file_id: minted, ck: invoice.fields.ck, name: gv03Name, type: invoice.fields.type, size: "23" }, invoiceBytes);
	assert.equal(mintGv03.status, 400, "a files store refuses GV03 (public-key) values outright");
	await assert.rejects(jinu.store.openFileName(minted, gv03Name), /not a placed/, "…and the client never opens one as a name");
	const foreign = await sora.store.fileName(minted, "totally-legit.exe"); // a GV04 value under the WRONG store's PSK
	const mint = await uploadWhole("jinu", "/files", { file_id: minted, ck: await sora.store.fileKey(minted, 1, newContentKey()), name: foreign, type: await sora.store.fileType(minted, 1, "application/octet-stream"), size: "23" }, invoiceBytes);
	assert.equal(mint.status, 200, "the shape is right, so an honest-looking server stores it…");
	await assert.rejects(jinu.store.openFileName(minted, foreign), /not sealed here/, "…but the minted name never opens in jinu's store");

	console.log("ok  api:security — registry scope, id validation, share-id ownership, exact Range, device-token reports, write-once restore, quiet health, O6 moving + minting");
} finally {
	await dev.close();
}
