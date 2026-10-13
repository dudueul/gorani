// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:music — the metadata feed's server contract (docs/MUSIC.md): an audio
 * upload may carry `mmeta`, a GV03-sealed summary of tags parsed client-side;
 * the server stores it per version, refuses unsealed blobs, and hands the
 * whole library back as ONE feed of opaque sealed blobs. The server never
 * learns a title — it stores ciphertext with a size.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { sealText } from "../../web/src/vault/vault-crypto.ts";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

async function upload(fields, file, email = "jinu@family.test", path = "/files") {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
	const r = await fetch(`${dev.base}/api/v1/members/jinu${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": email }, body });
	return { status: r.status, json: await r.json() };
}

const feed = async () => (await api(dev.base, "GET", "/api/v1/members/jinu/files/music", { email: "jinu@family.test" })).json;

try {
	// ── seed ────────────────────────────────────────────────────────────
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { body: { keyId: master.keyId, publicKey: master.publicKey } });
	await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	const kidVault = await createChildVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const guardian = await sealStoreKeyToMaster(filesStore, master);
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own }, guardian } } });
	assert.equal(saved.status, 200);
	const storePublic = { ec: filesStore.publicKey, kem: filesStore.pqPublicKey };

	// A GV02-prefixed body passes the sealed-shape check; the bytes are
	// opaque to this test (the unit suite owns the crypto proofs).
	const audio = new Uint8Array([...enc.encode("GV02"), ...enc.encode("fake audio bytes")]);

	// ── 1. An upload WITH sealed metadata lands in the feed ────────────
	const meta = { title: "Gorani Anthem", artist: "The Family", album: "Sealed Sounds", track: 7 };
	const up = await upload({ ck: "GV03:WRAPPED", name: await sealText(storePublic, "anthem.flac"), type: await sealText(storePublic, "audio/flac"), size: String(audio.length), mmeta: await sealText(storePublic, JSON.stringify(meta)) }, audio);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const tracks1 = (await feed()).tracks;
	assert.equal(tracks1.length, 1);
	assert.equal(tracks1[0].id, up.json.id);
	assert.equal(tracks1[0].version, 1);
	assert.ok(tracks1[0].blobSealed.startsWith("GV03:"), "the blob rides sealed");

	// ── 2. An upload WITHOUT metadata stays out of the feed ────────────
	const up2 = await upload({ ck: "GV03:WRAPPED", name: await sealText(storePublic, "notes.txt"), type: await sealText(storePublic, "text/plain"), size: String(audio.length) }, audio);
	assert.equal(up2.status, 200);
	assert.equal((await feed()).tracks.length, 1, "text uploads carry no metadata");

	// ── 3. An UNSEALED blob is refused like every other sealed text ────
	const bad = await upload({ ck: "GV03:WRAPPED", name: await sealText(storePublic, "song.mp3"), type: await sealText(storePublic, "audio/mpeg"), size: String(audio.length), mmeta: JSON.stringify(meta) }, audio);
	assert.equal(bad.status, 400, "unsealed metadata refused before storage");
	assert.equal((await feed()).tracks.length, 1);

	// ── 4. A new version carries the new blob (the pointer moves) ──────
	const meta2 = { ...meta, title: "Gorani Anthem (remaster)" };
	const v2 = await upload({ ck: "GV03:WRAPPED", name: await sealText(storePublic, "anthem.flac"), type: await sealText(storePublic, "audio/flac"), size: String(audio.length), base_version: "1", mmeta: await sealText(storePublic, JSON.stringify(meta2)) }, audio, "jinu@family.test", `/files/${up.json.id}/versions`);
	assert.equal(v2.status, 200, JSON.stringify(v2.json));
	const tracks4 = (await feed()).tracks;
	assert.equal(tracks4.length, 1, "one living version, one blob");
	assert.equal(tracks4[0].version, 2);

	console.log("ok  api:music — sealed blob per version, feed of opaque ciphertext, honest refusals");
} finally {
	await dev.close();
}