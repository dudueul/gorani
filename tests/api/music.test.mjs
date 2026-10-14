// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:music — the metadata feed's server contract (docs/MUSIC.md): an audio
 * upload may carry `mmeta`, a summary of tags parsed client-side and sealed
 * into the version's place (GV04 `file.music`, commit 25);
 * the server stores it per version, refuses unsealed blobs, and hands the
 * whole library back as ONE feed of opaque sealed blobs. The server never
 * learns a title — it stores ciphertext with a size.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { storeSealer } from "../lib/placed.mjs";
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
	const s = await storeSealer(filesStore.bundle, "jinu");
	/** A new file's fields, every value sealed into its place (version 1). */
	const fileFields = async (id, name, type) => ({ file_id: id, ck: await s.fileKey(id, 1, new Uint8Array(32)), name: await s.fileName(id, name), type: await s.fileType(id, 1, type), size: String(payload.length) });

	// A GV02-SHAPED body passes the sealed-shape check: magic ‖ nonce (12) ‖
	// payload ‖ tag (16), with `size` = the payload length (the worker checks
	// sealed − 32 since commit 23). The bytes are opaque to this test (the
	// unit suite owns the crypto proofs).
	const payload = enc.encode("fake audio bytes");
	const audio = new Uint8Array([...enc.encode("GV02"), ...new Uint8Array(12), ...payload, ...new Uint8Array(16)]);

	// ── 1. An upload WITH sealed metadata lands in the feed ────────────
	const meta = { title: "Gorani Anthem", artist: "The Family", album: "Sealed Sounds", track: 7 };
	const anthem = s.newId();
	const up = await upload({ ...(await fileFields(anthem, "anthem.flac", "audio/flac")), mmeta: await s.fileMusic(anthem, 1, meta) }, audio);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const tracks1 = (await feed()).tracks;
	assert.equal(tracks1.length, 1);
	assert.equal(tracks1[0].id, up.json.id);
	assert.equal(tracks1[0].version, 1);
	assert.ok(tracks1[0].blobSealed.startsWith("GV04:"), "the blob rides sealed");

	// ── 2. An upload WITHOUT metadata stays out of the feed ────────────
	const up2 = await upload(await fileFields(s.newId(), "notes.txt", "text/plain"), audio);
	assert.equal(up2.status, 200);
	assert.equal((await feed()).tracks.length, 1, "text uploads carry no metadata");

	// ── 3. An UNSEALED blob is refused like every other sealed text ────
	const bad = await upload({ ...(await fileFields(s.newId(), "song.mp3", "audio/mpeg")), mmeta: JSON.stringify(meta) }, audio);
	assert.equal(bad.status, 400, "unsealed metadata refused before storage");
	assert.equal((await feed()).tracks.length, 1);
	// …and refused BEFORE any row was written (commit 25: the blob used to be
	// checked after the file and version rows were inserted — the 400 then
	// made the Worker delete the object, and the rows pointed at nothing).
	const listed = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.equal(listed.json.files.length, 2, "only anthem and notes: the refused upload left no row behind");

	// ── 4. A new version carries the new blob (the pointer moves) ──────
	const meta2 = { ...meta, title: "Gorani Anthem (remaster)" };
	const v2 = await upload({ ck: await s.fileKey(anthem, 2, new Uint8Array(32)), name: await s.fileName(anthem, "anthem.flac"), type: await s.fileType(anthem, 2, "audio/flac"), size: String(payload.length), base_version: "1", mmeta: await s.fileMusic(anthem, 2, meta2) }, audio, "jinu@family.test", `/files/${anthem}/versions`);
	assert.equal(v2.status, 200, JSON.stringify(v2.json));
	const tracks4 = (await feed()).tracks;
	assert.equal(tracks4.length, 1, "one living version, one blob");
	assert.equal(tracks4[0].version, 2);
	// The blob opens in version 2's place — and not in version 1's.
	const { openPlacedText } = await import("../../web/src/vault/vault-crypto.ts");
	const { places } = await import("../../web/src/vault/places.ts");
	assert.equal(JSON.parse(await openPlacedText(s.priv, places.fileMusic("jinu", anthem, 2), tracks4[0].blobSealed)).title, "Gorani Anthem (remaster)");
	await assert.rejects(openPlacedText(s.priv, places.fileMusic("jinu", anthem, 1), tracks4[0].blobSealed));

	console.log("ok  api:music — sealed blob per version, feed of opaque ciphertext, honest refusals");
} finally {
	await dev.close();
}