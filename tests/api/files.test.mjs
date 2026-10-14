// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:files — the whole files surface against the real worker and the S3
 * stub, sealed exactly the way the browser seals (the vault-crypto and
 * chunked-file modules do the sealing here, as commit ⑨'s UI will):
 *
 *   family bootstrap → kid vault created (family.ts composition) →
 *   whole upload → list (no keys) → keys batch → download (with ck) →
 *   folders (create/rename/move) → change feed → versions (base_version
 *   conflict) → chunked upload in parts → Range read in the middle →
 *   rename/move/trash → duplicates (match) → secrets → refusals of
 *   unsealed input → family access (parent act-as; child denial).
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, openWith, generateHybridKey } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked, FRAME_OVERHEAD, sealedSize } from "../../web/src/vault/chunked-file.ts";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { sealText } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";

const dev = await suiteDev();
const dec = new TextDecoder();
const enc = new TextEncoder();

/** One multipart/form-data body, built by hand (the client's shape). */
function multipart(fields, file) {
	const boundary = `goranitest${Math.random().toString(16).slice(2)}`;
	const parts = [];
	for (const [k, v] of Object.entries(fields)) {
		parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`);
	}
	let tail = parts.join("");
	if (file) {
		tail += `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="sealed.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`;
	}
	const head = new TextEncoder().encode(tail);
	const end = new TextEncoder().encode(`\r\n--${boundary}--\r\n`);
	const body = file ? new Uint8Array([...head, ...file, ...end]) : new Uint8Array([...head, ...end]);
	return { contentType: `multipart/form-data; boundary=${boundary}`, body };
}

async function upload(base, email, member, path, fields, file) {
	const { contentType, body } = multipart(fields, file);
	const r = await fetch(`${base}/api/v1/members/${member}${path}`, {
		method: "POST",
		headers: { "content-type": contentType, "x-gorani-dev-email": email },
		body,
	});
	const text = await r.text();
	let json = null;
	try {
		json = JSON.parse(text);
	} catch {}
	return { status: r.status, json };
}

try {
	// ── 0. The family, its master, and the kid's vault ─────────────────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	const master = await createParentsMaster();
	const mset = await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	assert.equal(mset.status, 200, `master: ${JSON.stringify(mset.json)}`);
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "dad", name: "Dad", role: "parent", emails: ["dad@family.test"] } });

	// The kid's vault, composed the way commit ⑨'s UI will:
	const kidVault = await createChildVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const guardian = await sealStoreKeyToMaster(filesStore, master);
	const settings = {
		enabled: true,
		keyId: kidVault.keyId,
		publicKey: kidVault.publicKey,
		pqPublicKey: kidVault.pqPublicKey,
		methods: kidVault.methods,
		stores: { files: own },
		guardian,
	};
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings } });
	if (saved.status !== 200) console.error("SAVED FAIL", saved.status, JSON.stringify(saved.json));
	assert.equal(saved.status, 200, `saved: ${JSON.stringify(saved.json)}`);

	// A root change through the settings save is refused (the guard's essence).
	const other = await generateHybridKey();
	const clash = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { ...settings, keyId: other.keyId } } });
	assert.equal(clash.status, 409);

	// ── 1. A whole upload, sealed under a fresh content key ────────────
	// Since commit 25 (GV04): the CLIENT picks the file id, and the name,
	// type and content key are sealed into places that name it — with the
	// store's private key (tests/lib/placed.mjs).
	const store = await storeSealer(filesStore.bundle, "jinu");
	const ck = newContentKey();
	const key = await importContentKey(ck);
	const plain = enc.encode("a letter to the family");
	const sealed = await sealWith(key, plain);
	const { id: fileId, fields: first } = await store.newFile("letter.txt", "text/plain", ck);
	const { name, type: typeSealed, ck: ckSealed } = first;
	const up = await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...first, size: String(plain.length) }, sealed);
	assert.equal(up.status, 200, `up: ${JSON.stringify(up.json)}`);
	assert.equal(up.json.id, fileId, "the file has the id the client chose (and sealed into)");
	assert.equal(up.json.version, 1);

	// The same upload with a plaintext name is refused before anything stores.
	const plainName = await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...first, file_id: store.newId(), name: "letter.txt", size: String(plain.length) }, sealed);
	assert.equal(plainName.status, 400);
	// So is the older format (GV03, sealed to the PUBLIC key — movable and
	// mintable): a files store takes placed values only (the clean break).
	const storePublic = { ec: filesStore.publicKey, kem: filesStore.pqPublicKey };
	const gv03 = await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...first, file_id: store.newId(), name: await sealText(storePublic, "letter.txt"), size: String(plain.length) }, sealed);
	assert.equal(gv03.status, 400, "GV03 names are refused by a files store");
	// No id, no upload (the server no longer mints one after the sealing),
	// and an id already taken is a conflict — never a silent overwrite.
	const { file_id: _unused, ...noId } = first;
	void _unused;
	assert.equal((await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...noId, size: String(plain.length) }, sealed)).status, 400);
	assert.equal((await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...first, size: String(plain.length) }, sealed)).status, 409);

	// ── 2. Listing without keys; keys in a batch ───────────────────────
	const list = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=root", { email: "jinu@family.test" });
	assert.equal(list.status, 200);
	assert.equal(list.json.files.length, 1);
	assert.ok(list.json.files[0].name.startsWith("GV04:"), "the name is sealed in the listing");
	assert.equal(await store.openFileName(fileId, list.json.files[0].name), "letter.txt", "and opens in its place");
	assert.equal(list.json.files[0].key, undefined, "listings carry no keys");
	const keys = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [fileId] } });
	assert.ok(keys.json.keys[fileId].key.startsWith("GV04:"), "the wrapped key arrives sealed");

	// ── 3. Download: the bytes come back with the wrapped key header ──
	const dl = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
	assert.equal(dl.status, 200);
	assert.ok(dl.headers.get("x-gorani-ck").startsWith("GV04:"));
	assert.equal(dl.headers.get("x-gorani-version"), "1", "the download says which version it is — the key's place");
	const got = new Uint8Array(await dl.arrayBuffer());
	const opened = await store.openFileKey(fileId, 1, dl.headers.get("x-gorani-ck"));
	assert.equal(dec.decode(await openWith(opened, got)), dec.decode(plain));

	// ── 4. Folders: create, rename, move the file in ──────────────────
	const folderId = store.newId();
	const folder = await api(dev.base, "POST", "/api/v1/members/jinu/files/folders", { email: "jinu@family.test", body: { id: folderId, name: await store.folderName(folderId, "Photos") } });
	assert.equal(folder.status, 200);
	assert.equal(folder.json.id, folderId);
	const moved = await api(dev.base, "PATCH", `/api/v1/members/jinu/files/${fileId}`, { email: "jinu@family.test", body: { folderId } });
	assert.equal(moved.status, 200);
	assert.equal(moved.json.folder, folderId);
	const inFolder = await api(dev.base, "GET", `/api/v1/members/jinu/files/list?folder=${folderId}`, { email: "jinu@family.test" });
	assert.equal(inFolder.json.files.length, 1);

	// ── 5. The change feed: cursor, kinds, tombstones ──────────────────
	const changes = await api(dev.base, "GET", "/api/v1/members/jinu/files/changes?since=0", { email: "jinu@family.test" });
	assert.equal(changes.status, 200);
	const kinds = changes.json.changes.map((c) => c.kind);
	assert.ok(kinds.includes("file.put") && kinds.includes("folder.put") && kinds.includes("version.put"), JSON.stringify(kinds));
	assert.ok(changes.json.cursor > 0);
	const again = await api(dev.base, "GET", `/api/v1/members/jinu/files/changes?since=${changes.json.cursor}`, { email: "jinu@family.test" });
	assert.equal(again.json.changes.length, 0);

	// ── 6. A new version, and the base_version conflict ───────────────
	// A fresh content key per version, sealed into version 2's place (the
	// client knows the number: base_version + 1, which is why base_version
	// is now required).
	const v2ck = newContentKey();
	const v2key = await importContentKey(v2ck);
	const v2plain = enc.encode("a letter to the family, revised");
	const v2sealed = await sealWith(v2key, v2plain);
	const v2fields = { ck: await store.fileKey(fileId, 2, v2ck), type: await store.fileType(fileId, 2, "text/plain"), size: String(v2plain.length) };
	const v2 = await upload(dev.base, "jinu@family.test", "jinu", `/files/${fileId}/versions`, { ...v2fields, base_version: "1" }, v2sealed);
	assert.equal(v2.status, 200, JSON.stringify(v2.json));
	assert.equal(v2.json.version, 2);
	const stale = await upload(dev.base, "jinu@family.test", "jinu", `/files/${fileId}/versions`, { ...v2fields, base_version: "1" }, v2sealed);
	assert.equal(stale.status, 409);
	assert.equal(stale.json.version, 2, "the conflict says where the file is now");
	const unbased = await upload(dev.base, "jinu@family.test", "jinu", `/files/${fileId}/versions`, v2fields, v2sealed);
	assert.equal(unbased.status, 400, "no base_version, no guess: the key was sealed for a specific number");

	// ── 7. A chunked upload in parts, then a Range read in the middle ──
	// The chunk is the multipart part size, and the backends (S3, MinIO, R2
	// alike) require every part but the last to be ≥ 5 MiB — the init route
	// refuses anything smaller (an honest 400 instead of a 500 after every
	// part has been paid for). Two parts prove the multipart shape.
	const chunk = 5 * 1024 * 1024;
	const bigPlain = new Uint8Array(2 * chunk);
	for (let i = 0; i < bigPlain.length; i++) bigPlain[i] = i % 251;
	const bigCk = newContentKey();
	const bigSealed = await sealChunked(await importContentKey(bigCk), bigPlain, chunk);
	const bigFile = await store.newFile("photo.dat", "application/octet-stream", bigCk);
	// No id at all is refused: a new file's id is the client's (newFileId).
	const noNewId = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: bigPlain.length, chunk } });
	assert.equal(noNewId.status, 400);
	const start = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: bigPlain.length, chunk, newFileId: bigFile.id } });
	assert.equal(start.status, 200, JSON.stringify(start.json));
	assert.equal(start.json.parts, 2);
	// The honest refusal: a chunk below the backends' minimum part size is
	// rejected at init — before a single part is uploaded.
	const tiny = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: 200, chunk: 64, newFileId: store.newId() } });
	assert.equal(tiny.status, 400);
	const partEtags = [];
	for (let p = 1; p <= 2; p++) {
		const frame = bigSealed.subarray((p - 1) * (chunk + FRAME_OVERHEAD), p * (chunk + FRAME_OVERHEAD));
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.json.uploadId}/${p}?key=${encodeURIComponent(start.json.key)}`, {
			method: "PUT",
			headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" },
			body: frame,
		});
		assert.equal(r.status, 200, `part ${p}`);
		partEtags.push({ partNumber: p, etag: (await r.json()).etag });
	}
	const done = await upload(dev.base, "jinu@family.test", "jinu", `/files/uploads/${start.json.uploadId}/complete`, {
		key: start.json.key,
		size: String(bigPlain.length),
		chunk: String(chunk),
		ck: bigFile.fields.ck,
		name: bigFile.fields.name,
		type: bigFile.fields.type,
		parts: JSON.stringify(partEtags),
	}, null);
	assert.equal(done.status, 200, JSON.stringify(done.json));
	const bigId = done.json.id;
	assert.equal(bigId, bigFile.id, "the multipart file has the id it was started (and sealed) with");

	// A Range read in the middle. The contract (the Rust clients live by it):
	// the caller computes the *ciphertext* span of the frames it needs and
	// the server passes the Range through verbatim. Here: both frames minus
	// the final byte (so the answer is honest 206, not 200).
	const frame = chunk + FRAME_OVERHEAD;
	const dl2 = await fetch(`${dev.base}/api/v1/members/jinu/files/${bigId}`, { headers: { "x-gorani-dev-email": "jinu@family.test", Range: `bytes=0-${2 * frame - 2}` } });
	assert.equal(dl2.status, 206);
	assert.ok(dl2.headers.get("x-gorani-chunk") === String(chunk), "chunked objects are marked");
	const slice = new Uint8Array(await dl2.arrayBuffer());
	assert.equal(slice.length, 2 * frame - 1, "both frames, one byte short");
	assert.equal(sealedSize(bigPlain.length, chunk), bigSealed.length, "the server checked the object adds up");

	// ── 8. Rename, trash, duplicates ───────────────────────────────────
	const renamed = await api(dev.base, "PATCH", `/api/v1/members/jinu/files/${fileId}`, { email: "jinu@family.test", body: { name: await store.fileName(fileId, "letter (1).txt") } });
	assert.equal(renamed.status, 200);
	const match = await api(dev.base, "GET", `/api/v1/members/jinu/files/match?size=${v2plain.length}`, { email: "jinu@family.test" });
	assert.ok(match.json.files.some((f) => f.id === fileId));
	const trashed = await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${fileId}`, { email: "jinu@family.test" });
	assert.equal(trashed.status, 200);
	const afterTrash = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(!afterTrash.json.files.some((f) => f.id === fileId), "trashed files leave the lists");

	// ── 9. Secrets, stored sealed ──────────────────────────────────────
	const secrets = await store.secrets(JSON.stringify({ fp: "x".repeat(43), idx: "y".repeat(43) }));
	const putS = await api(dev.base, "PUT", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test", body: { sealed: secrets } });
	assert.equal(putS.status, 200);
	const getS = await api(dev.base, "GET", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test" });
	assert.equal(getS.json.sealed, secrets);
	const unsealedSecrets = await api(dev.base, "PUT", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test", body: { sealed: "not sealed at all" } });
	assert.equal(unsealedSecrets.status, 400);

	// ── 10. Family access: a parent acts for the child; the child cannot
	//        act for anyone else. ──────────────────────────────────────
	const asMom = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "mom@family.test" });
	assert.equal(asMom.status, 200);
	assert.equal(asMom.json.files.length, 1, "the parent sees the child's listing");
	const kidOther = await api(dev.base, "GET", "/api/v1/members/mom/files/list?folder=all", { email: "jinu@family.test" });
	assert.equal(kidOther.status, 403, "the child cannot open the parent's area");

	// Unsealed content is refused at the boundary (the store never sees it).
	const bad = await upload(dev.base, "jinu@family.test", "jinu", "/files", { file_id: store.newId(), ck: ckSealed, name, type: typeSealed, size: String(plain.length) }, enc.encode("plaintext bytes!!"));
	assert.equal(bad.status, 400);

	console.log("ok  api:files — upload/list/keys/download/folders/changes/versions/chunked+range/trash/duplicates/secrets/refusals/family");
} finally {
	await dev.close();
}