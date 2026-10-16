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
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
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
	// ── 0. The team, and the analyst's vault (set up by the analyst) ──
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "dad", name: "Dad", role: "lead", emails: ["dad@family.test"] } });

	// The kid's vault, composed the way commit ⑨'s UI will:
	const kidVault = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const settings = {
		enabled: true,
		keyId: kidVault.keyId,
		publicKey: kidVault.publicKey,
		pqPublicKey: kidVault.pqPublicKey,
		methods: kidVault.methods,
		stores: { files: own },
	};
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings } });
	if (saved.status !== 200) console.error("SAVED FAIL", saved.status, JSON.stringify(saved.json));
	assert.equal(saved.status, 200, `saved: ${JSON.stringify(saved.json)}`);

	// A root change through the settings save is refused (the guard's essence).
	const other = await generateHybridKey();
	const clash = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { ...settings, keyId: other.keyId } } });
	assert.equal(clash.status, 409);
	// …and so is a save that would leave no way in (commit 39l, member.rs ›
	// methods_refusal): the panel never removes the last method, and the
	// server does not take the panel's word for it.
	const save = (patch) => api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { ...settings, ...patch } } });
	assert.equal((await save({ methods: [] })).status, 400, "an enabled vault keeps at least one unlock method");
	assert.equal((await save({ methods: [{ kind: "password" }] })).status, 400, "a method carries its wrap and salt");
	const pw = { ...settings.methods[0], kind: "password", kdf: "argon2id" };
	assert.equal((await save({ methods: [...settings.methods, pw, pw, pw, pw, pw] })).status, 400, "no more passwords than the unlock screen tries");
	assert.deepEqual((await api(dev.base, "GET", "/api/v1/members/jinu/vault", { email: "jinu@family.test" })).json.methods, settings.methods, "none of those was saved");
	const trail = (await api(dev.base, "GET", "/api/v1/members/jinu/audit", { email: "jinu@family.test" })).json.filter((l) => l.action === "vault.save");
	assert.ok(trail.some((l) => /^methods:/.test(l.details ?? "")), "each save names its ways in, in the trail");

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

	// The read is on record (O14, D10): one merged row per reader × version ×
	// client × 5 minutes — a second download in the window adds a request,
	// not a line; another client is another line. A lead's download is
	// refused (no act-for since 27c) — and so is not a read.
	await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
	await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "jinu@family.test", "x-gorani-client": "web" } });
	assert.equal((await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "mom@family.test", "x-gorani-client": "web" } })).status, 403);
	const reads = (await api(dev.base, "GET", `/api/v1/members/jinu/reads?file=${fileId}`, { email: "jinu@family.test" })).json.reads;
	const jinuRead = reads.find((r) => r.actor === "jinu@family.test" && r.client !== "web");
	assert.equal(jinuRead.requests, 2, `two downloads, one merged line: ${JSON.stringify(reads)}`);
	assert.equal(jinuRead.version, 1);
	assert.ok(reads.some((r) => r.actor === "jinu@family.test" && r.client === "web"), "another client, another line");
	assert.ok(!reads.some((r) => r.actor === "mom@family.test"), "a refused download is not a read");

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

	// ── 7b. Large files (D12, docs/LARGE-FILES.md) ─────────────────────
	// The plan's limits: 255 GiB a file, 64 MiB a chunk — and 255 GiB at the
	// 32 MiB chunk chunkFor picks is a plan the backends accept.
	const GiB = 1024 ** 3;
	const MiB = 1024 ** 2;
	const plan = (size, c) => api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size, chunk: c, newFileId: store.newId() } });
	assert.equal((await plan(255 * GiB + 1, 32 * MiB)).status, 413, "over 255 GiB");
	assert.equal((await plan(GiB, 128 * MiB)).status, 400, "a chunk over 64 MiB");
	assert.equal((await plan(255 * GiB, 8 * MiB)).status, 400, "255 GiB in 8 MiB parts is more than 10 000");
	const ceiling = await plan(255 * GiB, 32 * MiB);
	assert.equal(ceiling.status, 200, JSON.stringify(ceiling.json));
	assert.equal(ceiling.json.parts, 8160, "255 GiB / 32 MiB");
	// A part must say its length: it is streamed to storage, never held.
	const unsized = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${ceiling.json.uploadId}/1?key=${encodeURIComponent(ceiling.json.key)}`, {
		method: "PUT",
		headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" },
		body: new ReadableStream({ start: (c) => (c.enqueue(new Uint8Array(1024)), c.close()) }),
		duplex: "half",
	});
	assert.equal(unsized.status, 411, "no Content-Length, no part");
	assert.equal((await api(dev.base, "DELETE", `/api/v1/members/jinu/files/uploads/${ceiling.json.uploadId}`, { email: "jinu@family.test" })).status, 200, "the plan aborted");
	// And a 16 MiB chunk end to end — parts piped through the Worker, the
	// object adding up, the bytes opening to the plaintext.
	const c16 = 16 * MiB;
	const p20 = new Uint8Array(20 * MiB);
	for (let i = 0; i < p20.length; i += 65536) crypto.getRandomValues(p20.subarray(i, i + 65536));
	const ck20 = newContentKey();
	const s20 = await sealChunked(await importContentKey(ck20), p20, c16);
	const f20 = await store.newFile("image.E01", "application/octet-stream", ck20);
	const st20 = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: p20.length, chunk: c16, newFileId: f20.id } });
	assert.equal(st20.json.parts, 2);
	const tags20 = [];
	for (let p = 1; p <= 2; p++) {
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${st20.json.uploadId}/${p}?key=${encodeURIComponent(st20.json.key)}`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test" }, body: s20.subarray((p - 1) * (c16 + FRAME_OVERHEAD), p * (c16 + FRAME_OVERHEAD)) });
		assert.equal(r.status, 200, `16 MiB part ${p}: ${r.status}`);
		tags20.push({ partNumber: p, etag: (await r.json()).etag });
	}
	// (With the original's modified date, 39y — the completion carries it.)
	const done20 = await upload(dev.base, "jinu@family.test", "jinu", `/files/uploads/${st20.json.uploadId}/complete`, { key: st20.json.key, size: String(p20.length), chunk: String(c16), ck: f20.fields.ck, name: f20.fields.name, type: f20.fields.type, parts: JSON.stringify(tags20), modified: await store.fileModified(f20.id, 1, "2011-12-13T14:15:16.000Z") }, null);
	assert.equal(done20.status, 200, JSON.stringify(done20.json));
	const got20 = await fetch(`${dev.base}/api/v1/members/jinu/files/${f20.id}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
	assert.equal(got20.headers.get("x-gorani-chunk"), String(c16));
	assert.deepEqual(new Uint8Array(await got20.arrayBuffer()), s20, "the stored object is exactly the frames sent, streamed through");

	// ── 8. Rename, trash, duplicates ───────────────────────────────────
	const renamed = await api(dev.base, "PATCH", `/api/v1/members/jinu/files/${fileId}`, { email: "jinu@family.test", body: { name: await store.fileName(fileId, "letter (1).txt") } });
	assert.equal(renamed.status, 200);
	const match = await api(dev.base, "GET", `/api/v1/members/jinu/files/match?size=${v2plain.length}`, { email: "jinu@family.test" });
	assert.ok(match.json.files.some((f) => f.id === fileId));
	const trashed = await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${fileId}`, { email: "jinu@family.test" });
	assert.equal(trashed.status, 200);
	const afterTrash = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" });
	assert.ok(!afterTrash.json.files.some((f) => f.id === fileId), "trashed files leave the lists");

	// ── 8b. A folder goes to the Trash with its contents, and comes back
	// with them — exactly them: the letter, trashed on its own above, was
	// not the folder's to take, so it is not the folder's to bring back.
	const subId = store.newId();
	assert.equal((await api(dev.base, "POST", "/api/v1/members/jinu/files/folders", { email: "jinu@family.test", body: { id: subId, parentId: folderId, name: await store.folderName(subId, "2026") } })).status, 200);
	assert.equal((await api(dev.base, "PATCH", `/api/v1/members/jinu/files/${bigFile.id}`, { email: "jinu@family.test", body: { folderId: subId } })).status, 200);
	const gone = await api(dev.base, "DELETE", `/api/v1/members/jinu/files/folders/${folderId}`, { email: "jinu@family.test" });
	assert.deepEqual(gone.json, { folders: 2, files: 1 }, "Photos, 2026 and photo.dat");
	const back = await api(dev.base, "POST", "/api/v1/members/jinu/files/trash/restore", { email: "jinu@family.test", body: { files: [], folders: [folderId] } });
	assert.deepEqual(back.json, { folders: 2, files: 1 }, "restoring the folder brings back what its deletion took");
	assert.ok((await api(dev.base, "GET", `/api/v1/members/jinu/files/list?folder=${subId}`, { email: "jinu@family.test" })).json.files.some((f) => f.id === bigFile.id), "the file is back where it was, two levels down");
	const stillTrashed = await api(dev.base, "GET", "/api/v1/members/jinu/files/trash", { email: "jinu@family.test" });
	assert.ok(stillTrashed.json.files.some((f) => f.id === fileId), "the letter trashed on its own stays in the Trash");
	assert.ok(!stillTrashed.json.folders.length, "no folder is left behind in the Trash");

	// ── 8c. Duplicates (commit 39n) ────────────────────────────────────
	// The upload check now says which file is the twin and where (match
	// returns its folder and SEALED name), and Find duplicates lists every
	// set of live files sharing a size and a keyed tag — opaque strings
	// the server already holds; the names stay sealed.
	const twinBytes = enc.encode("the same bytes, twice");
	const twinTag = "ab".repeat(32);
	const twins = [];
	for (const [nm, tag] of [["a.txt", twinTag], ["b.txt", twinTag], ["c.txt", "cd".repeat(32)]]) {
		const ckT = newContentKey();
		const f = await store.newFile(nm, "text/plain", ckT);
		const r = await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...f.fields, size: String(twinBytes.length), tag }, await sealWith(await importContentKey(ckT), twinBytes));
		assert.equal(r.status, 200, JSON.stringify(r.json));
		twins.push(f.id);
	}
	const matched = (await api(dev.base, "GET", `/api/v1/members/jinu/files/match?size=${twinBytes.length}`, { email: "jinu@family.test" })).json.files;
	const aRow = matched.find((m) => m.id === twins[0]);
	assert.ok(aRow && aRow.tag === twinTag && aRow.folder === null && /^GV04:/.test(aRow.name), "match names the twin — sealed — and its folder");
	const dups = (await api(dev.base, "GET", "/api/v1/members/jinu/files/duplicates", { email: "jinu@family.test" })).json.files;
	assert.deepEqual(dups.map((d) => d.id).sort(), [twins[0], twins[1]].sort(), "the two with the same size and tag, and not the third (same size, another tag)");
	assert.ok(dups.every((d) => /^GV04:/.test(d.name)), "names stay sealed");
	assert.equal((await api(dev.base, "GET", "/api/v1/members/jinu/files/duplicates", { email: "mom@family.test" })).status, 403, "only the area's own");
	assert.equal((await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${twins[1]}`, { email: "jinu@family.test" })).status, 200);
	assert.equal((await api(dev.base, "GET", "/api/v1/members/jinu/files/duplicates", { email: "jinu@family.test" })).json.files.length, 0, "a copy in the Trash is no longer a duplicate");

	// ── 8d. Video sidecars (commit 39p, docs/VIDEO.md) ─────────────────
	// One sealed summary per version: where the moov is, duration, codecs.
	// The server checks what it can see — a live version, sealed text, a
	// sane size, not a sample — and can read none of it.
	const vBytes = enc.encode("pretend these are an MP4's bytes");
	const ckV = newContentKey();
	const vf = await store.newFile("home-video.mp4", "video/mp4", ckV);
	assert.equal((await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...vf.fields, size: String(vBytes.length) }, await sealWith(await importContentKey(ckV), vBytes))).status, 200);
	const sidecar = { v: 1, container: "mp4", layout: "regular", moov: [24, 4000], durationMs: 61_000, codecs: "avc1.64001f,mp4a.40.2", width: 1920, height: 1080, tracks: [{ type: "video", codec: "avc1.64001f" }, { type: "audio", codec: "mp4a.40.2" }] };
	const vPath = `/api/v1/members/jinu/files/${vf.id}/video`;
	const asJinu = { email: "jinu@family.test" };
	assert.equal((await api(dev.base, "GET", vPath, asJinu)).status, 404, "none yet: the client makes it");
	assert.equal((await api(dev.base, "PUT", vPath, { ...asJinu, body: { version: 1, meta: JSON.stringify(sidecar) } })).status, 400, "an unsealed sidecar is refused");
	assert.equal((await api(dev.base, "PUT", vPath, { ...asJinu, body: { version: 2, meta: await store.fileVideo(vf.id, 2, sidecar) } })).status, 404, "a version that does not exist is refused");
	assert.equal((await api(dev.base, "PUT", vPath, { ...asJinu, body: { version: 1, meta: "GV04:" + "x".repeat(17_000) } })).status, 413, "a sidecar is small");
	assert.equal((await api(dev.base, "PUT", vPath, { ...asJinu, body: { version: 1, meta: await store.fileVideo(vf.id, 1, sidecar) } })).status, 200);
	const vGot = await api(dev.base, "GET", vPath, asJinu);
	assert.equal(vGot.json.version, 1);
	assert.deepEqual(JSON.parse(await store.openFileVideo(vf.id, 1, vGot.json.meta)), sidecar, "stored as sealed, opened here");
	const vFeed = (await api(dev.base, "GET", "/api/v1/members/jinu/files/videos", asJinu)).json.videos;
	assert.ok(vFeed.some((v) => v.id === vf.id && v.version === 1 && v.hasPoster === false && /^GV04:/.test(v.meta)), "one feed of sealed sidecars, for the Movie tab");
	assert.equal((await api(dev.base, "GET", vPath, { email: "mom@family.test" })).status, 403, "only the area's own");
	assert.equal((await api(dev.base, "PUT", vPath, { email: "mom@family.test", body: { version: 1, meta: await store.fileVideo(vf.id, 1, sidecar) } })).status, 403);
	assert.equal((await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${vf.id}`, asJinu)).status, 200);
	assert.ok(!(await api(dev.base, "GET", "/api/v1/members/jinu/files/videos", asJinu)).json.videos.some((v) => v.id === vf.id), "a file in the Trash leaves the feed");
	assert.equal((await api(dev.base, "PUT", vPath, { ...asJinu, body: { version: 1, meta: await store.fileVideo(vf.id, 1, sidecar) } })).status, 404, "…and takes no sidecar");

	// ── 9. Secrets, stored sealed ──────────────────────────────────────
	const secrets = await store.secrets(JSON.stringify({ fp: "x".repeat(43), idx: "y".repeat(43) }));
	const putS = await api(dev.base, "PUT", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test", body: { sealed: secrets } });
	assert.equal(putS.status, 200);
	const getS = await api(dev.base, "GET", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test" });
	assert.equal(getS.json.sealed, secrets);
	const unsealedSecrets = await api(dev.base, "PUT", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test", body: { sealed: "not sealed at all" } });
	assert.equal(unsealedSecrets.status, 400);

	// ── 10. Own areas only: neither direction (since 27c — the family's
	//        "a parent acts for the child" is gone; shared work is a case).
	const asMom = await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "mom@family.test" });
	assert.equal(asMom.status, 403, "a lead does not list an analyst's area");
	const kidOther = await api(dev.base, "GET", "/api/v1/members/mom/files/list?folder=all", { email: "jinu@family.test" });
	assert.equal(kidOther.status, 403, "nor the analyst the lead's");

	// Unsealed content is refused at the boundary (the store never sees it).
	const bad = await upload(dev.base, "jinu@family.test", "jinu", "/files", { file_id: store.newId(), ck: ckSealed, name, type: typeSealed, size: String(plain.length) }, enc.encode("plaintext bytes!!"));
	assert.equal(bad.status, 400);

	// ── The original's modified date (39y) ─────────────────────────────
	// Sealed into each version's place by the uploader's client; the
	// listing carries the CURRENT version's, still sealed; one that is not
	// sealed text is refused, and a file uploaded without one lists null.
	{
		const listed = async (id) => (await api(dev.base, "GET", "/api/v1/members/jinu/files/list?folder=all", { email: "jinu@family.test" })).json.files.find((f) => f.id === id);
		const ckD = newContentKey();
		const plainD = enc.encode("a file with a past");
		const fD = await store.newFile("dated.txt", "text/plain", ckD);
		const when1 = "2003-04-05T06:07:08.000Z";
		const upD = await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...fD.fields, size: String(plainD.length), modified: await store.fileModified(fD.id, 1, when1) }, await sealWith(await importContentKey(ckD), plainD));
		assert.equal(upD.status, 200, JSON.stringify(upD.json));
		const rowD = await listed(fD.id);
		assert.match(rowD.modified ?? "", /^GV04:/, "the listing carries it sealed — the server never sees the date");
		assert.equal(await store.openFileModified(fD.id, 1, rowD.modified), when1, "…and it opens, in version 1's place");
		await assert.rejects(store.openFileModified(fD.id, 2, rowD.modified), "…and nowhere else");
		const ckD2 = newContentKey();
		const when2 = "2004-05-06T07:08:09.000Z";
		const v2D = await upload(dev.base, "jinu@family.test", "jinu", `/files/${fD.id}/versions`, { ck: await store.fileKey(fD.id, 2, ckD2), type: await store.fileType(fD.id, 2, "text/plain"), size: String(plainD.length), base_version: "1", modified: await store.fileModified(fD.id, 2, when2) }, await sealWith(await importContentKey(ckD2), plainD));
		assert.equal(v2D.status, 200, JSON.stringify(v2D.json));
		assert.equal(await store.openFileModified(fD.id, 2, (await listed(fD.id)).modified), when2, "a new version carries its own, and the listing follows the current version");
		assert.equal(await store.openFileModified(f20.id, 1, (await listed(f20.id)).modified), "2011-12-13T14:15:16.000Z", "a chunked upload's completion carries it too");
		const fNone = await store.newFile("undated.txt", "text/plain", ckD);
		assert.equal((await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...fNone.fields, size: String(plainD.length) }, await sealWith(await importContentKey(ckD), plainD))).status, 200);
		assert.equal((await listed(fNone.id)).modified, null, "a file uploaded without one lists none (the explorer shows its upload time)");
		const fBad = await store.newFile("bad-date.txt", "text/plain", ckD);
		const badDate = await upload(dev.base, "jinu@family.test", "jinu", "/files", { ...fBad.fields, size: String(plainD.length), modified: when1 }, await sealWith(await importContentKey(ckD), plainD));
		assert.equal(badDate.status, 400, "a date in the clear is refused — the store would hold what the uploader's client did not seal");
		assert.match(badDate.json.error, /modified date must arrive sealed/);
		const walk = (await api(dev.base, "GET", "/api/v1/members/jinu/files/sealed?kind=modified&after=0&limit=100", { email: "jinu@family.test" })).json;
		assert.ok(walk.items.some((i) => i.a === fD.id && i.b === "1") && walk.items.some((i) => i.a === fD.id && i.b === "2"), "the rotation walk reaches every version's date (kind modified)");
	}

	console.log("ok  api:files — upload/list/keys/download/folders/changes/versions/chunked+range/trash/duplicates/video sidecars/secrets/refusals/family/the original's modified date (sealed, per version, walked)");
} finally {
	await dev.close();
}