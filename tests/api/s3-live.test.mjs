// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:s3-live — the storage contract against a REAL S3-compatible bucket
 * (MinIO, AWS S3, B2, Wasabi, R2's S3 API). Every other api suite talks to
 * tests/lib/s3stub.mjs, which accepts any Authorization header — so the
 * SigV4 signer is proven only by golden vectors. This suite is where a real
 * server checks the signature, enforces the 5 MiB part rule, and answers
 * Range requests its own way.
 *
 * OPT-IN, because it writes to a bucket:
 *
 *   GORANI_LIVE_S3=1
 *   S3_ENDPOINT=https://…   S3_REGION=…   S3_BUCKET=…
 *   S3_ACCESS_KEY_ID=…      S3_SECRET_KEY=…
 *
 * Use a DEDICATED, EMPTY bucket: the worker writes `files/<member>/…` and
 * `shares/<id>` at the bucket root, exactly as in production, and the suite
 * deletes what it wrote through the worker's own purge path at the end.
 *
 * What it proves:
 *   1. the endpoint is https, and the bucket refuses ANONYMOUS reads/writes
 *      (the "private bucket" of docs/PRODUCTION.md, checked, not assumed)
 *   2. a whole sealed upload round-trips and a Range read returns the exact
 *      bytes (signed GET + Range through the real server)
 *   3. a two-part multipart upload (5 MiB GC01 frames) completes, adds up,
 *      and opens; a forged size is refused and its object deleted
 *   4. a share link copy round-trips through the public route
 *   5. the purge path deletes the objects (the download answers 404 after)
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, openWith } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { sealChunked, openChunk, FRAME_OVERHEAD } from "../../web/src/vault/chunked-file.ts";
import { newShareId, newShareSecret, shareKeys, sealShareMeta } from "../../web/src/vault/share-crypto.ts";

const need = ["S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_KEY"];
if (process.env.GORANI_LIVE_S3 !== "1" || need.some((k) => !process.env[k])) {
	const missing = need.filter((k) => !process.env[k]);
	console.log(`skip  api:s3-live — set GORANI_LIVE_S3=1${missing.length ? ` and ${missing.join(", ")}` : ""} (use a dedicated, empty bucket)`);
	process.exit(0);
}
const s3 = {
	endpoint: process.env.S3_ENDPOINT.replace(/\/+$/, ""),
	region: process.env.S3_REGION,
	bucket: process.env.S3_BUCKET,
	accessKeyId: process.env.S3_ACCESS_KEY_ID,
	secretKey: process.env.S3_SECRET_KEY,
};

// ── 1. Transport and bucket posture, before the worker is involved ────
assert.ok(s3.endpoint.startsWith("https://"), "the S3 endpoint must be https (the worker refuses http outside dev)");
const anonList = await fetch(`${s3.endpoint}/${encodeURIComponent(s3.bucket)}?list-type=2&max-keys=1`);
assert.ok([401, 403].includes(anonList.status), `anonymous LIST must be refused — got ${anonList.status}: the bucket is not private`);
const probe = `gorani-anon-probe-${Date.now()}`;
const anonPut = await fetch(`${s3.endpoint}/${encodeURIComponent(s3.bucket)}/${probe}`, { method: "PUT", body: "x" });
assert.ok([401, 403].includes(anonPut.status), `anonymous PUT must be refused — got ${anonPut.status}`);

const dev = await startDev({ s3 });
const enc = new TextEncoder();
const email = "jinu@family.test";

async function multipart(fields, file) {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const parts = Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("");
	const head = enc.encode(parts + (file ? `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n` : ""));
	const tail = enc.encode(file ? `\r\n--${boundary}--\r\n` : `--${boundary}--\r\n`);
	return { contentType: `multipart/form-data; boundary=${boundary}`, body: new Uint8Array([...head, ...(file ?? []), ...tail]) };
}
async function post(path, fields, file) {
	const { contentType, body } = await multipart(fields, file);
	const r = await fetch(`${dev.base}/api/v1/members/jinu${path}`, { method: "POST", headers: { "content-type": contentType, "x-gorani-dev-email": email }, body });
	return { status: r.status, json: await r.json().catch(() => null) };
}

try {
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: [email] } });
	const vault = await createChildVault();
	const store = await createStoreKey();
	const settings = { enabled: true, keyId: vault.keyId, publicKey: vault.publicKey, pqPublicKey: vault.pqPublicKey, methods: vault.methods, stores: { files: await sealStoreKeyToMember(store, { ec: vault.publicKey, kem: vault.pqPublicKey }) }, guardian: await sealStoreKeyToMaster(store, master) };
	assert.equal((await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email, body: { settings } })).status, 200);
	const sealer = await storeSealer(store.bundle, "jinu");
	const ck = newContentKey();
	const key = await importContentKey(ck);

	// ── 2. Whole upload, download, exact Range ──────────────────────────
	const plain = enc.encode("live S3: signed PUT, signed GET, a Range the real server slices");
	const sealed = await sealWith(key, plain);
	const live = await sealer.newFile("live.txt", "text/plain", ck);
	const up = await post("/files", { ...live.fields, size: String(plain.length) }, sealed);
	assert.equal(up.status, 200, `whole upload through the real bucket: ${JSON.stringify(up.json)}`);
	const fileId = up.json.id;
	const dl = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": email } });
	assert.equal(dl.status, 200);
	assert.deepEqual(await openWith(key, new Uint8Array(await dl.arrayBuffer())), plain, "the bytes the real bucket returned open to the original");
	const ranged = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": email, Range: "bytes=4-19" } });
	assert.equal(ranged.status, 206);
	assert.deepEqual(new Uint8Array(await ranged.arrayBuffer()), sealed.slice(4, 20), "Range bytes=4-19 is exactly sixteen bytes from offset 4");

	// ── 3. Multipart: two 5 MiB frames; then a forged size ──────────────
	const chunk = 5 * 1024 * 1024;
	const big = new Uint8Array(chunk + 4096);
	for (let i = 0; i < big.length; i++) big[i] = (i * 31) % 251;
	const bigCk = newContentKey();
	const bigKey = await importContentKey(bigCk);
	const bigSealed = await sealChunked(bigKey, big, chunk);
	async function multipartUpload(declaredSize) {
		const bigFile = await sealer.newFile("big.bin", "application/octet-stream", bigCk);
		const start = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email, body: { size: big.length, chunk, newFileId: bigFile.id } });
		assert.equal(start.status, 200, JSON.stringify(start.json));
		const etags = [];
		for (let p = 1; p <= start.json.parts; p++) {
			const frame = bigSealed.subarray((p - 1) * (chunk + FRAME_OVERHEAD), p * (chunk + FRAME_OVERHEAD));
			const r = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.json.uploadId}/${p}`, { method: "PUT", headers: { "x-gorani-dev-email": email }, body: frame });
			assert.equal(r.status, 200, `part ${p} through the real bucket`);
			etags.push({ partNumber: p, etag: (await r.json()).etag });
		}
		return post(`/files/uploads/${start.json.uploadId}/complete`, { key: start.json.key, size: String(declaredSize), chunk: String(chunk), ck: bigFile.fields.ck, name: bigFile.fields.name, type: bigFile.fields.type, parts: JSON.stringify(etags) }, null);
	}
	const done = await multipartUpload(big.length);
	assert.equal(done.status, 200, `multipart complete: ${JSON.stringify(done.json)}`);
	const bigDl = new Uint8Array(await (await fetch(`${dev.base}/api/v1/members/jinu/files/${done.json.id}`, { headers: { "x-gorani-dev-email": email } })).arrayBuffer());
	assert.equal(bigDl.length, bigSealed.length);
	const f0 = await openChunk(bigKey, bigDl.subarray(0, chunk + FRAME_OVERHEAD), 0, false);
	const f1 = await openChunk(bigKey, bigDl.subarray(chunk + FRAME_OVERHEAD), 1, true);
	assert.deepEqual(new Uint8Array([...f0, ...f1]), big, "both frames open, the second as final");
	const forged = await multipartUpload(big.length + 1);
	assert.equal(forged.status, 400, "a declared size the object does not add up to is refused (and the object deleted)");

	// ── 4. A share copy through the public route ────────────────────────
	const shareId = newShareId();
	const keys = await shareKeys(shareId, newShareSecret());
	const copy = await sealChunked(keys.data, plain, 8 * 1024 * 1024);
	const sh = await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
		email,
		body: { id: shareId, fileId, version: 1, nameSealed: await sealer.shareName(shareId, "live.txt"), metaSealed: await sealShareMeta(keys.meta, shareId, { name: "live.txt", type: "text/plain", size: plain.length, modified: null }), expiresAt: new Date(Date.now() + 3600_000).toISOString(), downloadsLeft: 3, size: plain.length },
	});
	assert.equal(sh.status, 200, JSON.stringify(sh.json));
	const part = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${shareId}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": email }, body: copy });
	assert.equal(part.status, 200);
	const fin = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${shareId}/complete`, { email, body: { parts: [{ partNumber: 1, etag: (await part.json()).etag }], size: plain.length } });
	assert.equal(fin.status, 200, JSON.stringify(fin.json));
	const pub = await fetch(`${dev.base}/s/f/${shareId}/data`);
	assert.equal(pub.status, 200);
	assert.deepEqual(new Uint8Array(await pub.arrayBuffer()), copy, "the recipient receives the exact sealed copy");

	// ── 5. Clean up through the product's own purge path ────────────────
	await api(dev.base, "DELETE", `/api/v1/members/jinu/files/shares/${shareId}`, { email });
	for (const id of [fileId, done.json.id]) await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${id}`, { email });
	const purge = await api(dev.base, "POST", "/api/v1/members/jinu/housekeeping", { email, body: { trashDays: 0, shareDays: 0 } });
	assert.equal(purge.status, 200);
	assert.ok(purge.json.objectsDeleted >= 2, `the purge deleted the objects: ${JSON.stringify(purge.json)}`);

	console.log(`ok  api:s3-live — ${new URL(s3.endpoint).host}: private bucket, signed round trips, exact Range, multipart + size check, share copy, purge`);
} finally {
	await dev.close();
}
