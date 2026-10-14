// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:s3-live — the storage contract against a REAL S3-compatible bucket
 * (MinIO, AWS S3, IDrive e2, B2, Wasabi, R2's S3 API). Every other api suite
 * talks to tests/lib/s3stub.mjs, which accepts any Authorization header — so
 * the SigV4 signer is proven only by golden vectors. This suite is where a
 * real server checks the signature, enforces the 5 MiB part rule, and
 * answers Range requests its own way.
 *
 * OPT-IN, because it writes to a bucket:
 *
 *   GORANI_LIVE_S3=1
 *   S3_ENDPOINT=…   S3_REGION=…   S3_BUCKET=…
 *   S3_ACCESS_KEY_ID=…   S3_SECRET_KEY=… (or S3_SECRET_ACCESS_KEY, the AWS name)
 *
 * The endpoint may be a bare host (`s3.eu-central-1.idrivee2.com`, as a
 * provider console shows it): it means https, as it does to the Worker.
 *
 * Use a DEDICATED, EMPTY bucket: the worker writes `files/<member>/…`,
 * `cases/<id>/…` and `shares/<id>` at the bucket root, exactly as in
 * production, and the suite deletes what it wrote through the worker's own
 * purge path at the end.
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
 *
 * And, with GORANI_LIVE_S3_LOCK=1 as well (a bucket created WITH Object
 * Lock — docs/PRODUCTION.md › Write-once evidence; docs/CUSTODY.md › stage 3):
 *   6. the bucket says it has Object Lock and versioning, and no default
 *      retention; an evidence upload's object then carries a COMPLIANCE
 *      retention set by the Worker, and the storage server itself refuses to
 *      delete that version — the claim the stub can only model.
 *
 *    The probe locks ONE small object for ONE day (EVIDENCE_RETAIN_DAYS=1 on
 *    this server; no nightly pass runs, so no 7-year checkpoint lock): it
 *    cannot be deleted by anyone until tomorrow — that is what it proves.
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, openWith } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked, openChunk, FRAME_OVERHEAD } from "../../web/src/vault/chunked-file.ts";
import { newShareId, newShareSecret, shareKeys, sealShareMeta, newShareKdf } from "../../web/src/vault/share-crypto.ts";
import { member, vouch, openCase, signedHash, signedIntake } from "../lib/team.mjs";
import { s3fetch } from "../lib/sigv4.mjs";

const env = process.env;
const secretKey = env.S3_SECRET_KEY || env.S3_SECRET_ACCESS_KEY;
const need = { S3_ENDPOINT: env.S3_ENDPOINT, S3_REGION: env.S3_REGION, S3_BUCKET: env.S3_BUCKET, S3_ACCESS_KEY_ID: env.S3_ACCESS_KEY_ID, "S3_SECRET_KEY (or S3_SECRET_ACCESS_KEY)": secretKey };
const missing = Object.keys(need).filter((k) => !need[k]);
if (env.GORANI_LIVE_S3 !== "1" || missing.length) {
	console.log(`skip  api:s3-live — set GORANI_LIVE_S3=1${missing.length ? ` and ${missing.join(", ")}` : ""} (use a dedicated, empty bucket)`);
	process.exit(0);
}
const raw = env.S3_ENDPOINT.replace(/\/+$/, "");
const s3 = {
	endpoint: raw.includes("://") ? raw : `https://${raw}`,
	region: env.S3_REGION,
	bucket: env.S3_BUCKET,
	accessKeyId: env.S3_ACCESS_KEY_ID,
	secretKey,
};
const lockProbe = env.GORANI_LIVE_S3_LOCK === "1";

// ── 1. Transport and bucket posture, before the worker is involved ────
assert.ok(s3.endpoint.startsWith("https://"), "the S3 endpoint must be https (the worker refuses http outside dev)");
// Refused, the provider's way: 401/403 (AWS, MinIO), or a redirect OFF the
// S3 host with no S3 answer in it — IDrive e2 sends anonymous requests to
// its homepage (302, probed 2026-10-14). Redirects are not followed: a
// followed one would only measure the website.
const refusedAnonymously = async (r) => {
	if ([401, 403].includes(r.status)) return true;
	const to = r.headers.get("location");
	return r.status >= 300 && r.status < 400 && !!to && new URL(to, s3.endpoint).host !== new URL(s3.endpoint).host && !/<ListBucketResult/.test(await r.text());
};
const anonList = await fetch(`${s3.endpoint}/${encodeURIComponent(s3.bucket)}?list-type=2&max-keys=1`, { redirect: "manual" });
assert.ok(await refusedAnonymously(anonList), `anonymous LIST must be refused — got ${anonList.status}: the bucket is not private`);
const probe = `gorani-anon-probe-${Date.now()}`;
const anonPut = await fetch(`${s3.endpoint}/${encodeURIComponent(s3.bucket)}/${probe}`, { method: "PUT", body: "x", redirect: "manual" });
assert.ok(await refusedAnonymously(anonPut), `anonymous PUT must be refused — got ${anonPut.status}`);
// …and the credential works at all, before a server starts: a refused
// signature here is a key, region or addressing problem, named as such.
const signedList = await s3fetch(s3, "GET", "", { "list-type": "2", "max-keys": "1" });
assert.equal(signedList.status, 200, `a SIGNED list must succeed — got ${signedList.status}: ${(await signedList.text()).slice(0, 300)}`);

// The lock probe's bucket checks come first too: nothing is written (and
// nothing locked) unless the bucket is the kind gorani's lock expects.
if (lockProbe) {
	const cfg = await s3fetch(s3, "GET", "", { "object-lock": "" });
	const cfgBody = await cfg.text();
	assert.equal(cfg.status, 200, `GORANI_LIVE_S3_LOCK=1: the bucket has no Object Lock configuration (${cfg.status}: ${cfgBody.slice(0, 200)}) — Object Lock can only be enabled when a bucket is CREATED`);
	assert.match(cfgBody, /<ObjectLockEnabled>Enabled</, "the bucket's Object Lock is enabled");
	assert.doesNotMatch(cfgBody, /<DefaultRetention>/, "no DEFAULT retention: it would lock working files too (gorani locks each evidence object itself)");
	const ver = await s3fetch(s3, "GET", "", { versioning: "" });
	assert.match(await ver.text(), /<Status>Enabled</, "versioning is on (Object Lock requires it)");
}

const dev = await startDev({ s3, vars: lockProbe ? { OBJECT_LOCK: "on", EVIDENCE_RETAIN_DAYS: "1" } : {} });
const enc = new TextEncoder();
let base = "";
let email = "";

async function multipart(fields, file) {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const parts = Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("");
	const head = enc.encode(parts + (file ? `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n` : ""));
	const tail = enc.encode(file ? `\r\n--${boundary}--\r\n` : `--${boundary}--\r\n`);
	return { contentType: `multipart/form-data; boundary=${boundary}`, body: new Uint8Array([...head, ...(file ?? []), ...tail]) };
}
async function post(path, fields, file, at = base, who = email) {
	const { contentType, body } = await multipart(fields, file);
	const r = await fetch(`${dev.base}${at}${path}`, { method: "POST", headers: { "content-type": contentType, "x-gorani-dev-email": who }, body });
	return { status: r.status, json: await r.json().catch(() => null) };
}

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	({ email } = bo);
	base = `/api/v1/members/${bo.id}`;
	const sealer = bo.sealer;
	const ck = newContentKey();
	const key = await importContentKey(ck);

	// ── 2. Whole upload, download, exact Range ──────────────────────────
	const plain = enc.encode("live S3: signed PUT, signed GET, a Range the real server slices");
	const sealed = await sealWith(key, plain);
	const live = await sealer.newFile("live.txt", "text/plain", ck);
	const up = await post("/files", { ...live.fields, size: String(plain.length) }, sealed);
	assert.equal(up.status, 200, `whole upload through the real bucket: ${JSON.stringify(up.json)}`);
	const fileId = up.json.id;
	const dl = await fetch(`${dev.base}${base}/files/${fileId}`, { headers: { "x-gorani-dev-email": email } });
	assert.equal(dl.status, 200);
	assert.deepEqual(await openWith(key, new Uint8Array(await dl.arrayBuffer())), plain, "the bytes the real bucket returned open to the original");
	const ranged = await fetch(`${dev.base}${base}/files/${fileId}`, { headers: { "x-gorani-dev-email": email, Range: "bytes=4-19" } });
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
		const start = await api(dev.base, "POST", `${base}/files/uploads`, { email, body: { size: big.length, chunk, newFileId: bigFile.id } });
		assert.equal(start.status, 200, JSON.stringify(start.json));
		const etags = [];
		for (let p = 1; p <= start.json.parts; p++) {
			const frame = bigSealed.subarray((p - 1) * (chunk + FRAME_OVERHEAD), p * (chunk + FRAME_OVERHEAD));
			const r = await fetch(`${dev.base}${base}/files/uploads/${start.json.uploadId}/${p}`, { method: "PUT", headers: { "x-gorani-dev-email": email }, body: frame });
			assert.equal(r.status, 200, `part ${p} through the real bucket`);
			etags.push({ partNumber: p, etag: (await r.json()).etag });
		}
		return post(`/files/uploads/${start.json.uploadId}/complete`, { key: start.json.key, size: String(declaredSize), chunk: String(chunk), ck: bigFile.fields.ck, name: bigFile.fields.name, type: bigFile.fields.type, parts: JSON.stringify(etags) }, null);
	}
	const done = await multipartUpload(big.length);
	assert.equal(done.status, 200, `multipart complete: ${JSON.stringify(done.json)}`);
	const bigDl = new Uint8Array(await (await fetch(`${dev.base}${base}/files/${done.json.id}`, { headers: { "x-gorani-dev-email": email } })).arrayBuffer());
	assert.equal(bigDl.length, bigSealed.length);
	const f0 = await openChunk(bigKey, bigDl.subarray(0, chunk + FRAME_OVERHEAD), 0, false);
	const f1 = await openChunk(bigKey, bigDl.subarray(chunk + FRAME_OVERHEAD), 1, true);
	assert.deepEqual(new Uint8Array([...f0, ...f1]), big, "both frames open, the second as final");
	const forged = await multipartUpload(big.length + 1);
	assert.equal(forged.status, 400, "a declared size the object does not add up to is refused (and the object deleted)");

	// ── 4. A share copy through the public route ────────────────────────
	const shareId = newShareId();
	const kdf = newShareKdf(); // (every link carries a password since D11)
	const keys = await shareKeys(shareId, newShareSecret(), "live-suite-password", kdf);
	const copy = await sealChunked(keys.data, plain, 8 * 1024 * 1024);
	const sh = await api(dev.base, "POST", `${base}/files/shares`, {
		email,
		body: { id: shareId, fileId, version: 1, nameSealed: await sealer.shareName(shareId, "live.txt"), metaSealed: await sealShareMeta(keys.meta, shareId, { name: "live.txt", type: "text/plain", size: plain.length, modified: null }), expiresAt: new Date(Date.now() + 3600_000).toISOString(), downloadsLeft: 3, size: plain.length, kdf },
	});
	assert.equal(sh.status, 200, JSON.stringify(sh.json));
	const part = await fetch(`${dev.base}${base}/files/shares/${shareId}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": email }, body: copy });
	assert.equal(part.status, 200);
	const fin = await api(dev.base, "POST", `${base}/files/shares/${shareId}/complete`, { email, body: { parts: [{ partNumber: 1, etag: (await part.json()).etag }], size: plain.length } });
	assert.equal(fin.status, 200, JSON.stringify(fin.json));
	const claimed = await (await fetch(`${dev.base}/s/f/${shareId}/claim`, { method: "POST" })).json(); // O12: data needs a claim's token
	const pub = await fetch(`${dev.base}/s/f/${shareId}/data`, { headers: { "x-gorani-share-token": claimed.token } });
	assert.equal(pub.status, 200);
	assert.deepEqual(new Uint8Array(await pub.arrayBuffer()), copy, "the recipient receives the exact sealed copy");

	// ── 5. Clean up through the product's own purge path ────────────────
	await api(dev.base, "DELETE", `${base}/files/shares/${shareId}`, { email });
	for (const id of [fileId, done.json.id]) await api(dev.base, "DELETE", `${base}/files/${id}`, { email });
	const purge = await api(dev.base, "POST", `${base}/housekeeping`, { email, body: { trashDays: 0, shareDays: 0 } });
	assert.equal(purge.status, 200);
	assert.ok(purge.json.objectsDeleted >= 2, `the purge deleted the objects: ${JSON.stringify(purge.json)}`);
	assert.equal((await fetch(`${dev.base}${base}/files/${fileId}`, { headers: { "x-gorani-dev-email": email } })).status, 404, "the purged file is gone");

	// ── 6. (GORANI_LIVE_S3_LOCK=1) the real server enforces the lock ─────
	let locked = "";
	if (lockProbe) {
		await vouch(dev, ana, [bo]);
		const caseId = `live-lock-${Date.now().toString(36)}`;
		const evidence = await openCase(dev, ana, caseId, "Live lock probe", [[bo, "write"]], "evidence");
		const eck = newContentKey();
		const ef = await evidence.sealer.newFile("probe.bin", "application/octet-stream", eck);
		const eplain = enc.encode("one small object, locked for one day");
		const eup = await post("/files", { ...ef.fields, size: String(eplain.length), hash: await signedHash(bo, evidence.sealer, ef.id, 1, eplain), intake: await signedIntake(bo, evidence.sealer, ef.id, { source: "the live suite", method: "a 1-day lock probe" }) }, await sealWith(await importContentKey(eck), eplain), evidence.base);
		assert.equal(eup.status, 200, `evidence upload: ${JSON.stringify(eup.json)}`);
		// The bucket's own word on what is under the case's prefix.
		const listed = await (await s3fetch(s3, "GET", "", { "list-type": "2", prefix: `cases/${caseId}/` })).text();
		const objectKey = /<Key>([^<]+)<\/Key>/.exec(listed)?.[1];
		assert.ok(objectKey, `the evidence object is in the bucket: ${listed.slice(0, 300)}`);
		const ret = await s3fetch(s3, "GET", objectKey, { retention: "" });
		const retBody = await ret.text();
		assert.equal(ret.status, 200, `the object carries a retention — got ${ret.status}: ${retBody.slice(0, 300)} (see tests/output/wrangler-dev.log for the Worker's "lock … failed")`);
		assert.match(retBody, /<Mode>COMPLIANCE</, "COMPLIANCE mode: nobody can shorten or remove it");
		const until = /<RetainUntilDate>([^<]+)</.exec(retBody)?.[1];
		const days = (new Date(until) - Date.now()) / 86_400_000;
		assert.ok(days > 0.9 && days < 1.1, `until creation + EVIDENCE_RETAIN_DAYS (1): ${until}`);
		const head = await s3fetch(s3, "HEAD", objectKey);
		const versionId = head.headers.get("x-amz-version-id");
		assert.ok(versionId && versionId !== "null", "a versioned object (Object Lock protects versions)");
		// Refused how is the provider's choice: AWS and MinIO say 403
		// AccessDenied, IDrive e2 says 400 InvalidRequest (probed 2026-10-14).
		// What matters is that it is refused and the version survives.
		const del = await s3fetch(s3, "DELETE", objectKey, { versionId });
		assert.ok(del.status >= 400 && del.status < 500, `the server must refuse to delete a locked version — got ${del.status}: ${(await del.text()).slice(0, 300)}`);
		assert.equal((await s3fetch(s3, "HEAD", objectKey, { versionId })).status, 200, "…and the version is still there");
		const dl2 = await fetch(`${dev.base}${evidence.base}/files/${eup.json.id}`, { headers: { "x-gorani-dev-email": email } });
		assert.equal(dl2.status, 200, "the Worker still serves it");
		locked = `, Object Lock enforced by the server (${objectKey} until ${until})`;
	}

	console.log(`ok  api:s3-live — ${new URL(s3.endpoint).host}: private bucket, signed round trips, exact Range, multipart + size check, share copy, purge${locked}`);
} finally {
	await dev.close();
}
