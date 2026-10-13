// Copyright 2026- Seongwoo Hong. All rights reserved.

//! api:r2 — the R2 binding as the storage PRIORITY path. This suite runs the
//! dev server with the generated twin config (r2Twin(): wrangler.jsonc plus
//! the `R2BUCKET` binding), so workerd backs the binding with its local R2
//! simulator and every storage operation in worker/src/s3.rs takes the
//! R2 branch (an in-process call: no SigV4 signing, no HTTP hop). The walk
//! mirrors api:files' core loop so both backends prove the same contract:
//!
//!   whole upload → streamed 200 → Range 206 → chunked multipart → Range
//!
//! The delete/abort branches are one-liners over the same binding and keep
//! their coverage in the S3 suites (where the routes around them are
//! exercised end to end).

import assert from "node:assert/strict";
import { api, startDev, r2Twin } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, wrapContentKey, sealText } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked, FRAME_OVERHEAD } from "../../web/src/vault/chunked-file.ts";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";

const enc = new TextEncoder();

/** One multipart/form-data body, built by hand (the client's shape). */
function multipart(fields, file) {
	const boundary = `r2t${Math.random().toString(16).slice(2)}`;
	const parts = [];
	for (const [k, v] of Object.entries(fields)) parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`);
	const head = enc.encode(parts.join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const end = enc.encode(`\r\n--${boundary}--\r\n`);
	const body = file ? new Uint8Array([...head, ...file, ...end]) : new Uint8Array([...head, ...end]);
	return { contentType: `multipart/form-data; boundary=${boundary}`, body };
}

async function upload(dev, path, fields, file) {
	const { contentType, body } = multipart(fields, file);
	const r = await fetch(`${dev.base}/api/v1/members/jinu${path}`, { method: "POST", headers: { "content-type": contentType, "x-gorani-dev-email": "jinu@family.test" }, body });
	const text = await r.text();
	let json = null;
	try {
		json = JSON.parse(text);
	} catch {}
	return { status: r.status, json, text };
}

try {
	// The suite's own server: the R2-bound twin (a suite that ignores
	// GORANI_URL always starts fresh — a different storage backend must not
	// share state with the S3-configured suites).
	const twin = r2Twin();
	const dev = await startDev({ config: twin, persist: "persist-r2" });
	try {
		// ── 0. The family, its master, and the kid's vault ─────────────────
		await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
		await api(dev.base, "POST", "/api/v1/family/members", { body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
		const master = await createParentsMaster();
		await api(dev.base, "PUT", "/api/v1/family/master", { body: { keyId: master.keyId, publicKey: master.publicKey } });
		const kidVault = await createChildVault();
		const filesStore = await createStoreKey();
		const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
		const guardian = await sealStoreKeyToMaster(filesStore, master);
		const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own }, guardian } } });
		assert.equal(saved.status, 200, JSON.stringify(saved.json));

		const storePublic = { ec: filesStore.publicKey, kem: filesStore.pqPublicKey };
		const ck = newContentKey();
		const key = await importContentKey(ck);
		const ckSealed = await wrapContentKey(storePublic, ck);
		const typeSealed = await sealText(storePublic, "application/octet-stream");

		// ── 1. A whole upload through the binding ──────────────────────────
		const plain = enc.encode("r2-backed, still sealed on the way up");
		const sealed = await sealWith(key, plain);
		const up = await upload(dev, "/files", { ck: ckSealed, name: await sealText(storePublic, "letter.txt"), type: typeSealed, size: String(plain.length) }, sealed);
		assert.equal(up.status, 200, JSON.stringify(up.json));
		const fileId = up.json.id;

		// The stored object: GV02-sealed, byte-exact, with the wrapped key in
		// the header — the zero-trust contract doesn't care which backend sat
		// under it.
		const dl = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
		assert.equal(dl.status, 200);
		const stored = new Uint8Array(await dl.arrayBuffer());
		assert.equal(new TextDecoder().decode(stored.subarray(0, 4)), "GV02", "the stored object is GV02-sealed");
		assert.deepEqual(stored, new Uint8Array(sealed), "the exact sealed bytes");
		assert.ok(dl.headers.get("x-gorani-ck") === ckSealed, "the wrapped key rides the header");

		// A Range read through the binding: the caller's ciphertext span,
		// verbatim. bytes=4-20 (inclusive) → the 17 stored bytes 4..=20.
		const mid = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "jinu@family.test", Range: "bytes=4-20" } });
		assert.equal(mid.status, 206);
		assert.deepEqual(new Uint8Array(await mid.arrayBuffer()), stored.subarray(4, 21), "the requested span");

		// ── 2. A chunked upload in parts (GC01 frames, one part per frame) ─
		// The chunk is the multipart part size — the backends' minimum (5 MiB
		// for every part but the last) applies, and the simulator enforces it.
		const chunk = 5 * 1024 * 1024;
		const bigPlain = new Uint8Array(2 * chunk);
		for (let i = 0; i < bigPlain.length; i++) bigPlain[i] = i % 251;
		const bigSealed = await sealChunked(key, bigPlain, chunk);
		const start = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: bigPlain.length, chunk } });
		assert.equal(start.status, 200, JSON.stringify(start.json));
		assert.equal(start.json.parts, 2);
		const partEtags = [];
		for (let p = 1; p <= 2; p++) {
			const frame = bigSealed.subarray((p - 1) * (chunk + FRAME_OVERHEAD), p * (chunk + FRAME_OVERHEAD));
			const r = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.json.uploadId}/${p}?key=${encodeURIComponent(start.json.key)}`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" }, body: frame });
			assert.equal(r.status, 200, `part ${p}`);
			partEtags.push({ partNumber: p, etag: (await r.json()).etag });
		}
		const done = await upload(dev, `/files/uploads/${start.json.uploadId}/complete`, { key: start.json.key, size: String(bigPlain.length), chunk: String(chunk), ck: ckSealed, name: await sealText(storePublic, "photo.dat"), type: typeSealed, parts: JSON.stringify(partEtags) }, null);
		if (done.status !== 200) {
			// workerd logs errors to observability traces, not stderr — pull
			// them before the server dies so the failure is readable.
			for (const [table, sql] of [["logs", "SELECT level, message FROM logs WHERE level != 'info' ORDER BY ts_ms DESC LIMIT 6"], ["spans", "SELECT name, outcome, error FROM spans WHERE outcome != 'ok' OR error IS NOT NULL ORDER BY start_ms DESC LIMIT 6"]]) {
				const q = await fetch(`${dev.base}/cdn-cgi/local/explorer/api/local/observability/query`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sql }) });
				console.log(`TRACE ${table}:`, (await q.text()).slice(0, 2400));
			}
		}
		assert.equal(done.status, 200, JSON.stringify(done.json));
		const bigId = done.json.id;

		// A Range read in the middle: both frames, one byte short (honest 206).
		const frame = chunk + FRAME_OVERHEAD;
		const dl2 = await fetch(`${dev.base}/api/v1/members/jinu/files/${bigId}`, { headers: { "x-gorani-dev-email": "jinu@family.test", Range: `bytes=0-${2 * frame - 2}` } });
		assert.equal(dl2.status, 206);
		assert.ok(dl2.headers.get("x-gorani-chunk") === String(chunk), "chunked objects are marked");
		const slice = new Uint8Array(await dl2.arrayBuffer());
		assert.equal(slice.length, 2 * frame - 1, "both frames, one byte short");

		console.log("ok  api:r2 — the binding-backed backend proves the same sealed contract");
	} finally {
		await dev.close();
	}
} catch (e) {
	// The twin is generated from the real config; a wrangler failure here is
	// a suite failure (fail with the twin on disk for inspection).
	console.error(e?.message ?? e);
	process.exit(1);
}