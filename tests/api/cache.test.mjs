// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:cache — the edge cache for encrypted blob reads (worker/src/cache.rs,
 * docs/PRODUCTION.md › Object caching), proven against the runtime's own
 * emulated cache:
 *
 *   whole GET twice      → miss, then hit; byte-identical
 *   Range on the entry   → 206 sliced by the PLATFORM from the cached body
 *   over the threshold   → bypass (miss stays miss — the size gate holds)
 *   chunked frame span   → the media path's deterministic span keys hit
 *
 * Dev runs with CACHE_MAX_OBJECT_MB=1 so the boundary is a 2 MB upload.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { sealChunked, FRAME_OVERHEAD } from "../../web/src/vault/chunked-file.ts";
import { sealWith, newContentKey, importContentKey } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";

const dev = await suiteDev();
const enc = new TextEncoder();

async function uploadWhole(fields, file) {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
	const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": "jinu@family.test" }, body });
	return { status: r.status, json: await r.json() };
}

const get = async (id, range) => {
	const r = await fetch(`${dev.base}/api/v1/members/jinu/files/${id}`, { headers: { "x-gorani-dev-email": "jinu@family.test", ...(range ? { Range: range } : {}) } });
	return { status: r.status, body: new Uint8Array(await r.arrayBuffer()), cache: r.headers.get("x-gorani-cache") };
};

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
	const store = await storeSealer(filesStore.bundle, "jinu");

	const plain = enc.encode("the cache holds ciphertext — the key stays with the family");
	const ck = newContentKey();
	const sealed = new Uint8Array(await sealWith(await importContentKey(ck), plain));
	const up = await uploadWhole({ ...(await store.newFile("letter.txt", "text/plain", ck)).fields, size: String(plain.length) }, sealed);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const fileId = up.json.id;

	// ── 1. Whole GET: miss, then hit; the same bytes either way ─────────
	const first = await get(fileId);
	if (first.status !== 200) {
		// workerd logs errors to observability traces, not stderr.
		const q = await fetch(`${dev.base}/cdn-cgi/local/explorer/api/local/observability/query`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sql: "SELECT level, message FROM logs WHERE level != 'info' ORDER BY ts_ms DESC LIMIT 5" }) });
		console.error("TRACE:", (await q.text()).slice(0, 1500));
	}
	assert.equal(first.status, 200);
	assert.equal(first.cache, "miss", `first read is a miss (${first.cache})`);
	assert.deepEqual(first.body, sealed, "the sealed bytes, untouched by the cache");
	const second = await get(fileId);
	assert.equal(second.cache, "hit", `the second read is served from cache (${second.cache})`);
	assert.deepEqual(second.body, sealed, "the cached copy is byte-identical");

	// ── 2. Range over a cached entry: the platform slices it ───────────
	const slice = await get(fileId, "bytes=4-11");
	assert.equal(slice.status, 206);
	assert.equal(slice.cache, "hit", "the slice comes from the cached whole entry");
	assert.deepEqual(slice.body, sealed.subarray(4, 12), "the requested span, exact");

	// ── 3. Over the threshold: the size gate bypasses ───────────────────
	// 7 MB against the dev gate of 6 MB — sealed like any upload (the bytes
	// must start with the GV02 magic or the sealed-shape check refuses them).
	const bigPlainLength = 7 * 1024 * 1024;
	const big = new Uint8Array(await sealWith(await importContentKey(newContentKey()), new Uint8Array(bigPlainLength)));
	const ck2 = newContentKey();
	// `size` is the PLAINTEXT length — the worker checks it against the sealed
	// bytes (sealed − 32) since commit 23; this used to send the sealed length.
	const bigUp = await uploadWhole({ ...(await store.newFile("big.bin", "application/octet-stream", ck2)).fields, size: String(bigPlainLength) }, big);
	assert.equal(bigUp.status, 200, JSON.stringify(bigUp.json));
	const b1 = await get(bigUp.json.id);
	assert.equal(b1.status, 200);
	assert.equal(b1.cache, "bypass", "the big read bypasses the size gate");
	const b2 = await get(bigUp.json.id);
	assert.equal(b2.cache, "bypass", "and keeps bypassing — the gate held");
	assert.deepEqual(b2.body, big, "the bypass still serves the exact bytes");

	// ── 4. Chunked media: deterministic frame-span keys hit on replay ──
	const chunk = 5 * 1024 * 1024; // the backends' multipart minimum
	const frame = chunk + FRAME_OVERHEAD;
	const mediaPlain = new Uint8Array(2 * chunk);
	for (let i = 0; i < mediaPlain.length; i++) mediaPlain[i] = i % 251;
	const mediaCk = newContentKey();
	const mediaKey = await importContentKey(mediaCk);
	const mediaSealed = await sealChunked(mediaKey, mediaPlain, chunk);
	const media = await store.newFile("clip.dat", "application/octet-stream", mediaCk);
	const start = await api(dev.base, "POST", "/api/v1/members/jinu/files/uploads", { email: "jinu@family.test", body: { size: mediaPlain.length, chunk, newFileId: media.id } });
	assert.equal(start.status, 200, JSON.stringify(start.json));
	const etags = [];
	for (let p = 1; p <= 2; p++) {
		const frameBytes = mediaSealed.subarray((p - 1) * frame, p * frame);
		const r = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.json.uploadId}/${p}?key=${encodeURIComponent(start.json.key)}`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" }, body: frameBytes });
		assert.equal(r.status, 200, `part ${p}`);
		etags.push({ partNumber: p, etag: (await r.json()).etag });
	}
	const done = await fetch(`${dev.base}/api/v1/members/jinu/files/uploads/${start.json.uploadId}/complete`, {
		method: "POST",
		headers: { "content-type": "multipart/form-data; boundary=cd", "x-gorani-dev-email": "jinu@family.test" },
		body: await (async () => {
			const { file_id: _id, ...sealedFields } = media.fields;
			void _id;
			const fields = { key: start.json.key, size: String(mediaPlain.length), chunk: String(chunk), ...sealedFields, parts: JSON.stringify(etags) };
			const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--cd\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + "--cd--\r\n");
			return new Uint8Array([...head]);
		})(),
	});
	const doneText = await done.text();
	assert.equal(done.status, 200, doneText);
	const mediaId = JSON.parse(doneText).id;

	// The media worker's shape: frame-aligned ciphertext spans.
	const span1 = await get(mediaId, `bytes=0-${frame - 1}`);
	assert.equal(span1.status, 206);
	assert.equal(span1.cache, "miss", "first span read is a miss");
	assert.deepEqual(span1.body, mediaSealed.subarray(0, frame), "frame 0, exact");
	const span1Again = await get(mediaId, `bytes=0-${frame - 1}`);
	assert.equal(span1Again.cache, "hit", "the same span replays from cache");
	assert.deepEqual(span1Again.body, span1.body, "replay is byte-identical");
	const span2 = await get(mediaId, `bytes=${frame}-${2 * frame - 1}`);
	assert.equal(span2.status, 206);
	assert.equal(span2.cache, "miss", "a different span is its own key");
	assert.deepEqual(span2.body, mediaSealed.subarray(frame, 2 * frame), "frame 1, exact");
	const span2Again = await get(mediaId, `bytes=${frame}-${2 * frame - 1}`);
	assert.equal(span2Again.cache, "hit");

	console.log("ok  api:cache — miss→hit, platform Range slicing, size-gate bypass, frame-span replays");
} finally {
	await dev.close();
}