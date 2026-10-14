// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:shares — a GS01 share link, end to end: the owner seals a copy under
 * the link's data key, uploads it in GC1 frames; the recipient (NO member
 * identity — the fragment secret is the credential) opens the meta, claims
 * a download, decrypts the exact bytes; exhaustion, expiry and revocation
 * refuse honestly.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { sealWith, openWith, newContentKey, importContentKey } from "../../web/src/vault/vault-crypto.ts";
import { storeSealer } from "../lib/placed.mjs";
import { sealChunked, openChunk, DEFAULT_CHUNK } from "../../web/src/vault/chunked-file.ts";
import { newShareId, newShareSecret, newShareKdf, shareKeys, sealShareMeta, openShareMeta } from "../../web/src/vault/share-crypto.ts";
import { splitFrame, frameAad } from "../../web/public/gorani-media-lib.js";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
import { toBase64, fromBase64 } from "../../web/src/lib/encoding.ts";

const dev = await suiteDev();
const enc = new TextEncoder();
const dec = new TextDecoder();

async function uploadFile(fields, file, email = "jinu@family.test") {
	const boundary = `t${Math.random().toString(16).slice(2)}`;
	const head = new TextEncoder().encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const body = new Uint8Array([...head, ...file, ...new TextEncoder().encode(`\r\n--${boundary}--\r\n`)]);
	const r = await fetch(`${dev.base}/api/v1/members/jinu/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": email }, body });
	return { status: r.status, json: await r.json() };
}

try {
	// ── 0. Family + kid vault (the setup the other suites walk) ────────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	const kidVault = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own } } } });
	assert.equal(saved.status, 200);

	// A file to share.
	const store = await storeSealer(filesStore.bundle, "jinu");
	const ck = newContentKey();
	const key = await importContentKey(ck);
	const plain = enc.encode("the recipe for gorani bread — family secret");
	const sealed = await sealWith(key, plain);
	const file = await store.newFile("bread-recipe.txt", "text/plain", ck);
	const up = await uploadFile({ ...file.fields, size: String(plain.length) }, sealed);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const fileId = up.json.id;
	// The owner's copy of each link's name is sealed into THAT link's place.
	const ownerName = (shareId) => store.shareName(shareId, "bread-recipe.txt");

	// ── 1. The owner creates the share (GS01) ──────────────────────────
	const id = newShareId();
	const secret = newShareSecret();
	// Every link carries a password (D11, commit 30 — section 7 is the policy).
	const LINK_PW = "bread-secret-2026";
	const kdf1 = newShareKdf();
	const keys = await shareKeys(id, secret, LINK_PW, kdf1);
	const copy = await sealChunked(keys.data, plain, DEFAULT_CHUNK);
	const metaSealed = await sealShareMeta(keys.meta, id, { name: "bread-recipe.txt", type: "text/plain", size: plain.length, modified: null });
	const start = await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
		email: "jinu@family.test",
		body: { id, fileId, version: 1, nameSealed: await ownerName(id), metaSealed, expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString(), downloadsLeft: 2, size: plain.length, kdf: kdf1 },
	});
	assert.equal(start.status, 200, JSON.stringify(start.json));
	assert.equal(start.json.parts, 1, "one small file → one frame → one part");

	// The part PUT: frame bytes.
	const etagRes = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${id}/parts/1`, {
		method: "PUT",
		headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" },
		body: copy,
	});
	assert.equal(etagRes.status, 200);
	const { etag } = await etagRes.json();

	const complete = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${id}/complete`, { email: "jinu@family.test", body: { parts: [{ partNumber: 1, etag }], size: plain.length } });
	assert.equal(complete.status, 200, JSON.stringify(complete.json));

	// The owner's list shows it (name sealed to the store key).
	const list = await api(dev.base, "GET", "/api/v1/members/jinu/files/shares", { email: "jinu@family.test" });
	const mine = list.json.find((x) => x.id === id);
	assert.ok(mine && mine.ready && !mine.revoked);

	// ── 2. The recipient opens it — no member identity at all ──────────
	// First the PAGE itself (commit 24): it used to be fetched by the Worker
	// from its own public origin, a subrequest the platform refuses — so
	// /s/f/<id> was a bare 500 and no link ever opened. It now comes from the
	// ASSETS binding, under the share page's own strict CSP.
	const pageRes = await fetch(`${dev.base}/s/f/${id}`);
	assert.equal(pageRes.status, 200, "the share page is served");
	assert.match(pageRes.headers.get("content-type") ?? "", /^text\/html/);
	assert.match(pageRes.headers.get("content-security-policy") ?? "", /trusted-types 'none'/, "with the share page's policy, not the API's");
	assert.match(await pageRes.text(), /src="\/s\.js"/, "the built page, whose code is the same-origin /s.js");

	const metaRes = await fetch(`${dev.base}/s/f/${id}/meta`);
	if (metaRes.status !== 200) console.error("META FAIL", metaRes.status, await metaRes.text());
	assert.equal(metaRes.status, 200);
	const info = await metaRes.json();
	assert.ok(atob(info.metaSealed).startsWith("GS01"), "the meta is sealed (GS01 bytes)");
	const meta = await openShareMeta(keys.meta, id, info.metaSealed);
	assert.equal(meta.name, "bread-recipe.txt");
	assert.equal(meta.size, plain.length);

	// Without a claim there is no data (commit 25, O12): the link used to
	// serve /data to anyone, so download limits were the page's courtesy.
	assert.equal((await fetch(`${dev.base}/s/f/${id}/data`)).status, 403, "no token, no data");
	assert.equal((await fetch(`${dev.base}/s/f/${id}/data`, { headers: { "x-gorani-share-token": "made-up-token" } })).status, 403, "a forged token, no data");

	// The claim decrements — and returns the token /data serves to.
	const claim = await fetch(`${dev.base}/s/f/${id}/claim`, { method: "POST" });
	assert.equal(claim.status, 200);
	const claimed = await claim.json();
	assert.equal(claimed.downloadsLeft, 1);
	assert.match(claimed.token, /^[A-Za-z0-9_-]{43}$/, "a 256-bit token");
	const withToken = { headers: { "x-gorani-share-token": claimed.token } };

	// The data endpoint serves the sealed copy; the recipient decrypts.
	const dataRes = await fetch(`${dev.base}/s/f/${id}/data`, withToken);
	assert.equal(dataRes.status, 200);
	const sealedCopy = new Uint8Array(await dataRes.arrayBuffer());
	assert.equal(sealedCopy.length, copy.length);
	const frames = Math.ceil(plain.length / DEFAULT_CHUNK);
	const out = new Uint8Array(plain.length);
	for (let i = 0; i < frames; i++) {
		const at = i * (DEFAULT_CHUNK + 28);
		const len = Math.min(DEFAULT_CHUNK + 28, sealedCopy.length - at);
		const { iv, body } = splitFrame(sealedCopy, at, len);
		const one = await openChunk(keys.data, new Uint8Array([...iv, ...body]), i, i === frames - 1);
		out.set(one, i * DEFAULT_CHUNK);
	}
	assert.deepEqual(out, plain, "the recipient holds the exact bytes");
	assert.equal(dec.decode(out), dec.decode(plain));

	// Range requests work too, within the same download session (a large
	// copy fetched in pieces is still ONE download).
	const ranged = await fetch(`${dev.base}/s/f/${id}/data`, { headers: { ...withToken.headers, Range: `bytes=0-${DEFAULT_CHUNK + 27}` } });
	assert.equal(ranged.status, 206);
	assert.ok(ranged.headers.get("content-range")?.startsWith("bytes 0-"));

	// ── 3. Exhaustion: 2 downloads allowed, 2 claimed ──────────────────
	const claim2 = await fetch(`${dev.base}/s/f/${id}/claim`, { method: "POST" });
	assert.equal(claim2.status, 200);
	const last = await claim2.json();
	assert.equal(last.downloadsLeft, 0);
	// The LAST download downloads (O12a): /data used to re-check
	// `downloads_left > 0` after the claim had spent it — a one-download link
	// could never be fetched at all.
	assert.equal((await fetch(`${dev.base}/s/f/${id}/data`, { headers: { "x-gorani-share-token": last.token } })).status, 200, "the last claim's download is served");
	const claim3 = await fetch(`${dev.base}/s/f/${id}/claim`, { method: "POST" });
	assert.equal(claim3.status, 410, "used up");
	const metaGone = await fetch(`${dev.base}/s/f/${id}/meta`);
	assert.equal(metaGone.status, 410, `used up: ${await metaGone.text()}`);

	// ── 4. Revocation (owner side) deletes the object too ──────────────
	const id2 = newShareId();
	const secret2 = newShareSecret();
	const kdf2 = newShareKdf();
	const keys2 = await shareKeys(id2, secret2, LINK_PW, kdf2);
	const meta2 = await sealShareMeta(keys2.meta, id2, { name: "x.txt", type: null, size: 4, modified: null });
	const s2 = await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
		email: "jinu@family.test",
		body: { id: id2, fileId, version: 1, nameSealed: await ownerName(id2), metaSealed: meta2, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 5, size: 4, kdf: kdf2 },
	});
	assert.equal(s2.status, 200);
	// No parts uploaded yet: the meta must refuse (still being prepared).
	const early = await fetch(`${dev.base}/s/f/${id2}/meta`);
	assert.equal(early.status, 404, "not ready yet");
	// Completing with NO parts used to mark a share ready — a public link
	// whose copy object did not exist. Since commit 23 the copy must add up
	// to its declared size: the refusal on a throwaway share first…
	const idEmpty = newShareId();
	const kdfEmpty = newShareKdf();
	const metaEmpty = await sealShareMeta((await shareKeys(idEmpty, newShareSecret(), LINK_PW, kdfEmpty)).meta, idEmpty, { name: "x.txt", type: null, size: 4, modified: null });
	const sEmpty = await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
		email: "jinu@family.test",
		body: { id: idEmpty, fileId, version: 1, nameSealed: await ownerName(idEmpty), metaSealed: metaEmpty, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 5, size: 4, kdf: kdfEmpty },
	});
	assert.equal(sEmpty.status, 200);
	const empty = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${idEmpty}/complete`, { email: "jinu@family.test", body: { parts: [], size: 4 } });
	assert.notEqual(empty.status, 200, "a share with no copy bytes is never marked ready");
	assert.equal((await fetch(`${dev.base}/s/f/${idEmpty}/meta`)).status, 404, "…and its link stays 'being prepared'");
	// …then the honest path: a real 4-byte copy, one part, and it adds up.
	const copy2 = await sealChunked(keys2.data, enc.encode("four"), DEFAULT_CHUNK);
	const part2 = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${id2}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test" }, body: copy2 });
	assert.equal(part2.status, 200);
	const c2 = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${id2}/complete`, { email: "jinu@family.test", body: { parts: [{ partNumber: 1, etag: (await part2.json()).etag }], size: 4 } });
	assert.equal(c2.status, 200, JSON.stringify(c2.json));
	const ready = await fetch(`${dev.base}/s/f/${id2}/meta`);
	assert.equal(ready.status, 200);
	// A download session open when the owner revokes dies with the link.
	const token2 = (await (await fetch(`${dev.base}/s/f/${id2}/claim`, { method: "POST" })).json()).token;
	assert.equal((await fetch(`${dev.base}/s/f/${id2}/data`, { headers: { "x-gorani-share-token": token2 } })).status, 200);
	assert.equal((await api(dev.base, "DELETE", `/api/v1/members/jinu/files/shares/${id2}`, { email: "mom@family.test" })).status, 403, "a lead does not revoke another member's link (no act-for since 27c)");
	const revoke = await api(dev.base, "DELETE", `/api/v1/members/jinu/files/shares/${id2}`, { email: "jinu@family.test" });
	assert.equal(revoke.status, 200, JSON.stringify(revoke.json));
	const revokedMeta = await fetch(`${dev.base}/s/f/${id2}/meta`);
	assert.equal(revokedMeta.status, 404, "revoked shares open nothing");
	const revokedData = await fetch(`${dev.base}/s/f/${id2}/data`, { headers: { "x-gorani-share-token": token2 } });
	assert.equal(revokedData.status, 404);

	// ── 5. Expiry ───────────────────────────────────────────────────────
	const id3 = newShareId();
	const secret3 = newShareSecret();
	const kdf3 = newShareKdf();
	const keys3 = await shareKeys(id3, secret3, LINK_PW, kdf3);
	const meta3 = await sealShareMeta(keys3.meta, id3, { name: "old.txt", type: null, size: 4, modified: null });
	await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
		email: "jinu@family.test",
		body: { id: id3, fileId, version: 1, nameSealed: await ownerName(id3), metaSealed: meta3, expiresAt: new Date(Date.now() - 1000).toISOString(), downloadsLeft: 5, size: 4, kdf: kdf3 },
	});
	// (A real 4-byte copy: completion must add up since commit 23.)
	const part3 = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${id3}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": "jinu@family.test" }, body: await sealChunked(keys3.data, enc.encode("aged"), DEFAULT_CHUNK) });
	const done3 = await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${id3}/complete`, { email: "jinu@family.test", body: { parts: [{ partNumber: 1, etag: (await part3.json()).etag }], size: 4 } });
	assert.equal(done3.status, 200, JSON.stringify(done3.json));
	const expired = await fetch(`${dev.base}/s/f/${id3}/meta`);
	assert.equal(expired.status, 410, `expired: ${expired.status} ${await expired.text()}`);

	// ── 6. A password-protected share: both halves, end to end ─────────
// The dialog's exact server flow (kdf rides the share's record —
// parameters, not secrets), then the recipient walk WITH the password:
// wrong-password refused, right one opens and decrypts. The page's module
// does this derivation too — unit:share-lib proves the two agree.
	const pwId = newShareId();
	const pwSecret = newShareSecret();
	const pwKdf = newShareKdf();
	const pwKeys = await shareKeys(pwId, pwSecret, "bread-secret-2026", pwKdf);
	const pwCopy = await sealChunked(pwKeys.data, plain, DEFAULT_CHUNK);
	const pwMetaSealed = await sealShareMeta(pwKeys.meta, pwId, { name: "bread-recipe.txt", type: "text/plain", size: plain.length, modified: null });
	const pwStart = await api(dev.base, "POST", "/api/v1/members/jinu/files/shares", {
		email: "jinu@family.test",
		body: { id: pwId, fileId, version: 1, nameSealed: await ownerName(pwId), metaSealed: pwMetaSealed, expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString(), downloadsLeft: 2, size: plain.length, kdf: pwKdf },
	});
	assert.equal(pwStart.status, 200, JSON.stringify(pwStart.json));
	const pwEtagRes = await fetch(`${dev.base}/api/v1/members/jinu/files/shares/${pwId}/parts/1`, {
		method: "PUT",
		headers: { "x-gorani-dev-email": "jinu@family.test", "content-type": "application/octet-stream" },
		body: pwCopy,
	});
	const pwEtag = (await pwEtagRes.json()).etag;
	assert.equal((await api(dev.base, "POST", `/api/v1/members/jinu/files/shares/${pwId}/complete`, { email: "jinu@family.test", body: { parts: [{ partNumber: 1, etag: pwEtag }], size: plain.length } })).status, 200);

	// The server declares the kdf; the link's secret ALONE opens nothing.
	const pwMetaRes = await fetch(`${dev.base}/s/f/${pwId}/meta`);
	assert.equal(pwMetaRes.status, 200);
	const pwInfo = await pwMetaRes.json();
	assert.deepEqual(pwInfo.kdf, pwKdf, "the Argon2id settings ride the meta");
	await assert.rejects(() => shareKeys(pwId, pwSecret).then((k) => openShareMeta(k.meta, pwId, pwInfo.metaSealed)), /Wrong password|incomplete/);

	// The right password: the full recipient walk.
	const pwOpen = await shareKeys(pwId, pwSecret, "bread-secret-2026", pwInfo.kdf);
	assert.deepEqual(await openShareMeta(pwOpen.meta, pwId, pwInfo.metaSealed), { name: "bread-recipe.txt", type: "text/plain", size: plain.length, modified: null });
	const pwClaim = await fetch(`${dev.base}/s/f/${pwId}/claim`, { method: "POST" });
	const pwToken = (await pwClaim.clone().json()).token;
	assert.equal(pwClaim.status, 200);
	const pwData = await fetch(`${dev.base}/s/f/${pwId}/data`, { headers: { "x-gorani-share-token": pwToken } });
	assert.equal(pwData.status, 200);
	const pwSealedCopy = new Uint8Array(await pwData.arrayBuffer());
	const pwOut = new Uint8Array(plain.length);
	for (let i = 0; i < 1; i++) {
		const { iv, body } = splitFrame(pwSealedCopy, 0, pwSealedCopy.length);
		pwOut.set(await openChunk(pwOpen.data, new Uint8Array([...iv, ...body]), 0, true));
	}
	assert.deepEqual(pwOut, plain, "the password-gated copy opens to the exact bytes");

	// ── 7. The link policy (D11): a password, a week, 1–100 downloads ──
	// The server never sees the password; it requires the parameters that
	// prove one is mixed in, within the bounds a recipient's page accepts.
	const policy = async (over) => {
		const pid = newShareId();
		const pk = await shareKeys(pid, newShareSecret(), LINK_PW, kdf1);
		const body = { id: pid, fileId, version: 1, nameSealed: await ownerName(pid), metaSealed: await sealShareMeta(pk.meta, pid, { name: "p.txt", type: null, size: 4, modified: null }), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 5, size: 4, kdf: newShareKdf(), ...over };
		return api(dev.base, "POST", "/api/v1/members/jinu/files/shares", { email: "jinu@family.test", body });
	};
	const refused = async (over, why) => {
		const r = await policy(over);
		assert.equal(r.status, 400, `${JSON.stringify(over)} → ${r.status}`);
		assert.match(r.json.error, why);
	};
	await refused({ kdf: undefined }, /needs a password/);
	await refused({ kdf: { ...newShareKdf(), m: 1024 } }, /outside what a recipient's page accepts/);
	await refused({ kdf: { ...newShareKdf(), salt: "AAAA" } }, /outside/);
	await refused({ expiresAt: new Date(Date.now() + 8 * 86_400_000).toISOString() }, /within 7 days/);
	await refused({ expiresAt: "next week" }, /RFC 3339/);
	await refused({ downloadsLeft: 0 }, /1–100/);
	await refused({ downloadsLeft: 1000 }, /1–100/);
	assert.equal((await policy({ expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(), downloadsLeft: 100 })).status, 200, "a week and 100 downloads: the limit, allowed");

	// ── 8. The share index: public routes found the member every time ──
	// (implicit: /s/f/:id resolved mom↔jinu without any identity header).

	console.log("ok  api:shares — create/upload/complete, recipient decrypt, exhaustion, revocation, expiry, password links, the D11 policy (password, a week, 1–100 downloads)");
} finally {
	await dev.close();
}