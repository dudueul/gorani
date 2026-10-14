// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:hashes — the uploader signs what they uploaded (commit 29d,
 * docs/CUSTODY.md › Stage 4, D5.1; web/src/vault/content-hash.ts). What it
 * proves:
 *
 *   1. an evidence case refuses a version without its uploader's signed
 *      content hash — whole uploads, multipart completions and new versions
 *      alike — and leaves no object behind; a hash that is not sealed text
 *      is refused everywhere;
 *   2. a signed upload is stored as sent and handed back, still sealed, with
 *      the key (`files/keys`) and with the bytes (`x-gorani-hash`), for any
 *      version;
 *   3. a reader who trusts the uploader (here through a lead's certificate)
 *      verifies the bytes they decrypted against it;
 *   4. what fails, fails as what it is: a record moved to another version
 *      (does not open there), a record re-sealed by another holder of the
 *      case key into a place it was not signed for (signature), honest
 *      signature over other bytes (mismatch), a signer the reader never
 *      verified, a key that is not the signer's current identity;
 *   5. outside evidence the hash is optional: an unsigned upload lands and
 *      reads as `unsigned`, never as verified.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, openWith, sealPlacedText, openPlacedText } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked } from "../../web/src/vault/chunked-file.ts";
import { checkContentHash, sha256Hex, signContentHash } from "../../web/src/vault/content-hash.ts";
import { places } from "../../web/src/vault/places.ts";
import { statements } from "../../web/src/vault/identity.ts";
import { member, vouch, openCase, trustOf, signedHash, signedIntake } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();

async function post(who, path, fields, file) {
	const boundary = `h${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + (file ? `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n` : ""));
	const tail = enc.encode(file ? `\r\n--${boundary}--\r\n` : `--${boundary}--\r\n`);
	const r = await fetch(`${dev.base}${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...(file ?? []), ...tail]) });
	return { status: r.status, json: await r.json().catch(() => null) };
}
const keysUnder = async (prefix) => [...(await (await fetch(`${dev.s3}?list-type=2&prefix=${encodeURIComponent(prefix)}`)).text()).matchAll(/<Key>([^<]+)<\/Key>/g)].map((m) => m[1]);
/** What a reader holds after a download: the version, its sealed record, SHA-256 of the plaintext. */
async function readBack(who, kase, id, version) {
	const r = await fetch(`${dev.base}${kase.base}/files/${id}${version ? `?version=${version}` : ""}`, { headers: { "x-gorani-dev-email": who.email } });
	assert.equal(r.status, 200);
	const served = Number(r.headers.get("x-gorani-version"));
	const key = await kase.sealer.openFileKey(id, served, r.headers.get("x-gorani-ck"));
	const plain = await openWith(key, new Uint8Array(await r.arrayBuffer()));
	return { version: served, hash: r.headers.get("x-gorani-hash"), actual: { sha256: await sha256Hex(plain), size: plain.length } };
}

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const cy = await member(dev, "cy", "analyst", { by: ana });
	const dee = await member(dev, "dee", "analyst", { by: ana }); // never vouched for: nobody verified dee
	await vouch(dev, ana, [bo, cy]);
	const ev = await openCase(dev, ana, "ir-hash", "Signed evidence", [[bo, "write"], [cy, "write"]], "evidence");
	const working = await openCase(dev, ana, "wk-hash", "Working notes", [[bo, "write"]]);

	// ── 1. Evidence refuses an unsigned version ─────────────────────────
	const plain = enc.encode("disk image, sector 0: what Bo collected");
	const ck = newContentKey();
	const f = await ev.sealer.newFile("disk.E01", "application/octet-stream", ck);
	const sealed = await sealWith(await importContentKey(ck), plain);
	const unsigned = await post(bo, `${ev.base}/files`, { ...f.fields, size: String(plain.length) }, sealed);
	assert.equal(unsigned.status, 400);
	assert.match(unsigned.json.error, /signed content hash/, "named for what it is missing");
	assert.deepEqual(await keysUnder("cases/ir-hash/"), [], "the refused upload left no object behind");
	const plainHash = await post(bo, `${ev.base}/files`, { ...f.fields, size: String(plain.length), hash: JSON.stringify({ sha256: "0".repeat(64) }) }, sealed);
	assert.equal(plainHash.status, 400);
	assert.match(plainHash.json.error, /sealed into its place/, "a readable hash is refused: the server must not learn it");

	// The multipart path completes through the same check.
	const big = enc.encode("a memory image, in frames");
	const bigCk = newContentKey();
	const bigFile = await ev.sealer.newFile("memory.raw", "application/octet-stream", bigCk);
	const chunk = 5 * 1024 * 1024;
	const frames = await sealChunked(await importContentKey(bigCk), big, chunk);
	async function multipart(extra) {
		const start = await api(dev.base, "POST", `${ev.base}/files/uploads`, { email: bo.email, body: { size: big.length, chunk, newFileId: bigFile.id } });
		assert.equal(start.status, 200, start.text);
		const part = await fetch(`${dev.base}${ev.base}/files/uploads/${start.json.uploadId}/1`, { method: "PUT", headers: { "x-gorani-dev-email": bo.email }, body: frames });
		assert.equal(part.status, 200);
		return post(bo, `${ev.base}/files/uploads/${start.json.uploadId}/complete`, { key: start.json.key, size: String(big.length), chunk: String(chunk), ck: bigFile.fields.ck, name: bigFile.fields.name, type: bigFile.fields.type, parts: JSON.stringify([{ partNumber: 1, etag: (await part.json()).etag }]), ...extra });
	}
	const mpUnsigned = await multipart({});
	assert.equal(mpUnsigned.status, 400, "a multipart completion without the hash is refused too");
	assert.deepEqual(await keysUnder("cases/ir-hash/"), [], "…and its completed object deleted");
	const mp = await multipart({ hash: await signedHash(bo, ev.sealer, bigFile.id, 1, big), intake: await signedIntake(bo, ev.sealer, bigFile.id) });
	assert.equal(mp.status, 200, JSON.stringify(mp.json));

	// ── 2. A signed upload, stored and handed back sealed ────────────────
	const hash1 = await signedHash(bo, ev.sealer, f.id, 1, plain);
	const up = await post(bo, `${ev.base}/files`, { ...f.fields, size: String(plain.length), hash: hash1, intake: await signedIntake(bo, ev.sealer, f.id) }, sealed);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const keyed = await api(dev.base, "POST", `${ev.base}/files/keys`, { email: cy.email, body: { ids: [f.id] } });
	assert.equal(keyed.json.keys[f.id].hash, hash1, "with the key: the record exactly as the uploader sealed it");
	// A second version, signed for version 2 — and refused unsigned.
	const plain2 = enc.encode("disk image, re-acquired: other bytes");
	const ck2 = newContentKey();
	const v2fields = { ck: await ev.sealer.fileKey(f.id, 2, ck2), type: await ev.sealer.fileType(f.id, 2, "application/octet-stream"), size: String(plain2.length), base_version: "1" };
	const sealed2 = await sealWith(await importContentKey(ck2), plain2);
	assert.equal((await post(bo, `${ev.base}/files/${f.id}/versions`, v2fields, sealed2)).status, 400, "a new evidence version needs its own signature");
	const hash2 = await signedHash(bo, ev.sealer, f.id, 2, plain2);
	assert.equal((await post(bo, `${ev.base}/files/${f.id}/versions`, { ...v2fields, hash: hash2 }, sealed2)).status, 200);

	// ── 3. A reader who trusts the uploader verifies ────────────────────
	const cyTrust = await trustOf(dev, cy); // cy pinned ana; ana certified bo
	const r1 = await readBack(cy, ev, f.id, 1);
	assert.equal(r1.hash, hash1, "with the bytes: x-gorani-hash, for an OLD version too");
	const v1 = await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 1, r1.hash, r1.actual);
	assert.deepEqual({ status: v1.status, signer: v1.signer, via: v1.via }, { status: "verified", signer: "bo", via: "cert:ana" }, JSON.stringify(v1));
	const r2 = await readBack(cy, ev, f.id);
	assert.equal(r2.version, 2);
	assert.equal((await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 2, r2.hash, r2.actual)).status, "verified");
	const mpKeys = await api(dev.base, "POST", `${ev.base}/files/keys`, { email: cy.email, body: { ids: [bigFile.id] } });
	assert.equal((await checkContentHash(ev.sealer.priv, cyTrust, ev.area, bigFile.id, 1, mpKeys.json.keys[bigFile.id].hash, { sha256: await sha256Hex(big), size: big.length })).status, "verified", "the multipart upload's record too");

	// ── 4. Each failure as what it is ───────────────────────────────────
	// a. Version 1's record presented as version 2's (the server's power):
	//    it does not open in version 2's place.
	const moved = await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 2, hash1, r2.actual);
	assert.equal(moved.status, "invalid");
	assert.match(moved.why, /does not open in this version's place/);
	// b. cy holds the case key, so cy CAN seal into version 2's place — but
	//    bo's signature was over version 1's statement.
	const opened1 = JSON.parse(await openPlacedText(ev.sealer.priv, places.fileHash(ev.area, f.id, 1), hash1));
	const resealed = await sealPlacedText(ev.sealer.priv, places.fileHash(ev.area, f.id, 2), JSON.stringify({ ...opened1, sha256: r2.actual.sha256, size: r2.actual.size }));
	const forged = await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 2, resealed, r2.actual);
	assert.equal(forged.status, "invalid");
	assert.match(forged.why, /bo did not sign this record/, "a co-worker with the key cannot make bo vouch for bytes bo did not sign");
	// c. bo honestly signed OTHER bytes: the signature verifies, the bytes do not match.
	const other = await signContentHash(bo.signer, ev.sealer.priv, ev.area, f.id, 1, await sha256Hex(enc.encode("something else")), plain.length);
	const mismatch = await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 1, other, r1.actual);
	assert.equal(mismatch.status, "mismatch", "these are not the bytes bo signed");
	// d. A signer the reader never verified: dee (no certificate, not pinned).
	const byDee = await signContentHash(dee.signer, ev.sealer.priv, ev.area, f.id, 1, r1.actual.sha256, r1.actual.size);
	const untrusted = await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 1, byDee, r1.actual);
	assert.equal(untrusted.status, "untrusted");
	assert.match(untrusted.why, /dee is not an identity you verified/);
	//    …and the same record read by someone who trusts no one but themselves.
	assert.equal((await checkContentHash(ev.sealer.priv, await trustOf(dev, dee), ev.area, f.id, 1, hash1, r1.actual)).status, "untrusted");
	// e. A key id that is not the signer's current identity (re-enrolled since).
	const oldKey = await sealPlacedText(ev.sealer.priv, places.fileHash(ev.area, f.id, 1), JSON.stringify({ ...opened1, keyId: "a".repeat(64) }));
	const stale = await checkContentHash(ev.sealer.priv, cyTrust, ev.area, f.id, 1, oldKey, r1.actual);
	assert.equal(stale.status, "untrusted");
	assert.match(stale.why, /re-enrolled since/);
	// (The statement's spelling, pinned: area, file, version, hash, size.)
	assert.ok(await cyTrust.of("bo").verify(statements.contentHash(ev.area, f.id, 1, opened1.sha256, opened1.size), opened1.signature));

	// ── 5. Outside evidence the hash is optional ────────────────────────
	const wck = newContentKey();
	const wf = await working.sealer.newFile("notes.md", "text/markdown", wck);
	const wplain = enc.encode("# notes");
	assert.equal((await post(bo, `${working.base}/files`, { ...wf.fields, size: String(wplain.length) }, await sealWith(await importContentKey(wck), wplain))).status, 200, "a working case takes an unsigned upload");
	const wr = await readBack(bo, working, wf.id);
	assert.equal(wr.hash, null, "no record, no header");
	assert.equal((await checkContentHash(working.sealer.priv, await trustOf(dev, bo), working.area, wf.id, 1, wr.hash, wr.actual)).status, "unsigned", "…and it reads as unsigned, never as verified");
	const own = await post(bo, "/api/v1/members/bo/files", { ...(await bo.sealer.newFile("x.txt", "text/plain", newContentKey())).fields, size: "1", hash: "not sealed" }, await sealWith(await importContentKey(newContentKey()), enc.encode("x")));
	assert.equal(own.status, 400, "but a hash that IS sent must be sealed, in any area");

	console.log("ok  api:hashes — evidence refuses unsigned versions (whole, multipart, versions; no object left), records handed back sealed, a trusted signer verifies, moved/forged/mismatched/untrusted/stale each named, optional elsewhere");
} finally {
	await dev.close();
}
