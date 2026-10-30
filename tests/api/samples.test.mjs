// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:samples — malware samples, the server's half (commit 29e,
 * docs/CUSTODY.md › Stage 5, D8; the client's half — never rendered, the
 * "infected" zip, copies stay samples — is unit:explorer). What it proves:
 *
 *   1. an upload with `sample=1` is listed as a sample (with the key too,
 *      for the clients that decide what to render) and audited as one;
 *   2. a sample is never shared by link;
 *   3. marking is ONE WAY and COMPLETE: `sample: false` is refused; a mark
 *      without every version's re-sealed type, with a version the file does
 *      not have, or with a type that is not sealed text is refused and
 *      changes nothing; a complete mark sets the flag, stores the sealed
 *      types, and is audited;
 *   4. the per-file version walk the mark uses lists only that file;
 *   5. on a case: samples and evidence combine (signed, then marked), and
 *      a read-only grantee cannot mark;
 *   6. an inspection (commit 42g) is on the record before the bytes are
 *      opened: the line names the version and that it was a sample; an
 *      entry inside it rides sealed (plain text is refused); a version
 *      the file does not have, a file that is not there, and another
 *      member's area are refused; on a case, a read grant is enough.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, openPlacedText, sealPlacedText } from "../../web/src/vault/vault-crypto.ts";
import { places } from "../../web/src/vault/places.ts";
import { isSampleType, originalType, sampleType } from "../../web/src/vault/samples.ts";
import { newShareId, newShareSecret, shareKeys, sealShareMeta, newShareKdf } from "../../web/src/vault/share-crypto.ts";
import { member, vouch, openCase, signedHash, signedIntake } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();

async function post(who, path, fields, file) {
	const boundary = `s${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, json: await r.json().catch(() => null) };
}
/** A new file in `base`, sealed by `sealer`; `type` is the sealed type's
 * text. `extra(id, plain)` adds form fields that need the id (a signature). */
async function put(who, base, sealer, name, type, extra = () => ({})) {
	const plain = enc.encode(`bytes of ${name}`);
	const ck = newContentKey();
	const id = sealer.newId();
	const fields = { file_id: id, name: await sealer.fileName(id, name), type: await sealer.fileType(id, 1, type), ck: await sealer.fileKey(id, 1, ck), size: String(plain.length), ...(await extra(id, plain)) };
	const r = await post(who, `${base}/files`, fields, await sealWith(await importContentKey(ck), plain));
	assert.equal(r.status, 200, JSON.stringify(r.json));
	return { id, plain };
}
const listed = async (who, base) => (await api(dev.base, "GET", `${base}/files/list?folder=all`, { email: who.email })).json.files;
const audit = async (who, base) => (await api(dev.base, "GET", `${base}/audit`, { email: who.email })).json;
async function shareOf(who, base, sealer, fileId, size) {
	const shareId = newShareId();
	const kdf = newShareKdf();
	const keys = await shareKeys(shareId, newShareSecret(), "suite-password", kdf);
	return api(dev.base, "POST", `${base}/files/shares`, { email: who.email, body: { id: shareId, fileId, version: 1, nameSealed: await sealer.shareName(shareId, "x"), metaSealed: await sealShareMeta(keys.meta, shareId, { name: "x", type: "application/octet-stream", size, modified: null }), expiresAt: new Date(Date.now() + 3600_000).toISOString(), downloadsLeft: 1, size, kdf } });
}

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const cy = await member(dev, "cy", "analyst", { by: ana });
	await vouch(dev, ana, [bo, cy]);
	const own = "/api/v1/members/bo";

	// ── 1. Uploaded as a sample ─────────────────────────────────────────
	const s1 = await put(bo, own, bo.sealer, "invoice.pdf.exe", sampleType("application/x-msdownload"), () => ({ sample: "1" }));
	const normal = await put(bo, own, bo.sealer, "notes.txt", "text/plain");
	const rows = await listed(bo, own);
	assert.equal(rows.find((f) => f.id === s1.id).sample, true, "listed as a sample");
	assert.equal(rows.find((f) => f.id === normal.id).sample, false);
	const keyed = (await api(dev.base, "POST", `${own}/files/keys`, { email: bo.email, body: { ids: [s1.id] } })).json.keys[s1.id];
	assert.equal(keyed.sample, true, "the flag rides with the key, where clients decide what to render");
	const opened = await openPlacedText(bo.sealer.priv, places.fileType("bo", s1.id, 1), keyed.type);
	assert.ok(isSampleType(opened) && originalType(opened) === "application/x-msdownload", "the sealed type carries the client's own mark and the original");
	assert.ok((await audit(bo, own)).some((l) => l.action === "file.upload.sample" && l.target === s1.id), "audited as a sample upload");

	// ── 2. Never shared by link ─────────────────────────────────────────
	const link = await shareOf(bo, own, bo.sealer, s1.id, s1.plain.length);
	assert.equal(link.status, 409);
	assert.match(link.json.error, /never shared by link/);
	assert.equal((await shareOf(bo, own, bo.sealer, normal.id, normal.plain.length)).status, 200, "(a normal file still shares)");

	// ── 3. One way, and complete ────────────────────────────────────────
	// A second version first, so "every version" means two.
	const ck2 = newContentKey();
	const v2plain = enc.encode("notes, v2");
	assert.equal((await post(bo, `${own}/files/${normal.id}/versions`, { ck: await bo.sealer.fileKey(normal.id, 2, ck2), type: await bo.sealer.fileType(normal.id, 2, "text/plain"), size: String(v2plain.length), base_version: "1" }, await sealWith(await importContentKey(ck2), v2plain))).status, 200);
	const patch = (body, who = bo) => api(dev.base, "PATCH", `${own}/files/${normal.id}`, { email: who.email, body });
	const t1 = await bo.sealer.fileType(normal.id, 1, sampleType("text/plain"));
	const t2 = await bo.sealer.fileType(normal.id, 2, sampleType("text/plain"));
	assert.equal((await api(dev.base, "PATCH", `${own}/files/${s1.id}`, { email: bo.email, body: { sample: false } })).status, 400, "a sample is never unmarked");
	const partial = await patch({ sample: true, types: { 1: t1 } });
	assert.equal(partial.status, 400);
	assert.match(partial.json.error, /version 2 is missing/, "every version's type, or no mark");
	assert.equal((await patch({ sample: true, types: { 1: t1, 2: t2, 3: t2 } })).status, 400, "…and no version the file does not have");
	assert.equal((await patch({ sample: true, types: { 1: t1, 2: "application/x-gorani-sample" } })).status, 400, "…and only sealed types");
	assert.equal((await listed(bo, own)).find((f) => f.id === normal.id).sample, false, "a refused mark changed nothing");
	const marked = await patch({ sample: true, types: { 1: t1, 2: t2 } });
	assert.equal(marked.status, 200, marked.text);
	assert.equal(marked.json.sample, true);
	const walk = (await api(dev.base, "GET", `${own}/files/sealed?kind=version&file=${normal.id}&after=0&limit=10`, { email: bo.email })).json.items;
	// ── 4. The per-file walk lists only that file ─────────────────────
	assert.deepEqual(walk.map((v) => [v.a, v.b]), [[normal.id, "1"], [normal.id, "2"]], "only this file's versions");
	assert.deepEqual(walk.map((v) => v.v2), [t1, t2], "both types now carry the mark, as sealed by the client");
	assert.ok((await audit(bo, own)).some((l) => l.action === "file.sample" && l.target === normal.id), "the mark is audited");
	assert.equal((await shareOf(bo, own, bo.sealer, normal.id, v2plain.length)).status, 409, "a marked file is not linked either");

	// ── 5. On a case: with evidence, and by permission ──────────────────
	const ev = await openCase(dev, ana, "ir-sample", "Phishing kit", [[bo, "write"], [cy, "read"]], "evidence");
	// Evidence needs each version signed (stage 4); a sample is no exception.
	// (…and, since 29g, each new evidence file its intake record.)
	const signed = (sample) => async (id, plain) => ({ ...(sample ? { sample: "1" } : {}), hash: await signedHash(bo, ev.sealer, id, 1, plain), intake: await signedIntake(bo, ev.sealer, id) });
	const kit = await put(bo, ev.base, ev.sealer, "kit.zip", sampleType("application/zip"), signed(true));
	assert.equal((await listed(bo, ev.base)).find((f) => f.id === kit.id).sample, true, "a signed sample in an evidence case");
	const { id: emlId } = await put(bo, ev.base, ev.sealer, "mail.eml", "message/rfc822", signed(false));
	const caseMark = { sample: true, types: { 1: await ev.sealer.fileType(emlId, 1, sampleType("message/rfc822")) } };
	assert.equal((await api(dev.base, "PATCH", `${ev.base}/files/${emlId}`, { email: cy.email, body: caseMark })).status, 403, "a read-only grantee cannot mark");
	assert.equal((await api(dev.base, "PATCH", `${ev.base}/files/${emlId}`, { email: bo.email, body: caseMark })).status, 200, "a writer can — evidence stays evidence, and becomes a sample");
	assert.equal((await api(dev.base, "DELETE", `${ev.base}/files/${emlId}`, { email: bo.email })).status, 409, "(still never trashed)");

	// ── 6. Inspected (42g): on the record before the bytes are opened ───
	const inspect = (who, base, id, body = {}) => api(dev.base, "POST", `${base}/files/${id}/inspect`, { email: who.email, body });
	let seen = await inspect(bo, own, s1.id, { version: 1 });
	assert.equal(seen.status, 200, seen.text);
	assert.deepEqual(seen.json, { inspected: s1.id, version: 1, sample: true });
	let line = (await audit(bo, own)).find((l) => l.action === "file.inspect" && l.target === s1.id);
	assert.ok(line, "the inspection is audited");
	assert.equal(line.details, "version 1, a malware sample, in the hex view");
	assert.equal(line.actor, bo.email);
	assert.equal((await inspect(bo, own, s1.id, { version: 9 })).status, 404, "a version the file does not have");
	assert.equal((await inspect(bo, own, "f-not-there")).status, 404);
	assert.equal((await inspect(cy, own, s1.id)).status, 403, "another member's area: not theirs to look into");
	assert.equal((await inspect(bo, own, s1.id, { entry: "payload.exe" })).status, 400, "an entry's name in plain text is refused: the server is not to read it");
	const entry = await sealPlacedText(bo.sealer.priv, places.fileInspected("bo", s1.id, 1), "payload.exe");
	assert.equal((await inspect(bo, own, s1.id, { entry })).status, 200, "(no version: the current one)");
	line = (await audit(bo, own)).find((l) => l.action === "file.inspect" && l.target === s1.id && l.detailsSealed);
	assert.equal(line.details, "an entry inside version 1 of a malware sample (its name sealed), in the hex view");
	assert.equal(await openPlacedText(bo.sealer.priv, places.fileInspected("bo", s1.id, 1), line.detailsSealed), "payload.exe", "the name, sealed to the area: its members read it, the server does not");
	seen = await inspect(cy, ev.base, kit.id, { version: 1 });
	assert.equal(seen.status, 200, `a read-only grantee inspects too — inspecting is reading: ${seen.text}`);
	assert.ok((await audit(ana, ev.base)).some((l) => l.action === "file.inspect" && l.target === kit.id && l.actor === cy.email), "…on the case's trail, under their name");

	console.log("ok  api:samples — uploaded as a sample (listed, keyed, audited), never linked, marking one way and complete, the per-file walk, samples on evidence, read-only cannot mark, an inspection on the record before the bytes (its entry sealed, a read grant enough)");
} finally {
	await dev.close();
}
