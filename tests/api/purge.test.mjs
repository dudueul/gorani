// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:purge — Delete forever and Empty Trash (commit 39v).
 *
 * Asked for as "a right-click Delete forever, with a confirmation". The
 * Trash already purged itself after 30 days; this skips the wait — and with
 * it the one safety net a deletion had, so the team decided who may:
 *
 *   1. the owner, in their own area, and a lead; an analyst with a write
 *      grant on a case moves things to the Trash (a lead can still restore
 *      them), and nobody deletes in someone else's area;
 *   2. the preview — what the confirmation says — counts the files, the
 *      folders (each with everything beneath it) and the share links that
 *      would stop, and changes nothing;
 *   3. a file deleted forever leaves no row and no object: every version's
 *      bytes leave the bucket, its share links are revoked (a finished
 *      link's copy deleted, an unfinished one's upload aborted), the trail
 *      names who did it, and the change feed tells synced devices;
 *   4. a folder takes everything beneath it — a file trashed on its own
 *      from inside it too — and nothing beside it;
 *   5. Empty Trash takes exactly what the Trash holds;
 *   6. evidence is never deleted, and a legal hold deletes nothing.
 */

import assert from "node:assert/strict";
import { startDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { sealChunked, DEFAULT_CHUNK } from "../../web/src/vault/chunked-file.ts";
import { newShareId, newShareSecret, newShareKdf, shareKeys, sealShareMeta } from "../../web/src/vault/share-crypto.ts";
import { member, vouch, openCase, signedHash, signedIntake } from "../lib/team.mjs";

const dev = await startDev();
const enc = new TextEncoder();

/** A multipart form POST, as the browser sends an upload. */
async function form(who, path, fields, bytes) {
	const boundary = `p${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...bytes, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	const text = await r.text();
	assert.equal(r.status, 200, `${path}: ${text}`);
	return JSON.parse(text);
}

/** A whole-file upload into `base`; returns the file id. */
async function upload(who, base, sealer, name, { folder, evidence = false } = {}) {
	const ck = newContentKey();
	const f = await sealer.newFile(name, "text/plain", ck);
	const plain = enc.encode(`the bytes of ${name}`);
	const fields = { ...f.fields, size: String(plain.length), ...(folder ? { folder_id: folder } : {}), ...(evidence ? { hash: await signedHash(who, sealer, f.id, 1, plain), intake: await signedIntake(who, sealer, f.id) } : {}) };
	await form(who, `${base}/files`, fields, await sealWith(await importContentKey(ck), plain));
	return f.id;
}

/** Version 2 of a file, under its own content key. */
async function addVersion(who, base, sealer, id) {
	const ck = newContentKey();
	const plain = enc.encode("the second version");
	const fields = { ck: await sealer.fileKey(id, 2, ck), type: await sealer.fileType(id, 2, "text/plain"), size: String(plain.length), base_version: "1" };
	assert.equal((await form(who, `${base}/files/${id}/versions`, fields, await sealWith(await importContentKey(ck), plain))).version, 2);
}

/** A share link of a file; `finish: false` leaves its upload open, as a
 * closed tab would. */
async function share(who, sealer, fileId, { finish = true } = {}) {
	const id = newShareId();
	const kdf = newShareKdf();
	const keys = await shareKeys(id, newShareSecret(), "a-link-password-2026", kdf);
	const plain = enc.encode("the shared copy");
	const metaSealed = await sealShareMeta(keys.meta, id, { name: "shared.txt", type: "text/plain", size: plain.length, modified: null });
	const base = `/api/v1/members/${who.id}/files/shares`;
	const start = await api(dev.base, "POST", base, { email: who.email, body: { id, fileId, version: 1, nameSealed: await sealer.shareName(id, "shared.txt"), metaSealed, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), downloadsLeft: 3, size: plain.length, kdf } });
	assert.equal(start.status, 200, start.text);
	if (!finish) return id;
	const part = await fetch(`${dev.base}${base}/${id}/parts/1`, { method: "PUT", headers: { "x-gorani-dev-email": who.email, "content-type": "application/octet-stream" }, body: await sealChunked(keys.data, plain, DEFAULT_CHUNK) });
	assert.equal(part.status, 200);
	const { etag } = await part.json();
	assert.equal((await api(dev.base, "POST", `${base}/${id}/complete`, { email: who.email, body: { parts: [{ partNumber: 1, etag }], size: plain.length } })).status, 200);
	return id;
}

const keysUnder = async (prefix) => [...(await (await fetch(`${dev.s3}?list-type=2&prefix=${encodeURIComponent(prefix)}`)).text()).matchAll(/<Key>([^<]+)<\/Key>/g)].map((m) => m[1]);
const ids = (rows) => rows.map((r) => r.id);

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo]);
	const own = "/api/v1/members/bo";
	const as = (who, base) => (method, path, body) => api(dev.base, method, `${base}${path}`, { email: who.email, body });
	const boOwn = as(bo, own);

	// ── 1. Who may ────────────────────────────────────────────────────
	const kase = await openCase(dev, ana, "wk-purge", "Working notes", [[bo, "write"]]);
	const caseFile = await upload(bo, kase.base, kase.sealer, "case-note.txt");
	const byBo = await as(bo, kase.base)("POST", "/files/purge", { files: [caseFile] });
	assert.equal(byBo.status, 403, byBo.text);
	assert.match(byBo.json.error, /only a lead deletes forever in a case — Move to Trash instead/, "an analyst who writes on the case moves things to the Trash");
	assert.equal((await as(bo, kase.base)("DELETE", `/files/${caseFile}`)).status, 200, "…which still works for them");
	const anaArea = await as(bo, "/api/v1/members/ana")("POST", "/files/purge", { files: [caseFile] });
	assert.equal(anaArea.status, 403, "and nobody deletes in someone else's area");
	const byLead = await as(ana, kase.base)("POST", "/files/purge", { files: [caseFile] });
	assert.equal(byLead.status, 200, byLead.text);
	assert.equal(byLead.json.files, 1, "a lead deletes forever on the case — what the analyst trashed, too");
	assert.ok(!ids((await as(ana, kase.base)("GET", "/files/trash")).json.files).includes(caseFile), "…and it is not in the Trash");
	assert.deepEqual(await keysUnder(`cases/wk-purge/${caseFile}/`), [], "nor in the bucket");

	// ── 2. The preview, and 3. a file deleted forever ─────────────────
	const doomed = await upload(bo, own, bo.sealer, "doomed.txt");
	await addVersion(bo, own, bo.sealer, doomed);
	const neighbour = await upload(bo, own, bo.sealer, "neighbour.txt");
	const live = await share(bo, bo.sealer, doomed);
	const unfinished = await share(bo, bo.sealer, doomed, { finish: false });
	assert.equal((await keysUnder(`files/bo/${doomed}/`)).length, 2, "two versions, two objects");
	const preview = await boOwn("POST", "/files/purge", { files: [doomed], preview: true });
	assert.equal(preview.status, 200, preview.text);
	assert.deepEqual(preview.json, { files: 1, folders: 0, shares: 1 }, "the confirmation's numbers: one file, one working link (the unfinished one works for nobody yet)");
	assert.ok(ids((await boOwn("GET", "/files/list?folder=all")).json.files).includes(doomed), "a preview changes nothing");
	const since = (await boOwn("GET", "/files/changes?since=0")).json.cursor;

	const gone = await boOwn("POST", "/files/purge", { files: [doomed] });
	assert.equal(gone.status, 200, gone.text);
	assert.deepEqual([gone.json.files, gone.json.folders, gone.json.sharesRevoked], [1, 0, 2], "the file, and both its links revoked");
	assert.equal(gone.json.deletesPending, 0, "the storage confirmed every deletion");
	const listed = ids((await boOwn("GET", "/files/list?folder=all")).json.files);
	assert.ok(!listed.includes(doomed) && listed.includes(neighbour), "gone from the listing; its neighbour stays");
	assert.ok(!ids((await boOwn("GET", "/files/trash")).json.files).includes(doomed), "not in the Trash either");
	assert.deepEqual(await keysUnder(`files/bo/${doomed}/`), [], "both versions' bytes left the bucket");
	assert.equal((await keysUnder(`files/bo/${neighbour}/`)).length, 1, "the neighbour's did not");
	assert.ok(!(await keysUnder("shares/")).some((k) => k.includes(live)), "the link's sealed copy is deleted");
	const pending = (await boOwn("GET", "/storage/pending")).json.pending;
	assert.deepEqual(pending, [], `the unfinished link's upload was aborted, nothing left queued (${JSON.stringify(pending)})`);
	const shares = (await boOwn("GET", "/files/shares")).json;
	assert.ok([live, unfinished].every((id) => shares.find((s) => s.id === id)?.revoked), "both links read as revoked");
	assert.equal((await fetch(`${dev.base}/s/f/${live}/meta`)).status, 404, "the link no longer opens");
	const trail = (await boOwn("GET", "/audit")).json;
	assert.ok(trail.some((l) => l.action === "file.purge" && l.target === doomed), "the trail names the file");
	assert.ok(trail.some((l) => l.action === "files.purge" && l.target === "files:1,folders:0,sharesRevoked:2"), "…and what it came to");
	const feed = (await boOwn("GET", `/files/changes?since=${since}`)).json.changes;
	assert.ok(feed.some((c) => c.kind === "file.purge"), `a synced device hears of it (${feed.map((c) => c.kind)})`);
	const again = await boOwn("POST", "/files/purge", { files: [doomed] });
	assert.equal(again.status, 404, "deleting it again finds nothing");
	assert.match(again.json.error, /gone already/);

	// ── 4. A folder takes everything beneath it ───────────────────────
	const folder = async (id, name, parentId = null) => assert.equal((await boOwn("POST", "/files/folders", { id, name: await bo.sealer.folderName(id, name), parentId })).status, 200);
	await folder("pf-top", "Top");
	await folder("pf-sub", "Sub", "pf-top");
	await folder("pf-beside", "Beside");
	const inTop = await upload(bo, own, bo.sealer, "in-top.txt", { folder: "pf-top" });
	const inSub = await upload(bo, own, bo.sealer, "in-sub.txt", { folder: "pf-sub" });
	const trashedInside = await upload(bo, own, bo.sealer, "trashed-inside.txt", { folder: "pf-sub" });
	const beside = await upload(bo, own, bo.sealer, "beside.txt", { folder: "pf-beside" });
	assert.equal((await boOwn("DELETE", `/files/${trashedInside}`)).status, 200);
	assert.deepEqual((await boOwn("POST", "/files/purge", { folders: ["pf-top"], preview: true })).json, { files: 3, folders: 2, shares: 0 }, "the folder, its subfolder, and the three files beneath — the trashed one too");
	const tree = await boOwn("POST", "/files/purge", { folders: ["pf-top"] });
	assert.deepEqual([tree.json.files, tree.json.folders], [3, 2], tree.text);
	const after = await boOwn("GET", "/files/list?folder=all");
	assert.ok(!after.json.folders.some((f) => f.id === "pf-top" || f.id === "pf-sub") && after.json.folders.some((f) => f.id === "pf-beside"), "the folders are gone; the one beside stays");
	assert.ok(ids(after.json.files).includes(beside) && ![inTop, inSub].some((id) => ids(after.json.files).includes(id)), "…and so are the files that were in them");
	assert.ok(!ids((await boOwn("GET", "/files/trash")).json.files).includes(trashedInside), "the file trashed from inside went with its folder");
	assert.ok((await boOwn("GET", "/audit")).json.some((l) => l.action === "folder.purge" && l.target === "pf-top"));

	// ── 5. Empty Trash ────────────────────────────────────────────────
	const binned = await upload(bo, own, bo.sealer, "binned.txt");
	await folder("pf-binned", "Binned");
	assert.equal((await boOwn("DELETE", `/files/${binned}`)).status, 200);
	assert.equal((await boOwn("DELETE", "/files/folders/pf-binned")).status, 200);
	assert.deepEqual((await boOwn("POST", "/files/purge", { trash: true, preview: true })).json, { files: 1, folders: 1, shares: 0 }, "Empty Trash counts what the Trash holds");
	const emptied = await boOwn("POST", "/files/purge", { trash: true });
	assert.deepEqual([emptied.json.files, emptied.json.folders], [1, 1], emptied.text);
	const bin = (await boOwn("GET", "/files/trash")).json;
	assert.equal(bin.files.length + bin.folders.length, 0, "the Trash is empty");
	assert.ok(ids((await boOwn("GET", "/files/list?folder=all")).json.files).includes(neighbour), "and nothing living went with it");
	assert.ok((await boOwn("GET", "/audit")).json.some((l) => l.action === "trash.empty" && l.target === "files:1,folders:1,sharesRevoked:0"));
	assert.deepEqual((await boOwn("POST", "/files/purge", { trash: true })).json, { files: 0, folders: 0, shares: 0 }, "an empty Trash empties quietly");
	assert.equal((await boOwn("POST", "/files/purge", {})).status, 400, "naming nothing is a mistake, not Empty Trash");

	// ── 6. Evidence, and a legal hold ─────────────────────────────────
	const ev = await openCase(dev, ana, "ir-purge", "Evidence", [[bo, "write"]], "evidence");
	const item = await upload(bo, ev.base, ev.sealer, "exhibit.txt", { evidence: true });
	const refused = await as(ana, ev.base)("POST", "/files/purge", { files: [item] });
	assert.equal(refused.status, 409, refused.text);
	assert.match(refused.json.error, /evidence case: its files and folders are never deleted/, "not even a lead deletes evidence");
	assert.equal((await keysUnder(`cases/ir-purge/${item}/`)).length, 1, "its bytes stay");
	const held = await upload(ana, kase.base, kase.sealer, "held.txt");
	assert.equal((await api(dev.base, "POST", `${kase.base}/hold`, { email: ana.email, body: {} })).status, 200);
	const onHold = await as(ana, kase.base)("POST", "/files/purge", { files: [held] });
	assert.equal(onHold.status, 409, onHold.text);
	assert.match(onHold.json.error, /legal hold/, "a legal hold deletes nothing, forever or not");
	assert.equal((await as(ana, kase.base)("POST", "/files/purge", { trash: true })).status, 409, "…nor empties the Trash");

	console.log("ok  api:purge — the owner and a lead delete forever, an analyst on a case is sent to the Trash; the preview counts files, folders and working links and changes nothing; every version's bytes leave the bucket, links are revoked (copy deleted, open upload aborted), the trail and the change feed say so; a folder takes everything beneath it; Empty Trash takes the Trash only; evidence and a legal hold refuse");
} finally {
	await dev.close();
}
