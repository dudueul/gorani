// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:orphans — records that point at nothing (commit 39t, docs/ORPHANS.md).
 *
 * Asked for after the production 403s (39s): "if a record is orphaned —
 * no such folder and the like — remove it after checking S3 again". Each
 * kind is handled where it arises, and nothing is removed on one answer:
 *
 *   1. a folder that is gone (deleted, or in the Trash) takes no new file
 *      and no move: the server refuses with "no such folder" instead of
 *      storing a file no listing would ever show;
 *   2. a file whose bytes the storage does not have is checked twice — the
 *      object again, and other files of the same area — then a working
 *      file goes to the Trash, with the reason on its trail;
 *   3. when the storage has NONE of the area's files it is not this
 *      deployment's bucket: nothing is changed, and the reader is told;
 *   4. evidence is never moved: the loss is recorded, and it stays;
 *   5. a multipart upload the storage refused to start leaves no
 *      bookkeeping behind, and a part for an upload the storage no longer
 *      knows answers "no such upload" (the client then starts over).
 */

import assert from "node:assert/strict";
import { startDev, api, stubDelete, stubFault } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { member, vouch, openCase, signedHash, signedIntake } from "../lib/team.mjs";

// Object Lock off: the deployment default is "on", and then the stub (like
// a real locked bucket) refuses to delete an evidence object — this suite
// needs a storage that LOSES one, which a locked bucket would not.
const dev = await startDev({ vars: { OBJECT_LOCK: "off" } });
const enc = new TextEncoder();

/** A whole-file upload, as the browser makes it; returns the file id. */
async function upload(who, base, sealer, name, { folder, evidence = false } = {}) {
	const ck = newContentKey();
	const f = await sealer.newFile(name, "text/plain", ck);
	const plain = enc.encode(`the bytes of ${name}`);
	const fields = { ...f.fields, size: String(plain.length), ...(folder ? { folder_id: folder } : {}), ...(evidence ? { hash: await signedHash(who, sealer, f.id, 1, plain), intake: await signedIntake(who, sealer, f.id) } : {}) };
	const boundary = `o${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const sealed = await sealWith(await importContentKey(ck), plain);
	const r = await fetch(`${dev.base}${base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...sealed, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, text: await r.text(), id: f.id };
}
const keysUnder = async (prefix) => [...(await (await fetch(`${dev.s3}?list-type=2&prefix=${encodeURIComponent(prefix)}`)).text()).matchAll(/<Key>([^<]+)<\/Key>/g)].map((m) => m[1]);
const download = (who, base, id) => fetch(`${dev.base}${base}/files/${id}`, { headers: { "x-gorani-dev-email": who.email } });

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo]);
	const own = "/api/v1/members/bo";
	const call = (method, path, body) => api(dev.base, method, `${own}${path}`, { email: bo.email, body });

	// ── 1. A gone folder takes nothing ────────────────────────────────
	const folderId = "orphan-folder-1";
	assert.equal((await call("POST", "/files/folders", { id: folderId, name: await bo.sealer.folderName(folderId, "Gone soon"), parentId: null })).status, 200);
	const kept = await upload(bo, own, bo.sealer, "kept.txt");
	assert.equal(kept.status, 200, kept.text);
	assert.equal((await call("DELETE", `/files/folders/${folderId}`)).status, 200, "the folder goes to the Trash");
	const into = await upload(bo, own, bo.sealer, "into-gone.txt", { folder: folderId });
	assert.equal(into.status, 404, into.text);
	assert.match(JSON.parse(into.text).error, /no such folder: it was deleted or moved to the Trash/);
	assert.equal((await keysUnder(`files/bo/${into.id}/`)).length, 0, "…and its bytes were not left in the bucket");
	const moved = await call("PATCH", `/files/${kept.id}`, { folderId });
	assert.equal(moved.status, 404, moved.text);
	assert.match(moved.json.error, /no such folder/, "a move into it is refused the same way");
	const sub = await call("POST", "/files/folders", { id: "orphan-sub", name: await bo.sealer.folderName("orphan-sub", "Inside"), parentId: folderId });
	assert.equal(sub.status, 404, "…and so is a new folder inside it");

	// ── 2. Lost bytes: checked twice, then to the Trash ───────────────
	const second = await upload(bo, own, bo.sealer, "second.txt");
	const lost = await upload(bo, own, bo.sealer, "lost.txt");
	const [lostKey] = await keysUnder(`files/bo/${lost.id}/`);
	await stubDelete(dev, lostKey); // the storage loses it, behind the Worker's back
	const gone = await download(bo, own, lost.id);
	assert.equal(gone.status, 410, await gone.clone().text());
	assert.match((await gone.json()).error, /gone from the storage \(asked twice, while it answered for this area's other files\) — the file was moved to the Trash/);
	const listed = (await call("GET", "/files/list?folder=all")).json.files.map((f) => f.id);
	assert.ok(!listed.includes(lost.id) && listed.includes(second.id) && listed.includes(kept.id), "the lost file leaves the listing; the others stay");
	assert.ok((await call("GET", "/files/trash")).json.files.some((f) => f.id === lost.id), "…into the Trash, restorable should the bytes come back");
	const trail = (await call("GET", "/audit")).json.filter((l) => l.action === "file.lost" && l.target === lost.id);
	assert.equal(trail.length, 1, "the loss is on the trail");
	assert.match(trail[0].details ?? "", /asked twice/);

	// ── 3. Nothing of the area there: a wrong bucket, not a lost file ──
	for (const key of await keysUnder("files/bo/")) await stubDelete(dev, key);
	const none = await download(bo, own, second.id);
	assert.equal(none.status, 502, await none.clone().text());
	assert.match((await none.json()).error, /probably not this deployment's bucket .* nothing was changed/);
	assert.ok((await call("GET", "/files/list?folder=all")).json.files.some((f) => f.id === second.id), "nothing was trashed on a storage that has none of the area's files");

	// A storage that REFUSES (a 403) is not a missing file either: the
	// reader hears the refusal, and nothing moves.
	const refusedFile = await upload(bo, own, bo.sealer, "refused-read.txt");
	await stubFault(dev, { method: "GET", prefix: `files/bo/${refusedFile.id}/`, status: 403, count: 1, code: "AccessDenied" });
	const refusal = await download(bo, own, refusedFile.id);
	assert.equal(refusal.status, 502);
	assert.match((await refusal.json()).error, /the storage refused this read \(HTTP 403 AccessDenied\)/, "a refusal, not \"Not Found\"");

	// ── 4. Evidence is never moved ────────────────────────────────────
	const ev = await openCase(dev, ana, "ir-orphans", "Lost evidence", [[bo, "write"]], "evidence");
	const evA = await upload(bo, ev.base, ev.sealer, "image-a.E01", { evidence: true });
	const evB = await upload(bo, ev.base, ev.sealer, "image-b.E01", { evidence: true });
	assert.equal(evA.status, 200, evA.text);
	assert.equal(evB.status, 200, evB.text);
	const [evKey] = await keysUnder(`cases/ir-orphans/${evA.id}/`);
	await stubDelete(dev, evKey);
	const evGone = await download(bo, ev.base, evA.id);
	assert.equal(evGone.status, 410);
	assert.match((await evGone.json()).error, /it is evidence or under a hold, so it stays where it is; the loss is on its audit trail/);
	assert.ok((await api(dev.base, "GET", `${ev.base}/files/list?folder=all`, { email: bo.email })).json.files.some((f) => f.id === evA.id), "the evidence file is still listed");

	// ── 5. Upload leftovers ───────────────────────────────────────────
	const MiB = 1024 * 1024;
	await stubFault(dev, { method: "POST", prefix: "files/bo/", query: "uploads", status: 403, count: 1, code: "AccessDenied" });
	const refusedStart = await call("POST", "/files/uploads", { size: 6 * MiB, chunk: 5 * MiB, newFileId: "orphan-big-1" });
	assert.equal(refusedStart.status, 502, refusedStart.text);
	assert.match(refusedStart.json.error, /HTTP 403 AccessDenied/);
	assert.ok((await call("GET", "/audit")).json.some((l) => l.action === "file.uploadAbort"), "the refused start's bookkeeping went at once (not two days later)");
	// A part for a multipart upload the storage no longer knows.
	const started = await call("POST", "/files/uploads", { size: 6 * MiB, chunk: 5 * MiB, newFileId: "orphan-big-2" });
	assert.equal(started.status, 200, started.text);
	// The storage forgets it (an abort behind the Worker's back, or a
	// lifecycle rule): the stub numbers its multipart uploads upl-1, upl-2…
	for (let n = 1; n <= 5; n++) await fetch(`${dev.s3}/${started.json.key}?uploadId=upl-${n}`, { method: "DELETE" });
	const part = await fetch(`${dev.base}${own}/files/uploads/${started.json.uploadId}/1?key=${encodeURIComponent(started.json.key)}`, { method: "PUT", headers: { "x-gorani-dev-email": bo.email, "content-type": "application/octet-stream" }, body: new Uint8Array(5 * MiB + 28) });
	assert.equal(part.status, 404, await part.clone().text());
	assert.match((await part.json()).error, /no such upload/, "the client's cue to forget its resume record and start over");
	const again = await fetch(`${dev.base}${own}/files/uploads/${started.json.uploadId}/2?key=${encodeURIComponent(started.json.key)}`, { method: "PUT", headers: { "x-gorani-dev-email": bo.email, "content-type": "application/octet-stream" }, body: new Uint8Array(28) });
	assert.equal(again.status, 404, "…and its bookkeeping is gone with it");

	console.log("ok  api:orphans — a gone folder takes no file, move or subfolder (and leaves no bytes behind); lost bytes checked twice then a working file to the Trash, on its trail; none of the area's files there → nothing changed (a wrong bucket); a refused read is a refusal, not Not Found; lost evidence stays, recorded; a refused upload start leaves no bookkeeping; a part for an upload the storage forgot answers no such upload");
} finally {
	await dev.close();
}
