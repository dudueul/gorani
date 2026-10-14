// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:approvals — the two-person rule and the legal hold (commit 29f,
 * docs/CUSTODY.md › Stage 6, D5.7; worker/src/family/approvals.rs,
 * web/src/vault/approvals.ts). What it proves:
 *
 *   1. an evidence case does not close on one person's word: the direct
 *      close is refused and names the approval route; a working case still
 *      closes with one manager;
 *   2. a request is signed by whoever asks (a manager or a lead), one open
 *      request per case and action, and only for an action that is possible;
 *   3. the approver is a LEAD and NOT the requester; an approval runs the
 *      action once, in its own request, and a second approval is refused;
 *      both signatures verify for any reader who trusts the two people,
 *      and a record the server altered does not;
 *   4. an approver's client refuses to agree to a request whose signature
 *      does not verify (the server's word is not a request);
 *   5. a legal hold is placed by one person, and while it stands the case's
 *      store refuses trash and its housekeeping purges nothing — neither
 *      the trash nor old versions; it is lifted only by an approved
 *      `hold.release`, after which deletion works again;
 *   6. a withdrawn request cannot be approved; the nightly pass — which now
 *      tells each case store the registry's word on its hold before purging
 *      — keeps a held case held (a wrong word there would lift every hold
 *      every night).
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { approveRequest, requestApproval, verifyApproval } from "../../web/src/vault/approvals.ts";
import { member, vouch, openCase, trustOf, signedHash } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();

/** The API as a member's client calls it — failing loudly with the server's message. */
const callAs = (who) => async (method, path, body) => {
	const r = await api(dev.base, method, path, { email: who.email, body });
	if (r.status >= 300) throw new Error(`${r.status} ${r.json?.error ?? r.text}`);
	return r.json;
};
async function upload(who, kase, name, version = 1, fileId = null) {
	const plain = enc.encode(`${name} v${version}`);
	const ck = newContentKey();
	const id = fileId ?? kase.sealer.newId();
	const fields = version === 1
		? { file_id: id, name: await kase.sealer.fileName(id, name), type: await kase.sealer.fileType(id, 1, "text/plain"), ck: await kase.sealer.fileKey(id, 1, ck) }
		: { ck: await kase.sealer.fileKey(id, version, ck), type: await kase.sealer.fileType(id, version, "text/plain"), base_version: String(version - 1) };
	const boundary = `a${Math.random().toString(16).slice(2)}`;
	const all = { ...fields, size: String(plain.length), hash: await signedHash(who, kase.sealer, id, version, plain) };
	const head = enc.encode(Object.entries(all).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const path = version === 1 ? `${kase.base}/files` : `${kase.base}/files/${id}/versions`;
	const r = await fetch(`${dev.base}${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...(await sealWith(await importContentKey(ck), plain)), ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	assert.equal(r.status, 200, await r.text());
	return id;
}
const caseRow = async (who, id) => (await api(dev.base, "GET", "/api/v1/cases", { email: who.email })).json.cases.find((c) => c.id === id);

try {
	const ana = await member(dev, "ana", "lead");
	const lu = await member(dev, "lu", "lead", { by: ana });
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [lu, bo]);
	const ev = await openCase(dev, ana, "ir-two", "Two-person evidence", [[bo, "manage"]], "evidence");
	const wk = await openCase(dev, ana, "wk-hold", "Working notes under hold", [[bo, "write"]]);

	// ── 1. Evidence does not close on one person's word ────────────────
	const direct = await api(dev.base, "POST", `${ev.base}/close`, { email: ana.email, body: {} });
	assert.equal(direct.status, 409);
	assert.match(direct.json.error, /second lead's approval/);
	const scratch = await openCase(dev, ana, "wk-scratch", "Scratch", []);
	assert.equal((await api(dev.base, "POST", `${scratch.base}/close`, { email: ana.email, body: {} })).status, 200, "a working case still closes with one manager");

	// ── 2. Asking ──────────────────────────────────────────────────────
	const asBo = callAs(bo);
	await assert.rejects(requestApproval(asBo, bo.signer, "ir-two", "hold.release"), /not on hold/, "only a possible action can be asked for");
	const closeReq = await requestApproval(asBo, bo.signer, "ir-two", "case.close");
	assert.equal(closeReq.status, "pending");
	assert.equal(closeReq.requestedBy, "bo", "a manager of the case may ask (bo is an analyst)");
	await assert.rejects(requestApproval(asBo, bo.signer, "ir-two", "case.close"), /already waiting/, "one open request per case and action");
	const outsider = await member(dev, "dee", "analyst", { by: ana });
	await assert.rejects(requestApproval(callAs(outsider), outsider.signer, "ir-two", "case.close"), /only a manager of the case, or a lead/);

	// ── 3. Agreeing ────────────────────────────────────────────────────
	const pending = (await asBo("GET", `${ev.base}/approvals`)).approvals;
	assert.equal(pending.length, 1);
	const approveRaw = (who, a, signature) => api(dev.base, "POST", `${ev.base}/approvals/${a.id}/approve`, { email: who.email, body: { signature } });
	assert.equal((await approveRaw(bo, closeReq, "AAAA")).status, 403, "the approver is a lead");
	const anaTrust = await trustOf(dev, ana);
	const done = await approveRequest(callAs(ana), ana.signer, anaTrust, pending[0]);
	assert.equal(done.executed, "case.close");
	assert.equal((await caseRow(ana, "ir-two")).closed, true, "the action ran, in the approval's own request");
	assert.equal((await approveRaw(lu, done.approval, "AAAA")).status, 409, "…once");
	const record = (await asBo("GET", `${ev.base}/approvals`)).approvals[0];
	assert.deepEqual([record.status, record.requestedBy, record.approvedBy], ["approved", "bo", "ana"]);
	const luTrust = await trustOf(dev, lu);
	assert.deepEqual(await verifyApproval(luTrust, record), { request: true, approve: true }, "both signatures verify for a third reader");
	assert.deepEqual(await verifyApproval(luTrust, { ...record, approvedBy: "lu" }), { request: true, approve: false }, "a record naming another approver does not");
	assert.deepEqual(await verifyApproval(luTrust, { ...record, action: "hold.release" }), { request: false, approve: false }, "nor one naming another action");
	const audit = (await api(dev.base, "GET", "/api/v1/family", { email: ana.email })).json.audit;
	assert.ok(audit.some((l) => l.action === "approval.approve" && l.target === "ir-two") && audit.some((l) => l.action === "case.close" && l.target === "ir-two"), "the registry's trail has both");

	// A hold is placed by a manager of the case or a lead — not by any writer.
	const hold = await api(dev.base, "POST", `${wk.base}/hold`, { email: bo.email, body: {} });
	assert.equal(hold.status, 403, "bo writes on wk-hold but does not manage it: no hold from bo");

	// ── 5. The legal hold ──────────────────────────────────────────────
	// Before it: a trashed file and an old version, both due for purging.
	const trashed = await upload(bo, wk, "draft.txt");
	const kept = await upload(bo, wk, "timeline.txt");
	await upload(bo, wk, "timeline.txt", 2, kept);
	assert.equal((await api(dev.base, "DELETE", `${wk.base}/files/${trashed}`, { email: bo.email })).status, 200, "(trashed before the hold)");
	assert.equal((await api(dev.base, "POST", `${wk.base}/hold`, { email: ana.email, body: {} })).status, 200, "one person places a hold");
	assert.ok((await caseRow(ana, "wk-hold")).hold, "the registry has it");
	const refused = await api(dev.base, "DELETE", `${wk.base}/files/${kept}`, { email: bo.email });
	assert.equal(refused.status, 409);
	assert.match(refused.json.error, /legal hold/);
	const hk = (await api(dev.base, "POST", `${wk.base}/housekeeping`, { email: ana.email, body: { trashDays: 0, versionDays: 0 } })).json;
	assert.deepEqual([hk.held, hk.purgedFiles, hk.versionsPruned], [true, 0, 0], "a held store purges nothing — not the trash, not old versions");
	// Lifting it takes two: ana asks, ana cannot agree, lu agrees.
	const release = await requestApproval(callAs(ana), ana.signer, "wk-hold", "hold.release");
	await assert.rejects(approveRequest(callAs(ana), ana.signer, anaTrust, release), /different lead/, "not the requester (the client says so)");
	assert.equal((await api(dev.base, "POST", `${wk.base}/approvals/${release.id}/approve`, { email: ana.email, body: { signature: "AAAA" } })).status, 403, "…and the server too");
	// ── 4. An approver's client refuses a request whose signature fails ──
	await assert.rejects(approveRequest(callAs(lu), lu.signer, luTrust, { ...release, requestedBy: "bo" }), /did not ask for this/, "the server's word is not a request");
	const lifted = await approveRequest(callAs(lu), lu.signer, luTrust, release);
	assert.equal(lifted.executed, "hold.release");
	assert.ok(!(await caseRow(ana, "wk-hold")).hold);
	assert.equal((await api(dev.base, "DELETE", `${wk.base}/files/${kept}`, { email: bo.email })).status, 200, "deletion works again once two people lifted the hold");
	const after = (await api(dev.base, "POST", `${wk.base}/housekeeping`, { email: ana.email, body: { trashDays: 0, versionDays: 0 } })).json;
	assert.equal(after.held, false);
	assert.ok(after.purgedFiles >= 1, `…and the purge resumes: ${JSON.stringify(after)}`);

	// ── 6. Withdrawn; and the nightly reconciliation ───────────────────
	assert.equal((await api(dev.base, "POST", `${wk.base}/hold`, { email: ana.email, body: {} })).status, 200);
	const again = await requestApproval(callAs(ana), ana.signer, "wk-hold", "hold.release");
	assert.equal((await api(dev.base, "DELETE", `${wk.base}/approvals/${again.id}`, { email: bo.email })).status, 403, "only the requester or a lead withdraws");
	assert.equal((await api(dev.base, "DELETE", `${wk.base}/approvals/${again.id}`, { email: ana.email })).status, 200);
	await assert.rejects(approveRequest(callAs(lu), lu.signer, luTrust, again), /cancelled/, "a withdrawn request cannot be approved");
	const late = await upload(bo, wk, "late.txt");
	assert.equal((await api(dev.base, "DELETE", `${wk.base}/files/${late}`, { email: bo.email })).status, 409, "(held)");
	assert.equal((await fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`)).status, 200);
	assert.equal((await api(dev.base, "DELETE", `${wk.base}/files/${late}`, { email: bo.email })).status, 409, "after the nightly pass: still held, as the registry says");
	// (A store whose copy drifted from the registry — a lost `case-hold`
	// call — is set back by the same pass; no public route can make one
	// drift, which is the point, so this suite cannot stage it.)

	console.log("ok  api:approvals — evidence closes only with a second lead, signed requests and approvals verify for a third reader, the hold placed by one and lifted by two, a held store purges nothing, withdrawals, the nightly pass keeps holds");
} finally {
	await dev.close();
}
