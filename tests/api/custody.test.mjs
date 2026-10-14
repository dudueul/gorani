// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:custody — intake records and custody transfers (commit 29g,
 * docs/CUSTODY.md › Stage 6, D5.6; worker/src/custody.rs,
 * web/src/vault/intake.ts and custody.ts). What it proves:
 *
 *   1. an evidence file needs its intake record — sealed (a readable one is
 *      refused), signed by the uploader; a reader who trusts the uploader
 *      verifies it, and a record moved to another file does not open there;
 *      a later VERSION needs no new intake (an item is acquired once);
 *   2. custody starts with the uploader; only the custodian offers, links
 *      are numbered with no gap, one offer is open at a time, only the
 *      person named accepts — a READ-ONLY grantee too (custody is a record
 *      of responsibility, not access); the offerer may withdraw;
 *   3. the chain verifies link by link for any reader, and a chain the
 *      server altered (a receiver swapped, a forged acceptance) does not;
 *   4. custody is kept for evidence only;
 *   5. a case rotation re-seals the intake records and the custody reasons,
 *      and both still verify under the new key;
 *   6. a backup of the case carries the intake record and every link.
 */

import assert from "node:assert/strict";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith, generateHybridKey } from "../../web/src/vault/vault-crypto.ts";
import { signIntake, checkIntake } from "../../web/src/vault/intake.ts";
import { offerCustody, acceptCustody, verifyChain } from "../../web/src/vault/custody.ts";
import { rotateCase } from "../../web/src/vault/cases.ts";
import { readBackup } from "../../web/src/vault/backup.ts";
import { toBase64 } from "../../web/src/lib/encoding.ts";
import { member, vouch, openCase, trustOf, signedHash } from "../lib/team.mjs";

const dev = await suiteDev();
const enc = new TextEncoder();

const callAs = (who) => async (method, path, body) => {
	const r = await api(dev.base, method, path, { email: who.email, body });
	if (r.status >= 300) throw new Error(`${r.status} ${r.json?.error ?? r.text}`);
	return r.json;
};
async function post(who, path, fields, file) {
	const boundary = `k${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${path}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { status: r.status, json: await r.json().catch(() => null) };
}
const INTAKE = { source: "laptop WS-042, disk 0", collector: "bo", method: "FTK Imager 4.7, E01, write-blocked", collectedAt: "2026-10-14T09:12:00Z", notes: "seized at the desk, powered off" };

try {
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const cy = await member(dev, "cy", "analyst", { by: ana });
	const dee = await member(dev, "dee", "analyst", { by: ana });
	await vouch(dev, ana, [bo, cy, dee]);
	const ev = await openCase(dev, ana, "ir-cust", "Custody", [[bo, "write"], [cy, "read"], [dee, "write"]], "evidence");
	const wk = await openCase(dev, ana, "wk-cust", "Working", [[bo, "write"]]);

	// ── 1. Intake ──────────────────────────────────────────────────────
	const plain = enc.encode("the disk image");
	const ck = newContentKey();
	const f = await ev.sealer.newFile("WS-042.E01", "application/octet-stream", ck);
	const sealed = await sealWith(await importContentKey(ck), plain);
	const base = { ...f.fields, size: String(plain.length), hash: await signedHash(bo, ev.sealer, f.id, 1, plain) };
	const none = await post(bo, `${ev.base}/files`, base, sealed);
	assert.equal(none.status, 400);
	assert.match(none.json.error, /intake record/);
	assert.equal((await post(bo, `${ev.base}/files`, { ...base, intake: JSON.stringify(INTAKE) }, sealed)).status, 400, "a readable intake record is refused: it names hosts and people");
	const intake = await signIntake(bo.signer, ev.sealer.priv, ev.area, f.id, INTAKE);
	const up = await post(bo, `${ev.base}/files`, { ...base, intake }, sealed);
	assert.equal(up.status, 200, JSON.stringify(up.json));
	const keyed = (await api(dev.base, "POST", `${ev.base}/files/keys`, { email: cy.email, body: { ids: [f.id] } })).json.keys[f.id];
	assert.equal(keyed.intake, intake, "with the key, as sealed");
	const cyTrust = await trustOf(dev, cy);
	const checked = await checkIntake(ev.sealer.priv, cyTrust, ev.area, f.id, keyed.intake);
	assert.equal(checked.status, "verified", JSON.stringify(checked));
	assert.deepEqual({ source: checked.record.source, method: checked.record.method, signer: checked.signer }, { source: INTAKE.source, method: INTAKE.method, signer: "bo" });
	assert.equal((await checkIntake(ev.sealer.priv, cyTrust, ev.area, "another-file-id-xyz", keyed.intake)).status, "invalid", "a record moved to another file does not open there");
	// A later version: its own hash, no new intake.
	const ck2 = newContentKey();
	const v2 = enc.encode("the disk image, re-exported");
	const ver = await post(bo, `${ev.base}/files/${f.id}/versions`, { ck: await ev.sealer.fileKey(f.id, 2, ck2), type: await ev.sealer.fileType(f.id, 2, "application/octet-stream"), size: String(v2.length), base_version: "1", hash: await signedHash(bo, ev.sealer, f.id, 2, v2) }, await sealWith(await importContentKey(ck2), v2));
	assert.equal(ver.status, 200, "an item is acquired once: versions carry hashes, not intake");

	// ── 2. Custody ─────────────────────────────────────────────────────
	const chainOf = async (who = bo) => (await api(dev.base, "GET", `${ev.base}/files/${f.id}/custody`, { email: who.email })).json;
	let chain = await chainOf();
	assert.deepEqual([chain.owner, chain.custodian, chain.entries.length], ["bo", "bo", 0], "custody starts with the uploader");
	await assert.rejects(offerCustody(callAs(cy), cy.signer, ev.sealer.priv, ev.base, ev.area, f.id, chain, "dee", "not mine to give"), /only the current custodian/);
	await assert.rejects(offerCustody(callAs(bo), bo.signer, ev.sealer.priv, ev.base, ev.area, f.id, { ...chain, entries: [{}] }, "cy", "skip a number"), /link 1 of the chain/, "links are numbered, with no gap");
	await offerCustody(callAs(bo), bo.signer, ev.sealer.priv, ev.base, ev.area, f.id, chain, "cy", "to the lab for imaging review");
	chain = await chainOf();
	await assert.rejects(offerCustody(callAs(bo), bo.signer, ev.sealer.priv, ev.base, ev.area, f.id, chain, "dee", "a second offer"), /already open/, "one open offer at a time");
	const anaTrust = await trustOf(dev, ana);
	await assert.rejects(acceptCustody(callAs(dee), dee.signer, await trustOf(dev, dee), ev.sealer.priv, ev.base, ev.area, f.id, chain.entries[0]), /not made to you/, "dee's client will not accept cy's offer…");
	const stolen = await api(dev.base, "POST", `${ev.base}/files/${f.id}/custody/1/accept`, { email: dee.email, body: { signature: chain.entries[0].offerSignature } });
	assert.equal(stolen.status, 403, "…and the server refuses it from dee whatever the body says (it checks who is calling)");
	await acceptCustody(callAs(cy), cy.signer, cyTrust, ev.sealer.priv, ev.base, ev.area, f.id, chain.entries[0]);
	chain = await chainOf(cy);
	assert.equal(chain.custodian, "cy", "a READ-ONLY grantee holds custody: a record of responsibility, not access");
	// cy hands it on — withdraws — and hands it on again.
	await offerCustody(callAs(cy), cy.signer, ev.sealer.priv, ev.base, ev.area, f.id, chain, "dee", "wrong person");
	chain = await chainOf(cy);
	assert.equal((await api(dev.base, "POST", `${ev.base}/files/${f.id}/custody/2/cancel`, { email: dee.email, body: {} })).status, 403, "only the offerer withdraws");
	assert.equal((await api(dev.base, "POST", `${ev.base}/files/${f.id}/custody/2/cancel`, { email: cy.email, body: {} })).status, 200);
	chain = await chainOf(cy);
	await offerCustody(callAs(cy), cy.signer, ev.sealer.priv, ev.base, ev.area, f.id, chain, "dee", "to the analyst on shift");
	chain = await chainOf(cy);
	await acceptCustody(callAs(dee), dee.signer, await trustOf(dev, dee), ev.sealer.priv, ev.base, ev.area, f.id, chain.entries[2]);
	chain = await chainOf(dee);

	// ── 3. The chain verifies — and an altered one does not ─────────────
	const verified = await verifyChain(ev.sealer.priv, anaTrust, ev.area, f.id, chain);
	assert.equal(verified.ok, true, JSON.stringify(verified));
	assert.equal(verified.custodian, "dee");
	assert.deepEqual(verified.links.map((l) => [l.seq, l.from, l.to, l.reason]), [[1, "bo", "cy", "to the lab for imaging review"], [3, "cy", "dee", "to the analyst on shift"]], "the withdrawn link is not in the chain; the reasons open");
	const swapped = { ...chain, entries: chain.entries.map((e) => (e.seq === 1 ? { ...e, to: "dee" } : e)) };
	assert.equal((await verifyChain(ev.sealer.priv, anaTrust, ev.area, f.id, swapped)).ok, false, "a receiver the server swapped breaks the chain");
	const forged = { ...chain, entries: chain.entries.map((e) => (e.seq === 3 ? { ...e, acceptSignature: chain.entries[0].acceptSignature } : e)) };
	assert.equal((await verifyChain(ev.sealer.priv, anaTrust, ev.area, f.id, forged)).ok, false, "an acceptance moved from another link does not verify");

	// ── 4. Evidence only ───────────────────────────────────────────────
	const wck = newContentKey();
	const wf = await wk.sealer.newFile("notes.md", "text/markdown", wck);
	assert.equal((await post(bo, `${wk.base}/files`, { ...wf.fields, size: "2" }, await sealWith(await importContentKey(wck), enc.encode("hi")))).status, 200, "(no intake needed outside evidence)");
	assert.equal((await api(dev.base, "GET", `${wk.base}/files/${wf.id}/custody`, { email: bo.email })).status, 409, "custody is kept for evidence");

	// ── 5. A rotation re-seals intake and custody reasons ──────────────
	const row = async () => (await api(dev.base, "GET", "/api/v1/cases", { email: ana.email })).json.cases.find((c) => c.id === "ir-cust");
	const roots = await Promise.all((await row()).grantees.map(async (g) => (await api(dev.base, "GET", `/api/v1/members/${g.member}/root`, { email: ana.email })).json));
	const rotated = await rotateCase(callAs(ana), ana.root, await row(), roots, ana.signer, anaTrust);
	assert.equal(rotated.report.resealed.intake, 1);
	assert.equal(rotated.report.resealed.custody, 3, "every link's reason, the withdrawn one too");
	const after = (await api(dev.base, "POST", `${ev.base}/files/keys`, { email: ana.email, body: { ids: [f.id] } })).json.keys[f.id];
	assert.equal((await checkIntake(rotated.key, anaTrust, ev.area, f.id, after.intake)).status, "verified", "the intake still verifies, under the new key");
	assert.equal((await verifyChain(rotated.key, anaTrust, ev.area, f.id, await chainOf(ana))).ok, true, "…and so does the chain");

	// ── 6. A backup carries both ────────────────────────────────────────
	const backup = await generateHybridKey();
	const keyFile = { type: "gorani-backup-key", v: 1, keyId: backup.keyId, createdAt: new Date().toISOString(), key: toBase64(backup.bundle) };
	assert.equal((await api(dev.base, "PUT", `${ev.base}/backup-key`, { email: ana.email, body: { keyId: backup.keyId, publicKey: backup.publicKey, pqPublicKey: backup.pqPublicKey } })).status, 200);
	const run = await api(dev.base, "POST", `${ev.base}/backup/run`, { email: ana.email, body: {} });
	assert.equal(run.status, 200, JSON.stringify(run.json));
	const bytes = new Uint8Array(await (await fetch(`${dev.base}${ev.base}/backups/${run.json.stamp}`, { headers: { "x-gorani-dev-email": ana.email } })).arrayBuffer());
	const parsed = await readBackup(bytes, keyFile);
	const fileEntry = parsed.entries.find((e) => e.json.kind === "file" && e.json.id === f.id);
	assert.match(String(fileEntry?.json.intake), /^GV04:/, "the file entry carries its intake record, sealed");
	assert.deepEqual(parsed.entries.filter((e) => e.json.kind === "custody").map((e) => e.json.seq), [1, 2, 3], "every link, with its signatures");

	console.log("ok  api:custody — intake required on evidence (sealed, signed, verified, bound to its file), custody offered by the custodian and accepted by the receiver (read-only too), withdrawals, the chain verified and an altered one refused, evidence only, rotation and backups carry both");
} finally {
	await dev.close();
}
