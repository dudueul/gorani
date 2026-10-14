// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:timestamps — RFC 3161 trusted timestamps (commit 29j, docs/CUSTODY.md ›
 * Stage 7, D5.5; worker/src/tsa.rs, stamps.rs, family/tsa_certs.rs,
 * web/src/vault/timestamp.ts). Its own server, with TSA_URL pointing at
 * OpenSSL's own TSA behind HTTP (tests/lib/tsa-stub.mjs). What it proves:
 *
 *   1. a lead reads the TSA's certificate from a probe and certifies its
 *      key — the fingerprint is the one OpenSSL prints; only a lead may;
 *   2. an evidence upload's imprint (SHA-256 of the uploader's signature)
 *      is stamped by the store's alarm, no request waiting; the reader's
 *      check says verified, through ITS trust in the certifying lead;
 *   3. a TSA that is down loses nothing: the alarm backs off and stamps it;
 *   4. a token moved to another version is refused by name; a withdrawn
 *      TSA key turns its tokens "uncertified";
 *   5. a version recorded without an imprint gets one from re-verification
 *      (once — an imprint is never replaced), and is stamped;
 *   6. the nightly checkpoint is stamped too, over its exact bytes;
 *   7. the export carries all of it, and tools/verify-export.mjs — with its
 *      own DER walk and Node's X.509 parser — checks every token.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startDev, api } from "./_dev.mjs";
import { startTsaStub } from "../lib/tsa-stub.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { openContentHash } from "../../web/src/vault/content-hash.ts";
import { approveRequest, requestApproval } from "../../web/src/vault/approvals.ts";
import { buildExport, reverifyCase } from "../../web/src/vault/export.ts";
import { zipEntries } from "../../web/src/vault/zip.ts";
import { certifyTsa, checkCheckpointStamp, checkVersionStamp, trustedTsas, tsaIdentityOf } from "../../web/src/vault/timestamp.ts";
import { member, vouch, openCase, trustOf, signedHash, signedHashStamped, signedIntake } from "../lib/team.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const tsa = await startTsaStub({ key: "rsa", name: "gorani suite TSA" });
const dev = await startDev({ vars: { TSA_URL: tsa.url } });
const enc = new TextEncoder();

const callAs = (who) => async (method, path, body) => {
	const r = await api(dev.base, method, path, { email: who.email, body });
	if (r.status >= 300) throw new Error(`${r.status} ${r.json?.error ?? r.text}`);
	return r.json;
};
const sourceAs = (who) => ({
	get: (path) => callAs(who)("GET", path),
	post: (path, body) => callAs(who)("POST", path, body),
	put: (path, body) => callAs(who)("PUT", path, body),
	async object(path) {
		const r = await fetch(`${dev.base}${path}`, { headers: { "x-gorani-dev-email": who.email } });
		if (!r.ok) throw new Error(`${r.status} ${path}`);
		return { body: new Uint8Array(await r.arrayBuffer()), ck: r.headers.get("x-gorani-ck"), chunk: Number(r.headers.get("x-gorani-chunk")) || null, version: Number(r.headers.get("x-gorani-version")), hash: r.headers.get("x-gorani-hash") };
	},
});
/** Upload a new evidence file; `signing` picks the hash fields (stamped or not). */
async function upload(who, kase, name, text, signing = "stamped", extra = {}) {
	const plain = enc.encode(text);
	const ck = newContentKey();
	const id = kase.sealer.newId();
	const signed = signing === "stamped" ? await signedHashStamped(who, kase.sealer, id, 1, plain) : { hash: await signedHash(who, kase.sealer, id, 1, plain) };
	const fields = { file_id: id, name: await kase.sealer.fileName(id, name), type: await kase.sealer.fileType(id, 1, "application/octet-stream"), ck: await kase.sealer.fileKey(id, 1, ck), size: String(plain.length), ...signed, intake: await signedIntake(who, kase.sealer, id), ...extra };
	const boundary = `x${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${kase.base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...(await sealWith(await importContentKey(ck), plain)), ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	return { id, status: r.status, text: await r.text() };
}
const stampsOf = async (who, kase, id) => (await api(dev.base, "GET", `${kase.base}/files/${id}/stamps`, { email: who.email })).json.versions;
/** Wait until version `v` of `id` is stamped (the alarm runs on its own clock). */
async function stamped(who, kase, id, v = 1, ms = 30_000) {
	const end = Date.now() + ms;
	for (;;) {
		const row = (await stampsOf(who, kase, id)).find((s) => s.version === v);
		if (row?.status === "stamped") return row;
		if (Date.now() > end) throw new Error(`v${v} of ${id} not stamped in ${ms} ms: ${JSON.stringify(row)}`);
		await new Promise((r) => setTimeout(r, 250));
	}
}
function verifyTool(bytes) {
	const dir = mkdtempSync(join(tmpdir(), "gorani-export-"));
	try {
		writeFileSync(join(dir, "package.zip"), bytes);
		const r = spawnSync(process.execPath, [join(ROOT, "tools/verify-export.mjs"), join(dir, "package.zip")], { encoding: "utf8" });
		return { status: r.status, out: r.stdout + r.stderr };
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

try {
	const ana = await member(dev, "ana", "lead");
	const lu = await member(dev, "lu", "lead", { by: ana });
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [lu, bo]);
	const ev = await openCase(dev, ana, "ir-stamp", "Stamped evidence", [[bo, "write"]], "evidence");

	// ── 1. The TSA, certified by a lead who compared its fingerprint ────
	assert.deepEqual((await api(dev.base, "GET", "/api/v1/family/tsa", { email: bo.email })).json, { configured: true, certs: [] });
	assert.equal((await api(dev.base, "POST", "/api/v1/family/tsa/probe", { email: bo.email })).status, 403, "only a lead probes");
	const probe = (await api(dev.base, "POST", "/api/v1/family/tsa/probe", { email: ana.email })).json;
	const who = await tsaIdentityOf(probe.token);
	assert.deepEqual([who.name, who.spki, who.certFingerprint], ["gorani suite TSA", tsa.tsa.spki, tsa.tsa.fingerprint], "what the lead compares is what the authority's certificate says");
	await assert.rejects(certifyTsa(callAs(bo), bo.signer, who), /403 only a lead/);
	const certs = (await certifyTsa(callAs(ana), ana.signer, who)).certs;
	assert.deepEqual(certs.map((c) => [c.spki, c.by]), [[tsa.tsa.spki, "ana"]]);
	const boTsas = await trustedTsas(await trustOf(dev, bo), certs);
	assert.ok(boTsas.has(tsa.tsa.spki), "bo counts the key: ana certified it, and bo verified ana");

	// ── 2. An upload, stamped by the alarm ──────────────────────────────
	const before = tsa.requests.length;
	assert.match((await upload(bo, ev, "bad.bin", "x", "stamped", { stamp: "not hex" })).text, /64 lowercase hex/);
	const disk = await upload(bo, ev, "disk.E01", "the disk image's bytes");
	assert.equal(disk.status, 200, disk.text);
	const row = await stamped(bo, ev, disk.id);
	assert.ok(tsa.requests.length > before && tsa.requests.every((r) => r.contentType === "application/timestamp-query"), "the store asked the TSA, as RFC 3161 says to");
	const head = await sourceAs(bo).object(`${ev.base}/files/${disk.id}?version=1`);
	const record = await openContentHash(ev.sealer.priv, ev.area, disk.id, 1, head.hash);
	const check = await checkVersionStamp(record, row, boTsas);
	assert.equal(check.status, "verified", JSON.stringify(check));
	assert.ok(Math.abs(Date.parse(check.at) - Date.now()) < 120_000 && check.certifiedBy[0] === "ana", JSON.stringify(check));

	// ── 3. The TSA down: backed off, then stamped ───────────────────────
	tsa.failNext(2);
	const memo = await upload(bo, ev, "memo.txt", "a memo, while the TSA is down");
	assert.equal(memo.status, 200, memo.text);
	assert.equal((await stampsOf(bo, ev, memo.id))[0].status, "pending", "the upload did not wait for the TSA");
	const memoRow = await stamped(bo, ev, memo.id, 1, 45_000);
	assert.ok(tsa.requests.filter((r) => r.refused).length >= 2, "refused twice, retried");

	// ── 4. A moved token, and a withdrawn key ───────────────────────────
	const moved = await checkVersionStamp(record, { ...row, token: memoRow.token }, boTsas);
	assert.equal(moved.status, "invalid");
	assert.match(moved.why, /over other bytes/, "memo's token presented as disk's");
	const memoHead = await sourceAs(bo).object(`${ev.base}/files/${memo.id}?version=1`);
	const memoRecord = await openContentHash(ev.sealer.priv, ev.area, memo.id, 1, memoHead.hash);
	assert.match((await checkVersionStamp(memoRecord, row, boTsas)).why ?? "", /not this hash record's signature/, "disk's whole stamp row presented as memo's");
	assert.equal((await api(dev.base, "DELETE", `/api/v1/family/tsa/${tsa.tsa.spki}`, { email: bo.email })).status, 403, "only a lead withdraws");
	assert.equal((await api(dev.base, "DELETE", `/api/v1/family/tsa/${tsa.tsa.spki}`, { email: lu.email })).status, 200, "any lead withdraws — taking trust away is protective");
	const afterWithdraw = await trustedTsas(await trustOf(dev, bo), (await api(dev.base, "GET", "/api/v1/family/tsa", { email: bo.email })).json.certs);
	assert.equal((await checkVersionStamp(record, row, afterWithdraw)).status, "uncertified", "a sound token from a key nobody vouches for now");
	await certifyTsa(callAs(ana), ana.signer, who); // (back, for the rest)

	// ── 5. Re-verification asks for the missing stamp, once ─────────────
	const old = await upload(bo, ev, "old.log", "recorded before stamps", "unstamped");
	assert.equal(old.status, 200, old.text);
	assert.equal((await stampsOf(bo, ev, old.id))[0].status, "no-imprint");
	const rv = await reverifyCase(sourceAs(bo), ev.sealer.priv, await trustOf(dev, bo), "ir-stamp");
	assert.deepEqual([rv.checked, rv.failed, rv.stampsRequested], [3, 0, 1], JSON.stringify(rv.problems));
	await stamped(bo, ev, old.id);
	assert.equal((await api(dev.base, "PUT", `${ev.base}/files/${old.id}/stamps`, { email: bo.email, body: { version: 1, imprint: "ab".repeat(32) } })).status, 409, "an imprint is never replaced");

	// ── 6. The nightly checkpoint, stamped over its bytes ───────────────
	assert.equal((await fetch(`${dev.base}/cdn-cgi/local/scheduled?cron=${encodeURIComponent("17 3 * * *")}`)).status, 200);
	const verify = (await api(dev.base, "GET", `${ev.base}/audit/verify`, { email: ana.email })).json;
	const cp = verify.checkpoints.at(-1);
	assert.ok(cp?.token, `the checkpoint has its token: ${JSON.stringify(verify.checkpoints)}`);
	assert.equal((await checkCheckpointStamp(cp.body, cp.token, boTsas)).status, "verified");
	assert.equal((await checkCheckpointStamp(cp.body.replace(/"seq":\d+/, '"seq":1'), cp.token, boTsas)).status, "invalid", "a checkpoint rewritten after its stamp");

	// ── 7. The export carries the stamps; the standalone tool checks them ─
	const asked = await requestApproval(callAs(ana), ana.signer, "ir-stamp", "case.export");
	await approveRequest(callAs(lu), lu.signer, await trustOf(dev, lu), asked);
	const built = await buildExport(sourceAs(ana), ana.signer, await trustOf(dev, ana), ev.sealer.priv, "ir-stamp", asked.id);
	assert.deepEqual(built.problems, [], "every stamp checked out while building");
	const out = verifyTool(Buffer.concat(built.parts.map((p) => Buffer.from(p))));
	assert.equal(out.status, 0, out.out);
	assert.match(out.out, /✔ TSA key [0-9a-f]{16}… \(gorani suite TSA\): certified by ana, signed/);
	assert.match(out.out, /✔ disk\.E01 v1: timestamped \d{4}-\d\d-\d\dT[\d:.]+Z by gorani suite TSA \(key certified by ana\)/);
	assert.match(out.out, /✔ old\.log v1: timestamped/, "the backfilled stamp too");
	assert.match(out.out, /✔ audit checkpoint \d{4}-\d\d-\d\d \(lines to \d+\): timestamped/);
	assert.ok(out.out.includes(`TSA gorani suite TSA: certificate SHA-256 ${tsa.tsa.fingerprint}`), "the fingerprint to compare, out of band");
	// A token altered inside the package: the tool names it (beside the
	// manifest signature it also breaks — each check stands on its own).
	const m = built.manifest;
	const flip = (b64) => {
		const b = Buffer.from(b64, "base64");
		b[b.length - 1] ^= 0x01;
		return b.toString("base64");
	};
	const altered = { ...m, files: m.files.map((f) => (f.id === disk.id ? { ...f, versions: f.versions.map((v) => ({ ...v, stamp: { ...v.stamp, token: flip(v.stamp.token) } })) } : f)) };
	const repacked = verifyTool(Buffer.concat(zipEntries([{ name: "manifest.json", data: Buffer.from(JSON.stringify(altered, null, 2)) }, { name: "manifest.sig.json", data: Buffer.from("{}") }]).map((p) => Buffer.from(p))));
	assert.equal(repacked.status, 1);
	assert.match(repacked.out, /✘ disk\.E01 v1: timestamp — the TSA's signature does not verify/);

	console.log("ok  api:timestamps — a lead certifies the TSA key it compared; evidence imprints stamped by the alarm (a down TSA backed off, nothing lost); moved tokens and a withdrawn key refused by name; re-verification backfills once; the checkpoint stamped over its bytes; the export's every token checked by the standalone tool");
} finally {
	await dev.close();
	await tsa.close();
}
