// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:export — the signed export package and re-verification (commit 29h,
 * docs/CUSTODY.md › Stage 7, D5.8; web/src/vault/export.ts,
 * tools/verify-export.mjs). What it proves:
 *
 *   1. no export without an APPROVED case.export (two leads); the approval
 *      is spent by the export, and only one of the two people runs it;
 *   2. the package built in the exporter's client — evidence decrypted,
 *      every record checked — passes tools/verify-export.mjs, a second
 *      implementation using Node alone: identities, the exporter's
 *      signature, the approval's two signatures, every version's bytes and
 *      signed hash (a sample unzipped with "infected" first), intake,
 *      custody, the audit chain;
 *   3. a package altered after signing fails it: an evidence byte, the
 *      manifest, an audit line;
 *   4. re-verification re-hashes every version, records the counts in the
 *      case's audit, and clears the "overdue" flag the nightly pass reads.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "./_dev.mjs";
import { newContentKey, importContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";
import { sampleType } from "../../web/src/vault/samples.ts";
import { approveRequest, requestApproval } from "../../web/src/vault/approvals.ts";
import { offerCustody, acceptCustody } from "../../web/src/vault/custody.ts";
import { buildExport, reverifyCase } from "../../web/src/vault/export.ts";
import { zipEntries } from "../../web/src/vault/zip.ts";
import { member, vouch, openCase, trustOf, signedHash, signedIntake } from "../lib/team.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const dev = await suiteDev();
const enc = new TextEncoder();

const callAs = (who) => async (method, path, body) => {
	const r = await api(dev.base, method, path, { email: who.email, body });
	if (r.status >= 300) throw new Error(`${r.status} ${r.json?.error ?? r.text}`);
	return r.json;
};
/** The export's view of the API, as `who`'s browser has it. */
const sourceAs = (who) => ({
	get: (path) => callAs(who)("GET", path),
	post: (path, body) => callAs(who)("POST", path, body),
	async object(path) {
		const r = await fetch(`${dev.base}${path}`, { headers: { "x-gorani-dev-email": who.email } });
		if (!r.ok) throw new Error(`${r.status} ${path}`);
		return { body: new Uint8Array(await r.arrayBuffer()), ck: r.headers.get("x-gorani-ck"), chunk: Number(r.headers.get("x-gorani-chunk")) || null, version: Number(r.headers.get("x-gorani-version")), hash: r.headers.get("x-gorani-hash") };
	},
	// (D12, 31d) The streamed read the browser makes: the export decrypts as it goes.
	async objectStream(path) {
		const r = await fetch(`${dev.base}${path}`, { headers: { "x-gorani-dev-email": who.email } });
		if (!r.ok) throw new Error(`${r.status} ${path}`);
		return { body: r.body, size: Number(r.headers.get("content-length")), ck: r.headers.get("x-gorani-ck"), chunk: Number(r.headers.get("x-gorani-chunk")) || null, version: Number(r.headers.get("x-gorani-version")), hash: r.headers.get("x-gorani-hash") };
	},
});
async function upload(who, kase, name, type, text, extra = {}) {
	const plain = enc.encode(text);
	const ck = newContentKey();
	const id = kase.sealer.newId();
	const fields = { file_id: id, name: await kase.sealer.fileName(id, name), type: await kase.sealer.fileType(id, 1, type), ck: await kase.sealer.fileKey(id, 1, ck), size: String(plain.length), hash: await signedHash(who, kase.sealer, id, 1, plain), intake: await signedIntake(who, kase.sealer, id, { source: `the ${name} source` }), ...extra };
	const boundary = `x${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const r = await fetch(`${dev.base}${kase.base}/files`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...(await sealWith(await importContentKey(ck), plain)), ...enc.encode(`\r\n--${boundary}--\r\n`)]) });
	assert.equal(r.status, 200, await r.text());
	return id;
}
const concat = (parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
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
	const ev = await openCase(dev, ana, "ir-export", "Exported evidence", [[bo, "write"]], "evidence");
	const disk = await upload(bo, ev, "disk.E01", "application/octet-stream", "the disk image's bytes");
	await upload(bo, ev, "dropper.exe", sampleType("application/x-msdownload"), "MZ a sample", { sample: "1" });
	// A custody link: bo → ana.
	const chain = (await api(dev.base, "GET", `${ev.base}/files/${disk}/custody`, { email: bo.email })).json;
	await offerCustody(callAs(bo), bo.signer, ev.sealer.priv, ev.base, ev.area, disk, chain, "ana", "for the export");
	const offered = (await api(dev.base, "GET", `${ev.base}/files/${disk}/custody`, { email: ana.email })).json;
	await acceptCustody(callAs(ana), ana.signer, await trustOf(dev, ana), ev.sealer.priv, ev.base, ev.area, disk, offered.entries[0]);

	// ── 1. Only an approved export, once, by one of the two ───────────
	const anaTrust = await trustOf(dev, ana);
	const asked = await requestApproval(callAs(ana), ana.signer, "ir-export", "case.export");
	await assert.rejects(buildExport(sourceAs(ana), ana.signer, anaTrust, ev.sealer.priv, "ir-export", asked.id), /not approved yet/);
	await approveRequest(callAs(lu), lu.signer, await trustOf(dev, lu), asked);
	await assert.rejects(buildExport(sourceAs(bo), bo.signer, await trustOf(dev, bo), ev.sealer.priv, "ir-export", asked.id), /one of the two people/, "bo was not one of the two");
	const built = await buildExport(sourceAs(ana), ana.signer, anaTrust, ev.sealer.priv, "ir-export", asked.id);
	await assert.rejects(buildExport(sourceAs(ana), ana.signer, anaTrust, ev.sealer.priv, "ir-export", asked.id), /used by an earlier export/, "the approval is spent");
	assert.deepEqual(built.problems, [], "every record checked out while building");
	assert.ok((await api(dev.base, "GET", "/api/v1/family", { email: ana.email })).json.audit.some((l) => l.action === "case.export" && l.target === "ir-export"), "the registry records the export");

	// ── 2. The standalone verifier passes it ──────────────────────────
	const pkg = concat(built.parts);
	const good = verifyTool(pkg);
	assert.equal(good.status, 0, good.out);
	assert.match(good.out, /✔ the exporter's signature \(ana\)/);
	assert.match(good.out, /✔ approved by lu, signed/);
	assert.match(good.out, /✔ dropper\.exe v1: \d+ bytes/, "the sample, unzipped with \"infected\" and hashed");
	assert.match(good.out, /✔ disk\.E01: custody link 1, bo → ana/);
	assert.match(good.out, /✔ the audit trail: \d+ lines/);
	assert.match(good.out, /fingerprint ([0-9A-F]{4} ){7}[0-9A-F]{4}/);
	const m = built.manifest;
	const diskEntry = m.files.find((f) => f.id === disk);
	assert.equal(diskEntry.intake.source, "the disk.E01 source", "the intake record, opened, in the manifest");

	// ── 3. Altered after signing: refused ─────────────────────────────
	// (a) one evidence byte, flipped inside the package itself.
	const evidenceAt = pkg.indexOf(Buffer.from("the disk image's bytes"));
	assert.ok(evidenceAt > 0);
	const flipped = Buffer.from(pkg);
	flipped[evidenceAt] ^= 0x01;
	const bad1 = verifyTool(flipped);
	assert.equal(bad1.status, 1);
	assert.match(bad1.out, /✘ disk\.E01 v1/, "the altered evidence is named");
	// (b) the manifest edited (a file renamed) and re-zipped beside the
	// ORIGINAL signature.
	const originalSig = extract(pkg, "manifest.sig.json");
	const repack = (manifest) => verifyTool(concat(zipEntries([{ name: "manifest.json", data: Buffer.from(JSON.stringify(manifest, null, 2)) }, { name: "manifest.sig.json", data: originalSig }])));
	const bad2 = repack({ ...m, files: m.files.map((f) => (f.id === disk ? { ...f, name: "something-else.E01" } : f)) });
	assert.equal(bad2.status, 1);
	assert.match(bad2.out, /✘ manifest\.json is the signed bytes/);
	// (c) an audit line rewritten: the chain itself says so, signature aside.
	const bad3 = repack({ ...m, audit: { ...m.audit, lines: m.audit.lines.map((l, i) => (i === 0 ? { ...l, actor: "nobody@team.test" } : l)) } });
	assert.match(bad3.out, /✘ the audit trail/);

	// ── 3b. Streamed, and ZIP64 throughout (D12, 31d) ─────────────────
	// A second approved export, written through a sink as it is made and
	// with every ZIP64 field forced: the standalone tool reads it from disk
	// — ZIP64 end records, data descriptors, the sample's nested zip with
	// its data-descriptor check byte — and every check still passes.
	const again = await requestApproval(callAs(ana), ana.signer, "ir-export", "case.export");
	await approveRequest(callAs(lu), lu.signer, await trustOf(dev, lu), again);
	const streamedParts = [];
	const streamed = await buildExport(sourceAs(ana), ana.signer, anaTrust, ev.sealer.priv, "ir-export", again.id, { sink: async (b) => void streamedParts.push(b.slice()), forceZip64: true });
	assert.deepEqual(streamed.parts, [], "with a sink, nothing is collected — it all went out");
	const z64 = concat(streamedParts);
	assert.equal(z64.readUInt32LE(z64.length - 42), 0x07064b50, "a ZIP64 end locator");
	const good64 = verifyTool(z64);
	assert.equal(good64.status, 0, good64.out);
	assert.match(good64.out, /✔ dropper\.exe v1: \d+ bytes/, "the sample, opened in place with its data-descriptor check byte");

	// ── 4. Re-verification ────────────────────────────────────────────
	const before = (await api(dev.base, "GET", `${ev.base}/reverify`, { email: bo.email })).json;
	assert.equal(before.overdue, true, "evidence never re-verified: overdue");
	const rv = await reverifyCase(sourceAs(bo), ev.sealer.priv, await trustOf(dev, bo), "ir-export");
	assert.deepEqual([rv.checked, rv.failed], [2, 0]);
	const after = (await api(dev.base, "GET", `${ev.base}/reverify`, { email: bo.email })).json;
	assert.deepEqual([after.overdue, after.last.checked, after.last.failed, after.last.by], [false, 2, 0, "bo"]);
	assert.ok((await api(dev.base, "GET", `${ev.base}/audit`, { email: ana.email })).json.some((l) => l.action === "case.reverify"), "the case's audit records it");

	console.log("ok  api:export — two-person export spent once, the package verified by a standalone Node tool, altered evidence/manifest/audit refused, re-verification recorded and the overdue flag cleared");
} finally {
	await dev.close();
}

/** One entry's bytes from a stored zip (a test-side reader, for re-packing). */
function extract(buf, name) {
	let eocd = buf.length - 22;
	while (eocd >= 0 && buf.readUInt32LE(eocd) !== 0x06054b50) eocd--;
	let at = buf.readUInt32LE(eocd + 16);
	for (let n = buf.readUInt16LE(eocd + 10); n > 0; n--) {
		const nlen = buf.readUInt16LE(at + 28);
		const entry = buf.subarray(at + 46, at + 46 + nlen).toString("utf8");
		const local = buf.readUInt32LE(at + 42);
		if (entry === name) {
			const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
			return buf.subarray(start, start + buf.readUInt32LE(at + 20));
		}
		at += 46 + nlen + buf.readUInt16LE(at + 30) + buf.readUInt16LE(at + 32);
	}
	throw new Error(`no ${name}`);
}
