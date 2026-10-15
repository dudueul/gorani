// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:collect — a collector drops evidence into a case inbox (commit 37b,
 * docs/COLLECTORS.md): the real `gorani-sync collector` binary as the
 * machine, the web app's own vault code as the members, the real worker
 * between them. What it proves:
 *
 *   1. `collector init` makes an identity key whose id the browser computes
 *      too; two leads register it (37a) — and `whoami` is the registry's
 *      word that the token is THIS machine's key;
 *   2. no grant → no drop; no inbox key → no drop; an analyst cannot make
 *      the inbox key, a manager can;
 *   3. the collector refuses an inbox key signed by someone its pins do
 *      not vouch for — nothing is sealed, nothing sent — and accepts it
 *      once it pins that lead; later, a key made by a manager the pinned
 *      lead certified (one hop);
 *   4. what it dropped opens for a member ONLY through the inbox key, which
 *      opens only with the case key: the record is the collector's signed
 *      word for exactly these bytes, this case, this item — verified by the
 *      member against collectors two leads THEY trust registered; the
 *      store's copy of the bytes decrypts to the file;
 *   5. what the store could forge is named: a record moved from another
 *      item, a record signed by some other key, a stamp over another
 *      signature — each a reason, never "verified";
 *   6. an item id cannot be taken twice (the first item's bytes survive the
 *      attempt), a drop to a retired inbox key is refused, and a large file
 *      goes up as GC01 frames;
 *   7. a case-key rotation must carry every inbox key re-sealed (one short
 *      is refused), and the inbox still opens under the new key;
 *   8. a revoked collector's next drop is refused; the machine's own log
 *      holds a line per drop.
 *
 * Skipped when the debug binary is not built (cargo build -p gorani-client-core).
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "./_dev.mjs";
import { member, vouch, openCase, trustOf } from "../lib/team.mjs";
import { approveCollector, requestCollector, type CollectorRow } from "../../web/src/vault/collectors.ts";
import { checkInboxContent, createInboxKey, inboxStatements, openInboxItem, openInboxKeys, type InboxItem, type InboxKeyRow } from "../../web/src/vault/inbox.ts";
import { openCaseKey, rotateCase, type CaseRow } from "../../web/src/vault/cases.ts";
import { fingerprint, identityKeyId } from "../../web/src/vault/identity.ts";
import { sha256Hex } from "../../web/src/vault/content-hash.ts";
import { openChunked } from "../../web/src/vault/chunked-file.ts";
import { importContentKey, newContentKey, openWith, sealText, sealWith, wrapContentKey } from "../../web/src/vault/vault-crypto.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BIN = path.join(ROOT, "target/debug/gorani-sync");
if (!fs.existsSync(BIN)) {
	console.log("skip  api:collect — build it first: cargo build -p gorani-client-core");
	process.exit(0);
}

const dev = await suiteDev();
const home = path.join(ROOT, "tests/output/collect-home");
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true });
const PROFILE = path.join(home, "collector.json");
const CN = "5e1f0c2b7a9d4e3f8b6a1c0d2e4f6a8b.access";
const CASE = "ir-drop";
const BASE = `/api/v1/cases/${CASE}`;
const enc = new TextEncoder();

/** Run the CLI (spawn, not spawnSync: this process may run the S3 stub). */
function sync(args: string[]): Promise<{ status: number; out: string; stdout: string }> {
	const c = spawn(BIN, [...args, "--profile", PROFILE], { cwd: ROOT, env: { ...process.env, HOME: home } });
	let out = "";
	let stdout = "";
	c.stdout.on("data", (d) => {
		out += d;
		stdout += d;
	});
	c.stderr.on("data", (d) => (out += d));
	return new Promise((resolve) => {
		const t = setTimeout(() => c.kill("SIGKILL"), 240_000);
		c.on("exit", (s) => {
			clearTimeout(t);
			resolve({ status: s ?? 1, out, stdout });
		});
	});
}

const collect = (file: string, extra: string[] = []) =>
	sync(["collect", "--case", CASE, "--file", file, "--source", "WS-0412 (finance laptop)", "--method", "EDR live response, memory + triage", "--collected-at", "2026-10-15T08:30:00Z", "--notes", "ticket IR-311", ...extra]);

const call = (who: { email: string }) => async <T>(method: string, p: string, body?: unknown): Promise<T> => {
	const r = await api(dev.base, method, p, { email: who.email, body });
	if (r.status >= 300) throw new Error(`${method} ${p}: ${r.status} ${r.text.slice(0, 300)}`);
	return r.json as T;
};

/** A drop as the collector sends it, by hand — what a forging server or a
 * hostile collector could send. */
async function drop(fields: Record<string, string>, file: Uint8Array) {
	const boundary = `c${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const tail = enc.encode(`\r\n--${boundary}--\r\n`);
	const r = await fetch(`${dev.base}/api/v1/collect/cases/${CASE}/items`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-collector": CN }, body: new Uint8Array([...head, ...file, ...tail]) });
	return { status: r.status, text: await r.text() };
}

try {
	// ── 0. The team: two leads, an analyst, a manager; an evidence case ──
	const ana = await member(dev, "ana", "lead");
	const cy = await member(dev, "cy", "lead", { by: ana });
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const dan = await member(dev, "dan", "analyst", { by: ana });
	await vouch(dev, ana, [bo, cy, dan]); // ana certifies each; each pins ana
	await openCase(dev, ana, CASE, "Finance laptop intrusion", [[bo, "write"], [dan, "manage"]], "evidence");
	const caseOf = async (who: { email: string }) => ((await api(dev.base, "GET", "/api/v1/cases", { email: who.email })).json.cases as CaseRow[]).find((c) => c.id === CASE)!;

	// ── 1. The machine introduces itself; two leads register it ─────────
	const init = await sync(["collector", "init", "--server", dev.base, "--id", "edr-1", "--pins", `cy:${fingerprint(cy.record.keyId)}`, "--dev-collector", CN, "--protect", "file"]);
	assert.equal(init.status, 0, init.out);
	const intro = JSON.parse(init.stdout.trim()) as { id: string; publicKey: JsonWebKey; keyId: string; fingerprint: string };
	assert.equal(intro.keyId, await identityKeyId(intro.publicKey), "Rust and the browser compute one key id");
	assert.equal(intro.fingerprint, fingerprint(intro.keyId));
	assert.match((await sync(["collector", "init", "--server", dev.base, "--id", "edr-1", "--pins", "cy:" + "0".repeat(32), "--protect", "file"])).out, /already a collector/, "init never replaces a registered key");
	const requested = await requestCollector(call(ana), ana.signer, { id: "edr-1", name: "EDR drop", commonName: CN, publicKey: intro.publicKey });
	await approveCollector(call(cy), cy.signer, await trustOf(dev, cy), requested);
	const who = await sync(["collector", "whoami"]);
	assert.equal(who.status, 0, who.out);
	assert.equal(JSON.parse(who.stdout).id, "edr-1");

	// ── 2. Grant, then the inbox key ────────────────────────────────────
	const evidence = path.join(home, "triage.zip");
	const plain = enc.encode("memory image and triage bundle — WS-0412\n".repeat(200));
	fs.writeFileSync(evidence, plain);
	assert.match((await collect(evidence)).out, /403.*may not drop into that case/, "no grant, no drop");
	assert.equal((await api(dev.base, "PUT", `${BASE}/collectors/edr-1`, { email: ana.email })).status, 200);
	assert.match((await collect(evidence)).out, /409.*no inbox key yet/);
	const anaCaseKey = await openCaseKey(ana.root, await caseOf(ana), await trustOf(dev, ana));
	const boCaseKey = await openCaseKey(bo.root, await caseOf(bo), await trustOf(dev, bo));
	await assert.rejects(createInboxKey(call(bo), boCaseKey, CASE, bo.signer), /403/, "an analyst does not make the inbox key");
	await createInboxKey(call(ana), anaCaseKey, CASE, ana.signer);
	const firstKey = (await caseOf(bo)).inboxKeys!.find((k) => !k.retiredAt)!;
	assert.equal(firstKey.signedBy, "ana");

	// ── 3. The collector believes its pins, not the server ──────────────
	const refused = await collect(evidence);
	assert.notEqual(refused.status, 0);
	assert.match(refused.out, /pins do not vouch for/, "ana is not pinned here, and cy certified nobody");
	assert.equal(((await api(dev.base, "GET", `${BASE}/inbox`, { email: bo.email })).json.items as InboxItem[]).length, 0, "nothing was sent");
	assert.equal((await sync(["collector", "pin", "--pins", `ana:${fingerprint(ana.record.keyId)}`])).status, 0);
	const dropped = await collect(evidence, ["--name", "triage.zip", "--type", "application/zip"]);
	assert.equal(dropped.status, 0, dropped.out);
	const first = JSON.parse(dropped.stdout.trim()) as { item: string; size: number; sha256: string; inboxKeyId: string };
	assert.equal(first.sha256, await sha256Hex(plain));
	assert.equal(first.inboxKeyId, firstKey.keyId);

	// ── 4. A member opens it — through the inbox key, and checks it ─────
	const collectors = async () => (await api(dev.base, "GET", "/api/v1/family/collectors", { email: bo.email })).json.collectors as CollectorRow[];
	const inbox = async () => (await api(dev.base, "GET", `${BASE}/inbox`, { email: bo.email })).json.items as InboxItem[];
	const opened = async (caseKey: typeof boCaseKey, id: string) => {
		const keys = await openInboxKeys(caseKey, CASE, (await caseOf(bo)).inboxKeys as InboxKeyRow[]);
		const item = (await inbox()).find((i) => i.id === id)!;
		return { item, o: await openInboxItem(keys, CASE, item, await trustOf(dev, bo), await collectors()) };
	};
	let { item, o } = await opened(boCaseKey, first.item);
	assert.equal(item.status, "waiting");
	assert.equal(item.collector, "edr-1");
	assert.match(item.ck, /^GV03:/, "the content key is sealed to the inbox key, not placed (a collector cannot place)");
	assert.equal(o.problem, null, `verified: ${o.problem}`);
	assert.equal(o.meta.name, "triage.zip");
	assert.equal(o.meta.type, "application/zip");
	assert.equal(o.meta.source, "WS-0412 (finance laptop)");
	assert.equal(o.meta.notes, "ticket IR-311");
	const bytes = await fetch(`${dev.base}${BASE}/inbox/${first.item}`, { headers: { "x-gorani-dev-email": bo.email } });
	assert.equal(bytes.status, 200);
	const back = await openWith(o.contentKey, new Uint8Array(await bytes.arrayBuffer()));
	assert.deepEqual(back, plain, "the store's copy decrypts to the file");
	assert.equal(checkInboxContent(o, await sha256Hex(back), back.length), null);
	assert.match(checkInboxContent(o, "0".repeat(64), back.length) ?? "", /SHA-256 differs/);
	assert.equal((await api(dev.base, "GET", `${BASE}/inbox`, { email: "nobody@team.test" })).status, 403, "not on the case, no inbox");
	const reads = (await api(dev.base, "GET", `${BASE}/reads`, { email: ana.email })).json;
	assert.ok(JSON.stringify(reads).includes(`inbox:${first.item}`), "the read is on record, as a file's");

	// ── 5. What a store could forge is named, never "verified" ──────────
	const pub = firstKey.publicKey;
	const ckFresh = newContentKey();
	const body = await sealWith(await importContentKey(ckFresh), enc.encode("planted"));
	const forged = async (id: string, meta: string) => {
		const r = await drop({ item_id: id, inbox_key_id: firstKey.keyId, size: "7", ck: await wrapContentKey(pub, ckFresh), meta }, body);
		assert.equal(r.status, 200, r.text);
		return (await opened(boCaseKey, id)).o.problem;
	};
	// (a) a valid record moved from another item
	assert.match((await forged("moved-record", item.meta)) ?? "", /record is for item/);
	// (b) a record signed by a key that is not the collector's
	const fake = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
	const fields = { case: CASE, item: "fake-sig", collector: "edr-1", name: "x", type: "text/plain", size: 7, sha256: await sha256Hex(enc.encode("planted")), source: "s", method: "m", collectedAt: "2026-10-15T09:00:00Z", notes: "" };
	const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, fake.privateKey, inboxStatements.collect(fields) as BufferSource))));
	assert.match((await forged("fake-sig", await sealText(pub, JSON.stringify({ ...fields, signature: sig })))) ?? "", /signature does not verify/);
	// (c) the real item, served with a stamp imprint over some other
	// signature (a token for it would prove the wrong thing's time)
	const keys = await openInboxKeys(boCaseKey, CASE, (await caseOf(bo)).inboxKeys as InboxKeyRow[]);
	const restamped = { ...item, stamp: { ...item.stamp, imprint: "a".repeat(64) } };
	assert.match((await openInboxItem(keys, CASE, restamped, await trustOf(dev, bo), await collectors())).problem ?? "", /imprint is not over the collector's signature/);
	// (d) a size the store's own count contradicts
	assert.match((await openInboxItem(keys, CASE, { ...item, size: item.size + 1 }, await trustOf(dev, bo), await collectors())).problem ?? "", /the store received/);
	// …and the shapes the store itself refuses
	assert.equal((await drop({ item_id: "plain", inbox_key_id: firstKey.keyId, size: "7", ck: "not sealed", meta: "{}" }, body)).status, 400, "ck and meta arrive sealed");

	// ── 6. Ids are the collector's, once; retired keys; large drops ─────
	const again = await collect(evidence, ["--item-id", first.item]);
	assert.match(again.out, /409.*already received/);
	const still = await fetch(`${dev.base}${BASE}/inbox/${first.item}`, { headers: { "x-gorani-dev-email": bo.email } });
	assert.deepEqual(await openWith(o.contentKey, new Uint8Array(await still.arrayBuffer())), plain, "the first item's bytes survived the second drop");
	// dan — a manager ana certified — makes the next key: the collector
	// believes it through ana's certificate (one hop).
	const danCaseKey = await openCaseKey(dan.root, await caseOf(dan), await trustOf(dev, dan));
	await createInboxKey(call(dan), danCaseKey, CASE, dan.signer);
	const secondKey = (await caseOf(bo)).inboxKeys!.find((k) => !k.retiredAt)!;
	assert.equal(secondKey.signedBy, "dan");
	assert.ok((await caseOf(bo)).inboxKeys!.find((k) => k.keyId === firstKey.keyId)!.retiredAt, "the first key is retired, and kept");
	assert.match((await drop({ item_id: "old-key", inbox_key_id: firstKey.keyId, size: "7", ck: await wrapContentKey(pub, ckFresh), meta: item.meta }, body)).text, /CURRENT inbox key/, "a drop to a retired key is refused");
	const big = path.join(home, "disk.img");
	const bigPlain = new Uint8Array(49 * 1024 * 1024);
	for (let i = 0; i < bigPlain.length; i += 4096) bigPlain[i] = (i / 4096) & 0xff;
	fs.writeFileSync(big, bigPlain);
	const large = await collect(big, ["--type", "application/octet-stream"]);
	assert.equal(large.status, 0, large.out);
	const second = JSON.parse(large.stdout.trim()) as { item: string; parts: number; inboxKeyId: string };
	assert.ok(second.parts > 1, "frames, not one request");
	assert.equal(second.inboxKeyId, secondKey.keyId);
	({ item, o } = await opened(boCaseKey, second.item));
	assert.equal(o.problem, null, `verified: ${o.problem}`);
	assert.ok(item.chunk && item.chunk > 0);
	const bigBack = await openChunked(o.contentKey, new Uint8Array(await (await fetch(`${dev.base}${BASE}/inbox/${second.item}`, { headers: { "x-gorani-dev-email": bo.email } })).arrayBuffer()), item.chunk!);
	assert.equal(checkInboxContent(o, await sha256Hex(bigBack), bigBack.length), null, "the frames decrypt to what the collector signed");
	fs.rmSync(big);

	// ── 7. A case-key rotation carries every inbox key ──────────────────
	const c = await caseOf(ana);
	const roots = await Promise.all(c.grantees.map(async (g) => (await api(dev.base, "GET", `/api/v1/members/${g.member}/root`, { email: ana.email })).json));
	await assert.rejects(rotateCase(call(ana), ana.root, { ...c, inboxKeys: c.inboxKeys!.slice(1) }, roots, ana.signer, await trustOf(dev, ana)), /409.*inbox key/, "one inbox key short is refused");
	await rotateCase(call(ana), ana.root, await caseOf(ana), roots, ana.signer, await trustOf(dev, ana));
	const boNewKey = await openCaseKey(bo.root, await caseOf(bo), await trustOf(dev, bo));
	assert.equal((await opened(boNewKey, first.item)).o.problem, null, "the first item opens under the new case key");
	await assert.rejects(opened(boCaseKey, first.item), "…and no longer under the old one");

	// ── 8. Revoked: the next drop is refused; the machine kept a log ─────
	assert.equal((await api(dev.base, "DELETE", "/api/v1/family/collectors/edr-1", { email: cy.email })).status, 200);
	assert.match((await collect(evidence)).out, /403.*not a registered, active collector/);
	const log = fs.readFileSync(path.join(home, "collector.log"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
	assert.deepEqual(log.map((l) => l.item), [first.item, second.item], "a line per drop, nothing for refusals");
	assert.equal(log[0].sha256, first.sha256);

	console.log("ok    api:collect (init + two-lead registration, pins decide the inbox key, sealed + signed drops verified by members, forgeries named, retired keys, frames, rotation, revocation)");
} finally {
	await dev.close();
}
