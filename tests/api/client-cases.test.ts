// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:client-cases — the native client in a case (commit 33c,
 * docs/DESKTOP.md): the real `gorani-sync` binary against the real worker,
 * with a team built the way members' browsers build it (tests/lib/team.mjs
 * — the web app's own identity, case and grant code). Two implementations
 * of one protocol, checking each other over the wire:
 *
 *   1. `cases` opens each grant only through a signature the member can
 *      check: ana's grants (a lead bo pinned) open; cy's (a lead bo never
 *      verified) are listed and named as unverified — and refused for use;
 *   2. into an evidence case, `push` needs the intake record (refused
 *      before anything is sent), then sends the content hash SIGNED by bo,
 *      its timestamp imprint and the signed intake — which the BROWSER's
 *      code, on ana's side, opens and verifies (Rust signs, TS checks);
 *   3. `pull` checks what the uploader signed BEFORE writing: ana's
 *      evidence (TS signs, Rust checks) is "verified" and lands byte for
 *      byte; a record that vouches for other bytes refuses the pull and
 *      writes nothing; evidence from someone bo never verified is refused
 *      unless --accept-unverified;
 *   4. a 49 MiB evidence file goes up as GC01 frames under the case key,
 *      signed, and comes back streamed and verified;
 *   5. a read-only grant reads, and the server refuses its push.
 *
 * Skipped when the debug binary is not built (cargo build -p gorani-client-core).
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "./_dev.mjs";
import { member, vouch, openCase, pinIdentity, trustOf, signedHashStamped, signedIntake } from "../lib/team.mjs";
import { checkContentHash, openContentHash, sha256Hex } from "../../web/src/vault/content-hash.ts";
import { checkIntake } from "../../web/src/vault/intake.ts";
import { stampImprint } from "../../web/src/vault/timestamp.ts";
import { importContentKey, newContentKey, sealWith } from "../../web/src/vault/vault-crypto.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BIN = path.join(ROOT, "target/debug/gorani-sync");
if (!fs.existsSync(BIN)) {
	console.log("skip  api:client-cases — build it first: cargo build -p gorani-client-core");
	process.exit(0);
}

const dev = await suiteDev();
const home = path.join(ROOT, "tests/output/client-cases-home");
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true });
const enc = new TextEncoder();

/** Run the CLI (spawn, not spawnSync: this process may run the S3 stub — client-live.test.ts says why). */
function sync(args: string[]): Promise<{ status: number; out: string }> {
	const c = spawn(BIN, args, { cwd: ROOT, env: { ...process.env, HOME: home } });
	let out = "";
	c.stdout.on("data", (d) => (out += d));
	c.stderr.on("data", (d) => (out += d));
	return new Promise((resolve) => {
		const t = setTimeout(() => c.kill("SIGKILL"), 180_000);
		c.on("exit", (s) => {
			clearTimeout(t);
			resolve({ status: s ?? 1, out });
		});
	});
}

/** A multipart upload as the browser's bridge posts it. */
async function post(who: { email: string }, p: string, fields: Record<string, string>, file: Uint8Array) {
	const boundary = `c${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const tail = enc.encode(`\r\n--${boundary}--\r\n`);
	const r = await fetch(`${dev.base}${p}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...tail]) });
	return { status: r.status, json: (await r.json().catch(() => null)) as { id?: string; error?: string } | null };
}

try {
	// ── 0. The team, as browsers build it ───────────────────────────────
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const dee = await member(dev, "dee", "analyst", { by: ana }); // on the case; nobody certified her, so bo cannot verify her
	const cy = await member(dev, "cy", "lead", { by: ana }); // a lead bo never verified
	await vouch(dev, ana, [bo]); // ana certifies bo; bo pins ana
	await pinIdentity(dev, ana, dee); // ana verified dee herself — enough for ana to grant her, not for bo to trust her
	await pinIdentity(dev, cy, bo); // cy verified bo, so cy can grant bo a case — but bo has no reason to trust cy
	const ev = await openCase(dev, ana, "ir-cli", "Ransomware at WS-042", [[bo, "write"], [dee, "write"]], "evidence");
	const wk = await openCase(dev, ana, "wk-cli", "Working notes", [[bo, "read"]]);
	await openCase(dev, cy, "cy-cli", "cy's own case", [[bo, "write"]]);

	const profile = path.join(home, "bo.json");
	const as = (args: string[]) => sync([...args, "--profile", profile, "--secret", bo.recoveryCode, "--dev-email", bo.email]);
	const setup = await sync(["setup", "--server", dev.base, "--member", "bo", "--name", "bo's workstation", "--secret", bo.recoveryCode, "--device-secret", "b".repeat(64), "--dev-email", bo.email, "--profile", profile]);
	assert.equal(setup.status, 0, setup.out);

	// ── 1. cases: each grant opened only through a signature bo can check ─
	const listed = await as(["cases"]);
	assert.equal(listed.status, 0, listed.out);
	assert.match(listed.out, /3 case\(s\) granted to you/);
	assert.match(listed.out, /ir-cli\s+evidence\s+write\s+Ransomware at WS-042\n\s+key verified — granted by ana/, `the evidence case, its title opened: ${listed.out}`);
	assert.match(listed.out, /wk-cli\s+working\s+read\s+Working notes/);
	assert.match(listed.out, /cy-cli[^\n]*\(title not opened\)\n\s+⚠ key not opened: [^\n]*signed by cy, whose identity you have not verified/, "a grant from an unverified lead: listed, named, not opened");
	const rogue = await as(["ls", "--case", "cy-cli"]);
	assert.notEqual(rogue.status, 0, "…and not usable");
	assert.match(rogue.out, /whose identity you have not verified/);

	// ── 2. push into evidence: intake required, hash signed (Rust signs, TS checks) ─
	const triage = path.join(home, "triage.txt");
	const triageBytes = enc.encode("triage notes, WS-042: encrypted shares since 02:14; ransom note in C:\\Users\\Public");
	fs.writeFileSync(triage, triageBytes);
	const bare = await as(["push", "--case", "ir-cli", "--file", triage]);
	assert.notEqual(bare.status, 0);
	assert.match(bare.out, /needs its intake record/, "refused before anything is sent");
	assert.equal((await api(dev.base, "GET", `${ev.base}/files/changes?since=0`, { email: ana.email })).json.changes.length, 0, "nothing reached the case");
	const intake = ["--source", "laptop WS-042, disk 0", "--collector", "bo", "--method", "KAPE 1.3 triage, write-blocked", "--collected-at", "2026-10-14T09:30:00Z", "--notes", "first responder"];
	const pushed = await as(["push", "--case", "ir-cli", "--file", triage, ...intake]);
	assert.equal(pushed.status, 0, pushed.out);
	const m = pushed.out.match(/pushed: (\S+) \((\d+) bytes, SHA-256 ([0-9a-f]{64})\) — content hash signed by bo, intake recorded/);
	assert.ok(m, pushed.out);
	const [, triageId, , triageSha] = m;
	assert.equal(triageSha, await sha256Hex(triageBytes));
	// ana's browser code opens and verifies what the native client sealed and signed.
	const anaTrust = await trustOf(dev, ana);
	const keyed = (await api(dev.base, "POST", `${ev.base}/files/keys`, { email: ana.email, body: { ids: [triageId] } })).json.keys[triageId];
	assert.equal(await ev.sealer.openFileName(triageId, (await api(dev.base, "GET", `${ev.base}/files/changes?since=0`, { email: ana.email })).json.changes.find((c: { data: { file?: { id: string } } }) => c.data.file?.id === triageId).data.file.name), "triage.txt", "the name, sealed into its place under the case key");
	const hashCheck = await checkContentHash(ev.sealer.priv, anaTrust, ev.area, triageId, 1, keyed.hash, { sha256: triageSha, size: triageBytes.length });
	assert.deepEqual([hashCheck.status, (hashCheck as { signer?: string }).signer], ["verified", "bo"], `TS verifies the Rust signature: ${JSON.stringify(hashCheck)}`);
	const intakeCheck = await checkIntake(ev.sealer.priv, anaTrust, ev.area, triageId, keyed.intake);
	assert.equal(intakeCheck.status, "verified", JSON.stringify(intakeCheck));
	assert.deepEqual((({ source, collector, method, collectedAt, notes }) => ({ source, collector, method, collectedAt, notes }))((intakeCheck as { record: Record<string, string> }).record), { source: "laptop WS-042, disk 0", collector: "bo", method: "KAPE 1.3 triage, write-blocked", collectedAt: "2026-10-14T09:30:00Z", notes: "first responder" });
	const record = await openContentHash(ev.sealer.priv, ev.area, triageId, 1, keyed.hash);
	const stamps = (await api(dev.base, "GET", `${ev.base}/files/${triageId}/stamps`, { email: ana.email })).json;
	assert.equal(stamps.versions[0].imprint, await stampImprint(record!.signature), "the timestamp imprint: SHA-256 of bo's signature, as the browser computes it");

	// ── 3. pull: what the uploader signed, checked before anything is written ─
	const memory = enc.encode("MEMORY.RAW — 4 GiB in production; a token of it here");
	{
		const ck = newContentKey();
		const f = await ev.sealer.newFile("memory.raw", "application/octet-stream", ck);
		const r = await post(ana, `${ev.base}/files`, { ...f.fields, size: String(memory.length), ...(await signedHashStamped(ana, ev.sealer, f.id, 1, memory)), intake: await signedIntake(ana, ev.sealer, f.id, { source: "WS-042 RAM", method: "winpmem 4.0" }) }, await sealWith(await importContentKey(ck), memory));
		assert.equal(r.status, 200, JSON.stringify(r.json));
		const out = path.join(home, "memory.raw");
		const got = await as(["pull", "--case", "ir-cli", "--id", f.id, "--out", out]);
		assert.equal(got.status, 0, got.out);
		assert.match(got.out, /content verified — exactly the bytes ana signed/, "TS signed, Rust verified");
		assert.match(got.out, /intake verified \(signed by ana\): from WS-042 RAM — collected by ana \(winpmem 4\.0\)/);
		assert.ok(fs.readFileSync(out).equals(Buffer.from(memory)), "byte for byte");
	}
	{
		// ana vouches for OTHER bytes than the ones stored (a swap, or a mistake).
		const ck = newContentKey();
		const f = await ev.sealer.newFile("swapped.bin", "application/octet-stream", ck);
		const stored = enc.encode("what the server holds");
		const r = await post(ana, `${ev.base}/files`, { ...f.fields, size: String(stored.length), ...(await signedHashStamped(ana, ev.sealer, f.id, 1, enc.encode("what ana collected"))), intake: await signedIntake(ana, ev.sealer, f.id) }, await sealWith(await importContentKey(ck), stored));
		assert.equal(r.status, 200);
		const out = path.join(home, "swapped.bin");
		const got = await as(["pull", "--case", "ir-cli", "--id", f.id, "--out", out]);
		assert.notEqual(got.status, 0);
		assert.match(got.out, /does NOT match what ana signed/);
		assert.ok(!fs.existsSync(out) && !fs.existsSync(`${out}.part`), "nothing written");
	}
	{
		// dee's evidence: signed, but by someone bo never verified.
		const ck = newContentKey();
		const f = await ev.sealer.newFile("dee.log", "text/plain", ck);
		const plain = enc.encode("dee's collection log");
		const r = await post(dee, `${ev.base}/files`, { ...f.fields, size: String(plain.length), ...(await signedHashStamped(dee, ev.sealer, f.id, 1, plain)), intake: await signedIntake(dee, ev.sealer, f.id) }, await sealWith(await importContentKey(ck), plain));
		assert.equal(r.status, 200);
		const out = path.join(home, "dee.log");
		const refused = await as(["pull", "--case", "ir-cli", "--id", f.id, "--out", out]);
		assert.notEqual(refused.status, 0);
		assert.match(refused.out, /signed by dee, not verified: dee is not an identity you verified/);
		assert.match(refused.out, /--accept-unverified/);
		assert.ok(!fs.existsSync(out), "not written without the switch");
		const accepted = await as(["pull", "--case", "ir-cli", "--id", f.id, "--out", out, "--accept-unverified"]);
		assert.equal(accepted.status, 0, accepted.out);
		assert.ok(fs.readFileSync(out).equals(Buffer.from(plain)));
	}

	// ── 4. A large evidence file: GC01 frames under the case key, signed ──
	const big = Buffer.alloc(49 * 1024 * 1024);
	for (let i = 0; i < big.length; i += 4096) big.writeUInt32BE(i, i);
	const bigPath = path.join(home, "disk.E01");
	fs.writeFileSync(bigPath, big);
	const bigPush = await as(["push", "--case", "ir-cli", "--file", bigPath, ...intake]);
	assert.equal(bigPush.status, 0, bigPush.out);
	const bm = bigPush.out.match(/pushed: (\S+) \(\d+ bytes in 7 parts, SHA-256 ([0-9a-f]{64})\) — content hash signed by bo, intake recorded/);
	assert.ok(bm, bigPush.out);
	const bigKeys = (await api(dev.base, "POST", `${ev.base}/files/keys`, { email: ana.email, body: { ids: [bm[1]] } })).json.keys[bm[1]];
	assert.equal((await checkContentHash(ev.sealer.priv, anaTrust, ev.area, bm[1], 1, bigKeys.hash, { sha256: bm[2], size: big.length })).status, "verified", "the multipart completion carried the signed record");
	const bigOut = path.join(home, "disk-back.E01");
	const bigPull = await as(["pull", "--case", "ir-cli", "--id", bm[1], "--out", bigOut]);
	assert.equal(bigPull.status, 0, bigPull.out);
	assert.match(bigPull.out, /content verified — exactly the bytes bo signed/);
	assert.ok(fs.readFileSync(bigOut).equals(big), "49 MiB, byte for byte");
	fs.rmSync(bigPath);
	fs.rmSync(bigOut);

	// ── 5. ls opens names in the case; a read grant reads and cannot push ─
	const ls = await as(["ls", "--case", "ir-cli"]);
	assert.equal(ls.status, 0, ls.out);
	for (const name of ["triage.txt", "memory.raw", "swapped.bin", "dee.log", "disk.E01"]) assert.match(ls.out, new RegExp(name.replace(".", "\\.")), `${name}, opened in its place`);
	{
		const ck = newContentKey();
		const f = await wk.sealer.newFile("plan.md", "text/markdown", ck);
		const plain = enc.encode("# containment plan");
		assert.equal((await post(ana, `${wk.base}/files`, { ...f.fields, size: String(plain.length) }, await sealWith(await importContentKey(ck), plain))).status, 200);
		const out = path.join(home, "plan.md");
		const got = await as(["pull", "--case", "wk-cli", "--id", f.id, "--out", out]);
		assert.equal(got.status, 0, got.out);
		assert.match(got.out, /content not signed by its uploader/, "a working case: unsigned is said, and written");
		assert.ok(fs.readFileSync(out).equals(Buffer.from(plain)));
		const ro = await as(["push", "--case", "wk-cli", "--file", triage]);
		assert.notEqual(ro.status, 0);
		assert.match(ro.out, /http 403/, `the server refuses a read grant's push: ${ro.out}`);
	}

	console.log("ok  api:client-cases — the native client in a case: grants open only through a signature the member can check (an unverified lead's refused), evidence pushes carry an intake record and a content hash signed in Rust and verified in TS (with its timestamp imprint), pulls verify a TS signature before writing and refuse a mismatched record or unverified evidence, a 49 MiB evidence file in signed GC01 frames, a read grant refused a push");
} finally {
	await dev.close();
}
