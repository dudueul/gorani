// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:replica — the replica protocol (commit 39a, clients/core/src/replica.rs):
 * what the Windows (Cloud Files) and macOS (File Provider) shells call,
 * proven against the real worker here, so each platform's own suite can
 * prove its placeholder layer against the in-memory twin. Through
 * `gorani-sync replica` (JSON lines):
 *
 *   1. unlocked with the DEVICE copy; the tree BY ID — folders, files in
 *      them, a sample flagged, a name that does not open in its place shown
 *      as unverified (and flagged so);
 *   2. reads of ONE version: whole, a range across GC01 frames of a 49 MiB
 *      file; an old version is refused, not answered with new bytes; a
 *      sample never;
 *   3. a new file from a path — whole, and 49 MiB in frames — sealed into
 *      its place and folder: the BROWSER's code opens what it sent;
 *   4. a new version from a path — whole, and large in frames (a version
 *      through the multipart path); a file the browser saved meanwhile
 *      makes a conflict copy, the browser's version stands;
 *   5. mkdir, rename and move, trash (a folder only when empty); a change
 *      made elsewhere shows on the next poll;
 *   6. an evidence case: read-only, each file checked against its
 *      uploader's signed hash before a byte is served.
 *
 * Skipped when the CLI is not built (cargo build -p gorani-client-core).
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "./_dev.mjs";
import { member, openCase, signedHashStamped, signedIntake } from "../lib/team.mjs";
import { placedShape } from "../lib/placed.mjs";
import { deriveRecordKey, macRecord } from "../../web/src/vault/records.ts";
import { sampleType } from "../../web/src/vault/samples.ts";
import { importContentKey, newContentKey, openWith, sealWith } from "../../web/src/vault/vault-crypto.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SYNC = path.join(ROOT, "target/debug/gorani-sync");
if (!fs.existsSync(SYNC)) {
	console.log("skip  api:replica — build first: cargo build -p gorani-client-core");
	process.exit(0);
}

const dev = await suiteDev();
const home = path.join(ROOT, "tests/output/replica-home");
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true });
const enc = new TextEncoder();
const MiB = 1024 * 1024;

type Item = { id: string; parent: string; name: string; kind: "file" | "dir"; size: number; version: number; sample: boolean; nameVerified: boolean };
type Answer = Record<string, unknown> & { error?: string; code?: string };

function cli(args: string[]): Promise<{ status: number; out: string }> {
	const c = spawn(SYNC, args, { cwd: ROOT, env: { ...process.env, HOME: home } });
	let out = "";
	c.stdout.on("data", (d) => (out += d));
	c.stderr.on("data", (d) => (out += d));
	return new Promise((r) => c.on("exit", (code) => r({ status: code ?? 1, out })));
}

/** The replica over JSON lines: one request, one answer. */
function replica(args: string[]) {
	const c = spawn(SYNC, ["replica", ...args], { cwd: ROOT, env: { ...process.env, HOME: home } });
	let buf = "";
	let err = "";
	const queue: Answer[] = [];
	const waiting: ((a: Answer) => void)[] = [];
	const deliver = (a: Answer) => (waiting.length ? waiting.shift()!(a) : queue.push(a));
	c.stdout.on("data", (d) => {
		buf += d;
		for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
			const line = buf.slice(0, i);
			buf = buf.slice(i + 1);
			if (line.trim()) deliver(JSON.parse(line));
		}
	});
	c.stderr.on("data", (d) => (err += d));
	const exited = new Promise<number>((r) => c.on("exit", (code) => r(code ?? 1)));
	void exited.then(() => {
		while (waiting.length) waiting.shift()!({ error: `the replica exited: ${err}`, code: "gone" });
	});
	const next = () => new Promise<Answer>((r) => (queue.length ? r(queue.shift()!) : waiting.push(r)));
	return {
		ready: next(),
		ask: (req: Record<string, unknown>) => {
			c.stdin.write(`${JSON.stringify(req)}\n`);
			return next();
		},
		stderr: () => err,
		close: async () => {
			c.stdin.end();
			return exited;
		},
	};
}
const ok = (a: Answer, what: string) => {
	assert.ok(!a.error, `${what}: ${a.error}`);
	return a;
};

async function post(who: { email: string }, p: string, fields: Record<string, string>, file: Uint8Array) {
	const boundary = `r${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const tail = enc.encode(`\r\n--${boundary}--\r\n`);
	const r = await fetch(`${dev.base}${p}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...tail]) });
	return { status: r.status, json: (await r.json().catch(() => null)) as Record<string, unknown> | null };
}

/** A recognisable large file: every 4 bytes, its own offset. */
function pattern(size: number, salt: number): Buffer {
	const b = Buffer.alloc(size);
	for (let i = 0; i + 4 <= size; i += 4) b.writeUInt32BE((i ^ salt) >>> 0, i);
	return b;
}

try {
	// ── 0. A member enrolled on this computer, and what the web app put there ──
	const ana = await member(dev, "ana", "lead");
	const own = `/api/v1/members/ana`;
	ana.settings.stores.files.mac = await macRecord(await deriveRecordKey(ana.root), "files", ana.settings.stores.files);
	assert.equal((await api(dev.base, "PUT", `${own}/vault`, { email: ana.email, body: { settings: ana.settings } })).status, 200);
	const profile = path.join(home, "ana.json");
	const setup = await cli(["setup", "--server", dev.base, "--member", "ana", "--name", "ana's workstation", "--secret", ana.recoveryCode, "--device-secret", "f".repeat(64), "--dev-email", ana.email, "--profile", profile]);
	assert.equal(setup.status, 0, setup.out);
	const upload = async (name: string, plain: Uint8Array, extra: Record<string, string> = {}, type = "text/plain") => {
		const ck = newContentKey();
		const f = await ana.sealer.newFile(name, type, ck);
		const r = await post(ana, `${own}/files`, { ...f.fields, size: String(plain.length), ...extra }, await sealWith(await importContentKey(ck), plain));
		assert.equal(r.status, 200, JSON.stringify(r.json));
		return f.id;
	};
	const reportId = await upload("report.txt", enc.encode("draft 1"));
	const notesId = "notes-folder-0001";
	assert.equal((await api(dev.base, "POST", `${own}/files/folders`, { email: ana.email, body: { id: notesId, name: await ana.sealer.folderName(notesId, "notes") } })).status, 200);
	const todoId = await upload("todo.md", enc.encode("- contain WS-042"), { folder_id: notesId });
	const sampleId = await upload("invoice.pdf.exe", enc.encode("MZ"), { sample: "1" }, sampleType("application/x-msdownload"));
	const mintedId = await upload("honest.txt", enc.encode("x"));
	assert.equal((await api(dev.base, "PATCH", `${own}/files/${mintedId}`, { email: ana.email, body: { name: placedShape("payroll.xlsx") } })).status, 200);
	const big = pattern(49 * MiB, 0);
	fs.writeFileSync(path.join(home, "disk.img"), big);
	assert.equal((await cli(["push", "--file", path.join(home, "disk.img"), "--profile", profile, "--dev-email", ana.email])).status, 0);

	const webRead = async (id: string) => {
		const r = await fetch(`${dev.base}${own}/files/${id}`, { headers: { "x-gorani-dev-email": ana.email } });
		assert.equal(r.status, 200);
		const version = Number(r.headers.get("x-gorani-version"));
		const key = await ana.sealer.openFileKey(id, version, r.headers.get("x-gorani-ck"));
		return { version, plain: Buffer.from(await openWith(key, new Uint8Array(await r.arrayBuffer()))) };
	};
	const webList = async () => {
		const l = (await api(dev.base, "GET", `${own}/files/list?folder=all`, { email: ana.email })).json;
		return Promise.all(l.files.map(async (f: { id: string; name: string; folder: string | null; version: number; size: number }) => ({ ...f, opened: await ana.sealer.openFileName(f.id, f.name).catch(() => null) })));
	};

	// ── 1. The tree, by id ──
	const r = replica(["--profile", profile, "--dev-email", ana.email]);
	const ready = await r.ready;
	assert.deepEqual([ready.ready, ready.readOnly], ["ana", null], `unlocked with the device copy: ${JSON.stringify(ready)} ${r.stderr()}`);
	const items = async () => (ok(await r.ask({ op: "items" }), "items").items as Item[]);
	let all = await items();
	const by = (pred: (i: Item) => boolean) => all.find(pred)!;
	const disk = by((i) => i.name === "disk.img");
	assert.deepEqual([by((i) => i.id === notesId).kind, by((i) => i.id === todoId).parent, by((i) => i.id === reportId).parent], ["dir", notesId, ""], "folders, and files by their folder's id");
	assert.equal(by((i) => i.id === sampleId).sample, true, "a sample is listed, flagged");
	const minted = by((i) => i.id === mintedId);
	assert.deepEqual([minted.name, minted.nameVerified], [`⚠ unverified ‹${mintedId}›`, false], "a minted name never shows as what it claims");
	assert.deepEqual([disk.size, disk.version], [big.length, 1]);

	// ── 2. Reads of one version ──
	const read = async (id: string, version: number, offset: number, len: number) => {
		const a = await r.ask({ op: "read", id, version, offset, len });
		return a.error ? a : { data: Buffer.from(String(a.data), "base64") };
	};
	assert.equal(((await read(reportId, 1, 0, 100)) as { data: Buffer }).data.toString(), "draft 1");
	const at = 2 * 8 * MiB - 4096;
	assert.ok(((await read(disk.id, 1, at, 300_000)) as { data: Buffer }).data.equals(big.subarray(at, at + 300_000)), "a range across a frame boundary, byte for byte");
	const stale = (await read(reportId, 7, 0, 10)) as Answer;
	assert.equal(stale.code, "io");
	assert.match(String(stale.error), /changed on the server/, "a placeholder for another version is not filled with these bytes");
	assert.equal(((await read(sampleId, 1, 0, 10)) as Answer).code, "denied", "a sample is never readable raw");

	// ── 3. New files from paths ──
	const local = (name: string, bytes: Uint8Array) => {
		const p = path.join(home, name);
		fs.writeFileSync(p, bytes);
		return p;
	};
	const made = ok(await r.ask({ op: "create", parent: notesId, name: "findings.md", path: local("findings.md", enc.encode("# Findings\n")) }), "create").item as Item;
	assert.deepEqual([made.parent, made.version, made.size], [notesId, 1, 11]);
	const wl = (await webList()).find((f) => f.id === made.id)!;
	assert.deepEqual([wl.opened, wl.folder], ["findings.md", notesId], "sealed into its place and folder");
	assert.equal((await webRead(made.id)).plain.toString(), "# Findings\n");
	const big2 = pattern(49 * MiB + 77, 0x5a5a);
	const madeBig = ok(await r.ask({ op: "create", parent: "", name: "image.e01", path: local("image.e01", big2) }), "create large").item as Item;
	assert.equal(madeBig.size, big2.length);
	assert.ok(((await read(madeBig.id, 1, 6 * 8 * MiB - 10, 20)) as { data: Buffer }).data.equals(big2.subarray(6 * 8 * MiB - 10, 6 * 8 * MiB + 10)), "49 MiB in frames, read back across a boundary");
	assert.equal((await r.ask({ op: "create", parent: "", name: "bad/name", path: local("x", enc.encode("x")) })).code, "denied");

	// ── 4. New versions; a conflict ──
	const s1 = ok(await r.ask({ op: "save", id: made.id, base: 1, path: local("findings.md", enc.encode("# Findings\nWS-042 contained.\n")) }), "save") as { outcome: string; item: Item };
	assert.deepEqual([s1.outcome, s1.item.version], ["version", 2]);
	assert.deepEqual([(await webRead(made.id)).version, (await webRead(made.id)).plain.toString()], [2, "# Findings\nWS-042 contained.\n"], "the next version, which the browser opens");
	const big3 = pattern(49 * MiB + 77, 0x7777);
	const s2 = ok(await r.ask({ op: "save", id: madeBig.id, base: 1, path: local("image.e01", big3) }), "save large") as { outcome: string; item: Item };
	assert.deepEqual([s2.outcome, s2.item.version], ["version", 2], "a large file's next version, through the multipart path");
	assert.ok(((await read(madeBig.id, 2, 3 * 8 * MiB, 64)) as { data: Buffer }).data.equals(big3.subarray(3 * 8 * MiB, 3 * 8 * MiB + 64)));
	// The browser saves v2 of report.txt; the replica, still at v1, saves too.
	{
		const ck = newContentKey();
		const plain = enc.encode("draft 2 (from the browser)");
		const p = await post(ana, `${own}/files/${reportId}/versions`, { base_version: "1", ck: await ana.sealer.fileKey(reportId, 2, ck), type: await ana.sealer.fileType(reportId, 2, "text/plain"), size: String(plain.length) }, await sealWith(await importContentKey(ck), plain));
		assert.equal(p.status, 200, JSON.stringify(p.json));
	}
	const s3 = ok(await r.ask({ op: "save", id: reportId, base: 1, path: local("report.txt", enc.encode("draft 2 (from the workstation)")) }), "save stale") as { outcome: string; copy: Item };
	assert.equal(s3.outcome, "conflict");
	assert.match(s3.copy.name, /^report \(conflict \d{4}-\d\d-\d\d \d{6}\)\.txt$/);
	assert.equal((await webRead(reportId)).plain.toString(), "draft 2 (from the browser)", "the browser's save stands");
	assert.equal((await webRead(s3.copy.id)).plain.toString(), "draft 2 (from the workstation)", "nothing lost");

	// ── 5. Folders, renames, the Trash, changes from elsewhere ──
	const out = ok(await r.ask({ op: "mkdir", parent: "", name: "out" }), "mkdir").item as Item;
	ok(await r.ask({ op: "rename", id: made.id, parent: out.id, name: "findings-final.md" }), "rename + move");
	const moved = (await webList()).find((f) => f.id === made.id)!;
	assert.deepEqual([moved.opened, moved.folder], ["findings-final.md", out.id], "sealed again in its place, in its new folder");
	assert.equal((await r.ask({ op: "trash", id: out.id })).code, "not_empty");
	ok(await r.ask({ op: "trash", id: made.id }), "trash file");
	ok(await r.ask({ op: "trash", id: out.id }), "trash folder");
	assert.ok(!(await webList()).some((f) => f.id === made.id), "trashed");
	ok(await r.ask({ op: "poll" }), "poll");
	const fromWeb = await upload("from-the-web.txt", enc.encode("hello"));
	assert.equal((ok(await r.ask({ op: "poll" }), "poll") as { changed: boolean }).changed, true, "a change made elsewhere");
	all = await items();
	assert.ok(all.some((i) => i.id === fromWeb), "…is in the next listing");
	assert.equal(await r.close(), 0);

	// ── 6. An evidence case ──
	const ev = await openCase(dev, ana, "ir-replica", "Replicated evidence", [], "evidence");
	const evUpload = async (name: string, stored: Uint8Array, signedFor: Uint8Array) => {
		const ck = newContentKey();
		const f = await ev.sealer.newFile(name, "application/octet-stream", ck);
		const p = await post(ana, `${ev.base}/files`, { ...f.fields, size: String(stored.length), ...(await signedHashStamped(ana, ev.sealer, f.id, 1, signedFor)), intake: await signedIntake(ana, ev.sealer, f.id) }, await sealWith(await importContentKey(ck), stored));
		assert.equal(p.status, 200, JSON.stringify(p.json));
		return f.id;
	};
	const mem = enc.encode("memory image");
	const memId = await evUpload("memory.raw", mem, mem);
	const swappedId = await evUpload("swapped.bin", enc.encode("what the server holds"), enc.encode("what ana collected"));
	const e = replica(["--profile", profile, "--dev-email", ana.email, "--case", "ir-replica"]);
	const eready = await e.ready;
	assert.equal(eready.ready, "case:ir-replica", JSON.stringify(eready) + e.stderr());
	assert.match(String(eready.readOnly), /read-only/);
	const er = async (id: string) => e.ask({ op: "read", id, version: 1, offset: 0, len: 100 });
	assert.equal(Buffer.from(String((ok(await er(memId), "evidence read") as { data: string }).data), "base64").toString(), "memory image");
	const sw = await er(swappedId);
	assert.equal(sw.code, "denied", "a record that vouches for other bytes refuses the read");
	assert.match(String(sw.error), /does NOT match what ana signed/);
	assert.equal((await e.ask({ op: "mkdir", parent: "", name: "x" })).code, "read_only", "no writes into evidence through a replica");
	assert.equal(await e.close(), 0);

	console.log("ok  api:replica — the tree by id, reads of one version (frames, stale refused, samples never), new files and versions from paths (whole and framed), conflicts kept, folders/renames/trash, polling, evidence read-only and checked");
} finally {
	await dev.close();
}
