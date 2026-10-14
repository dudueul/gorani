// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:linux-shell — the Linux shell (commit 33d, docs/DESKTOP.md): the
 * client core's sync engine, driven two ways against the real worker.
 *
 *   A. `gorani-mount script` — the engine over JSON lines, no FUSE needed
 *      (the doc's pattern: the engine first, against wrangler dev):
 *      unlocked with the DEVICE copy (no password typed); the tree from the
 *      listing, names opened in their places, an unsealed name shown as
 *      unverified; whole and chunked reads (a range in the middle of a
 *      49 MiB GC01 file fetches only its frames); writes sealed on close as
 *      a new file or the next version, which the BROWSER's code opens; a
 *      file that changed elsewhere while open becomes a conflict copy —
 *      nothing overwritten; rename/move, mkdir/rmdir, trash; a sample never
 *      readable; an evidence case read-only, its files checked against the
 *      uploader's signature at open (a mismatched record refused).
 *   B. a real FUSE mount, where the machine allows one (/dev/fuse and root
 *      here): readdir, read, write, rename, unlink through the kernel —
 *      with async fs calls only (this process may run the S3 stub the
 *      mount's requests end up at; a sync call would freeze it).
 *
 * Skipped when the binaries are not built (cargo build -p gorani-client-core -p gorani-linux).
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "./_dev.mjs";
import { member, openCase, signedHashStamped, signedIntake, vouch } from "../lib/team.mjs";
import { placedShape } from "../lib/placed.mjs";
import { deriveRecordKey, macRecord } from "../../web/src/vault/records.ts";
import { sampleType } from "../../web/src/vault/samples.ts";
import { importContentKey, newContentKey, openWith, sealWith } from "../../web/src/vault/vault-crypto.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SYNC = path.join(ROOT, "target/debug/gorani-sync");
const MOUNT = path.join(ROOT, "target/debug/gorani-mount");
if (!fs.existsSync(SYNC) || !fs.existsSync(MOUNT)) {
	console.log("skip  api:linux-shell — build first: cargo build -p gorani-client-core -p gorani-linux");
	process.exit(0);
}

const dev = await suiteDev();
const home = path.join(ROOT, "tests/output/linux-shell-home");
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true });
const enc = new TextEncoder();
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

type Answer = Record<string, unknown> & { error?: string; errno?: number };

/** The CLI, spawned async (a spawnSync would freeze this process's S3 stub mid-push). */
function cli(args: string[]): Promise<{ status: number; out: string }> {
	const c = spawn(SYNC, args, { cwd: ROOT, env: { ...process.env, HOME: home } });
	let out = "";
	c.stdout.on("data", (d) => (out += d));
	c.stderr.on("data", (d) => (out += d));
	return new Promise((r) => c.on("exit", (code) => r({ status: code ?? 1, out })));
}

/** The engine over JSON lines: one request, one answer. */
function shell(args: string[]) {
	const c = spawn(MOUNT, ["script", ...args], { cwd: ROOT, env: { ...process.env, HOME: home } });
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
		while (waiting.length) waiting.shift()!({ error: `the shell exited: ${err}`, errno: -1 });
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

/** A multipart upload as the browser's bridge posts it. */
async function post(who: { email: string }, p: string, fields: Record<string, string>, file: Uint8Array) {
	const boundary = `l${Math.random().toString(16).slice(2)}`;
	const head = enc.encode(Object.entries(fields).map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`).join("") + `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="s"\r\n\r\n`);
	const tail = enc.encode(`\r\n--${boundary}--\r\n`);
	const r = await fetch(`${dev.base}${p}`, { method: "POST", headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "x-gorani-dev-email": who.email }, body: new Uint8Array([...head, ...file, ...tail]) });
	return { status: r.status, json: (await r.json().catch(() => null)) as Record<string, unknown> | null };
}

try {
	// ── 0. A member with a vault the CLI accepts, enrolled on this computer ─
	const ana = await member(dev, "ana", "lead");
	const own = `/api/v1/members/ana`;
	// (The web app authenticates the files store record on first open; the
	// native client refuses one that is not — commit 24, O3.)
	ana.settings.stores.files.mac = await macRecord(await deriveRecordKey(ana.root), "files", ana.settings.stores.files);
	assert.equal((await api(dev.base, "PUT", `${own}/vault`, { email: ana.email, body: { settings: ana.settings } })).status, 200);
	const profile = path.join(home, "ana.json");
	const setup = await cli(["setup", "--server", dev.base, "--member", "ana", "--name", "ana's laptop", "--secret", ana.recoveryCode, "--device-secret", "c".repeat(64), "--dev-email", ana.email, "--profile", profile]);
	assert.equal(setup.status, 0, setup.out);

	// What the web app put there: a file, a folder with a file, a sample.
	const upload = async (name: string, plain: Uint8Array, extra: Record<string, string> = {}, type = "text/plain") => {
		const ck = newContentKey();
		const f = await ana.sealer.newFile(name, type, ck);
		const r = await post(ana, `${own}/files`, { ...f.fields, size: String(plain.length), ...extra }, await sealWith(await importContentKey(ck), plain));
		assert.equal(r.status, 200, JSON.stringify(r.json));
		return f.id;
	};
	const report = enc.encode("Quarterly report — draft 1");
	const reportId = await upload("report.txt", report);
	const notesId = "notes-folder-0001";
	assert.equal((await api(dev.base, "POST", `${own}/files/folders`, { email: ana.email, body: { id: notesId, name: await ana.sealer.folderName(notesId, "notes") } })).status, 200);
	await upload("todo.md", enc.encode("- contain WS-042"), { folder_id: notesId });
	await upload("invoice.pdf.exe", enc.encode("MZ — a dropper"), { sample: "1" }, sampleType("application/x-msdownload"));
	// A name the server minted (shape-only, sealed nowhere): it must not show as what it claims.
	const mintedId = await upload("honest.txt", enc.encode("x"));
	assert.equal((await api(dev.base, "PATCH", `${own}/files/${mintedId}`, { email: ana.email, body: { name: placedShape("payroll.xlsx") } })).status, 200);
	// A large file, pushed by the CLI in GC01 frames.
	const big = Buffer.alloc(49 * 1024 * 1024);
	for (let i = 0; i < big.length; i += 4) big.writeUInt32BE(i, i);
	fs.writeFileSync(path.join(home, "disk.img"), big);
	const pushed = await cli(["push", "--file", path.join(home, "disk.img"), "--profile", profile, "--dev-email", ana.email]);
	assert.equal(pushed.status, 0, pushed.out);
	assert.match(pushed.out, /in 7 parts/, "the device unlock (no --secret) pushed it chunked");
	fs.rmSync(path.join(home, "disk.img"));

	/** What the web app reads back: the living version's plaintext and name. */
	const webRead = async (id: string) => {
		const r = await fetch(`${dev.base}${own}/files/${id}`, { headers: { "x-gorani-dev-email": ana.email } });
		assert.equal(r.status, 200);
		const version = Number(r.headers.get("x-gorani-version"));
		const key = await ana.sealer.openFileKey(id, version, r.headers.get("x-gorani-ck"));
		return { version, plain: Buffer.from(await openWith(key, new Uint8Array(await r.arrayBuffer()))) };
	};
	const webList = async () => {
		const l = (await api(dev.base, "GET", `${own}/files/list?folder=all`, { email: ana.email })).json;
		return Promise.all(l.files.map(async (f: { id: string; name: string; folder: string | null; version: number }) => ({ ...f, opened: await ana.sealer.openFileName(f.id, f.name).catch(() => null) })));
	};

	// ── A. The engine, scripted ──────────────────────────────────────────
	const sh = shell(["--profile", profile, "--dev-email", ana.email]);
	const ready = await sh.ready;
	assert.equal(ready.ready, "ana", `unlocked with the device copy: ${JSON.stringify(ready)} ${sh.stderr()}`);
	assert.equal(ready.readOnly, null);
	const top = ok(await sh.ask({ op: "ls", path: "/" }), "ls /").entries as { name: string; kind: string; size: number }[];
	const names = top.map((e) => e.name);
	for (const n of ["report.txt", "notes", "invoice.pdf.exe", "disk.img"]) assert.ok(names.includes(n), `${n} listed: ${names}`);
	assert.ok(names.includes(`⚠ unverified ‹${mintedId}›`) && !names.includes("payroll.xlsx"), "a minted name is shown as unverified, never as what it claims");
	assert.equal(top.find((e) => e.name === "notes")!.kind, "dir");
	assert.deepEqual((ok(await sh.ask({ op: "ls", path: "/notes" }), "ls /notes").entries as { name: string }[]).map((e) => e.name), ["todo.md"]);
	// Reads: whole, and a range in the middle of the chunked file.
	assert.equal(Buffer.from((ok(await sh.ask({ op: "cat", path: "/report.txt" }), "cat") as { b64: string }).b64, "base64").toString(), "Quarterly report — draft 1");
	const at = 3 * 8 * 1024 * 1024 + 1234;
	const slice = Buffer.from((ok(await sh.ask({ op: "read", path: "/disk.img", offset: at, len: 70_000 }), "range read") as { b64: string }).b64, "base64");
	assert.ok(slice.equals(big.subarray(at, at + 70_000)), "a range across a frame boundary of the GC01 file, byte for byte");
	const sample = await sh.ask({ op: "cat", path: "/invoice.pdf.exe" });
	assert.equal(sample.errno, 13, "a sample is never readable raw");
	assert.match(String(sample.error), /malware sample/);

	// Writes: a new file in a folder, then its next version — the browser's code opens both.
	ok(await sh.ask({ op: "put", path: "/notes/draft.md", b64: b64(enc.encode("# Draft\nfirst")) }), "new file");
	let draft = (await webList()).find((f) => f.opened === "draft.md");
	assert.ok(draft && draft.folder === notesId, "sealed into its place, in its folder");
	assert.equal((await webRead(draft.id)).plain.toString(), "# Draft\nfirst");
	ok(await sh.ask({ op: "put", path: "/notes/draft.md", b64: b64(enc.encode("# Draft\nsecond")) }), "overwrite");
	const v2 = await webRead(draft.id);
	assert.deepEqual([v2.version, v2.plain.toString()], [2, "# Draft\nsecond"], "the next version, not a new file");

	// A conflict: open report.txt for writing, the web app saves v2 meanwhile, then this one closes.
	const fh = (ok(await sh.ask({ op: "open", path: "/report.txt", write: true }), "open rw") as { fh: number }).fh;
	{
		const ck = newContentKey();
		const plain = enc.encode("Quarterly report — draft 2 (from the browser)");
		const r = await post(ana, `${own}/files/${reportId}/versions`, { base_version: "1", ck: await ana.sealer.fileKey(reportId, 2, ck), type: await ana.sealer.fileType(reportId, 2, "text/plain"), size: String(plain.length) }, await sealWith(await importContentKey(ck), plain));
		assert.equal(r.status, 200, JSON.stringify(r.json));
	}
	ok(await sh.ask({ op: "write", fh, offset: 0, b64: b64(enc.encode("Quarterly report — edited on the laptop")) }), "write");
	ok(await sh.ask({ op: "close", fh }), "close (the upload)");
	const afterConflict = await webList();
	assert.equal((await webRead(reportId)).plain.toString(), "Quarterly report — draft 2 (from the browser)", "the browser's save stands");
	const copy = afterConflict.find((f) => /^report \(conflict \d{4}-\d\d-\d\d \d{6}\)\.txt$/.test(f.opened ?? ""));
	assert.ok(copy, `the laptop's bytes became a conflict copy: ${afterConflict.map((f) => f.opened)}`);
	assert.equal((await webRead(copy.id)).plain.toString(), "Quarterly report — edited on the laptop", "nothing lost");
	assert.match(sh.stderr(), /changed elsewhere while it was open/);

	// Rename and move; folders; trash.
	ok(await sh.ask({ op: "mv", from: "/notes/draft.md", to: "/draft-final.md" }), "mv");
	draft = (await webList()).find((f) => f.id === draft!.id);
	assert.deepEqual([draft!.opened, draft!.folder], ["draft-final.md", null], "renamed (sealed again, in its place) and moved to the top");
	ok(await sh.ask({ op: "mkdir", path: "/out" }), "mkdir");
	ok(await sh.ask({ op: "put", path: "/out/x.txt", b64: b64(enc.encode("x")) }), "put in new folder");
	assert.equal((await sh.ask({ op: "rmdir", path: "/out" })).errno, 39, "a folder with something in it is not removed");
	ok(await sh.ask({ op: "rm", path: "/out/x.txt" }), "rm");
	ok(await sh.ask({ op: "rmdir", path: "/out" }), "rmdir");
	assert.ok(!(await webList()).some((f) => f.opened === "x.txt"), "trashed");
	ok(await sh.ask({ op: "truncate", path: "/draft-final.md", size: 2 }), "truncate");
	assert.equal((await webRead(draft!.id)).plain.toString(), "# ", "truncate is a new version too");
	// Changes made elsewhere arrive on refresh.
	await upload("from-the-web.txt", enc.encode("hello"));
	assert.equal((ok(await sh.ask({ op: "refresh" }), "refresh") as { changed: boolean }).changed, true);
	assert.ok(((ok(await sh.ask({ op: "ls", path: "/" }), "ls") as { entries: { name: string }[] }).entries).some((e) => e.name === "from-the-web.txt"));
	assert.equal(await sh.close(), 0);

	// The evidence case: read-only, every file judged at open.
	const ev = await openCase(dev, ana, "ir-mount", "Mounted evidence", [], "evidence");
	const evUpload = async (name: string, stored: Uint8Array, signedFor: Uint8Array) => {
		const ck = newContentKey();
		const f = await ev.sealer.newFile(name, "application/octet-stream", ck);
		const r = await post(ana, `${ev.base}/files`, { ...f.fields, size: String(stored.length), ...(await signedHashStamped(ana, ev.sealer, f.id, 1, signedFor)), intake: await signedIntake(ana, ev.sealer, f.id) }, await sealWith(await importContentKey(ck), stored));
		assert.equal(r.status, 200, JSON.stringify(r.json));
	};
	const mem = enc.encode("memory image");
	await evUpload("memory.raw", mem, mem);
	await evUpload("swapped.bin", enc.encode("what the server holds"), enc.encode("what ana collected"));
	const es = shell(["--profile", profile, "--dev-email", ana.email, "--case", "ir-mount"]);
	const eready = await es.ready;
	assert.equal(eready.ready, "case:ir-mount", JSON.stringify(eready) + es.stderr());
	assert.match(String(eready.readOnly), /read-only through the mount/);
	assert.equal(Buffer.from((ok(await es.ask({ op: "cat", path: "/memory.raw" }), "evidence cat") as { b64: string }).b64, "base64").toString(), "memory image");
	const swapped = await es.ask({ op: "cat", path: "/swapped.bin" });
	assert.equal(swapped.errno, 13, "a record that vouches for other bytes refuses the open");
	assert.match(String(swapped.error), /does NOT match what ana signed/);
	assert.equal((await es.ask({ op: "put", path: "/new.txt", b64: b64(enc.encode("x")) })).errno, 30, "no writes into evidence through the mount");
	assert.equal(await es.close(), 0);

	// A working case on a READ grant: read-only from the start, not refused at every save.
	const bo = await member(dev, "bo", "analyst", { by: ana });
	await vouch(dev, ana, [bo]);
	const wk = await openCase(dev, ana, "wk-mount", "Shared notes", [[bo, "read"]]);
	{
		const ck = newContentKey();
		const f = await wk.sealer.newFile("plan.md", "text/markdown", ck);
		const plain = enc.encode("# plan");
		assert.equal((await post(ana, `${wk.base}/files`, { ...f.fields, size: String(plain.length) }, await sealWith(await importContentKey(ck), plain))).status, 200);
	}
	const boProfile = path.join(home, "bo.json");
	const boSetup = await cli(["setup", "--server", dev.base, "--member", "bo", "--name", "bo's laptop", "--secret", bo.recoveryCode, "--device-secret", "d".repeat(64), "--dev-email", bo.email, "--profile", boProfile]);
	assert.equal(boSetup.status, 0, boSetup.out);
	const rs = shell(["--profile", boProfile, "--dev-email", bo.email, "--case", "wk-mount"]);
	const rready = await rs.ready;
	assert.equal(rready.ready, "case:wk-mount", JSON.stringify(rready) + rs.stderr());
	assert.match(String(rready.readOnly), /grant on this case is read-only/);
	assert.equal(Buffer.from((ok(await rs.ask({ op: "cat", path: "/plan.md" }), "read grant reads") as { b64: string }).b64, "base64").toString(), "# plan");
	assert.equal((await rs.ask({ op: "put", path: "/new.md", b64: b64(enc.encode("x")) })).errno, 30, "EROFS, before any request is made");
	assert.equal(await rs.close(), 0);

	// ── B. A real FUSE mount ─────────────────────────────────────────────
	const dir = path.join(home, "Gorani");
	fs.mkdirSync(dir);
	const m = spawn(MOUNT, [dir, "--profile", profile, "--dev-email", ana.email], { cwd: ROOT, env: { ...process.env, HOME: home } });
	let mout = "";
	m.stdout.on("data", (d) => (mout += d));
	m.stderr.on("data", (d) => (mout += d));
	const mexit = new Promise<number>((r) => m.on("exit", (c) => r(c ?? 1)));
	const mounted = await Promise.race([
		new Promise<boolean>((r) => {
			const t = setInterval(() => {
				if (/mounted ana at/.test(mout)) {
					clearInterval(t);
					r(true);
				}
			}, 100);
			void mexit.then(() => {
				clearInterval(t);
				r(false);
			});
		}),
		new Promise<boolean>((r) => setTimeout(() => r(false), 30_000)),
	]);
	let fuseNote = "";
	if (!mounted) {
		m.kill("SIGKILL");
		// Not every machine allows FUSE (no /dev/fuse, no privilege): the
		// engine above is the proof there, and this says so plainly.
		assert.match(mout, /mount .*(Operation not permitted|No such file|Permission denied|not found)/, `the mount failed for an unexpected reason: ${mout}`);
		fuseNote = ` (FUSE unavailable here: ${mout.trim().split("\n").pop()})`;
		console.log(`  ${fuseNote.trim()}`);
	} else {
		try {
			const listed = await fsp.readdir(dir);
			for (const n of ["report.txt", "notes", "draft-final.md", "from-the-web.txt", "disk.img"]) assert.ok(listed.includes(n), `${n} through the kernel: ${listed}`);
			assert.equal(await fsp.readFile(path.join(dir, "report.txt"), "utf8"), "Quarterly report — draft 2 (from the browser)");
			assert.equal((await fsp.stat(path.join(dir, "disk.img"))).size, big.length);
			const fd = await fsp.open(path.join(dir, "disk.img"), "r");
			const got = Buffer.alloc(100_000);
			await fd.read(got, 0, got.length, 5 * 8 * 1024 * 1024 - 50_000);
			await fd.close();
			assert.ok(got.equals(big.subarray(5 * 8 * 1024 * 1024 - 50_000, 5 * 8 * 1024 * 1024 + 50_000)), "pread across a frame boundary through FUSE");
			await assert.rejects(fsp.readFile(path.join(dir, "invoice.pdf.exe")), /EACCES/, "a sample, refused by the kernel's answer");
			await fsp.writeFile(path.join(dir, "notes", "via-fuse.txt"), "written through the kernel");
			const vf = (await webList()).find((f) => f.opened === "via-fuse.txt");
			assert.ok(vf && vf.folder === notesId, "a file written through FUSE, sealed into its place");
			assert.equal((await webRead(vf.id)).plain.toString(), "written through the kernel");
			await fsp.rename(path.join(dir, "notes", "via-fuse.txt"), path.join(dir, "via-fuse-moved.txt"));
			const moved = (await webList()).find((f) => f.id === vf.id)!;
			assert.deepEqual([moved.opened, moved.folder], ["via-fuse-moved.txt", null], "renamed and moved through the kernel");
			await fsp.unlink(path.join(dir, "via-fuse-moved.txt"));
			assert.ok(!(await webList()).some((f) => f.id === vf.id), "unlink trashes it");
			await fsp.mkdir(path.join(dir, "made-here"));
			assert.ok((await fsp.readdir(dir)).includes("made-here"));
		} finally {
			m.kill("SIGTERM");
			const code = await Promise.race([mexit, new Promise<number>((r) => setTimeout(() => r(-1), 10_000))]);
			if (code === -1) {
				m.kill("SIGKILL");
				spawnSync("umount", ["-l", dir]);
			}
		}
		assert.match(mout, /unmounted/, `a clean unmount on SIGTERM: ${mout}`);
	}

	console.log(`ok  api:linux-shell — the sync engine (device unlock, names in their places and an unverified one marked, whole and frame-range reads, writes as new files and next versions the browser opens, a conflict kept as a copy, rename/move/mkdir/rmdir/trash, a sample never readable, evidence read-only and judged at open, a read grant read-only from the start)${mounted ? ", and the same through a real FUSE mount" : fuseNote}`);
} finally {
	await dev.close();
}
