// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:zipstream — the streaming zip writer (web/src/vault/zip.ts ›
 * ZipStream, D12 31d), read back by an INDEPENDENT reader: Python's
 * zipfile. What it proves, in normal and in forced-ZIP64 form:
 *
 *   1. stored entries streamed in pieces come out byte for byte, with the
 *      CRC and sizes their data descriptors carry;
 *   2. a ZipCrypto entry written with a data descriptor (its check byte
 *      the DOS time's high byte, not the CRC's) opens with "infected" and
 *      refuses a wrong password;
 *   3. a zip written INTO another zip's entry (a sample inside an export)
 *      is itself a valid zip;
 *   4. the ZIP64 end records (forced) are what a reader expects.
 *
 * Without python3 on the PATH it says so and checks the structure only.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZipStream } from "../../web/src/vault/zip.ts";

const enc = new TextEncoder();
const pieces = (b: Uint8Array, n: number) => async (write: (x: Uint8Array) => Promise<void>) => {
	for (let i = 0; i < b.length; i += n) await write(b.subarray(i, i + n));
};
const disk = new Uint8Array(300_000).map((_, i) => (i * 31) % 256);
const notes = enc.encode("collected 2026-10-14 by bo — chain of custody follows");
const sample = enc.encode("MZ\u0090 a dropper, never to be run");

async function build(forceZip64: boolean): Promise<Uint8Array> {
	const out: Uint8Array[] = [];
	const zip = new ZipStream(async (b) => void out.push(b.slice()), { forceZip64 });
	await zip.add("evidence/disk.E01", pieces(disk, 4096), { size: disk.length });
	await zip.addBytes("notes.txt", notes);
	// A sample's zip, written into the outer entry as it streams.
	await zip.add("evidence/dropper.exe.zip", async (writeOuter) => {
		const inner = new ZipStream(writeOuter, { forceZip64 });
		await inner.add("dropper.exe", pieces(sample, 7), { password: "infected", size: sample.length });
		await inner.finish();
	});
	await zip.finish();
	return Buffer.concat(out);
}

const py = (args: string[], file: string) => spawnSync("python3", ["-I", "-c", args.join("\n"), file], { encoding: "latin1" });

for (const forceZip64 of [false, true]) {
	const bytes = await build(forceZip64);
	const mode = forceZip64 ? "ZIP64" : "plain";
	// The structure, without Python: end records where they belong.
	const view = Buffer.from(bytes);
	assert.equal(view.readUInt32LE(view.length - 22), 0x06054b50, `${mode}: the end-of-central-directory record closes it`);
	if (forceZip64) assert.equal(view.readUInt32LE(view.length - 42), 0x07064b50, "ZIP64: its locator sits just before");
	const dir = mkdtempSync(join(tmpdir(), "gorani-zipstream-"));
	try {
		writeFileSync(join(dir, "x.zip"), bytes);
		const names = py(["import zipfile,sys", "z=zipfile.ZipFile(sys.argv[1])", "print('\\n'.join(i.filename+' '+str(i.file_size)+' '+str(i.CRC) for i in z.infolist()))"], join(dir, "x.zip"));
		if (names.error) {
			console.log("  (python3 not found: the streamed zip was not cross-checked by an independent reader)");
			continue;
		}
		assert.equal(names.status, 0, names.stderr);
		const listed = names.stdout.trim().split("\n").map((l) => l.split(" "));
		assert.deepEqual(listed.map((l) => l[0]), ["evidence/disk.E01", "notes.txt", "evidence/dropper.exe.zip"], `${mode}: every entry, in order`);
		assert.equal(Number(listed[0]![1]), disk.length);
		const content = py(["import zipfile,sys,hashlib", "z=zipfile.ZipFile(sys.argv[1])", "print(hashlib.sha256(z.read('evidence/disk.E01')).hexdigest())", "print(z.read('notes.txt').decode())", "z.testzip() is None or sys.exit('a CRC is wrong')"], join(dir, "x.zip"));
		assert.equal(content.status, 0, content.stderr);
		const [sha, text] = content.stdout.trim().split("\n");
		const { createHash } = await import("node:crypto");
		assert.equal(sha, createHash("sha256").update(disk).digest("hex"), `${mode}: the streamed entry, byte for byte`);
		assert.equal(text, Buffer.from(notes).toString("latin1"));
		// The nested sample zip: unzip the outer entry, then open the inner one with "infected".
		const inner = py(["import zipfile,sys,io", "z=zipfile.ZipFile(sys.argv[1])", "i=zipfile.ZipFile(io.BytesIO(z.read('evidence/dropper.exe.zip')))", "sys.stdout.buffer.write(i.read('dropper.exe', pwd=b'infected'))"], join(dir, "x.zip"));
		assert.equal(inner.status, 0, inner.stderr);
		assert.equal(inner.stdout, Buffer.from(sample).toString("latin1"), `${mode}: the sample opens with "infected" (bit 3: the time's check byte)`);
		const wrong = py(["import zipfile,sys,io", "z=zipfile.ZipFile(sys.argv[1])", "zipfile.ZipFile(io.BytesIO(z.read('evidence/dropper.exe.zip'))).read('dropper.exe', pwd=b'wrong')"], join(dir, "x.zip"));
		assert.notEqual(wrong.status, 0, `${mode}: a wrong password is refused`);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

// Misuse is refused, not written.
const zip = new ZipStream(async () => {});
await zip.addBytes("a.txt", notes);
await assert.rejects(zip.addBytes("a.txt", notes), /two zip entries/);
await assert.rejects(zip.addBytes("../escape", notes), /plain relative name/);
await zip.finish();
await assert.rejects(zip.addBytes("late.txt", notes), /already finished/);

console.log("ok  zipstream: streamed stored entries, a ZipCrypto entry with a data descriptor, a zip inside a zip — plain and ZIP64 — read back by Python's zipfile");
