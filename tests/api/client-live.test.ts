// Copyright 2026- Seongwoo Hong. All rights reserved.

//! The live end-to-end: `gorani-sync` (the real native binary) against the
//! real worker — enrol with a recovery code, push a sealed file, ls the
//! change feed with opened names, pull and compare bytes. Skipped when the
//! debug binary is not built (cargo builds it with `cargo test`).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "../api/_dev.mjs";
import { createCodeVault, createStoreKey, sealStoreKeyToMember } from "../../web/src/vault/keys.ts";
import { deriveRecordKey, macRecord } from "../../web/src/vault/records.ts";
import { importVaultKey } from "../../web/src/vault/vault-crypto.ts";
import { sampleType } from "../../web/src/vault/samples.ts";
import { storeSealer } from "../lib/placed.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BIN = path.join(ROOT, "target/debug/gorani-sync");
if (!existsSync(BIN)) {
	console.log("skip  live:client — build it first: cargo build -p gorani-client-core");
	process.exit(0);
}

const dev = await suiteDev();
const home = path.join(ROOT, "tests/output/client-home");
import fs from "node:fs";
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true });

function sync(args: string[], env: Record<string, string> = {}) {
	// spawn — NOT spawnSync. This process also runs the S3 stub; a sync
	// spawn freezes its event loop, and the worker's S3 round-trips then
	// hang for the whole CLI run. That freeze WAS the "293 s hang" (uploads
	// and streamed downloads both touch the stub; JSON routes never did —
	// which is why only push/pull stalled). Bisected with a TCP dump proxy.
	const c = spawn(BIN, args, { cwd: ROOT, env: { ...process.env, ...env } });
	let out = "";
	c.stdout.on("data", (d) => (out += d));
	c.stderr.on("data", (d) => (out += d));
	return new Promise<{ status: number; out: string }>((resolve) => {
		const t = setTimeout(() => c.kill("SIGKILL"), 120_000);
		c.on("exit", (s) => {
			clearTimeout(t);
			if (s !== 0) console.error("SYNC-FAIL", out);
			resolve({ status: s ?? 1, out });
		});
	});
}



try {
	// ── 0. The family + the member's vault (setup the UI would do) ──────
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "lead", emails: ["mom@family.test"] } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "analyst", emails: ["jinu@family.test"] } });
	const kidVault = await createCodeVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	// Authenticated as the setup screen does it (records.ts): the CLI refuses
	// a files-store record without a MAC under this root (commit 24, O3).
	const recordKey = await deriveRecordKey(await importVaultKey(kidVault.rootBundle.slice()));
	own.mac = await macRecord(recordKey, "files", own);
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own } } } });
	assert.equal(saved.status, 200);
	const recoveryCode = kidVault.recoveryCode;

	// ── 1. enrol: the real binary, the real worker ──────────────────────
	const deviceSecret = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
	console.error("STEP setup");
	const setup = await sync(
		[
			"setup",
			"--server", dev.base,
			"--member", "jinu",
			"--name", "Jinu's CLI",
			"--secret", recoveryCode,
			"--device-secret", deviceSecret,
			"--dev-email", "jinu@family.test",
			"--profile", path.join(home, "profile.json"),
		],
		{ GORANI_URL: dev.base },
	);
	assert.equal(setup.status, 0, `setup failed: ${setup.out}`);
	assert.match(setup.out, /enrolled device /);
	// The device's wrapped copy is on the server (the web app sees it).
	const devices = await api(dev.base, "GET", "/api/v1/members/jinu/devices", { email: "jinu@family.test" });
	assert.ok(devices.json.find((d) => d.platform === "linux"), "the enrolled device is listed");

	// The area's files secrets, as a browser makes them at its first upload
	// (model.ts › ensureSecrets): with them the CLI tags what it pushes the
	// way the browser does, and checks for duplicates (commit 39n).
	const jinuStore = await storeSealer(filesStore.bundle, "jinu");
	const fp = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
	const idx = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
	assert.equal((await api(dev.base, "PUT", "/api/v1/members/jinu/files/secrets", { email: "jinu@family.test", body: { sealed: await jinuStore.secrets(JSON.stringify({ fp, idx })) } })).status, 200);

	// ── 2. push: the native write path — the CLI seals and uploads ──────
	// (The old stall had two stacked causes, both found by bisecting raw
	// sockets and a TCP dump proxy: spawnSync froze this process's S3 stub
	// while the CLI ran, and ureq's default `Accept-Encoding` makes workerd
	// compress + chunk every response — ~5 s/request. The client now sends
	// `Accept-Encoding: identity`; the spawn above is async.)
	const localFile = path.join(home, "hello.txt");
	fs.writeFileSync(localFile, "hello from the native client — sealed on the way up");
	const plainHello = fs.readFileSync(localFile);
	console.error("STEP push");
	const push = await sync(["push", "--file", localFile, "--name", "hello.txt", "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.equal(push.status, 0, `push failed: ${push.out}`);
	const fileId = push.out.match(/pushed: (\S+)/)?.[1];
	assert.ok(fileId && fileId !== "?", `push printed the file id: ${push.out}`);
	// The same bytes again (commit 39n): not a terminal, so skipped — with a
	// line naming the copy already there; `--duplicates keep` stores it.
	const tagged = (await api(dev.base, "GET", `/api/v1/members/jinu/files/match?size=${plainHello.length}`, { email: "jinu@family.test" })).json.files.find((f) => f.id === fileId);
	assert.match(tagged?.tag ?? "", /^[0-9a-f]{64}$/, "the CLI tagged its upload, as the browser does");
	const again = await sync(["push", "--file", localFile, "--name", "hello again.txt", "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.equal(again.status, 0, again.out);
	assert.match(again.out, /"skipped":"hello again\.txt"/, `a duplicate push is skipped: ${again.out}`);
	assert.match(again.out, /already here as “hello\.txt”/, "…saying which file has the bytes");
	const kept = await sync(["push", "--file", localFile, "--name", "hello kept.txt", "--duplicates", "keep", "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	const keptId = kept.out.match(/pushed: (\S+)/)?.[1];
	assert.ok(keptId, `--duplicates keep stores a second copy: ${kept.out}`);
	const dupSets = (await api(dev.base, "GET", "/api/v1/members/jinu/files/duplicates", { email: "jinu@family.test" })).json.files.map((f) => f.id).sort();
	assert.deepEqual(dupSets, [fileId, keptId].sort(), "and Find duplicates lists the pair — a CLI copy is found like a browser one");
	assert.equal((await api(dev.base, "DELETE", `/api/v1/members/jinu/files/${keptId}`, { email: "jinu@family.test" })).status, 200);

	// ── 3. ls: the change feed with names opened by the client ─────────
	console.error("STEP ls");
	const ls = await sync(["ls", "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.equal(ls.status, 0, `ls failed: ${ls.out}`);
	assert.match(ls.out, /hello\.txt/, "the client opened the upload's name");

	// ── 4. pull: the native client decrypts and the bytes match ────────
	console.error("STEP pull");
	const outPath = path.join(home, "pulled.txt");
	const pull = await sync(["pull", "--id", fileId, "--out", outPath, "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.equal(pull.status, 0, `pull failed: ${pull.out}`);
	assert.equal(fs.readFileSync(outPath, "utf8"), plainHello.toString("utf8"), "round trip: the exact bytes");

	// ── 4a. A large file (D12 in the client, commit 33b) ────────────────
	// 60 MiB: past the whole-upload limit, so GC01 frames at chunk_for —
	// read from disk one at a time. The first push is stopped after three
	// parts (a debug-build hook); the second resumes from part 4 and sends
	// only the rest. The pull streams frame windows to disk.
	const bigPath = path.join(home, "image.E01");
	const big = Buffer.alloc(60 * 1024 * 1024);
	for (let i = 0; i < big.length; i += 65536) big.fill((i / 65536) % 251, i, i + 65536);
	big.write("gorani evidence image", 1234);
	fs.writeFileSync(bigPath, big);
	const { createHash } = await import("node:crypto");
	const bigSha = createHash("sha256").update(big).digest("hex");
	console.error("STEP push large (stopped)");
	const stopped = await sync(["push", "--file", bigPath, "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode], { GORANI_TEST_STOP_AFTER_PARTS: "3" });
	assert.notEqual(stopped.status, 0, "the hook stopped it");
	assert.match(stopped.out, /stopped after 3 parts/);
	const journalDir = path.join(home, "profile.uploads");
	const journalFiles = fs.readdirSync(journalDir);
	assert.equal(journalFiles.length, 1, "one unfinished upload journalled");
	assert.ok(!journalFiles[0]!.includes("image") && !fs.readFileSync(path.join(journalDir, journalFiles[0]!), "utf8").includes("image.E01"), "no file name in the clear, in its name or its body");
	console.error("STEP push large (resumed)");
	const resumed = await sync(["push", "--file", bigPath, "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.equal(resumed.status, 0, `the resumed push: ${resumed.out}`);
	assert.match(resumed.out, /resuming image\.E01 from part 4 of 8/);
	assert.match(resumed.out, new RegExp(`in 8 parts, SHA-256 ${bigSha}`));
	assert.deepEqual(fs.readdirSync(journalDir), [], "the journal forgets a finished upload");
	const bigId = resumed.out.match(/pushed: (\S+)/)?.[1];
	console.error("STEP pull large");
	const bigOut = path.join(home, "image.pulled");
	const bigPull = await sync(["pull", "--id", bigId!, "--out", bigOut, "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.equal(bigPull.status, 0, `pull: ${bigPull.out}`);
	assert.match(bigPull.out, new RegExp(`SHA-256 ${bigSha}`), "streamed to disk, hashed on the way");
	assert.ok(fs.readFileSync(bigOut).equals(big), "the 60 MiB image, byte for byte");
	assert.ok(!fs.existsSync(`${bigOut}.part`), "no partial file left behind");

	// ── 4b. A malware sample is never written to disk raw (commit 29e) ──
	// Marked the way the web app marks it (every version's type re-sealed
	// with the sample mark); then `pull` refuses, and writes nothing.
	const sealer = await storeSealer(filesStore.bundle, "jinu");
	const marked = await api(dev.base, "PATCH", `/api/v1/members/jinu/files/${fileId}`, { email: "jinu@family.test", body: { sample: true, types: { "1": await sealer.fileType(fileId, 1, sampleType("text/plain")) } } });
	assert.equal(marked.status, 200, marked.text);
	const samplePath = path.join(home, "sample.out");
	const refusedPull = await sync(["pull", "--id", fileId, "--out", samplePath, "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.notEqual(refusedPull.status, 0, "pull refuses a sample");
	assert.match(refusedPull.out, /malware sample/, `the refusal says why: ${refusedPull.out}`);
	assert.ok(!fs.existsSync(samplePath), "…and wrote nothing to disk");

	// ── 5. Zero-trust spot check: the server stored only sealed shapes ──
	const keys = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [fileId] } });
	assert.ok(keys.json.keys[fileId].key.startsWith("GV04:"), "the content key rides wrapped — sealed into its place by the CLI (GV04)");
	const raw = await fetch(`${dev.base}/api/v1/members/jinu/files/${fileId}`, { headers: { "x-gorani-dev-email": "jinu@family.test" } });
	const stored = new Uint8Array(await raw.arrayBuffer());
	assert.equal(new TextDecoder().decode(stored.subarray(0, 4)), "GV02", "the stored object is GV02-sealed");

	// ── 6. The server swaps the files store (O3) — the binary refuses ───
	// The attack: a fresh key pair, its private half sealed to Jinu's root
	// (sealing needs only the PUBLIC key), dropped into the settings row with
	// the old MAC. Before commit 24 the CLI would have opened it and sealed
	// the next push to the attacker. Now: refused, nothing sealed.
	const attacker = await createStoreKey();
	const forged = { ...(await sealStoreKeyToMember(attacker, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey })), mac: own.mac };
	const swap = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: forged } } } });
	assert.equal(swap.status, 200, "(the server stores what it is given — the client is the judge)");
	fs.writeFileSync(localFile, "this must never be sealed to the attacker");
	const refused = await sync(["push", "--file", localFile, "--name", "secret.txt", "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.notEqual(refused.status, 0, "push with a swapped store record is refused");
	assert.match(refused.out, /failed authentication/, `the refusal names the reason: ${refused.out}`);

	console.log("ok  live:client — enrol, push (a duplicate skipped and named, kept on --duplicates keep, listed by Find duplicates), ls, pull, round trip, a 60 MiB file in GC01 frames stopped after 3 parts and resumed from part 4, pulled streamed and byte-equal, a sample refused by pull, zero-trust, a swapped store record refused");
} finally {
	await dev.close();
}