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
import { createChildVault, createParentsMaster, createStoreKey, sealStoreKeyToMember, sealStoreKeyToMaster } from "../../web/src/vault/family.ts";
import { deriveRecordKey, macRecord } from "../../web/src/vault/records.ts";
import { importVaultKey } from "../../web/src/vault/vault-crypto.ts";

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
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "mom", name: "Mom", role: "parent", emails: ["mom@family.test"] } });
	const master = await createParentsMaster();
	await api(dev.base, "PUT", "/api/v1/family/master", { email: "mom@family.test", body: { keyId: master.keyId, publicKey: master.publicKey } });
	await api(dev.base, "POST", "/api/v1/family/members", { email: "mom@family.test", body: { id: "jinu", name: "Jinu", role: "child", emails: ["jinu@family.test"] } });
	const kidVault = await createChildVault();
	const filesStore = await createStoreKey();
	const own = await sealStoreKeyToMember(filesStore, { ec: kidVault.publicKey, kem: kidVault.pqPublicKey });
	// Authenticated as the setup screen does it (records.ts): the CLI refuses
	// a files-store record without a MAC under this root (commit 24, O3).
	const recordKey = await deriveRecordKey(await importVaultKey(kidVault.rootBundle.slice()));
	own.mac = await macRecord(recordKey, "files", own);
	const guardian = await sealStoreKeyToMaster(filesStore, master);
	const saved = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: own }, guardian } } });
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
	const devices = await api(dev.base, "GET", "/api/v1/members/jinu/devices", { email: "mom@family.test" });
	assert.ok(devices.json.find((d) => d.platform === "linux"), "the enrolled device is listed");

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

	// ── 5. Zero-trust spot check: the server stored only sealed shapes ──
	const keys = await api(dev.base, "POST", "/api/v1/members/jinu/files/keys", { email: "jinu@family.test", body: { ids: [fileId] } });
	assert.ok(keys.json.keys[fileId].key.startsWith("GV03:"), "the content key rides wrapped");
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
	const swap = await api(dev.base, "PUT", "/api/v1/members/jinu/vault", { email: "jinu@family.test", body: { settings: { enabled: true, keyId: kidVault.keyId, publicKey: kidVault.publicKey, pqPublicKey: kidVault.pqPublicKey, methods: kidVault.methods, stores: { files: forged }, guardian } } });
	assert.equal(swap.status, 200, "(the server stores what it is given — the client is the judge)");
	fs.writeFileSync(localFile, "this must never be sealed to the attacker");
	const refused = await sync(["push", "--file", localFile, "--name", "secret.txt", "--dev-email", "jinu@family.test", "--profile", path.join(home, "profile.json"), "--secret", recoveryCode]);
	assert.notEqual(refused.status, 0, "push with a swapped store record is refused");
	assert.match(refused.out, /failed authentication/, `the refusal names the reason: ${refused.out}`);

	console.log("ok  live:client — enrol, push, ls, pull, round trip, zero-trust, a swapped store record refused");
} finally {
	await dev.close();
}