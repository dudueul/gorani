// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:device-protect — where this computer's device secret lives (commit
 * 34, clients/core/src/devicekey.rs). Against the real worker, a real
 * software TPM 2.0 (swtpm, driven through tpm2-tools exactly as a hardware
 * one is) and a real login keyring (GNOME Keyring on a private D-Bus
 * session, reached through secret-tool):
 *
 *   1. `setup --protect tpm+keyring` leaves NO device secret in the
 *      profile — only the TPM's sealed blobs and a keyring reference — and
 *      the device unlocks without a password; the server records the
 *      protection label;
 *   2. a copy of the profile is useless elsewhere: another TPM cannot even
 *      load the blob, another login's keyring holds no part;
 *   3. a machine with neither is refused at setup unless the person
 *      chooses `--protect file` explicitly (and is warned);
 *   4. `protect` moves an enrolled computer's in-file secret into the TPM
 *      without enrolling again — the server's copy re-wrapped, the old
 *      secret no longer opening anything — and a run that died after the
 *      server took the new copy is finished by the next one; replaced
 *      keyring parts are forgotten;
 *   5. `devices` lists every computer's protection, and a lost one is
 *      revoked from another (the web app has no devices screen yet).
 *
 * Skipped without the binaries, swtpm, tpm2-tools, secret-tool,
 * gnome-keyring or dbus-daemon (apt: swtpm tpm2-tools libsecret-tools
 * gnome-keyring dbus).
 */

import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { suiteDev, api } from "./_dev.mjs";
import { member } from "../lib/team.mjs";
import { deriveRecordKey, macRecord } from "../../web/src/vault/records.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SYNC = path.join(ROOT, "target/debug/gorani-sync");
const have = (tool: string) => spawnSync("sh", ["-c", `command -v ${tool}`]).status === 0;
const missing = ["swtpm", "tpm2_createprimary", "secret-tool", "gnome-keyring-daemon", "dbus-daemon"].filter((t) => !have(t));
if (!fs.existsSync(SYNC) || missing.length) {
	console.log(`skip  api:device-protect — needs ${fs.existsSync(SYNC) ? missing.join(", ") : "cargo build -p gorani-client-core"}`);
	process.exit(0);
}

const dev = await suiteDev();
const work = path.join(ROOT, "tests/output/device-protect");
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(work, { recursive: true });
const children: ChildProcess[] = [];

const freePort = () => new Promise<number>((r) => {
	const s = net.createServer().listen(0, "127.0.0.1", () => {
		const p = (s.address() as net.AddressInfo).port;
		s.close(() => r(p));
	});
});

/** A software TPM 2.0 with its own state (its own seeds — its own chip). */
async function startTpm(state: string, port: number) {
	fs.mkdirSync(state, { recursive: true });
	const p = spawn("swtpm", ["socket", "--tpmstate", `dir=${state}`, "--tpm2", "--server", `type=tcp,port=${port}`, "--ctrl", `type=tcp,port=${port + 1}`, "--flags", "not-need-init,startup-clear"], { stdio: "ignore" });
	children.push(p);
	for (let i = 0; i < 50; i++) {
		const up = await new Promise<boolean>((r) => net.connect(port, "127.0.0.1").on("connect", function () { this.destroy(); r(true); }).on("error", () => r(false)));
		if (up) break;
		await new Promise((r) => setTimeout(r, 100));
	}
	return { stop: () => new Promise<void>((r) => (p.exitCode !== null ? r() : (p.on("exit", () => r()), p.kill("SIGTERM")))) };
}

/** A private session bus with an unlocked GNOME Keyring on it (a login). */
async function startLogin(name: string, password: string) {
	const home = path.join(work, name);
	fs.mkdirSync(path.join(home, ".local/share"), { recursive: true });
	const address = `unix:path=${path.join(home, "bus")}`;
	const bus = spawn("dbus-daemon", ["--session", "--nofork", `--address=${address}`], { stdio: "ignore" });
	children.push(bus);
	for (let i = 0; i < 50 && !fs.existsSync(path.join(home, "bus")); i++) await new Promise((r) => setTimeout(r, 100));
	const env = { ...process.env, HOME: home, XDG_DATA_HOME: path.join(home, ".local/share"), DBUS_SESSION_BUS_ADDRESS: address };
	const k = spawnSync("gnome-keyring-daemon", ["--unlock", "--components=secrets"], { input: password, env, encoding: "utf8" });
	assert.equal(k.status, 0, k.stderr);
	return { env: { HOME: home, XDG_DATA_HOME: env.XDG_DATA_HOME, DBUS_SESSION_BUS_ADDRESS: address }, stop: () => bus.kill("SIGTERM") };
}

/** The CLI, async (this process may run the S3 stub). */
function cli(args: string[], env: Record<string, string>): Promise<{ status: number; out: string }> {
	const c = spawn(SYNC, args, { cwd: ROOT, env: { ...process.env, ...env } });
	let out = "";
	c.stdout.on("data", (d) => (out += d));
	c.stderr.on("data", (d) => (out += d));
	return new Promise((r) => c.on("exit", (code) => r({ status: code ?? 1, out })));
}
const lookup = (item: string, env: Record<string, string>) => spawnSync("secret-tool", ["lookup", "application", "gorani-device", "item", item], { env: { ...process.env, ...env }, encoding: "utf8" });

try {
	const tpmPort = await freePort();
	let tpm = await startTpm(path.join(work, "tpm-a"), tpmPort);
	const login = await startLogin("login-a", "ana's login password");
	const env = { ...login.env, TPM2TOOLS_TCTI: `swtpm:host=127.0.0.1,port=${tpmPort}` };

	const ana = await member(dev, "ana", "lead");
	ana.settings.stores.files.mac = await macRecord(await deriveRecordKey(ana.root), "files", ana.settings.stores.files);
	assert.equal((await api(dev.base, "PUT", "/api/v1/members/ana/vault", { email: ana.email, body: { settings: ana.settings } })).status, 200);
	const devices = async () => (await api(dev.base, "GET", "/api/v1/members/ana/devices", { email: ana.email })).json as { id: string; protection: string | null }[];
	const setupArgs = (profile: string, extra: string[]) => ["setup", "--server", dev.base, "--member", "ana", "--name", path.basename(profile), "--secret", ana.recoveryCode, "--dev-email", ana.email, "--profile", profile, ...extra];
	const ls = (profile: string, e: Record<string, string> = env) => cli(["ls", "--profile", profile, "--dev-email", ana.email], e);

	// ── 1. TPM + keyring: nothing secret in the profile ──────────────────
	const profile = path.join(work, "laptop.json");
	const made = await cli(setupArgs(profile, ["--protect", "tpm+keyring"]), env);
	assert.equal(made.status, 0, made.out);
	assert.match(made.out, /protected by: tpm\+keyring/);
	const text = fs.readFileSync(profile, "utf8");
	const saved = JSON.parse(text);
	assert.equal(saved.deviceSecret, undefined, "no device secret in the profile");
	assert.deepEqual(saved.deviceProtectors.map((p: { kind: string }) => p.kind), ["tpm", "keyring"]);
	const keyringItem = saved.deviceProtectors[1].item as string;
	const part = lookup(keyringItem, env);
	assert.equal(part.status, 0, part.stderr);
	assert.match(part.stdout.trim(), /^[0-9a-f]{64}$/, "the keyring holds its part");
	assert.ok(!text.includes(part.stdout.trim()), "…and the profile does not");
	const opened = await ls(profile);
	assert.equal(opened.status, 0, `unlocked by the TPM and the keyring, no password: ${opened.out}`);
	const laptop = (await devices()).find((d) => d.id === saved.deviceId);
	assert.equal(laptop?.protection, "tpm+keyring", "the server records what protects the device");

	// ── 2. A copy of the profile, elsewhere ──────────────────────────────
	await tpm.stop();
	tpm = await startTpm(path.join(work, "tpm-b"), tpmPort); // another machine's chip
	const otherChip = await ls(profile);
	assert.notEqual(otherChip.status, 0);
	assert.match(otherChip.out, /sealed by another machine's TPM/, otherChip.out);
	await tpm.stop();
	tpm = await startTpm(path.join(work, "tpm-a"), tpmPort); // back home
	assert.equal((await ls(profile)).status, 0, "this machine's chip again");
	const otherLogin = await startLogin("login-b", "someone else's password");
	const wrongLogin = await ls(profile, { ...otherLogin.env, TPM2TOOLS_TCTI: env.TPM2TOOLS_TCTI });
	assert.notEqual(wrongLogin.status, 0);
	assert.match(wrongLogin.out, /login keyring/, wrongLogin.out);
	otherLogin.stop();

	// ── 3. Neither available: refused, unless chosen explicitly ──────────
	const bare = { TPM2TOOLS_TCTI: `swtpm:host=127.0.0.1,port=${await freePort()}`, DBUS_SESSION_BUS_ADDRESS: `unix:path=${path.join(work, "no-bus")}` };
	const before = (await devices()).length;
	const refused = await cli(setupArgs(path.join(work, "bare.json"), []), bare);
	assert.notEqual(refused.status, 0);
	assert.match(refused.out, /neither a TPM .* nor a login keyring/);
	assert.match(refused.out, /--protect file/);
	assert.equal((await devices()).length, before, "no device was enrolled");
	assert.ok(!fs.existsSync(path.join(work, "bare.json")));

	// ── 4. protect: an in-file secret moved into the TPM ──────────────────
	const old = path.join(work, "old.json");
	const legacy = await cli(setupArgs(old, ["--device-secret", "e".repeat(64)]), env);
	assert.equal(legacy.status, 0, legacy.out);
	assert.match(legacy.out, /protected by: file/);
	assert.match(legacy.out, /warning: .*Move it: gorani-sync protect/);
	const oldId = JSON.parse(fs.readFileSync(old, "utf8")).deviceId;
	assert.equal((await devices()).find((d) => d.id === oldId)?.protection, "file");
	const stale = path.join(work, "old-copy.json");
	fs.copyFileSync(old, stale); // what a backup taken today would hold
	const moved = await cli(["protect", "--protect", "tpm", "--profile", old, "--dev-email", ana.email], env);
	assert.equal(moved.status, 0, moved.out);
	assert.match(moved.out, /now protected by: tpm/);
	const after = JSON.parse(fs.readFileSync(old, "utf8"));
	assert.equal(after.deviceSecret, undefined, "the in-file secret is gone");
	assert.equal(after.deviceId, oldId, "the same enrolment");
	assert.deepEqual(after.deviceProtectors.map((p: { kind: string }) => p.kind), ["tpm"]);
	assert.equal((await ls(old)).status, 0);
	assert.equal((await devices()).find((d) => d.id === oldId)?.protection, "tpm");
	const backup = await ls(stale);
	assert.notEqual(backup.status, 0, "the old secret opens nothing any more");
	assert.match(backup.out, /does not open with its device secret/);

	// A run that died after the server took its new copy: the profile still
	// names the old secret, with the new protectors pending. It unlocks, and
	// the next protect finishes it (then moves on, here to the keyring).
	const crashed = path.join(work, "crashed.json");
	fs.writeFileSync(crashed, JSON.stringify({ ...after, deviceSecret: "e".repeat(64), deviceProtectors: [], pendingProtectors: after.deviceProtectors }), { mode: 0o600 });
	assert.equal((await ls(crashed)).status, 0, "the pending protectors open the server's copy");
	const finished = await cli(["protect", "--protect", "keyring", "--profile", crashed, "--dev-email", ana.email], env);
	assert.equal(finished.status, 0, finished.out);
	const done = JSON.parse(fs.readFileSync(crashed, "utf8"));
	assert.deepEqual([done.deviceSecret, done.pendingProtectors, done.deviceProtectors.map((p: { kind: string }) => p.kind)], [undefined, undefined, ["keyring"]]);
	assert.equal((await ls(crashed)).status, 0);
	// Moving again forgets the keyring part it replaces.
	const k1 = done.deviceProtectors[0].item as string;
	assert.equal(lookup(k1, env).status, 0);
	assert.equal((await cli(["protect", "--protect", "tpm", "--profile", crashed, "--dev-email", ana.email], env)).status, 0);
	assert.notEqual(lookup(k1, env).status, 0, "the replaced keyring part is gone from the keyring");
	assert.equal((await ls(crashed)).status, 0);

	// ── 5. A lost computer, revoked from another ──────────────────────────
	const listing = await cli(["devices", "--profile", profile, "--dev-email", ana.email], env);
	assert.equal(listing.status, 0, listing.out);
	assert.match(listing.out, /protected by: tpm\+keyring .*← this computer/);
	assert.match(listing.out, new RegExp(`${oldId}.*protected by: tpm`));
	const revoked = await cli(["revoke", "--device", oldId, "--profile", profile, "--dev-email", ana.email], env);
	assert.equal(revoked.status, 0, revoked.out);
	const lost = await ls(crashed); // the revoked computer's own profile
	assert.notEqual(lost.status, 0, "a revoked computer never unlocks again — whatever its TPM holds");
	assert.equal((await ls(profile)).status, 0, "the others still do");

	console.log("ok  api:device-protect — TPM + keyring hold the device secret (none in the profile; unlocks without a password; the server records the label), a copied profile fails on another TPM and another login, no protector refuses setup unless --protect file, protect moves an in-file secret into the TPM (old secret dead), finishes a run that died mid-way, and forgets replaced keyring parts; devices lists every computer's protection, and a lost one is revoked from another");
	login.stop();
	await tpm.stop();
} finally {
	for (const c of children) if (c.exitCode === null) c.kill("SIGKILL");
	await dev.close();
}
