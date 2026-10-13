// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The cross-language vectors test: TypeScript must open what Rust sealed,
 * Rust must open what TypeScript sealed (that direction runs inside
 * `cargo test`, which this test drives so one command proves both).
 *
 * Run: node tests/run.mjs unit   (or node tests/unit/formats.test.mjs)
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { cargoCommand } from "../lib/cargo.mjs";
import {
	open,
	openText,
	openWith,
	openTextWith,
	importVaultKey,
	importContentKey,
	unwrapContentKey,
	wrapContentKey,
	unlockWithMethod,
	isHybridPublic,
} from "../../web/src/vault/vault-crypto.ts";
import { fromBase64 } from "../../web/src/lib/encoding.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const VECTORS = path.join(ROOT, "crates/formats/tests/vectors.json");
const RUST_OUT = path.join(ROOT, "tests/output/rust-out.json");

// ── 1. Drive the Rust side (opens the TS vectors; writes rust-out) ──
fs.mkdirSync(path.dirname(RUST_OUT), { recursive: true });
const { cmd: cargoCmd, env } = cargoCommand();
const cargo = spawnSync(cargoCmd, ["test", "-p", "gorani-formats", "--test", "vectors"], {
	cwd: ROOT,
	env: { ...env, GORANI_RUST_OUT: RUST_OUT },
	encoding: "utf8",
	maxBuffer: 16 * 1024 * 1024,
});
assert.equal(cargo.status, 0, `cargo test failed (status ${cargo.status}, signal ${cargo.signal}, error ${cargo.error}):\n${cargo.stdout}\n${cargo.stderr}`);

// ── 2. The TS vectors: TS opens its own, and tampering fails ────────
const v = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
const pPriv = await importVaultKey(fromBase64(v.p256.pkcs8));
const hPriv = await importVaultKey(fromBase64(v.hybrid.bundle));
assert.equal(await openText(pPriv, v.p256.sealedText), "a name, sealed (GV01)");
assert.equal(await openText(hPriv, v.hybrid.sealedText), "한국어 이름.pdf");
assert.equal(new TextDecoder().decode(await open(pPriv, fromBase64(v.p256.sealed))), "sealed to P-256");
assert.equal(new TextDecoder().decode(await open(hPriv, fromBase64(v.hybrid.sealed))), "sealed post-quantum");
// The content key unwraps from either wrap. Keys are non-extractable (the
// point), so compare what they *open*, not their bytes.
const ck = await unwrapContentKey(hPriv, v.content.wrapped);
const ckP = await unwrapContentKey(pPriv, v.content.wrappedP256);
assert.equal(new TextDecoder().decode(await openWith(ck, fromBase64(v.content.sealed))), "an attachment's bytes");
assert.equal(new TextDecoder().decode(await openWith(ckP, fromBase64(v.content.sealed))), "an attachment's bytes");
assert.equal(await openTextWith(ck, v.content.sealedText), "한국어 문서");
// Every unlock method opens the root to the same bundle bytes.
const bundle = fromBase64(v.hybrid.bundle);
for (const [kind, secret] of [
	["password", "correct horse battery staple"],
	["recovery", v.unlock.recoveryCode],
	["passkey", fromBase64(v.unlock.passkeyPrf)],
]) {
	const opened = await unlockWithMethod(v.unlock[kind], secret);
	assert.deepEqual(opened, bundle, `${kind} method opens the root`);
}
// Tampered bytes fail everywhere.
for (const [name, sealed] of [["v1", v.p256.sealed], ["v3", v.hybrid.sealed], ["v2", v.content.sealed]]) {
	const bytes = fromBase64(sealed);
	bytes[Math.floor(bytes.length / 2)] ^= 0x40;
	await assert.rejects(() => open(hPriv, bytes), undefined, `${name} tampered`);
}

// ── 3. Rust-sealed: TS opens what Rust sealed ───────────────────────
const r = JSON.parse(fs.readFileSync(RUST_OUT, "utf8"));
assert.equal(new TextDecoder().decode(await open(pPriv, fromBase64(r.p256Sealed))), "sealed by rust (GV01)");
assert.equal(new TextDecoder().decode(await open(hPriv, fromBase64(r.hybridSealed))), "sealed by rust (GV03)");
assert.equal(new TextDecoder().decode(await openWith(ck, fromBase64(r.contentSealed))), "sealed by rust (GV02)");
assert.equal(await openText(hPriv, r.textSealed), "러스트가 봉인한 이름.txt");
// Rust re-wrapped the content key to the P-256 key; TS unwraps it too.
assert.deepEqual(await unwrapContentKey(pPriv, r.rewrapped), ck);
// Rust-sealed chunked frames open in TS, and TS span math matches.
const { openChunked, sealChunked, FRAME_OVERHEAD, sealedSize } = await import("../../web/src/vault/chunked-file.ts");
const rustChunked = fromBase64(r.chunkedSealed);
const rustPlain = fromBase64(r.chunkedPlain);
assert.equal(new TextDecoder().decode(await openChunked(ck, rustChunked, r.chunkedChunk)), new TextDecoder().decode(rustPlain));
assert.equal(sealedSize(rustPlain.length, r.chunkedChunk), rustChunked.length);
// Every frame but the last is exactly chunk + overhead; the last is shorter.
const f = r.chunkedChunk + FRAME_OVERHEAD;
assert.equal(rustChunked.length % f, (rustPlain.length % r.chunkedChunk) + FRAME_OVERHEAD, "the tail frame's size");
// TS seals chunked frames Rust already proved it can open (same arithmetic).
const tsResealed = await sealChunked(ck, rustPlain, r.chunkedChunk);
assert.equal(tsResealed.length, rustChunked.length);
// And TS re-wraps the same key to the hybrid key, as rotation would.
const hybridPublic = { ec: { kty: "EC", crv: "P-256", x: v.hybrid.x, y: v.hybrid.y }, kem: v.hybrid.kem };
assert.ok(isHybridPublic(hybridPublic));
const resealed = await wrapContentKey(hybridPublic, fromBase64(v.content.key));
assert.deepEqual(await unwrapContentKey(hPriv, resealed), ck);

console.log("ok  formats: TS ⇄ Rust vectors, both directions");