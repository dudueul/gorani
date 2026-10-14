// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:timestamp — the reader's RFC 3161 check (web/src/vault/timestamp.ts,
 * commit 29j) against tokens from OpenSSL's own TSA (tests/lib/tsa-stub.mjs
 * › makeTsa): an independent writer, RSA and ECDSA. Written as the ways a
 * token can lie, each caught by the check that names it:
 *
 *   over other bytes → the imprint;           a byte of its TSTInfo changed → messageDigest;
 *   its signature altered → the signature;    signed by a key nobody certified → uncertified;
 *   a certification by someone you never verified → ignored;
 *   a certification's signature moved to another key → ignored.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { buildTrust, createIdentity, pin, type RegistryIdentity } from "../../web/src/vault/identity.ts";
import { createCodeVault } from "../../web/src/vault/keys.ts";
import { importVaultKey } from "../../web/src/vault/vault-crypto.ts";
import { checkCheckpointStamp, checkToken, checkVersionStamp, describeStamp, stampImprint, trustedTsas, tsaIdentityOf, type TsaCert } from "../../web/src/vault/timestamp.ts";
import { statements } from "../../web/src/vault/identity.ts";
import { makeTsa } from "../lib/tsa-stub.mjs";

const hex = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

async function member(id: string) {
	const vault = await createCodeVault();
	const root = await importVaultKey(vault.rootBundle.slice());
	const made = await createIdentity(id, root, { ec: vault.publicKey, kem: vault.pqPublicKey });
	const entry: RegistryIdentity = { member: id, ...made.registry, certs: [] };
	return { id, root, record: made.record, signer: made.signer, entry };
}

const rsa = makeTsa({ key: "rsa", name: "gorani unit TSA (RSA)" });
const ec = makeTsa({ key: "ec", name: "gorani unit TSA (EC)" });
try {
	// The team: ana (a lead) certifies the RSA TSA; bo verified ana's fingerprint.
	const ana = await member("ana");
	const bo = await member("bo");
	const mallory = await member("mallory");
	const boRecord = await pin("bo", bo.root, bo.record, { member: "ana", keyId: ana.record.keyId });
	const trust = await buildTrust("bo", bo.root, boRecord, [ana.entry, bo.entry, mallory.entry]);
	const certOf = async (who: typeof ana, tsa: { spki: string; name: string }): Promise<TsaCert> => ({ spki: tsa.spki, name: tsa.name, by: who.id, keyId: who.signer.keyId, signature: await who.signer.sign(statements.tsa(tsa.spki, tsa.name)) });
	const anaRsa = await certOf(ana, rsa);

	// ── 1. Who the TSA is, as a lead sees it before certifying ──────────
	const imprint = hex("an uploader's signature bytes");
	const token = new Uint8Array(rsa.token(imprint));
	const who = await tsaIdentityOf(Buffer.from(token).toString("base64"));
	assert.equal(who.name, "gorani unit TSA (RSA)");
	assert.equal(who.spki, rsa.spki, "the SPKI digest is the one Node computes from the certificate");
	assert.equal(who.certFingerprint, rsa.fingerprint, "and the fingerprint is the one `openssl x509 -fingerprint -sha256` prints");

	// ── 2. Certifications count only from people the reader verified ────
	const trusted = await trustedTsas(trust, [anaRsa]);
	assert.deepEqual([...trusted.keys()], [rsa.spki]);
	assert.equal((await trustedTsas(trust, [await certOf(mallory, ec)])).size, 0, "mallory is not someone bo verified");
	assert.equal((await trustedTsas(trust, [{ ...anaRsa, spki: ec.spki }])).size, 0, "ana's signature moved to another key does not verify");
	assert.equal((await trustedTsas(null, [anaRsa])).size, 0, "no trust, no TSA");

	// ── 3. Verified — RSA and ECDSA ─────────────────────────────────────
	const ok = await checkToken(token, imprint, trusted);
	assert.equal(ok.status, "verified", describeStamp(ok));
	assert.ok(ok.status === "verified" && ok.certifiedBy[0] === "ana" && Math.abs(Date.parse(ok.at) - Date.now()) < 120_000, JSON.stringify(ok));
	const ecToken = new Uint8Array(ec.token(imprint));
	const ecTrusted = await trustedTsas(trust, [anaRsa, await certOf(ana, ec)]);
	assert.equal((await checkToken(ecToken, imprint, ecTrusted)).status, "verified", "an ECDSA TSA (DER signature → P1363)");

	// ── 4. Each lie, named ──────────────────────────────────────────────
	const why = async (t: Uint8Array, i = imprint, tr = trusted) => {
		const c = await checkToken(t, i, tr);
		return c.status === "invalid" ? c.why : c.status;
	};
	assert.match(await why(token, hex("other bytes")), /over other bytes/);
	assert.equal(await why(ecToken), "uncertified", "a sound token from a key nobody bo trusts certified");
	// A byte of the TSTInfo (inside the genTime digits): the signed digest no longer matches.
	const tst = Buffer.from(token);
	const at = tst.indexOf(Buffer.from(String(new Date().getUTCFullYear())));
	assert.ok(at > 0);
	tst[at + 3] ^= 0x01;
	assert.match(await why(new Uint8Array(tst)), /messageDigest/);
	// The signature's last byte.
	const sig = Buffer.from(token);
	sig[sig.length - 1] ^= 0x01;
	assert.match(await why(new Uint8Array(sig)), /does not verify/);
	assert.match(await why(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])), /not a timestamp token/);

	// ── 5. The two things gorani stamps ─────────────────────────────────
	// A version: the imprint is SHA-256 of the hash record's signature.
	const record = { signature: Buffer.from("a sixty-four byte ECDSA P-256 signature, r ‖ s, as P1363 has it").toString("base64") };
	const vImprint = await stampImprint(record.signature);
	assert.equal(vImprint, hex(Buffer.from(record.signature, "base64")));
	const row = { version: 1, status: "stamped" as const, imprint: vImprint, token: rsa.token(vImprint).toString("base64"), at: null };
	assert.equal((await checkVersionStamp(record, row, trusted)).status, "verified");
	const other = { signature: Buffer.from("another record's signature").toString("base64") };
	assert.match(describeStamp(await checkVersionStamp(other, row, trusted)), /not this hash record's signature/, "a stamp moved to another version");
	assert.equal((await checkVersionStamp(record, { ...row, status: "pending", token: null }, trusted)).status, "pending");
	// A checkpoint: over its exact bytes.
	const body = JSON.stringify({ area: "case:ir-7", date: "2026-10-14", seq: 42, hash: "ab".repeat(32) });
	const cpToken = rsa.token(hex(body)).toString("base64");
	assert.equal((await checkCheckpointStamp(body, cpToken, trusted)).status, "verified");
	assert.match(describeStamp(await checkCheckpointStamp(body.replace("42", "41"), cpToken, trusted)), /over other bytes/, "a checkpoint rewritten after it was stamped");

	console.log("ok  timestamp: OpenSSL's RSA and ECDSA tokens verified; other bytes, an edited TSTInfo, an altered signature, an uncertified key and certifications nobody trusted each refused by name");
} finally {
	rsa.close();
	ec.close();
}
