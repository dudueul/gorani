// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A FairPlay player for the tests (commit 40b, api:drm) — what Safari does
 * with an SPC and a CKC, minus the DRM module, written a second time in
 * JavaScript from crates/fairplay's protocol notes so the suite checks the
 * Worker's license server against an implementation that is not its own.
 *
 * And the throwaway credentials: a fresh 1024-bit RSA key, DER-looking
 * bytes for the certificate (only its SHA-1 matters to the protocol), a
 * random ASK — made when the suite starts, handed to its own server as
 * vars, gone when it ends. Nothing of Apple's is in this repository, and
 * nothing here would play in a real Safari.
 */

import crypto from "node:crypto";

const TAG = {
	SK_R1: 0x3d1a10b8bffac2ecn,
	SK_R1_INTEGRITY: 0xb349d4809e910687n,
	ANTI_REPLAY_SEED: 0x89c90f12204106b2n,
	R2: 0x71b5595ac1521133n,
	RETURN_REQUEST: 0x19f9d4e5ab7609cbn,
	ASSET_ID: 0x1bf7f53f5d5d5a1fn,
	TRANSACTION_ID: 0x47aa7ad3440577den,
	PROTOCOL_VERSIONS_SUPPORTED: 0x67b8fb79ecce1a13n,
	PROTOCOL_VERSION_USED: 0x5d81bcbcc7f61703n,
	STREAMING_INDICATOR: 0xabb0256a31843974n,
	ENCRYPTED_CK: 0x58b38165af0e3d5an,
	R1: 0xea74c4645d5efee9n,
	HDCP_ENFORCEMENT: 0x2e52f1530d8ddb4an,
};
export const HDCP_TYPE0 = 0x40791ac78bd5c571n;
export { TAG };

const sha1 = (b) => crypto.createHash("sha1").update(b).digest();
const ecb = (key, block, decrypt = false) => {
	const c = decrypt ? crypto.createDecipheriv("aes-128-ecb", key, null) : crypto.createCipheriv("aes-128-ecb", key, null);
	c.setAutoPadding(false);
	return Buffer.concat([c.update(block), c.final()]);
};
const cbc = (key, iv, data, decrypt = false) => {
	const c = decrypt ? crypto.createDecipheriv("aes-128-cbc", key, iv) : crypto.createCipheriv("aes-128-cbc", key, iv);
	c.setAutoPadding(false);
	return Buffer.concat([c.update(data), c.final()]);
};
const u32 = (n) => {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n >>> 0);
	return b;
};
const u64 = (n) => {
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(n);
	return b;
};

/** The hash half of Apple's D function (crates/fairplay › d_hash). */
export function dHash(r2) {
	const PRIME = 813416437;
	const pad = Buffer.alloc(64);
	Buffer.from(r2).copy(pad);
	pad[r2.length] = 0x80;
	const m = [];
	for (let i = 0; i < 14; i++) m.push(pad.readUInt32BE(4 * i));
	for (let i = 1; i < 7; i++) m[0] = (m[0] + m[i]) >>> 0;
	m[1] = 0;
	for (let i = 0; i < 7; i++) m[1] = (m[1] + m[i + 7]) >>> 0;
	for (const w of [0, 1]) {
		for (let r = 0; r < 16; r++) {
			if (m[w] & 1) m[w] = m[w] >>> 1;
			else m[w] = ((Math.imul(m[w], 3) + 1) >>> 0) % PRIME;
		}
	}
	for (let i = 0; i < 4; i++) {
		pad[56 + i] = (m[0] >>> (8 * i)) & 0xff;
		pad[60 + i] = (m[1] >>> (8 * i)) & 0xff;
	}
	return sha1(pad).subarray(0, 16);
}

/** One TLLV: tag, block length, value length, value, random padding. */
function tllv(tag, value) {
	const padLen = 32 - (value.length % 16);
	return Buffer.concat([u64(tag), u32(value.length + padLen), u32(value.length), value, crypto.randomBytes(padLen)]);
}

function parseTllvs(buf) {
	const out = [];
	for (let o = 0; o < buf.length; ) {
		const tag = buf.readBigUInt64BE(o);
		const block = buf.readUInt32BE(o + 8);
		const len = buf.readUInt32BE(o + 12);
		out.push([tag, buf.subarray(o + 16, o + 16 + len)]);
		o += 16 + block;
	}
	return out;
}

/** Throwaway credentials, and the vars a suite's server takes them as. */
export function throwawayCredentials() {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
	const cert = Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x00]), crypto.randomBytes(256)]);
	const ask = crypto.randomBytes(16);
	return {
		publicKey,
		cert,
		ask,
		vars: {
			FAIRPLAY_CERT: cert.toString("base64"),
			FAIRPLAY_PRIVATE_KEY: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
			FAIRPLAY_ASK: ask.toString("hex"),
		},
	};
}

/** An SPC asking for `assetId`, and the session to open its CKC with. */
export function buildSpc(creds, assetId) {
	const r = (n) => crypto.randomBytes(n);
	const [sk, hu, r1, r2, seed, integrity, skr1Iv, tx] = [r(16), r(20), r(44), r(21), r(16), r(16), r(16), r(8)];
	const dask = ecb(creds.ask, dHash(r2));
	const skr1 = Buffer.concat([skr1Iv, cbc(dask, skr1Iv, Buffer.concat([sk, hu, r1, integrity]))]);
	const body = Buffer.concat([
		tllv(TAG.SK_R1, skr1),
		tllv(TAG.SK_R1_INTEGRITY, integrity),
		tllv(TAG.ANTI_REPLAY_SEED, seed),
		tllv(TAG.R2, r2),
		tllv(TAG.ASSET_ID, Buffer.from(assetId)),
		tllv(TAG.TRANSACTION_ID, tx),
		tllv(TAG.PROTOCOL_VERSIONS_SUPPORTED, u32(1)),
		tllv(TAG.PROTOCOL_VERSION_USED, u32(1)),
		tllv(TAG.STREAMING_INDICATOR, u64(0x891dbf47c0e666abn)),
		tllv(TAG.RETURN_REQUEST, Buffer.concat([u64(TAG.ASSET_ID), u64(TAG.TRANSACTION_ID)])),
	]);
	const spck = r(16);
	const iv = r(16);
	const payload = cbc(spck, iv, body);
	const wrapped = crypto.publicEncrypt({ key: creds.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, spck);
	const spc = Buffer.concat([u32(1), u32(0), iv, wrapped, sha1(creds.cert), u32(payload.length), payload]);
	return { spc, session: { sk, r1, seed } };
}

/** What a CKC carries for this session: its TLLVs, and the content key. */
export function openCkc(session, ckc) {
	const buf = Buffer.from(ckc);
	if (buf.readUInt32BE(0) !== 1) throw new Error(`CKC version ${buf.readUInt32BE(0)}`);
	const iv = buf.subarray(8, 24);
	const len = buf.readUInt32BE(24);
	const key = ecb(sha1(session.r1).subarray(0, 16), session.seed);
	const tllvs = parseTllvs(cbc(key, iv, buf.subarray(28, 28 + len), true));
	const ck = tllvs.find(([t]) => t === TAG.ENCRYPTED_CK)?.[1];
	if (!ck || ck.length !== 32) throw new Error("the CKC carries no content key");
	return { tllvs, iv: ck.subarray(0, 16), key: ecb(session.sk, ck.subarray(16, 32), true) };
}
