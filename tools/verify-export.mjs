#!/usr/bin/env node
// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * verify-export.mjs — check a gorani export package (docs/CUSTODY.md ›
 * Stage 7 › 29h) with Node alone: no gorani code, no dependencies, no
 * network. It is deliberately a SECOND implementation of everything it
 * checks — the zip reader, the statement encoding, the audit chain — so a
 * bug in gorani's writer and the same bug in its reader cannot agree.
 *
 *   node verify-export.mjs package.zip
 *
 * It checks, and says which failed:
 *   - manifest.json is the bytes the exporter signed (SHA-256 + ECDSA P-256);
 *   - every identity's key id is the hash of its key, and its self-signature holds;
 *   - the export's approval: two different people, both signatures, this case;
 *   - every evidence entry: present, the size and SHA-256 the manifest says (samples
 *     are unzipped with "infected" first), and its uploader's signed hash record;
 *   - every intake record's signature, every custody link's two signatures and the
 *     chain's continuity, each reason against the digest its offer signed;
 *   - the audit trail: each line's hash recomputed from the previous one.
 *
 * What it cannot decide for you: whether the exporter's key is who it says.
 * It prints the fingerprint — compare it with the exporter, out of band.
 * Exit status: 0 when every check passed, 1 otherwise.
 */

import { createHash, createPublicKey, verify as verifySig } from "node:crypto";
import { readFileSync } from "node:fs";

// ── the zip (stored entries; ZipCrypto for samples) ──────────────────

function readZip(buf) {
	let eocd = -1;
	for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
		if (buf.readUInt32LE(i) === 0x06054b50) {
			eocd = i;
			break;
		}
	}
	if (eocd < 0) throw new Error("not a zip (no end-of-central-directory record)");
	const count = buf.readUInt16LE(eocd + 10);
	let at = buf.readUInt32LE(eocd + 16);
	const entries = new Map();
	for (let n = 0; n < count; n++) {
		if (buf.readUInt32LE(at) !== 0x02014b50) throw new Error("a broken central directory");
		const flags = buf.readUInt16LE(at + 8);
		const method = buf.readUInt16LE(at + 10);
		const crc = buf.readUInt32LE(at + 16);
		const csize = buf.readUInt32LE(at + 20);
		const usize = buf.readUInt32LE(at + 24);
		const nlen = buf.readUInt16LE(at + 28);
		const xlen = buf.readUInt16LE(at + 30);
		const clen = buf.readUInt16LE(at + 32);
		const local = buf.readUInt32LE(at + 42);
		const name = buf.subarray(at + 46, at + 46 + nlen).toString("utf8");
		if (method !== 0) throw new Error(`${name}: compression method ${method} — gorani packages are stored`);
		const lnlen = buf.readUInt16LE(local + 26);
		const lxlen = buf.readUInt16LE(local + 28);
		const start = local + 30 + lnlen + lxlen;
		entries.set(name, { flags, crc, usize, data: buf.subarray(start, start + csize) });
		at += 46 + nlen + xlen + clen;
	}
	return entries;
}

const CRC = new Uint32Array(256).map((_, n) => {
	let c = n;
	for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
	return c >>> 0;
});
const crcStep = (c, b) => (CRC[(c ^ b) & 0xff] ^ (c >>> 8)) >>> 0;
const crc32 = (buf) => {
	let c = 0xffffffff;
	for (const b of buf) c = crcStep(c, b);
	return (c ^ 0xffffffff) >>> 0;
};

/** Decrypt a ZipCrypto entry (APPNOTE 6.1) and check its CRC. */
function unzipCrypto(entry, password) {
	let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
	const update = (b) => {
		k0 = crcStep(k0, b);
		k1 = (k1 + (k0 & 0xff)) >>> 0;
		k1 = (Math.imul(k1, 134775813) + 1) >>> 0;
		k2 = crcStep(k2, k1 >>> 24);
	};
	for (const b of Buffer.from(password, "utf8")) update(b);
	const out = Buffer.alloc(entry.data.length);
	for (let i = 0; i < entry.data.length; i++) {
		const t = (k2 | 2) & 0xffff;
		const p = entry.data[i] ^ (((t * (t ^ 1)) >>> 8) & 0xff);
		out[i] = p;
		update(p);
	}
	if (out[11] !== entry.crc >>> 24) throw new Error("wrong password");
	const plain = out.subarray(12);
	if (crc32(plain) !== entry.crc) throw new Error("CRC mismatch");
	return plain;
}

// ── statements and signatures ────────────────────────────────────────

/** lp(domain) ‖ lp(field)…, lp(x) = u32 BE length ‖ UTF-8 (identity.ts › stmt). */
function stmt(domain, ...fields) {
	const parts = [domain, ...fields].map((f) => (Buffer.isBuffer(f) ? f : Buffer.from(String(f), "utf8")));
	return Buffer.concat(parts.flatMap((p) => {
		const n = Buffer.alloc(4);
		n.writeUInt32BE(p.length);
		return [n, p];
	}));
}
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
const b64url = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const rawPoint = (jwk) => Buffer.concat([Buffer.from([4]), b64url(jwk.x), b64url(jwk.y)]);
function verifyWith(jwk, statement, signatureB64) {
	try {
		const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
		return verifySig("sha256", statement, { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signatureB64, "base64"));
	} catch {
		return false;
	}
}

// ── the checks ───────────────────────────────────────────────────────

const path = process.argv[2];
if (!path) {
	console.error("usage: node verify-export.mjs package.zip");
	process.exit(2);
}
const results = [];
const check = (ok, what) => results.push({ ok: !!ok, what });

const zip = readZip(readFileSync(path));
const manifestBytes = zip.get("manifest.json")?.data;
const sig = JSON.parse(zip.get("manifest.sig.json")?.data.toString("utf8") ?? "null");
if (!manifestBytes || !sig) {
	console.error("✘ manifest.json or manifest.sig.json is missing — not a gorani export package");
	process.exit(1);
}
const m = JSON.parse(manifestBytes.toString("utf8"));
const area = `case:${m.case}`;

// Identities: the key id is the key's hash, and the self-signature holds.
const ids = new Map();
for (const e of m.identities) {
	const keyOk = sha256hex(stmt("gorani-identity-key-v1", rawPoint(e.publicKey))) === e.keyId;
	const selfOk = verifyWith(e.publicKey, stmt("gorani-identity-v1", e.member, e.keyId, e.rootDigest), e.signature);
	check(keyOk && selfOk, `identity ${e.member} (${e.keyId.slice(0, 16)}…): key id and self-signature`);
	if (keyOk && selfOk) ids.set(e.member, e);
}
const signedBy = (member, keyId, statement, signature) => {
	const e = ids.get(member);
	return !!e && (!keyId || e.keyId === keyId) && verifyWith(e.publicKey, statement, signature);
};

// The manifest, as signed.
const digest = sha256hex(manifestBytes);
check(digest === sig.digest, `manifest.json is the signed bytes (SHA-256 ${digest.slice(0, 16)}…)`);
check(sig.case === m.case && sig.exportId === m.exportId && sig.exporter === m.exporter, "the signature names this case, export and exporter");
check(signedBy(m.exporter, sig.keyId, stmt("gorani-export-v1", m.case, m.exportId, digest), sig.signature), `the exporter's signature (${m.exporter})`);

// The two-person approval.
const a = m.approval;
check(a.action === "case.export" && a.id === m.exportId && a.approvedBy && a.approvedBy !== a.requestedBy, "an export approval for this export, by two different people");
check(signedBy(a.requestedBy, null, stmt("gorani-approval-v1", a.id, a.action, m.case, a.requestedBy), a.requestSignature), `requested by ${a.requestedBy}, signed`);
check(signedBy(a.approvedBy, null, stmt("gorani-approve-v1", a.id, a.action, m.case, a.requestedBy, a.approvedBy), a.approveSignature), `approved by ${a.approvedBy}, signed`);

// The evidence.
for (const f of m.files) {
	for (const v of f.versions) {
		const entry = zip.get(v.path);
		if (!entry) {
			check(false, `${f.name} v${v.version}: ${v.path} is in the package`);
			continue;
		}
		let plain;
		try {
			plain = v.packed === "zip-infected" ? unzipCrypto([...readZip(entry.data).values()][0], "infected") : entry.data;
		} catch (e) {
			check(false, `${f.name} v${v.version}: the sample zip opens (${e.message})`);
			continue;
		}
		check(plain.length === v.size && sha256hex(plain) === v.sha256, `${f.name} v${v.version}: ${v.size} bytes, SHA-256 ${v.sha256.slice(0, 16)}…`);
		const r = v.hashRecord;
		check(r && r.sha256 === v.sha256 && r.size === v.size && signedBy(r.signer, r.keyId, stmt("gorani-content-hash-v1", area, f.id, String(v.version), r.sha256, String(r.size)), r.signature), `${f.name} v${v.version}: signed by its uploader${r ? ` (${r.signer})` : " — no record"}`);
	}
	if (f.intake) {
		const i = f.intake;
		check(signedBy(i.signer, i.keyId, stmt("gorani-intake-v1", area, f.id, i.source, i.collector, i.method, i.collectedAt, i.notes), i.signature), `${f.name}: intake record signed by ${i.signer}`);
	}
	if (f.custody) {
		let holder = f.custody.owner;
		for (const l of f.custody.links) {
			const offer = signedBy(l.from, null, stmt("gorani-custody-offer-v1", area, f.id, String(l.seq), l.from, l.to, sha256hex(Buffer.from(l.reason ?? "", "utf8"))), l.offerSignature);
			const accept = !l.acceptedAt || signedBy(l.to, null, stmt("gorani-custody-accept-v1", area, f.id, String(l.seq), l.from, l.to), l.acceptSignature);
			check(offer && accept && l.from === holder, `${f.name}: custody link ${l.seq}, ${l.from} → ${l.to}`);
			if (l.acceptedAt) holder = l.to;
		}
		check(holder === f.custody.custodian, `${f.name}: held by ${f.custody.custodian} at export`);
	}
}

// The audit trail, recomputed.
const lp = (...fields) => stmt(...fields);
let prev = m.audit.base?.hash ?? "0".repeat(64);
let seq = m.audit.base?.seq ?? 0;
let chainOk = true;
for (const l of m.audit.lines) {
	const h = createHash("sha256").update(prev).update(lp("gorani-audit-v1", l.id, l.at, l.actor, l.action, l.target, l.details ?? "", l.detailsSealed ?? "")).digest("hex");
	if (l.id !== seq + 1 || h !== l.hash) chainOk = false;
	prev = l.hash;
	seq = l.id;
}
check(chainOk, `the audit trail: ${m.audit.lines.length} lines, each linked to the one before`);

// The report.
const exporter = ids.get(m.exporter);
const fp = exporter ? exporter.keyId.slice(0, 32).toUpperCase().match(/.{4}/g).join(" ") : "(unknown)";
for (const r of results) console.log(`${r.ok ? "✔" : "✘"} ${r.what}`);
const failed = results.filter((r) => !r.ok).length;
console.log("");
console.log(`case ${m.case}, export ${m.exportId}: ${results.length - failed} of ${results.length} checks passed${m.problems?.length ? `; the exporter recorded ${m.problems.length} problem(s): ${m.problems.join("; ")}` : ""}`);
console.log(`exporter ${m.exporter}, fingerprint ${fp} — compare it with them, out of band`);
process.exit(failed ? 1 : 0);
