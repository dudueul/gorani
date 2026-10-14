#!/usr/bin/env node
// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * verify-export.mjs — check a gorani export package (docs/CUSTODY.md ›
 * Stage 7 › 29h) with Node alone: no gorani code, no dependencies, no
 * network. It is deliberately a SECOND implementation of everything it
 * checks — the zip reader, the statement encoding, the audit chain — so a
 * bug in gorani's writer and the same bug in its reader cannot agree.
 *
 *   node verify-export.mjs package.zip [--tsa <SHA-256 of a TSA key's SPKI, hex>]…
 *
 * It checks, and says which failed:
 *   - manifest.json is the bytes the exporter signed (SHA-256 + ECDSA P-256);
 *   - every identity's key id is the hash of its key, and its self-signature holds;
 *   - the export's approval: two different people, both signatures, this case;
 *   - every evidence entry: present, the size and SHA-256 the manifest says (samples
 *     are unzipped with "infected" first), and its uploader's signed hash record;
 *   - every intake record's signature, every custody link's two signatures and the
 *     chain's continuity, each reason against the digest its offer signed;
 *   - the audit trail: each line's hash recomputed from the previous one;
 *   - (commit 29j) every RFC 3161 timestamp: a version's over SHA-256 of its
 *     hashRecord's signature, a checkpoint's over the checkpoint's bytes —
 *     the TSA's signature (with Node's own X.509 parser), its signing-
 *     certificate binding and timestamping EKU, and its KEY certified by a
 *     lead in the package (tsa › certs) or named with --tsa.
 *
 * What it cannot decide for you: whether the exporter's key is who it says,
 * or whether a TSA's key is the authority's. It prints both fingerprints —
 * compare them out of band (the exporter in person; the TSA's certificate
 * on its own site).
 * Exit status: 0 when every check passed, 1 otherwise.
 */

import { createHash, createPublicKey, verify as verifySig, X509Certificate } from "node:crypto";
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

// ── RFC 3161 tokens (commit 29j) ─────────────────────────────────────
// Its own DER walk (web/src/vault/timestamp.ts has the other one); the
// certificate itself is read by Node's X509Certificate, a third parser.

function tlv(buf, at = 0) {
	const tag = buf[at];
	let len = buf[at + 1];
	let head = 2;
	if (tag === undefined || len === undefined) throw new Error("truncated DER");
	if (len & 0x80) {
		const n = len & 0x7f;
		if (n < 1 || n > 4) throw new Error("not DER (indefinite or huge length)");
		len = buf.readUIntBE(at + 2, n);
		head += n;
	}
	if (at + head + len > buf.length) throw new Error("truncated DER");
	return { tag, body: buf.subarray(at + head, at + head + len), raw: buf.subarray(at, at + head + len), end: at + head + len };
}
function kids(body) {
	const out = [];
	for (let at = 0; at < body.length; at = out[out.length - 1].end) out.push(tlv(body, at));
	return out.map(({ tag, body, raw }, i) => ({ tag, body, raw, i }));
}
const tagged = (t, tag, what) => {
	if (!t || t.tag !== tag) throw new Error(`${what}: expected tag ${tag.toString(16)}`);
	return t;
};
function oid(t) {
	const b = tagged(t, 0x06, "OID").body;
	const out = [];
	let v = 0;
	for (const x of b) {
		v = v * 128 + (x & 0x7f);
		if (x & 0x80) continue;
		if (!out.length) out.push(v < 80 ? Math.floor(v / 40) : 2, v < 80 ? v % 40 : v - 80);
		else out.push(v);
		v = 0;
	}
	return out.join(".");
}
const HASHES = { "2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512" };
const SIG_HASH = { "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512", "1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512" };
const stripZeros = (hex) => hex.replace(/^(00)+(?=.)/, "").toUpperCase();

/** { ok, why } or { ok, at, tsa, spki, fingerprint } — certification is the caller's. */
function checkStamp(tokenB64, imprintHex) {
	try {
		const token = Buffer.from(tokenB64, "base64");
		const [ctype, content] = kids(tlv(token).body);
		if (oid(ctype) !== "1.2.840.113549.1.7.2") return { ok: false, why: "not CMS SignedData" };
		const sd = kids(tagged(kids(tagged(content, 0xa0, "content").body)[0], 0x30, "SignedData").body);
		const [eType, eWrap] = kids(sd[2].body);
		if (oid(eType) !== "1.2.840.113549.1.9.16.1.4") return { ok: false, why: "the signed content is not a TSTInfo" };
		const eContent = tagged(kids(tagged(eWrap, 0xa0, "eContent").body)[0], 0x04, "eContent").body;
		const tst = kids(tlv(eContent).body);
		const [mAlg, mHash] = kids(tst[2].body);
		if (oid(kids(mAlg.body)[0]) !== "2.16.840.1.101.3.4.2.1" || mHash.body.toString("hex") !== imprintHex) return { ok: false, why: "the token is over other bytes" };
		const g = tagged(tst[4], 0x18, "genTime").body.toString("latin1");
		const at = `${g.slice(0, 4)}-${g.slice(4, 6)}-${g.slice(6, 8)}T${g.slice(8, 10)}:${g.slice(10, 12)}:${g.slice(12)}`;
		let rest = sd.slice(3);
		const certs = rest[0]?.tag === 0xa0 ? kids(rest.shift().body).filter((c) => c.tag === 0x30).map((c) => ({ raw: Buffer.from(c.raw), x: new X509Certificate(c.raw) })) : [];
		if (rest[0]?.tag === 0xa1) rest.shift();
		const signers = kids(tagged(rest[0], 0x31, "signerInfos").body);
		const si = kids(tagged(signers[0], 0x30, "SignerInfo").body);
		const serial = si[1].tag === 0x30 ? stripZeros(kids(si[1].body)[1].body.toString("hex")) : null;
		const cert = certs.find((c) => serial && stripZeros(c.x.serialNumber) === serial) ?? (serial ? null : certs[0]);
		if (!cert) return { ok: false, why: "the token carries no certificate for its signer" };
		const digest = HASHES[oid(kids(si[2].body)[0])];
		if (!digest) return { ok: false, why: "an unsupported digest" };
		const signedAttrs = tagged(si[3], 0xa0, "signedAttrs");
		const attrs = new Map(kids(signedAttrs.body).map((a) => {
			const [type, values] = kids(a.body);
			return [oid(type), kids(values.body)];
		}));
		if (oid(attrs.get("1.2.840.113549.1.9.3")?.[0]) !== "1.2.840.113549.1.9.16.1.4") return { ok: false, why: "contentType is not TSTInfo" };
		if (!attrs.get("1.2.840.113549.1.9.4")?.[0]?.body.equals(createHash(digest).update(eContent).digest())) return { ok: false, why: "messageDigest does not match the TSTInfo" };
		const ess2 = attrs.get("1.2.840.113549.1.9.16.2.47")?.[0];
		const ess1 = attrs.get("1.2.840.113549.1.9.16.2.12")?.[0];
		const firstId = (attr) => kids(kids(kids(attr.body)[0].body)[0].body);
		let bound = false;
		if (ess2) {
			const id = firstId(ess2);
			const alg = id[0].tag === 0x30 ? HASHES[oid(kids(id[0].body)[0])] : "sha256";
			const hash = (id[0].tag === 0x30 ? id[1] : id[0]).body;
			bound = !!alg && hash.equals(createHash(alg).update(cert.raw).digest());
		} else if (ess1) {
			bound = firstId(ess1)[0].body.equals(createHash("sha1").update(cert.raw).digest());
		}
		if (!bound) return { ok: false, why: "the signing-certificate attribute does not name this certificate" };
		if (!(cert.x.keyUsage ?? []).includes("1.3.6.1.5.5.7.3.8")) return { ok: false, why: "the certificate is not for timestamping (EKU)" };
		const t = Date.parse(at);
		if (t < Date.parse(cert.x.validFrom) || t > Date.parse(cert.x.validTo)) return { ok: false, why: "stamped outside the certificate's validity" };
		const sigAlg = oid(kids(si[4].body)[0]);
		const hash = sigAlg === "1.2.840.113549.1.1.1" ? digest : SIG_HASH[sigAlg];
		if (!hash) return { ok: false, why: `an unsupported signature algorithm ${sigAlg}` };
		const data = Buffer.from(signedAttrs.raw);
		data[0] = 0x31; // signed as a SET, carried as [0]
		const key = cert.x.publicKey;
		const sigOk = verifySig(hash, data, key.asymmetricKeyType === "ec" ? { key, dsaEncoding: "der" } : key, tagged(si[5], 0x04, "signature").body);
		if (!sigOk) return { ok: false, why: "the TSA's signature does not verify" };
		const spki = sha256hex(key.export({ type: "spki", format: "der" }));
		const tsa = /CN=([^\n,]+)/.exec(cert.x.subject)?.[1] ?? cert.x.subject;
		return { ok: true, at, tsa, spki, fingerprint: cert.x.fingerprint256 };
	} catch (e) {
		return { ok: false, why: `not a readable timestamp token (${e.message})` };
	}
}

// ── the checks ───────────────────────────────────────────────────────

const args = process.argv.slice(2);
const path = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--tsa");
const pinnedTsas = new Set(args.flatMap((a, i) => (args[i - 1] === "--tsa" ? [a.toLowerCase()] : [])));
if (!path) {
	console.error("usage: node verify-export.mjs package.zip [--tsa <SHA-256 of a TSA key's SPKI, hex>]…");
	process.exit(2);
}
const results = [];
const notes = [];
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

// The TSA keys that count: certified by a lead whose identity is in the
// package (and checked above), or named on the command line.
const tsaKeys = new Map([...pinnedTsas].map((k) => [k, ["--tsa"]]));
for (const c of m.tsa?.certs ?? []) {
	const ok = signedBy(c.by, c.keyId, stmt("gorani-tsa-v1", c.spki, c.name), c.signature);
	check(ok, `TSA key ${c.spki.slice(0, 16)}… (${c.name}): certified by ${c.by}, signed`);
	if (ok) tsaKeys.set(c.spki, [...(tsaKeys.get(c.spki) ?? []), c.by]);
}
const seenTsas = new Map();
/** One stamp, reported: valid, over the right bytes, by a key that counts. */
function stampCheck(label, tokenB64, imprintHex) {
	const r = checkStamp(tokenB64, imprintHex);
	if (!r.ok) return check(false, `${label}: timestamp — ${r.why}`);
	seenTsas.set(r.spki, r);
	const by = tsaKeys.get(r.spki);
	check(!!by, `${label}: timestamped ${r.at} by ${r.tsa}${by ? ` (key certified by ${by.join(", ")})` : ` — its key ${r.spki.slice(0, 16)}… is certified by nobody in this package (pass --tsa to trust it)`}`);
}

// The two-person approval.
const a = m.approval;
check(a.action === "case.export" && a.id === m.exportId && a.approvedBy && a.approvedBy !== a.requestedBy, "an export approval for this export, by two different people");
check(signedBy(a.requestedBy, null, stmt("gorani-approval-v1", a.id, a.action, m.case, a.requestedBy), a.requestSignature), `requested by ${a.requestedBy}, signed`);
check(signedBy(a.approvedBy, null, stmt("gorani-approve-v1", a.id, a.action, m.case, a.requestedBy, a.approvedBy), a.approveSignature), `approved by ${a.approvedBy}, signed`);

// The evidence.
for (const f of m.files) {
	for (const v of f.versions) {
		// The bytes; then the records, which stand on their own — a missing
		// entry does not hide what the signatures and stamps say.
		const entry = zip.get(v.path);
		if (!entry) check(false, `${f.name} v${v.version}: ${v.path} is in the package`);
		else {
			let plain = null;
			try {
				plain = v.packed === "zip-infected" ? unzipCrypto([...readZip(entry.data).values()][0], "infected") : entry.data;
			} catch (e) {
				check(false, `${f.name} v${v.version}: the sample zip opens (${e.message})`);
			}
			if (plain) check(plain.length === v.size && sha256hex(plain) === v.sha256, `${f.name} v${v.version}: ${v.size} bytes, SHA-256 ${v.sha256.slice(0, 16)}…`);
		}
		const r = v.hashRecord;
		check(r && r.sha256 === v.sha256 && r.size === v.size && signedBy(r.signer, r.keyId, stmt("gorani-content-hash-v1", area, f.id, String(v.version), r.sha256, String(r.size)), r.signature), `${f.name} v${v.version}: signed by its uploader${r ? ` (${r.signer})` : " — no record"}`);
		// The stamp dates THAT signature: its imprint is the signature's SHA-256.
		if (v.stamp && r) stampCheck(`${f.name} v${v.version}`, v.stamp.token, sha256hex(Buffer.from(r.signature, "base64")));
		else notes.push(`${f.name} v${v.version}: not timestamped`);
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

// The checkpoints' timestamps: each over the checkpoint's bytes, and the
// checkpoint naming the chain's hash at its line — so the token dates every
// line up to it.
const byId = new Map(m.audit.lines.map((l) => [l.id, l.hash]));
for (const cp of m.audit.verify?.checkpoints ?? []) {
	if (!cp.token || !cp.body) continue;
	let body;
	try {
		body = JSON.parse(cp.body);
	} catch {
		check(false, `audit checkpoint ${cp.date}: its body is not JSON`);
		continue;
	}
	if (byId.has(body.seq)) check(byId.get(body.seq) === body.hash && body.area === area, `audit checkpoint ${cp.date}: names line ${body.seq} of this trail, as the chain has it`);
	else notes.push(`audit checkpoint ${cp.date}: line ${body.seq} is outside the exported lines`);
	stampCheck(`audit checkpoint ${cp.date} (lines to ${body.seq})`, cp.token, sha256hex(Buffer.from(cp.body, "utf8")));
}

// The report.
const exporter = ids.get(m.exporter);
const fp = exporter ? exporter.keyId.slice(0, 32).toUpperCase().match(/.{4}/g).join(" ") : "(unknown)";
for (const r of results) console.log(`${r.ok ? "✔" : "✘"} ${r.what}`);
for (const n of notes) console.log(`· ${n}`);
const failed = results.filter((r) => !r.ok).length;
console.log("");
console.log(`case ${m.case}, export ${m.exportId}: ${results.length - failed} of ${results.length} checks passed${m.problems?.length ? `; the exporter recorded ${m.problems.length} problem(s): ${m.problems.join("; ")}` : ""}`);
console.log(`exporter ${m.exporter}, fingerprint ${fp} — compare it with them, out of band`);
for (const t of seenTsas.values()) console.log(`TSA ${t.tsa}: certificate SHA-256 ${t.fingerprint} — compare it with the authority's own published certificate`);
process.exit(failed ? 1 : 0);
