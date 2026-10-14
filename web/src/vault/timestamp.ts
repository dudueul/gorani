// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Trusted timestamps — docs/CUSTODY.md › Stage 7 (D5.5, commit 29j). The
 * Worker asks the timestamp authority (worker/src/tsa.rs) and stores what
 * it answers; it vouches for none of it. This module is the READER'S check,
 * the one a review relies on.
 *
 * ```text
 * token     = ContentInfo(SignedData(TSTInfo { genTime, messageImprint, … }))   RFC 3161 / RFC 5652
 * version   imprint = SHA-256(the uploader's signature bytes)   (content-hash.ts record)
 * checkpoint imprint = SHA-256(the checkpoint's exact JSON bytes)
 * TSA cert  counts when a lead you trust signed stmt("gorani-tsa-v1", SHA-256(its SPKI), name)
 * ```
 *
 * The checks, and why each is there:
 *  1. **the imprint**: the token is over THIS record — a token moved from
 *     another version (or another deployment) names other bytes;
 *  2. **messageDigest**: the TSA's signed attributes commit to this TSTInfo
 *     (CMS signs the attributes, which carry the content's digest);
 *  3. **the signing-certificate attribute** (ESS, RFC 5035): the signature
 *     names the certificate it was made with — without it, a token could be
 *     re-wrapped with another certificate for the same key;
 *  4. **the certificate** is for timestamping (EKU) and was valid at genTime;
 *  5. **the signature** verifies under the certificate's key (WebCrypto:
 *     RSA PKCS#1 v1.5 or ECDSA — what TSAs use);
 *  6. **the key is certified** by someone you trust. Steps 1–5 prove "the
 *     holder of this key said so"; only step 6 says the holder is the TSA
 *     the team chose. A token that passes 1–5 and not 6 is `uncertified`,
 *     never `verified`.
 *
 * What this does NOT do is walk a certificate chain to a root: the team
 * pins the TSA's KEY (a lead compares the fingerprint the TSA publishes),
 * which is both simpler and stronger than trusting every CA a browser does.
 *
 * Its DER reader is deliberately small and strict (definite lengths,
 * single-byte tags), and tools/verify-export.mjs carries a second one —
 * written separately, so one misreading cannot agree with itself.
 */

import { fromBase64, toHex } from "../lib/encoding.ts";
import { statements, type Signer, type Trust } from "./identity.ts";

const subtle = () => globalThis.crypto.subtle;
const sha = async (alg: string, bytes: Uint8Array) => new Uint8Array(await subtle().digest(alg, bytes as BufferSource));
const sha256hex = async (bytes: Uint8Array) => toHex(await sha("SHA-256", bytes));

// ── DER ──────────────────────────────────────────────────────────────

interface Tlv {
	tag: number;
	body: Uint8Array;
	raw: Uint8Array;
}

class DerError extends Error {}

function tlvAt(buf: Uint8Array, at: number): { t: Tlv; next: number } {
	if (at + 2 > buf.length) throw new DerError("truncated DER");
	const tag = buf[at] ?? 0;
	if ((tag & 0x1f) === 0x1f) throw new DerError("a multi-byte DER tag");
	let len = buf[at + 1] ?? 0;
	let head = 2;
	if (len >= 0x80) {
		const n = len & 0x7f;
		if (n === 0 || n > 4) throw new DerError("an indefinite or oversized DER length");
		len = 0;
		for (let i = 0; i < n; i++) len = len * 256 + (buf[at + 2 + i] ?? 0);
		head = 2 + n;
	}
	const end = at + head + len;
	if (end > buf.length) throw new DerError("truncated DER");
	return { t: { tag, body: buf.subarray(at + head, end), raw: buf.subarray(at, end) }, next: end };
}

/** The TLVs that make up a constructed value's contents. */
function items(body: Uint8Array): Tlv[] {
	const out: Tlv[] = [];
	for (let at = 0; at < body.length; ) {
		const { t, next } = tlvAt(body, at);
		out.push(t);
		at = next;
	}
	return out;
}

/** A buffer that must be exactly one TLV of `tag`. */
function whole(buf: Uint8Array, tag: number, what: string): Tlv {
	const { t, next } = tlvAt(buf, 0);
	if (next !== buf.length) throw new DerError(`${what}: trailing bytes`);
	return want(t, tag, what);
}

function want(t: Tlv | undefined, tag: number, what: string): Tlv {
	if (!t) throw new DerError(`${what}: missing`);
	if (t.tag !== tag) throw new DerError(`${what}: tag 0x${t.tag.toString(16)}, expected 0x${tag.toString(16)}`);
	return t;
}

function oidOf(t: Tlv | undefined): string {
	const b = want(t, 0x06, "OID").body;
	const parts: number[] = [];
	let v = 0;
	for (const byte of b) {
		v = v * 128 + (byte & 0x7f);
		if (!(byte & 0x80)) {
			if (parts.length === 0) parts.push(v < 80 ? Math.floor(v / 40) : 2, v < 80 ? v % 40 : v - 80);
			else parts.push(v);
			v = 0;
		}
	}
	return parts.join(".");
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

const OID = {
	signedData: "1.2.840.113549.1.7.2",
	tstInfo: "1.2.840.113549.1.9.16.1.4",
	contentType: "1.2.840.113549.1.9.3",
	messageDigest: "1.2.840.113549.1.9.4",
	signingCertificate: "1.2.840.113549.1.9.16.2.12",
	signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
	commonName: "2.5.4.3",
	extKeyUsage: "2.5.29.37",
	subjectKeyId: "2.5.29.14",
	timeStamping: "1.3.6.1.5.5.7.3.8",
	rsa: "1.2.840.113549.1.1.1",
	ec: "1.2.840.10045.2.1",
} as const;

const DIGESTS: Record<string, string> = {
	"2.16.840.1.101.3.4.2.1": "SHA-256",
	"2.16.840.1.101.3.4.2.2": "SHA-384",
	"2.16.840.1.101.3.4.2.3": "SHA-512",
};
const RSA_SIGS: Record<string, string> = {
	"1.2.840.113549.1.1.11": "SHA-256",
	"1.2.840.113549.1.1.12": "SHA-384",
	"1.2.840.113549.1.1.13": "SHA-512",
};
const EC_SIGS: Record<string, string> = {
	"1.2.840.10045.4.3.2": "SHA-256",
	"1.2.840.10045.4.3.3": "SHA-384",
	"1.2.840.10045.4.3.4": "SHA-512",
};
const CURVES: Record<string, { name: string; size: number }> = {
	"1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
	"1.3.132.0.34": { name: "P-384", size: 48 },
	"1.3.132.0.35": { name: "P-521", size: 66 },
};

/** UTCTime / GeneralizedTime → ISO 8601 (UTC only — DER allows nothing else). */
function timeOf(t: Tlv): string {
	const s = new TextDecoder().decode(t.body);
	let full: string;
	if (t.tag === 0x17 && /^\d{12}Z$/.test(s)) full = `${Number(s.slice(0, 2)) < 50 ? "20" : "19"}${s}`;
	else if (t.tag === 0x18 && /^\d{14}(\.\d+)?Z$/.test(s)) full = s;
	else throw new DerError(`a time that is not UTC: ${s}`);
	return `${full.slice(0, 4)}-${full.slice(4, 6)}-${full.slice(6, 8)}T${full.slice(8, 10)}:${full.slice(10, 12)}:${full.slice(12)}`;
}

function textOf(t: Tlv): string {
	if (t.tag === 0x1e) {
		let s = "";
		for (let i = 0; i + 1 < t.body.length; i += 2) s += String.fromCharCode(((t.body[i] ?? 0) << 8) | (t.body[i + 1] ?? 0));
		return s;
	}
	return new TextDecoder().decode(t.body);
}

// ── certificates ────────────────────────────────────────────────────

interface Cert {
	raw: Uint8Array;
	serial: Uint8Array;
	issuer: Uint8Array;
	subject: string;
	notBefore: string;
	notAfter: string;
	spki: Uint8Array;
	spkiAlg: string;
	curve: string | null;
	eku: string[];
	ski: Uint8Array | null;
}

function readCert(raw: Uint8Array): Cert {
	const [tbs] = items(whole(raw, 0x30, "Certificate").body);
	const f = items(want(tbs, 0x30, "TBSCertificate").body);
	let i = f[0]?.tag === 0xa0 ? 1 : 0; // [0] version
	const serial = want(f[i++], 0x02, "serialNumber").body;
	i++; // signature algorithm
	const issuer = want(f[i++], 0x30, "issuer").raw;
	const validity = items(want(f[i++], 0x30, "validity").body);
	const subjectName = want(f[i++], 0x30, "subject");
	const spki = want(f[i++], 0x30, "subjectPublicKeyInfo");
	const [alg] = items(spki.body);
	const [algOid, params] = items(want(alg, 0x30, "algorithm").body);
	let subject = "";
	for (const rdn of items(subjectName.body)) {
		for (const atv of items(rdn.body)) {
			const [type, value] = items(atv.body);
			if (type && value && oidOf(type) === OID.commonName) subject = textOf(value);
		}
	}
	const eku: string[] = [];
	let ski: Uint8Array | null = null;
	for (const ext of f.slice(i)) {
		if (ext.tag !== 0xa3) continue;
		for (const e of items(want(items(ext.body)[0], 0x30, "extensions").body)) {
			const parts = items(e.body);
			const id = oidOf(parts[0]);
			const value = want(parts[parts.length - 1], 0x04, "extnValue").body;
			if (id === OID.extKeyUsage) for (const o of items(whole(value, 0x30, "ExtKeyUsage").body)) eku.push(oidOf(o));
			if (id === OID.subjectKeyId) ski = whole(value, 0x04, "SubjectKeyIdentifier").body;
		}
	}
	return {
		raw,
		serial,
		issuer,
		subject: subject || "(no common name)",
		notBefore: timeOf(want(validity[0], validity[0]?.tag === 0x18 ? 0x18 : 0x17, "notBefore")),
		notAfter: timeOf(want(validity[1], validity[1]?.tag === 0x18 ? 0x18 : 0x17, "notAfter")),
		spki: spki.raw,
		spkiAlg: oidOf(algOid),
		curve: params?.tag === 0x06 ? oidOf(params) : null,
		eku,
		ski,
	};
}

// ── the token ───────────────────────────────────────────────────────

interface ParsedToken {
	at: string;
	imprintAlg: string;
	imprint: string;
	eContent: Uint8Array;
	certs: Cert[];
	sid: { serial: Uint8Array; issuer: Uint8Array } | { ski: Uint8Array };
	digestAlg: string;
	signedAttrs: Uint8Array;
	attrs: Map<string, Tlv[]>;
	sigAlg: string;
	signature: Uint8Array;
}

function parseToken(der: Uint8Array): ParsedToken {
	const [ctype, content] = items(whole(der, 0x30, "ContentInfo").body);
	if (oidOf(ctype) !== OID.signedData) throw new DerError("not CMS SignedData");
	const sd = items(want(items(want(content, 0xa0, "content").body)[0], 0x30, "SignedData").body);
	const encap = items(want(sd[2], 0x30, "encapContentInfo").body);
	if (oidOf(encap[0]) !== OID.tstInfo) throw new DerError("the signed content is not a TSTInfo");
	const eContent = want(items(want(encap[1], 0xa0, "eContent").body)[0], 0x04, "eContent").body;
	const tst = items(whole(eContent, 0x30, "TSTInfo").body);
	const [mAlg, mHash] = items(want(tst[2], 0x30, "messageImprint").body);
	const imprintAlg = oidOf(items(want(mAlg, 0x30, "hashAlgorithm").body)[0]);
	const imprint = toHex(want(mHash, 0x04, "hashedMessage").body);
	const at = timeOf(want(tst[4], 0x18, "genTime"));
	let rest = sd.slice(3);
	const certs: Cert[] = [];
	if (rest[0]?.tag === 0xa0) {
		for (const c of items(rest[0].body)) if (c.tag === 0x30) certs.push(readCert(c.raw));
		rest = rest.slice(1);
	}
	if (rest[0]?.tag === 0xa1) rest = rest.slice(1); // crls
	const signers = items(want(rest[0], 0x31, "signerInfos").body);
	if (signers.length !== 1) throw new DerError(`${signers.length} signers — a timestamp token has one`);
	const si = items(want(signers[0], 0x30, "SignerInfo").body);
	const sidT = want(si[1], si[1]?.tag === 0x80 ? 0x80 : 0x30, "sid");
	const sid = sidT.tag === 0x30 ? (() => {
		const [issuer, serial] = items(sidT.body);
		return { issuer: want(issuer, 0x30, "issuer").raw, serial: want(serial, 0x02, "serialNumber").body };
	})() : { ski: want(sidT, 0x80, "subjectKeyIdentifier").body };
	const digestAlg = oidOf(items(want(si[2], 0x30, "digestAlgorithm").body)[0]);
	const signedAttrsT = want(si[3], 0xa0, "signedAttrs (a timestamp token signs its attributes)");
	const attrs = new Map<string, Tlv[]>();
	for (const a of items(signedAttrsT.body)) {
		const [type, values] = items(want(a, 0x30, "Attribute").body);
		attrs.set(oidOf(type), items(want(values, 0x31, "attribute values").body));
	}
	const sigAlg = oidOf(items(want(si[4], 0x30, "signatureAlgorithm").body)[0]);
	const signature = want(si[5], 0x04, "signature").body;
	return { at, imprintAlg, imprint, eContent, certs, sid, digestAlg, signedAttrs: signedAttrsT.raw, attrs, sigAlg, signature };
}

/** The certificate the SignerInfo names — by issuer and serial, or by key id. */
function signerCert(p: ParsedToken): Cert | undefined {
	const sid = p.sid;
	if ("ski" in sid) return p.certs.find((c) => c.ski && same(c.ski, sid.ski));
	return p.certs.find((c) => same(c.serial, sid.serial) && same(c.issuer, sid.issuer));
}

/** ECDSA's DER signature as the fixed-width r ‖ s WebCrypto verifies. */
function p1363(der: Uint8Array, size: number): Uint8Array {
	const [r, s] = items(whole(der, 0x30, "ECDSA signature").body);
	const out = new Uint8Array(size * 2);
	for (const [k, n] of [want(r, 0x02, "r"), want(s, 0x02, "s")].entries()) {
		let v = n.body;
		while (v.length > size && v[0] === 0) v = v.subarray(1);
		if (v.length > size) throw new DerError("an ECDSA integer wider than its curve");
		out.set(v, (k + 1) * size - v.length);
	}
	return out;
}

async function signatureHolds(cert: Cert, p: ParsedToken): Promise<boolean> {
	// CMS signs the DER of the attributes as a SET (tag 0x31), not the [0] it travels as.
	const signed = new Uint8Array(p.signedAttrs);
	signed[0] = 0x31;
	if (cert.spkiAlg === OID.rsa) {
		const hash = p.sigAlg === OID.rsa ? DIGESTS[p.digestAlg] : RSA_SIGS[p.sigAlg];
		if (!hash) throw new DerError(`unsupported RSA signature algorithm ${p.sigAlg}`);
		const key = await subtle().importKey("spki", cert.spki as BufferSource, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
		return subtle().verify("RSASSA-PKCS1-v1_5", key, p.signature as BufferSource, signed as BufferSource);
	}
	if (cert.spkiAlg === OID.ec) {
		const hash = EC_SIGS[p.sigAlg];
		const curve = cert.curve ? CURVES[cert.curve] : undefined;
		if (!hash || !curve) throw new DerError(`unsupported ECDSA algorithm or curve (${p.sigAlg}, ${cert.curve})`);
		const key = await subtle().importKey("spki", cert.spki as BufferSource, { name: "ECDSA", namedCurve: curve.name }, false, ["verify"]);
		return subtle().verify({ name: "ECDSA", hash }, key, p1363(p.signature, curve.size) as BufferSource, signed as BufferSource);
	}
	throw new DerError(`unsupported TSA key algorithm ${cert.spkiAlg}`);
}

// ── what a reader learns ────────────────────────────────────────────

/** Only `verified` means "a TSA the team chose saw this record by `at`". */
export type StampCheck =
	| { status: "verified"; at: string; tsa: string; spki: string; certifiedBy: string[] }
	| { status: "uncertified"; at: string; tsa: string; spki: string }
	| { status: "invalid"; why: string }
	| { status: "pending" }
	| { status: "absent"; why: string };

/** A lead's certification of a TSA key, as the registry lists it. */
export interface TsaCert {
	spki: string;
	name: string;
	by: string;
	keyId: string;
	signature: string;
	at?: string;
}

/** The TSA keys this reader counts: SPKI digest → who vouched for it. */
export type TrustedTsas = Map<string, { name: string; by: string[] }>;

/**
 * Keep the certifications that verify under the reader's OWN trust: the
 * certifier is someone they verified, with the key they verified. The
 * registry takes certifications only from leads; this does not rely on it.
 */
export async function trustedTsas(trust: Trust | null, certs: TsaCert[]): Promise<TrustedTsas> {
	const out: TrustedTsas = new Map();
	if (!trust) return out;
	for (const c of certs) {
		const t = trust.of(c.by);
		if (!t || t.keyId !== c.keyId) continue;
		if (!(await t.verify(statements.tsa(c.spki, c.name), c.signature))) continue;
		const entry = out.get(c.spki) ?? { name: c.name, by: [] };
		entry.by.push(c.by);
		out.set(c.spki, entry);
	}
	return out;
}

/**
 * Check a token against the imprint it must be over and the TSA keys the
 * reader counts. Every failure says which check failed.
 */
export async function checkToken(token: string | Uint8Array, imprint: string, trusted: TrustedTsas): Promise<StampCheck> {
	let p: ParsedToken;
	try {
		p = parseToken(typeof token === "string" ? fromBase64(token) : token);
	} catch (e) {
		return { status: "invalid", why: `not a timestamp token (${(e as Error).message})` };
	}
	if (p.imprintAlg !== "2.16.840.1.101.3.4.2.1" || p.imprint !== imprint) return { status: "invalid", why: "the token is over other bytes — not this record (moved from another version, or another deployment)" };
	const cert = signerCert(p);
	if (!cert) return { status: "invalid", why: "the token does not carry its signer's certificate" };
	try {
		const digest = DIGESTS[p.digestAlg];
		if (!digest) return { status: "invalid", why: `an unsupported digest algorithm (${p.digestAlg})` };
		const ct = p.attrs.get(OID.contentType)?.[0];
		if (!ct || oidOf(ct) !== OID.tstInfo) return { status: "invalid", why: "the signed attributes do not say the content is a TSTInfo" };
		const md = p.attrs.get(OID.messageDigest)?.[0];
		if (!md || !same(want(md, 0x04, "messageDigest").body, await sha(digest, p.eContent))) return { status: "invalid", why: "the TSA's signature does not cover this TSTInfo (messageDigest)" };
		if (!(await bindsCertificate(p, cert))) return { status: "invalid", why: "the token does not name the certificate it was signed with (ESS signing-certificate)" };
		if (!cert.eku.includes(OID.timeStamping)) return { status: "invalid", why: `${cert.subject}'s certificate is not issued for timestamping` };
		if (Date.parse(p.at) < Date.parse(cert.notBefore) || Date.parse(p.at) > Date.parse(cert.notAfter)) return { status: "invalid", why: `stamped ${p.at}, outside ${cert.subject}'s certificate validity (${cert.notBefore} – ${cert.notAfter})` };
		if (!(await signatureHolds(cert, p))) return { status: "invalid", why: `the signature does not verify under ${cert.subject}'s key` };
	} catch (e) {
		return { status: "invalid", why: (e as Error).message };
	}
	const spki = await sha256hex(cert.spki);
	const vouched = trusted.get(spki);
	if (!vouched) return { status: "uncertified", at: p.at, tsa: cert.subject, spki };
	return { status: "verified", at: p.at, tsa: cert.subject, spki, certifiedBy: vouched.by };
}

/** ESSCertIDv2 (SHA-256 unless named) or ESSCertID (SHA-1) over the certificate. */
async function bindsCertificate(p: ParsedToken, cert: Cert): Promise<boolean> {
	const v2 = p.attrs.get(OID.signingCertificateV2)?.[0];
	const v1 = p.attrs.get(OID.signingCertificate)?.[0];
	const first = (attr: Tlv) => items(want(items(want(attr, 0x30, "SigningCertificate").body)[0], 0x30, "certs").body)[0];
	if (v2) {
		const id = items(want(first(v2), 0x30, "ESSCertIDv2").body);
		const named = id[0]?.tag === 0x30 ? DIGESTS[oidOf(items(id[0].body)[0])] : "SHA-256";
		const hash = want(id[0]?.tag === 0x30 ? id[1] : id[0], 0x04, "certHash").body;
		return !!named && same(hash, await sha(named, cert.raw));
	}
	if (v1) return same(want(items(want(first(v1), 0x30, "ESSCertID").body)[0], 0x04, "certHash").body, await sha("SHA-1", cert.raw));
	return false;
}

// ── the two things gorani stamps ─────────────────────────────────────

/** A version's imprint: SHA-256 of its uploader's signature bytes. */
export const stampImprint = async (signatureB64: string) => sha256hex(fromBase64(signatureB64));

/** A version's stamp as `GET …/files/<id>/stamps` lists it. */
export interface VersionStamp {
	version: number;
	status: "stamped" | "pending" | "no-tsa" | "no-imprint" | "unsigned";
	imprint: string | null;
	token: string | null;
	at: string | null;
}

/**
 * Check a version's stamp against its OPENED hash record (content-hash.ts ›
 * openContentHash): the imprint must be that record's signature — or the
 * token dates something else entirely.
 */
export async function checkVersionStamp(record: { signature: string } | null, row: VersionStamp | undefined, trusted: TrustedTsas): Promise<StampCheck> {
	if (!row || !record) return { status: "absent", why: "no signed hash record to stamp" };
	if (row.status === "pending") return { status: "pending" };
	if (!row.token || !row.imprint) return { status: "absent", why: row.status === "no-tsa" ? "no timestamp authority is configured" : "recorded without a timestamp imprint" };
	const expected = await stampImprint(record.signature);
	if (row.imprint !== expected) return { status: "invalid", why: "the recorded imprint is not this hash record's signature" };
	return checkToken(row.token, expected, trusted);
}

/** An audit checkpoint's stamp: over the checkpoint's exact bytes. */
export async function checkCheckpointStamp(body: string, token: string | null | undefined, trusted: TrustedTsas): Promise<StampCheck> {
	if (!token) return { status: "absent", why: "this checkpoint has no token" };
	return checkToken(token, await sha256hex(new TextEncoder().encode(body)), trusted);
}

// ── certifying the TSA (a lead) ──────────────────────────────────────

/** What a lead compares before certifying: from a probe token's certificate. */
export interface TsaIdentity {
	name: string;
	spki: string;
	/** SHA-256 of the whole certificate, AB:CD:… — what `openssl x509 -fingerprint -sha256` and a TSA's page show. */
	certFingerprint: string;
	notBefore: string;
	notAfter: string;
}

export async function tsaIdentityOf(token: string): Promise<TsaIdentity> {
	const p = parseToken(fromBase64(token));
	const cert = signerCert(p);
	if (!cert) throw new Error("the TSA's token carries no certificate — it must answer certReq");
	const fp = (await sha256hex(cert.raw)).toUpperCase().match(/../g)?.join(":") ?? "";
	return { name: cert.subject, spki: await sha256hex(cert.spki), certFingerprint: fp, notBefore: cert.notBefore, notAfter: cert.notAfter };
}

/** A JSON call against the API (the shell's, or a test's). */
export type TsaCall = <T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown) => Promise<T>;

/** Sign "this key is our TSA" — only after comparing `certFingerprint` out of band. */
export async function certifyTsa(call: TsaCall, signer: Signer, tsa: { spki: string; name: string }): Promise<{ configured: boolean; certs: TsaCert[] }> {
	const signature = await signer.sign(statements.tsa(tsa.spki, tsa.name));
	return call("PUT", "/api/v1/family/tsa", { spki: tsa.spki, name: tsa.name, keyId: signer.keyId, signature });
}

/** One line for a person. */
export function describeStamp(c: StampCheck): string {
	switch (c.status) {
		case "verified":
			return `timestamped ${c.at} by ${c.tsa} (certified by ${c.certifiedBy.join(", ")})`;
		case "uncertified":
			return `⚠ timestamped ${c.at} by ${c.tsa} — a key nobody you trust certified (SPKI ${c.spki.slice(0, 16)}…)`;
		case "invalid":
			return `⚠ timestamp invalid: ${c.why}`;
		case "pending":
			return "timestamp pending — the timestamp authority has not answered yet";
		case "absent":
			return `not timestamped (${c.why})`;
	}
}
