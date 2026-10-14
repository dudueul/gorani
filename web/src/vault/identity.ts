// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Member identity keys — docs/CASES.md › Member identity keys (stage 4,
 * commit 27). Until now a key copy sealed to you by SOMEONE ELSE could be
 * checked for consistency, never for authenticity: the server that stores
 * the copy also stores the public halves it is checked against (O3's
 * trust-on-first-use gap). Signatures close it, and three ideas carry the
 * whole module:
 *
 * 1. **An identity key per member** — ECDSA P-256 / SHA-256, the private
 *    half sealed to the member's own root, the public half in the registry.
 *    Its id is a full SHA-256; its **fingerprint** is the first 128 bits in
 *    eight groups (`3F2A 9C1B …`), short enough to read aloud.
 * 2. **Trust is the member's own decision, stored where the server cannot
 *    forge it.** A member PINS the identities they verified themselves
 *    (comparing fingerprints in person or on a call — a lead's, at least).
 *    The pins live in the member's vault settings under a MAC from their
 *    root (records.ts' key, another domain), so a server that adds a pin
 *    breaks the MAC. A **certificate** — a pinned member's signature over
 *    (member, identity key id, root digest) — extends trust ONE hop: a lead
 *    the member pinned vouches for everyone the lead verified.
 * 3. **Statements, not objects, are signed** — length-prefixed fields under
 *    a domain string (`stmt`), so a signature over a grant can never be
 *    replayed as a certificate:
 *
 * ```text
 * identity  "gorani-identity-v1" ‖ member ‖ identity key id ‖ root digest   (self-signed)
 * cert      "gorani-cert-v1"     ‖ member ‖ identity key id ‖ root digest   (by a certifier)
 * grant     "gorani-grant-v1"    ‖ case   ‖ case key digest ‖ grantee       (by the granter)
 * content   "gorani-content-hash-v1" ‖ area ‖ file ‖ version ‖ SHA-256 ‖ size   (by the uploader; content-hash.ts)
 * approval  "gorani-approval-v1" ‖ id ‖ action ‖ case ‖ requester              (two-person rule: who asked; approvals.ts)
 * approve   "gorani-approve-v1"  ‖ id ‖ action ‖ case ‖ requester ‖ approver   (…and the second lead who agreed)
 * intake    "gorani-intake-v1"   ‖ area ‖ file ‖ source ‖ collector ‖ method ‖ collected-at ‖ notes   (intake.ts)
 * offer     "gorani-custody-offer-v1"  ‖ area ‖ file ‖ seq ‖ from ‖ to ‖ SHA-256(reason)          (custody.ts)
 * accept    "gorani-custody-accept-v1" ‖ area ‖ file ‖ seq ‖ from ‖ to
 * export    "gorani-export-v1"   ‖ case ‖ export id ‖ SHA-256(manifest.json)   (the exporter; export.ts)
 * ```
 *
 * Digests are FULL SHA-256 of the public halves (ec raw ‖ ML-KEM public):
 * the short `keyId`s elsewhere are labels, ~84 bits — fine for "which
 * key", too short to sign as "this key" against a server with time to grind.
 *
 * The honest limits:
 * - **One hop.** A certificate counts only from an identity YOU pinned.
 *   That is the whole PKI: no chains, no expiry dates, no revocation lists —
 *   a team re-verifies when someone re-enrolls (the registry drops their
 *   certificates when their identity changes).
 * - **Departures.** A member who left keeps their identity key. What they
 *   signed while on the team still verifies (it must: a ceremony checks the
 *   recovery record its departed creator signed), so a server colluding
 *   with them could present a NEW signature as an old one. The registry
 *   flags them inactive (`Trusted.active`); re-pin and rotate the recovery
 *   key after a lead leaves (the recovery record says it is owed).
 * - **Rollback.** A server can replay an older, validly signed grant (an
 *   earlier case key) to a member who never saw the newer one. A client
 *   that has seen a newer key id should refuse an older one; this module
 *   gives the signatures, freshness is the caller's memory.
 */

import { fromBase64, toBase64, toHex } from "../lib/encoding.ts";
import { ecRawOfJwk, deriveRecordKey } from "./records.ts";
import { isHybridPrivate, kemPublicOf, openSealedText, sealText, type SealTarget, type VaultPrivateKey } from "./vault-crypto.ts";

const subtle = () => globalThis.crypto.subtle;
const enc = new TextEncoder();
const ECDSA = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

// ── statements ────────────────────────────────────────────────────────

/** lp(domain) ‖ lp(field)…, lp(x) = u32 BE length ‖ bytes — one spelling per statement. */
export function stmt(domain: string, ...fields: (string | Uint8Array)[]): Uint8Array {
	const parts = [domain, ...fields].map((f) => (typeof f === "string" ? enc.encode(f) : f));
	const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
	const view = new DataView(out.buffer);
	let at = 0;
	for (const p of parts) {
		view.setUint32(at, p.length);
		out.set(p, at + 4);
		at += 4 + p.length;
	}
	return out;
}

export const statements = {
	identity: (member: string, keyId: string, rootDigest: string) => stmt("gorani-identity-v1", member, keyId, rootDigest),
	cert: (member: string, keyId: string, rootDigest: string) => stmt("gorani-cert-v1", member, keyId, rootDigest),
	grant: (caseId: string, caseKeyDigest: string, grantee: string) => stmt("gorani-grant-v1", caseId, caseKeyDigest, grantee),
	contentHash: (area: string, file: string, version: number, sha256: string, size: number) => stmt("gorani-content-hash-v1", area, file, String(version), sha256, String(size)),
	approval: (id: string, action: string, caseId: string, requester: string) => stmt("gorani-approval-v1", id, action, caseId, requester),
	approve: (id: string, action: string, caseId: string, requester: string, approver: string) => stmt("gorani-approve-v1", id, action, caseId, requester, approver),
	intake: (area: string, file: string, source: string, collector: string, method: string, collectedAt: string, notes: string) => stmt("gorani-intake-v1", area, file, source, collector, method, collectedAt, notes),
	custodyOffer: (area: string, file: string, seq: number, from: string, to: string, reasonDigest: string) => stmt("gorani-custody-offer-v1", area, file, String(seq), from, to, reasonDigest),
	custodyAccept: (area: string, file: string, seq: number, from: string, to: string) => stmt("gorani-custody-accept-v1", area, file, String(seq), from, to),
	exportManifest: (caseId: string, exportId: string, manifestDigest: string) => stmt("gorani-export-v1", caseId, exportId, manifestDigest),
};

// ── ids, digests, fingerprints ────────────────────────────────────────

const sha256hex = async (bytes: Uint8Array) => toHex(new Uint8Array(await subtle().digest("SHA-256", bytes as BufferSource)));

/** An identity key's id: SHA-256 over its domain and uncompressed point, hex. */
export const identityKeyId = (publicKey: JsonWebKey) => sha256hex(stmt("gorani-identity-key-v1", ecRawOfJwk(publicKey)));

/** A hybrid key's FULL digest (a root's, a case key's), from its public halves. */
export const hybridDigest = (ec: JsonWebKey, kem: string) => sha256hex(stmt("gorani-hybrid-key-v1", ecRawOfJwk(ec), fromBase64(kem)));

/** The same digest from an opened private key (its public halves inside). */
export async function hybridDigestOf(key: VaultPrivateKey): Promise<string> {
	if (!isHybridPrivate(key)) throw new Error("hybrid keys only");
	return sha256hex(stmt("gorani-hybrid-key-v1", key.ecPublic, kemPublicOf(key.kem)));
}

/** What people compare: 128 bits of the id, eight groups of four. */
export function fingerprint(keyId: string): string {
	return keyId.slice(0, 32).toUpperCase().match(/.{4}/g)!.join(" ");
}

// ── the member's own identity ─────────────────────────────────────────

/** Who signs: the member and their non-extractable signing key. */
export interface Signer {
	member: string;
	keyId: string;
	sign(statement: Uint8Array): Promise<string>;
}

/** A pin: an identity the member verified themselves. */
export interface Pin {
	member: string;
	keyId: string;
}

/** The identity record in the member's vault settings (MAC'd by the root). */
export interface IdentityRecord {
	keyId: string;
	publicKey: JsonWebKey;
	privateKeySealed: string;
	pins: Pin[];
	mac?: string;
}

/** What the registry holds for each member (public, readable by members). */
export interface RegistryIdentity {
	member: string;
	keyId: string;
	publicKey: JsonWebKey;
	rootDigest: string;
	signature: string;
	/** False once the member left: their past signatures still verify (a
	 * grant, the recovery record); the registry takes no new ones. */
	active?: boolean;
	certs: { by: string; keyId: string; rootDigest: string; signature: string }[];
}

function pinsBytes(pins: Pin[]): Uint8Array[] {
	// Sorted, so the same set has one spelling whatever order it was built in.
	return [...pins].sort((a, b) => (a.member + "\0" + a.keyId < b.member + "\0" + b.keyId ? -1 : 1)).flatMap((p) => [enc.encode(p.member), enc.encode(p.keyId)]);
}

function identityRecordBytes(member: string, rec: IdentityRecord): Uint8Array {
	return stmt("gorani-identity-record-v1", member, rec.keyId, ecRawOfJwk(rec.publicKey), rec.privateKeySealed, ...pinsBytes(rec.pins));
}

async function macIdentity(root: VaultPrivateKey, member: string, rec: IdentityRecord): Promise<string> {
	const key = await deriveRecordKey(root);
	return toBase64(new Uint8Array(await subtle().sign("HMAC", key, identityRecordBytes(member, rec) as BufferSource)));
}

async function verifyIdentityMac(root: VaultPrivateKey, member: string, rec: IdentityRecord): Promise<boolean> {
	if (!rec.mac) return false;
	const key = await deriveRecordKey(root);
	return subtle().verify("HMAC", key, fromBase64(rec.mac) as BufferSource, identityRecordBytes(member, rec) as BufferSource);
}

const signerOf = (member: string, keyId: string, privateKey: CryptoKey): Signer => ({
	member,
	keyId,
	sign: async (s) => toBase64(new Uint8Array(await subtle().sign(SIGN, privateKey, s as BufferSource))),
});

/**
 * A member's new identity: the record for their vault settings (MAC'd,
 * self-pinned) and the body of `PUT /api/v1/family/identity`. The private
 * key is generated extractable ONCE, to be sealed to the root; the signer
 * returned holds a non-extractable re-import.
 */
export async function createIdentity(member: string, root: VaultPrivateKey, rootPublic: { ec: JsonWebKey; kem: string }): Promise<{ record: IdentityRecord; registry: Omit<RegistryIdentity, "member" | "certs">; signer: Signer }> {
	const pair = (await subtle().generateKey(ECDSA, true, ["sign", "verify"])) as CryptoKeyPair;
	const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
	const jwk = await subtle().exportKey("jwk", pair.publicKey);
	const publicKey: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
	const keyId = await identityKeyId(publicKey);
	const target: SealTarget = rootPublic;
	const privateKeySealed = await sealText(target, toBase64(pkcs8));
	const signing = await subtle().importKey("pkcs8", pkcs8 as BufferSource, ECDSA, false, ["sign"]);
	pkcs8.fill(0);
	const record: IdentityRecord = { keyId, publicKey, privateKeySealed, pins: [{ member, keyId }] };
	record.mac = await macIdentity(root, member, record);
	const rootDigest = await hybridDigest(rootPublic.ec, rootPublic.kem);
	const signer = signerOf(member, keyId, signing);
	return { record, signer, registry: { keyId, publicKey, rootDigest, signature: await signer.sign(statements.identity(member, keyId, rootDigest)) } };
}

/** Open the member's identity from their settings: MAC first, then the key. */
export async function openIdentity(member: string, root: VaultPrivateKey, rec: IdentityRecord): Promise<Signer> {
	if (!(await verifyIdentityMac(root, member, rec))) throw new Error("the identity record does not verify under your root — refusing it");
	if ((await identityKeyId(rec.publicKey)) !== rec.keyId) throw new Error("the identity record's key id does not match its key");
	const pkcs8 = fromBase64(await openSealedText(root, rec.privateKeySealed));
	try {
		return signerOf(member, rec.keyId, await subtle().importKey("pkcs8", pkcs8 as BufferSource, ECDSA, false, ["sign"]));
	} finally {
		pkcs8.fill(0);
	}
}

/** Pin another member's identity (after comparing fingerprints): a new
 * record for the settings, re-MAC'd. */
export async function pin(member: string, root: VaultPrivateKey, rec: IdentityRecord, add: Pin): Promise<IdentityRecord> {
	if (!(await verifyIdentityMac(root, member, rec))) throw new Error("the identity record does not verify under your root — refusing it");
	const pins = [...rec.pins.filter((p) => p.member !== add.member), add];
	const next: IdentityRecord = { keyId: rec.keyId, publicKey: rec.publicKey, privateKeySealed: rec.privateKeySealed, pins };
	next.mac = await macIdentity(root, member, next);
	return next;
}

/** A certificate: `signer` vouches that `who` is the member with this identity and root. */
export async function certify(signer: Signer, who: RegistryIdentity): Promise<{ keyId: string; rootDigest: string; signature: string }> {
	return { keyId: who.keyId, rootDigest: who.rootDigest, signature: await signer.sign(statements.cert(who.member, who.keyId, who.rootDigest)) };
}

// ── trust ─────────────────────────────────────────────────────────────

/** A member whose identity this client trusts, and why. */
export interface Trusted {
	member: string;
	keyId: string;
	rootDigest: string;
	via: "pin" | `cert:${string}`;
	/** False for a member who left (see RegistryIdentity.active). */
	active: boolean;
	verify(statement: Uint8Array, signature: string): Promise<boolean>;
}

const verifierOf = async (publicKey: JsonWebKey) => {
	const key = await subtle().importKey("jwk", { ...publicKey, ext: true }, ECDSA, false, ["verify"]);
	return async (s: Uint8Array, sig: string) => {
		try {
			return await subtle().verify(SIGN, key, fromBase64(sig) as BufferSource, s as BufferSource);
		} catch {
			return false;
		}
	};
};

export interface Trust {
	me: string;
	/** The trusted identity of `member`, or null. */
	of(member: string): Trusted | null;
}

/**
 * Decide, from the registry's identities and the member's OWN pins, whom to
 * trust. Every check is local: a registry entry counts only if its key id
 * matches its key, its self-signature verifies, and it is pinned — or
 * certified by a pinned identity whose own entry passed the same checks.
 */
export async function buildTrust(member: string, root: VaultPrivateKey, rec: IdentityRecord, registry: RegistryIdentity[]): Promise<Trust> {
	if (!(await verifyIdentityMac(root, member, rec))) throw new Error("the identity record does not verify under your root — refusing it");
	const pinned = new Map(rec.pins.map((p) => [p.member, p.keyId]));
	const sound = new Map<string, { entry: RegistryIdentity; verify: (s: Uint8Array, sig: string) => Promise<boolean> }>();
	for (const e of registry) {
		if ((await identityKeyId(e.publicKey)) !== e.keyId) continue;
		const verify = await verifierOf(e.publicKey);
		if (!(await verify(statements.identity(e.member, e.keyId, e.rootDigest), e.signature))) continue;
		sound.set(e.member, { entry: e, verify });
	}
	const trusted = new Map<string, Trusted>();
	const make = (e: RegistryIdentity, verify: Trusted["verify"], via: Trusted["via"]): Trusted => ({ member: e.member, keyId: e.keyId, rootDigest: e.rootDigest, via, active: e.active !== false, verify });
	for (const [m, { entry, verify }] of sound) if (pinned.get(m) === entry.keyId) trusted.set(m, make(entry, verify, "pin"));
	// One hop: a certificate counts only from a PINNED certifier.
	for (const [m, { entry, verify }] of sound) {
		if (trusted.has(m)) continue;
		for (const c of entry.certs) {
			const by = trusted.get(c.by);
			if (!by || by.via !== "pin" || c.keyId !== entry.keyId || c.rootDigest !== entry.rootDigest) continue;
			if (await by.verify(statements.cert(m, entry.keyId, entry.rootDigest), c.signature)) {
				trusted.set(m, make(entry, verify, `cert:${c.by}`));
				break;
			}
		}
	}
	return { me: member, of: (m) => trusted.get(m) ?? null };
}

/** A member's root, checked: its digest must be the one their trusted identity names. */
export async function trustedRoot(trust: Trust, root: { member: string; publicKey: JsonWebKey; pqPublicKey: string }): Promise<SealTarget> {
	const t = trust.of(root.member);
	if (!t) throw new Error(`${root.member}'s identity is not verified — compare fingerprints (or have a lead you verified certify them) first`);
	if ((await hybridDigest(root.publicKey, root.pqPublicKey)) !== t.rootDigest) throw new Error(`the root offered for ${root.member} is not the one their identity names — refusing to seal to it`);
	return { ec: root.publicKey, kem: root.pqPublicKey };
}
