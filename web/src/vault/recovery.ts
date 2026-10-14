// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Team recovery — M-of-N leads (docs/CASES.md › Recovery, › The protocol,
 * concretely; docs/DECISIONS.md › D4). Stage 5, commit 27.
 *
 * One **recovery key** per team (a hybrid pair, like any store key). Its
 * public half is what every area key is ALSO sealed to (a "recovery copy");
 * its private half never exists whole at rest: it is split with Shamir
 * (shamir.ts) into one share per lead, each share sealed to that lead's
 * root. Opening a recovery copy takes a **ceremony**:
 *
 * ```text
 * coordinator   makes an ephemeral key pair; signs (ceremony id, target,
 *               reason, ephemeral digest, recovery key id); posts it.
 * M approvers   verify the coordinator's signature against an identity they
 *               trust, open their own share, re-seal it to the ephemeral key.
 * coordinator   opens the M shares, combines them, CHECKS the result against
 *               the signed recovery digest, opens the target's recovery copy,
 *               re-seals the area key to its new holder, and lets the
 *               recovery key and the ephemeral key go.
 * ```
 *
 * Every public key the protocol seals to is checked first — the recovery
 * key against its creator's signature, each share's lead root against their
 * trusted identity, the ephemeral key against the coordinator's signature —
 * because each is a place where a server that controls the registry could
 * otherwise put a key of its own (the table in docs/CASES.md names them).
 *
 * The honest limit, unchanged from the design: the coordinator's browser
 * holds the whole recovery key while it combines. The registry marks the
 * key "rotation required" after every completed ceremony; `setupRecovery`
 * again (new key, new shares) and every area holder re-sealing their copy
 * is the remedy.
 */

import { combine, split } from "./shamir.ts";
import { createStoreKey, sealStoreKeyToMember, type SealingKey } from "./keys.ts";
import { checkRecordMatches } from "./records.ts";
import { hybridDigest, hybridDigestOf, statements, stmt, trustedRoot, type Signer, type Trust } from "./identity.ts";
import type { MemberRoot } from "./cases.ts";
import { hybridKeyId, importVaultKey, isHybridPrivate, kemPublicOf, openSealedText, sealText, type SealTarget, type VaultPrivateKey } from "./vault-crypto.ts";
import { fromBase64, toBase64, toBase64Url } from "../lib/encoding.ts";
import { newItemId } from "./places.ts";

/** The recovery record as `GET /api/v1/recovery` gives it (public). */
export interface RecoveryRecord {
	keyId: string;
	publicKey: { ec: JsonWebKey; kem: string };
	digest: string;
	threshold: number;
	holders: string[];
	createdBy: string;
	signature: string;
	rotationRequired: boolean;
}

/** A ceremony as `GET /api/v1/recovery/ceremonies` lists it. */
export interface Ceremony {
	id: string;
	coordinator: string;
	target: string;
	reason: string;
	ephemeralPublic: { ec: JsonWebKey; kem: string };
	ephemeralDigest: string;
	recoveryKeyId: string;
	signature: string;
	state: "open" | "done" | "cancelled";
	approvals: string[];
}

export const recoveryStatement = (digest: string, threshold: number, holders: string[]) => stmt("gorani-recovery-v1", digest, String(threshold), ...[...holders].sort());
export const ceremonyStatement = (c: Pick<Ceremony, "id" | "target" | "reason" | "ephemeralDigest" | "recoveryKeyId">) => stmt("gorani-ceremony-v1", c.id, c.target, c.reason, c.ephemeralDigest, c.recoveryKeyId);

// ── setup ─────────────────────────────────────────────────────────────

/**
 * A new team recovery key, split M-of-N to `holders` (every lead): the body
 * of `PUT /api/v1/recovery`. The private bundle is wiped before returning —
 * from here on it exists only as shares.
 */
export async function setupRecovery(signer: Signer, trust: Trust, holders: MemberRoot[], threshold: number): Promise<Record<string, unknown>> {
	const fresh = await createStoreKey();
	try {
		const digest = await hybridDigest(fresh.publicKey, fresh.pqPublicKey);
		const sorted = [...holders].sort((a, b) => (a.member < b.member ? -1 : 1));
		const pieces = split(fresh.bundle, threshold, sorted.length);
		const shares = [];
		for (let i = 0; i < sorted.length; i++) shares.push({ member: sorted[i]!.member, shareSealed: await sealText(await trustedRoot(trust, sorted[i]!), pieces[i]!) });
		const members = sorted.map((h) => h.member);
		return { keyId: fresh.keyId, publicKey: { ec: fresh.publicKey, kem: fresh.pqPublicKey }, digest, threshold, holders: members, signature: await signer.sign(recoveryStatement(digest, threshold, members)), shares };
	} finally {
		fresh.bundle.fill(0);
	}
}

/** The recovery public key — only after its creator's signature verifies
 * against an identity this client trusts, and its digest matches. */
export async function trustedRecoveryKey(trust: Trust, rec: RecoveryRecord): Promise<SealTarget> {
	const creator = trust.of(rec.createdBy);
	if (!creator) throw new Error(`the recovery key was set up by ${rec.createdBy}, whose identity you have not verified`);
	if ((await hybridDigest(rec.publicKey.ec, rec.publicKey.kem)) !== rec.digest) throw new Error("the recovery key's public halves do not match its digest");
	if (!(await creator.verify(recoveryStatement(rec.digest, rec.threshold, rec.holders), rec.signature))) throw new Error("the recovery key's signature does not verify — refusing to seal anything to it");
	return rec.publicKey;
}

/** A recovery copy of an area key (its bundle, base64): the body of
 * `PUT /api/v1/recovery/copies` minus the area. */
export async function sealRecoveryCopy(trust: Trust, rec: RecoveryRecord, bundleB64: string): Promise<{ keyId: string; sealed: string }> {
	return { keyId: rec.keyId, sealed: await sealText(await trustedRecoveryKey(trust, rec), bundleB64) };
}

// ── the ceremony ──────────────────────────────────────────────────────

/** Open a ceremony: the body of `POST /api/v1/recovery/ceremonies`, and the
 * ephemeral private key the coordinator keeps (and wipes when done). */
export async function newCeremony(signer: Signer, rec: RecoveryRecord, target: string, reason: string): Promise<{ body: Omit<Ceremony, "coordinator" | "state" | "approvals">; ephemeral: VaultPrivateKey }> {
	const eph = await createStoreKey();
	const ephemeralDigest = await hybridDigest(eph.publicKey, eph.pqPublicKey);
	const ephemeral = await importVaultKey(eph.bundle); // wipes the bundle
	const c = { id: newItemId(), target, reason, ephemeralPublic: { ec: eph.publicKey, kem: eph.pqPublicKey }, ephemeralDigest, recoveryKeyId: rec.keyId };
	return { ephemeral, body: { ...c, signature: await signer.sign(ceremonyStatement(c)) } };
}

/**
 * Approve: verify the ceremony is what its coordinator signed (a server that
 * swapped the ephemeral key would collect the shares), open your share,
 * re-seal it to the ephemeral key. The body of `PUT …/ceremonies/<id>/shares`.
 */
export async function approveCeremony(root: VaultPrivateKey, trust: Trust, c: Ceremony, rec: RecoveryRecord, myShareSealed: string): Promise<{ shareSealed: string }> {
	const coordinator = trust.of(c.coordinator);
	if (!coordinator) throw new Error(`the ceremony was opened by ${c.coordinator}, whose identity you have not verified`);
	if (c.recoveryKeyId !== rec.keyId) throw new Error("the ceremony names another recovery key");
	if ((await hybridDigest(c.ephemeralPublic.ec, c.ephemeralPublic.kem)) !== c.ephemeralDigest) throw new Error("the ceremony's key does not match its digest");
	if (!(await coordinator.verify(ceremonyStatement(c), c.signature))) throw new Error("the ceremony's signature does not verify — do NOT approve it");
	const share = await openSealedText(root, myShareSealed);
	return { shareSealed: await sealText(c.ephemeralPublic, share) };
}

/** Combine the approvals into the recovery key — and prove it IS the
 * recovery key (Shamir alone would silently yield a wrong one). */
export async function combineCeremony(ephemeral: VaultPrivateKey, sharesSealed: string[], rec: RecoveryRecord, trust: Trust): Promise<VaultPrivateKey> {
	await trustedRecoveryKey(trust, rec); // the digest we check against is the signed one
	const shares = [];
	for (const s of sharesSealed) shares.push(await openSealedText(ephemeral, s));
	const wrong = () => new Error("the combined shares do not make the recovery key — a share is wrong or from another split");
	const bundle = combine(shares);
	let key: VaultPrivateKey;
	try {
		key = await importVaultKey(bundle); // wipes the bundle
	} catch {
		throw wrong(); // a wrong share usually garbles the bundle past parsing
	}
	if (!isHybridPrivate(key) || (await hybridDigestOf(key)) !== rec.digest) throw wrong();
	return key;
}

// ── outcomes ──────────────────────────────────────────────────────────

/** A case nobody can open any more: a signed manage grant for `holder`,
 * from the case's recovery copy. The body of `…/complete` for a case. */
export async function recoverCaseGrant(recoveryKey: VaultPrivateKey, copySealed: string, caseInfo: { id: string; keyId: string; publicKey: { ec: JsonWebKey; kem: string } }, holder: MemberRoot, signer: Signer, trust: Trust) {
	const b64 = await openSealedText(recoveryKey, copySealed);
	const key = await importVaultKey(fromBase64(b64));
	await checkRecordMatches(key, { keyId: caseInfo.keyId, publicKey: caseInfo.publicKey.ec, pqPublicKey: caseInfo.publicKey.kem });
	return {
		grant: {
			member: holder.member,
			keyId: caseInfo.keyId,
			keySealed: await sealText(await trustedRoot(trust, holder), b64),
			signature: await signer.sign(statements.grant(caseInfo.id, await hybridDigestOf(key), holder.member)),
		},
	};
}

/** The P-256 JWK of a raw uncompressed point. */
function jwkOfRaw(raw: Uint8Array): JsonWebKey {
	return { kty: "EC", crv: "P-256", x: toBase64Url(raw.subarray(1, 33)), y: toBase64Url(raw.subarray(33, 65)) };
}

/**
 * A member who lost every unlock method: their own area's key, from its
 * recovery copy, sealed to the NEW root they enrolled. `draftRootDigest`
 * must be the digest the member read aloud to the coordinator — the one
 * check a server cannot fake (it would need the member's voice).
 */
export async function recoverMemberStore(recoveryKey: VaultPrivateKey, copySealed: string, draftRoot: { ec: JsonWebKey; kem: string }, confirmedDigest: string): Promise<{ storeRecord: SealingKey }> {
	if ((await hybridDigest(draftRoot.ec, draftRoot.kem)) !== confirmedDigest) throw new Error("the enrolled root is not the one the member confirmed — refusing to seal their area to it");
	const bundle = fromBase64(await openSealedText(recoveryKey, copySealed));
	const key = await importVaultKey(bundle.slice());
	if (!isHybridPrivate(key)) throw new Error("area keys are hybrid");
	const kemPub = kemPublicOf(key.kem);
	const store = { keyId: await hybridKeyId(key.ecPublic, kemPub), publicKey: jwkOfRaw(key.ecPublic), pqPublicKey: toBase64(kemPub), bundle };
	try {
		return { storeRecord: await sealStoreKeyToMember(store, draftRoot) };
	} finally {
		bundle.fill(0);
	}
}
