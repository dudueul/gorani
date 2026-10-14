// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Case keys — the client half of docs/CASES.md › Areas and their keys
 * (commit 26) and › Member identity keys (commit 27). The registry
 * (worker/src/family.rs › Cases and grants) decides WHO may hold a case's
 * key; this module is the only code that ever holds one.
 *
 * A case is a store like a member's own area (lib/area.ts): one hybrid key
 * pair, GV04 places with `store` = `case:<id>`. What is new is where its
 * private half lives — not in anyone's settings, but in the GRANTS:
 *
 * ```text
 * open     the lead's browser makes the key; seals it to their own root
 *          (their grant, permission "manage") and SIGNS the grant; seals
 *          the title into the case's `case.title` place.
 * grant    a manager opens their own copy (verifying its signature), checks
 *          the grantee's root against the grantee's TRUSTED identity, seals
 *          the copy to it and signs (case, key digest, grantee).
 * open it  the grantee verifies the signature against an identity THEY
 *          trust (identity.ts › buildTrust), then opens the copy and checks
 *          it is the key the signature names.
 * revoke   the registry drops the grant and marks the case "rotation
 *          required" — the revoked member KEPT the key.
 * rotate   a fresh key, sealed and signed for every remaining grantee;
 *          commit it (the old copies stay as `prev` until…) → the reseal
 *          walk → "done".
 * ```
 *
 * Why the rotation commits BEFORE it walks (the member-store runbook walks
 * first): the new key must exist somewhere other than this tab before any
 * value is sealed to it. Walk first and crash half-way, and half the case
 * is sealed to a key that died with the tab. Commit first, and a crashed
 * walk resumes from the grants, which hold both keys — both SIGNED — until
 * "done". (An unsigned old key would let a server hand the resumed walk a
 * key of its own, and the walk would launder the server's values into the
 * real case key.)
 *
 * The limit that remains is identity.ts' rollback note: a validly signed
 * OLDER grant can be replayed to a member who never saw the newer one.
 */

import { createStoreKey } from "./keys.ts";
import { checkRecordMatches } from "./records.ts";
import { places } from "./places.ts";
import { opensAnything, resealStore, type ApiCall, type RotationReport } from "./rotation.ts";
import { hybridDigest, hybridDigestOf, statements, trustedRoot, type Signer, type Trust } from "./identity.ts";
import { importVaultKey, openPlacedText, openSealedText, sealPlacedText, sealText, type VaultPrivateKey } from "./vault-crypto.ts";
import { fromBase64, toBase64 } from "../lib/encoding.ts";
import { caseArea } from "../lib/area.ts";

export type CaseKind = "evidence" | "working";
export type CasePermission = "read" | "write" | "manage";

/** A case as `GET /api/v1/cases` lists it. */
export interface CaseRow {
	id: string;
	kind: CaseKind;
	titleSealed: string | null;
	keyId: string;
	publicKey: { ec: JsonWebKey; kem: string };
	createdBy: string;
	createdAt: string;
	closed: boolean;
	rotationRequired: boolean;
	/** A rotation whose reseal walk has not finished. */
	rotating: { prevKeyId: string } | null;
	/** A legal hold (commit 29f): placed by one person, lifted only by two. */
	hold?: { since: string } | null;
	/** The caller's own grant, with their key copy and who signed it — null
	 * for a lead's or auditor's structure-only view. */
	grant: {
		permission: CasePermission;
		keySealed: string;
		keyId: string;
		expiresAt: string | null;
		signature: string | null;
		signedBy: string | null;
		prevKeySealed: string | null;
		prevSignature: string | null;
		prevSignedBy: string | null;
	} | null;
	grantees: { member: string; permission: CasePermission; expiresAt: string | null }[];
}

/** A grantee's root public halves (`GET /api/v1/members/<id>/root`). */
export interface MemberRoot {
	member: string;
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey: string;
}

/** The record a copy must match: the registry's public halves for the case. */
const recordOf = (keyId: string, pub: { ec: JsonWebKey; kem: string }) => ({ keyId, publicKey: pub.ec, pqPublicKey: pub.kem });

/**
 * Open a copy, verified: the signer must be an identity `trust` trusts, the
 * signature must name THIS case, THIS key (by full digest) and `trust.me`.
 * Returns the key and its bundle text (a manager re-seals the latter).
 */
async function openSigned(root: VaultPrivateKey, trust: Trust, caseId: string, sealed: string, signature: string | null, signedBy: string | null): Promise<{ key: VaultPrivateKey; b64: string }> {
	if (!signature || !signedBy) throw new Error(`your copy of case ${caseId}'s key is unsigned — ask a manager to grant it again`);
	const signer = trust.of(signedBy);
	if (!signer) throw new Error(`your copy of case ${caseId}'s key was signed by ${signedBy}, whose identity you have not verified`);
	const b64 = await openSealedText(root, sealed);
	const key = await importVaultKey(fromBase64(b64));
	if (!(await signer.verify(statements.grant(caseId, await hybridDigestOf(key), trust.me), signature))) {
		throw new Error(`the signature on your copy of case ${caseId}'s key does not verify — it is not the key ${signedBy} granted you`);
	}
	return { key, b64 };
}

/**
 * Open a new case: the body of `POST /api/v1/cases`, and the case key (the
 * caller keeps it for the first uploads, then lets it go like any key).
 */
export async function newCase(id: string, kind: CaseKind, title: string, openerRoot: { ec: JsonWebKey; kem: string }, signer: Signer): Promise<{ body: Record<string, unknown>; key: VaultPrivateKey }> {
	const fresh = await createStoreKey();
	const keySealed = await sealText(openerRoot, toBase64(fresh.bundle));
	const key = await importVaultKey(fresh.bundle); // wipes the bundle
	const titleSealed = await sealPlacedText(key, places.caseTitle(caseArea(id)), title);
	const signature = await signer.sign(statements.grant(id, await hybridDigest(fresh.publicKey, fresh.pqPublicKey), signer.member));
	return { key, body: { id, kind, keyId: fresh.keyId, publicKey: { ec: fresh.publicKey, kem: fresh.pqPublicKey }, keySealed, titleSealed, signature } };
}

/** Open your copy of a case key — signed by someone you trust, and the
 * case's key (the registry's public halves agree). */
export async function openCaseKey(root: VaultPrivateKey, c: CaseRow, trust: Trust): Promise<VaultPrivateKey> {
	if (!c.grant) throw new Error(`you hold no grant on case ${c.id}`);
	const { key } = await openSigned(root, trust, c.id, c.grant.keySealed, c.grant.signature, c.grant.signedBy);
	await checkRecordMatches(key, recordOf(c.keyId, c.publicKey));
	return key;
}

/** The case's title, opened in its place. */
export function openCaseTitle(key: VaultPrivateKey, c: CaseRow): Promise<string | null> {
	return c.titleSealed ? openPlacedText(key, places.caseTitle(caseArea(c.id)), c.titleSealed) : Promise.resolve(null);
}

/**
 * The body of `PUT …/grants/<member>` minus the permission: your copy,
 * verified, re-sealed to the grantee's root — which must be the root their
 * TRUSTED identity names (a server cannot slip in a root of its own) — and
 * signed.
 */
export async function sealCaseGrant(root: VaultPrivateKey, c: CaseRow, grantee: MemberRoot, signer: Signer, trust: Trust): Promise<{ keySealed: string; keyId: string; signature: string }> {
	if (!c.grant) throw new Error(`you hold no grant on case ${c.id}`);
	const target = await trustedRoot(trust, grantee);
	const { key, b64 } = await openSigned(root, trust, c.id, c.grant.keySealed, c.grant.signature, c.grant.signedBy);
	await checkRecordMatches(key, recordOf(c.keyId, c.publicKey));
	const signature = await signer.sign(statements.grant(c.id, await hybridDigestOf(key), grantee.member));
	return { keySealed: await sealText(target, b64), keyId: c.keyId, signature };
}

export interface CaseRotation {
	report: RotationReport;
	/** The new key — the caller's to use, then let go. */
	key: VaultPrivateKey;
}

/**
 * Rotate a case key, or resume a rotation a crashed tab left walking.
 *
 * `grantees` are the roots of EVERY remaining grantee (yourself included),
 * fetched by the caller; each is checked against its trusted identity, and
 * the registry refuses a set that is one short or one long. `call` is the
 * JSON API (the bridge's, or a test's).
 */
export async function rotateCase(call: ApiCall, root: VaultPrivateKey, c: CaseRow, grantees: MemberRoot[], signer: Signer, trust: Trust): Promise<CaseRotation> {
	if (!c.grant) throw new Error(`you hold no grant on case ${c.id}`);
	let oldKey: VaultPrivateKey;
	let newKey: VaultPrivateKey;
	if (c.rotating) {
		// Resume: the grant holds both keys, both signed, until "done".
		if (!c.grant.prevKeySealed) throw new Error("the case is rotating but your grant has no previous key — a manager who held it must finish");
		oldKey = (await openSigned(root, trust, c.id, c.grant.prevKeySealed, c.grant.prevSignature, c.grant.prevSignedBy)).key;
		newKey = await openCaseKey(root, c, trust);
	} else {
		oldKey = await openCaseKey(root, c, trust);
		const fresh = await createStoreKey();
		const digest = await hybridDigest(fresh.publicKey, fresh.pqPublicKey);
		const b64 = toBase64(fresh.bundle);
		const grants = [];
		for (const g of grantees) grants.push({ member: g.member, keySealed: await sealText(await trustedRoot(trust, g), b64), signature: await signer.sign(statements.grant(c.id, digest, g.member)) });
		newKey = await importVaultKey(fresh.bundle);
		const title = await openCaseTitle(oldKey, c);
		const titleSealed = title === null ? undefined : await sealPlacedText(newKey, places.caseTitle(caseArea(c.id)), title);
		// Step 1: commit — the new key now lives in the grants, not only here.
		await call("PUT", `/api/v1/cases/${c.id}/key`, { keyId: fresh.keyId, publicKey: { ec: fresh.publicKey, kem: fresh.pqPublicKey }, grants, titleSealed });
	}
	const area = caseArea(c.id);
	const report = await resealStore(call, area, oldKey, newKey);
	// The proof before "done": the old key opens nothing left in the case.
	const left = await opensAnything(call, area, oldKey);
	if (left !== 0) throw new Error(`${left} value(s) still open under the old case key — the walk is not done`);
	// Step 2: done — the previous copies go.
	await call("POST", `/api/v1/cases/${c.id}/key/done`);
	return { report, key: newKey };
}
