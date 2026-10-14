// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Case keys — the client half of docs/CASES.md › Areas and their keys
 * (commit 26). The registry (worker/src/family.rs › Cases and grants)
 * decides WHO may hold a case's key; this module is the only code that
 * ever holds one.
 *
 * A case is a store like a member's own area (lib/area.ts): one hybrid key
 * pair, GV04 places with `store` = `case:<id>`. What is new is where its
 * private half lives — not in anyone's settings, but in the GRANTS:
 *
 * ```text
 * open     the lead's browser makes the key; seals it to their own root
 *          (their grant, permission "manage"); seals the title into the
 *          case's `case.title` place; posts the public halves.
 * grant    a manager opens their own copy and seals it to the grantee's
 *          root (GET /members/<id>/root); the registry checks the policy.
 * revoke   the registry drops the grant and marks the case "rotation
 *          required" — the revoked member KEPT the key.
 * rotate   a fresh key, sealed to every remaining grantee; commit it (the
 *          old copies stay as `prev` until…) → the reseal walk → "done".
 * ```
 *
 * Why the rotation commits BEFORE it walks (the member-store runbook walks
 * first): the new key must exist somewhere other than this tab before any
 * value is sealed to it. Walk first and crash half-way, and half the case
 * is sealed to a key that died with the tab. Commit first, and a crashed
 * walk resumes from the grants, which hold both keys until "done".
 *
 * The honest limit (until stage 4's signed grants): a copy sealed to you by
 * someone else is checked against the registry's public halves for the
 * case — consistency, not authenticity. A server that substituted BOTH the
 * copy and the public halves before your first open would not be caught
 * here; the grantor's signature over (case, key id, you) closes that.
 */

import { createStoreKey } from "./family.ts";
import { checkRecordMatches } from "./records.ts";
import { places } from "./places.ts";
import { opensAnything, resealStore, type ApiCall, type RotationReport } from "./rotation.ts";
import { importVaultKey, openPlacedText, openSealedText, sealPlacedText, sealText, type SealTarget, type VaultPrivateKey } from "./vault-crypto.ts";
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
	/** The caller's own grant, with their key copy — null for a lead's or
	 * auditor's structure-only view. */
	grant: { permission: CasePermission; keySealed: string; keyId: string; expiresAt: string | null; prevKeySealed: string | null } | null;
	grantees: { member: string; permission: CasePermission; expiresAt: string | null }[];
}

/** A grantee's root public halves (`GET /api/v1/members/<id>/root`). */
export interface MemberRoot {
	member: string;
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey: string;
}

export const rootTarget = (r: MemberRoot): SealTarget => ({ ec: r.publicKey, kem: r.pqPublicKey });

/** The record a copy must match: the registry's public halves for the case. */
const recordOf = (keyId: string, pub: { ec: JsonWebKey; kem: string }) => ({ keyId, publicKey: pub.ec, pqPublicKey: pub.kem });

/**
 * Open a new case: the body of `POST /api/v1/cases`, and the case key (the
 * caller keeps it for the first uploads, then lets it go like any key).
 */
export async function newCase(id: string, kind: CaseKind, title: string, openerRoot: SealTarget): Promise<{ body: Record<string, unknown>; key: VaultPrivateKey }> {
	const fresh = await createStoreKey();
	const keySealed = await sealText(openerRoot, toBase64(fresh.bundle));
	const key = await importVaultKey(fresh.bundle); // wipes the bundle
	const titleSealed = await sealPlacedText(key, places.caseTitle(caseArea(id)), title);
	return { key, body: { id, kind, keyId: fresh.keyId, publicKey: { ec: fresh.publicKey, kem: fresh.pqPublicKey }, keySealed, titleSealed } };
}

/** Open your copy of a case key — and check it IS the case's key. */
export async function openCaseKey(root: VaultPrivateKey, c: CaseRow): Promise<VaultPrivateKey> {
	if (!c.grant) throw new Error(`you hold no grant on case ${c.id}`);
	const key = await importVaultKey(fromBase64(await openSealedText(root, c.grant.keySealed)));
	await checkRecordMatches(key, recordOf(c.keyId, c.publicKey));
	return key;
}

/** The case's title, opened in its place. */
export function openCaseTitle(key: VaultPrivateKey, c: CaseRow): Promise<string | null> {
	return c.titleSealed ? openPlacedText(key, places.caseTitle(caseArea(c.id)), c.titleSealed) : Promise.resolve(null);
}

/**
 * The key copy for a new grantee: your copy, re-sealed to their root. The
 * bundle is opened and checked first — never pass on a key that is not the
 * case's (a corrupted copy would lock the grantee out silently).
 */
export async function sealCaseGrant(root: VaultPrivateKey, c: CaseRow, grantee: MemberRoot): Promise<{ keySealed: string; keyId: string }> {
	if (!c.grant) throw new Error(`you hold no grant on case ${c.id}`);
	const b64 = await openSealedText(root, c.grant.keySealed);
	await checkRecordMatches(await importVaultKey(fromBase64(b64)), recordOf(c.keyId, c.publicKey));
	return { keySealed: await sealText(rootTarget(grantee), b64), keyId: c.keyId };
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
 * fetched by the caller; the registry refuses a set that is one short or
 * one long. `call` is the JSON API (the bridge's, or a test's).
 */
export async function rotateCase(call: ApiCall, root: VaultPrivateKey, c: CaseRow, grantees: MemberRoot[]): Promise<CaseRotation> {
	if (!c.grant) throw new Error(`you hold no grant on case ${c.id}`);
	let oldKey: VaultPrivateKey;
	let newKey: VaultPrivateKey;
	if (c.rotating) {
		// Resume: the grant holds both keys until the walk says "done".
		if (!c.grant.prevKeySealed) throw new Error("the case is rotating but your grant has no previous key — a manager who held it must finish");
		oldKey = await importVaultKey(fromBase64(await openSealedText(root, c.grant.prevKeySealed)));
		newKey = await openCaseKey(root, c);
	} else {
		oldKey = await openCaseKey(root, c);
		const fresh = await createStoreKey();
		const b64 = toBase64(fresh.bundle);
		const grants = [];
		for (const g of grantees) grants.push({ member: g.member, keySealed: await sealText(rootTarget(g), b64) });
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
