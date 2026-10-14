// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The family key hierarchy (docs/FAMILY.md is the prose twin).
 *
 * Gorani is a family NAS: several members, each with their own vault, and a
 * one-way hierarchy — **parents can open the children's areas; children can
 * never open the parents' or each other's.** The trick is to stay inside the
 * same envelope scheme as everything else (seal the *small* key, never the
 * content) and add exactly two wrappers:
 *
 * ```text
 * parents' master key pair (one per family)
 *     private half ──sealed (GV03)──▶ to each parent's root      (parent.settings.masterSealed)
 *     public half  ◀──every child's files-store private key is sealed to it──┘
 *                    (in the child's settings: guardian.storeSealed, beside the
 *                     child's own copy stores.files.privateKeySealed)
 * family shared area: ONE store key, its private half sealed to every member's root
 *                     (each member's settings hold their own copy: stores["family"])
 * ```
 *
 * So a parent unlocking their own root can unwrap the master, unwrap any
 * child's store key, and open every file in that child's area — while a
 * child's root opens only their own store and the family area. Nothing here
 * is a new primitive: it is the same seal/open calls from vault-crypto.ts,
 * composed; the vectors in crates/formats prove those primitives byte-for-byte
 * across languages.
 *
 * Consequences worth internalising (each is a test in tests/unit/family.test.mjs):
 *  - A child's root compromise opens that child's area only — the master is
 *    sealed to parents' roots, never to children's.
 *  - Revoking a parent = rotate the master: re-seal the master's private to
 *    the remaining parents' roots and each child's store bundle to the new
 *    public half. Two small seals per member; no file is re-encrypted.
 *  - A child's store key can be rotated *by a parent alone* — both required
 *    publics are public halves; the child never has to be online.
 *  - The **guardian enrolment code** (a recovery-kind method on the child's
 *    root) lets a parent's computer enrol for desktop sync of the child's
 *    area, and lets a parent regain a child's vault — without ever knowing
 *    the child's password.
 *  - The family shared area is enforced in two layers: crypto (everyone can
 *    read) and the server (role policy: only parents may write).
 *
 * The key ids that name keys (`masterKeyId`, `keyId`) are data, not crypto:
 * callers compare them (settings-side) to pick the right key; this module
 * does the sealing and opening.
 */

import {
	generateHybridKey,
	importVaultKey,
	sealText,
	openText,
	makePasswordMethod,
	makeRecoveryMethod,
	type VaultPrivateKey,
	type SealTarget,
	type UnlockMethod,
} from "./vault-crypto.ts";
import { toBase64, fromBase64 } from "../lib/encoding.ts";
import { openSealedText } from "./vault-crypto.ts";
import { checkRecordMatches } from "./records.ts";

const toB64 = (b: Uint8Array) => toBase64(b);

/** A family member's role. The server stores it readable; it is policy, not content. */
/** The family's roles — the migration source of docs/CASES.md (parent →
 * lead, child → analyst); the registry still accepts them as aliases. */
export type Role = "parent" | "child";

/** A hybrid public key as settings keep it (serialisable). */
export interface HybridPublic { ec: JsonWebKey; kem: string }

/** The parents' master key, as a parent's settings hold it: the public half for everyone, this parent's sealed copy. */
export interface MasterForParent {
	keyId: string;
	/** The master's public half (children need it to re-seal their store keys on rotation). */
	publicKey: HybridPublic;
	/** The master's private bundle, sealed (GV03) to this parent's root. */
	privateKeySealed: string;
}

/** What a child's settings hold about guardianship. */
export interface GuardianForChild {
	/** The master key this child's store is sealed to (rotation target). */
	masterKeyId: string;
	masterPublicKey: HybridPublic;
	/** The child's files-store private key, sealed to the master public half. */
	storeSealed: string;
}

/** A store key as settings keep it: public half, private sealed to the member's root. */
export interface SealingKey {
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey?: string;
	privateKeySealed: string;
	/** The record's MAC under its owner's root-derived key (records.ts). */
	mac?: string;
}

// ── vault creation ──────────────────────────────────────────────────

export interface NewVault {
	/** The root's private bundle (GK01): wrap it into unlock methods, then wipe. */
	rootBundle: Uint8Array;
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey: string;
	methods: UnlockMethod[];
	/** The recovery code (or enrolment code), shown once. */
	recoveryCode: string;
}

/**
 * A parent's vault: hybrid root, a password method and a recovery code.
 * The password is typed by the parent; the recovery code is shown once.
 */
export async function createParentVault(password: string): Promise<NewVault> {
	const root = await generateHybridKey();
	const passwordMethod = await makePasswordMethod(root.bundle, password, "Password");
	const recovery = await makeRecoveryMethod(root.bundle);
	return {
		rootBundle: root.bundle,
		keyId: root.keyId,
		publicKey: root.publicKey,
		pqPublicKey: root.pqPublicKey,
		methods: [passwordMethod, recovery.method],
		recoveryCode: recovery.code,
	};
}

/**
 * A child's vault: hybrid root, and a single **enrolment/recovery code**
 * (the same 40-character shape as a recovery code). The parent sets this up:
 * the code is what the child types to unlock (a password and passkeys are
 * added later, from the child's own unlocked session), and what a parent
 * types to enrol a *guardian device* or regain the vault. One secret, three
 * uses — and the server never sees it.
 */
export async function createChildVault(): Promise<NewVault> {
	const root = await generateHybridKey();
	const code = await makeRecoveryMethod(root.bundle, "Recovery or enrolment code");
	return {
		rootBundle: root.bundle,
		keyId: root.keyId,
		publicKey: root.publicKey,
		pqPublicKey: root.pqPublicKey,
		methods: [code.method],
		recoveryCode: code.code,
	};
}

// ── the parents' master key ─────────────────────────────────────────

export interface NewMaster {
	keyId: string;
	publicKey: HybridPublic;
	/** The master's private bundle (GK01) — seal it to every parent's root, then wipe. */
	bundle: Uint8Array;
}

export async function createParentsMaster(): Promise<NewMaster> {
	const root = await generateHybridKey();
	return { keyId: root.keyId, publicKey: { ec: root.publicKey, kem: root.pqPublicKey }, bundle: root.bundle };
}

/** The master's private half, sealed to one parent's root public key. */
export async function sealMasterToParent(master: NewMaster, parentRootPublic: SealTarget): Promise<string> {
	return sealText(parentRootPublic, toB64(master.bundle));
}

/** Open a parent's copy of the master with that parent's root private key. */
export async function openMaster(parentRoot: VaultPrivateKey, masterSealed: string): Promise<VaultPrivateKey> {
	return importVaultKey(fromBase64(await openSealedText(parentRoot, masterSealed)));
}

// ── store keys (files, family area) ────────────────────────────────

export interface NewStoreKey {
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey: string;
	/** The store's private bundle (GK01): seal it wherever it belongs, then wipe. */
	bundle: Uint8Array;
}

export async function createStoreKey(): Promise<NewStoreKey> {
	const root = await generateHybridKey();
	return { keyId: root.keyId, publicKey: root.publicKey, pqPublicKey: root.pqPublicKey, bundle: root.bundle };
}

/** A member's own copy of a store key: the private bundle sealed to their root. */
export async function sealStoreKeyToMember(store: NewStoreKey, memberRootPublic: SealTarget): Promise<SealingKey> {
	return {
		keyId: store.keyId,
		publicKey: store.publicKey,
		pqPublicKey: store.pqPublicKey,
		privateKeySealed: await sealText(memberRootPublic, toB64(store.bundle)),
	};
}

/** The child's guardianship record: the store bundle sealed to the master public half. */
export async function sealStoreKeyToMaster(store: NewStoreKey, master: NewMaster): Promise<GuardianForChild> {
	return {
		masterKeyId: master.keyId,
		masterPublicKey: master.publicKey,
		storeSealed: await sealText(master.publicKey, toB64(store.bundle)),
	};
}

/** Open a store key's private bundle from a member's own settings (their root opens it). */
export async function openStoreKey(memberRoot: VaultPrivateKey, key: SealingKey): Promise<VaultPrivateKey> {
	// Sealed text only (an unsealed "private key" from the server is refused),
	// and the opened key must BE the record's key — the same public halves
	// and id (docs/SECURITY-REVIEW.md › O3; records.ts). The MAC check that
	// pins the record to its owner happens in the session.
	const opened = await importVaultKey(fromBase64(await openSealedText(memberRoot, key.privateKeySealed)));
	await checkRecordMatches(opened, key);
	return opened;
}

/**
 * Open a child's store key as a parent: unwrap the master, then the child's
 * guardianship copy. Callers check `guardian.masterKeyId` against the
 * master's id they hold (data, not crypto) before trusting the result.
 */
export async function openChildStoreKey(parentRoot: VaultPrivateKey, masterSealed: string, guardian: GuardianForChild): Promise<VaultPrivateKey> {
	const master = await openMaster(parentRoot, masterSealed);
	return importVaultKey(fromBase64(await openSealedText(master, guardian.storeSealed)));
}

/**
 * The family shared area: one store key, sealed to every member's root — one
 * copy per member, each in that member's own settings.
 */
export async function sealFamilyStoreKey(store: NewStoreKey, memberRootPublics: SealTarget[]): Promise<SealingKey[]> {
	const out: SealingKey[] = [];
	for (const publicHalf of memberRootPublics) out.push(await sealStoreKeyToMember(store, publicHalf));
	return out;
}

/**
 * Rotate the FAMILY SHARED AREA's store key — the step that must run when a
 * member leaves, BEFORE their deactivation: a fresh store pair, its private
 * sealed to every REMAINING member's root. The departing member's root opens
 * none of the new copies, and every family-area content key re-wraps to the
 * new public half (the client drives it exactly like a child-store rotation:
 * unwrap each wrap with the old private half, wrap to the new public half,
 * store via files/reseal) — so their old copy of the old key decrypts
 * nothing, not even bytes already stored. Two small seals per member; no
 * file is re-encrypted. (Same shape as rotateChildStoreKey; the difference
 * is who holds copies — every member's own settings, not the master.)
 */
export async function rotateFamilyStoreKey(remainingRootPublics: SealTarget[]): Promise<{ key: NewStoreKey; copies: SealingKey[] }> {
	const store = await createStoreKey();
	return { key: store, copies: await sealFamilyStoreKey(store, remainingRootPublics) };
}

// ── the guardian enrolment code ─────────────────────────────────────

/**
 * A method on the child's root that a parent (or the child) can type: a
 * recovery-format code, labeled for the device it enrols. Enrol a parent's
 * computer for the child's area, or regain the child's vault — the child's
 * password is never involved.
 */
export async function makeGuardianEnrolmentMethod(childRootBundle: Uint8Array, deviceName: string): Promise<{ method: UnlockMethod; code: string }> {
	return makeRecoveryMethod(childRootBundle, `Guardian code (${deviceName})`);
}

// ── rotations ───────────────────────────────────────────────────────

export interface MasterRotation {
	master: NewMaster;
	/** One sealed copy per parent's root (order matches the input). */
	parentSealed: string[];
	/** One guardianship record per child store bundle (order matches the input). */
	childGuardians: GuardianForChild[];
}

/**
 * Rotate the master (a parent was revoked, or their device lost): a new
 * master pair; its private sealed again to each parent's root; each child's
 * store bundle re-sealed to the new public half. The caller collected the
 * bundles by opening each child's old `guardian.storeSealed` with the old
 * master. Two small seals per member — no content is touched.
 */
export async function rotateMaster(parentRootPublics: SealTarget[], childStoreBundles: Uint8Array[]): Promise<MasterRotation> {
	const master = await createParentsMaster();
	const parentSealed: string[] = [];
	for (const p of parentRootPublics) parentSealed.push(await sealMasterToParent(master, p));
	const childGuardians: GuardianForChild[] = [];
	for (const bundle of childStoreBundles) {
		childGuardians.push({ masterKeyId: master.keyId, masterPublicKey: master.publicKey, storeSealed: await sealText(master.publicKey, toB64(bundle)) });
	}
	return { master, parentSealed, childGuardians };
}

/** A child's store key rotated to a fresh pair; sealed to the child's root and the master. */
export async function rotateChildStoreKey(master: NewMaster, childRootPublic: SealTarget): Promise<{ key: NewStoreKey; own: SealingKey; guardian: GuardianForChild }> {
	const store = await createStoreKey();
	return {
		key: store,
		own: await sealStoreKeyToMember(store, childRootPublic),
		guardian: await sealStoreKeyToMaster(store, master),
	};
}