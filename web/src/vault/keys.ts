// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Vaults and store keys — the small set of compositions every area is built
 * from (commit 27c; until then this lived in family.ts beside the family
 * edition's master key and guardian copies, which are gone).
 *
 * ```text
 * member root (one hybrid pair per member; unlock methods wrap its bundle)
 *    └── a store key per area ── its private bundle sealed (GV03) to:
 *          the member's root                (own area: settings.stores.files)
 *          each grantee's root              (a case: the registry's grants, cases.ts)
 *          the team recovery key            (every area: a recovery copy, recovery.ts)
 * ```
 *
 * Nothing here is a new primitive: the same seal/open calls from
 * vault-crypto.ts, composed — the envelope scheme of the whole product (seal
 * the small key, never the content).
 */

import { generateHybridKey, importVaultKey, sealText, makePasswordMethod, makeRecoveryMethod, openSealedText, type VaultPrivateKey, type SealTarget, type UnlockMethod } from "./vault-crypto.ts";
import { toBase64, fromBase64 } from "../lib/encoding.ts";
import { checkRecordMatches } from "./records.ts";

/** A hybrid public key as settings keep it (serialisable). */
export interface HybridPublic {
	ec: JsonWebKey;
	kem: string;
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
	/** The recovery code, shown once. */
	recoveryCode: string;
}

/** A vault with a password and a recovery code (the recovery code is shown once). */
export async function createVault(password: string): Promise<NewVault> {
	const root = await generateHybridKey();
	const passwordMethod = await makePasswordMethod(root.bundle, password, "Password");
	const recovery = await makeRecoveryMethod(root.bundle);
	return { rootBundle: root.bundle, keyId: root.keyId, publicKey: root.publicKey, pqPublicKey: root.pqPublicKey, methods: [passwordMethod, recovery.method], recoveryCode: recovery.code };
}

/**
 * A vault whose only method is a 40-character code (the recovery-code
 * shape) — a password and passkeys are added later from the unlocked
 * session. Fast (no Argon2), which is why the test suites use it.
 */
export async function createCodeVault(): Promise<NewVault> {
	const root = await generateHybridKey();
	const code = await makeRecoveryMethod(root.bundle, "Recovery code");
	return { rootBundle: root.bundle, keyId: root.keyId, publicKey: root.publicKey, pqPublicKey: root.pqPublicKey, methods: [code.method], recoveryCode: code.code };
}

// ── store keys ──────────────────────────────────────────────────────

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
	return { keyId: store.keyId, publicKey: store.publicKey, pqPublicKey: store.pqPublicKey, privateKeySealed: await sealText(memberRootPublic, toBase64(store.bundle)) };
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
