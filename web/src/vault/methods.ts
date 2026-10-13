// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Unlock methods as the browser manages them (docs/VAULT.md › Unlock
 * methods). Three kinds, one rule:
 *
 * | Kind      | Secret                                   | Where it lives |
 * |-----------|------------------------------------------|----------------|
 * | password  | Argon2id (64 MiB, 3 passes, 4 lanes)      | your head      |
 * | recovery  | 40 characters, ≈196 bits                  | paper, offline |
 * | passkey   | PRF output, 256 bits, after Face/PIN      | the authenticator |
 *
 * **The one rule: adding a method requires confirming with an existing one.**
 * The open root cannot hand out its bytes (it is non-extractable), so to wrap
 * a copy under a new method the caller must first open the root *again* with
 * a method they already have. Someone holding only a stolen settings object
 * can therefore never add their own method — they would have to know a
 * secret first. (An improvement gorani applies before any files load.)
 *
 * Every method's `wrapped` is GW1: `AES-256-GCM(KEK, root bundle)` — the
 * server stores it and can open nothing with it.
 */

import { fromBase64 } from "../lib/encoding.ts";
import {
	generateHybridKey,
	makePasswordMethod,
	makeRecoveryMethod,
	makePasskeyMethod,
	unlockWithMethod,
	type UnlockMethod,
	type UnlockKind,
} from "./vault-crypto.ts";

export type { UnlockKind, UnlockMethod };

/** A vault as the settings keep it (the member DO stores this JSON verbatim). */
export interface VaultSettings {
	enabled: boolean;
	keyId: string;
	publicKey: JsonWebKey;
	pqPublicKey: string;
	methods: UnlockMethod[];
	stores: Record<string, { keyId: string; publicKey: JsonWebKey; pqPublicKey?: string; privateKeySealed: string }>;
	guardian?: { masterKeyId: string; masterPublicKey: { ec: JsonWebKey; kem: string }; storeSealed: string };
	/** Parents only: their sealed copy of the family master (family.ts). */
	masterSealed?: string;
}

/** The three ways a user presents a secret, before we know which method matches. */
export type PresentSecret =
	| { kind: "password"; value: string }
	| { kind: "recovery"; value: string }
	| { kind: "passkey"; output: Uint8Array };

/** Open the root bundle with the presented secret, trying that kind's methods. */
export async function openRoot(settings: VaultSettings, secret: PresentSecret): Promise<{ bundle: Uint8Array; methodId: string }> {
	const candidates = settings.methods.filter((m) => m.kind === secret.kind);
	let lastError = new Error(`no ${secret.kind} method is enrolled`);
	for (const method of candidates) {
		try {
			// unlockWithMethod derives the KEK and GW1-opens; the bundle lives
			// only long enough to be imported non-extractable (session.ts).
			const bundle = await unlockWithMethod(method, secret.kind === "passkey" ? secret.output : secret.value as string);
			return { bundle, methodId: method.id };
		} catch (e) {
			lastError = e instanceof Error ? e : new Error(String(e));
		}
	}
	throw lastError;
}

/** The bundle a confirming method opens — the precondition for adding methods. */
export async function confirmKeyBytes(settings: VaultSettings, secret: PresentSecret): Promise<Uint8Array> {
	const { bundle } = await openRoot(settings, secret);
	return bundle;
}

/** Add (or replace) a password method: type the new password; the caller has
 * already confirmed with an existing method (the `confirming` bundle). */
export async function addPasswordMethod(confirming: Uint8Array, password: string, label = "Password"): Promise<UnlockMethod> {
	return makePasswordMethod(confirming, password, label);
}

/** Add a recovery method; the code is shown exactly once. */
export async function addRecoveryMethod(confirming: Uint8Array): Promise<{ method: UnlockMethod; code: string }> {
	return makeRecoveryMethod(confirming);
}

/** Add a passkey method (the PRF output came from the just-run ceremony). */
export async function addPasskeyMethod(confirming: Uint8Array, prfOutput: Uint8Array, credentialId: string, prfSaltB64: string, label = "Passkey"): Promise<UnlockMethod> {
	// The method stores the PRF salt base64 (settings are JSON); the
	// derivation takes the raw bytes.
	return makePasskeyMethod(confirming, prfOutput, credentialId, fromBase64(prfSaltB64), label);
}

/** A brand-new vault: hybrid PQ root from birth, password + recovery methods. */
export async function createVaultBundle(password: string): Promise<{
	settings: VaultSettings;
	recoveryCode: string;
	rootBundle: Uint8Array;
	keyId: string;
}> {
	const root = await generateHybridKey();
	const passwordMethod = await makePasswordMethod(root.bundle, password, "Password");
	const recovery = await makeRecoveryMethod(root.bundle);
	return {
		settings: {
			enabled: true,
			keyId: root.keyId,
			publicKey: root.publicKey,
			pqPublicKey: root.pqPublicKey,
			methods: [passwordMethod, recovery.method],
			stores: {},
		},
		recoveryCode: recovery.code,
		rootBundle: root.bundle,
		keyId: root.keyId,
	};
}

/** Which kinds are enrolled (the unlock screen shows what exists). */
export function enrolledKinds(settings: VaultSettings): UnlockKind[] {
	const kinds = new Set<UnlockKind>();
	for (const m of settings.methods) kinds.add(m.kind);
	return [...kinds];
}

/** Sanity: every method carries a GW1 wrap and a salt; a settings object
 * without methods cannot open. (Deep consistency — every method wrapping the
 * same root — is proven by actually opening; a wrong one just fails.) */
export function methodsConsistent(settings: VaultSettings): boolean {
	return settings.methods.length > 0 && settings.methods.every((m) => m.wrapped.length > 0 && m.salt.length > 0);
}