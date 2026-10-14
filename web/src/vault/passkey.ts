// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Passkey unlock, via the WebAuthn **PRF extension** (docs/ENCRYPTION.md):
 * the authenticator holds a 256-bit secret it releases only after user
 * verification (Face ID, Touch ID, Windows Hello), mixed with a per-credential
 * salt we generate. The output — not the passkey itself — is the KEK that
 * unwraps the root key.
 *
 * ```text
 * unlock secret = PRF(authenticator, salt = prfSalt)      (32 bytes, never leaves the device)
 * KEK           = HKDF-SHA256(secret, salt, "gorani-passkey-v1")
 * root          = GW1-open(KEK, methods[passkey].wrapped)
 * ```
 *
 * Why this is the method to prefer: the secret cannot be phished (bound to
 * this origin), cannot be guessed (256 bits inside the authenticator), and
 * cannot be copied off the device. A password is what you type; a passkey is
 * what you *are* to your computer.
 *
 * Two calls matter: `createPasskey` enrols one (needs the PRF extension —
 * refused politely when the platform lacks it, "use a password instead"),
 * and `prfOutput` evaluates it at unlock. The challenge is random and
 * client-side on purpose: this is not a login ceremony — nothing here proves
 * identity to a server. The PRF output IS the secret; the server never sees
 * it, only its consequence (a GW1-wrapped root it cannot open).
 */

import { toBase64, fromBase64 } from "../lib/encoding.ts";
import { toB64Url, fromB64Url } from "./share-crypto.ts";

export interface CreatedPasskey {
	credentialId: string; // base64url
	prfSalt: string; // base64
}

/**
 * The relying-party id a passkey is bound to: this page's exact hostname
 * (commit 25, docs/SECURITY-REVIEW.md › O15).
 *
 * It used to be "the last two labels" — a guess at the registrable domain
 * so a passkey would survive a move between subdomains. The guess is wrong
 * exactly where it matters: on `gorani.family.workers.dev` it yields
 * `workers.dev`, a PUBLIC SUFFIX the browser refuses as an rp.id (no passkey
 * could be created at all), and on `vault.example.co.uk` it yields `co.uk`.
 * A wider rp.id is also a wider blast radius: every sibling subdomain could
 * ask for the same credential. The hostname is always valid and never
 * wider than the app. (Moving hosts means enrolling passkeys again — the
 * password and recovery methods are unaffected.)
 */
export const relyingPartyId = (): string => location.hostname;

const subtle = () => globalThis.crypto.subtle;

/** A random challenge: freshness theatre for the ceremony, entropy for the hash. */
const challenge = () => crypto.getRandomValues(new Uint8Array(32));

/** Does this platform's authenticator support PRF? (Chrome/Edge/Safari 18+: yes.) */
export async function prfSupported(): Promise<boolean> {
	if (!window.PublicKeyCredential || !navigator.credentials) return false;
	// The extension itself cannot be probed without a ceremony; we ask the
	// platform for conditional support the standard way and otherwise let
	// create() fail with NotAllowedError, reported as "try a password".
	return typeof window.PublicKeyCredential === "function";
}

/** Enrol one passkey for this member, with PRF requested up front. */
export async function createPasskey(memberId: string, memberName: string): Promise<CreatedPasskey> {
	const prfSalt = crypto.getRandomValues(new Uint8Array(32));
	const userHandle = new TextEncoder().encode(memberId);
	const cred = (await navigator.credentials.create({
		publicKey: {
			challenge: challenge(),
			rp: { id: relyingPartyId(), name: "Gorani" },
			user: { id: userHandle, name: memberName, displayName: `${memberName} (Gorani)` },
			pubKeyCredParams: [
				{ type: "public-key", alg: -7 }, // ES256 — every authenticator has it
				{ type: "public-key", alg: -257 }, // RS256 — older Windows Hello
			],
			authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
			extensions: { prf: {} },
		},
	})) as PublicKeyCredential | null;
	if (!cred) throw new Error("The passkey ceremony was cancelled");
	// The extension results tell us whether PRF is really enabled for this
	// credential (an authenticator may accept create() but not support PRF).
	const results = (cred.getClientExtensionResults() as { prf?: { enabled?: boolean } }).prf;
	if (!results?.enabled) {
		throw new Error("This authenticator does not support PRF — use a password instead");
	}
	return { credentialId: cred.id, prfSalt: toBase64(prfSalt) };
}

/** Evaluate the PRF at unlock time (the authenticator asks for verification). */
export async function prfOutput(credentialId: string, prfSaltB64: string): Promise<Uint8Array> {
	const assertion = (await navigator.credentials.get({
		publicKey: {
			challenge: challenge(),
			// The SAME rp id as at creation, said explicitly. (Before commit
			// 25 creation used "the last two labels" while this call took the
			// browser's default — the hostname — so on any subdomain the two
			// disagreed and an enrolled passkey could never unlock.)
			rpId: relyingPartyId(),
			allowCredentials: [{ id: fromB64Url(credentialId), type: "public-key" }],
			userVerification: "required",
			extensions: { prf: { eval: { first: fromBase64(prfSaltB64) } } },
		},
	})) as PublicKeyCredential | null;
	if (!assertion) throw new Error("The passkey ceremony was cancelled");
	const results = (assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf?.results;
	if (!results?.first) throw new Error("This passkey cannot produce its unlock secret (PRF) — use the recovery code");
	return new Uint8Array(results.first);
}

/** The bytes a new credential's user.id carries (used to find it again later). */
export function userHandleOf(memberId: string): Uint8Array {
	return new TextEncoder().encode(memberId);
}

export { toB64Url as toBase64Url, fromB64Url as fromBase64Url };