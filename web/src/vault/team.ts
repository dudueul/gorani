// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The team, as one unlocked member's client sees it — the glue between the
 * session and stages 3–5 (docs/CASES.md › Stage 6, the screens). Two jobs
 * run at every unlock, quietly, before anything else needs them:
 *
 * 1. **Identity** — open the member's identity (identity.ts) from their
 *    settings, creating it the first time; register its public half if the
 *    registry does not have it (a new member; a member re-enrolled by a
 *    ceremony, whose old identity the registry dropped).
 * 2. **Recovery copy** — if the team has a recovery key and this member's
 *    own area has no copy under it (never sealed, or sealed to a key since
 *    rotated), seal one — to the recovery key only after its signature
 *    verifies (recovery.ts › trustedRecoveryKey).
 *
 * The functions take the JSON API as a parameter (the browser passes its
 * `api`, a test its own) so they run the same in both.
 */

import type { VaultSession } from "./session.ts";
import type { VaultSettings } from "./methods.ts";
import { buildTrust, createIdentity, hybridDigest, openIdentity, statements, type RegistryIdentity, type Signer, type Trust } from "./identity.ts";
import { sealRecoveryCopy, type RecoveryRecord } from "./recovery.ts";
import { openSealedText } from "./vault-crypto.ts";
import { updateSettings } from "./settings-store.ts";

/** The JSON API: GET / PUT / POST / DELETE with a body, throwing on refusals. */
export type TeamCall = <T>(method: "GET" | "PUT" | "PATCH" | "POST" | "DELETE", path: string, body?: unknown) => Promise<T>;

export interface TeamContext {
	memberId: string;
	signer: Signer;
	trust: Trust;
	identities: RegistryIdentity[];
	/** The settings as they now are (an identity may have been added). */
	settings: VaultSettings;
}

/** Open (or create, then register) this member's identity, and build their trust. */
export async function openTeam(call: TeamCall, session: VaultSession, memberId: string): Promise<TeamContext> {
	let settings = session.settings;
	const rootPublic = { ec: settings.publicKey, kem: settings.pqPublicKey };
	let signer: Signer;
	if (!settings.identity) {
		const made = await createIdentity(memberId, session.root, rootPublic);
		// Saved field by field (settings-store.ts), and into the session's
		// own object as well: the shell later saves pinned store records
		// from it, and before 39l that object lacked the identity made here.
		settings = await updateSettings(call, memberId, session.rootKeyId, (s) => ({ ...s, identity: made.record }));
		session.settings.identity = made.record;
		signer = made.signer;
	} else {
		signer = await openIdentity(memberId, session.root, settings.identity);
	}
	let identities = (await call<{ identities: RegistryIdentity[] }>("GET", "/api/v1/family/identities")).identities;
	const record = settings.identity!;
	if (!identities.some((e) => e.member === memberId && e.keyId === record.keyId)) {
		const rootDigest = await hybridDigest(rootPublic.ec, rootPublic.kem);
		await call("PUT", "/api/v1/family/identity", { keyId: record.keyId, publicKey: record.publicKey, rootDigest, signature: await signer.sign(statements.identity(memberId, record.keyId, rootDigest)) });
		identities = (await call<{ identities: RegistryIdentity[] }>("GET", "/api/v1/family/identities")).identities;
	}
	const trust = await buildTrust(memberId, session.root, record, identities);
	return { memberId, signer, trust, identities, settings };
}

/** Seal this member's own area's recovery copy if it is missing or stale.
 * Returns what happened, for the screen to say. */
export async function refreshRecoveryCopy(call: TeamCall, session: VaultSession, team: TeamContext): Promise<"none" | "current" | "sealed" | "untrusted"> {
	const r = await call<{ recovery: RecoveryRecord | null; myCopyKeyId?: string | null }>("GET", "/api/v1/recovery");
	if (!r.recovery) return "none";
	if (r.myCopyKeyId === r.recovery.keyId) return "current";
	const own = team.settings.stores?.files;
	if (!own) return "none";
	let copy;
	try {
		copy = await sealRecoveryCopy(team.trust, r.recovery, await openSealedText(session.root, own.privateKeySealed));
	} catch {
		// The recovery key's creator is not (yet) someone this member trusts:
		// sealing to an unverified key is exactly what must not happen.
		return "untrusted";
	}
	await call("PUT", "/api/v1/recovery/copies", { area: team.memberId, ...copy });
	return "sealed";
}
