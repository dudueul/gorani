// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Collectors — docs/COLLECTORS.md (commit 37a). The registry half is
 * worker/src/family/collectors.rs; this is what a member's client decides.
 *
 * A collector is a machine that drops evidence into case inboxes with no
 * person signed in. Two leads register it, each signing a statement that
 * NAMES it — its id, its Access service token and its identity key:
 *
 * ```text
 * request   stmt("gorani-collector-v1",         id, commonName, keyId, requester)
 * approve   stmt("gorani-collector-approve-v1", id, commonName, keyId, requester, approver)
 * ```
 *
 * The case two-person rule (approvals.ts) signs an action and a case, not a
 * thing; reusing it here would let a server attach two leads' agreement to
 * a collector of its own. So this has its own statements, and a client
 * counts a collector's key only when BOTH signatures verify under leads it
 * trusts, by two different people — the registry stores the signatures and
 * checks none of them.
 */

import { identityKeyId, stmt, type Signer, type Trust } from "./identity.ts";

export const collectorStatements = {
	request: (id: string, commonName: string, keyId: string, requester: string) => stmt("gorani-collector-v1", id, commonName, keyId, requester),
	approve: (id: string, commonName: string, keyId: string, requester: string, approver: string) => stmt("gorani-collector-approve-v1", id, commonName, keyId, requester, approver),
};

/** A collector as `GET /api/v1/family/collectors` lists it. */
export interface CollectorRow {
	id: string;
	name: string;
	/** The Access service token's Client ID (its JWT's `common_name`). */
	commonName: string;
	status: "pending" | "active" | "revoked" | "expired";
	keyId: string;
	publicKey: JsonWebKey;
	requestedBy: string;
	requestedAt: string;
	requestSignature: string;
	approvedBy: string | null;
	approvedAt: string | null;
	approveSignature: string | null;
	revokedBy: string | null;
	revokedAt: string | null;
	/** The cases it may drop into. */
	cases: string[];
}

export type CollectorCall = <T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown) => Promise<T>;

/** Ask to register a collector (a lead): its key id computed here, the statement signed. */
export async function requestCollector(call: CollectorCall, signer: Signer, c: { id: string; name: string; commonName: string; publicKey: JsonWebKey }): Promise<CollectorRow> {
	const keyId = await identityKeyId(c.publicKey);
	const signature = await signer.sign(collectorStatements.request(c.id, c.commonName, keyId, signer.member));
	return call<CollectorRow>("POST", "/api/v1/family/collectors", { ...c, keyId, signature });
}

/**
 * Approve, as the second lead. The REQUEST's signature is checked first,
 * against this lead's trust, and the key id against the key: agreeing to a
 * registration its requester never made — or to a key it does not name —
 * would be agreeing to the server's word.
 */
export async function approveCollector(call: CollectorCall, signer: Signer, trust: Trust, c: CollectorRow): Promise<CollectorRow> {
	if (c.requestedBy === signer.member) throw new Error("the second person must be a different lead — you asked for this");
	if ((await identityKeyId(c.publicKey)) !== c.keyId) throw new Error("the registration's key id is not its key's — refusing to approve it");
	const asker = trust.of(c.requestedBy);
	if (!asker) throw new Error(`${c.requestedBy}'s identity is not one you verified — compare fingerprints before agreeing to their request`);
	if (!(await asker.verify(collectorStatements.request(c.id, c.commonName, c.keyId, c.requestedBy), c.requestSignature))) {
		throw new Error(`the registration's signature does not verify — ${c.requestedBy} did not ask for this collector; refusing to approve`);
	}
	const signature = await signer.sign(collectorStatements.approve(c.id, c.commonName, c.keyId, c.requestedBy, signer.member));
	return call<CollectorRow>("POST", `/api/v1/family/collectors/${c.id}/approve`, { signature });
}

/** A collector whose key this client counts, and why. */
export interface TrustedCollector {
	id: string;
	name: string;
	keyId: string;
	/** The two leads whose signatures vouched for it. */
	vouchedBy: [string, string];
	verify(statement: Uint8Array, signature: string): Promise<boolean>;
}

/** Why a collector is NOT counted, for a person (or null when it is). */
export async function collectorVerdict(trust: Trust, c: CollectorRow): Promise<string | null> {
	if (c.status !== "active") return `the collector is ${c.status}`;
	if ((await identityKeyId(c.publicKey)) !== c.keyId) return "its key id is not its key's";
	if (!c.approvedBy || !c.approveSignature) return "it was never approved";
	if (c.approvedBy === c.requestedBy) return "one person both asked and approved";
	const asker = trust.of(c.requestedBy);
	const approver = trust.of(c.approvedBy);
	if (!asker) return `${c.requestedBy}, who asked for it, is not an identity you verified`;
	if (!approver) return `${c.approvedBy}, who approved it, is not an identity you verified`;
	if (!(await asker.verify(collectorStatements.request(c.id, c.commonName, c.keyId, c.requestedBy), c.requestSignature))) return `the registration's signature does not verify — ${c.requestedBy} did not ask for this collector`;
	if (!(await approver.verify(collectorStatements.approve(c.id, c.commonName, c.keyId, c.requestedBy, c.approvedBy), c.approveSignature))) return `the approval's signature does not verify — ${c.approvedBy} did not approve this collector`;
	return null;
}

/** The collectors this client counts: active, and vouched for by two leads it trusts. */
export async function collectorTrust(trust: Trust, rows: CollectorRow[]): Promise<Map<string, TrustedCollector>> {
	const out = new Map<string, TrustedCollector>();
	for (const c of rows) {
		if ((await collectorVerdict(trust, c)) !== null) continue;
		const key = await globalThis.crypto.subtle.importKey("jwk", { ...c.publicKey, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
		out.set(c.id, {
			id: c.id,
			name: c.name,
			keyId: c.keyId,
			vouchedBy: [c.requestedBy, c.approvedBy!],
			verify: async (s, sig) => {
				try {
					const bytes = Uint8Array.from(atob(sig), (ch) => ch.charCodeAt(0));
					return await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bytes as BufferSource, s as BufferSource);
				} catch {
					return false;
				}
			},
		});
	}
	return out;
}
