// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Case inboxes — docs/COLLECTORS.md (commit 37b). The registry half is
 * worker/src/family/inbox.rs, the store half worker/src/inbox.rs, the
 * collector's half clients/core/src/collector.rs; this is what a member's
 * client makes and checks.
 *
 * A collector must be able to seal evidence for a case WITHOUT the case
 * key (GV04 sealing needs the store's PRIVATE key, and a robot holding a
 * case's private key could read the whole case). So each case gets an
 * inbox key — a second hybrid pair, made by a manager:
 *
 * ```text
 * public    in the registry, with stmt("gorani-inbox-v1", case, inbox key digest)
 *           signed by the manager — what a collector checks against the leads it pinned
 * private   sealed UNDER THE CASE KEY into place case.inbox(area, key id): only a
 *           case-key holder could have put it there, and only one can take it out
 * ```
 *
 * What a collector drops, and what this module opens:
 *
 * ```text
 * object   the bytes under a fresh content key (GV02 whole, GC01 frames)
 * ck       that content key, sealed to the inbox public key (GV03)
 * meta     sealed to the inbox public key (GV03), JSON:
 *            { case, item, collector, name, type, size, sha256,
 *              source, method, collectedAt, notes, signature }
 *          signature = the collector's, over
 *            stmt("gorani-collect-v1", case, item, collector, sha256, size,
 *                 name, type, source, method, collectedAt, notes)
 * stamp    SHA-256(signature bytes) — the RFC 3161 imprint, as a version's
 * ```
 *
 * Every field is signed, and the signature travels SEALED: in the clear it
 * would let the store test a guess ("is this the known file X?") — the
 * reason content hashes are sealed too. The store checks shapes and nothing
 * else; trust is decided here, by the member, against collectors whose
 * registration two leads THEY trust signed (collectors.ts).
 */

import { createStoreKey } from "./keys.ts";
import { checkRecordMatches } from "./records.ts";
import { places } from "./places.ts";
import { hybridDigest, stmt, type Signer, type Trust } from "./identity.ts";
import { collectorTrust, type CollectorRow } from "./collectors.ts";
import { stampImprint } from "./timestamp.ts";
import { importVaultKey, openPlacedText, openSealedText, sealPlacedText, unwrapContentKey, type VaultPrivateKey } from "./vault-crypto.ts";
import { fromBase64, toBase64 } from "../lib/encoding.ts";
import { caseArea } from "../lib/area.ts";

export const inboxStatements = {
	/** A manager's word that this is the case's inbox key. */
	key: (caseId: string, keyDigest: string) => stmt("gorani-inbox-v1", caseId, keyDigest),
	/** A collector's word for what it collected. */
	collect: (m: Omit<CollectMeta, "signature">) => stmt("gorani-collect-v1", m.case, m.item, m.collector, m.sha256, String(m.size), m.name, m.type, m.source, m.method, m.collectedAt, m.notes),
};

/** An inbox key as the case list carries it (`CaseRow.inboxKeys`). */
export interface InboxKeyRow {
	keyId: string;
	publicKey: { ec: JsonWebKey; kem: string };
	signature: string;
	signedBy: string;
	createdAt: string;
	/** Set once a newer key replaced it; collectors seal only to the current one. */
	retiredAt: string | null;
	/** The private half, sealed under the case key — present for those on the case. */
	privateSealed?: string;
}

/** What a collector sealed into an item's `meta`. */
export interface CollectMeta {
	case: string;
	item: string;
	collector: string;
	name: string;
	type: string;
	size: number;
	sha256: string;
	source: string;
	method: string;
	collectedAt: string;
	notes: string;
	signature: string;
}

/** An inbox item as `GET /api/v1/cases/<id>/inbox` lists it. */
export interface InboxItem {
	id: string;
	collector: string;
	inboxKeyId: string;
	size: number;
	chunk: number | null;
	ck: string;
	meta: string;
	stamp: { imprint: string | null; token: string | null; at: string | null };
	receivedAt: string;
	status: "waiting" | "accepted" | "rejected";
	accepted: { at: string; by: string; file: string } | null;
	rejected: { at: string; by: string; reason: string } | null;
}

export type InboxCall = <T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown) => Promise<T>;

/**
 * Make the case's (next) inbox key, as a manager holding the case key: the
 * body of `PUT /api/v1/cases/<id>/inbox-key`. The previous key, if any, is
 * retired by the registry — kept, because items sealed to it still open.
 */
export async function newInboxKey(caseKey: VaultPrivateKey, caseId: string, signer: Signer): Promise<{ keyId: string; publicKey: { ec: JsonWebKey; kem: string }; signature: string; privateSealed: string }> {
	const fresh = await createStoreKey();
	const signature = await signer.sign(inboxStatements.key(caseId, await hybridDigest(fresh.publicKey, fresh.pqPublicKey)));
	const b64 = toBase64(fresh.bundle);
	fresh.bundle.fill(0);
	const privateSealed = await sealPlacedText(caseKey, places.caseInbox(caseArea(caseId), fresh.keyId), b64);
	return { keyId: fresh.keyId, publicKey: { ec: fresh.publicKey, kem: fresh.pqPublicKey }, signature, privateSealed };
}

/** Make it and send it. Returns the case list the registry answers with. */
export async function createInboxKey<T>(call: InboxCall, caseKey: VaultPrivateKey, caseId: string, signer: Signer): Promise<T> {
	return call<T>("PUT", `/api/v1/cases/${caseId}/inbox-key`, await newInboxKey(caseKey, caseId, signer));
}

/**
 * Open an inbox key with the case key. Its place proves a case-key holder
 * sealed it there (a server cannot: GV04 needs the case's private key), and
 * the opened key must be the one the registry's public halves describe —
 * else a server could pair a real private half with public halves of its
 * own, and collectors would seal to the server.
 */
export async function openInboxKey(caseKey: VaultPrivateKey, caseId: string, k: InboxKeyRow): Promise<VaultPrivateKey> {
	return (await openChecked(caseKey, caseId, k)).key;
}

async function openChecked(caseKey: VaultPrivateKey, caseId: string, k: InboxKeyRow): Promise<{ key: VaultPrivateKey; b64: string }> {
	if (!k.privateSealed) throw new Error(`inbox key ${k.keyId} came without its private half — you are not on case ${caseId}`);
	const b64 = await openPlacedText(caseKey, places.caseInbox(caseArea(caseId), k.keyId), k.privateSealed);
	const key = await importVaultKey(fromBase64(b64));
	await checkRecordMatches(key, { keyId: k.keyId, publicKey: k.publicKey.ec, pqPublicKey: k.publicKey.kem });
	return { key, b64 };
}

/** Was this inbox key signed by a manager the member trusts? (What a
 * collector checks before sealing; a member's view shows it too.) */
export async function inboxKeyVerdict(trust: Trust, caseId: string, k: InboxKeyRow): Promise<string | null> {
	const signer = trust.of(k.signedBy);
	if (!signer) return `signed by ${k.signedBy}, whose identity you have not verified`;
	const ok = await signer.verify(inboxStatements.key(caseId, await hybridDigest(k.publicKey.ec, k.publicKey.kem)), k.signature);
	return ok ? null : `the signature does not verify — ${k.signedBy} did not make this inbox key`;
}

/**
 * Re-seal every inbox key under a case's NEW key (a case-key rotation):
 * the `inboxKeys` of `PUT /api/v1/cases/<id>/key`. Each is opened with the
 * old key — and must still be the key its public halves describe — before
 * it moves; the registry refuses a set that is one short or one long.
 */
export async function resealInboxKeys(oldKey: VaultPrivateKey, newKey: VaultPrivateKey, caseId: string, keys: InboxKeyRow[]): Promise<{ keyId: string; privateSealed: string }[]> {
	const out = [];
	for (const k of keys) {
		const { b64 } = await openChecked(oldKey, caseId, k);
		out.push({ keyId: k.keyId, privateSealed: await sealPlacedText(newKey, places.caseInbox(caseArea(caseId), k.keyId), b64) });
	}
	return out;
}

/** An item opened: what its collector said, and whether this member counts it. */
export interface OpenedItem {
	meta: CollectMeta;
	/** The item's content key — open the object with it (GV02 or GC01). */
	contentKey: CryptoKey;
	/** Null when the item is VERIFIED: a collector this member trusts signed
	 * exactly these fields, for this case and this item. Otherwise, why not. */
	problem: string | null;
}

/**
 * Open an inbox item with the case's inbox keys, and decide whether to
 * believe it. A signature is checked against the collectors THIS member
 * counts (two leads they trust registered it) — not against the registry's
 * word that the collector exists. The SHA-256 is the collector's claim:
 * the caller compares it with what it decrypts (`checkInboxContent`).
 */
export async function openInboxItem(inboxKeys: Map<string, VaultPrivateKey>, caseId: string, item: InboxItem, trust: Trust, collectors: CollectorRow[]): Promise<OpenedItem> {
	const key = inboxKeys.get(item.inboxKeyId);
	if (!key) throw new Error(`item ${item.id} is sealed to inbox key ${item.inboxKeyId}, which this case does not have`);
	const meta = JSON.parse(await openSealedText(key, item.meta)) as CollectMeta;
	const contentKey = await unwrapContentKey(key, item.ck);
	return { meta, contentKey, problem: await itemProblem(caseId, item, meta, trust, collectors) };
}

async function itemProblem(caseId: string, item: InboxItem, meta: CollectMeta, trust: Trust, collectors: CollectorRow[]): Promise<string | null> {
	// The sealed record must be about THIS drop: a valid record lifted from
	// another case, item or collector — or one whose size the store's own
	// count contradicts — is not this item's.
	if (meta.case !== caseId) return `its record is for case ${meta.case}, not ${caseId}`;
	if (meta.item !== item.id) return `its record is for item ${meta.item}, not ${item.id}`;
	if (meta.collector !== item.collector) return `its record names collector ${meta.collector}, but ${item.collector} dropped it`;
	if (meta.size !== item.size) return `its record says ${meta.size} bytes, the store received ${item.size}`;
	if (!/^[0-9a-f]{64}$/.test(meta.sha256 ?? "")) return "its record carries no SHA-256";
	const who = (await collectorTrust(trust, collectors)).get(item.collector);
	if (!who) return `collector ${item.collector} is not one you count — two leads you verified must have registered it (Team › Collectors)`;
	const { signature, ...fields } = meta;
	if (!(await who.verify(inboxStatements.collect(fields), signature))) return `the collector's signature does not verify — ${item.collector} did not collect this`;
	if (item.stamp.imprint && item.stamp.imprint !== (await stampImprint(signature))) return "its timestamp imprint is not over the collector's signature";
	return null;
}

/** The last check, on the decrypted bytes: are they what the collector signed? */
export function checkInboxContent(opened: OpenedItem, sha256: string, size: number): string | null {
	if (size !== opened.meta.size) return `decrypted ${size} bytes, the collector signed ${opened.meta.size}`;
	if (sha256 !== opened.meta.sha256) return "the content is not what the collector signed (SHA-256 differs)";
	return null;
}

/** Open every inbox key a case has (a member on it, with the case key). */
export async function openInboxKeys(caseKey: VaultPrivateKey, caseId: string, keys: InboxKeyRow[]): Promise<Map<string, VaultPrivateKey>> {
	const out = new Map<string, VaultPrivateKey>();
	for (const k of keys) out.set(k.keyId, await openInboxKey(caseKey, caseId, k));
	return out;
}
