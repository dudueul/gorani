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
import { newItemId, places } from "./places.ts";
import { hybridDigest, stmt, type Signer, type Trust } from "./identity.ts";
import { collectorTrust, type CollectorRow } from "./collectors.ts";
import { stampImprint } from "./timestamp.ts";
import { sha256Stream, signContentHashStamped } from "./content-hash.ts";
import { signIntake } from "./intake.ts";
import { openChunked, openChunkedStream, sealedSize } from "./chunked-file.ts";
import { importVaultKey, openPlacedText, openSealedText, openWith, sealPlacedText, unwrapContentKey, wrapPlacedKey, type VaultPrivateKey } from "./vault-crypto.ts";
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

// ── deciding an item (commit 37c) ─────────────────────────────────────

/**
 * Decrypt an item's bytes as they arrive and hash them — never held whole
 * when framed (a 255 GiB disk image streams through). `body` is the
 * response of `GET …/inbox/<item>`. The frame count comes from the item's
 * own size and frame size, not from a Content-Length header: a streamed
 * response may carry none, and a frame boundary must not hang on one.
 */
export async function hashInboxContent(opened: OpenedItem, item: Pick<InboxItem, "size" | "chunk">, body: ReadableStream<Uint8Array>, sink?: (plain: Uint8Array) => Promise<void> | void): Promise<{ sha256: string; size: number }> {
	const chunk = item.chunk;
	const h = await sha256Stream();
	let size = 0;
	const feed = async (p: Uint8Array) => {
		h.update(p);
		size += p.length;
		if (sink) await sink(p);
	};
	if (chunk) await openChunkedStream(opened.contentKey, body, chunk, sealedSize(item.size, chunk), feed);
	else await feed(await openWith(opened.contentKey, new Uint8Array(await new Response(body).arrayBuffer())));
	return { sha256: h.hex(), size };
}

/** (The same over bytes in memory — a test's, a small item's.) */
export async function hashInboxBytes(opened: OpenedItem, chunk: number | null, sealed: Uint8Array): Promise<{ sha256: string; size: number }> {
	const plain = chunk ? await openChunked(opened.contentKey, sealed, chunk) : await openWith(opened.contentKey, sealed);
	const h = await sha256Stream();
	h.update(plain);
	return { sha256: h.hex(), size: plain.length };
}

/** What `file.collection(area, file)` holds: the collector's word, kept whole. */
export interface CollectionRecord {
	v: 1;
	item: string;
	collector: string;
	inboxKeyId: string;
	receivedAt: string;
	/** The RFC 3161 token over SHA-256(the collector's signature), when the store had one. */
	stamp: { imprint: string | null; token: string | null; at: string | null };
	meta: CollectMeta;
	acceptedBy: string;
}

/**
 * Accept an item into the case as a NEW file — the body of `POST
 * …/inbox/<item>/accept`, sent. Only a VERIFIED item whose bytes were
 * checked (`content`, from `hashInboxContent`) is accepted: a person files
 * what they could tie to a collector they trust, and turns the rest away.
 *
 * What the file carries is what a person's upload carries — name, type and
 * content key placed with the case key, THEIR signed content hash (with
 * its timestamp imprint) and a signed intake record repeating the
 * collector's fields — plus the collector's record, placed beside it. Two
 * signatures over the same bytes: the machine that collected them and the
 * person who accepted them. The bytes stay where they landed.
 */
export async function acceptInboxItem<T>(call: InboxCall, caseKey: VaultPrivateKey, inboxKeys: Map<string, VaultPrivateKey>, caseId: string, item: InboxItem, opened: OpenedItem, content: { sha256: string; size: number }, signer: Signer, opts: { name?: string; folderId?: string } = {}): Promise<T> {
	if (opened.problem) throw new Error(`refusing to accept an item that is not verified: ${opened.problem}`);
	const bad = checkInboxContent(opened, content.sha256, content.size);
	if (bad) throw new Error(`refusing to accept it: ${bad}`);
	const inboxKey = inboxKeys.get(item.inboxKeyId);
	if (!inboxKey) throw new Error(`no inbox key ${item.inboxKeyId}`);
	const area = caseArea(caseId);
	const file = newItemId();
	const m = opened.meta;
	const raw = fromBase64(await openSealedText(inboxKey, item.ck));
	const record: CollectionRecord = { v: 1, item: item.id, collector: item.collector, inboxKeyId: item.inboxKeyId, receivedAt: item.receivedAt, stamp: item.stamp, meta: m, acceptedBy: signer.member };
	const hash = await signContentHashStamped(signer, caseKey, area, file, 1, content.sha256, content.size);
	const body = {
		fileId: file,
		name: await sealPlacedText(caseKey, places.fileName(area, file), opts.name ?? m.name),
		type: await sealPlacedText(caseKey, places.fileType(area, file, 1), m.type || "application/octet-stream"),
		ck: await wrapPlacedKey(caseKey, places.fileKey(area, file, 1), raw),
		hash: hash.sealed,
		stamp: hash.stamp,
		intake: await signIntake(signer, caseKey, area, file, { source: m.source, collector: `collector:${m.collector}`, method: m.method, collectedAt: m.collectedAt, notes: m.notes }),
		collection: await sealPlacedText(caseKey, places.fileCollection(area, file), JSON.stringify(record)),
		...(opts.folderId ? { folderId: opts.folderId } : {}),
	};
	raw.fill(0);
	return call<T>("POST", `/api/v1/cases/${caseId}/inbox/${item.id}/accept`, body);
}

/** Turn an item away, saying why — the reason sealed (it may name what the item is). */
export async function rejectInboxItem<T>(call: InboxCall, caseKey: VaultPrivateKey, caseId: string, itemId: string, reason: string): Promise<T> {
	if (!reason.trim()) throw new Error("a rejection says why");
	return call<T>("POST", `/api/v1/cases/${caseId}/inbox/${itemId}/reject`, { reason: await sealPlacedText(caseKey, places.inboxReject(caseArea(caseId), itemId), reason.trim()) });
}

/** A rejection's reason, opened in its place. */
export function openRejectReason(caseKey: VaultPrivateKey, caseId: string, itemId: string, sealed: string): Promise<string> {
	return openPlacedText(caseKey, places.inboxReject(caseArea(caseId), itemId), sealed);
}

/**
 * A file's collection record, opened in its place and checked: the
 * collector this member counts signed exactly these fields for this case,
 * and they vouch for THESE bytes (`content`: the file's verified SHA-256
 * and size). The file's own content hash names the person who accepted it;
 * this names the machine that collected it.
 */
export async function checkCollection(caseKey: VaultPrivateKey, caseId: string, file: string, sealed: string, trust: Trust, collectors: CollectorRow[], content?: { sha256: string; size: number }): Promise<{ record: CollectionRecord; problem: string | null }> {
	const record = JSON.parse(await openPlacedText(caseKey, places.fileCollection(caseArea(caseId), file), sealed)) as CollectionRecord;
	const m = record.meta;
	const asItem = { id: record.item, collector: record.collector, size: m.size, stamp: record.stamp } as InboxItem;
	let problem = await itemProblem(caseId, asItem, m, trust, collectors);
	if (!problem && content && (content.sha256 !== m.sha256 || content.size !== m.size)) problem = "the file is not the bytes the collector signed";
	return { record, problem };
}
