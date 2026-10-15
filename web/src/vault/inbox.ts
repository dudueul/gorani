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
 *
 * Since commit 38 (docs/REQUESTS.md) an inbox also takes items from an
 * UPLOAD LINK — an outsider's browser, collector `request:<link id>` — and
 * a member's own area has an inbox too, its keys sealed under the files
 * key (place store.inbox) rather than kept in the registry. An outsider
 * has no identity key, so such an item carries no signature: its record
 * says what the link-holder declared, the link says who could have sent
 * it, and the person accepting it is the first to sign anything.
 *
 * Everything below takes an AREA (lib/area.ts) — `case:<id>` or a member
 * id; the `…InboxItem`/`checkCollection` names of 37b–37d keep their case
 * id parameter and call the area forms.
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
import { areaPath, caseArea } from "../lib/area.ts";
import { sampleType } from "./samples.ts";

export const inboxStatements = {
	/** A manager's word that this is the case's inbox key. */
	key: (caseId: string, keyDigest: string) => stmt("gorani-inbox-v1", caseId, keyDigest),
	/** A collector's word for what it collected. */
	collect: (m: Omit<CollectMeta, "signature">) => stmt("gorani-collect-v1", m.case, m.item, m.collector, m.sha256, String(m.size), m.name, m.type, m.source, m.method, m.collectedAt, m.notes),
	/** A member's word that this is their own area's inbox key (commit 38a). */
	areaKey: (member: string, keyDigest: string) => stmt("gorani-area-inbox-v1", member, keyDigest),
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

/**
 * What an upload link's page sealed into an item's `meta` (commit 38b,
 * web/src/request-page.ts). No signature — the sender has no identity key;
 * every field is the link-holder's word.
 */
export interface RequestMeta {
	/** The link's id: an item moved from another link's inbox names that link. */
	request: string;
	item: string;
	name: string;
	type: string;
	size: number;
	sha256: string;
	/** Who the sender says they are, and what they wrote — as typed. */
	sender: string;
	message: string;
	/** The sender's clock (the store's `receivedAt` is the one to cite). */
	sentAt: string;
}

/** The collector field of an upload link's items. */
export const requestCollector = (linkId: string) => `request:${linkId}`;
/** The link id of an upload link's item, or null for a collector's. */
export const linkOf = (item: Pick<InboxItem, "collector">) => (item.collector.startsWith("request:") ? item.collector.slice("request:".length) : null);

/** An inbox item as `GET …/inbox` lists it. */
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
 * Make a member's own (next) inbox key (commit 38a): the body of `PUT
 * /api/v1/members/<id>/inbox-key`. The same pair a case's is; the private
 * half sealed under the member's FILES key into place store.inbox, kept in
 * their own store (a store-key rotation re-seals it: rotation.ts).
 */
export async function newAreaInboxKey(filesKey: VaultPrivateKey, member: string, signer: Signer): Promise<{ keyId: string; publicKey: { ec: JsonWebKey; kem: string }; signature: string; signedBy: string; privateSealed: string }> {
	const fresh = await createStoreKey();
	const signature = await signer.sign(inboxStatements.areaKey(member, await hybridDigest(fresh.publicKey, fresh.pqPublicKey)));
	const b64 = toBase64(fresh.bundle);
	fresh.bundle.fill(0);
	const privateSealed = await sealPlacedText(filesKey, places.storeInbox(member, fresh.keyId), b64);
	return { keyId: fresh.keyId, publicKey: { ec: fresh.publicKey, kem: fresh.pqPublicKey }, signature, signedBy: signer.member, privateSealed };
}

/** Make it and send it. Returns this store's inbox keys (`{ inboxKeys }`). */
export async function createAreaInboxKey(call: InboxCall, filesKey: VaultPrivateKey, member: string, signer: Signer): Promise<{ inboxKeys: InboxKeyRow[] }> {
	return call("PUT", `/api/v1/members/${member}/inbox-key`, await newAreaInboxKey(filesKey, member, signer));
}

/** A member's own inbox keys, as their store lists them. */
export async function areaInboxKeys(call: InboxCall, member: string): Promise<InboxKeyRow[]> {
	return (await call<{ inboxKeys: InboxKeyRow[] }>("GET", `/api/v1/members/${member}/inbox-keys`)).inboxKeys;
}

/** Where an area's inbox key's private half is sealed: a case's under the
 * case key (case.inbox), a member's under their files key (store.inbox). */
const inboxPlace = (area: string, keyId: string) => (area.startsWith("case:") ? places.caseInbox(area, keyId) : places.storeInbox(area, keyId));

/** Open every inbox key an area has, with the area's store key (a case
 * key, or a member's files key) — each checked as `openInboxKey` checks. */
export async function openAreaInboxKeys(storeKey: VaultPrivateKey, area: string, keys: InboxKeyRow[]): Promise<Map<string, VaultPrivateKey>> {
	const out = new Map<string, VaultPrivateKey>();
	for (const k of keys) out.set(k.keyId, (await openCheckedIn(storeKey, area, k)).key);
	return out;
}

/** The area's current inbox key, opened and checked: what an upload link
 * is made for (its digest goes in the link — requests.ts). */
export async function currentInboxKey(storeKey: VaultPrivateKey, area: string, keys: InboxKeyRow[]): Promise<InboxKeyRow | null> {
	const k = keys.find((x) => !x.retiredAt);
	if (!k) return null;
	await openCheckedIn(storeKey, area, k);
	return k;
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

function openChecked(caseKey: VaultPrivateKey, caseId: string, k: InboxKeyRow): Promise<{ key: VaultPrivateKey; b64: string }> {
	return openCheckedIn(caseKey, caseArea(caseId), k);
}

async function openCheckedIn(storeKey: VaultPrivateKey, area: string, k: InboxKeyRow): Promise<{ key: VaultPrivateKey; b64: string }> {
	if (!k.privateSealed) throw new Error(`inbox key ${k.keyId} came without its private half — you are not on ${area}`);
	const b64 = await openPlacedText(storeKey, inboxPlace(area, k.keyId), k.privateSealed);
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

/** An item opened: what its sender said, and whether this member counts it. */
export type OpenedItem = (
	| { kind: "collector"; meta: CollectMeta }
	/** An upload link's (commit 38): an outsider's declaration, unsigned. */
	| { kind: "request"; meta: RequestMeta }
) & {
	/** The item's content key — open the object with it (GV02 or GC01). */
	contentKey: CryptoKey;
	/** Null when the item is consistent and, for a collector's, VERIFIED: a
	 * collector this member trusts signed exactly these fields, for this case
	 * and this item. Otherwise, why not. (A link's item has no signature to
	 * verify — null says only that its record is about THIS item.) */
	problem: string | null;
};

/**
 * Open an inbox item with the case's inbox keys, and decide whether to
 * believe it. A signature is checked against the collectors THIS member
 * counts (two leads they trust registered it) — not against the registry's
 * word that the collector exists. The SHA-256 is the collector's claim:
 * the caller compares it with what it decrypts (`checkInboxContent`).
 */
export function openInboxItem(inboxKeys: Map<string, VaultPrivateKey>, caseId: string, item: InboxItem, trust: Trust, collectors: CollectorRow[]): Promise<OpenedItem> {
	return openItem(inboxKeys, caseArea(caseId), item, trust, collectors);
}

/** The same in any area — a case's inbox, or a member's own (commit 38a).
 * `trust` may be null before the member's identity is open: a link's item
 * needs none; a collector's then says it cannot be checked yet. */
export async function openItem(inboxKeys: Map<string, VaultPrivateKey>, area: string, item: InboxItem, trust: Trust | null, collectors: CollectorRow[]): Promise<OpenedItem> {
	const key = inboxKeys.get(item.inboxKeyId);
	if (!key) throw new Error(`item ${item.id} is sealed to inbox key ${item.inboxKeyId}, which ${area} does not have`);
	const raw = JSON.parse(await openSealedText(key, item.meta));
	const contentKey = await unwrapContentKey(key, item.ck);
	if (linkOf(item)) {
		const meta = raw as RequestMeta;
		return { kind: "request", meta, contentKey, problem: requestProblem(item, meta) };
	}
	const meta = raw as CollectMeta;
	return { kind: "collector", meta, contentKey, problem: await itemProblem(area, item, meta, trust, collectors) };
}

async function itemProblem(area: string, item: Pick<InboxItem, "id" | "collector" | "size" | "stamp">, meta: CollectMeta, trust: Trust | null, collectors: CollectorRow[]): Promise<string | null> {
	// (Collectors drop into cases only — a member's own inbox takes links' items.)
	if (!area.startsWith("case:")) return `a collector's item in ${area}'s own inbox — collectors drop into cases only`;
	const caseId = area.slice("case:".length);
	// The sealed record must be about THIS drop: a valid record lifted from
	// another case, item or collector — or one whose size the store's own
	// count contradicts — is not this item's.
	if (meta.case !== caseId) return `its record is for case ${meta.case}, not ${caseId}`;
	if (meta.item !== item.id) return `its record is for item ${meta.item}, not ${item.id}`;
	if (meta.collector !== item.collector) return `its record names collector ${meta.collector}, but ${item.collector} dropped it`;
	if (meta.size !== item.size) return `its record says ${meta.size} bytes, the store received ${item.size}`;
	if (!/^[0-9a-f]{64}$/.test(meta.sha256 ?? "")) return "its record carries no SHA-256";
	if (!trust) return "your identity is not open yet — a collector's signature is checked with it";
	const who = (await collectorTrust(trust, collectors)).get(item.collector);
	if (!who) return `collector ${item.collector} is not one you count — two leads you verified must have registered it (Team › Collectors)`;
	const { signature, ...fields } = meta;
	if (!(await who.verify(inboxStatements.collect(fields), signature))) return `the collector's signature does not verify — ${item.collector} did not collect this`;
	if (item.stamp.imprint && item.stamp.imprint !== (await stampImprint(signature))) return "its timestamp imprint is not over the collector's signature";
	return null;
}

/**
 * An upload link's item: its record must be about THIS item, from THIS
 * link. That is all there is to check — no key signed it. (The store could
 * move a sealed record between items or links of one area; the record
 * names both, so a moved one is caught. Into another area it would not
 * open at all: another area's inbox keys are other keys.)
 */
function requestProblem(item: Pick<InboxItem, "id" | "collector" | "size">, meta: RequestMeta): string | null {
	const link = linkOf(item);
	if (meta.request !== link) return `its record is for link ${meta.request}, not ${link}`;
	if (meta.item !== item.id) return `its record is for item ${meta.item}, not ${item.id}`;
	if (meta.size !== item.size) return `its record says ${meta.size} bytes, the store received ${item.size}`;
	if (!/^[0-9a-f]{64}$/.test(meta.sha256 ?? "")) return "its record carries no SHA-256";
	if (typeof meta.name !== "string" || !meta.name) return "its record carries no file name";
	return null;
}

/** The last check, on the decrypted bytes: are they what the sender recorded? */
export function checkInboxContent(opened: OpenedItem, sha256: string, size: number): string | null {
	const who = opened.kind === "collector" ? "the collector signed" : "the sender declared";
	if (size !== opened.meta.size) return `decrypted ${size} bytes, ${who} ${opened.meta.size}`;
	if (sha256 !== opened.meta.sha256) return `the content is not what ${who} (SHA-256 differs)`;
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

/** What `file.collection(area, file)` holds: the sender's word, kept whole. */
export type CollectionRecord = {
	v: 1;
	item: string;
	/** The collector's id — or `request:<link id>` for an upload link's item. */
	collector: string;
	inboxKeyId: string;
	receivedAt: string;
	/** The RFC 3161 token over SHA-256(the collector's signature), when the store had one. */
	stamp: { imprint: string | null; token: string | null; at: string | null };
	acceptedBy: string;
} & (
	| { kind?: undefined; meta: CollectMeta }
	/** (commit 38) An upload link's: the sender's declaration, no signature. */
	| { kind: "request"; meta: RequestMeta }
);

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
export function acceptInboxItem<T>(call: InboxCall, caseKey: VaultPrivateKey, inboxKeys: Map<string, VaultPrivateKey>, caseId: string, item: InboxItem, opened: OpenedItem, content: { sha256: string; size: number }, signer: Signer, opts: AcceptOptions = {}): Promise<T> {
	return acceptItem<T>(call, caseKey, inboxKeys, caseArea(caseId), item, opened, content, signer, opts);
}

export interface AcceptOptions {
	name?: string;
	folderId?: string;
	/**
	 * File it as a malware sample (D8, commit 29e: the viewer refuses it,
	 * it leaves only zipped under "infected", never by link). The DEFAULT
	 * for an upload link's item (docs/REQUESTS.md › Untrusted content): an
	 * outsider's bytes are untrusted until a person decides otherwise —
	 * and a sample stays a sample (there is no unmarking).
	 */
	asSample?: boolean;
	/** (An upload link's item) how the accepter names where it came from. */
	linkLabel?: string;
}

/**
 * The same in any area (commit 38a). An upload link's item is accepted
 * when its record is about this item and its bytes hash to what the
 * sender declared — there is no signature to require; the accepter's own
 * content hash and intake are the first signatures on it. Its intake says
 * so: collector `request:<link>`, the sender's name as they typed it.
 */
export async function acceptItem<T>(call: InboxCall, storeKey: VaultPrivateKey, inboxKeys: Map<string, VaultPrivateKey>, area: string, item: InboxItem, opened: OpenedItem, content: { sha256: string; size: number }, signer: Signer, opts: AcceptOptions = {}): Promise<T> {
	if (opened.problem) throw new Error(`refusing to accept an item that is not verified: ${opened.problem}`);
	const bad = checkInboxContent(opened, content.sha256, content.size);
	if (bad) throw new Error(`refusing to accept it: ${bad}`);
	const inboxKey = inboxKeys.get(item.inboxKeyId);
	if (!inboxKey) throw new Error(`no inbox key ${item.inboxKeyId}`);
	const file = newItemId();
	const raw = fromBase64(await openSealedText(inboxKey, item.ck));
	const base = { v: 1 as const, item: item.id, collector: item.collector, inboxKeyId: item.inboxKeyId, receivedAt: item.receivedAt, stamp: item.stamp, acceptedBy: signer.member };
	let record: CollectionRecord;
	let intake: { source: string; collector: string; method: string; collectedAt: string; notes: string };
	let sample: boolean;
	if (opened.kind === "collector") {
		const m = opened.meta;
		record = { ...base, meta: m };
		intake = { source: m.source, collector: `collector:${m.collector}`, method: m.method, collectedAt: m.collectedAt, notes: m.notes };
		sample = opts.asSample ?? false;
	} else {
		const m = opened.meta;
		record = { ...base, kind: "request", meta: m };
		// (The store's clock, not the sender's: `receivedAt` is what the store recorded.)
		const from = m.sender.trim() || "an unnamed sender";
		intake = { source: `${from}, through upload link ${opts.linkLabel?.trim() || m.request}`, collector: item.collector, method: "upload link (sealed in the sender's browser)", collectedAt: item.receivedAt, notes: m.message };
		sample = opts.asSample ?? true;
	}
	const type = opened.meta.type || "application/octet-stream";
	const hash = await signContentHashStamped(signer, storeKey, area, file, 1, content.sha256, content.size);
	const body = {
		fileId: file,
		name: await sealPlacedText(storeKey, places.fileName(area, file), opts.name ?? opened.meta.name),
		type: await sealPlacedText(storeKey, places.fileType(area, file, 1), sample ? sampleType(type) : type),
		ck: await wrapPlacedKey(storeKey, places.fileKey(area, file, 1), raw),
		hash: hash.sealed,
		stamp: hash.stamp,
		intake: await signIntake(signer, storeKey, area, file, intake),
		collection: await sealPlacedText(storeKey, places.fileCollection(area, file), JSON.stringify(record)),
		...(sample ? { sample: true } : {}),
		...(opts.folderId ? { folderId: opts.folderId } : {}),
	};
	raw.fill(0);
	return call<T>("POST", `${areaPath(area)}/inbox/${item.id}/accept`, body);
}

/** Turn an item away, saying why — the reason sealed (it may name what the item is). */
export function rejectInboxItem<T>(call: InboxCall, caseKey: VaultPrivateKey, caseId: string, itemId: string, reason: string): Promise<T> {
	return rejectItem<T>(call, caseKey, caseArea(caseId), itemId, reason);
}

export async function rejectItem<T>(call: InboxCall, storeKey: VaultPrivateKey, area: string, itemId: string, reason: string): Promise<T> {
	if (!reason.trim()) throw new Error("a rejection says why");
	return call<T>("POST", `${areaPath(area)}/inbox/${itemId}/reject`, { reason: await sealPlacedText(storeKey, places.inboxReject(area, itemId), reason.trim()) });
}

/** A rejection's reason, opened in its place. */
export function openRejectReason(caseKey: VaultPrivateKey, caseId: string, itemId: string, sealed: string): Promise<string> {
	return openPlacedText(caseKey, places.inboxReject(caseArea(caseId), itemId), sealed);
}

export function openItemRejectReason(storeKey: VaultPrivateKey, area: string, itemId: string, sealed: string): Promise<string> {
	return openPlacedText(storeKey, places.inboxReject(area, itemId), sealed);
}

/**
 * A file's collection record, opened in its place and checked: the
 * collector this member counts signed exactly these fields for this case,
 * and they vouch for THESE bytes (`content`: the file's verified SHA-256
 * and size). The file's own content hash names the person who accepted it;
 * this names the machine that collected it.
 */
export function checkCollection(caseKey: VaultPrivateKey, caseId: string, file: string, sealed: string, trust: Trust, collectors: CollectorRow[], content?: { sha256: string; size: number }): Promise<{ record: CollectionRecord; problem: string | null }> {
	return checkItemCollection(caseKey, caseArea(caseId), file, sealed, trust, collectors, content);
}

/**
 * The same in any area. An upload link's record has nothing to verify but
 * that it is about its own item and these bytes — `problem` null then
 * means CONSISTENT, not signed (`record.kind === "request"` says which).
 */
export async function checkItemCollection(storeKey: VaultPrivateKey, area: string, file: string, sealed: string, trust: Trust, collectors: CollectorRow[], content?: { sha256: string; size: number }): Promise<{ record: CollectionRecord; problem: string | null }> {
	const record = JSON.parse(await openPlacedText(storeKey, places.fileCollection(area, file), sealed)) as CollectionRecord;
	const m = record.meta;
	const asItem = { id: record.item, collector: record.collector, size: m.size, stamp: record.stamp };
	const isLink = record.collector.startsWith("request:");
	if (isLink !== (record.kind === "request")) return { record, problem: "its record's kind does not match who sent it" };
	let problem = record.kind === "request" ? requestProblem(asItem, record.meta) : await itemProblem(area, asItem, record.meta, trust, collectors);
	if (!problem && content && (content.sha256 !== m.sha256 || content.size !== m.size)) problem = record.kind === "request" ? "the file is not the bytes the sender declared" : "the file is not the bytes the collector signed";
	return { record, problem };
}
