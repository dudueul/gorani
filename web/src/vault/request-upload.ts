// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Upload links, the SENDER's side — docs/REQUESTS.md (commit 38b). What the
 * upload page (web/src/request-page.ts) runs, kept free of the DOM so the
 * API suite drives the very same code (tests/api/requests.test.ts).
 *
 * The sender has a link and a password, and nothing else: no account, no
 * key of their own. What this does with them:
 *
 * ```text
 * open      view token → POST /s/r/<id>/meta → the sealed note, the limits, the inbox key;
 *           the key must hash to the digest in the link's fragment, or nothing is sealed
 * seal      per file: a fresh content key; the bytes GV02 (whole) or GC01 frames (large);
 *           the key and a record { request, item, name, type, size, sha256, sender,
 *           message, sentAt } sealed to the inbox public key (GV03)
 * send      every request carries the SEND token (x-gorani-request-send), derived from
 *           the link's secret AND the password; ten wrong ones lock the link
 * ```
 *
 * Nothing here can read back what it sent — not the bytes, not the record.
 * The receipt (`SentFile`) is what the sender keeps: the name, the size and
 * the SHA-256 of what left their machine, to compare with what the
 * recipient says arrived.
 */

import { hybridDigest } from "./identity.ts";
import { newItemId } from "./places.ts";
import { openRequestNote, requestKeys } from "./request-crypto.ts";
import { parseRequestLink } from "./requests.ts";
import { chunkFor, frameCount, sealChunk } from "./chunked-file.ts";
import { sha256Stream } from "./content-hash.ts";
import { importContentKey, newContentKey, sealText, sealWith, wrapContentKey, type HybridPublicKey } from "./vault-crypto.ts";
import type { RequestMeta } from "./inbox.ts";

/** Up to this size a file goes up in one request (the app's own uploads and collectors use the same). */
export const WHOLE_LIMIT = 48 * 1024 * 1024;

/** An opened link: what the sender's page shows, and what it seals to. */
export interface OpenLink {
	origin: string;
	id: string;
	secret: string;
	/** The owner's note, opened with the link's note key. */
	note: string;
	expiresAt: string;
	filesLeft: number;
	bytesLeft: number;
	inboxKey: { keyId: string; publicKey: HybridPublicKey };
}

/** What a sender keeps of a file they sent. */
export interface SentFile {
	item: string;
	name: string;
	size: number;
	sha256: string;
}

type Fetch = typeof fetch;

/** A refusal from the server, as the page shows it (status kept: 403 wrong password, 423 locked…). */
export class LinkError extends Error {
	// (A plain field, not a parameter property: Node's type stripping — the
	// API suites run this file as-is — supports erasable syntax only.)
	readonly status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

async function refusal(r: Response): Promise<LinkError> {
	const text = await r.text().catch(() => "");
	let msg = text;
	try {
		msg = (JSON.parse(text) as { error?: string }).error ?? text;
	} catch {
		/* plain text */
	}
	return new LinkError(r.status, msg || `refused (${r.status})`);
}

/**
 * Open a link (`href`: the whole link as the sender pasted or opened it).
 * The inbox key the server offers is checked against the link's digest
 * BEFORE anything else — a substituted key is the one attack on this page
 * that would succeed silently, so it is the one refused loudly.
 */
export async function openLink(origin: string, href: string, fetchFn: Fetch = fetch): Promise<OpenLink> {
	const parsed = parseRequestLink(href);
	if (!parsed) throw new Error("this is not a complete upload link — ask its sender for it again (everything after # is part of it)");
	const keys = await requestKeys(parsed.id, parsed.secret);
	const r = await fetchFn(`${origin}/s/r/${parsed.id}/meta`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ view: keys.view }) });
	if (!r.ok) throw await refusal(r);
	const m = (await r.json()) as { noteSealed: string; expiresAt: string; filesLeft: number; bytesLeft: number; inboxKey: { keyId: string; publicKey: HybridPublicKey } };
	const pk = m.inboxKey?.publicKey;
	if (!pk?.ec || typeof pk.kem !== "string") throw new Error("the server sent no key to seal to");
	if ((await hybridDigest(pk.ec, pk.kem)) !== parsed.digest) {
		throw new Error("the server offered a key this link does not name — nothing was sent. Tell the person who gave you the link.");
	}
	return { origin, id: parsed.id, secret: parsed.secret, note: await openRequestNote(keys.note, parsed.id, m.noteSealed), expiresAt: m.expiresAt, filesLeft: m.filesLeft, bytesLeft: m.bytesLeft, inboxKey: m.inboxKey };
}

/** The send token for this link and password (computed once per batch). */
export async function sendToken(link: Pick<OpenLink, "id" | "secret">, password: string): Promise<string> {
	return (await requestKeys(link.id, link.secret, password)).send;
}

/** What a file is, to this module: a Blob with a name (a browser File, or Node's). */
export interface Sendable {
	name: string;
	type: string;
	size: number;
	slice(start?: number, end?: number): Blob;
}

/**
 * Seal and send one file. `progress(sent, total)` is called as bytes leave.
 * `wholeLimit` is for tests (a small file through the framed path).
 */
export async function sendFile(link: OpenLink, token: string, file: Sendable, from: { sender: string; message: string }, opts: { progress?: (sent: number, total: number) => void; wholeLimit?: number; fetchFn?: Fetch } = {}): Promise<SentFile> {
	const fetchFn = opts.fetchFn ?? fetch;
	const base = `${link.origin}/s/r/${link.id}`;
	const headers = { "x-gorani-request-send": token };
	const item = newItemId();
	const raw = newContentKey();
	const key = await importContentKey(raw);
	const pk = link.inboxKey.publicKey;
	const ck = await wrapContentKey(pk, raw);
	raw.fill(0);
	const record = async (sha256: string): Promise<string> => {
		const meta: RequestMeta = { request: link.id, item, name: file.name || "unnamed", type: file.type || "application/octet-stream", size: file.size, sha256, sender: from.sender.trim(), message: from.message.trim(), sentAt: new Date().toISOString() };
		return sealText(pk, JSON.stringify(meta));
	};
	const fields = () => ({ item_id: item, inbox_key_id: link.inboxKey.keyId, size: String(file.size), ck });

	if (file.size <= (opts.wholeLimit ?? WHOLE_LIMIT)) {
		const plain = new Uint8Array(await file.slice(0, file.size).arrayBuffer());
		const sha256 = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", plain as BufferSource)));
		const form = new FormData();
		for (const [k, v] of Object.entries({ ...fields(), meta: await record(sha256) })) form.append(k, v);
		form.append("file", new Blob([(await sealWith(key, plain)) as BlobPart]), "sealed");
		plain.fill(0);
		const r = await fetchFn(`${base}/items`, { method: "POST", headers, body: form });
		if (!r.ok) throw await refusal(r);
		opts.progress?.(file.size, file.size);
		return { item, name: file.name, size: file.size, sha256 };
	}

	// Large: GC01 frames, one storage part each; the SHA-256 is taken as the
	// frames go, and the record (which carries it) goes with the completion.
	const chunk = chunkFor(file.size);
	const n = frameCount(file.size, chunk);
	const started = await fetchFn(`${base}/uploads`, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ itemId: item, size: file.size, chunk }) });
	if (!started.ok) throw await refusal(started);
	const { uploadId, parts } = (await started.json()) as { uploadId: string; parts: number };
	if (parts !== n) throw new Error("the server counted a different number of parts");
	const h = await sha256Stream();
	const etags: { partNumber: number; etag: string }[] = [];
	for (let i = 0; i < n; i++) {
		const plain = new Uint8Array(await file.slice(i * chunk, Math.min(file.size, (i + 1) * chunk)).arrayBuffer());
		h.update(plain);
		const frame = await sealChunk(key, plain, i, i === n - 1);
		plain.fill(0);
		etags.push(await putPart(fetchFn, `${base}/uploads/${uploadId}/${i + 1}`, headers, frame));
		opts.progress?.(Math.min(file.size, (i + 1) * chunk), file.size);
	}
	const sha256 = h.hex();
	const form = new FormData();
	for (const [k, v] of Object.entries({ ...fields(), meta: await record(sha256), chunk: String(chunk), parts: JSON.stringify(etags) })) form.append(k, v);
	const done = await fetchFn(`${base}/uploads/${uploadId}/complete`, { method: "POST", headers, body: form });
	if (!done.ok) throw await refusal(done);
	return { item, name: file.name, size: file.size, sha256 };
}

/**
 * One frame; a dropped connection is tried again (twice), a refusal is not
 * — except "too many requests" (429, from an edge rule in front of the
 * Worker: docs/PRODUCTION.md), which is waited out as the answer says, up
 * to five times.
 */
async function putPart(fetchFn: Fetch, url: string, headers: Record<string, string>, frame: Uint8Array): Promise<{ partNumber: number; etag: string }> {
	let dropped = 0;
	let slowed = 0;
	for (;;) {
		let r: Response;
		try {
			r = await fetchFn(url, { method: "PUT", headers: { ...headers, "content-type": "application/octet-stream" }, body: frame as BodyInit });
		} catch (e) {
			if (++dropped > 2) throw e;
			continue;
		}
		if (r.status === 429 && ++slowed <= 5) {
			const wait = Math.min(60, Math.max(1, Number(r.headers.get("retry-after")) || 5));
			await new Promise((resolve) => setTimeout(resolve, wait * 1000));
			continue;
		}
		if (!r.ok) throw await refusal(r);
		return (await r.json()) as { partNumber: number; etag: string };
	}
}

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
