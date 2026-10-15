// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Places — where a sealed value lives (GV04, vault-crypto.ts › sealPlaced;
 * docs/SECURITY-REVIEW.md › O6). The Rust twin is crates/formats ›
 * placed.rs › Place.
 *
 * A place is built by the code that seals or opens a value, from what it is
 * sealing or opening — NEVER read off the server. That is the whole point:
 * the server decides which row it hands back; the client decides where
 * that row must have come from, and a value moved from anywhere else fails.
 *
 * ```text
 * place = lp("gorani-place-v1") ‖ lp(kind) ‖ lp(store) ‖ lp(item) ‖ lp(version)
 *         lp(x) = u32 BE length ‖ UTF-8;  version: decimal, "" for none
 * ```
 *
 * Length prefixes, not separators: ("ab","c") and ("a","bc") must be two
 * places, and an id may contain any character a separator would use.
 *
 * | kind | store | item | version | the value |
 * |---|---|---|---|---|
 * | `file.name` | member | file id | — | the file's name |
 * | `file.key` | member | file id | n | version n's content key |
 * | `file.type` | member | file id | n | version n's MIME type |
 * | `file.music` | member | file id | n | version n's tag summary |
 * | `file.hash` | member | file id | n | version n's signed content hash (content-hash.ts) |
 * | `file.intake` | member | file id | — | an evidence file's signed intake record (intake.ts) |
 * | `custody.reason` | member | file id | n | custody link n's reason (custody.ts) |
 * | `folder.name` | member | folder id | — | the folder's name |
 * | `share.name` | member | share id | — | the owner's copy of a link's name |
 * | `store.secrets` | member | — | — | fingerprint + index keys |
 * | `case.title` | `case:<id>` | — | — | a case's title (in the registry) |
 * | `case.inbox` | `case:<id>` | inbox key id | — | an inbox key's private half (in the registry; inbox.ts) |
 * | `file.collection` | `case:<id>` | file id | — | an accepted inbox item's collection record (inbox.ts) |
 * | `inbox.reject` | `case:<id>` | item id | — | why an inbox item was rejected (inbox.ts) |
 *
 * The `store` column is an AREA (lib/area.ts): a member id, or `case:<id>`
 * for a case (commit 26) — the same kinds, in a different store.
 *
 * Names are bound to the file, not to a version: a rename re-seals into the
 * same place. A version's key and type are bound to the version, so version
 * 1's key cannot be presented as version 2's.
 */

const enc = new TextEncoder();

export function place(kind: string, store: string, item: string, version?: number): Uint8Array {
	const fields = ["gorani-place-v1", kind, store, item, version === undefined ? "" : String(version)].map((f) => enc.encode(f));
	const out = new Uint8Array(fields.reduce((n, f) => n + 4 + f.length, 0));
	const view = new DataView(out.buffer);
	let at = 0;
	for (const f of fields) {
		view.setUint32(at, f.length);
		out.set(f, at + 4);
		at += 4 + f.length;
	}
	return out;
}

export const places = {
	fileName: (store: string, file: string) => place("file.name", store, file),
	fileKey: (store: string, file: string, version: number) => place("file.key", store, file, version),
	fileType: (store: string, file: string, version: number) => place("file.type", store, file, version),
	fileMusic: (store: string, file: string, version: number) => place("file.music", store, file, version),
	fileHash: (store: string, file: string, version: number) => place("file.hash", store, file, version),
	fileIntake: (store: string, file: string) => place("file.intake", store, file),
	custodyReason: (store: string, file: string, seq: number) => place("custody.reason", store, file, seq),
	folderName: (store: string, folder: string) => place("folder.name", store, folder),
	shareName: (store: string, share: string) => place("share.name", store, share),
	storeSecrets: (store: string) => place("store.secrets", store, ""),
	caseTitle: (store: string) => place("case.title", store, ""),
	/** A case inbox's private key (commit 37b): sealed with the case key, named by the inbox key's id. */
	caseInbox: (store: string, keyId: string) => place("case.inbox", store, keyId),
	/** An accepted inbox item's collection record (commit 37c): the collector's signed word, beside the file. */
	fileCollection: (store: string, file: string) => place("file.collection", store, file),
	/** Why an inbox item was turned away (commit 37c). */
	inboxReject: (store: string, item: string) => place("inbox.reject", store, item),
};

/** A fresh client-chosen id (file, folder): 128 random bits, base64url — the
 * shape the Worker's id allow-list accepts. Ids are chosen BEFORE sealing
 * because the place needs them (the Worker used to mint file ids after the
 * upload, when nothing could be bound to them any more). */
export function newItemId(): string {
	const b = globalThis.crypto.getRandomValues(new Uint8Array(16));
	return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
