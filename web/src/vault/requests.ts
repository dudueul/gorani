// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Upload links, the owner's side — docs/REQUESTS.md (commit 38b). The
 * Worker half is worker/src/requests.rs; the sender's half is
 * request-upload.ts (and the page around it, web/src/request-page.ts).
 *
 * A link opens a narrow door INTO an area: an outsider seals files in
 * their browser to the area's INBOX key (inbox.ts) and they wait in the
 * inbox until a person accepts them. Making one, in this browser:
 *
 * ```text
 * id, secret    fresh (request-crypto.ts): 16 and 32 random bytes, base64url
 * tokens        view = HKDF(secret), send = HKDF(secret ‖ SHA-256(password)) —
 *               the server keeps SHA-256 of each, never the secret or the password
 * note          sealed with the link's note key (GR01): the sender reads it, the server cannot
 * label         sealed with the store key into place request.label: the owner's list
 * inbox key     the area's CURRENT inbox key, opened and checked here first
 *               (inbox.ts › currentInboxKey) — its full hybrid digest goes in the link
 * link          <origin>/s/r/<id>#<secret>.<digest, base64url>
 * ```
 *
 * Why the digest rides in the fragment: the sender's page asks the SERVER
 * for the inbox key to seal to. A server that answered with a key of its
 * own would read everything sent — unless the page can tell. It can: the
 * fragment never reaches a server, and the page refuses a key that does
 * not hash to the digest the link's maker put there.
 */

import { hybridDigest } from "./identity.ts";
import { places } from "./places.ts";
import { newRequestId, newRequestSecret, isRequestId, isRequestSecret, requestKeys, sealRequestNote, tokenHash } from "./request-crypto.ts";
import { fromB64Url, toB64Url } from "./share-crypto.ts";
import { openPlacedText, sealPlacedText, type VaultPrivateKey } from "./vault-crypto.ts";
import { areaPath } from "../lib/area.ts";
import type { InboxCall, InboxKeyRow } from "./inbox.ts";

/** What the server allows (worker/src/requests.rs): this module never asks for more. */
export const LINK_LIMITS = { days: 30, files: 1000, bytes: 255 * 1024 ** 3 } as const;

/** An upload link as `GET …/requests` lists it (the token hashes stay on the server). */
export interface RequestRow {
	id: string;
	folderId: string | null;
	inboxKeyId: string;
	/** Sealed: open with `openRequestLabel`. */
	label: string;
	expiresAt: string;
	maxFiles: number;
	maxBytes: number;
	filesReceived: number;
	bytesReceived: number;
	failedAttempts: number;
	locked: boolean;
	revoked: boolean;
	expired: boolean;
	createdBy: string;
	createdAt: string;
}

export interface NewLinkOptions {
	/** Where the sender opens it: the deployment's origin (`location.origin`). */
	origin: string;
	/** The owner's name for the link — sealed, never shown to the sender. */
	label: string;
	/** What the sender reads ("the logs from WS-0412, please") — sealed with the link. */
	note: string;
	/** Needed to SEND (not to read the note): give it separately from the link. */
	password: string;
	/** Where accepted files go by default (a folder of the area); root when absent. */
	folderId?: string | null;
	days: number;
	maxFiles: number;
	maxBytes: number;
}

/**
 * A link password's floor. Lower than a vault password's on purpose: it
 * is never the only secret (the link's 256-bit secret is the other half),
 * a guess must be sent to the server, and the link locks after ten wrong
 * ones. An offline guess needs the stored hash AND the link.
 */
export function linkPasswordProblem(password: string): string | null {
	return [...password.normalize("NFKC")].length < 8 ? "a link's password is at least 8 characters" : null;
}

/**
 * A password to read aloud or paste — as the share dialog makes one: four
 * groups of four from 32 characters without look-alikes (80 bits).
 */
export function generatedLinkPassword(): string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
	const chars = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => alphabet[b % alphabet.length]);
	return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join("")).join("-");
}

/** The fragment's digest: the inbox key's hybrid digest (hex) as base64url (43 characters). */
export const digestForLink = (hex: string) => toB64Url(Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16)));

/**
 * Make an upload link into `area`, sealing to `inbox` — the area's current
 * inbox key, which the CALLER opened and checked (inbox.ts ›
 * currentInboxKey): a link made for a key nobody here could open would
 * collect files nobody can read. Returns the link — shown once; its secret
 * exists nowhere else.
 */
export async function createRequestLink(call: InboxCall, storeKey: VaultPrivateKey, area: string, inbox: Pick<InboxKeyRow, "keyId" | "publicKey" | "retiredAt">, opts: NewLinkOptions): Promise<{ link: string; row: RequestRow }> {
	const bad = linkPasswordProblem(opts.password);
	if (bad) throw new Error(bad);
	if (inbox.retiredAt) throw new Error("that inbox key is retired — a link seals to the current one");
	if (!opts.label.trim()) throw new Error("a link has a label, for your own list");
	if (!(opts.days > 0 && opts.days <= LINK_LIMITS.days)) throw new Error(`a link stays open 1–${LINK_LIMITS.days} days`);
	if (!(opts.maxFiles >= 1 && opts.maxFiles <= LINK_LIMITS.files)) throw new Error(`a link takes 1–${LINK_LIMITS.files} files`);
	if (!(opts.maxBytes >= 1 && opts.maxBytes <= LINK_LIMITS.bytes)) throw new Error("a link takes at most 255 GiB");
	const id = newRequestId();
	const secret = newRequestSecret();
	const keys = await requestKeys(id, secret, opts.password);
	const digest = await hybridDigest(inbox.publicKey.ec, inbox.publicKey.kem);
	const row = await call<RequestRow>("POST", `${areaPath(area)}/requests`, {
		id,
		folderId: opts.folderId ?? undefined,
		inboxKeyId: inbox.keyId,
		inboxPublic: inbox.publicKey,
		viewHash: await tokenHash(keys.view),
		sendHash: await tokenHash(keys.send),
		noteSealed: await sealRequestNote(keys.note, id, opts.note),
		labelSealed: await sealPlacedText(storeKey, places.requestLabel(area, id), opts.label.trim()),
		expiresAt: new Date(Date.now() + opts.days * 86_400_000).toISOString(),
		maxFiles: opts.maxFiles,
		maxBytes: opts.maxBytes,
	});
	return { link: `${opts.origin.replace(/\/$/, "")}/s/r/${id}#${secret}.${digestForLink(digest)}`, row };
}

/** The area's links, newest first. */
export async function listRequests(call: InboxCall, area: string): Promise<RequestRow[]> {
	return (await call<{ requests: RequestRow[] }>("GET", `${areaPath(area)}/requests`)).requests;
}

/** A link's label, opened in its place. */
export function openRequestLabel(storeKey: VaultPrivateKey, area: string, row: Pick<RequestRow, "id" | "label">): Promise<string> {
	return openPlacedText(storeKey, places.requestLabel(area, row.id), row.label);
}

/** Close a link for good: the next send is refused (items already in the inbox stay). */
export function revokeRequest(call: InboxCall, area: string, id: string): Promise<{ id: string; revoked: true }> {
	return call("DELETE", `${areaPath(area)}/requests/${id}`);
}

/** Is a link still taking files? (The server decides; this is the list's word for it.) */
export function linkState(r: Pick<RequestRow, "revoked" | "expired" | "locked" | "filesReceived" | "maxFiles" | "bytesReceived" | "maxBytes">): "open" | "revoked" | "expired" | "locked" | "full" {
	if (r.revoked) return "revoked";
	if (r.expired) return "expired";
	if (r.locked) return "locked";
	if (r.filesReceived >= r.maxFiles || r.bytesReceived >= r.maxBytes) return "full";
	return "open";
}

/**
 * A link, taken apart: `/s/r/<id>#<secret>.<digest>`. The digest comes back
 * as hex — what identity.ts › hybridDigest computes. Null when it is not
 * one (a share link, a truncated paste).
 */
export function parseRequestLink(href: string): { id: string; secret: string; digest: string } | null {
	let u: URL;
	try {
		u = new URL(href, "https://gorani.invalid");
	} catch {
		return null;
	}
	const id = /^\/s\/r\/([A-Za-z0-9_-]{22})\/?$/.exec(u.pathname)?.[1];
	const [secret, d] = decodeURIComponent(u.hash.replace(/^#/, "")).split(".");
	if (!id || !isRequestId(id) || !secret || !isRequestSecret(secret) || !d) return null;
	let bytes: Uint8Array;
	try {
		bytes = fromB64Url(d);
	} catch {
		return null;
	}
	if (bytes.length !== 32) return null;
	return { id, secret, digest: [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("") };
}
