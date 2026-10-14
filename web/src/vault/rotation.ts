// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The store-rotation walk (docs/FAMILY.md › Removing a member,
 * docs/SECURITY-REVIEW.md › O5): every value sealed to a store key — every
 * VERSION's content key and type, file names, folder names, music tags,
 * share names, the files secrets — re-sealed from the old store key to the
 * new one, page by page, by the client. The server lists rows and stores
 * results; it never holds a key.
 *
 * Why it must be every row: a departing member keeps their copy of the OLD
 * store private key. Whatever is still sealed to it, they can still open
 * (given the ciphertext, e.g. from a backup or the edge cache). The walk
 * before commit 24 re-wrapped only each file's living version and the file
 * names — older versions, folders, tags and secrets stayed readable.
 *
 * Idempotent and resumable: a value that already opens under the NEW key is
 * skipped; one that opens under neither is an error (it was sealed to some
 * third key — stop and look, never guess).
 */

import { openSealedText, sealText, type SealTarget, type VaultPrivateKey } from "./vault-crypto.ts";

export const SEALED_KINDS = ["version", "file", "folder", "music", "share", "secrets"] as const;
export type SealedKind = (typeof SEALED_KINDS)[number];

/** A JSON call against the API (the browser's bridge, or a test's helper). */
export type ApiCall = (method: "GET" | "PUT", path: string, body?: unknown) => Promise<unknown>;

interface SealedPage {
	items: { row: number; a: string | null; b: string | null; v1: string | null; v2: string | null }[];
	next: number | null;
}

export interface RotationReport {
	resealed: Record<SealedKind, number>;
	alreadyNew: Record<SealedKind, number>;
}

/** Re-seal one value: old key → new key; already-new → null (skip). */
async function reseal(value: string, oldPrivate: VaultPrivateKey, newPrivate: VaultPrivateKey, newPublic: SealTarget): Promise<string | null> {
	let plain: string;
	try {
		plain = await openSealedText(oldPrivate, value);
	} catch {
		try {
			await openSealedText(newPrivate, value);
			return null; // done on an earlier run
		} catch {
			throw new Error("a value opens under neither the old nor the new store key — refusing to continue");
		}
	}
	return sealText(newPublic, plain);
}

/**
 * Walk member `memberId`'s whole store from `oldPrivate` to the new key pair.
 * Run it BEFORE the settings switch to the new key and before the departing
 * member is deactivated (the runbook's order).
 */
export async function resealStore(call: ApiCall, memberId: string, oldPrivate: VaultPrivateKey, newPrivate: VaultPrivateKey, newPublic: SealTarget): Promise<RotationReport> {
	const zero = () => Object.fromEntries(SEALED_KINDS.map((k) => [k, 0])) as Record<SealedKind, number>;
	const report: RotationReport = { resealed: zero(), alreadyNew: zero() };
	for (const kind of SEALED_KINDS) {
		let after = 0;
		for (;;) {
			const page = (await call("GET", `/api/v1/members/${memberId}/files/sealed?kind=${kind}&after=${after}&limit=500`)) as SealedPage;
			const items: { kind: SealedKind; row: number; v1: string; v2?: string }[] = [];
			for (const it of page.items) {
				if (!it.v1) continue;
				const v1 = await reseal(it.v1, oldPrivate, newPrivate, newPublic);
				// A version's type rides with its content key (both sealed to the
				// store); a version without a type has nothing more to move.
				const v2 = kind === "version" && it.v2 ? await reseal(it.v2, oldPrivate, newPrivate, newPublic) : null;
				if (v1 === null && v2 === null) {
					report.alreadyNew[kind]++;
					continue;
				}
				items.push({ kind, row: it.row, v1: v1 ?? it.v1, ...(v2 ? { v2 } : {}) });
			}
			if (items.length) {
				await call("PUT", `/api/v1/members/${memberId}/files/reseal`, { items });
				report.resealed[kind] += items.length;
			}
			if (page.next === null) break;
			after = page.next;
		}
	}
	return report;
}

/** Can this key still open any value of the store? (The proof step: after a
 * rotation, the OLD key must open nothing.) Returns the count it opens. */
export async function opensAnything(call: ApiCall, memberId: string, key: VaultPrivateKey): Promise<number> {
	let opened = 0;
	for (const kind of SEALED_KINDS) {
		let after = 0;
		for (;;) {
			const page = (await call("GET", `/api/v1/members/${memberId}/files/sealed?kind=${kind}&after=${after}&limit=500`)) as SealedPage;
			for (const it of page.items) {
				for (const v of [it.v1, it.v2]) {
					if (!v) continue;
					try {
						await openSealedText(key, v);
						opened++;
					} catch {
						// sealed to another key — exactly what the proof wants
					}
				}
			}
			if (page.next === null) break;
			after = page.next;
		}
	}
	return opened;
}
