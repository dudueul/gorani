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
 *
 * Places (commit 25, GV04 — places.ts): every value is opened and re-sealed
 * in the place its ROW names — `version` rows by (file, version), `file`
 * and `folder` rows by their id, and so on. The walk never trusts a value
 * to say where it belongs; it asks the row, and a value moved from another
 * row fails under both keys. Re-sealing under the new key also moves every
 * value to the new store PSK: what the departing member could still mint
 * with the OLD key is refused from here on.
 *
 * Areas (commit 26): `memberId` is an AREA — a member id or `case:<id>`
 * (lib/area.ts). A case rotates through the same walk (cases.ts ›
 * rotateCase), because a case is a store like any other.
 */

import { openPlacedText, sealPlacedText, type VaultPrivateKey } from "./vault-crypto.ts";
import { places } from "./places.ts";
import { areaPath } from "../lib/area.ts";

// (`hash`: the uploaders' signed content hashes — commit 29d. Re-sealed like
// the rest; the SIGNATURE inside does not change, it never named a key.)
export const SEALED_KINDS = ["version", "file", "folder", "music", "share", "secrets", "hash"] as const;
export type SealedKind = (typeof SEALED_KINDS)[number];

/** A JSON call against the API (the browser's bridge, or a test's helper). */
export type ApiCall = (method: "GET" | "PUT" | "POST", path: string, body?: unknown) => Promise<unknown>;

interface SealedItem {
	row: number;
	a: string | null;
	b: string | null;
	v1: string | null;
	v2: string | null;
}

interface SealedPage {
	items: SealedItem[];
	next: number | null;
}

export interface RotationReport {
	resealed: Record<SealedKind, number>;
	alreadyNew: Record<SealedKind, number>;
}

/** The places of a row's two values (v1, v2) — from the row, never the value. */
function placesOf(memberId: string, kind: SealedKind, it: SealedItem): [Uint8Array, Uint8Array | null] {
	const id = it.a ?? "";
	const version = Number(it.b);
	switch (kind) {
		case "version":
			return [places.fileKey(memberId, id, version), places.fileType(memberId, id, version)];
		case "file":
			return [places.fileName(memberId, id), null];
		case "folder":
			return [places.folderName(memberId, id), null];
		case "music":
			return [places.fileMusic(memberId, id, version), null];
		case "share":
			return [places.shareName(memberId, id), null];
		case "secrets":
			return [places.storeSecrets(memberId), null];
		case "hash":
			return [places.fileHash(memberId, id, version), null];
	}
}

/** Re-seal one value in its place: old key → new key; already-new → null (skip). */
async function reseal(value: string, place: Uint8Array, oldPrivate: VaultPrivateKey, newPrivate: VaultPrivateKey): Promise<string | null> {
	let plain: string;
	try {
		plain = await openPlacedText(oldPrivate, place, value);
	} catch {
		try {
			await openPlacedText(newPrivate, place, value);
			return null; // done on an earlier run
		} catch {
			throw new Error("a value opens under neither the old nor the new store key in its place — refusing to continue");
		}
	}
	return sealPlacedText(newPrivate, place, plain);
}

async function* pages(call: ApiCall, memberId: string, kind: SealedKind): AsyncGenerator<SealedItem[]> {
	let after = 0;
	for (;;) {
		const page = (await call("GET", `${areaPath(memberId)}/files/sealed?kind=${kind}&after=${after}&limit=500`)) as SealedPage;
		yield page.items;
		if (page.next === null) return;
		after = page.next;
	}
}

/**
 * Walk member `memberId`'s whole store from `oldPrivate` to `newPrivate`.
 * (No public key parameter: a store seals to itself, GV04.) Run it BEFORE
 * the settings switch to the new key and before the departing member is
 * deactivated (the runbook's order).
 */
export async function resealStore(call: ApiCall, memberId: string, oldPrivate: VaultPrivateKey, newPrivate: VaultPrivateKey): Promise<RotationReport> {
	const zero = () => Object.fromEntries(SEALED_KINDS.map((k) => [k, 0])) as Record<SealedKind, number>;
	const report: RotationReport = { resealed: zero(), alreadyNew: zero() };
	for (const kind of SEALED_KINDS) {
		for await (const page of pages(call, memberId, kind)) {
			const items: { kind: SealedKind; row: number; v1: string; v2?: string }[] = [];
			for (const it of page) {
				if (!it.v1) continue;
				const [p1, p2] = placesOf(memberId, kind, it);
				const v1 = await reseal(it.v1, p1, oldPrivate, newPrivate);
				// A version's type rides with its content key (both sealed into
				// the version's places); a version without a type has no v2.
				const v2 = p2 && it.v2 ? await reseal(it.v2, p2, oldPrivate, newPrivate) : null;
				if (v1 === null && v2 === null) {
					report.alreadyNew[kind]++;
					continue;
				}
				items.push({ kind, row: it.row, v1: v1 ?? it.v1, ...(v2 ? { v2 } : {}) });
			}
			if (items.length) {
				await call("PUT", `${areaPath(memberId)}/files/reseal`, { items });
				report.resealed[kind] += items.length;
			}
		}
	}
	return report;
}

/** Can this key still open any value of the store, in its place? (The proof
 * step: after a rotation, the OLD key must open nothing.) Returns the count. */
export async function opensAnything(call: ApiCall, memberId: string, key: VaultPrivateKey): Promise<number> {
	let opened = 0;
	for (const kind of SEALED_KINDS) {
		for await (const page of pages(call, memberId, kind)) {
			for (const it of page) {
				const [p1, p2] = placesOf(memberId, kind, it);
				for (const [v, p] of [
					[it.v1, p1],
					[it.v2, p2],
				] as const) {
					if (!v || !p) continue;
					try {
						await openPlacedText(key, p, v);
						opened++;
					} catch {
						// sealed to another key — exactly what the proof wants
					}
				}
			}
		}
	}
	return opened;
}
