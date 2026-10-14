// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Signed content hashes — docs/CUSTODY.md › Stage 4 (D5.1, commit 29d).
 *
 * The question a review asks of an evidence file is not "does it decrypt"
 * (AES-GCM already proves the bytes are the ones sealed with this content
 * key) but "are these the bytes Bo uploaded?" — a claim only Bo can make.
 * So the uploader signs it, before the bytes leave their machine:
 *
 * ```text
 * h      = SHA-256(plaintext)                       (what the evidence IS, not its ciphertext)
 * s      = sign(identity key, stmt("gorani-content-hash-v1", area, file, version, h, size))
 * record = { v: 1, sha256: h, size, signer, keyId, signature: s }
 * stored = sealPlaced(store key, file.hash(area, file, version), record)   (GV04)
 * ```
 *
 * - **Sealed, not readable**: a plaintext hash is a fingerprint of the
 *   content — the server could answer "does this case hold the file with
 *   hash X?" (a known document, a known sample) without any key. Sealed,
 *   it learns nothing it could not learn from a ciphertext's length.
 * - **In its place**: the record opens only from `file.hash` of THIS
 *   area, file and version — a server cannot present version 1's record
 *   as version 2's, or one case's as another's. The signed statement names
 *   the same four things, so even a holder of the store key (anyone on the
 *   case) cannot re-seal a record somewhere it was not signed for.
 * - **Signed by a person, checked against YOUR trust**: the signature
 *   verifies under the signer's identity key, and that key counts only if
 *   the reader trusts it (identity.ts › buildTrust — pinned, or certified
 *   by someone pinned). A co-worker on the case can seal a record (they
 *   hold the store key) but cannot sign it as Bo.
 *
 * The honest limits:
 * - **Re-enrolment**: the registry lists each member's CURRENT identity.
 *   A record signed before they re-enrolled names an older key id, and is
 *   reported `untrusted` ("re-enrolled since"), not `verified` — the
 *   signed export (stage 7) is where a signer's past keys travel with the
 *   evidence.
 * - **When**: the record says who and what, not when. The audit trail
 *   (stage 1) says when the version was recorded; an RFC 3161 timestamp
 *   (commit 29j, timestamp.ts) over the record's SIGNATURE makes that
 *   independent of the deployment — `signContentHashStamped` returns the
 *   imprint the upload sends for it.
 */

import { toHex } from "../lib/encoding.ts";
import { statements, type Signer, type Trust } from "./identity.ts";
import { places } from "./places.ts";
import { stampImprint } from "./timestamp.ts";
import { openPlacedText, sealPlacedText, type VaultPrivateKey } from "./vault-crypto.ts";

/** What is sealed into `file.hash(area, file, version)`. */
export interface ContentHashRecord {
	v: 1;
	/** SHA-256 of the plaintext, lowercase hex. */
	sha256: string;
	/** The plaintext length in bytes (the server's readable size must agree). */
	size: number;
	/** The member who signed, and their identity key id at the time. */
	signer: string;
	keyId: string;
	/** ECDSA P-256 / SHA-256 over `statements.contentHash(…)`, base64. */
	signature: string;
}

/** What a reader learns. Only `verified` means "these are the signer's bytes". */
export type HashCheck =
	| { status: "verified"; signer: string; via: string; active: boolean }
	| { status: "unsigned" }
	| { status: "mismatch"; signer: string; claimed: { sha256: string; size: number }; actual: { sha256: string; size: number } }
	| { status: "untrusted"; signer: string; why: string }
	| { status: "invalid"; why: string };

/** SHA-256 of bytes in hand, lowercase hex. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
	return toHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes as BufferSource)));
}

/**
 * SHA-256 of bytes that arrive in pieces — a chunked download hands its
 * plaintext over frame by frame and never holds it whole. WebCrypto's
 * digest has no incremental form; hash-wasm (already the vault's Argon2)
 * does.
 */
export async function sha256Stream(): Promise<{ update(bytes: Uint8Array): void; hex(): string }> {
	const { createSHA256 } = await import("hash-wasm");
	const h = await createSHA256();
	h.init();
	return {
		update: (bytes) => void h.update(bytes),
		hex: () => h.digest("hex"),
	};
}

/** The uploader's half: sign the hash and seal the record into its place. */
export async function signContentHash(signer: Signer, store: VaultPrivateKey, area: string, file: string, version: number, sha256: string, size: number): Promise<string> {
	return (await signContentHashStamped(signer, store, area, file, version, sha256, size)).sealed;
}

/**
 * The same, with the imprint the Worker's TSA stamps (commit 29j): SHA-256
 * of the signature. Not of the content hash — a timestamp authority would
 * then hold the evidence's fingerprint — and not of the sealed record,
 * which nobody outside the case could tie to what it says. The signature
 * is random-looking to the TSA, and an export's reader can hash it and
 * verify it in the open.
 */
export async function signContentHashStamped(signer: Signer, store: VaultPrivateKey, area: string, file: string, version: number, sha256: string, size: number): Promise<{ sealed: string; stamp: string }> {
	const signature = await signer.sign(statements.contentHash(area, file, version, sha256, size));
	const record: ContentHashRecord = { v: 1, sha256, size, signer: signer.member, keyId: signer.keyId, signature };
	return { sealed: await sealPlacedText(store, places.fileHash(area, file, version), JSON.stringify(record)), stamp: await stampImprint(signature) };
}

const HEX64 = /^[0-9a-f]{64}$/;

function wellFormed(r: unknown): r is ContentHashRecord {
	const x = r as Partial<ContentHashRecord> | null;
	return !!x && x.v === 1 && typeof x.sha256 === "string" && HEX64.test(x.sha256) && Number.isSafeInteger(x.size) && (x.size as number) >= 0 && typeof x.signer === "string" && typeof x.keyId === "string" && HEX64.test(x.keyId) && typeof x.signature === "string";
}

/** Open a record in its place, without judging it (an export carries it;
 * checkContentHash says what it is worth). Null when absent or unopenable. */
export async function openContentHash(store: VaultPrivateKey, area: string, file: string, version: number, sealed: string | null | undefined): Promise<ContentHashRecord | null> {
	if (!sealed) return null;
	try {
		const r = JSON.parse(await openPlacedText(store, places.fileHash(area, file, version), sealed));
		return wellFormed(r) ? r : null;
	} catch {
		return null;
	}
}

/**
 * The reader's half: open the record in THIS version's place, check the
 * signature against the reader's own trust, then compare with what the
 * reader decrypted. The order matters for what is reported: a record
 * nobody trusted signed is `untrusted`/`invalid` whatever it claims; only a
 * record from a trusted signer can be a `mismatch` — "Bo vouched for other
 * bytes than these".
 */
export async function checkContentHash(store: VaultPrivateKey, trust: Trust | null, area: string, file: string, version: number, sealed: string | null | undefined, actual: { sha256: string; size: number }): Promise<HashCheck> {
	if (!sealed) return { status: "unsigned" };
	let record: unknown;
	try {
		record = JSON.parse(await openPlacedText(store, places.fileHash(area, file, version), sealed));
	} catch {
		return { status: "invalid", why: "the hash record does not open in this version's place — moved from another file or version, or not sealed by this store" };
	}
	if (!wellFormed(record)) return { status: "invalid", why: "the hash record is malformed" };
	if (!trust) return { status: "untrusted", signer: record.signer, why: "your team context is not open, so no identity can be checked yet" };
	const t = trust.of(record.signer);
	if (!t) return { status: "untrusted", signer: record.signer, why: `${record.signer} is not an identity you verified (compare fingerprints, or have a lead you verified certify them)` };
	if (t.keyId !== record.keyId) return { status: "untrusted", signer: record.signer, why: `signed with an identity key (${record.keyId.slice(0, 16)}…) that is not ${record.signer}'s current one — re-enrolled since?` };
	if (!(await t.verify(statements.contentHash(area, file, version, record.sha256, record.size), record.signature))) {
		return { status: "invalid", why: `the signature does not verify — ${record.signer} did not sign this record` };
	}
	if (record.sha256 !== actual.sha256 || record.size !== actual.size) {
		return { status: "mismatch", signer: record.signer, claimed: { sha256: record.sha256, size: record.size }, actual };
	}
	return { status: "verified", signer: record.signer, via: t.via, active: t.active };
}

/** One line for a person: what the check means. */
export function describeHashCheck(c: HashCheck): string {
	switch (c.status) {
		case "verified":
			return `content verified — exactly the bytes ${c.signer} signed${c.active ? "" : ` (${c.signer} has since left the team)`}`;
		case "unsigned":
			return "content not signed by its uploader";
		case "mismatch":
			return `⚠ content does NOT match what ${c.signer} signed (SHA-256 ${c.actual.sha256.slice(0, 16)}…, signed ${c.claimed.sha256.slice(0, 16)}…)`;
		case "untrusted":
			return `⚠ signed by ${c.signer}, not verified: ${c.why}`;
		case "invalid":
			return `⚠ content signature invalid: ${c.why}`;
	}
}
