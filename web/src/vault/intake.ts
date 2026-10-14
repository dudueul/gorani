// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Intake records — docs/CUSTODY.md › Stage 6 › 29g (D5.6).
 *
 * The content hash (stage 4) says WHAT the evidence is and WHO uploaded it.
 * The intake record says where it came from: which host or device, who
 * collected it, how (the tool, the method), and when — the half of
 * provenance a hash cannot carry. Required on an evidence file's first
 * version, like the hash; sealed (it names hosts and people) into
 * `file.intake(area, file)`, and signed by the uploader:
 *
 * ```text
 * stmt("gorani-intake-v1", area, file, source, collector, method, collectedAt, notes)
 * ```
 *
 * Per FILE, not per version: an item is acquired once; later versions are
 * the same item's processing (a re-export, a decrypted copy), recorded by
 * their own content hashes and the audit trail.
 */

import { statements, type Signer, type Trust } from "./identity.ts";
import { places } from "./places.ts";
import { openPlacedText, sealPlacedText, type VaultPrivateKey } from "./vault-crypto.ts";

/** What the person fills in. */
export interface IntakeFields {
	/** The host, device or account it came from ("laptop WS-042, disk 0"). */
	source: string;
	/** Who collected it — a person, not necessarily the uploader. */
	collector: string;
	/** How ("FTK Imager 4.7, E01, write-blocked"). */
	method: string;
	/** When it was collected, ISO 8601. */
	collectedAt: string;
	notes: string;
}

export interface IntakeRecord extends IntakeFields {
	v: 1;
	signer: string;
	keyId: string;
	signature: string;
}

export type IntakeCheck =
	| { status: "verified"; record: IntakeRecord; signer: string }
	| { status: "none" }
	| { status: "untrusted"; record: IntakeRecord; signer: string; why: string }
	| { status: "invalid"; why: string };

const clean = (f: IntakeFields): IntakeFields => ({
	source: f.source.trim(),
	collector: f.collector.trim(),
	method: f.method.trim(),
	collectedAt: f.collectedAt.trim(),
	notes: f.notes.trim(),
});

/** Seal and sign an intake record for `file` in `area`. Source, collector and method are required. */
export async function signIntake(signer: Signer, store: VaultPrivateKey, area: string, file: string, fields: IntakeFields): Promise<string> {
	const f = clean(fields);
	if (!f.source || !f.collector || !f.method) throw new Error("an intake record names its source, its collector and its method");
	if (Number.isNaN(Date.parse(f.collectedAt))) throw new Error("collected-at must be a date and time");
	const signature = await signer.sign(statements.intake(area, file, f.source, f.collector, f.method, f.collectedAt, f.notes));
	const record: IntakeRecord = { v: 1, ...f, signer: signer.member, keyId: signer.keyId, signature };
	return sealPlacedText(store, places.fileIntake(area, file), JSON.stringify(record));
}

/** Open a file's intake record in its place and check its signature against YOUR trust. */
export async function checkIntake(store: VaultPrivateKey, trust: Trust | null, area: string, file: string, sealed: string | null | undefined): Promise<IntakeCheck> {
	if (!sealed) return { status: "none" };
	let r: IntakeRecord;
	try {
		r = JSON.parse(await openPlacedText(store, places.fileIntake(area, file), sealed)) as IntakeRecord;
	} catch {
		return { status: "invalid", why: "the intake record does not open in this file's place — moved from another file, or not sealed by this store" };
	}
	if (r?.v !== 1 || typeof r.signer !== "string" || typeof r.signature !== "string") return { status: "invalid", why: "the intake record is malformed" };
	const t = trust?.of(r.signer) ?? null;
	if (!t) return { status: "untrusted", record: r, signer: r.signer, why: `${r.signer} is not an identity you verified` };
	if (t.keyId !== r.keyId) return { status: "untrusted", record: r, signer: r.signer, why: `signed with an identity key that is not ${r.signer}'s current one — re-enrolled since?` };
	if (!(await t.verify(statements.intake(area, file, r.source, r.collector, r.method, r.collectedAt, r.notes), r.signature))) return { status: "invalid", why: `the signature does not verify — ${r.signer} did not sign this record` };
	return { status: "verified", record: r, signer: r.signer };
}
