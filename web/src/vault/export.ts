// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The signed export package, and re-verification — docs/CUSTODY.md ›
 * Stage 7 › 29h (D5.8).
 *
 * An export is the moment evidence leaves the vault for someone outside
 * it — counsel, an insurer, a court. So the package is built for a reader
 * who has NONE of gorani's keys and none of its code:
 *
 * ```text
 * package.zip
 *   manifest.json       the case, the two-person approval, every file and version
 *                       (name, size, SHA-256 of the plaintext, the uploader's signed
 *                       hash record, the intake record, the custody chain), the whole
 *                       audit trail, and every signer's public identity
 *   manifest.sig.json   the exporter's signature over
 *                       stmt("gorani-export-v1", case, export id, SHA-256(manifest.json))
 *   VERIFY.txt          how to check all of it (tools/verify-export.mjs, or by hand)
 *   evidence/<file>/v<n>/<name>       the plaintext — a sample as <name>.zip under "infected"
 * ```
 *
 * Every check is made HERE before anything is written (this browser holds
 * the key): each version decrypts, re-hashes and is compared with its
 * signed record; each intake record and custody chain is verified. What
 * fails is not hidden — it is recorded in the manifest beside the item, so
 * the package says what it is. The export runs only on an approved,
 * unconsumed `case.export` (the two-person rule), which the server spends.
 *
 * Re-verification walks the same files the same way and reports counts
 * only: what was checked, what failed.
 *
 * Trusted timestamps (commit 29j, timestamp.ts) travel with each version
 * and each audit checkpoint: the token as the TSA issued it, its imprint,
 * and — in `tsa.certs` — the leads' certifications of the TSA keys, whose
 * signers are among `identities`. Re-verification also asks for a stamp
 * on any signed version recorded before stamps existed.
 */

import { statements, type RegistryIdentity, type Signer, type Trust } from "./identity.ts";
import { places } from "./places.ts";
import { openPlacedText, openWith, unwrapPlacedKey, type VaultPrivateKey } from "./vault-crypto.ts";
import { openChunked } from "./chunked-file.ts";
import { checkContentHash, openContentHash, sha256Hex, type ContentHashRecord, type HashCheck } from "./content-hash.ts";
import { checkIntake, type IntakeRecord } from "./intake.ts";
import { verifyChain, type CustodyChain } from "./custody.ts";
import { isSampleType, zipEncrypted } from "./samples.ts";
import { zipEntries, type ZipEntry } from "./zip.ts";
import type { Approval } from "./approvals.ts";
import { checkCheckpointStamp, checkVersionStamp, stampImprint, trustedTsas, type StampCheck, type TrustedTsas, type TsaCert, type VersionStamp } from "./timestamp.ts";

/** How this module reaches the API: the browser's fetches, or a test's. */
export interface ExportSource {
	get<T>(path: string): Promise<T>;
	post<T>(path: string, body: unknown): Promise<T>;
	/** (commit 29j) Re-verification's request for a missing stamp; absent → not asked. */
	put?<T>(path: string, body: unknown): Promise<T>;
	/** A version's sealed bytes and the headers that open it (`GET …/files/<id>?version=n`). */
	object(path: string): Promise<{ body: Uint8Array; ck: string; chunk: number | null; version: number; hash: string | null }>;
}

export interface VersionReport {
	version: number;
	size: number;
	sha256: string;
	path: string;
	/** "zip-infected" when the entry is a sample's zip (unzip it with "infected" to hash). */
	packed: "plain" | "zip-infected";
	hashRecord: ContentHashRecord | null;
	hashCheck: HashCheck["status"];
	/** Its RFC 3161 token and imprint (the TSA's, untouched), and what the exporter's check said. */
	stamp: { imprint: string; token: string; at: string | null } | null;
	stampCheck: StampCheck["status"];
	stampNote: string;
}

export interface FileReport {
	id: string;
	name: string;
	sample: boolean;
	intake: IntakeRecord | null;
	intakeCheck: string;
	custody: { owner: string; custodian: string; ok: boolean; links: { seq: number; from: string; to: string; reason: string | null; offeredAt: string; offerSignature: string; acceptedAt: string | null; acceptSignature: string | null; ok: boolean; why: string }[] } | null;
	versions: VersionReport[];
}

interface FileRow {
	id: string;
	name: string;
	sample?: boolean;
}

/**
 * Walk every live file and every version of a case: decrypt, re-hash, and
 * check each signed record. `onVersion` receives the plaintext (the export
 * stores it; re-verification drops it).
 */
async function walk(source: ExportSource, store: VaultPrivateKey, trust: Trust, caseId: string, tsas: TrustedTsas, onVersion: (file: FileRow & { name: string }, v: VersionReport, plain: Uint8Array) => Promise<void> | void): Promise<FileReport[]> {
	const base = `/api/v1/cases/${caseId}`;
	const area = `case:${caseId}`;
	const rows: FileRow[] = [];
	for (let offset = 0; ; ) {
		const page = await source.get<{ total: number; files: FileRow[] }>(`${base}/files/list?folder=all&limit=1000&offset=${offset}`);
		rows.push(...page.files);
		offset += page.files.length;
		if (!page.files.length || offset >= page.total) break;
	}
	const out: FileReport[] = [];
	for (const row of rows) {
		const name = await openPlacedText(store, places.fileName(area, row.id), row.name).catch(() => row.id);
		const keys = (await source.post<{ keys: Record<string, { intake?: string | null; sample?: boolean }> }>(`${base}/files/keys`, { ids: [row.id] })).keys[row.id];
		const intake = await checkIntake(store, trust, area, row.id, keys?.intake ?? null);
		let custody: FileReport["custody"] = null;
		try {
			const chain = await source.get<CustodyChain>(`${base}/files/${row.id}/custody`);
			const v = await verifyChain(store, trust, area, row.id, chain);
			const bySeq = new Map(chain.entries.map((e) => [e.seq, e]));
			custody = { owner: chain.owner, custodian: v.custodian, ok: v.ok, links: v.links.map((l) => ({ ...l, ...pick(bySeq.get(l.seq)!) })) };
		} catch {
			custody = null; // (not an evidence case: no custody kept)
		}
		const versions: VersionReport[] = [];
		let sample = row.sample === true || keys?.sample === true;
		const stamps = new Map((await source.get<{ versions: VersionStamp[] }>(`${base}/files/${row.id}/stamps`).catch(() => ({ versions: [] }))).versions.map((s) => [s.version, s]));
		for (let after = 0; ; ) {
			const page = await source.get<{ items: { row: number; b: string; v2: string | null }[]; next: number | null }>(`${base}/files/sealed?kind=version&file=${encodeURIComponent(row.id)}&after=${after}&limit=500`);
			for (const it of page.items) {
				const n = Number(it.b);
				if (it.v2) {
					const t = await openPlacedText(store, places.fileType(area, row.id, n), it.v2).catch(() => null);
					if (t === null || isSampleType(t)) sample = true; // the careful side, as the viewer
				}
				const obj = await source.object(`${base}/files/${row.id}?version=${n}`);
				const key = await unwrapPlacedKey(store, places.fileKey(area, row.id, obj.version), obj.ck);
				const plain = obj.chunk ? await openChunked(key, obj.body, obj.chunk) : await openWith(key, obj.body);
				const sha256 = await sha256Hex(plain);
				const check = await checkContentHash(store, trust, area, row.id, obj.version, obj.hash, { sha256, size: plain.length });
				const safe = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_") || row.id;
				const hashRecord = await openContentHash(store, area, row.id, obj.version, obj.hash);
				const s = stamps.get(obj.version);
				const stampCheck = await checkVersionStamp(hashRecord, s, tsas);
				const v: VersionReport = {
					version: obj.version,
					size: plain.length,
					sha256,
					path: `evidence/${row.id}/v${obj.version}/${safe}${sample ? ".zip" : ""}`,
					packed: sample ? "zip-infected" : "plain",
					hashRecord,
					hashCheck: check.status,
					stamp: s?.token && s.imprint ? { imprint: s.imprint, token: s.token, at: s.at } : null,
					stampCheck: stampCheck.status,
					stampNote: s?.status === "no-imprint" ? "no-imprint" : stampCheck.status === "invalid" || stampCheck.status === "absent" ? stampCheck.why : "",
				};
				versions.push(v);
				await onVersion({ ...row, name }, v, plain);
			}
			if (page.next === null) break;
			after = page.next;
		}
		out.push({ id: row.id, name, sample, intake: intake.status === "verified" || intake.status === "untrusted" ? intake.record : null, intakeCheck: intake.status, custody, versions });
	}
	return out;
}

const pick = (e: { offeredAt: string; offerSignature: string; acceptedAt: string | null; acceptSignature: string | null }) => ({ offeredAt: e.offeredAt, offerSignature: e.offerSignature, acceptedAt: e.acceptedAt, acceptSignature: e.acceptSignature });

/** The TSA keys this reader counts (commit 29j): the leads' certifications, under the reader's own trust. */
async function tsasOf(source: ExportSource, trust: Trust): Promise<{ certs: TsaCert[]; trusted: TrustedTsas }> {
	const { certs } = await source.get<{ certs: TsaCert[] }>("/api/v1/family/tsa").catch(() => ({ certs: [] as TsaCert[] }));
	return { certs, trusted: await trustedTsas(trust, certs) };
}

/** A stamp the exporter or re-verifier should not pass over in silence. */
const stampProblem = (v: VersionReport) => (v.stampCheck === "invalid" || v.stampCheck === "uncertified" ? `timestamp ${v.stampCheck}${v.stampNote ? ` (${v.stampNote})` : ""}` : null);

/**
 * Re-hash every version against its signed record; record the counts in
 * the case's audit. A signed version without a timestamp imprint (recorded
 * before commit 29j) gets one asked for now: a later stamp still dates the
 * signature — later than the upload, earlier than any dispute.
 */
export async function reverifyCase(source: ExportSource, store: VaultPrivateKey, trust: Trust, caseId: string): Promise<{ checked: number; failed: number; problems: string[]; stampsRequested: number }> {
	let checked = 0;
	let stampsRequested = 0;
	const problems: string[] = [];
	const { trusted } = await tsasOf(source, trust);
	const missing: { file: string; version: number; signature: string }[] = [];
	await walk(source, store, trust, caseId, trusted, (f, v) => {
		checked++;
		if (v.hashCheck !== "verified") problems.push(`${f.name} v${v.version}: ${v.hashCheck}`);
		const sp = stampProblem(v);
		if (sp) problems.push(`${f.name} v${v.version}: ${sp}`);
		if (v.stampNote === "no-imprint" && v.hashCheck === "verified" && v.hashRecord) missing.push({ file: f.id, version: v.version, signature: v.hashRecord.signature });
	});
	for (const m of missing) {
		if (!source.put) break;
		try {
			await source.put(`/api/v1/cases/${caseId}/files/${m.file}/stamps`, { version: m.version, imprint: await stampImprint(m.signature) });
			stampsRequested++;
		} catch {
			// (a read-only grant cannot ask; the next re-verifier with write access will)
		}
	}
	await source.post(`/api/v1/cases/${caseId}/reverify`, { checked, failed: problems.length });
	return { checked, failed: problems.length, problems, stampsRequested };
}

export interface ExportResult {
	parts: Uint8Array[];
	manifest: Record<string, unknown>;
	digest: string;
	problems: string[];
}

/** Build the signed package for an approved, unconsumed `case.export`. */
export async function buildExport(source: ExportSource, signer: Signer, trust: Trust, store: VaultPrivateKey, caseId: string, approvalId: string): Promise<ExportResult> {
	const started = await source.post<{ exportId: string; exporter: string; approval: Approval }>(`/api/v1/cases/${caseId}/export`, { approval: approvalId });
	const entries: ZipEntry[] = [];
	const problems: string[] = [];
	const tsa = await tsasOf(source, trust);
	const files = await walk(source, store, trust, caseId, tsa.trusted, (f, v, plain) => {
		entries.push({ name: v.path, data: v.packed === "zip-infected" ? concat(zipEncrypted(f.name, plain)) : plain });
		if (v.hashCheck !== "verified") problems.push(`${f.name} v${v.version}: content ${v.hashCheck}`);
		const sp = stampProblem(v);
		if (sp) problems.push(`${f.name} v${v.version}: ${sp}`);
	});
	for (const f of files) {
		if (f.intakeCheck !== "verified" && f.intakeCheck !== "none") problems.push(`${f.name}: intake ${f.intakeCheck}`);
		if (f.custody && !f.custody.ok) problems.push(`${f.name}: custody chain does not verify`);
	}
	// The whole audit trail, oldest first, with its base and the server's verification of it.
	const base = `/api/v1/cases/${caseId}`;
	const lines: unknown[] = [];
	let auditBase: unknown = null;
	for (let after = 0; ; ) {
		const page = await source.get<{ base: unknown; lines: { id: number }[]; next: number | null }>(`${base}/audit/lines?after=${after}&limit=1000`);
		auditBase ??= page.base;
		lines.push(...page.lines);
		if (page.next === null) break;
		after = page.next;
	}
	const auditVerify = await source.get<{ checkpoints?: { date: string; body?: string; token?: string | null }[] }>(`${base}/audit/verify`);
	// Each checkpoint's timestamp, checked like a version's.
	for (const cp of auditVerify.checkpoints ?? []) {
		if (!cp.body || !cp.token) continue;
		const c = await checkCheckpointStamp(cp.body, cp.token, tsa.trusted);
		if (c.status === "invalid" || c.status === "uncertified") problems.push(`audit checkpoint ${cp.date}: timestamp ${c.status}${c.status === "invalid" ? ` (${c.why})` : ""}`);
	}
	// Every identity the package names — the public halves a recipient checks signatures with.
	const named = new Set<string>([signer.member, started.approval.requestedBy, started.approval.approvedBy ?? ""]);
	for (const f of files) {
		if (f.intake) named.add(f.intake.signer);
		for (const v of f.versions) if (v.hashRecord) named.add(v.hashRecord.signer);
		for (const l of f.custody?.links ?? []) named.add(l.from).add(l.to);
		if (f.custody) named.add(f.custody.owner);
	}
	for (const c of tsa.certs) named.add(c.by);
	const registry = (await source.get<{ identities: RegistryIdentity[] }>("/api/v1/family/identities")).identities;
	const identities = registry.filter((e) => named.has(e.member)).map((e) => ({ member: e.member, keyId: e.keyId, publicKey: e.publicKey, rootDigest: e.rootDigest, signature: e.signature, active: e.active !== false, certs: e.certs }));
	const manifest = {
		format: "gorani-export-v1",
		case: caseId,
		exportId: started.exportId,
		exporter: signer.member,
		exporterKeyId: signer.keyId,
		builtAt: new Date().toISOString(),
		approval: started.approval,
		problems,
		files,
		audit: { base: auditBase, lines, verify: auditVerify },
		// The leads' word on which TSA keys count (timestamp.ts › trustedTsas).
		tsa: { certs: tsa.certs },
		identities,
	};
	const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest, null, 2));
	const digest = await sha256Hex(manifestBytes);
	const signature = await signer.sign(statements.exportManifest(caseId, started.exportId, digest));
	const sig = { statement: "gorani-export-v1 ‖ case ‖ export id ‖ SHA-256(manifest.json), each length-prefixed (u32 big-endian)", case: caseId, exportId: started.exportId, exporter: signer.member, keyId: signer.keyId, digest, signature, algorithm: "ECDSA P-256 / SHA-256, IEEE P1363 (r ‖ s), base64" };
	const pkg: ZipEntry[] = [
		{ name: "manifest.json", data: manifestBytes },
		{ name: "manifest.sig.json", data: new TextEncoder().encode(JSON.stringify(sig, null, 2)) },
		{ name: "VERIFY.txt", data: new TextEncoder().encode(verifyText(caseId, started.exportId, signer, digest)) },
		...entries,
	];
	return { parts: zipEntries(pkg), manifest, digest, problems };
}

function verifyText(caseId: string, exportId: string, signer: Signer, digest: string): string {
	const fp = signer.keyId.slice(0, 32).toUpperCase().match(/.{4}/g)!.join(" ");
	return [
		`gorani export of case ${caseId} — export ${exportId}`,
		"",
		`Exported and signed by ${signer.member}, identity key fingerprint:`,
		`    ${fp}`,
		"Compare this fingerprint with the exporter in person or on a call before relying on the package.",
		"",
		`SHA-256 of manifest.json: ${digest}`,
		"",
		"To check everything (Node 20+, nothing else, no network):",
		"    node verify-export.mjs package.zip",
		"(tools/verify-export.mjs in the gorani repository.)",
		"",
		"By hand: every evidence/… entry's SHA-256 is in manifest.json › files › versions › sha256.",
		"Samples (packed: zip-infected) are zips under the password \"infected\": unzip, then hash.",
		"Each version's hashRecord is its uploader's signature; each intake record and custody link",
		"is signed too; the approval carries two leads' signatures. The public keys are in identities.",
		"A version's stamp is an RFC 3161 token over SHA-256 of its hashRecord's signature; a",
		"checkpoint's, over the checkpoint's bytes (audit › verify › checkpoints). `openssl ts",
		"-verify` checks one by hand; tsa › certs says which TSA keys the team's leads certified.",
		"",
	].join("\n");
}

function concat(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}
