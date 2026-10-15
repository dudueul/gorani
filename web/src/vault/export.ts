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
 * Collected evidence (commit 37d, docs/COLLECTORS.md): a file accepted from
 * a case inbox carries its collection record — the collector's signed
 * fields and their timestamp — checked here against version 1's bytes; the
 * package lists the collector's registration (its key, both leads'
 * signatures), so a recipient checks the machine's word with no registry.
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
import { openChunked, openChunkedStream } from "./chunked-file.ts";
import { checkContentHash, openContentHash, sha256Hex, sha256Stream, type ContentHashRecord, type HashCheck } from "./content-hash.ts";
import { checkIntake, type IntakeRecord } from "./intake.ts";
import { checkCollection, type CollectionRecord } from "./inbox.ts";
import type { CollectorRow } from "./collectors.ts";
import { verifyChain, type CustodyChain } from "./custody.ts";
import { isSampleType, SAMPLE_PASSWORD } from "./samples.ts";
import { ZipStream, type ZipSink } from "./zip.ts";
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
	/** (D12, 31d) The same as a stream — `size` is the sealed length; absent → `object` is used. */
	objectStream?(path: string): Promise<{ body: ReadableStream<Uint8Array>; size: number; ck: string; chunk: number | null; version: number; hash: string | null }>;
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
	/** (commit 37d) Collected by a machine: its record (null when it did not open), and the exporter's check. */
	/** `declared` (commit 38): an upload link's record — consistent, but nobody signed it. */
	collection: { record: CollectionRecord | null; check: "verified" | "declared" | "unverified"; why: string } | null;
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
/**
 * A version's plaintext, pushed through `write` as it decrypts (D12, 31d):
 * each version streams ONCE — into the export's zip, or nowhere (a
 * re-verification) — and is hashed on the way.
 */
type Pump = (write: (plain: Uint8Array) => Promise<void>) => Promise<void>;

async function walk(source: ExportSource, store: VaultPrivateKey, trust: Trust, caseId: string, tsas: TrustedTsas, onVersion: (file: FileRow & { name: string }, at: { version: number; path: string; packed: VersionReport["packed"]; sizeHint: number }, pump: Pump) => Promise<void> | void): Promise<FileReport[]> {
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
	let collectors: CollectorRow[] | null = null;
	for (const row of rows) {
		const name = await openPlacedText(store, places.fileName(area, row.id), row.name).catch(() => row.id);
		const keys = (await source.post<{ keys: Record<string, { intake?: string | null; sample?: boolean; collection?: string | null }> }>(`${base}/files/keys`, { ids: [row.id] })).keys[row.id];
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
				// Streamed where the source can (the browser, the tests' fetch): a
				// 255 GB image is decrypted frame by frame, never held (D12).
				const objectPath = `${base}/files/${row.id}?version=${n}`;
				const streamed = source.objectStream ? await source.objectStream(objectPath) : null;
				const whole = streamed ? null : await source.object(objectPath);
				const obj = (streamed ?? whole)!;
				if (obj.version !== n) throw new Error(`asked for version ${n} of ${name}, the server answered with ${obj.version}`);
				const key = await unwrapPlacedKey(store, places.fileKey(area, row.id, obj.version), obj.ck);
				const h = await sha256Stream();
				let plainSize = 0;
				let pumped = false;
				const pump: Pump = async (write) => {
					if (pumped) throw new Error("a version streams once");
					pumped = true;
					const feed = async (p: Uint8Array) => {
						h.update(p);
						plainSize += p.length;
						await write(p);
					};
					if (streamed && obj.chunk) await openChunkedStream(key, streamed.body, obj.chunk, streamed.size, feed);
					else {
						const bytes = streamed ? new Uint8Array(await new Response(streamed.body).arrayBuffer()) : whole!.body;
						await feed(obj.chunk ? await openChunked(key, bytes, obj.chunk) : await openWith(key, bytes));
					}
				};
				const safe = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_") || row.id;
				const hashRecord = await openContentHash(store, area, row.id, obj.version, obj.hash);
				const s = stamps.get(obj.version);
				const stampCheck = await checkVersionStamp(hashRecord, s, tsas);
				const path = `evidence/${row.id}/v${obj.version}/${safe}${sample ? ".zip" : ""}`;
				const packed: VersionReport["packed"] = sample ? "zip-infected" : "plain";
				await onVersion({ ...row, name }, { version: obj.version, path, packed, sizeHint: streamed ? streamed.size : whole!.body.length }, pump);
				if (!pumped) await pump(async () => {});
				const sha256 = h.hex();
				const check = await checkContentHash(store, trust, area, row.id, obj.version, obj.hash, { sha256, size: plainSize });
				const v: VersionReport = {
					version: obj.version,
					size: plainSize,
					sha256,
					path,
					packed,
					hashRecord,
					hashCheck: check.status,
					stamp: s?.token && s.imprint ? { imprint: s.imprint, token: s.token, at: s.at } : null,
					stampCheck: stampCheck.status,
					stampNote: s?.status === "no-imprint" ? "no-imprint" : stampCheck.status === "invalid" || stampCheck.status === "absent" ? stampCheck.why : "",
				};
				versions.push(v);
			}
			if (page.next === null) break;
			after = page.next;
		}
		// The collector's record answers for version 1 — the bytes it dropped.
		let collection: FileReport["collection"] = null;
		if (keys?.collection) {
			const v1 = versions.find((v) => v.version === 1);
			collectors ??= await source.get<{ collectors: CollectorRow[] }>("/api/v1/family/collectors").then((r) => r.collectors, () => []);
			try {
				const c = await checkCollection(store, caseId, row.id, keys.collection, trust, collectors, v1 ? { sha256: v1.sha256, size: v1.size } : undefined);
				const why = c.problem ?? (v1 ? "" : "the file has no version 1");
				collection = { record: c.record, check: why ? "unverified" : c.record.kind === "request" ? "declared" : "verified", why };
			} catch (e) {
				collection = { record: null, check: "unverified", why: `the record does not open in its place (${e instanceof Error ? e.message : String(e)})` };
			}
		}
		out.push({ id: row.id, name, sample, intake: intake.status === "verified" || intake.status === "untrusted" ? intake.record : null, intakeCheck: intake.status, custody, versions, collection });
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
	const files = await walk(source, store, trust, caseId, trusted, () => {});
	for (const f of files) {
		for (const v of f.versions) {
			checked++;
			if (v.hashCheck !== "verified") problems.push(`${f.name} v${v.version}: ${v.hashCheck}`);
			const sp = stampProblem(v);
			if (sp) problems.push(`${f.name} v${v.version}: ${sp}`);
			if (v.stampNote === "no-imprint" && v.hashCheck === "verified" && v.hashRecord) missing.push({ file: f.id, version: v.version, signature: v.hashRecord.signature });
		}
		if (f.collection?.check === "unverified") problems.push(`${f.name}: collection ${f.collection.why}`);
	}
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
	/** The package, when no sink was given (tests, small cases); empty when it streamed. */
	parts: Uint8Array[];
	manifest: Record<string, unknown>;
	digest: string;
	problems: string[];
}

/**
 * Build the signed package for an approved, unconsumed `case.export`.
 *
 * Streamed (D12, 31d): with a `sink`, the zip goes out as it is made — each
 * version decrypted once, straight into its entry (a sample into its own
 * "infected" zip inside), hashed on the way — and the manifest, which
 * needs every hash, is written LAST (a zip's order is its central
 * directory's, not its bytes'). Without one, the parts are collected and
 * returned. `forceZip64` writes every ZIP64 field (how a test proves them).
 */
export async function buildExport(source: ExportSource, signer: Signer, trust: Trust, store: VaultPrivateKey, caseId: string, approvalId: string, { sink, forceZip64 = false }: { sink?: ZipSink; forceZip64?: boolean } = {}): Promise<ExportResult> {
	const started = await source.post<{ exportId: string; exporter: string; approval: Approval }>(`/api/v1/cases/${caseId}/export`, { approval: approvalId });
	const collected: Uint8Array[] = [];
	const zip = new ZipStream(sink ?? (async (b) => void collected.push(b)), { forceZip64 });
	const problems: string[] = [];
	const tsa = await tsasOf(source, trust);
	const files = await walk(source, store, trust, caseId, tsa.trusted, async (f, at, pump) => {
		if (at.packed === "zip-infected") {
			// A sample leaves only zipped under "infected" — a zip inside the package's entry.
			await zip.add(at.path, async (writeOuter) => {
				const inner = new ZipStream(writeOuter, { forceZip64 });
				await inner.add(f.name.replace(/[\\/]/g, "_") || "sample", pump, { password: SAMPLE_PASSWORD, size: at.sizeHint });
				await inner.finish();
			}, { size: at.sizeHint + 512 + 2 * f.name.length });
		} else {
			await zip.add(at.path, pump, { size: at.sizeHint });
		}
	});
	for (const f of files) {
		for (const v of f.versions) {
			if (v.hashCheck !== "verified") problems.push(`${f.name} v${v.version}: content ${v.hashCheck}`);
			const sp = stampProblem(v);
			if (sp) problems.push(`${f.name} v${v.version}: ${sp}`);
		}
	}
	for (const f of files) {
		if (f.intakeCheck !== "verified" && f.intakeCheck !== "none") problems.push(`${f.name}: intake ${f.intakeCheck}`);
		if (f.custody && !f.custody.ok) problems.push(`${f.name}: custody chain does not verify`);
		if (f.collection?.check === "unverified") problems.push(`${f.name}: collection ${f.collection.why}`);
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
	// The collectors the files name, with their registrations (and the two
	// leads who signed each among the identities).
	const collectorIds = new Set(files.flatMap((f) => (f.collection?.record ? [f.collection.record.collector] : [])));
	const collectorRows = collectorIds.size ? (await source.get<{ collectors: CollectorRow[] }>("/api/v1/family/collectors")).collectors.filter((c) => collectorIds.has(c.id)) : [];
	const collectors = collectorRows.map((c) => ({ id: c.id, name: c.name, commonName: c.commonName, status: c.status, keyId: c.keyId, publicKey: c.publicKey, requestedBy: c.requestedBy, requestSignature: c.requestSignature, approvedBy: c.approvedBy, approveSignature: c.approveSignature, revokedAt: c.revokedAt }));
	for (const c of collectors) named.add(c.requestedBy).add(c.approvedBy ?? "");
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
		// (commit 37d) Each collector's registration: tools/verify-export.mjs checks both leads' signatures.
		collectors,
		identities,
	};
	const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest, null, 2));
	const digest = await sha256Hex(manifestBytes);
	const signature = await signer.sign(statements.exportManifest(caseId, started.exportId, digest));
	const sig = { statement: "gorani-export-v1 ‖ case ‖ export id ‖ SHA-256(manifest.json), each length-prefixed (u32 big-endian)", case: caseId, exportId: started.exportId, exporter: signer.member, keyId: signer.keyId, digest, signature, algorithm: "ECDSA P-256 / SHA-256, IEEE P1363 (r ‖ s), base64" };
	await zip.addBytes("manifest.json", manifestBytes);
	await zip.addBytes("manifest.sig.json", new TextEncoder().encode(JSON.stringify(sig, null, 2)));
	await zip.addBytes("VERIFY.txt", new TextEncoder().encode(verifyText(caseId, started.exportId, signer, digest)));
	await zip.finish();
	return { parts: collected, manifest, digest, problems };
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
