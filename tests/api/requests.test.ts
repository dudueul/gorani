// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * api:requests — upload links (commit 38, docs/REQUESTS.md): someone with
 * no account sends files into a member's folder or into a case, sealed in
 * their browser to the area's INBOX key; a person accepts each. The sender
 * here is vault/request-upload.ts — the code the upload page runs — and
 * the owner is the web app's own vault code. What it proves:
 *
 *   1. a member's own area gets an inbox key: made in their browser, its
 *      private half sealed under THEIR files key (place store.inbox); a
 *      private half paired with public halves of the server's choosing does
 *      not open; nobody else reads another member's inbox keys;
 *   2. a link is made with a password and limits the server enforces (no
 *      longer than 30 days, a password, a sealed note the server cannot
 *      read, a label sealed with the store key); an id cannot be taken twice;
 *   3. the sender's page opens the note, and REFUSES a key that does not
 *      hash to the digest in the link's fragment — the substitution a server
 *      would try; a wrong secret finds no link;
 *   4. a wrong password is refused and counted; ten lock the link (423),
 *      and the owner sees it; revoking closes it (404);
 *   5. a small file goes up whole and a large one as GC01 frames; the files
 *      and bytes left are enforced (413, 409), the last slot taken once;
 *   6. what arrives opens ONLY with the inbox key: a record about THIS item
 *      from THIS link — one moved from another item or link is named;
 *   7. accepting files it as a malware SAMPLE by default (sealed type, the
 *      store's flag), into the link's folder, with the accepter's signed
 *      content hash and intake and the sender's record beside it; a person
 *      may accept as a normal file instead; rejecting seals the reason;
 *   8. a link into a case is a manager's act, sealed to the case's inbox
 *      key — the registry's, checked; the case's members accept; an export
 *      carries the sender's record, and tools/verify-export.mjs checks it
 *      for what it is — consistent, and unsigned;
 *  8b. the CLI (gorani-sync) reads a member's own inbox, decrypts and hashes
 *      an item here, runs a scanner on the decrypted bytes — WITHOUT a shell
 *      — and files nothing when it objects; files a link's item as a sample
 *      by default; refuses --as-file for a hash MalwareBazaar knows; and
 *      what it signs, the browser's code verifies;
 *   9. a store-key rotation re-seals the inbox key and the links' labels;
 *  10. the opt-in hash lookup sends MalwareBazaar the SHA-256 and the
 *      Auth-Key — nothing else — and the registry's audit records the
 *      lookup without the hash;
 *  11. the upload page is served under the share page's CSP; a link's
 *      routes are rate limited — except a large file's frames, one request
 *      per 8 MiB, which a limit of 60 a minute would stop halfway.
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startDev, api } from "./_dev.mjs";
import { startMalwareBazaarStub } from "../lib/malwarebazaar-stub.mjs";
import { member, vouch, openCase, trustOf } from "../lib/team.mjs";
import { acceptItem, areaInboxKeys, checkItemCollection, createAreaInboxKey, createInboxKey, currentInboxKey, hashInboxContent, openAreaInboxKeys, openItem, openItemRejectReason, rejectItem, type InboxItem, type InboxKeyRow } from "../../web/src/vault/inbox.ts";
import { createRequestLink, digestForLink, listRequests, openRequestLabel, revokeRequest, type RequestRow } from "../../web/src/vault/requests.ts";
import { LinkError, openLink, sendFile, sendToken } from "../../web/src/vault/request-upload.ts";
import { requestKeys, sealRequestNote, tokenHash, newRequestId } from "../../web/src/vault/request-crypto.ts";
import { checkContentHash, sha256Hex } from "../../web/src/vault/content-hash.ts";
import { checkIntake } from "../../web/src/vault/intake.ts";
import { places } from "../../web/src/vault/places.ts";
import { isSampleType, originalType } from "../../web/src/vault/samples.ts";
import { createStoreKey } from "../../web/src/vault/keys.ts";
import { hybridDigest } from "../../web/src/vault/identity.ts";
import { importVaultKey, openPlacedText, sealPlacedText } from "../../web/src/vault/vault-crypto.ts";
import { resealStore } from "../../web/src/vault/rotation.ts";
import { deriveRecordKey, macRecord } from "../../web/src/vault/records.ts";
import type { CaseRow } from "../../web/src/vault/cases.ts";
import { approveRequest, requestApproval } from "../../web/src/vault/approvals.ts";
import { buildExport } from "../../web/src/vault/export.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BIN = path.join(ROOT, "target/debug/gorani-sync");

/** Run the CLI (spawn, not spawnSync: this process runs the S3 stub). */
function sync(args: string[], profile: string, home: string): Promise<{ status: number; out: string }> {
	const c = spawn(BIN, [...args, "--profile", profile], { cwd: ROOT, env: { ...process.env, HOME: home } });
	let out = "";
	c.stdout.on("data", (d) => (out += d));
	c.stderr.on("data", (d) => (out += d));
	return new Promise((resolve) => {
		const t = setTimeout(() => c.kill("SIGKILL"), 240_000);
		c.on("exit", (code) => {
			clearTimeout(t);
			resolve({ status: code ?? 1, out });
		});
	});
}

const MB_KEY = "suite-auth-key";
const known = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA-256 of nothing — "known" to the stub
const mb = await startMalwareBazaarStub({ key: MB_KEY, known: { [known]: { fileType: "exe", signature: "SuiteRAT", tags: ["rat", "suite"] } } });
const dev = await startDev({ vars: { MALWAREBAZAAR_URL: mb.url, MALWAREBAZAAR_AUTH_KEY: MB_KEY } });
const enc = new TextEncoder();

const call = (who: { email: string }) => async <T>(method: string, p: string, body?: unknown): Promise<T> => {
	const r = await api(dev.base, method, p, { email: who.email, body });
	if (r.status >= 300) throw new Error(`${method} ${p}: ${r.status} ${r.text.slice(0, 300)}`);
	return r.json as T;
};

/** The export's view of the API, as `who`'s browser has it (export.ts › ExportSource). */
const sourceAs = (who: { email: string }) => ({
	get: <T>(p: string) => call(who)<T>("GET", p),
	post: <T>(p: string, body: unknown) => call(who)<T>("POST", p, body),
	async object(p: string) {
		const r = await fetch(`${dev.base}${p}`, { headers: { "x-gorani-dev-email": who.email } });
		if (!r.ok) throw new Error(`${r.status} ${p}`);
		return { body: new Uint8Array(await r.arrayBuffer()), ck: r.headers.get("x-gorani-ck") ?? "", chunk: Number(r.headers.get("x-gorani-chunk")) || null, version: Number(r.headers.get("x-gorani-version")), hash: r.headers.get("x-gorani-hash") };
	},
});

/** A file as the sender's browser has one (Node's File is a Blob with a name). */
const fileOf = (name: string, bytes: Uint8Array, type = "application/octet-stream") => new File([bytes as BlobPart], name, { type });

/** Deterministic-looking bytes of `n`: a fast fill, not crypto-random (the content key makes them unreadable anyway). */
function bytesOf(n: number, seed: number): Uint8Array {
	const b = new Uint8Array(n);
	let x = seed >>> 0 || 1;
	for (let i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >>> 17;
		x ^= x << 5;
		b[i] = x & 0xff;
	}
	return b;
}

const rejects = async (p: Promise<unknown>, status: number, what: string) => {
	try {
		await p;
	} catch (e) {
		assert.ok(e instanceof LinkError, `${what}: a LinkError, got ${e}`);
		assert.equal(e.status, status, `${what}: ${e.message}`);
		return e;
	}
	assert.fail(`${what}: accepted`);
};

try {
	// ── 0. The team: two leads (an export takes both), an analyst ──
	const ana = await member(dev, "ana", "lead");
	const bo = await member(dev, "bo", "analyst", { by: ana });
	const cy = await member(dev, "cy", "lead", { by: ana });
	await vouch(dev, ana, [bo, cy]);
	const boTrust = await trustOf(dev, bo);

	// ── 1. Bo's own inbox key ──
	assert.deepEqual(await areaInboxKeys(call(bo), "bo"), [], "no inbox key until the owner makes one");
	const { inboxKeys: made } = await createAreaInboxKey(call(bo), bo.sealer.priv, "bo", bo.signer);
	assert.equal(made.length, 1);
	assert.match(made[0].privateSealed!, /^GV04:/, "the private half is placed under bo's files key");
	assert.equal((await api(dev.base, "GET", "/api/v1/members/bo/inbox-keys", { email: cy.email })).status, 403, "nobody reads another member's inbox keys");
	const boKey = (await currentInboxKey(bo.sealer.priv, "bo", made))!;
	// A private half beside public halves of someone else's choosing does not open.
	const other = await createStoreKey();
	await assert.rejects(openAreaInboxKeys(bo.sealer.priv, "bo", [{ ...boKey, publicKey: { ec: other.publicKey, kem: other.pqPublicKey } }]), "public halves the private half does not match");
	// …nor a private half sealed into another key's place.
	await assert.rejects(openAreaInboxKeys(bo.sealer.priv, "bo", [{ ...boKey, keyId: "other-key" }]));

	// ── 2. A link into a folder of bo's ──
	const folderId = "intake-folder-000000001";
	assert.equal((await api(dev.base, "POST", "/api/v1/members/bo/files/folders", { email: bo.email, body: { id: folderId, name: await bo.sealer.folderName(folderId, "From clients") } })).status, 200);
	const password = "plum-otter-41-kite";
	const MiB = 1024 * 1024;
	const linkA = await createRequestLink(call(bo), bo.sealer.priv, "bo", boKey, { origin: dev.base, label: "ACME incident, Oct", note: "The EDR export and the mail headers, please.", password, folderId, days: 7, maxFiles: 4, maxBytes: 20 * MiB });
	assert.match(linkA.link, /^http:\/\/127\.0\.0\.1:\d+\/s\/r\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/, "link: id, then secret and digest in the fragment");
	assert.equal(linkA.row.folderId, folderId);
	const rows = await listRequests(call(bo), "bo");
	assert.equal(await openRequestLabel(bo.sealer.priv, "bo", rows[0]), "ACME incident, Oct", "the label opens for its owner");
	assert.equal(JSON.stringify(rows).includes(linkA.link.split("#")[1].split(".")[0]), false, "the secret is nowhere on the server");

	// What the server refuses, whatever a client sends:
	const raw = async (over: Record<string, unknown>) => {
		const id = newRequestId();
		const k = await requestKeys(id, "A".repeat(43), "a password");
		const body = { id, inboxKeyId: boKey.keyId, inboxPublic: boKey.publicKey, viewHash: await tokenHash(k.view), sendHash: await tokenHash(k.send), noteSealed: await sealRequestNote(k.note, id, "n"), labelSealed: await sealPlacedText(bo.sealer.priv, places.requestLabel("bo", id), "l"), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), maxFiles: 1, maxBytes: 1000, ...over };
		return api(dev.base, "POST", "/api/v1/members/bo/requests", { email: bo.email, body });
	};
	assert.equal((await raw({ expiresAt: new Date(Date.now() + 40 * 86_400_000).toISOString() })).status, 400, "no link lives longer than 30 days");
	assert.equal((await raw({ expiresAt: new Date(Date.now() - 1000).toISOString() })).status, 400, "nor starts expired");
	const same = await tokenHash("x");
	assert.equal((await raw({ viewHash: same, sendHash: same })).status, 400, "a link has a password: send ≠ view");
	assert.equal((await raw({ noteSealed: "plain words" })).status, 400, "the note is sealed");
	assert.equal((await raw({ maxFiles: 5000 })).status, 400, "at most 1000 files");
	assert.equal((await raw({ inboxPublic: { ec: other.publicKey, kem: other.pqPublicKey } })).status, 409, "the inbox key's own public halves, not others");
	assert.equal((await raw({ folderId: "no-such-folder" })).status, 404);
	const takenId = linkA.row.id;
	assert.equal((await raw({ id: takenId })).status, 409, "a link id is taken once, across every area");
	assert.equal((await api(dev.base, "POST", "/api/v1/members/bo/requests", { email: cy.email, body: {} })).status, 403, "only the owner opens a door into their area");

	// ── 3. The sender opens it ──
	const sender = await openLink(dev.base, linkA.link);
	assert.equal(sender.note, "The EDR export and the mail headers, please.");
	assert.deepEqual([sender.filesLeft, sender.bytesLeft, sender.inboxKey.keyId], [4, 20 * MiB, boKey.keyId]);
	// The substitution: a link whose digest names another key (as if the server swapped it).
	const [head, frag] = linkA.link.split("#");
	const swapped = `${head}#${frag.split(".")[0]}.${digestForLink(await hybridDigest(other.publicKey, other.pqPublicKey))}`;
	await assert.rejects(openLink(dev.base, swapped), /offered a key this link does not name/, "a key the link does not name is refused before anything is sealed");
	await rejects(openLink(dev.base, `${head}#${"B".repeat(43)}.${frag.split(".")[1]}`), 404, "a wrong secret finds no link");
	await assert.rejects(openLink(dev.base, head), /not a complete upload link/);

	// ── 4. A wrong password ──
	const small = enc.encode("Received: from mail.acme.example (203.0.113.7)\r\nSubject: invoice\r\n");
	await rejects(sendFile(sender, await sendToken(sender, "not the password"), fileOf("headers.eml", small, "message/rfc822"), { sender: "Pat", message: "" }), 403, "a wrong password");
	assert.equal((await listRequests(call(bo), "bo")).find((r) => r.id === takenId)!.failedAttempts, 1, "…counted, for the owner to see");

	// ── 5. Whole and framed; the limits ──
	const token = await sendToken(sender, password);
	const s1 = await sendFile(sender, token, fileOf("headers.eml", small, "message/rfc822"), { sender: "Pat (ACME IT)", message: "Ticket 4411" });
	assert.equal(s1.sha256, await sha256Hex(small), "the receipt is the SHA-256 of what left");
	const large = bytesOf(9 * MiB + 123, 7);
	const s2 = await sendFile(sender, token, fileOf("edr-export.zip", large, "application/zip"), { sender: "Pat (ACME IT)", message: "" }, { wholeLimit: MiB });
	await rejects(sendFile(sender, token, fileOf("too-big.bin", bytesOf(12 * MiB, 3)), { sender: "", message: "" }, { wholeLimit: MiB }), 413, "more bytes than the link has left");
	const s3 = await sendFile(sender, token, fileOf("note.txt", enc.encode("one more")), { sender: "Pat", message: "" });
	const s4 = await sendFile(sender, token, fileOf("empty", new Uint8Array(0)), { sender: "Pat", message: "an empty one" });
	await rejects(sendFile(sender, token, fileOf("fifth.txt", enc.encode("5")), { sender: "", message: "" }), 409, "all the files it was opened for");
	const after = (await listRequests(call(bo), "bo")).find((r) => r.id === takenId)!;
	assert.deepEqual([after.filesReceived, after.bytesReceived], [4, small.length + large.length + 8 + 0]);

	// ── 6. Bo's inbox ──
	const { items } = await call(bo)<{ items: InboxItem[] }>("GET", "/api/v1/members/bo/inbox");
	assert.equal(items.length, 4);
	assert.ok(items.every((i) => i.collector === `request:${takenId}` && i.status === "waiting"));
	assert.equal(items.find((i) => i.id === s2.item)!.chunk, 8 * MiB, "the large one arrived as frames");
	assert.equal((await api(dev.base, "GET", "/api/v1/members/bo/inbox", { email: cy.email })).status, 403, "nobody else reads bo's inbox");
	const keys = await openAreaInboxKeys(bo.sealer.priv, "bo", await areaInboxKeys(call(bo), "bo"));
	const item = (id: string) => items.find((i) => i.id === id)!;
	const o1 = await openItem(keys, "bo", item(s1.item), boTrust, []);
	assert.equal(o1.kind, "request");
	assert.equal(o1.problem, null);
	assert.deepEqual([o1.meta.name, o1.meta.type, o1.meta.sender, o1.meta.message, o1.meta.sha256], ["headers.eml", "message/rfc822", "Pat (ACME IT)", "Ticket 4411", s1.sha256]);
	// What a store could do with sealed records, named:
	assert.match((await openItem(keys, "bo", { ...item(s1.item), id: s3.item }, boTrust, [])).problem ?? "", /record is for item/, "a record moved to another item");
	assert.match((await openItem(keys, "bo", { ...item(s1.item), collector: `request:${"Z".repeat(22)}` }, boTrust, [])).problem ?? "", /record is for link/, "…or to another link");
	assert.match((await openItem(keys, "bo", { ...item(s1.item), size: 1 }, boTrust, [])).problem ?? "", /the store received/);
	await assert.rejects(openItem(new Map(), "bo", item(s1.item), boTrust, []), /does not have/, "without the inbox key nothing opens");

	// ── 7. Accept, as a sample (the default) and as a normal file; reject ──
	const fetchItem = async (id: string) => {
		const r = await fetch(`${dev.base}/api/v1/members/bo/inbox/${id}`, { headers: { "x-gorani-dev-email": bo.email } });
		assert.equal(r.status, 200);
		return r.body!;
	};
	const c1 = await hashInboxContent(o1, item(s1.item), await fetchItem(s1.item));
	assert.deepEqual(c1, { sha256: s1.sha256, size: small.length }, "the bytes decrypt to what was sent");
	await assert.rejects(acceptItem(call(bo), bo.sealer.priv, keys, "bo", item(s1.item), o1, { ...c1, sha256: "0".repeat(64) }, bo.signer), /not what the sender declared/, "bytes that differ are not accepted");
	const a1 = await acceptItem<{ file: { id: string } }>(call(bo), bo.sealer.priv, keys, "bo", item(s1.item), o1, c1, bo.signer, { folderId, linkLabel: "ACME incident, Oct" });
	const f1 = a1.file.id;
	const listed = (await call(bo)<{ files: { id: string; sample: boolean }[] }>("GET", `/api/v1/members/bo/files/list?folder=${folderId}`)).files;
	assert.deepEqual(listed.map((f) => [f.id, f.sample]), [[f1, true]], "filed into the link's folder, as a malware sample");
	const k1 = (await call(bo)<{ keys: Record<string, { type?: string; sample?: boolean; intake?: string; collection?: string }> }>("POST", "/api/v1/members/bo/files/keys", { ids: [f1] })).keys[f1];
	const obj = await fetch(`${dev.base}/api/v1/members/bo/files/${f1}`, { headers: { "x-gorani-dev-email": bo.email } });
	const t = await openPlacedText(bo.sealer.priv, places.fileType("bo", f1, 1), k1.type!);
	assert.ok(k1.sample && isSampleType(t) && originalType(t) === "message/rfc822", `both marks: the store's flag, and the sealed type keeping the original (${t})`);
	assert.equal((await checkContentHash(bo.sealer.priv, boTrust, "bo", f1, 1, obj.headers.get("x-gorani-hash"), c1)).status, "verified", "bo signed the bytes");
	const intake = await checkIntake(bo.sealer.priv, boTrust, "bo", f1, k1.intake);
	assert.equal(intake.status, "verified");
	if (intake.status === "verified") assert.deepEqual([intake.record.collector, intake.record.source], [`request:${takenId}`, "Pat (ACME IT), through upload link ACME incident, Oct"]);
	const col = await checkItemCollection(bo.sealer.priv, "bo", f1, k1.collection!, boTrust, [], c1);
	assert.deepEqual([col.record.kind, col.problem, col.record.meta.sha256], ["request", null, s1.sha256], "the sender's record rides beside the file");
	await assert.rejects(acceptItem(call(bo), bo.sealer.priv, keys, "bo", item(s1.item), o1, c1, bo.signer), /409.*already decided/, "decided once");

	const o2 = await openItem(keys, "bo", item(s2.item), boTrust, []);
	const c2 = await hashInboxContent(o2, item(s2.item), await fetchItem(s2.item));
	assert.equal(c2.sha256, s2.sha256, "the framed upload decrypts to what was sent");
	const a2 = await acceptItem<{ file: { id: string; sample: boolean } }>(call(bo), bo.sealer.priv, keys, "bo", item(s2.item), o2, c2, bo.signer, { asSample: false });
	assert.equal((await call(bo)<{ files: { id: string; sample: boolean }[] }>("GET", "/api/v1/members/bo/files/list?folder=root")).files.find((f) => f.id === a2.file.id)?.sample, false, "a person may file it as a normal file");

	await rejectItem(call(bo), bo.sealer.priv, "bo", s3.item, "not what we asked for");
	const rej = (await call(bo)<{ items: InboxItem[] }>("GET", "/api/v1/members/bo/inbox")).items.find((i) => i.id === s3.item)!;
	assert.equal(await openItemRejectReason(bo.sealer.priv, "bo", s3.item, rej.rejected!.reason), "not what we asked for", "the reason is sealed");

	// ── 4 (cont.). Ten wrong passwords lock a link; revoking closes one ──
	const linkB = await createRequestLink(call(bo), bo.sealer.priv, "bo", boKey, { origin: dev.base, label: "to be locked", note: "", password, days: 1, maxFiles: 5, maxBytes: MiB });
	const senderB = await openLink(dev.base, linkB.link);
	const wrong = await sendToken(senderB, "guess");
	for (let i = 0; i < 10; i++) await rejects(sendFile(senderB, wrong, fileOf("x", enc.encode("x")), { sender: "", message: "" }), 403, `wrong password ${i + 1}`);
	await rejects(sendFile(senderB, await sendToken(senderB, password), fileOf("x", enc.encode("x")), { sender: "", message: "" }), 423, "locked: even the right password");
	await rejects(openLink(dev.base, linkB.link), 423, "the page says it is locked");
	const lockedRow = (await listRequests(call(bo), "bo")).find((r) => r.id === linkB.row.id)!;
	assert.deepEqual([lockedRow.locked, lockedRow.failedAttempts], [true, 10]);
	const actions = (await call(bo)<{ action: string }[]>("GET", "/api/v1/members/bo/audit")).map((l) => l.action);
	assert.ok(actions.includes("request.locked") && actions.includes("request.create") && actions.includes("inbox.accept"), `audited: ${actions.join(", ")}`);
	await revokeRequest(call(bo), "bo", takenId);
	await rejects(openLink(dev.base, linkA.link), 404, "a revoked link is no link");

	// ── 8. A link into a case: a manager's act ──
	const kase = await openCase(dev, ana, "ir-req", "Inbound from ACME", [[bo, "write"], [cy, "manage"]], "evidence");
	await createInboxKey(call(ana), kase.sealer.priv, "ir-req", ana.signer);
	const caseKeys = (await call(ana)<{ cases: CaseRow[] }>("GET", "/api/v1/cases")).cases.find((c) => c.id === "ir-req")!.inboxKeys as InboxKeyRow[];
	const caseKey = (await currentInboxKey(kase.sealer.priv, kase.area, caseKeys))!;
	await assert.rejects(createRequestLink(call(bo), kase.sealer.priv, kase.area, caseKey, { origin: dev.base, label: "x", note: "", password, days: 1, maxFiles: 1, maxBytes: MiB }), /403/, "a writer does not open doors into a case");
	await assert.rejects(createRequestLink(call(ana), kase.sealer.priv, kase.area, { ...caseKey, publicKey: { ec: other.publicKey, kem: other.pqPublicKey } }, { origin: dev.base, label: "x", note: "", password, days: 1, maxFiles: 1, maxBytes: MiB }), /409.*public halves/, "…and a case link seals to the case's own inbox key");
	const linkC = await createRequestLink(call(ana), kase.sealer.priv, kase.area, caseKey, { origin: dev.base, label: "ACME → case", note: "For the case", password, days: 3, maxFiles: 2, maxBytes: MiB });
	const senderC = await openLink(dev.base, linkC.link);
	assert.equal(senderC.inboxKey.keyId, caseKey.keyId);
	const sc = await sendFile(senderC, await sendToken(senderC, password), fileOf("ioc.txt", enc.encode("203.0.113.7\n")), { sender: "Pat", message: "" });
	const caseItems = (await call(bo)<{ items: InboxItem[] }>("GET", `${kase.base}/inbox`)).items;
	const ci = caseItems.find((i) => i.id === sc.item)!;
	assert.equal(ci.collector, `request:${linkC.row.id}`);
	const caseInbox = await openAreaInboxKeys(kase.sealer.priv, kase.area, caseKeys);
	const oc = await openItem(caseInbox, kase.area, ci, await trustOf(dev, ana), []);
	assert.equal(oc.problem, null);
	const cc = await hashInboxContent(oc, ci, (await fetch(`${dev.base}${kase.base}/inbox/${ci.id}`, { headers: { "x-gorani-dev-email": ana.email } })).body!);
	const ac = await acceptItem<{ file: { id: string } }>(call(ana), kase.sealer.priv, caseInbox, kase.area, ci, oc, cc, ana.signer);
	assert.equal((await call(ana)<{ files: { id: string; sample: boolean }[] }>("GET", `${kase.base}/files/list?folder=root`)).files.find((f) => f.id === ac.file.id)?.sample, true, "into the case, as a sample");
	assert.equal((await listRequests(call(bo), kase.area)).length, 1, "the case's members see its links");
	// The export: the sender's record travels, checked for what it is.
	const anaTrust = await trustOf(dev, ana);
	const asked = await requestApproval(call(ana), ana.signer, "ir-req", "case.export");
	await approveRequest(call(cy), cy.signer, await trustOf(dev, cy), asked);
	const built = await buildExport(sourceAs(ana), ana.signer, anaTrust, kase.sealer.priv, "ir-req", asked.id);
	assert.deepEqual(built.problems, [], "every record checked out while building");
	const exported = (built.manifest as { files: { id: string; collection: { check: string; record: { kind?: string } } | null }[] }).files.find((f) => f.id === ac.file.id)!;
	assert.deepEqual([exported.collection?.check, exported.collection?.record.kind], ["declared", "request"], "declared — consistent, and nobody signed it");
	const pkgDir = fs.mkdtempSync(path.join(os.tmpdir(), "gorani-requests-export-"));
	fs.writeFileSync(path.join(pkgDir, "package.zip"), Buffer.concat(built.parts.map((p) => Buffer.from(p))));
	const verified = spawnSync(process.execPath, [path.join(ROOT, "tools/verify-export.mjs"), path.join(pkgDir, "package.zip")], { encoding: "utf8" });
	fs.rmSync(pkgDir, { recursive: true, force: true });
	assert.equal(verified.status, 0, verified.stdout + verified.stderr);
	assert.match(verified.stdout, /✔ ioc\.txt: its upload-link record is about this item/);
	assert.match(verified.stdout, /✔ ioc\.txt: version 1 is the bytes the sender declared/);
	assert.match(verified.stdout + verified.stderr, /ioc\.txt: sent through an upload link by “Pat” — the sender's word, unsigned; accepted by ana/);

	// ── 8b. The CLI, on bo's own inbox ──
	if (fs.existsSync(BIN)) {
		const home = fs.mkdtempSync(path.join(os.tmpdir(), "gorani-requests-cli-"));
		const profile = path.join(home, "bo.json");
		const asBo = (args: string[]) => sync([...args, "--secret", bo.recoveryCode, "--dev-email", bo.email], profile, home);
		// The files store's record authenticated, as the setup screen does (records.ts): the
		// CLI refuses one without a MAC under the member's root (commit 24, O3).
		const files = { ...bo.settings.stores.files, mac: await macRecord(await deriveRecordKey(bo.root), "files", bo.settings.stores.files) };
		assert.equal((await api(dev.base, "PUT", "/api/v1/members/bo/vault", { email: bo.email, body: { settings: { ...bo.settings, stores: { files } } } })).status, 200);
		assert.equal((await sync(["setup", "--server", dev.base, "--member", "bo", "--name", "bo's workstation", "--secret", bo.recoveryCode, "--device-secret", "e".repeat(64), "--dev-email", bo.email], profile, home)).status, 0);
		const linkD = await createRequestLink(call(bo), bo.sealer.priv, "bo", boKey, { origin: dev.base, label: "CLI intake", note: "", password, folderId, days: 1, maxFiles: 5, maxBytes: MiB });
		const senderD = await openLink(dev.base, linkD.link);
		const tD = await sendToken(senderD, password);
		const flagged = await sendFile(senderD, tD, fileOf("dropper.exe", enc.encode("MZ… EICAR-STANDARD-ANTIVIRUS-TEST-FILE …")), { sender: "Pat", message: "from the quarantine" });
		const clean = await sendFile(senderD, tD, fileOf("readme.txt", enc.encode("nothing to see"), "text/plain; charset=utf-8"), { sender: "Pat", message: "" });
		const knownOne = await sendFile(senderD, tD, fileOf("known.bin", new Uint8Array(0)), { sender: "Pat", message: "" });
		const listing = await asBo(["inbox"]);
		assert.equal(listing.status, 0, listing.out);
		assert.match(listing.out, new RegExp(`${clean.item}\treadme\.txt\t14 bytes\tfrom link “CLI intake”\twaiting\tan outsider's upload, unsigned — sent by “Pat”`));
		const checked = await asBo(["inbox", "--item", clean.item, "--check-hash"]);
		assert.match(checked.out, new RegExp(`SHA-256 ${clean.sha256}\tthe bytes are what its record says`));
		assert.match(checked.out, /MalwareBazaar: not known there/);
		// The scanner: a stand-in that objects to the EICAR marker. Run without a shell — the
		// `sh -c` here is the SCANNER, chosen by the person; the item's name never reaches it.
		const scanner = `sh -c '! grep -q EICAR-STANDARD "$0"'`;
		const refused = await asBo(["accept", "--item", flagged.item, "--scan", scanner]);
		assert.notEqual(refused.status, 0);
		assert.match(refused.out, /the scanner refused .* \(exit 1\) — nothing was filed/);
		assert.equal((await call(bo)<{ items: InboxItem[] }>("GET", "/api/v1/members/bo/inbox")).items.find((i) => i.id === flagged.item)!.status, "waiting", "…and nothing was");
		assert.equal(fs.readdirSync(os.tmpdir()).filter((d) => d.startsWith("gorani-scan-")).length, 0, "the decrypted copy is gone");
		const ok = await asBo(["accept", "--item", clean.item, "--scan", scanner]);
		assert.equal(ok.status, 0, ok.out);
		assert.match(ok.out, /accepted .* as file [A-Za-z0-9_-]+, a malware sample — SHA-256 [0-9a-f]{64}: the bytes the sender declared, signed by you \(bo\)/);
		assert.match((await asBo(["accept", "--item", knownOne.item, "--as-file", "--check-hash"])).out, /MalwareBazaar: KNOWN — SuiteRAT[\s\S]*filed as a sample or not at all/, "a known hash is not filed as a normal file");
		assert.equal((await asBo(["accept", "--item", knownOne.item, "--check-hash"])).status, 0, "…as a sample, it is");
		// What the CLI signed (Rust), the browser's code verifies (TS).
		const cliFile = (await call(bo)<{ items: InboxItem[] }>("GET", "/api/v1/members/bo/inbox")).items.find((i) => i.id === clean.item)!.accepted!.file;
		const kc = (await call(bo)<{ keys: Record<string, { type: string; sample: boolean; intake: string; collection: string }> }>("POST", "/api/v1/members/bo/files/keys", { ids: [cliFile] })).keys[cliFile];
		assert.ok(kc.sample && isSampleType(await openPlacedText(bo.sealer.priv, places.fileType("bo", cliFile, 1), kc.type)), "a sample by both marks");
		assert.equal(originalType(await openPlacedText(bo.sealer.priv, places.fileType("bo", cliFile, 1), kc.type)), "text/plain; charset=utf-8", "the original type kept, encoded as the browser encodes it");
		const ci2 = await checkIntake(bo.sealer.priv, boTrust, "bo", cliFile, kc.intake);
		assert.equal(ci2.status, "verified");
		if (ci2.status === "verified") assert.equal(ci2.record.source, "Pat, through upload link CLI intake");
		assert.deepEqual([(await checkItemCollection(bo.sealer.priv, "bo", cliFile, kc.collection, boTrust, [], { sha256: clean.sha256, size: 14 })).problem], [null]);
		assert.equal((await call(bo)<{ files: { id: string }[] }>("GET", `/api/v1/members/bo/files/list?folder=${folderId}`)).files.some((f) => f.id === cliFile), true, "into the link's folder");
		fs.rmSync(home, { recursive: true, force: true });
	} else {
		console.log("skip  api:requests › the CLI part — build it first: cargo build -p gorani-client-core");
	}

	// ── 9. A rotation of bo's files key re-seals the inbox key and the labels ──
	const fresh = await createStoreKey();
	const freshKey = await importVaultKey(fresh.bundle.slice());
	const report = await resealStore(call(bo) as never, "bo", bo.sealer.priv, freshKey);
	const cli = fs.existsSync(BIN);
	assert.deepEqual([report.resealed.inboxkey, report.resealed.requestlabel, report.resealed.collection, report.resealed.reject], [1, cli ? 3 : 2, cli ? 4 : 2, 1], "the inbox key, every label, every record, the reason");
	const rotated = await areaInboxKeys(call(bo), "bo");
	assert.equal((await openAreaInboxKeys(freshKey, "bo", rotated)).size, 1, "the inbox key opens with the new files key — links keep working");
	await assert.rejects(openAreaInboxKeys(bo.sealer.priv, "bo", rotated), "…and not with the old one");

	// ── 10. The hash lookup: the SHA-256, and only that ──
	const hit = await call(bo)<{ found: boolean; signature: string; tags: string[]; link: string }>("POST", "/api/v1/malware/lookup", { sha256: known.toUpperCase() });
	assert.deepEqual([hit.found, hit.signature, hit.tags], [true, "SuiteRAT", ["rat", "suite"]]);
	assert.equal(hit.link, `https://bazaar.abuse.ch/sample/${known}/`);
	assert.deepEqual(await call(bo)("POST", "/api/v1/malware/lookup", { sha256: s1.sha256 }), { found: false });
	assert.equal((await api(dev.base, "POST", "/api/v1/malware/lookup", { email: bo.email, body: { sha256: "not a hash", name: "headers.eml" } })).status, 400);
	assert.equal((await api(dev.base, "POST", "/api/v1/malware/lookup", { email: "stranger@else.test", body: { sha256: known } })).status, 403, "members only");
	// (Two lookups here, and three by the CLI in 8b.)
	assert.equal(mb.requests.length, cli ? 5 : 2, "one request per lookup — no retries, no extras");
	for (const r of mb.requests) {
		assert.equal(r.headers["auth-key"], MB_KEY, "the Auth-Key goes from the Worker");
		assert.match(r.body, /^query=get_info&hash=[0-9a-f]{64}$/, "…with the hash, and nothing else");
		assert.equal(r.headers["x-gorani-dev-email"], undefined, "no caller identity forwarded");
	}
	const registry = (await call(ana)<{ audit: { action: string; target: string; details: string | null }[] }>("GET", "/api/v1/family")).audit.filter((l) => l.action === "malware.lookup");
	assert.equal(registry.length, cli ? 5 : 2, "each lookup is on the registry's trail");
	assert.ok(registry.every((l) => l.target === "bo" && !JSON.stringify(l).includes(known) && !JSON.stringify(l).includes(s1.sha256)), "…without the hash");

	// ── 11. The page ──
	const page = await fetch(`${dev.base}/s/r/${linkC.row.id}`);
	assert.equal(page.status, 200);
	assert.match(await page.text(), /Send files · Gorani/);
	assert.match(page.headers.get("content-security-policy") ?? "", /trusted-types 'none'/, "the share page's policy: no Trusted Types policy at all");
	assert.equal(page.headers.get("referrer-policy"), "no-referrer");
	assert.equal((await fetch(`${dev.base}/s/r/not-an-id`)).status, 404);

	// The limit (60 a minute per caller and link) — and the frames it leaves out.
	const linkE = await createRequestLink(call(bo), freshKey, "bo", { ...boKey, retiredAt: null }, { origin: dev.base, label: "limits", note: "", password, days: 1, maxFiles: 1, maxBytes: MiB });
	const senderE = await openLink(dev.base, linkE.link);
	const tE = await sendToken(senderE, password);
	const frames = await Promise.all(Array.from({ length: 70 }, (_, n) => fetch(`${dev.base}/s/r/${linkE.row.id}/uploads/no-such-upload/${n + 1}`, { method: "PUT", headers: { "x-gorani-request-send": tE }, body: new Uint8Array(1) }).then((r) => r.status)));
	assert.ok(!frames.includes(429), `frames are never rate limited (got ${[...new Set(frames)].join(", ")})`);
	// Up to 2 × 60 + 10 asks: the limiter counts in FIXED one-minute
	// windows, so 70 asks that straddle a window's end can split 20 + 50
	// and never pass 60 in either (it happened, 39s). Twice the limit and
	// more puts at least one window over it, wherever the edge falls.
	const metas: number[] = [];
	for (let n = 0; n < 130 && !metas.includes(429); n++) metas.push((await fetch(`${dev.base}/s/r/${linkE.row.id}/meta`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ view: "x" }) })).status);
	assert.ok(metas.includes(429), `…the rest of a link's routes are (${metas.length} asks, none refused)`);

	console.log("ok  api:requests — area inbox keys, links with passwords and limits, key substitution refused, lockout, whole + framed uploads, samples by default, case links by managers, rotation, the hash lookup sends the hash only");
} finally {
	await dev.close();
	await mb.close();
}
