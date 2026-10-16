// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The explorer model, driven in Node against a fake server and REAL crypto:
 * the same vault-crypto/chunked-file the browser uses, so the sealed round
 * trips here are the real ones. What it proves:
 *
 *   listings decrypt names into memory → rename re-seals → upload seals with
 *   a fresh content key, fingerprints, asks about duplicates → download
 *   opens what was uploaded → trash + restore → copy-paste duplicates via a
 *   NEW key (the original's history untouched) → the change feed advances →
 *   (commit 25, O6) names the server swapped between files show as
 *   UNVERIFIED, and a key moved to another file does not open → (commit
 *   29d, D5.1) every upload carries its uploader's signed content hash, a
 *   download checks it, and a record moved to another file does not verify
 *   → (commit 29e, D8) a sample uploaded as one, or marked later, is never
 *   previewed, downloads as a ZipCrypto zip under "infected" (opened here
 *   by Python's zipfile, an independent reader), and its copies stay
 *   samples; a server that clears its flag cannot make it renderable.
 */

import assert from "node:assert/strict";
import { generateHybridKey, importVaultKey, openWith, unwrapPlacedKey, isPlacedText } from "../../web/src/vault/vault-crypto.ts";
import { openChunk, chunkFor, frameCount, sealedSize } from "../../web/src/vault/chunked-file.ts";
import { FilesModel, UNVERIFIED, WHOLE_LIMIT, type FilesBridge } from "../../web/src/ui/files/model.ts";
import { memoryJournal } from "../../web/src/lib/upload-journal.ts";
import { places } from "../../web/src/vault/places.ts";
import { createCodeVault } from "../../web/src/vault/keys.ts";
import { buildTrust, createIdentity } from "../../web/src/vault/identity.ts";
import { isSampleType } from "../../web/src/vault/samples.ts";
import { openPlacedText } from "../../web/src/vault/vault-crypto.ts";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── the fake server: rows + objects, sealed like the real one ───────
const store = await generateHybridKey();
const storePrivate = await importVaultKey(store.bundle);
const objects = new Map<string, Uint8Array>();
const rows = new Map<string, { id: string; folder: string | null; name: string; size: number; version: number; createdAt: string; updatedAt: string; trashedWith?: string | null; sample?: boolean }>();
const folders = new Map<string, { id: string; parent: string | null; name: string; createdAt: string; updatedAt: string; deletedAt?: string | null }>();
const versions = new Map<string, { ck: string; object: string; type: string | null; chunk: number | null; hash: string | null }>();
let feedCursor = 0;
const feed: { seq: number; kind: string; data: unknown }[] = [];
let secretsSealed: string | null = null;

function now() {
	return new Date().toISOString();
}

function touch(id: string) {
	const row = rows.get(id);
	if (row) row.updatedAt = now();
}

const server = {
	get(path: string): unknown {
		const url = new URL(path, "http://x");
		const p = url.pathname;
		if (p.endsWith("/files/list")) {
			const folder = url.searchParams.get("folder") ?? "root";
			return {
				files: [...rows.values()].filter((r) => !r.trashedWith && (folder === "all" || (folder === "root" ? r.folder === null : r.folder === folder))).map((r) => ({ id: r.id, folder: r.folder, name: r.name, size: r.size, version: r.version, createdAt: r.createdAt, updatedAt: r.updatedAt, sample: r.sample === true })),
				folders: [...folders.values()].filter((f) => !f.deletedAt && (folder === "root" ? f.parent === null : f.parent === folder)).map((f) => ({ id: f.id, parent: f.parent, name: f.name, createdAt: f.createdAt, updatedAt: f.updatedAt })),
			};
		}
		if (p.endsWith("/files/trash")) {
			return {
				files: [...rows.values()].filter((r) => r.trashedWith !== undefined && r.trashedWith !== null || rows.get(r.id)?.trashedWith).map((r) => ({ id: r.id, folder: r.folder, name: r.name, size: r.size, version: r.version, createdAt: r.createdAt, updatedAt: r.updatedAt })),
				folders: [...folders.values()].filter((f) => f.deletedAt).map((f) => ({ id: f.id, parent: f.parent, name: f.name, createdAt: f.createdAt, updatedAt: f.updatedAt })),
				trashedWith: [],
			};
		}
		if (p.endsWith("/files/secrets")) return { sealed: secretsSealed };
		// (No GET /files/keys here on purpose: the real worker routes a GET of
		// that path to "download the file whose id is `keys`" → 404. This fake
		// once answered the GET, and the app shipped calling it — a mock of the
		// tested layer that agreed with the bug. The fake mirrors the real
		// contract now: POST with { ids }, see send() below.)
		if (p.endsWith("/files/match")) {
			const size = url.searchParams.get("size");
			return { files: [...rows.values()].filter((r) => String(r.size) === size && !r.trashedWith).map((r) => ({ id: r.id, tag: tags.get(r.id) ?? null, folder: r.folder, name: r.name })) };
		}
		if (p.endsWith("/files/sealed")) {
			// (Only the one-file version walk the sample mark uses.)
			const file = url.searchParams.get("file")!;
			const v = versions.get(file);
			return { items: v ? [{ row: 1, a: file, b: String(rows.get(file)?.version ?? 1), v1: v.ck, v2: v.type }] : [], next: null };
		}
		if (p.endsWith("/files/changes")) {
			const since = Number(url.searchParams.get("since") ?? 0);
			return { cursor: feedCursor, changes: feed.filter((c) => c.seq > since) };
		}
		throw new Error(`fake server: GET ${path}`);
	},
	send(method: string, path: string, body?: { settings?: unknown; sealed?: string; ids?: string[]; files?: string[]; folders?: string[]; name?: string; parentId?: string | null; folderId?: string | null }): unknown {
		const p = new URL(path, "http://x").pathname;
		if (p.endsWith("/files/keys")) {
			// The real contract (worker/src/routes.rs): POST, ids in the body,
			// only the asked-for ids answered.
			assert.equal(method, "POST", "files/keys is a POST route");
			const out: Record<string, unknown> = {};
			for (const id of body?.ids ?? []) {
				const v = versions.get(id);
				if (v) out[id] = { key: v.ck, chunk: v.chunk, type: v.type, version: rows.get(id)?.version ?? 1, size: rows.get(id)?.size ?? 0, hash: v.hash, sample: rows.get(id)?.sample === true };
			}
			return { keys: out };
		}
		if (p.endsWith("/files/secrets") && method === "PUT") {
			secretsSealed = body!.sealed as string;
			return { ok: true };
		}
		if (p.endsWith("/files/trash/restore")) {
			for (const id of body!.files ?? []) {
				const r = rows.get(id)!;
				r.trashedWith = null;
				touch(id);
			}
			return { files: (body!.files ?? []).length, folders: 0 };
		}
		if (p.endsWith("/files/folders") && method === "POST") {
			// The client chose the id (commit 25) — its name is sealed into it.
			const id = (body as { id?: string }).id;
			assert.ok(id, "a new folder arrives with its client-chosen id");
			folders.set(id, { id, parent: (body!.parentId as string | null) ?? null, name: body!.name as string, createdAt: now(), updatedAt: now() });
			return { id };
		}
		if (p.endsWith("/files/folders") && false) return {};
		if (/\/files\/folders\/[^/]+$/.test(p)) {
			const id = p.split("/").pop()!;
			const f = folders.get(id);
			assert.ok(f, "folder exists");
			if (method === "PATCH") {
				if (body!.name) f.name = body!.name;
				if (body!.parentId !== undefined) f.parent = (body!.parentId as string | null) ?? null;
				f.updatedAt = now();
			}
			if (method === "DELETE") f.deletedAt = now();
			return { ok: true };
		}
		if (/\/files\/[^/]+$/.test(p)) {
			const id = p.split("/").pop()!;
			const r = rows.get(id);
			assert.ok(r, "file exists");
			if (method === "PATCH") {
				const mark = body as { sample?: boolean; types?: Record<string, string> };
				if (mark.sample !== undefined) {
					// The real store's rule: one way, every version's type re-sealed.
					assert.equal(mark.sample, true, "a sample is never unmarked");
					assert.deepEqual(Object.keys(mark.types ?? {}), [String(r.version)], "every version's type comes with the mark");
					versions.get(id)!.type = mark.types![String(r.version)]!;
					r.sample = true;
				}
				if (body!.name) r.name = body!.name;
				if (body!.folderId !== undefined) r.folder = (body!.folderId as string | null) ?? null;
				touch(id);
			}
			if (method === "DELETE") {
				r.trashedWith = "fake-folder"; // the real server sets deleted_at
				r.updatedAt = now();
			}
			return { ok: true };
		}
		if (p.endsWith("/files/uploads")) throw new Error("fake server: multipart not needed here (small tests)");
		if (p.endsWith("/files/restore-since")) return {};
		throw new Error(`fake server: ${method} ${path}`);
	},
};

const tags = new Map<string, string>();

const multipartCalls: { chunk: number; count: number }[] = [];
const uploadsOpen = new Map<string, { fileId: string; chunk: number; parts: Map<number, Uint8Array> }>();
const partsSent: number[] = [];
let failPartAt: number | null = null;
const journal = memoryJournal();

// ── the bridge: real crypto, the fake server behind it ──────────────
const bridge: FilesBridge = {
	apiGet: <T>(path: string) => Promise.resolve(server.get(path) as T),
	apiSend: <T>(method: "POST" | "PUT" | "PATCH" | "DELETE", path: string, body?: unknown) => Promise.resolve(server.send(method, path, body) as T),
	storePrivate: async () => storePrivate,
	identityHeaders: () => ({}),
	async fetchObject(_member, id, _version, range) {
		const v = versions.get(id)!;
		const obj = objects.get(v.object)!;
		const version = rows.get(id)?.version ?? 1;
		if (range) {
			// range in the test = a whole-frame fetch (the preview path)
			return { body: obj.subarray(range[0], range[1] + 1), ck: v.ck, chunk: v.chunk, version, hash: v.hash };
		}
		return { body: obj, ck: v.ck, chunk: v.chunk, version, hash: v.hash };
	},
	async fetchObjectStream(member, id, _version, sink) {
		const v = versions.get(id)!;
		const obj = objects.get(v.object)!;
		const version = rows.get(id)?.version ?? 1;
		const key = await unwrapPlacedKey(storePrivate, places.fileKey(member, id, version), v.ck);
		const chunk = v.chunk ?? 0;
		if (!chunk) {
			await sink(await openWith(key, obj));
			return { version, hash: v.hash };
		}
		const frame = chunk + 28;
		for (let at = 0; at < obj.length; at += frame) {
			await sink(await openChunk(key, obj.subarray(at, Math.min(obj.length, at + frame)), at / frame, at + frame >= obj.length));
		}
		return { version, hash: v.hash };
	},
	async putWhole(_member, fields, sealed) {
		const id = fields.file_id;
		assert.ok(id && !rows.has(id), "a new file arrives with a fresh client-chosen id");
		const object = `obj/${id}`;
		objects.set(object, sealed);
		versions.set(id, { ck: fields.ck, object, type: fields.type, chunk: null, hash: fields.hash ?? null });
		rows.set(id, { id, folder: (fields.folder_id as string | null) ?? null, name: fields.name, size: Number(fields.size), version: 1, createdAt: now(), updatedAt: now(), sample: fields.sample === "1" });
		tags.set(id, fields.tag);
		feedCursor++;
		feed.push({ seq: feedCursor, kind: "file.put", data: { id } });
	},
	// (D12) A GC01 upload in the model's three steps: the fake server keeps
	// each part as the backend would, and assembles them at completion in
	// the order the client lists. `failPartAt` drops the connection once.
	async multipartStart(_member, plan) {
		const uploadId = `up-${plan.newFileId}`;
		uploadsOpen.set(uploadId, { fileId: plan.newFileId, chunk: plan.chunk, parts: new Map() });
		multipartCalls.push({ chunk: plan.chunk, count: Math.max(1, Math.ceil(plan.size / plan.chunk)) });
		return { uploadId, key: `files/jinu/${plan.newFileId}/u-1`, parts: Math.max(1, Math.ceil(plan.size / plan.chunk)) };
	},
	async multipartPart(_member, uploadId, _key, n, frame) {
		const up = uploadsOpen.get(uploadId);
		if (!up) throw new Error("no such upload");
		if (failPartAt === n) {
			failPartAt = null;
			throw new Error(`part ${n} failed three times — the network`);
		}
		partsSent.push(n);
		up.parts.set(n, frame.slice());
		return { partNumber: n, etag: `"etag-${n}"` };
	},
	async multipartComplete(_member, uploadId, fields) {
		const up = uploadsOpen.get(uploadId);
		if (!up) throw new Error("no such upload");
		const listed = (JSON.parse(fields.parts) as { partNumber: number }[]).map((p) => up.parts.get(p.partNumber)!);
		const sealed = new Uint8Array(listed.reduce((n, p) => n + p.length, 0));
		listed.reduce((at, p) => (sealed.set(p, at), at + p.length), 0);
		uploadsOpen.delete(uploadId);
		const chunk = up.chunk;
		const id = up.fileId;
		const object = `obj/${id}`;
		objects.set(object, sealed);
		versions.set(id, { ck: fields.ck, object, type: fields.type, chunk, hash: fields.hash ?? null });
		rows.set(id, { id, folder: (fields.folder_id as string | null) ?? null, name: fields.name, size: Number(fields.size), version: 1, createdAt: now(), updatedAt: now() });
		tags.set(id, fields.tag);
		feedCursor++;
		feed.push({ seq: feedCursor, kind: "file.put", data: { id } });
	},
	confirmDuplicate: async (question) => {
		dupAsked = question.twins.length;
		dupQuestion = question;
		return dupAnswer;
	},
	toast: (m) => void toasts.push(m),
	identity: () => me,
	uploadJournal: journal,
};

// The member's identity (commit 29d): its own entry, self-pinned, is all
// the trust this test needs — the uploader verifies their own signature.
const vault = await createCodeVault();
const rootKey = await importVaultKey(vault.rootBundle.slice());
const made = await createIdentity("jinu", rootKey, { ec: vault.publicKey, kem: vault.pqPublicKey });
const me = { signer: made.signer, trust: await buildTrust("jinu", rootKey, made.record, [{ member: "jinu", ...made.registry, certs: [] }]) };
const toasts: string[] = [];

let dupAsked = 0;
let dupAnswer: { action: "skip" | "keep"; forRest: boolean } | null = null;
let dupQuestion: { file: { name: string }; twins: { name: string; where: string }[]; later: number } | null = null;

// ── the tests ───────────────────────────────────────────────────────
const model = new FilesModel(bridge, "jinu");
await model.open();

// 1. The empty listing is empty and clean.
assert.equal(model.state.get().files.length, 0);
assert.equal(model.state.get().error, null);

// 2. A folder via the model's op (sealed name on the server, decrypted in memory).
const folderId = await model.newFolder(null, "Photos");
const listed = model.state.get().folders.find((f) => f.id === folderId);
assert.equal(listed?.name, "Photos", "the tree shows the decrypted name");
// The server holds only the sealed text.
assert.ok(isPlacedText(folders.get(folderId)!.name), "the server never saw the name (GV04, sealed into the folder's place)");

// 3. Upload with a duplicate check: the first copy just lands.
dupAnswer = { action: "keep", forRest: false };
const bytes = new TextEncoder().encode("family photo bytes");
const file = new File([bytes as BlobPart], "beach.png", { type: "image/png" });
await model.upload([file]);
const row = model.state.get().files[0];
assert.equal(row.name, "beach.png");
assert.equal(row.kind, "image");
assert.equal(row.size, bytes.length);
assert.equal(dupAsked, 0, "no twin, no question");

// The stored object is GV02-sealed under a fresh content key, wrapped GV04
// into this file's version-1 place.
const v = versions.get(row.id)!;
assert.ok(isPlacedText(v.ck));
const plain = await openWith(await unwrapPlacedKey(storePrivate, places.fileKey("jinu", row.id, 1), v.ck), objects.get(v.object)!);
assert.deepEqual(plain, bytes);

// 4. The SAME bytes again → the fingerprint question fires.
await model.upload([new File([bytes as BlobPart], "beach copy.png", { type: "image/png" })]);
assert.equal(dupAsked, 1, "the fingerprint caught the twin");
assert.deepEqual([dupQuestion?.file.name, dupQuestion?.twins[0]?.name, dupQuestion?.twins[0]?.where, dupQuestion?.later], ["beach copy.png", "beach.png", "", 0], "the prompt says which file is already there, and where (39n)");
assert.equal(model.state.get().files.length, 2, "keep both → two files");

// 5. Download round-trips the exact bytes — and checks the uploader's
// signed content hash on the way (commit 29d).
let downloaded: Uint8Array | null = null;
assert.ok(isPlacedText(versions.get(row.id)!.hash ?? ""), "the upload carried a sealed, signed content hash");
await model.download(row.id, "beach.png");
void downloaded;
assert.match(toasts.at(-1) ?? "", /content verified — exactly the bytes jinu signed/);
assert.equal((await model.verify(row.id)).status, "verified");

// 5b. A file past the whole-upload limit (D12): hashed in a streamed pass,
// then sealed and handed over frame by frame — and it opens, verified.
{
	const big = new Uint8Array(WHOLE_LIMIT + 1024 * 1024);
	for (let i = 0; i < big.length; i += 65536) crypto.getRandomValues(big.subarray(i, Math.min(big.length, i + 65536)));
	await model.upload([new File([big as BlobPart], "memory.raw", { type: "application/octet-stream" })]);
	const call = multipartCalls.at(-1)!;
	assert.deepEqual(call, { chunk: chunkFor(big.length), count: frameCount(big.length, chunkFor(big.length)) }, "the chunk chunkFor picks, one frame per part");
	const bigRow = model.state.get().files.find((f) => f.name === "memory.raw")!;
	assert.equal(objects.get(versions.get(bigRow.id)!.object)!.length, sealedSize(big.length, call.chunk), "every frame, in order");
	assert.equal((await model.verify(bigRow.id)).status, "verified", "the streamed SHA-256 is the one the frames open to");
	assert.deepEqual(await journal.list("jinu"), [], "a finished upload leaves nothing in the journal");
}

// 5c. A connection that drops part-way (D12, 31b): the journal remembers
// the parts that landed; choosing the same file again sends only the rest,
// with the same id, key and signed record — and the file opens, verified.
{
	const big = new Uint8Array(WHOLE_LIMIT + 9 * 1024 * 1024);
	for (let i = 0; i < big.length; i += 65536) crypto.getRandomValues(big.subarray(i, Math.min(big.length, i + 65536)));
	const disk = new File([big as BlobPart], "disk.E01", { type: "application/octet-stream", lastModified: 1_700_000_000_000 });
	failPartAt = 4;
	partsSent.length = 0;
	await assert.rejects(model.upload([disk]), /part 4 failed/);
	assert.deepEqual(partsSent, [1, 2, 3], "three parts landed before the drop");
	const stopped = await model.unfinishedUploads();
	assert.deepEqual(stopped.map((u) => [u.name, u.done]), [["disk.E01", 3]], "the journal says what stopped, its name opened from the sealed field");
	assert.ok(!JSON.stringify(await journal.list("jinu")).includes("disk.E01"), "no plaintext name at rest");
	partsSent.length = 0;
	await model.upload([disk]);
	assert.deepEqual(partsSent, [4, 5, 6, 7, 8], "only the missing parts are sent");
	assert.match(toasts.find((t) => /Resuming/.test(t)) ?? "", /Resuming “disk\.E01” from part 4 of 8/);
	const row = model.state.get().files.find((f) => f.name === "disk.E01")!;
	assert.equal((await model.verify(row.id)).status, "verified", "the resumed file opens to the bytes its signature names");
	assert.deepEqual(await journal.list("jinu"), []);
	// The server forgot an upload (its window passed): the next try starts over.
	failPartAt = 2;
	const memo = new File([big.subarray(0, WHOLE_LIMIT + 1) as BlobPart], "capture.pcap", { lastModified: 1_700_000_000_001 });
	await assert.rejects(model.upload([memo]), /part 2 failed/);
	uploadsOpen.clear();
	partsSent.length = 0;
	await model.upload([memo]);
	assert.ok(toasts.some((t) => /gone from the server — starting over/.test(t)));
	assert.deepEqual(partsSent, [1, 2, 3, 4, 5, 6, 7], "every part again, under a fresh upload");
	assert.equal((await model.verify(model.state.get().files.find((f) => f.name === "capture.pcap")!.id)).status, "verified");
}

// 6. Rename re-seals; the server's stored name changes shape but stays sealed.
await model.rename("file", row.id, "sunset.png");
assert.ok(isPlacedText(rows.get(row.id)!.name));
assert.equal(model.names.get(row.id), "sunset.png");

// 7. Trash + restore.
await model.trash("file", [row.id]);
assert.ok(!model.state.get().files.some((f) => f.id === row.id), "gone from the lists");
await model.openTrash();
assert.ok(model.state.get().trashFiles.some((f) => f.id === row.id), "in the Trash");
await model.restore([row.id], []);
await model.closeTrash();
assert.ok(model.state.get().files.some((f) => f.id === row.id), "restored");

// 8. Copy-paste duplicates through a NEW content key (a copy is a new file).
model.select({ kind: "file", id: row.id });
model.copy();
await model.paste();
const copies = model.state.get().files.filter((f) => f.name.startsWith("sunset"));
assert.equal(copies.length, 2);
const ckA = versions.get(row.id)!.ck;
const ckB = versions.get(copies.find((f) => f.id !== row.id)!.id)!.ck;
assert.notEqual(ckA, ckB, "a copy is a new sealed object with its own key");
assert.ok(isPlacedText(ckA) && isPlacedText(ckB));

// 9. The change feed: the fake server counted the writes; the model advances.
await new Promise((r) => setTimeout(r, 0));
assert.ok(feedCursor > 0);

// 10. Sorting: by size then flip.
model.sortBy("size");
assert.equal(model.state.get().sort.by, "size");
model.sortBy("size");
assert.equal(model.state.get().sort.dir, "desc");

// 11. O6 — the server swaps two files' names (and keys). The listing does
// not crash and does not lie: both rows show as UNVERIFIED, and the moved
// key does not open as the other file's.
const [one, two] = [copies[0].id, copies[1].id];
const fresh = new FilesModel(bridge, "jinu"); // a new session: no names cached
const nameOne = rows.get(one)!.name;
rows.get(one)!.name = rows.get(two)!.name;
rows.get(two)!.name = nameOne;
const keyOne = versions.get(one)!.ck;
versions.get(one)!.ck = versions.get(two)!.ck;
versions.get(two)!.ck = keyOne;
await fresh.open();
const shown = fresh.state.get().files;
assert.equal(shown.find((f) => f.id === one)?.name, UNVERIFIED, "a name moved from another file is shown as unverified");
assert.equal(shown.find((f) => f.id === two)?.name, UNVERIFIED);
assert.ok(shown.some((f) => f.name === "beach.png" || f.name === "beach copy.png"), "untouched rows still open normally");
await assert.rejects(fresh.openBytes(one, undefined, () => {}), /not sealed here/, "the moved key does not open as this file's");
fresh.dispose();

// 12. D5.1 — a signed record the server moves to another file does not
// verify there: it opens only in its own place (and names its own file).
const [keyBack, hashOne] = [versions.get(two)!.ck, versions.get(one)!.hash];
versions.get(two)!.ck = versions.get(one)!.ck;
versions.get(one)!.ck = keyBack; // the keys back where they belong
versions.get(two)!.hash = hashOne; // …but `one`'s record now under `two`
const moved = await model.verify(two);
assert.equal(moved.status, "invalid", JSON.stringify(moved));
assert.equal((await model.verify(one)).status, "verified", "the record still verifies where it was signed");
// No identity (the team context not open): a signature cannot be checked —
// said as such, never "verified".
const anonymous = new FilesModel({ ...bridge, identity: () => null }, "jinu");
assert.equal((await anonymous.verify(one)).status, "untrusted");
anonymous.dispose();

// 13. D8 — malware samples (commit 29e).
const evil = new TextEncoder().encode("MZ\x90\x00 pretend this is a dropper");
await model.upload([new File([evil as BlobPart], "dropper.png", { type: "image/png" })], { sample: true });
const dropper = model.state.get().files.find((f) => f.name === "dropper.png")!;
assert.equal(dropper.sample, true);
assert.equal(dropper.kind, "sample", "listed as a sample, whatever its name says");
assert.ok(isSampleType(await openPlacedText(storePrivate, places.fileType("jinu", dropper.id, 1), versions.get(dropper.id)!.type!)), "its sealed type carries the client's own mark");
assert.equal(await model.preview(dropper.id), null, "a sample is never decrypted for a preview");
const info = await model.info(dropper.id);
assert.equal(info?.policy, "sample");
assert.equal(info?.mime, null, "…nor given a mime to render with");
assert.equal(info?.shownType, "image/png", "its original type is kept, for display only");
// A server that clears its readable flag: the sealed mark still holds.
rows.get(dropper.id)!.sample = false;
await model.refresh();
assert.equal(await model.preview(dropper.id), null, "the flag cleared by the server — still refused");
assert.equal(await model.renderPolicy(dropper.id), "sample");
// The download is a zip under "infected", opened here by an independent reader.
await model.download(dropper.id, "dropper.png");
assert.equal(model.lastSaved?.name, "dropper.png.zip");
assert.match(toasts.at(-1) ?? "", /malware sample, zipped \(password: infected\); SHA-256 [0-9a-f]{64} — content verified/);
const dir = mkdtempSync(join(tmpdir(), "gorani-zip-"));
try {
	writeFileSync(join(dir, "s.zip"), concatAll(model.lastSaved!.parts));
	const py = spawnSync("python3", ["-I", "-c", "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); sys.stdout.buffer.write(z.read(z.namelist()[0], pwd=b'infected')); print(); print(z.namelist()[0])", join(dir, "s.zip")], { encoding: "latin1" });
	if (py.error) console.log("  (python3 not found: the zip was not cross-checked by an independent reader)");
	else {
		assert.equal(py.status, 0, py.stderr);
		const [bytes, entry] = [py.stdout.slice(0, evil.length), py.stdout.trim().split("\n").pop()];
		assert.equal(bytes, Buffer.from(evil).toString("latin1"), "Python's zipfile opens it with 'infected' to the exact bytes");
		assert.equal(entry, "dropper.png");
		const wrong = spawnSync("python3", ["-I", "-c", "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).read('dropper.png', pwd=b'wrong')", join(dir, "s.zip")]);
		assert.notEqual(wrong.status, 0, "…and refuses a wrong password");
	}
} finally {
	rmSync(dir, { recursive: true, force: true });
}
// A copy of a sample is a sample.
model.select({ kind: "file", id: dropper.id });
model.copy();
await model.paste();
const copy = model.state.get().files.find((f) => f.name === "dropper copy.png")!;
assert.equal(copy.sample, true, "copying never strips the mark");
// Marking a normal file later: one way, its type re-sealed with the mark.
const plainRow = model.state.get().files.find((f) => !f.sample && f.kind !== "sample")!;
await model.markSample(plainRow.id);
assert.equal(model.state.get().files.find((f) => f.id === plainRow.id)?.sample, true);
assert.equal(await model.preview(plainRow.id), null);

model.dispose(); // stops the change-feed poll so the test process can exit

console.log("ok  explorer model: sealed listings, uploads+duplicates, downloads, trash, copies, feed");

function concatAll(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}
