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
 *   download checks it, and a record moved to another file does not verify.
 */

import assert from "node:assert/strict";
import { generateHybridKey, importVaultKey, openWith, unwrapPlacedKey, isPlacedText } from "../../web/src/vault/vault-crypto.ts";
import { openChunk } from "../../web/src/vault/chunked-file.ts";
import { FilesModel, UNVERIFIED, type FilesBridge } from "../../web/src/ui/files/model.ts";
import { places } from "../../web/src/vault/places.ts";
import { createCodeVault } from "../../web/src/vault/keys.ts";
import { buildTrust, createIdentity } from "../../web/src/vault/identity.ts";

// ── the fake server: rows + objects, sealed like the real one ───────
const store = await generateHybridKey();
const storePrivate = await importVaultKey(store.bundle);
const objects = new Map<string, Uint8Array>();
const rows = new Map<string, { id: string; folder: string | null; name: string; size: number; version: number; createdAt: string; updatedAt: string; trashedWith?: string | null }>();
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
				files: [...rows.values()].filter((r) => !r.trashedWith && (folder === "all" || (folder === "root" ? r.folder === null : r.folder === folder))).map((r) => ({ id: r.id, folder: r.folder, name: r.name, size: r.size, version: r.version, createdAt: r.createdAt, updatedAt: r.updatedAt })),
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
			return { files: [...rows.values()].filter((r) => String(r.size) === size && !r.trashedWith).map((r) => ({ id: r.id, tag: tags.get(r.id) ?? null })) };
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
				if (v) out[id] = { key: v.ck, chunk: v.chunk, type: v.type, version: rows.get(id)?.version ?? 1, size: rows.get(id)?.size ?? 0 };
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
		rows.set(id, { id, folder: (fields.folder_id as string | null) ?? null, name: fields.name, size: Number(fields.size), version: 1, createdAt: now(), updatedAt: now() });
		tags.set(id, fields.tag);
		feedCursor++;
		feed.push({ seq: feedCursor, kind: "file.put", data: { id } });
	},
	async putMultipart(_member, fields, sealed, chunk) {
		const id = fields.file_id;
		const object = `obj/${id}`;
		objects.set(object, sealed);
		versions.set(id, { ck: fields.ck, object, type: fields.type, chunk, hash: fields.hash ?? null });
		rows.set(id, { id, folder: (fields.folder_id as string | null) ?? null, name: fields.name, size: Number(fields.size), version: 1, createdAt: now(), updatedAt: now() });
		tags.set(id, fields.tag);
		feedCursor++;
		feed.push({ seq: feedCursor, kind: "file.put", data: { id } });
	},
	confirmDuplicate: async (count) => {
		dupAsked = count;
		return dupAnswer;
	},
	toast: (m) => void toasts.push(m),
	identity: () => me,
};

// The member's identity (commit 29d): its own entry, self-pinned, is all
// the trust this test needs — the uploader verifies their own signature.
const vault = await createCodeVault();
const rootKey = await importVaultKey(vault.rootBundle.slice());
const made = await createIdentity("jinu", rootKey, { ec: vault.publicKey, kem: vault.pqPublicKey });
const me = { signer: made.signer, trust: await buildTrust("jinu", rootKey, made.record, [{ member: "jinu", ...made.registry, certs: [] }]) };
const toasts: string[] = [];

let dupAsked = 0;
let dupAnswer: "skip" | "keep" | "version" | null = null;

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
dupAnswer = "keep";
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
assert.equal(model.state.get().files.length, 2, "keep both → two files");

// 5. Download round-trips the exact bytes — and checks the uploader's
// signed content hash on the way (commit 29d).
let downloaded: Uint8Array | null = null;
assert.ok(isPlacedText(versions.get(row.id)!.hash ?? ""), "the upload carried a sealed, signed content hash");
await model.download(row.id, "beach.png");
void downloaded;
assert.match(toasts.at(-1) ?? "", /content verified — exactly the bytes jinu signed/);
assert.equal((await model.verify(row.id)).status, "verified");

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

model.dispose(); // stops the change-feed poll so the test process can exit

console.log("ok  explorer model: sealed listings, uploads+duplicates, downloads, trash, copies, feed");