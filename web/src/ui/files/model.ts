// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The explorer's data layer — framework-free, testable in Node (Lesson 9:
 * the model never touches the DOM; the views never touch fetch or crypto).
 *
 * Everything the server sends is *structure*: ids, sizes, times, and SEALED
 * names (`GV04:…`, each sealed into its place — the file it names). This
 * model decrypts names into an in-memory cache the moment a listing arrives
 * — plaintext exists only in this tab, only while unlocked, and dies with
 * the session. A name that does not open where the server put it (moved
 * from another file, or minted without the store's key — O6) is shown as
 * UNVERIFIED rather than hidden or crashing the view: tampering should be
 * visible.
 *
 * Selection, clipboard, history and the change feed live here too, so both
 * platform simulations (Windows 11 and macOS Finder) are two skins over one
 * grammar of operations — which is exactly the point of the simulation.
 */

import { store, type Store } from "../../lib/store.ts";
import { newContentKey, importContentKey, sealWith, openWith, sealPlacedText, openPlacedText, wrapPlacedKey, unwrapPlacedKey, type VaultPrivateKey } from "../../vault/vault-crypto.ts";
import { places, newItemId } from "../../vault/places.ts";
import { controllingMediaWorker, registerMedia } from "../../lib/media-worker.ts";
import { sealChunked, openChunk, DEFAULT_CHUNK } from "../../vault/chunked-file.ts";
import { parseAudioMeta, type AudioMeta } from "../../vault/music-meta.ts";
import { toBase64, fromBase64 } from "../../lib/encoding.ts";
import { kindOf, type FileKind } from "./icons.ts";
import { blobURL, revokeBlobURL } from "../../lib/blob-urls.ts";
import type { LocalIndexLike } from "../../vault/index.ts";
import type { IndexEntry } from "../../vault/index-engine.ts";

/** What a name that does not open in its place is shown as (O6). */
export const UNVERIFIED = "⚠ unverified — not sealed here";

export interface FolderRow {
	id: string;
	parent: string | null;
	nameSealed: string;
	name: string; // decrypted, in-memory only
	createdAt: string;
	updatedAt: string;
	deletedAt?: string | null;
	trashedWith?: string | null;
}

export interface FileRow {
	id: string;
	folder: string | null;
	nameSealed: string;
	name: string;
	kind: FileKind;
	size: number;
	version: number;
	createdAt: string;
	updatedAt: string;
	trashedWith?: string | null;
}

export interface Selection {
	kind: "file" | "folder";
	id: string;
}

export interface SortState {
	by: "name" | "modified" | "type" | "size";
	dir: "asc" | "desc";
}

export interface FilesState {
	folderId: string | null;
	folders: FolderRow[];
	files: FileRow[];
	selection: Selection[];
	sort: SortState;
	loading: boolean;
	error: string | null;
	trashMode: boolean;
	trashFiles: FileRow[];
	trashFolders: FolderRow[];
}

/** The crypto + transport the model needs. The bridge (bridge.ts) knows about
 * sessions and non-extractable keys; the tests inject their own. */
export interface FilesBridge {
	apiGet<T>(path: string): Promise<T>;
	apiSend<T>(method: "POST" | "PUT" | "PATCH" | "DELETE", path: string, body?: unknown): Promise<T>;
	/** The files store's private key. It also SEALS (GV04: a store seals to
	 * itself, with a secret only its key computes) — there is no public-key
	 * path into a store any more (commit 25). */
	storePrivate(): Promise<VaultPrivateKey>;
	/** `version`: which version the bytes are (the `x-gorani-version` header) —
	 * the place the content key opens from. */
	fetchObject(memberId: string, id: string, version: number | undefined, range?: [number, number]): Promise<{ body: Uint8Array; ck: string; chunk: number | null; version: number }>;
	fetchObjectStream(memberId: string, id: string, version: number | undefined, sink: (plain: Uint8Array) => Promise<void> | void): Promise<void>;
	putWhole(memberId: string, fields: Record<string, string>, sealed: Uint8Array): Promise<void>;
	/** Headers that identify this client to the API beyond its cookies (the
	 * dev server's identity header; nothing in production) — for fetches
	 * made outside the bridge, i.e. by the media service worker. */
	identityHeaders(): Record<string, string>;
	putMultipart(memberId: string, fields: Record<string, string>, sealed: Uint8Array, chunk: number): Promise<void>;
	confirmDuplicate(count: number): Promise<"skip" | "keep" | "version" | null>;
	toast(message: string): void;
}

export type DuplicateAnswer = "skip" | "keep" | "version" | null;

export class FilesModel {
	readonly state: Store<FilesState>;
	/** Plaintext names, in memory for this session only. */
	readonly names = new Map<string, string>();
	/** File fingerprints (HMAC of SHA-256), for the duplicate check. */
	readonly tags = new Map<string, string>();
	private secrets: { fp: Uint8Array; idx: Uint8Array } | null = null;
	private history: (string | null)[] = [null];
	private historyAt = 0;
	private clipboard: { mode: "copy" | "cut"; files: string[]; folders: string[] } | null = null;
	private pollTimer: ReturnType<typeof setInterval> | undefined;
	private readonly listeners = new Set<() => void>();

	readonly memberId: string;
	/** The local index, if the shell opened one (search/recents, no server). */
	readonly index?: LocalIndexLike;

	private readonly bridge: FilesBridge;

	constructor(bridge: FilesBridge, memberId: string, index?: LocalIndexLike) {
		this.bridge = bridge;
		this.memberId = memberId;
		this.index = index;
		this.state = store<FilesState>({ folderId: null, folders: [], files: [], selection: [], sort: { by: "name", dir: "asc" }, loading: false, error: null, trashMode: false, trashFiles: [], trashFolders: [] });
	}

	subscribe(listener: () => void): () => void {
		return this.state.subscribe(() => listener());
	}

	/** The transport (for features that drive their own endpoints — shares). */
	get api(): FilesBridge {
		return this.bridge;
	}

	/** A share link's name for the owner's list, sealed into the share's place. */
	async sealShareName(shareId: string, text: string): Promise<string> {
		return sealPlacedText(await this.bridge.storePrivate(), places.shareName(this.memberId, shareId), text);
	}

	/** Open a name where the server put it; a name that will not open there
	 * becomes a visible warning (never cached — the next listing tries again). */
	private async openName(priv: VaultPrivateKey, place: Uint8Array, id: string, sealed: string): Promise<string> {
		const cached = this.names.get(id);
		if (cached !== undefined) return cached;
		try {
			const name = await openPlacedText(priv, place, sealed);
			this.names.set(id, name);
			return name;
		} catch {
			return UNVERIFIED;
		}
	}

	private set(patch: Partial<FilesState>): void {
		this.state.set({ ...this.state.get(), ...patch });
	}

	// ── navigation ──────────────────────────────────────────────────────

	async open(): Promise<void> {
		await this.list(null);
		void this.watchChanges();
	}

	async setFolder(id: string | null): Promise<void> {
		this.history = [...this.history.slice(0, this.historyAt + 1), id];
		this.historyAt++;
		await this.list(id);
	}

	async back(): Promise<void> {
		if (this.historyAt > 0) {
			this.historyAt--;
			const id = this.history[this.historyAt] ?? null;
			await this.list(id);
		}
	}

	async forward(): Promise<void> {
		if (this.historyAt < this.history.length - 1) {
			this.historyAt++;
			const id = this.history[this.historyAt] ?? null;
			await this.list(id);
		}
	}

	get canBack(): boolean {
		return this.historyAt > 0;
	}

	get canForward(): boolean {
		return this.historyAt < this.history.length - 1;
	}

	private async list(folderId: string | null, opts: { trash?: boolean } = {}): Promise<void> {
		this.set({ loading: true, error: null, folderId });
		try {
			if (opts.trash) {
				const t = await this.bridge.apiGet<{ files: FileRowJson[]; folders: FolderJson[]; trashedWith: { id: string; with: string }[] }>(`/api/v1/members/${this.memberId}/files/trash`);
				const withMap = new Map(t.trashedWith.map((x) => [x.id, x.with]));
				this.set({
					trashFiles: await this.decryptFiles(t.files.map((f) => ({ ...f, trashedWith: withMap.get(f.id) ?? null }))),
					trashFolders: await this.decryptFolders(t.folders.map((f) => ({ ...f, trashedWith: withMap.get(f.id) ?? null }))),
					loading: false,
				});
				return;
			}
			const l = await this.bridge.apiGet<{ files: FileRowJson[]; folders: FolderJson[] }>(`/api/v1/members/${this.memberId}/files/list?folder=${folderId ?? "root"}&limit=1000`);
			this.set({
				folders: await this.decryptFolders(l.folders),
				files: await this.decryptFiles(l.files),
				selection: [],
				loading: false,
			});
		} catch (e) {
			this.set({ loading: false, error: e instanceof Error ? e.message : String(e) });
		}
	}

	async openTrash(): Promise<void> {
		this.set({ trashMode: true });
		await this.list(this.state.get().folderId, { trash: true });
	}

	async closeTrash(): Promise<void> {
		this.set({ trashMode: false });
		await this.list(this.state.get().folderId);
	}

	// ── decryption of listings ──────────────────────────────────────────

	private async decryptFolders(rows: FolderJson[]): Promise<FolderRow[]> {
		const priv = await this.bridge.storePrivate();
		return Promise.all(
			rows.map(async (f) => {
				const name = await this.openName(priv, places.folderName(this.memberId, f.id), f.id, f.name);
				return { id: f.id, parent: f.parent, nameSealed: f.name, name, createdAt: f.createdAt, updatedAt: f.updatedAt, deletedAt: f.deletedAt ?? null, trashedWith: f.trashedWith ?? null };
			}),
		);
	}

	private async decryptFiles(rows: FileRowJson[]): Promise<FileRow[]> {
		const priv = await this.bridge.storePrivate();
		return Promise.all(
			rows.map(async (f) => {
				const name = await this.openName(priv, places.fileName(this.memberId, f.id), f.id, f.name);
				return { id: f.id, folder: f.folder, nameSealed: f.name, name, kind: kindOf(name), size: Number(f.size), version: f.version, createdAt: f.createdAt, updatedAt: f.updatedAt, trashedWith: f.trashedWith ?? null };
			}),
		);
	}

	// ── sorting ─────────────────────────────────────────────────────────

	sorted(): { folders: FolderRow[]; files: FileRow[] } {
		const s = this.state.get();
		const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
		const dir = s.sort.dir === "asc" ? 1 : -1;
		const files = [...s.files].sort((a, b) => {
			switch (s.sort.by) {
				case "name":
					return cmp(a.name, b.name) * dir;
				case "modified":
					return a.updatedAt.localeCompare(b.updatedAt) * dir;
				case "size":
					return (a.size - b.size) * dir;
				case "type":
					return cmp(a.kind, b.kind) * dir || cmp(a.name, b.name) * dir;
			}
		});
		const folders = [...s.folders].sort((a, b) => cmp(a.name, b.name) * dir);
		return { folders, files };
	}

	sortBy(by: SortState["by"]): void {
		const cur = this.state.get().sort;
		this.set({ sort: { by, dir: cur.by === by && cur.dir === "asc" ? "desc" : "asc" } });
	}

	// ── selection ───────────────────────────────────────────────────────

	select(sel: Selection, opts: { add?: boolean; range?: boolean } = {}): void {
		const s = this.state.get();
		let next = opts.add ? [...s.selection] : [];
		const anchorSel = s.selection[0];
		if (opts.range && s.selection.length && anchorSel) {
			const order = this.orderedIds();
			const anchor = order.indexOf(`${anchorSel.kind}:${anchorSel.id}`);
			const target = order.indexOf(`${sel.kind}:${sel.id}`);
			const [from, to] = anchor <= target ? [anchor, target] : [target, anchor];
			next = order.slice(from, to + 1).map((k) => ({ kind: k.startsWith("f:") ? ("folder" as const) : ("file" as const), id: k.slice(2) }));
		} else if (opts.add) {
			const exists = next.findIndex((x) => x.id === sel.id);
			if (exists >= 0) next.splice(exists, 1);
			else next.push(sel);
		} else {
			next = [sel];
		}
		this.set({ selection: next });
	}

	selectAll(): void {
		const s = this.state.get();
		const source = s.trashMode ? { folders: s.trashFolders, files: s.trashFiles } : { folders: s.folders, files: s.files };
		this.set({
			selection: [...source.folders.map((f) => ({ kind: "folder" as const, id: f.id })), ...source.files.map((f) => ({ kind: "file" as const, id: f.id }))],
		});
	}

	clearSelection(): void {
		this.set({ selection: [] });
	}

	private orderedIds(): string[] {
		const s = this.state.get();
		const { folders, files } = this.sorted();
		return [...(s.trashMode ? s.trashFolders : folders).map((f) => `folder:${f.id}`), ...(s.trashMode ? s.trashFiles : files).map((f) => `file:${f.id}`)];
	}

	// ── operations ──────────────────────────────────────────────────────

	async rename(kind: "file" | "folder", id: string, newName: string): Promise<void> {
		if (!newName.trim()) return;
		const priv = await this.bridge.storePrivate();
		const sealed = await sealPlacedText(priv, kind === "file" ? places.fileName(this.memberId, id) : places.folderName(this.memberId, id), newName.trim());
		const path = kind === "file" ? `/api/v1/members/${this.memberId}/files/${id}` : `/api/v1/members/${this.memberId}/files/folders/${id}`;
		await this.bridge.apiSend("PATCH", path, kind === "file" ? { name: sealed } : { name: sealed });
		this.names.set(id, newName.trim());
		await this.refresh();
		this.bridge.toast(`Renamed to “${newName.trim()}”`);
	}

	async move(kind: "file" | "folder", ids: string[], folderId: string | null): Promise<void> {
		for (const id of ids) {
			const path = kind === "file" ? `/api/v1/members/${this.memberId}/files/${id}` : `/api/v1/members/${this.memberId}/files/folders/${id}`;
			await this.bridge.apiSend("PATCH", path, kind === "file" ? { folderId } : { parentId: folderId });
		}
		await this.refresh();
		this.bridge.toast(`Moved ${ids.length} item${ids.length > 1 ? "s" : ""}`);
	}

	async trash(kind: "file" | "folder", ids: string[]): Promise<void> {
		for (const id of ids) {
			const path = kind === "file" ? `/api/v1/members/${this.memberId}/files/${id}` : `/api/v1/members/${this.memberId}/files/folders/${id}`;
			await this.bridge.apiSend("DELETE", path);
		}
		await this.refresh();
		this.bridge.toast(`Moved ${ids.length} item${ids.length > 1 ? "s" : ""} to the Trash`);
	}

	async restore(files: string[], folders: string[]): Promise<void> {
		await this.bridge.apiSend("POST", `/api/v1/members/${this.memberId}/files/trash/restore`, { files, folders });
		await this.openTrash();
		this.bridge.toast(`Restored ${files.length + folders.length} item${files.length + folders.length > 1 ? "s" : ""}`);
	}

	async newFolder(parentId: string | null, name: string): Promise<string> {
		// The id first, then the name sealed into it (the place names the folder).
		const id = newItemId();
		const sealed = await sealPlacedText(await this.bridge.storePrivate(), places.folderName(this.memberId, id), name.trim());
		const created = await this.bridge.apiSend<{ id: string }>("POST", `/api/v1/members/${this.memberId}/files/folders`, { id, name: sealed, parentId });
		await this.refresh();
		return created.id;
	}

	/** Upload: seal in the browser, fingerprint, ask about duplicates, send. */
	async upload(files: File[]): Promise<void> {
		await this.ensureSecrets();
		const folderId = this.state.get().folderId;
		for (const file of files) {
			const plain = new Uint8Array(await file.arrayBuffer());
			const tag = await this.fingerprint(plain);
			// The duplicate check: same size on the server, compare tags locally.
			const same = await this.bridge.apiGet<{ files: { id: string; tag: string | null }[] }>(`/api/v1/members/${this.memberId}/files/match?size=${plain.length}`);
			const twins = same.files.filter((x) => x.tag && x.tag === tag);
			if (twins.length) {
				const answer = await this.bridge.confirmDuplicate(twins.length);
				if (answer === "skip") {
					this.bridge.toast(`Skipped “${file.name}” (already here)`);
					continue;
				}
				// "keep" and "version" both store the bytes again as a new file:
				// identical bytes as a new VERSION of the twin would record
				// nothing new. (A dead `asVersion` parameter used to pretend
				// otherwise; removed in commit 25.)
			}
			await this.uploadOne(file, plain, tag, folderId);
		}
		await this.refresh();
	}

	private async uploadOne(file: File, plain: Uint8Array, tag: string, folderId: string | null): Promise<void> {
		// The file id first: the name, the type and the content key are sealed
		// INTO places that name it (O6) — so the server cannot move them to
		// another file, and could not have made them up (it lacks the PSK).
		// A new file is version 1.
		const priv = await this.bridge.storePrivate();
		const id = newItemId();
		const ck = newContentKey();
		const key = await importContentKey(ck);
		const nameSealed = await sealPlacedText(priv, places.fileName(this.memberId, id), file.name);
		const typeSealed = await sealPlacedText(priv, places.fileType(this.memberId, id, 1), file.type || "application/octet-stream");
		const ckSealed = await wrapPlacedKey(priv, places.fileKey(this.memberId, id, 1), ck);
		ck.fill(0);
		// Music metadata (docs/MUSIC.md): the tags exist only in plaintext we
		// already hold, so parse them here and seal the summary — the library
		// feed opens these blobs instead of ever re-reading the audio.
		let mmeta: string | undefined;
		if (file.type.startsWith("audio/")) {
			const meta = parseAudioMeta(plain);
			if (meta) mmeta = await sealPlacedText(priv, places.fileMusic(this.memberId, id, 1), JSON.stringify(meta));
		}
		if (plain.length > 48 * 1024 * 1024) {
			const chunked = await sealChunked(key, plain, DEFAULT_CHUNK);
			await this.bridge.putMultipart(this.memberId, { file_id: id, ck: ckSealed, name: nameSealed, type: typeSealed, size: String(plain.length), chunk: String(DEFAULT_CHUNK), tag, ...(mmeta ? { mmeta } : {}), ...(folderId ? { folder_id: folderId } : {}) }, chunked, DEFAULT_CHUNK);
		} else {
			const sealed = await sealWith(key, plain);
			await this.bridge.putWhole(this.memberId, { file_id: id, ck: ckSealed, name: nameSealed, type: typeSealed, size: String(plain.length), tag, ...(mmeta ? { mmeta } : {}), ...(folderId ? { folder_id: folderId } : {}) }, sealed);
		}
	}

	/**
	 * The music library (docs/MUSIC.md): one feed of sealed metadata blobs,
	 * opened with the store key — browsing the library never decrypts the
	 * audio itself. Blobs we can no longer open (a rotated key's leftovers)
	 * are skipped honestly rather than failing the library.
	 */
	async musicLibrary(): Promise<(AudioMeta & { id: string; version: number; size: number })[]> {
		const feed = await this.bridge.apiGet<{ tracks: { id: string; version: number; blobSealed: string; size: number }[] }>(`/api/v1/members/${this.memberId}/files/music`);
		const priv = await this.bridge.storePrivate();
		const out: (AudioMeta & { id: string; version: number; size: number })[] = [];
		for (const t of feed.tracks) {
			try {
				const meta = JSON.parse(await openPlacedText(priv, places.fileMusic(this.memberId, t.id, t.version), t.blobSealed)) as AudioMeta;
				out.push({ ...meta, id: t.id, version: t.version, size: t.size });
			} catch {
				void 0; // a blob from a key this member no longer holds, or not from here
			}
		}
		return out.sort((x, y) => (x.artist ?? "").localeCompare(y.artist ?? "") || (x.album ?? "").localeCompare(y.album ?? "") || (x.title ?? "").localeCompare(y.title ?? ""));
	}

	private async fingerprint(plain: Uint8Array): Promise<string> {
		await this.ensureSecrets();
		const { fp } = this.secrets!;
		const subtle = crypto.subtle;
		const digest = new Uint8Array(await subtle.digest("SHA-256", plain as BufferSource));
		const hmac = await subtle.importKey("raw", fp as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		const sig = new Uint8Array(await subtle.sign("HMAC", hmac, digest as BufferSource));
		return [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
	}

	/** The files secrets {fp, idx}, sealed to the store key by the first device. */
	private async ensureSecrets(): Promise<void> {
		if (this.secrets) return;
		const priv = await this.bridge.storePrivate();
		const existing = await this.bridge.apiGet<{ sealed: string | null }>(`/api/v1/members/${this.memberId}/files/secrets`);
		if (existing.sealed) {
			const json = JSON.parse(await openPlacedText(priv, places.storeSecrets(this.memberId), existing.sealed)) as { fp: string; idx: string };
			this.secrets = { fp: fromBase64(json.fp), idx: fromBase64(json.idx) };
			return;
		}
		const fp = crypto.getRandomValues(new Uint8Array(32));
		const idx = crypto.getRandomValues(new Uint8Array(32));
		const sealed = await sealPlacedText(priv, places.storeSecrets(this.memberId), JSON.stringify({ fp: toBase64(fp), idx: toBase64(idx) }));
		await this.bridge.apiSend("PUT", `/api/v1/members/${this.memberId}/files/secrets`, { sealed });
		this.secrets = { fp, idx };
	}

	// ── download ────────────────────────────────────────────────────────

	/** Open a file's current version and hand the bytes to ONE download.
	 *
	 * (Commit 24: the sink used to start a browser download per decrypted
	 * frame — a 100 MB file arrived as thirteen 8 MiB pieces. The frames are
	 * collected and saved as one Blob; a Blob of parts is not a copy.) */
	async download(id: string, name: string): Promise<void> {
		const parts: Uint8Array[] = [];
		await this.openBytes(id, undefined, (plain) => {
			parts.push(plain);
		});
		// The save itself is browser-only (the Node test collects bytes).
		if (typeof document !== "undefined") {
			const url = blobURL(new Blob(parts as BlobPart[], { type: "application/octet-stream" }));
			const a = document.createElement("a");
			a.href = url;
			a.download = name;
			a.click();
			setTimeout(() => revokeBlobURL(url), 5000);
		}
		this.bridge.toast(`Downloaded “${name}”`);
	}

	/** Open + decrypt; chunked objects stream frame by frame (never whole). */
	async openBytes(id: string, version: number | undefined, sink: (plain: Uint8Array) => Promise<void> | void): Promise<void> {
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null }> }>(id);
		const meta = keys.keys[id];
		if (!meta) throw new Error("the file's key was not found");
		const chunk = meta.chunk;
		if (chunk && chunk > 0) {
			await this.bridge.fetchObjectStream(this.memberId, id, version, sink);
			return;
		}
		const { body, ck, version: served } = await this.bridge.fetchObject(this.memberId, id, version);
		// The key opens only from the place of the version the bytes ARE (and,
		// asked for a version, it must be that one).
		if (version !== undefined && served !== version) throw new Error("the server answered with another version");
		const priv = await this.bridge.storePrivate();
		const key = await unwrapPlacedKey(priv, places.fileKey(this.memberId, id, served), ck);
		await sink(await openWith(key, body));
	}

	/** A decrypted slice for previews (first bytes only; nothing stored). */
	async preview(id: string, maxBytes = 128 * 1024): Promise<{ bytes: Uint8Array; name: string; mime: string } | null> {
		const s = this.state.get();
		const row = s.files.find((f) => f.id === id) ?? s.trashFiles.find((f) => f.id === id);
		if (!row) return null;
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null; type: string | null; version: number }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return null;
		const priv = await this.bridge.storePrivate();
		const mime = meta.type ? await openPlacedText(priv, places.fileType(this.memberId, id, meta.version), meta.type) : "application/octet-stream";
		const key = await unwrapPlacedKey(priv, places.fileKey(this.memberId, id, meta.version), meta.key);
		let plain: Uint8Array;
		if (meta.chunk && meta.chunk > 0) {
			// The first frame only: previews never pull a whole video in.
			const { body } = await this.bridge.fetchObject(this.memberId, id, meta.version, [0, Math.min(meta.chunk, maxBytes) + 28 - 1]);
			plain = await openChunk(key, body, 0, false);
		} else {
			const { body } = await this.bridge.fetchObject(this.memberId, id, meta.version);
			plain = await openWith(key, body);
		}
		return { bytes: plain.subarray(0, maxBytes), name: row.name, mime };
	}

	// ── streaming playback (the media service worker) ───────────────────

	/** A playable URL for a video/audio file: the scoped media service
	 * worker answers the browser's native Range requests with decrypted
	 * plaintext (the content key is handed over as a cloned, still
	 * non-extractable CryptoKey). Returns null where service workers are
	 * unavailable — the viewer falls back to the decrypted blob. */
	async mediaHandle(id: string, mime: string | null = null): Promise<{ url: string } | null> {
		const worker = await controllingMediaWorker();
		if (!worker) return null;
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null; version: number }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return null;
		const s = this.state.get();
		const row = s.files.find((f) => f.id === id);
		if (!row) return null;
		const priv = await this.bridge.storePrivate();
		const key = await unwrapPlacedKey(priv, places.fileKey(this.memberId, id, meta.version), meta.key);
		const url = `/media/${id}`;
		// The version rides along: the worker fetches exactly the version
		// this key was opened for (a newer one would not open with it).
		// (`headers`: the dev server's identity header — a service worker cannot
		// read the page's localStorage. Empty in production, where Access's
		// cookie rides every same-origin fetch, the worker's included.)
		await registerMedia(worker, { url, memberId: this.memberId, fileId: id, version: meta.version, key, chunk: meta.chunk, size: row.size, mime, headers: this.bridge.identityHeaders() });
		return { url };
	}

	// ── clipboard ───────────────────────────────────────────────────────

	copy(): void {
		const sel = this.state.get().selection;
		this.clipboard = { mode: "copy", files: sel.filter((s) => s.kind === "file").map((s) => s.id), folders: sel.filter((s) => s.kind === "folder").map((s) => s.id) };
		if (this.clipboard.files.length + this.clipboard.folders.length) this.bridge.toast("Copied");
	}

	cut(): void {
		const sel = this.state.get().selection;
		this.clipboard = { mode: "cut", files: sel.filter((s) => s.kind === "file").map((s) => s.id), folders: sel.filter((s) => s.kind === "folder").map((s) => s.id) };
		if (this.clipboard.files.length + this.clipboard.folders.length) this.bridge.toast("Cut");
	}

	async paste(): Promise<void> {
		const clip = this.clipboard;
		if (!clip) return;
		const folderId = this.state.get().folderId;
		if (clip.mode === "cut") {
			for (const id of clip.files) await this.bridge.apiSend("PATCH", `/api/v1/members/${this.memberId}/files/${id}`, { folderId });
			for (const id of clip.folders) await this.bridge.apiSend("PATCH", `/api/v1/members/${this.memberId}/files/folders/${id}`, { parentId: folderId });
			this.clipboard = null;
			await this.refresh();
			this.bridge.toast("Pasted (moved)");
			return;
		}
		// Copy = duplicate: open the bytes, seal them fresh (a copy is a new
		// file with a new content key — the original's history is untouched).
		for (const id of clip.files) {
			const plainParts: Uint8Array[] = [];
			await this.openBytes(id, undefined, async (plain) => {
				plainParts.push(plain);
			});
			const plain = concat(plainParts);
			const name = this.names.get(id) ?? "copy";
			await this.uploadOne(new File([plain as BlobPart], copyName(name)), plain, await this.fingerprint(plain), folderId);
		}
		await this.refresh();
		this.bridge.toast(`Duplicated ${clip.files.length} file${clip.files.length > 1 ? "s" : ""}`);
	}

	// ── the change feed (other devices' edits, within seconds) ──────────

	private async watchChanges(): Promise<void> {
		if (this.pollTimer) clearInterval(this.pollTimer);
		this.pollTimer = setInterval(() => void this.pollChanges(), 10_000);
		// (Node tests have no DOM — the visibility hook is browser-only.)
		if (typeof document !== "undefined") document.addEventListener("visibilitychange", this.onVisible);
	}

	private onVisible = () => {
		if (document.visibilityState === "visible") void this.pollChanges();
	};

	private async pollChanges(): Promise<void> {
		try {
			const s = this.state.get();
			void s;
			// The cursor starts at 0 the first time; each poll advances it.
			const since = this.cursor;
			const feed = await this.bridge.apiGet<{ cursor: number; changes: { seq: number; kind: string; data: unknown }[] }>(`/api/v1/members/${this.memberId}/files/changes?since=${since}&limit=500`);
			this.cursor = feed.cursor;
			// The index follows the feed's tombstones: trashed and purged
			// entries leave the search results exactly as they leave the lists.
			const gone: string[] = [];
			for (const c of feed.changes) {
				const d = c.data as { id?: string; file?: { id?: string; deleted?: boolean } };
				if ((c.kind === "file.put" && d.file?.deleted && d.file.id) || c.kind === "file.purge") gone.push(d.file?.id ?? d.id ?? "");
				if ((c.kind === "folder.put" && (d as { folder?: { deleted?: boolean } }).folder?.deleted && (d as { folder?: { id?: string } }).folder?.id) || c.kind === "folder.purge") gone.push((d as { id?: string }).id ?? "");
			}
			this.index?.remove(gone.filter(Boolean));
			if (feed.changes.length) await this.refresh();
		} catch {
			// offline — the next poll retries
		}
	}

	private cursor = 0;

	/** The wrapped content key (+ chunk/type/version) of ONE file's living
	 * version. The route is `POST …/files/keys { ids }` — a POST because the
	 * ids ride in the body (a batch can be hundreds long), and so that a key
	 * request is never a cacheable, prefetchable, history-logged GET URL.
	 * Asking for exactly the file being opened keeps the view's key material
	 * minimal (docs/ENCRYPTION.md: the listing never carries keys). */
	private keysFor<T>(id: string): Promise<T> {
		return this.bridge.apiSend<T>("POST", `/api/v1/members/${this.memberId}/files/keys`, { ids: [id] });
	}

	/** Info for the Get Info / details pane: everything readable, opened. */
	async info(id: string): Promise<{ name: string; kind: FileKind; size: number; version: number; createdAt: string; updatedAt: string; mime: string | null } | null> {
		const keys = await this.keysFor<{ keys: Record<string, { key: string; version: number; type: string | null; size: number }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return null;
		const priv = await this.bridge.storePrivate();
		const mime = meta.type ? await openPlacedText(priv, places.fileType(this.memberId, id, meta.version), meta.type).catch(() => null) : null;
		const s = this.state.get();
		const row = s.files.find((f) => f.id === id) ?? s.trashFiles.find((f) => f.id === id);
		return row ? { name: row.name, kind: row.kind, size: row.size, version: meta.version, createdAt: row.createdAt, updatedAt: row.updatedAt, mime } : null;
	}

	async refresh(): Promise<void> {
		const s = this.state.get();
		await this.list(s.folderId, { trash: s.trashMode });
	}

	dispose(): void {
		if (this.pollTimer) clearInterval(this.pollTimer);
		if (typeof document !== "undefined") document.removeEventListener("visibilitychange", this.onVisible);
		this.names.clear();
	}
}

interface FileRowJson {
	id: string;
	folder: string | null;
	name: string;
	size: number | string;
	version: number;
	createdAt: string;
	updatedAt: string;
	trashedWith?: string | null;
}

interface FolderJson {
	id: string;
	parent: string | null;
	name: string;
	createdAt: string;
	updatedAt: string;
	deletedAt?: string | null;
	trashedWith?: string | null;
}

function copyName(name: string): string {
	const dot = name.lastIndexOf(".");
	const base = dot > 0 ? name.slice(0, dot) : name;
	const ext = dot > 0 ? name.slice(dot) : "";
	return `${base} copy${ext}`;
}

export function concat(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}