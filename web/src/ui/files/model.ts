// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The explorer's data layer — framework-free, testable in Node (Lesson 9:
 * the model never touches the DOM; the views never touch fetch or crypto).
 *
 * Everything the server sends is *structure*: ids, sizes, times, and SEALED
 * names (`GV03:…`). This model decrypts names into an in-memory cache the
 * moment a listing arrives — plaintext exists only in this tab, only while
 * unlocked, and dies with the session.
 *
 * Selection, clipboard, history and the change feed live here too, so both
 * platform simulations (Windows 11 and macOS Finder) are two skins over one
 * grammar of operations — which is exactly the point of the simulation.
 */

import { store, type Store } from "../../lib/store.ts";
import { newContentKey, importContentKey, sealText, openText, sealWith, openWith, wrapContentKey, unwrapContentKey, type VaultPrivateKey, type SealTarget } from "../../vault/vault-crypto.ts";
import { sealChunked, openChunk, DEFAULT_CHUNK } from "../../vault/chunked-file.ts";
import { toBase64, fromBase64 } from "../../lib/encoding.ts";
import { kindOf, type FileKind } from "./icons.ts";

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
	storePrivate(): Promise<VaultPrivateKey>;
	storePublic(): Promise<SealTarget>;
	fetchObject(memberId: string, id: string, version: number | undefined, range?: [number, number]): Promise<{ body: Uint8Array; ck: string; chunk: number | null }>;
	fetchObjectStream(memberId: string, id: string, version: number | undefined, sink: (plain: Uint8Array) => Promise<void> | void): Promise<void>;
	putWhole(memberId: string, fields: Record<string, string>, sealed: Uint8Array): Promise<void>;
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

	private readonly bridge: FilesBridge;

	constructor(bridge: FilesBridge, memberId: string) {
		this.bridge = bridge;
		this.memberId = memberId;
		this.state = store<FilesState>({ folderId: null, folders: [], files: [], selection: [], sort: { by: "name", dir: "asc" }, loading: false, error: null, trashMode: false, trashFiles: [], trashFolders: [] });
	}

	subscribe(listener: () => void): () => void {
		return this.state.subscribe(() => listener());
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
				const name = this.names.get(f.id) ?? (await openText(priv, f.name));
				this.names.set(f.id, name);
				return { id: f.id, parent: f.parent, nameSealed: f.name, name, createdAt: f.createdAt, updatedAt: f.updatedAt, deletedAt: f.deletedAt ?? null, trashedWith: f.trashedWith ?? null };
			}),
		);
	}

	private async decryptFiles(rows: FileRowJson[]): Promise<FileRow[]> {
		const priv = await this.bridge.storePrivate();
		return Promise.all(
			rows.map(async (f) => {
				const name = this.names.get(f.id) ?? (await openText(priv, f.name));
				this.names.set(f.id, name);
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
		const pub = await this.bridge.storePublic();
		const sealed = await sealText(pub, newName.trim());
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
		const pub = await this.bridge.storePublic();
		const sealed = await sealText(pub, name.trim());
		const created = await this.bridge.apiSend<{ id: string }>("POST", `/api/v1/members/${this.memberId}/files/folders`, { name: sealed, parentId });
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
				void answer;
			}
			await this.uploadOne(file, plain, tag, folderId, twins.length ? ("version" as const) : undefined);
		}
		await this.refresh();
	}

	private async uploadOne(file: File, plain: Uint8Array, tag: string, folderId: string | null, asVersion?: "version"): Promise<void> {
		const pub = await this.bridge.storePublic();
		const ck = newContentKey();
		const key = await importContentKey(ck);
		const nameSealed = await sealText(pub, file.name);
		const typeSealed = await sealText(pub, file.type || "application/octet-stream");
		const ckSealed = await wrapContentKey(pub, ck);
		if (plain.length > 48 * 1024 * 1024) {
			const chunked = await sealChunked(key, plain, DEFAULT_CHUNK);
			await this.bridge.putMultipart(this.memberId, { ck: ckSealed, name: nameSealed, type: typeSealed, size: String(plain.length), chunk: String(DEFAULT_CHUNK), tag, ...(folderId ? { folder_id: folderId } : {}), ...(asVersion ? {} : {}) }, chunked, DEFAULT_CHUNK);
		} else {
			const sealed = await sealWith(key, plain);
			await this.bridge.putWhole(this.memberId, { ck: ckSealed, name: nameSealed, type: typeSealed, size: String(plain.length), tag, ...(folderId ? { folder_id: folderId } : {}) }, sealed);
		}
		void asVersion;
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
			const json = JSON.parse(await openText(priv, existing.sealed)) as { fp: string; idx: string };
			this.secrets = { fp: fromBase64(json.fp), idx: fromBase64(json.idx) };
			return;
		}
		const fp = crypto.getRandomValues(new Uint8Array(32));
		const idx = crypto.getRandomValues(new Uint8Array(32));
		const pub = await this.bridge.storePublic();
		const sealed = await sealText(pub, JSON.stringify({ fp: toBase64(fp), idx: toBase64(idx) }));
		await this.bridge.apiSend("PUT", `/api/v1/members/${this.memberId}/files/secrets`, { sealed });
		this.secrets = { fp, idx };
	}

	// ── download ────────────────────────────────────────────────────────

	/** Open a file's current version and hand the bytes to a download. */
	async download(id: string, name: string): Promise<void> {
		await this.openBytes(id, undefined, async (plain) => {
			// The save itself is browser-only (the Node test collects bytes).
			if (typeof document === "undefined") return;
			const url = URL.createObjectURL(new Blob([plain as BlobPart]));
			const a = document.createElement("a");
			a.href = url;
			a.download = name;
			a.click();
			setTimeout(() => URL.revokeObjectURL(url), 5000);
		});
		this.bridge.toast(`Downloaded “${name}”`);
	}

	/** Open + decrypt; chunked objects stream frame by frame (never whole). */
	async openBytes(id: string, version: number | undefined, sink: (plain: Uint8Array) => Promise<void> | void): Promise<void> {
		const keys = await this.bridge.apiGet<{ keys: Record<string, { key: string; chunk: number | null }> }>(`/api/v1/members/${this.memberId}/files/keys`);
		const meta = keys.keys[id];
		if (!meta) throw new Error("the file's key was not found");
		const chunk = meta.chunk;
		if (chunk && chunk > 0) {
			await this.bridge.fetchObjectStream(this.memberId, id, version, sink);
			return;
		}
		const { body, ck } = await this.bridge.fetchObject(this.memberId, id, version);
		const priv = await this.bridge.storePrivate();
		const key = await unwrapContentKey(priv, ck);
		await sink(await openWith(key, body));
	}

	/** A decrypted slice for previews (first bytes only; nothing stored). */
	async preview(id: string, maxBytes = 128 * 1024): Promise<{ bytes: Uint8Array; name: string; mime: string } | null> {
		const s = this.state.get();
		const row = s.files.find((f) => f.id === id) ?? s.trashFiles.find((f) => f.id === id);
		if (!row) return null;
		const keys = await this.bridge.apiGet<{ keys: Record<string, { key: string; chunk: number | null; type: string | null }> }>(`/api/v1/members/${this.memberId}/files/keys`);
		const meta = keys.keys[id];
		if (!meta) return null;
		const priv = await this.bridge.storePrivate();
		const mime = meta.type ? await openText(priv, meta.type) : "application/octet-stream";
		const key = await unwrapContentKey(priv, meta.key);
		let plain: Uint8Array;
		if (meta.chunk && meta.chunk > 0) {
			// The first frame only: previews never pull a whole video in.
			const { body } = await this.bridge.fetchObject(this.memberId, id, undefined, [0, Math.min(meta.chunk, maxBytes) + 28 - 1]);
			plain = await openChunk(key, body, 0, false);
		} else {
			const { body } = await this.bridge.fetchObject(this.memberId, id, undefined);
			plain = await openWith(key, body);
		}
		return { bytes: plain.subarray(0, maxBytes), name: row.name, mime };
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
			if (feed.changes.length) await this.refresh();
		} catch {
			// offline — the next poll retries
		}
	}

	private cursor = 0;

	/** Info for the Get Info / details pane: everything readable, opened. */
	async info(id: string): Promise<{ name: string; kind: FileKind; size: number; version: number; createdAt: string; updatedAt: string; mime: string | null } | null> {
		const keys = await this.bridge.apiGet<{ keys: Record<string, { key: string; version: number; type: string | null; size: number }> }>(`/api/v1/members/${this.memberId}/files/keys`);
		const meta = keys.keys[id];
		if (!meta) return null;
		const priv = await this.bridge.storePrivate();
		const mime = meta.type ? await openText(priv, meta.type) : null;
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