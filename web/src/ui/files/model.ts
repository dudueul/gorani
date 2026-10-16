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
import { controllingMediaWorker, registerDownload, registerMedia } from "../../lib/media-worker.ts";
import { openChunk, sealChunk, chunkFor, frameCount, MAX_FILE } from "../../vault/chunked-file.ts";
import type { UploadJournal, UploadRecord } from "../../lib/upload-journal.ts";
import { parseAudioMeta, type AudioMeta } from "../../vault/music-meta.ts";
import { toBase64, fromBase64 } from "../../lib/encoding.ts";
import { areaPath } from "../../lib/area.ts";
import { writePlace } from "./place.ts";
import { folderPath } from "./paths.ts";
import { kindOf, type FileKind } from "./icons.ts";
import { blobURL, revokeBlobURL } from "../../lib/blob-urls.ts";
import type { LocalIndexLike } from "../../vault/index.ts";
import type { Signer, Trust } from "../../vault/identity.ts";
import { checkContentHash, describeHashCheck, openContentHash, sha256Stream, signContentHashStamped, type HashCheck } from "../../vault/content-hash.ts";
import { checkVersionStamp, describeStamp, trustedTsas, type StampCheck, type TsaCert, type VersionStamp } from "../../vault/timestamp.ts";
import { SAMPLE_PASSWORD, isSampleType, originalType, sampleType, zipEncrypted } from "../../vault/samples.ts";
import { signIntake, type IntakeFields } from "../../vault/intake.ts";
import { acceptCustody, offerCustody, verifyChain, type CustodyCall, type CustodyChain } from "../../vault/custody.ts";
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
	/** A malware sample (commit 29e): the server's flag. The model also
	 * honours the sealed type's mark (isSample) — either one counts. */
	sample: boolean;
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
	/** The current folder's child folders — what the view lists. */
	folders: FolderRow[];
	/** Every folder of the area: the tree, breadcrumbs, "Move to…". (The
	 * server sends them whole with each listing; until commit 39l they were
	 * all shown as `folders` — every folder appeared inside every folder.) */
	tree: FolderRow[];
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
	/** `hash`: the version's signed content hash, still sealed (the
	 * `x-gorani-hash` header — commit 29d), or null when it has none. */
	fetchObject(memberId: string, id: string, version: number | undefined, range?: [number, number]): Promise<{ body: Uint8Array; ck: string; chunk: number | null; version: number; hash: string | null }>;
	fetchObjectStream(memberId: string, id: string, version: number | undefined, sink: (plain: Uint8Array) => Promise<void> | void): Promise<{ version: number; hash: string | null }>;
	putWhole(memberId: string, fields: Record<string, string>, sealed: Uint8Array): Promise<void>;
	/** Headers that identify this client to the API beyond its cookies (the
	 * dev server's identity header; nothing in production) — for fetches
	 * made outside the bridge, i.e. by the media service worker. */
	identityHeaders(): Record<string, string>;
	/**
	 * A GC01 upload, one part per frame (D12, docs/LARGE-FILES.md), in three
	 * steps the MODEL drives (FilesModel › sendFrames) — so it can journal
	 * each part and resume after a dropped connection or a closed tab.
	 * `multipartPart` retries what the network lost, never a refusal.
	 */
	multipartStart(memberId: string, plan: { size: number; chunk: number; newFileId: string }): Promise<{ uploadId: string; key: string; parts: number }>;
	multipartPart(memberId: string, uploadId: string, key: string, n: number, frame: Uint8Array): Promise<{ partNumber: number; etag: string }>;
	multipartComplete(memberId: string, uploadId: string, fields: Record<string, string>): Promise<void>;
	/** Where unfinished uploads are remembered (this browser's IndexedDB); absent → not resumable. */
	uploadJournal?: UploadJournal;
	/** The duplicate prompt (commit 39n): which file, where its twins are,
	 * how many files are still to come; the answer may stand for the rest. */
	confirmDuplicate(question: DuplicateQuestion): Promise<DuplicateAnswer>;
	toast(message: string): void;
	/** The member's identity (commit 29d, docs/CUSTODY.md › stage 4): the
	 * signer that vouches for what they upload, and the trust that checks
	 * what others did. Null until the team context is open — the member's
	 * own area works without it; an evidence case refuses an unsigned
	 * upload. Optional, so a test bridge may leave it out. */
	identity?(): { signer: Signer; trust: Trust } | null;
	/** What kind of area this is (commit 29g): an evidence case's uploads
	 * carry an intake record. Optional — a test bridge may leave it out. */
	areaKind?(): "evidence" | "working" | "own" | null;
	/** Ask the person for an upload batch's intake record (evidence only);
	 * null when they cancel. */
	intake?(files: File[]): Promise<IntakeFields | null>;
}

/** A file already in the area with exactly the same bytes. */
export interface DuplicateTwin {
	id: string;
	name: string;
	/** Its folder's path; "" at the top. */
	where: string;
}

/** What the duplicate prompt is told: the file, its twins, and how many
 * files of this upload are still to come. */
export interface DuplicateQuestion {
	file: { name: string; size: number };
	twins: DuplicateTwin[];
	later: number;
}

/** Skip this file or keep both — and whether that stands for every other
 * duplicate in this upload; null stops the upload. (Until 39n the prompt
 * was a bare OK/Cancel with a count: it never said WHICH file was already
 * there, or where, and a batch asked once per twin.) */
export type DuplicateAnswer = { action: "skip" | "keep"; forRest: boolean } | null;

/** Find duplicates (commit 39n): one set of files with exactly the same
 * bytes, oldest first. */
export interface DuplicateGroup {
	size: number;
	files: { id: string; name: string; folderId: string | null; where: string; updatedAt: string }[];
}

export class FilesModel {
	readonly state: Store<FilesState>;
	/** Plaintext names, in memory for this session only. */
	readonly names = new Map<string, string>();
	/** File fingerprints (HMAC of SHA-256), for the duplicate check. */
	readonly tags = new Map<string, string>();
	private secrets: { fp: Uint8Array; idx: Uint8Array } | null = null;
	private history: (string | null)[] = [null];
	private historyAt = 0;
	/** Where the explorer is going: the last listing asked for. The state
	 * moves only when a listing lands (list), so for a moment the screen is
	 * still where it was — a refresh, or the same folder opened twice, must
	 * go by where it is headed instead. */
	private target: { folderId: string | null; trash: boolean } = { folderId: null, trash: false };
	/** Each listing's number: one that lands after a newer one was asked for
	 * is dropped (two quick double-clicks; a change-feed refresh mid-walk). */
	private listSeq = 0;
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
		this.state = store<FilesState>({ folderId: null, folders: [], tree: [], files: [], selection: [], sort: { by: "name", dir: "asc" }, loading: false, error: null, trashMode: false, trashFiles: [], trashFolders: [] });
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

	/** Open the area, in `folder` when the address named one that exists. */
	async open(folder: string | null = null): Promise<void> {
		await this.list(folder);
		if (folder && !this.state.get().tree.some((f) => f.id === folder)) await this.list(null);
		this.history = [this.state.get().folderId];
		this.historyAt = 0;
		writePlace(this.memberId, this.state.get().folderId, "replace");
		void this.watchChanges();
		// Uploads that stopped part-way here (D12, 31b): say so once, and how
		// to continue — the parts already sent are not sent again.
		void this.unfinishedUploads()
			.then((u) => {
				if (!u.length) return;
				const list = u.map((x) => `“${x.name}” (${Math.floor((100 * x.done) / x.total)}%)`).join(", ");
				this.bridge.toast(`${u.length === 1 ? "An upload" : `${u.length} uploads`} stopped part-way: ${list} — choose the same file again to continue from where it stopped`);
			})
			.catch(() => undefined);
	}

	/** Go to a folder (null: the area's top). Leaves the Trash too — until
	 * commit 39l a folder opened from the Trash listed into the Trash view,
	 * and Home re-listed the folder you were in rather than the top. */
	async setFolder(id: string | null): Promise<void> {
		// The open folder, opened again (a double-click is two clicks first;
		// a tree row clicked twice): no new history entry, nothing to load.
		if (!this.target.trash && this.target.folderId === id && this.history[this.historyAt] === id) return;
		this.history = [...this.history.slice(0, this.historyAt + 1), id];
		this.historyAt++;
		writePlace(this.memberId, id, "push");
		await this.list(id);
	}

	/** The browser's Back/Forward brought the address here: follow it,
	 * without writing it again. */
	async follow(id: string | null): Promise<void> {
		if (!this.target.trash && this.target.folderId === id) return;
		this.history = [...this.history.slice(0, this.historyAt + 1), id];
		this.historyAt++;
		await this.list(id);
	}

	async back(): Promise<void> {
		if (this.historyAt > 0) {
			this.historyAt--;
			const id = this.history[this.historyAt] ?? null;
			writePlace(this.memberId, id, "replace");
			await this.list(id);
		}
	}

	async forward(): Promise<void> {
		if (this.historyAt < this.history.length - 1) {
			this.historyAt++;
			const id = this.history[this.historyAt] ?? null;
			writePlace(this.memberId, id, "replace");
			await this.list(id);
		}
	}

	get canBack(): boolean {
		return this.historyAt > 0;
	}

	get canForward(): boolean {
		return this.historyAt < this.history.length - 1;
	}

	/** List a folder (or the Trash) and show it — all at once: the folder,
	 * its contents and the mode change together when the listing lands.
	 * Until commit 39l the folder id changed first and the old contents
	 * stayed up under the new path until the new ones decrypted (Finder's
	 * next column showed the parent's files; a click there acted on them). */
	private async list(folderId: string | null, opts: { trash?: boolean } = {}): Promise<void> {
		const trash = Boolean(opts.trash);
		const seq = ++this.listSeq;
		this.target = { folderId, trash };
		this.set({ loading: true, error: null });
		try {
			if (trash) {
				const t = await this.bridge.apiGet<{ files: FileRowJson[]; folders: FolderJson[]; trashedWith: { id: string; with: string }[] }>(`${areaPath(this.memberId)}/files/trash`);
				const withMap = new Map(t.trashedWith.map((x) => [x.id, x.with]));
				const trashFiles = await this.decryptFiles(t.files.map((f) => ({ ...f, trashedWith: withMap.get(f.id) ?? null })));
				const trashFolders = await this.decryptFolders(t.folders.map((f) => ({ ...f, trashedWith: withMap.get(f.id) ?? null })));
				if (seq !== this.listSeq) return;
				this.set({ folderId, trashMode: true, trashFiles, trashFolders, selection: [], loading: false });
				return;
			}
			const l = await this.bridge.apiGet<{ files: FileRowJson[]; folders: FolderJson[] }>(`${areaPath(this.memberId)}/files/list?folder=${folderId ?? "root"}&limit=1000`);
			const tree = await this.decryptFolders(l.folders);
			const folders = tree.filter((f) => (f.parent ?? null) === folderId);
			const files = await this.decryptFiles(l.files);
			if (seq !== this.listSeq) return;
			this.set({ folderId, trashMode: false, folders, tree, files, selection: [], loading: false });
			// The local index learns every listing (names decrypted here, in
			// this browser only). Until commit 39l nothing fed it: search found
			// nothing and Recents stayed empty, whatever the vault held.
			const when = (iso: string) => Date.parse(iso) || Date.now();
			this.index?.upsert([
				...tree.map((f) => ({ id: f.id, kind: "folder" as const, folderId: f.parent ?? null, name: f.name, updatedAt: when(f.updatedAt || f.createdAt) })),
				...files.map((f) => ({ id: f.id, kind: "file" as const, folderId: f.folder ?? null, name: f.name, updatedAt: when(f.updatedAt || f.createdAt), size: f.size })),
			]);
		} catch (e) {
			if (seq !== this.listSeq) return;
			this.set({ folderId, trashMode: trash, loading: false, error: e instanceof Error ? e.message : String(e) });
		}
	}

	async openTrash(): Promise<void> {
		await this.list(this.target.folderId, { trash: true });
	}

	async closeTrash(): Promise<void> {
		await this.list(this.target.folderId);
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
				const sample = f.sample === true;
				return { id: f.id, folder: f.folder, nameSealed: f.name, name, kind: sample ? "sample" : kindOf(name), size: Number(f.size), version: f.version, createdAt: f.createdAt, updatedAt: f.updatedAt, trashedWith: f.trashedWith ?? null, sample };
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

	/** Exactly these (the marquee: until 39m it added each hit with a
	 * toggling select on every pointer move, so items flickered in and out). */
	selectOnly(items: Selection[]): void {
		this.set({ selection: items });
	}

	/** The sort's direction, set rather than flipped (the Sort by menu). */
	sortDirection(dir: SortState["dir"]): void {
		this.set({ sort: { ...this.state.get().sort, dir } });
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

	/** What kind of area this is (the shell knows; "own" outside a case). The
	 * menus offer custody only where it exists: an evidence case. */
	areaKind(): "evidence" | "working" | "own" | null {
		return this.bridge.areaKind?.() ?? null;
	}

	async rename(kind: "file" | "folder", id: string, newName: string): Promise<void> {
		if (!newName.trim()) return;
		const priv = await this.bridge.storePrivate();
		const sealed = await sealPlacedText(priv, kind === "file" ? places.fileName(this.memberId, id) : places.folderName(this.memberId, id), newName.trim());
		const path = kind === "file" ? `${areaPath(this.memberId)}/files/${id}` : `${areaPath(this.memberId)}/files/folders/${id}`;
		await this.bridge.apiSend("PATCH", path, kind === "file" ? { name: sealed } : { name: sealed });
		this.names.set(id, newName.trim());
		await this.refresh();
		this.bridge.toast(`Renamed to “${newName.trim()}”`);
	}

	async move(kind: "file" | "folder", ids: string[], folderId: string | null): Promise<void> {
		await this.moveItems(ids.map((id) => ({ kind, id })), folderId);
	}

	/** Move a selection — files and folders together — into a folder (null:
	 * the top). Until commit 39m every caller passed ONE kind for the lot,
	 * the first item's, so a folder dragged or moved along with files went
	 * to the files route and failed. Each item goes on its own; one the
	 * server refuses (a folder into its own subfolder) is reported, and the
	 * rest still move. */
	async moveItems(items: Selection[], folderId: string | null): Promise<void> {
		const failed: string[] = [];
		let moved = 0;
		for (const it of items) {
			if (it.kind === "folder" && it.id === folderId) continue; // a folder onto itself: nothing to do
			const path = it.kind === "file" ? `${areaPath(this.memberId)}/files/${it.id}` : `${areaPath(this.memberId)}/files/folders/${it.id}`;
			try {
				await this.bridge.apiSend("PATCH", path, it.kind === "file" ? { folderId } : { parentId: folderId });
				moved++;
			} catch (e) {
				failed.push(`“${this.names.get(it.id) ?? it.id}”: ${e instanceof Error ? e.message : String(e)}`);
			}
		}
		await this.refresh();
		this.bridge.toast([moved ? `Moved ${moved} item${moved > 1 ? "s" : ""}` : "", failed.length ? `not moved — ${failed.join("; ")}` : ""].filter(Boolean).join(" · ") || "Nothing to move");
	}

	async trash(kind: "file" | "folder", ids: string[]): Promise<void> {
		await this.trashItems(ids.map((id) => ({ kind, id })));
	}

	/** To the Trash, files and folders together (see moveItems: until 39m a
	 * mixed selection was deleted as the first item's kind). */
	async trashItems(items: Selection[]): Promise<void> {
		for (const it of items) {
			const path = it.kind === "file" ? `${areaPath(this.memberId)}/files/${it.id}` : `${areaPath(this.memberId)}/files/folders/${it.id}`;
			await this.bridge.apiSend("DELETE", path);
		}
		await this.refresh();
		this.bridge.toast(`Moved ${items.length} item${items.length > 1 ? "s" : ""} to the Trash`);
	}

	async restore(files: string[], folders: string[]): Promise<void> {
		await this.bridge.apiSend("POST", `${areaPath(this.memberId)}/files/trash/restore`, { files, folders });
		await this.openTrash();
		this.bridge.toast(`Restored ${files.length + folders.length} item${files.length + folders.length > 1 ? "s" : ""}`);
	}

	async newFolder(parentId: string | null, name: string): Promise<string> {
		// The id first, then the name sealed into it (the place names the folder).
		const id = newItemId();
		const sealed = await sealPlacedText(await this.bridge.storePrivate(), places.folderName(this.memberId, id), name.trim());
		const created = await this.bridge.apiSend<{ id: string }>("POST", `${areaPath(this.memberId)}/files/folders`, { id, name: sealed, parentId });
		await this.refresh();
		return created.id;
	}

	/** Upload: seal in the browser, fingerprint, ask about duplicates, send.
	 * `sample`: upload as malware samples (commit 29e) — marked from the
	 * first byte, so nothing ever previews them in between. */
	async upload(files: File[], { sample = false }: { sample?: boolean } = {}): Promise<void> {
		await this.ensureSecrets();
		const folderId = this.state.get().folderId;
		// An evidence case asks where the batch came from, once, before a
		// byte is sealed (commit 29g): each file signs its own record of it.
		let intake: IntakeFields | null = null;
		if (this.bridge.areaKind?.() === "evidence") {
			intake = (await this.bridge.intake?.(files)) ?? null;
			if (!intake) {
				this.bridge.toast("Upload cancelled — an evidence file needs its intake record");
				return;
			}
		}
		// "Do the same for the rest of this upload", once answered.
		let standing: "skip" | "keep" | null = null;
		for (const [i, file] of files.entries()) {
			if (file.size > MAX_FILE) {
				this.bridge.toast(`“${file.name}” is ${(file.size / 1024 ** 3).toFixed(1)} GiB — a file is at most 255 GiB`);
				continue;
			}
			// One SHA-256, two uses: the duplicate tag (keyed, below) and the
			// signed content hash (uploadOne) — read once, streamed (D12).
			const digest = await digestOf(file);
			const tag = await this.fingerprint(digest);
			// The duplicate check: same size on the server, compare tags locally.
			const same = await this.bridge.apiGet<{ files: { id: string; tag: string | null; folder?: string | null; name?: string | null }[] }>(`${areaPath(this.memberId)}/files/match?size=${file.size}`);
			const twins = same.files.filter((x) => x.tag && x.tag === tag);
			if (twins.length) {
				let action = standing;
				if (!action) {
					const answer = await this.bridge.confirmDuplicate({ file: { name: file.name, size: file.size }, twins: await this.describeTwins(twins), later: files.length - i - 1 });
					if (!answer) {
						this.bridge.toast(`Upload stopped at “${file.name}”`);
						break;
					}
					action = answer.action;
					if (answer.forRest) standing = answer.action;
				}
				if (action === "skip") {
					this.bridge.toast(`Skipped “${file.name}” (already here)`);
					continue;
				}
				// "keep" and "version" both store the bytes again as a new file:
				// identical bytes as a new VERSION of the twin would record
				// nothing new. (A dead `asVersion` parameter used to pretend
				// otherwise; removed in commit 25.)
			}
			await this.uploadOne(file, tag, folderId, hexOf(digest), sample, intake);
		}
		await this.refresh();
	}

	/** Find duplicates: the area's files that have exactly the same bytes as
	 * another (same size and keyed tag — files_store.rs › files_duplicates),
	 * grouped, each copy named (opened here) and placed in its folder. */
	async findDuplicates(): Promise<DuplicateGroup[]> {
		const res = await this.bridge.apiGet<{ files: { id: string; size: number; tag: string; folder: string | null; name: string; updatedAt: string }[] }>(`${areaPath(this.memberId)}/files/duplicates`);
		const priv = await this.bridge.storePrivate();
		const tree = this.state.get().tree;
		const groups = new Map<string, DuplicateGroup>();
		for (const r of res.files) {
			const key = `${r.size}:${r.tag}`;
			const group = groups.get(key) ?? { size: Number(r.size), files: [] };
			group.files.push({ id: r.id, folderId: r.folder ?? null, name: await this.openName(priv, places.fileName(this.memberId, r.id), r.id, r.name), where: r.folder ? folderPath(tree, r.folder) : "", updatedAt: r.updatedAt });
			groups.set(key, group);
		}
		return [...groups.values()].filter((g) => g.files.length > 1);
	}

	/** The twins as the prompt shows them: each one's name (opened here,
	 * from the sealed name the match route returns) and its folder's path. */
	private async describeTwins(rows: { id: string; folder?: string | null; name?: string | null }[]): Promise<DuplicateTwin[]> {
		const priv = await this.bridge.storePrivate();
		const tree = this.state.get().tree;
		return Promise.all(
			rows.map(async (r) => ({
				id: r.id,
				name: r.name ? await this.openName(priv, places.fileName(this.memberId, r.id), r.id, r.name) : (this.names.get(r.id) ?? "a file"),
				where: r.folder ? folderPath(tree, r.folder) : "",
			})),
		);
	}

	private async uploadOne(file: File, tag: string, folderId: string | null, sha256: string, sample = false, intakeFields: IntakeFields | null = null): Promise<void> {
		const priv = await this.bridge.storePrivate();
		// An upload of this very file that stopped part-way (D12, 31b): carry
		// on with the SAME id, key and signed record its stored frames were
		// sealed with — the journal knows it by a keyed fingerprint of the
		// file's name, size, time and SHA-256, never by its name.
		const journal = file.size > WHOLE_LIMIT ? this.bridge.uploadJournal : undefined;
		const journalKey = journal ? await this.fingerprint(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`gorani-upload-v1\n${file.name}\n${file.size}\n${file.lastModified}\n${sha256}`)))) : null;
		const prior = journal && journalKey ? await journal.get(journalKey) : null;
		if (journal && journalKey && prior && prior.area === this.memberId && prior.size === file.size) {
			const key = await unwrapPlacedKey(priv, places.fileKey(this.memberId, prior.fileId, 1), prior.fields.ck ?? "");
			this.bridge.toast(`Resuming “${file.name}” from part ${prior.parts.length + 1} of ${frameCount(file.size, prior.chunk)}`);
			try {
				await this.sendFrames(file, key, prior.chunk, prior.fields, { journal, key: journalKey, prior });
				return;
			} catch (e) {
				// The server forgot it (the housekeeping window passed, or it was
				// discarded): drop the record and start this file over.
				if (!/no such upload/.test(String(e))) throw e;
				await journal.delete(journalKey);
				this.bridge.toast(`The earlier upload of “${file.name}” is gone from the server — starting over`);
			}
		}
		// The file id first: the name, the type and the content key are sealed
		// INTO places that name it (O6) — so the server cannot move them to
		// another file, and could not have made them up (it lacks the PSK).
		// A new file is version 1.
		const id = newItemId();
		const ck = newContentKey();
		const key = await importContentKey(ck);
		const nameSealed = await sealPlacedText(priv, places.fileName(this.memberId, id), file.name);
		// A sample's type is the client's own mark (samples.ts): sealed, so a
		// server that clears its readable flag cannot make it renderable.
		const typeSealed = await sealPlacedText(priv, places.fileType(this.memberId, id, 1), sample ? sampleType(file.type) : file.type || "application/octet-stream");
		const ckSealed = await wrapPlacedKey(priv, places.fileKey(this.memberId, id, 1), ck);
		ck.fill(0);
		// Music metadata (docs/MUSIC.md): the tags exist only in plaintext we
		// already hold, so parse them here and seal the summary — the library
		// feed opens these blobs instead of ever re-reading the audio.
		// (Never for a sample: a tag parser is attack surface too.)
		let mmeta: string | undefined;
		if (!sample && file.type.startsWith("audio/") && file.size <= TAG_PARSE_LIMIT) {
			const meta = parseAudioMeta(new Uint8Array(await file.arrayBuffer()));
			if (meta) mmeta = await sealPlacedText(priv, places.fileMusic(this.memberId, id, 1), JSON.stringify(meta));
		}
		// The uploader's signature over SHA-256 of the plaintext (commit 29d,
		// content-hash.ts) — sealed into version 1's place. Sent whenever the
		// member's identity is open; an evidence case refuses an upload
		// without one, so there the missing identity is said plainly.
		const me = this.bridge.identity?.() ?? null;
		// With it, the imprint the deployment's timestamp authority stamps
		// (commit 29j, timestamp.ts) — SHA-256 of the signature, nothing more.
		const signed = me ? await signContentHashStamped(me.signer, priv, this.memberId, id, 1, sha256, file.size) : undefined;
		const hash = signed?.sealed;
		// …and, in an evidence case, its intake record, sealed into this
		// file's place and signed the same way (commit 29g, intake.ts).
		const intake = me && intakeFields ? await signIntake(me.signer, priv, this.memberId, id, intakeFields) : undefined;
		const extra = { ...(mmeta ? { mmeta } : {}), ...(signed ? { hash: signed.sealed, stamp: signed.stamp } : {}), ...(intake ? { intake } : {}), ...(sample ? { sample: "1" } : {}), ...(folderId ? { folder_id: folderId } : {}) };
		try {
			if (file.size > WHOLE_LIMIT) {
				// GC01 frames, each read and sealed only when the bridge is ready
				// to send it (D12): the chunk grows with the file so no upload
				// needs more than 10 000 parts (chunkFor, docs/LARGE-FILES.md).
				const chunk = chunkFor(file.size);
				await this.sendFrames(file, key, chunk, { file_id: id, ck: ckSealed, name: nameSealed, type: typeSealed, size: String(file.size), chunk: String(chunk), tag, ...extra }, journal && journalKey ? { journal, key: journalKey, prior: null } : null);
			} else {
				const sealed = await sealWith(key, new Uint8Array(await file.arrayBuffer()));
				await this.bridge.putWhole(this.memberId, { file_id: id, ck: ckSealed, name: nameSealed, type: typeSealed, size: String(file.size), tag, ...extra }, sealed);
			}
		} catch (e) {
			if (!hash && /signed content hash/.test(String(e))) throw new Error("this evidence case takes only signed uploads, and your identity is not open yet — wait for the team to open (or see Team › People), then try again");
			throw e;
		}
	}

	/**
	 * Send a file as GC01 frames (D12): each frame read and sealed only when
	 * it is next, sent, journalled, dropped — memory never grows with the
	 * file. With a journal, every part that lands is recorded, so a stopped
	 * upload continues from its first missing part (31b); `resume.prior` is
	 * that record. The journal entry goes when the server confirms the file.
	 */
	private async sendFrames(file: File, key: CryptoKey, chunk: number, fields: Record<string, string>, resume: { journal: UploadJournal; key: string; prior: UploadRecord | null } | null): Promise<void> {
		const count = frameCount(file.size, chunk);
		const fileId = fields.file_id ?? "";
		let rec = resume?.prior ?? null;
		if (!rec) {
			const start = await this.bridge.multipartStart(this.memberId, { size: file.size, chunk, newFileId: fileId });
			if (start.parts !== count) throw new Error(`the server planned ${start.parts} parts for ${count} frames`);
			rec = { area: this.memberId, fileId, uploadId: start.uploadId, objectKey: start.key, chunk, size: file.size, fields, parts: [], startedAt: new Date().toISOString() };
			await resume?.journal.put(resume.key, rec);
		}
		const step = Math.max(1, Math.floor(count / 4));
		for (let p = rec.parts.length + 1; p <= count; p++) {
			const i = p - 1;
			const frame = await sealChunk(key, new Uint8Array(await file.slice(i * chunk, Math.min(file.size, p * chunk)).arrayBuffer()), i, p === count);
			rec.parts.push(await this.bridge.multipartPart(this.memberId, rec.uploadId, rec.objectKey, p, frame));
			await resume?.journal.put(resume.key, rec);
			if (count >= 100 && p % step === 0 && p < count) this.bridge.toast(`Uploading “${file.name}” — ${Math.round((100 * p) / count)}% (${p} of ${count} parts)`);
		}
		const { file_id: _id, ...rest } = rec.fields;
		void _id;
		await this.bridge.multipartComplete(this.memberId, rec.uploadId, { ...rest, key: rec.objectKey, parts: JSON.stringify(rec.parts) });
		await resume?.journal.delete(resume.key);
	}

	/**
	 * Uploads in this area that stopped part-way (D12, 31b), with their
	 * names opened — for the explorer to say so. Choosing the same file
	 * again resumes one; `discardUpload` gives one up.
	 */
	async unfinishedUploads(): Promise<{ key: string; name: string; done: number; total: number; startedAt: string }[]> {
		const journal = this.bridge.uploadJournal;
		if (!journal) return [];
		const priv = await this.bridge.storePrivate();
		const out: { key: string; name: string; done: number; total: number; startedAt: string }[] = [];
		for (const { key, record } of await journal.list(this.memberId)) {
			const name = await openPlacedText(priv, places.fileName(this.memberId, record.fileId), record.fields.name ?? "").catch(() => "(a file)");
			out.push({ key, name, done: record.parts.length, total: frameCount(record.size, record.chunk), startedAt: record.startedAt });
		}
		return out;
	}

	/** Give up an unfinished upload: the server aborts it (its parts are freed), the journal forgets it. */
	async discardUpload(key: string): Promise<void> {
		const journal = this.bridge.uploadJournal;
		const rec = journal ? await journal.get(key) : null;
		if (!journal || !rec) return;
		await this.bridge.apiSend("DELETE", `${areaPath(this.memberId)}/files/uploads/${rec.uploadId}`).catch(() => undefined);
		await journal.delete(key);
	}

	/**
	 * The music library (docs/MUSIC.md): one feed of sealed metadata blobs,
	 * opened with the store key — browsing the library never decrypts the
	 * audio itself. Blobs we can no longer open (a rotated key's leftovers)
	 * are skipped honestly rather than failing the library.
	 */
	async musicLibrary(): Promise<(AudioMeta & { id: string; version: number; size: number })[]> {
		const feed = await this.bridge.apiGet<{ tracks: { id: string; version: number; blobSealed: string; size: number }[] }>(`${areaPath(this.memberId)}/files/music`);
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

	/** The duplicate tag: HMAC(fp, SHA-256(plaintext)) — keyed, so the server
	 * cannot compare it with a hash it knows. Takes the digest, which the
	 * upload also signs. */
	private async fingerprint(digest: Uint8Array): Promise<string> {
		await this.ensureSecrets();
		const { fp } = this.secrets!;
		const subtle = crypto.subtle;
		const hmac = await subtle.importKey("raw", fp as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		const sig = new Uint8Array(await subtle.sign("HMAC", hmac, digest as BufferSource));
		return [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
	}

	/** The files secrets {fp, idx}, sealed to the store key by the first device. */
	private async ensureSecrets(): Promise<void> {
		if (this.secrets) return;
		const priv = await this.bridge.storePrivate();
		const existing = await this.bridge.apiGet<{ sealed: string | null }>(`${areaPath(this.memberId)}/files/secrets`);
		if (existing.sealed) {
			const json = JSON.parse(await openPlacedText(priv, places.storeSecrets(this.memberId), existing.sealed)) as { fp: string; idx: string };
			this.secrets = { fp: fromBase64(json.fp), idx: fromBase64(json.idx) };
			return;
		}
		const fp = crypto.getRandomValues(new Uint8Array(32));
		const idx = crypto.getRandomValues(new Uint8Array(32));
		const sealed = await sealPlacedText(priv, places.storeSecrets(this.memberId), JSON.stringify({ fp: toBase64(fp), idx: toBase64(idx) }));
		await this.bridge.apiSend("PUT", `${areaPath(this.memberId)}/files/secrets`, { sealed });
		this.secrets = { fp, idx };
	}

	// ── download ────────────────────────────────────────────────────────

	/** Open a file's current version and hand the bytes to ONE download.
	 *
	 * (Commit 24: the sink used to start a browser download per decrypted
	 * frame — a 100 MB file arrived as thirteen 8 MiB pieces. The frames are
	 * collected and saved as one Blob; a Blob of parts is not a copy.) */
	async download(id: string, name: string): Promise<void> {
		// A large chunked file streams through the media worker straight to
		// the browser's own download (D12, 31c) — never into this tab.
		if (await this.streamDownload(id, name)) return;
		const parts: Uint8Array[] = [];
		// The signed content hash is checked on the way (commit 29d): the
		// bytes pass through SHA-256 as they are collected, frame by frame.
		const h = await sha256Stream();
		let size = 0;
		const served = await this.openBytes(id, undefined, (plain) => {
			parts.push(plain);
			h.update(plain);
			size += plain.length;
		});
		const sha256 = h.hex();
		const check = await this.checkHash(id, served, { sha256, size });
		// A sample (or a file whose type does not verify) leaves only zipped
		// under "infected" (commit 29e, samples.ts) — never raw on disk.
		const policy = await this.renderPolicy(id);
		if (policy !== "normal") {
			const zipped = zipEncrypted(name, concat(parts));
			this.save(zipped, `${name}.zip`);
			const why = policy === "sample" ? "a malware sample" : "its type does not verify, so it is treated as a sample";
			this.bridge.toast(`Downloaded “${name}.zip” — ${why}, zipped (password: ${SAMPLE_PASSWORD}); SHA-256 ${sha256}${check.status === "unsigned" ? "" : ` — ${describeHashCheck(check)}`}`);
			return;
		}
		this.save(parts, name);
		this.bridge.toast(check.status === "unsigned" ? `Downloaded “${name}”` : `Downloaded “${name}” — ${describeHashCheck(check)}`);
	}

	/**
	 * The streamed download (D12, docs/LARGE-FILES.md › 31c): above
	 * STREAM_DOWNLOAD_AT, a chunked file goes through the media service
	 * worker — decrypted a window of frames at a time into the browser's own
	 * download — and its SHA-256 comes back to be checked against the
	 * uploader's signed record, as the in-tab path checks it. False when
	 * this path does not apply (small, whole, a sample, no worker); a file
	 * too large for the tab with no worker is refused rather than tried.
	 */
	private async streamDownload(id: string, name: string): Promise<boolean> {
		const row = this.state.get().files.find((f) => f.id === id);
		if (!row || row.size <= STREAM_DOWNLOAD_AT) return false;
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null; version: number; type: string | null; sample?: boolean; hash?: string | null }> }>(id);
		const meta = keys.keys[id];
		if (!meta?.chunk) return false;
		if ((await this.policyOf(meta, id, null)) !== "normal") {
			// A sample leaves only zipped under "infected" — in this tab (31d streams the export's).
			if (row.size > IN_TAB_LIMIT) throw new Error(`“${name}” is a sample of ${(row.size / 1024 ** 3).toFixed(1)} GiB — too large to zip in the browser; export the case instead`);
			return false;
		}
		const worker = await controllingMediaWorker(2000);
		if (!worker) {
			if (row.size > IN_TAB_LIMIT) throw new Error(`“${name}” is ${(row.size / 1024 ** 3).toFixed(1)} GiB: it downloads through the media worker, which is not running — reload the page and try again`);
			return false;
		}
		const priv = await this.bridge.storePrivate();
		const key = await unwrapPlacedKey(priv, places.fileKey(this.memberId, id, meta.version), meta.key);
		const url = `/media/dl/${toBase64(crypto.getRandomValues(new Uint8Array(18))).replace(/\+/g, "-").replace(/\//g, "_")}`;
		const { done } = await registerDownload(worker, { url, memberId: this.memberId, fileId: id, version: meta.version, key, chunk: meta.chunk, size: row.size, name, headers: this.bridge.identityHeaders() });
		if (typeof document !== "undefined") {
			// A NAVIGATION to the worker's URL, not <a download>: Chromium sends a
			// download-attribute request straight to the network, past the
			// worker; a navigation the worker answers, and its attachment answer
			// downloads while this page stays where it is.
			const a = document.createElement("a");
			a.href = url;
			a.click();
		}
		this.bridge.toast(`Downloading “${name}” (${(row.size / 1024 ** 3).toFixed(1)} GiB) — it is checked against its signature when it finishes`);
		void done.then(async (r) => {
			if (!r.ok || !r.sha256) return this.bridge.toast(`⚠ “${name}” did not finish downloading: ${r.error ?? "stopped"} — the file on disk is incomplete`);
			const check = await this.checkHash(id, { version: meta.version, hash: meta.hash ?? null }, { sha256: r.sha256, size: r.size ?? 0 });
			this.bridge.toast(check.status === "unsigned" ? `Downloaded “${name}” — SHA-256 ${r.sha256}` : `Downloaded “${name}” — ${describeHashCheck(check)}`);
		});
		return true;
	}

	/** The last download's parts — what a Node test can inspect (the browser saves them). */
	lastSaved: { name: string; parts: Uint8Array[] } | null = null;

	/** Save parts as one file. The save itself is browser-only (a Blob of
	 * parts is not a copy); a Node test reads `lastSaved`. */
	private save(parts: Uint8Array[], name: string): void {
		this.lastSaved = { name, parts };
		if (typeof document === "undefined") return;
		const url = blobURL(new Blob(parts as BlobPart[], { type: "application/octet-stream" }));
		const a = document.createElement("a");
		a.href = url;
		a.download = name;
		a.click();
		setTimeout(() => revokeBlobURL(url), 5000);
	}

	// ── malware samples (commit 29e, docs/CUSTODY.md › stage 5) ─────────

	/**
	 * What may be RENDERED of a file: `normal`; `sample` — either mark says
	 * so (the server's flag, or the sealed type); `unverified` — the type is
	 * missing or does not open in its place. A server that wanted a sample
	 * rendered would have to hide BOTH marks, and the only way it could
	 * touch the sealed one (remove or garble it) lands here, refused like a
	 * sample. Only `normal` is ever previewed, played or opened.
	 */
	async renderPolicy(id: string): Promise<"normal" | "sample" | "unverified"> {
		if (this.rowOf(id)?.sample) return "sample";
		const keys = await this.keysFor<{ keys: Record<string, { type: string | null; version: number; sample?: boolean }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return "unverified";
		return this.policyOf(meta, id, null);
	}

	private async policyOf(meta: { type: string | null; version: number; sample?: boolean }, id: string, opened: { mime: string | null; ok: boolean } | null): Promise<"normal" | "sample" | "unverified"> {
		if (meta.sample || this.rowOf(id)?.sample) return "sample";
		if (!meta.type) return "unverified";
		const o = opened ?? (await this.openType(meta, id));
		if (!o.ok) return "unverified";
		return isSampleType(o.mime) ? "sample" : "normal";
	}

	private async openType(meta: { type: string | null; version: number }, id: string): Promise<{ mime: string | null; ok: boolean }> {
		if (!meta.type) return { mime: null, ok: false };
		try {
			return { mime: await openPlacedText(await this.bridge.storePrivate(), places.fileType(this.memberId, id, meta.version), meta.type), ok: true };
		} catch {
			return { mime: null, ok: false };
		}
	}

	private rowOf(id: string): FileRow | undefined {
		const s = this.state.get();
		return s.files.find((f) => f.id === id) ?? s.trashFiles.find((f) => f.id === id);
	}

	/**
	 * Mark a file as a malware sample — ONE WAY (the server refuses to
	 * unmark). Every version's type is re-sealed with the sample mark in
	 * the same request, keeping the original type for display; the server
	 * refuses a mark that leaves a version out.
	 */
	async markSample(id: string): Promise<void> {
		const priv = await this.bridge.storePrivate();
		const types: Record<string, string> = {};
		let after = 0;
		for (;;) {
			const page = await this.bridge.apiGet<{ items: { row: number; a: string; b: string; v1: string; v2: string | null }[]; next: number | null }>(`${areaPath(this.memberId)}/files/sealed?kind=version&file=${encodeURIComponent(id)}&after=${after}&limit=500`);
			for (const it of page.items) {
				const version = Number(it.b);
				const place = places.fileType(this.memberId, id, version);
				let original: string | null = null;
				if (it.v2) {
					try {
						original = await openPlacedText(priv, place, it.v2);
					} catch {
						original = null; // a type that does not open: marked anyway, its original unknown
					}
				}
				types[String(version)] = await sealPlacedText(priv, place, original && isSampleType(original) ? original : sampleType(original));
			}
			if (page.next === null) break;
			after = page.next;
		}
		await this.bridge.apiSend("PATCH", `${areaPath(this.memberId)}/files/${id}`, { sample: true, types });
		await this.refresh();
		this.bridge.toast(`“${this.names.get(id) ?? id}” is a malware sample now — never previewed, never shared by link, downloaded zipped (password: ${SAMPLE_PASSWORD})`);
	}

	/**
	 * Verify a version's content against its uploader's signature: open it,
	 * hash what decrypted, check the record (content-hash.ts). Reads every
	 * byte — the claim is about all of them.
	 */
	async verify(id: string, version?: number): Promise<HashCheck> {
		return (await this.verifyServed(id, version)).check;
	}

	private async verifyServed(id: string, version?: number): Promise<{ check: HashCheck; served: { version: number; hash: string | null } }> {
		const h = await sha256Stream();
		let size = 0;
		const served = await this.openBytes(id, version, (plain) => {
			h.update(plain);
			size += plain.length;
		});
		return { check: await this.checkHash(id, served, { sha256: h.hex(), size }), served };
	}

	/**
	 * The served version's trusted timestamp (commit 29j), checked HERE: the
	 * token against its signature's imprint, and the TSA's key against the
	 * leads' certifications THIS member's trust accepts.
	 */
	async stamp(id: string, served: { version: number; hash: string | null }): Promise<StampCheck> {
		const me = this.bridge.identity?.() ?? null;
		const [stamps, tsa] = await Promise.all([
			this.bridge.apiGet<{ versions: VersionStamp[] }>(`${areaPath(this.memberId)}/files/${id}/stamps`),
			this.bridge.apiGet<{ certs: TsaCert[] }>("/api/v1/family/tsa").catch(() => ({ certs: [] as TsaCert[] })),
		]);
		const record = await openContentHash(await this.bridge.storePrivate(), this.memberId, id, served.version, served.hash);
		return checkVersionStamp(record, stamps.versions.find((v) => v.version === served.version), await trustedTsas(me?.trust ?? null, tsa.certs));
	}

	// ── custody (commit 29g, docs/CUSTODY.md › stage 6) ─────────────────

	private custodyCall: CustodyCall = <T>(method: "GET" | "POST" | "DELETE", path: string, body?: unknown) => (method === "GET" ? this.bridge.apiGet<T>(path) : this.bridge.apiSend<T>(method, path, body));

	private identityOrThrow(): { signer: Signer; trust: Trust } {
		const me = this.bridge.identity?.() ?? null;
		if (!me) throw new Error("your identity is not open yet — custody is signed and checked with it");
		return me;
	}

	/** A file's custody chain, verified by THIS member's client. */
	async custody(id: string): Promise<{ chain: CustodyChain; me: string } & Awaited<ReturnType<typeof verifyChain>>> {
		const me = this.identityOrThrow();
		const chain = await this.bridge.apiGet<CustodyChain>(`${areaPath(this.memberId)}/files/${id}/custody`);
		return { chain, me: me.signer.member, ...(await verifyChain(await this.bridge.storePrivate(), me.trust, this.memberId, id, chain)) };
	}

	/** Hand a file over (the custodian): the next link, signed. */
	async offerCustody(id: string, to: string, reason: string): Promise<void> {
		const me = this.identityOrThrow();
		const c = await this.custody(id);
		await offerCustody(this.custodyCall, me.signer, await this.bridge.storePrivate(), areaPath(this.memberId), this.memberId, id, c.chain, to, reason);
		this.bridge.toast(`Offered “${this.names.get(id) ?? id}” to ${to} — custody moves when they accept`);
	}

	/** Accept the open offer made to this member. */
	async acceptCustody(id: string): Promise<void> {
		const me = this.identityOrThrow();
		const c = await this.custody(id);
		if (!c.pending || c.pending.to !== me.signer.member) throw new Error("no offer of this file is waiting for you");
		await acceptCustody(this.custodyCall, me.signer, me.trust, await this.bridge.storePrivate(), areaPath(this.memberId), this.memberId, id, c.pending);
		this.bridge.toast(`You hold “${this.names.get(id) ?? id}” now — signed by you and ${c.pending.from}`);
	}

	/** `verify`, said to the person (the explorers' "Verify signature"). */
	async verifyAndReport(id: string): Promise<HashCheck | null> {
		const name = this.names.get(id) ?? id;
		try {
			const { check, served } = await this.verifyServed(id);
			// And when it was signed, by a third party — where the deployment stamps.
			const stamp = check.status === "unsigned" ? null : await this.stamp(id, served).catch(() => null);
			const when = stamp && !(stamp.status === "absent" && /no timestamp authority/.test(stamp.why)) ? ` · ${describeStamp(stamp)}` : "";
			this.bridge.toast(`“${name}”: ${describeHashCheck(check)}${when}`);
			return check;
		} catch (e) {
			this.bridge.toast(`“${name}”: could not verify — ${e instanceof Error ? e.message : String(e)}`);
			return null;
		}
	}

	private async checkHash(id: string, served: { version: number; hash: string | null }, actual: { sha256: string; size: number }): Promise<HashCheck> {
		const me = this.bridge.identity?.() ?? null;
		return checkContentHash(await this.bridge.storePrivate(), me?.trust ?? null, this.memberId, id, served.version, served.hash, actual);
	}

	/** Open + decrypt; chunked objects stream frame by frame (never whole).
	 * Returns which version the bytes were and its sealed content hash. */
	async openBytes(id: string, version: number | undefined, sink: (plain: Uint8Array) => Promise<void> | void): Promise<{ version: number; hash: string | null }> {
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null }> }>(id);
		const meta = keys.keys[id];
		if (!meta) throw new Error("the file's key was not found");
		const chunk = meta.chunk;
		if (chunk && chunk > 0) return this.bridge.fetchObjectStream(this.memberId, id, version, sink);
		const { body, ck, version: served, hash } = await this.bridge.fetchObject(this.memberId, id, version);
		// The key opens only from the place of the version the bytes ARE (and,
		// asked for a version, it must be that one).
		if (version !== undefined && served !== version) throw new Error("the server answered with another version");
		const priv = await this.bridge.storePrivate();
		const key = await unwrapPlacedKey(priv, places.fileKey(this.memberId, id, served), ck);
		await sink(await openWith(key, body));
		return { version: served, hash };
	}

	/** A decrypted slice for previews (first bytes only; nothing stored). */
	async preview(id: string, maxBytes = 128 * 1024): Promise<{ bytes: Uint8Array; name: string; mime: string } | null> {
		const s = this.state.get();
		const row = s.files.find((f) => f.id === id) ?? s.trashFiles.find((f) => f.id === id);
		if (!row) return null;
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null; type: string | null; version: number; sample?: boolean }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return null;
		const priv = await this.bridge.storePrivate();
		// Nothing is decrypted for rendering unless the type verifies and says
		// "not a sample" (commit 29e).
		const opened = await this.openType(meta, id);
		if ((await this.policyOf(meta, id, opened)) !== "normal") return null;
		const mime = opened.mime ?? "application/octet-stream";
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
		const keys = await this.keysFor<{ keys: Record<string, { key: string; chunk: number | null; version: number; type: string | null; sample?: boolean }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return null;
		if ((await this.policyOf(meta, id, null)) !== "normal") return null; // never played (commit 29e)
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

	/** Whether Paste has anything to paste (the menus grey it out otherwise —
	 * until 39m they asked whether something was SELECTED instead). */
	get canPaste(): boolean {
		return !!this.clipboard && this.clipboard.files.length + this.clipboard.folders.length > 0;
	}

	/** Paste into `into` (a folder right-clicked, a tree row), or into the
	 * open folder. */
	async paste(into?: string | null): Promise<void> {
		const clip = this.clipboard;
		if (!clip) return;
		const folderId = into === undefined ? this.state.get().folderId : into;
		if (clip.mode === "cut") {
			for (const id of clip.files) await this.bridge.apiSend("PATCH", `${areaPath(this.memberId)}/files/${id}`, { folderId });
			for (const id of clip.folders) await this.bridge.apiSend("PATCH", `${areaPath(this.memberId)}/files/folders/${id}`, { parentId: folderId });
			this.clipboard = null;
			await this.refresh();
			this.bridge.toast("Pasted (moved)");
			return;
		}
		// Copy = duplicate: open the bytes, seal them fresh (a copy is a new
		// file with a new content key — the original's history is untouched).
		// Folders are not copied (a deep copy re-seals every file inside):
		// said, not silently skipped.
		if (clip.folders.length && !clip.files.length) {
			this.bridge.toast("Folders are not copied — Cut and Paste moves them");
			return;
		}
		for (const id of clip.files) {
			const plainParts: Uint8Array[] = [];
			const served = await this.openBytes(id, undefined, async (plain) => {
				plainParts.push(plain);
			});
			const plain = concat(plainParts);
			const name = this.names.get(id) ?? "copy";
			const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", plain as BufferSource));
			// The copy is signed by whoever makes it — so a source whose own
			// signature FAILS is not copied: that would launder altered bytes
			// under a new, valid signature. (Unsigned or merely unverified
			// sources copy; the copy says who vouches for it now.)
			const check = await this.checkHash(id, served, { sha256: hexOf(digest), size: plain.length });
			if (check.status === "mismatch" || check.status === "invalid") throw new Error(`not copying “${name}”: ${describeHashCheck(check)}`);
			// A copy of a sample is a sample (commit 29e) — copying must never
			// be the way a sample loses its mark. (An unverifiable type copies
			// as a sample too: the careful side.)
			const sample = (await this.renderPolicy(id)) !== "normal";
			const original = sample ? (await this.info(id))?.shownType ?? "" : "";
			// A copy inside an evidence case is a new item: its intake says
			// exactly what it is — this case's own copy, checked first.
			const me = this.bridge.identity?.() ?? null;
			const intake: IntakeFields | null = this.bridge.areaKind?.() === "evidence" ? { source: `a copy of “${name}” (${id}) in this case`, collector: me?.signer.member ?? "", method: "duplicated in gorani from the case's own copy, after its signature was checked", collectedAt: new Date().toISOString(), notes: "" } : null;
			await this.uploadOne(new File([plain as BlobPart], copyName(name), { type: original }), await this.fingerprint(digest), folderId, hexOf(digest), sample, intake);
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
			const feed = await this.bridge.apiGet<{ cursor: number; changes: { seq: number; kind: string; data: unknown }[] }>(`${areaPath(this.memberId)}/files/changes?since=${since}&limit=500`);
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
		return this.bridge.apiSend<T>("POST", `${areaPath(this.memberId)}/files/keys`, { ids: [id] });
	}

	/** Info for the Get Info / details pane: everything readable, opened. */
	/** `mime` is what may be rendered: null unless `policy` is "normal" (commit
	 * 29e). `shownType` is for display only — a sample's original type. */
	async info(id: string): Promise<{ name: string; kind: FileKind; size: number; version: number; createdAt: string; updatedAt: string; mime: string | null; policy: "normal" | "sample" | "unverified"; shownType: string | null } | null> {
		const keys = await this.keysFor<{ keys: Record<string, { key: string; version: number; type: string | null; size: number; sample?: boolean }> }>(id);
		const meta = keys.keys[id];
		if (!meta) return null;
		const opened = await this.openType(meta, id);
		const policy = await this.policyOf(meta, id, opened);
		const row = this.rowOf(id);
		const shownType = opened.mime && isSampleType(opened.mime) ? originalType(opened.mime) : opened.mime;
		return row ? { name: row.name, kind: row.kind, size: row.size, version: meta.version, createdAt: row.createdAt, updatedAt: row.updatedAt, mime: policy === "normal" ? opened.mime : null, policy, shownType } : null;
	}

	async refresh(): Promise<void> {
		await this.list(this.target.folderId, { trash: this.target.trash });
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
	sample?: boolean;
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

/** Lowercase hex of a digest. */
/** Downloads above this stream through the media worker to disk (D12, 31c). */
export const STREAM_DOWNLOAD_AT = 256 * 1024 * 1024;
/** Above this, a download is not even tried in the tab's memory. */
const IN_TAB_LIMIT = 2 * 1024 ** 3;
/** Files up to this size go up whole, in one request; larger ones as GC01 frames. */
export const WHOLE_LIMIT = 48 * 1024 * 1024;
/** Audio tags are parsed from the whole file — up to this size (the parser needs it in memory). */
const TAG_PARSE_LIMIT = 512 * 1024 * 1024;
/** The hashing pass reads this much at a time. */
const HASH_SLICE = 8 * 1024 * 1024;

/**
 * SHA-256 of a file in one streamed pass (D12): the duplicate tag and the
 * signed content hash need it before any byte is sealed, and a 255 GB
 * image cannot be read whole. Small files take WebCrypto's one-shot digest.
 */
async function digestOf(file: Blob): Promise<Uint8Array> {
	if (file.size <= WHOLE_LIMIT) return new Uint8Array(await crypto.subtle.digest("SHA-256", (await file.arrayBuffer()) as BufferSource));
	const h = await sha256Stream();
	for (let at = 0; at < file.size; at += HASH_SLICE) h.update(new Uint8Array(await file.slice(at, Math.min(file.size, at + HASH_SLICE)).arrayBuffer()));
	return new Uint8Array(h.hex().match(/../g)!.map((x) => parseInt(x, 16)));
}

function hexOf(bytes: Uint8Array): string {
	return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
