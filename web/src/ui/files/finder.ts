// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-finder>: the macOS Finder simulation.
 *
 * The Finder-isms, each a real operation on the sealed model:
 *
 * | Finder-ism | Here |
 * |---|---|
 * | Toolbar with view segmented control | icon / list / column views |
 * | Sidebar favorites | Home, the member's tree, Trash |
 * | **Column view** (the Finder signature) | cascading columns; a click walks deeper |
 * | Quick Look (Space) | a modal preview — decrypted here, sealed everywhere else |
 * | Get Info (⌘I) | model.info — sizes, times, version |
 * | Enter = rename, ⌘O / ⌘↓ = open | Finder's convention, not Windows' |
 * | ⌘C/⌘X/⌘V, ⌘A, ⌘Delete → Trash; ⌥⌘Delete, and ⌘Delete in the Trash → Delete Forever (39v: a lead's, or the owner's) | model clipboard + trash / purge |
 * | Path bar at the bottom | breadcrumbs |
 * | Drag to move, drop on sidebar folder | model.moveItems; desktop drop → upload |
 * | Context menus (39m) | an item: Open / Get Info / Rename / Duplicate / Move to › / Move to Trash / Delete Forever… (39v) / Copy / Paste Item / Download as Zip (41a); the Trash: Put Back / Delete Forever… / Empty Trash…; empty space: New Folder / Upload / Download Folder as Zip / Paste Item / Select All / View as › / Sort By ›; sidebar rows; search and recent results; the menu key and Shift+F10 |
 * | List view columns sortable | same sort state as the Windows skin |
 *
 * The point of shipping both skins: the same sealed operations, two platform
 * grammars — and the family can pick whichever feels like home.
 */

import { LitElement, html, nothing, type PropertyValues, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel, Selection, SortState } from "./model.ts";
import { shownModified } from "./model.ts";
import { icon, type FileKind } from "./icons.ts";
import { fmtSize, fmtDate, typingInField, showMenu, startRename, promptName, setDragIds, dragIds, kindLabel, modKey, markSample, custodyAction, deleteForever, emptyTrash, moveTargets, takeDrop, isOwnDrag, carriesFiles, uploadStatus, type MenuItem } from "./shared.ts";
import { fromRelativePaths } from "./dropped.ts";
import type { ViewerTarget } from "../viewer/viewer.ts";
import { renderMime } from "../viewer/mode.ts";
import { blobURL, revokeBlobURL } from "../../lib/blob-urls.ts";
import "../viewer/viewer.ts";
import "./share-dialog.ts";
import "./requests-dialog.ts";
import { showDuplicates } from "./duplicates-dialog.ts";

type ViewMode = "icon" | "list" | "column";

@customElement("gorani-finder")
export class GoraniFinder extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: String }) memberName = "";

	@state() private view: ViewMode = "column";
	@state() private v = 0;
	/** Files from outside are being dragged over the view (39r). */
	@state() private dropHint = false;
	private dropHintTimer: ReturnType<typeof setTimeout> | undefined;
	@state() private renaming: Selection | null = null;
	@state() private query = "";
	@state() private searchHits: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number }[] | null = null;
	@state() private recentsMode = false;
	@state() private recentRows: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; updatedAt: number; size?: number }[] = [];
	private typeBuffer = "";
	private typeTimer: ReturnType<typeof setTimeout> | undefined;
	@state() private quickLook: { id: string; name: string; url?: string; text?: string; kind: FileKind; meta?: { size: number; version: number; updatedAt: string } } | null = null;
	@state() private info: Awaited<ReturnType<FilesModel["info"]>> = null;
	@state() private shareTarget: { id: string; name: string; size: number; version: number; modified: string | null } | null = null;
	/** The upload-links dialog (commit 38): its tab, and the folder a new link files into. */
	@state() private requests: { tab: "inbox" | "links"; folderId: string | null; folderName: string } | null = null;

	private openRequests(tab: "inbox" | "links", folderId: string | null = this.s().folderId, folderName = folderId ? (this.model.names.get(folderId) ?? "") : ""): void {
		this.requests = { tab, folderId, folderName };
	}

	private openShare(id: string): void {
		const row = this.s().files.find((f) => f.id === id);
		if (!row) return;
		this.shareTarget = { id, name: row.name, size: row.size, version: row.version, modified: row.modified };
	}

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	// Escape closes Get Info and Quick Look wherever the focus is (commit 39l:
	// after a menu item, focus is on the page, not in the Finder — the key
	// never reached its own handler, and the panel stayed over the files).
	private onDocKey = (e: KeyboardEvent) => {
		if (e.key !== "Escape") return;
		if (this.info) this.info = null;
		else if (this.quickLook) this.quickLook = null;
	};
	override connectedCallback(): void {
		super.connectedCallback();
		document.addEventListener("keydown", this.onDocKey);
	}
	override disconnectedCallback(): void {
		document.removeEventListener("keydown", this.onDocKey);
		this.unsubscribe?.();
		this.unsubscribe = null;
		super.disconnectedCallback();
	}

	/** The model's ticks re-render this view — the model's of the moment:
	 * switching areas hands this same element a NEW model (shell.ts ›
	 * openArea). Until 41b the first model's subscription was the only
	 * one, so after a switch the new area's listing landed unseen. */
	private unsubscribe: (() => void) | null = null;

	protected override willUpdate(changed: PropertyValues<this>): void {
		if (!changed.has("model")) return;
		this.unsubscribe?.();
		this.unsubscribe = this.model?.subscribe(() => {
			this.v++;
			void this.requestUpdate();
		}) ?? null;
	}

	protected override firstUpdated(): void {
		this.tabIndex = 0;
	}

	private s = () => this.model.state.get();

	private firstSel(): Selection | null {
		return this.s().selection[0] ?? null;
	}

	private visible(): { folders: ReturnType<FilesModel["state"]["get"]>["folders"]; files: ReturnType<FilesModel["state"]["get"]>["files"] } {
		const s = this.s();
		const { folders, files } = this.model.sorted();
		const q = this.query.trim().toLowerCase();
		const hit = <T extends { name: string }>(x: T) => !q || x.name.toLowerCase().includes(q);
		return { folders: (s.trashMode ? s.trashFolders : folders).filter(hit), files: (s.trashMode ? s.trashFiles : files).filter(hit) };
	}

	private isSelected(kind: string, id: string): boolean {
		return this.s().selection.some((x) => x.kind === kind && x.id === id);
	}

	// ── operations ──────────────────────────────────────────────────────

	private selection(): Selection[] {
		return this.s().selection;
	}

	/** Every navigation goes here: it leaves Search, Recents and the Trash,
	 * and the model puts the folder in the address (commit 39l). */
	private go(id: string | null): Promise<void> {
		this.recentsMode = false;
		this.searchHits = null;
		this.query = "";
		return this.model.setFolder(id);
	}

	private async openEntry(kind: "file" | "folder", id: string): Promise<void> {
		if (this.s().trashMode) return;
		if (kind === "folder") {
			// Column view too: the open folder IS the walked path's end (the
			// columns are drawn from it — columnView). Until commit 39l a folder
			// opened here was pushed onto a list nothing drew.
			await this.go(id);
			return;
		}
		const row = this.s().files.find((f) => f.id === id) ?? this.s().trashFiles.find((f) => f.id === id);
		if (!row) return;
		this.quickLook = null;
		// With the folder's other files, in the order shown (41b): ← and → in the viewer.
		const target = (f: typeof row): ViewerTarget => ({ id: f.id, name: f.name, kind: f.kind, size: f.size, version: f.version });
		const siblings = this.s().trashMode ? undefined : this.visible().files.map(target);
		this.dispatchEvent(new CustomEvent("open-viewer", { detail: { ...target(row), siblings } as ViewerTarget, bubbles: true, composed: true }));
	}

	private async quickLookOn(id: string): Promise<void> {
		const row = this.s().files.find((f) => f.id === id) ?? this.s().trashFiles.find((f) => f.id === id);
		if (!row) return;
		revokeBlobURL(this.quickLook?.url); // the previous preview's handle
		this.quickLook = { id, name: row.name, kind: row.kind };
		try {
			const p = await this.model.preview(id, 512 * 1024);
			if (p && this.quickLook?.id === id) {
				if (row.kind === "image") this.quickLook.url = blobURL(new Blob([p.bytes as BlobPart], { type: renderMime("image", p.mime, row.name) }));
				else if (row.kind === "text" || row.kind === "code" || row.kind === "pdf") this.quickLook.text = new TextDecoder().decode(p.bytes.subarray(0, 16384));
				this.quickLook.meta = { size: row.size, version: row.version, updatedAt: shownModified(row) };
			}
		} catch {
			// best-effort
		}
	}

	private async getInfo(id: string): Promise<void> {
		this.info = await this.model.info(id);
	}

	private async downloadSelection(): Promise<void> {
		for (const sel of this.selection().filter((x) => x.kind === "file")) {
			await this.model.download(sel.id, this.model.names.get(sel.id) ?? "download");
		}
	}

	private async deleteSelection(): Promise<void> {
		const sel = this.selection();
		if (!sel.length) return;
		await this.model.trashItems(sel);
	}

	/** Delete Forever (39v) — asked first; offered only to whom the server
	 * allows it (model.ts › canPurge), and the keys say why to the rest. */
	private async purgeSelection(): Promise<void> {
		const sel = this.selection();
		if (!sel.length) return;
		if (!this.model.canPurge()) {
			this.model.api.toast(this.model.areaKind() === "evidence" ? "An evidence case's files are never deleted" : "Only a lead deletes forever here — ⌘Delete moves it to the Trash");
			return;
		}
		await deleteForever(this.model, sel);
	}

	private purgeItem(target: { kind: "file" | "folder"; id: string }[]): MenuItem[] {
		return this.model.canPurge() ? [{ label: "Delete Forever…", run: () => this.attempt(deleteForever(this.model, target)) }] : [];
	}

	private emptyTrashItem(): MenuItem[] {
		return this.model.canPurge() ? [{ label: "Empty Trash…", run: () => this.attempt(emptyTrash(this.model)) }] : [];
	}

	/** A menu's action: a failure becomes a toast in the server's words
	 * instead of an unhandled rejection (as in the Windows skin). */
	private attempt(p: Promise<unknown>): void {
		p.catch((e) => this.model.api.toast(e instanceof Error ? e.message : String(e)));
	}

	private pick(selector: string): void {
		this.querySelector<HTMLInputElement>(selector)?.click();
	}

	private async renameSelection(): Promise<void> {
		const sel = this.selection()[0];
		if (!sel) return;
		this.renaming = sel;
		this.v++;
		await this.requestUpdate();
		startRename(this, `[data-rename="${sel.id}"]`, this.model.names.get(sel.id) ?? "", async (value) => {
			this.renaming = null;
			if (value) await this.model.rename(sel.kind, sel.id, value);
		});
	}

	private async newFolder(parent: string | null = this.s().folderId): Promise<void> {
		const name = await promptName("New Folder", "untitled folder");
		if (name) await this.model.newFolder(parent, name);
	}

	// ── context menus (commit 39m) ──────────────────────────────────────

	private contextMenu(e: MouseEvent, kind: "file" | "folder", id: string, name: string): void {
		e.preventDefault();
		e.stopPropagation();
		this.itemMenu(kind, id, name, e.clientX, e.clientY);
	}

	private itemMenu(kind: "file" | "folder", id: string, name: string, x: number, y: number): void {
		if (!this.isSelected(kind, id)) this.model.select({ kind, id });
		const sel = this.selection();
		const many = sel.length > 1;
		const s = this.s();
		const sample = s.files.find((f) => f.id === id)?.sample === true;
		if (s.trashMode) {
			showMenu(
				[
					{ label: "Put Back", run: () => this.attempt(this.model.restore(sel.filter((x) => x.kind === "file").map((x) => x.id), sel.filter((x) => x.kind === "folder").map((x) => x.id))) },
					...this.purgeItem(sel),
					{ separator: true, label: "" },
					{ label: "Select All", run: () => this.model.selectAll() },
				],
				x,
				y,
			);
			return;
		}
		const intoFolder = kind === "folder" && !many;
		const items: MenuItem[] = [
			{ label: kind === "folder" ? "Open" : "Quick Look", run: () => void this.openEntry(kind, id), disabled: many },
			{ label: "Get Info", run: () => this.attempt(this.getInfo(id)), disabled: many || kind === "folder" },
			{ separator: true, label: "" },
			{ label: "Rename…", run: () => void this.renameSelection(), disabled: many },
			{ label: "Duplicate", run: () => { this.model.copy(); this.attempt(this.model.paste()); }, disabled: !sel.some((x) => x.kind === "file") },
			{ label: "Move to", submenu: moveTargets(s.tree, sel, s.folderId, this.memberName || "Home", (to) => this.attempt(this.model.moveItems(sel, to))) },
			{ label: "Move to Trash", run: () => this.attempt(this.deleteSelection()) },
			...this.purgeItem(sel),
			{ separator: true, label: "" },
			{ label: "Copy", run: () => this.model.copy() },
			{ label: "Cut", run: () => this.model.cut() },
			{ label: intoFolder ? "Paste Item into Folder" : "Paste Item", run: () => this.attempt(this.model.paste(intoFolder ? id : undefined)), disabled: !this.model.canPaste },
			{ separator: true, label: "" },
			{ label: "Share…", run: () => this.openShare(id), disabled: kind === "folder" || many || sample },
			{ label: "Request Files into Folder…", run: () => this.openRequests("links", id, name), disabled: kind !== "folder" || many },
			{ label: "Mark as Malware Sample…", run: () => this.attempt(markSample(this.model, id, name)), disabled: kind === "folder" || many || sample },
			{ label: "Download", run: () => this.attempt(this.downloadSelection()), disabled: !sel.some((x) => x.kind === "file") },
			// (41a) Files and folders, one zip; samples left out, checks inside.
			{ label: "Download as Zip", run: () => this.attempt(this.model.downloadZip(sel)) },
			{ label: "Verify Signature", run: () => this.attempt(this.model.verifyAndReport(id)), disabled: kind === "folder" || many },
			{ label: "Custody…", run: () => this.attempt(custodyAction(this.model, id, name)), disabled: kind === "folder" || many || this.model.areaKind() !== "evidence" },
		];
		showMenu(items, x, y);
	}

	private viewItems(): MenuItem[] {
		const item = (mode: ViewMode, label: string): MenuItem => ({ label, checked: this.view === mode, run: () => (this.view = mode) });
		return [item("icon", "as Icons"), item("list", "as List"), item("column", "as Columns")];
	}

	private sortItems(): MenuItem[] {
		const cur = this.s().sort;
		const item = (by: SortState["by"], label: string): MenuItem => ({ label, checked: cur.by === by, run: () => cur.by !== by && this.model.sortBy(by) });
		return [
			item("name", "Name"),
			item("type", "Kind"),
			item("modified", "Date Modified"),
			item("size", "Size"),
			{ separator: true, label: "" },
			{ label: "Ascending", checked: cur.dir === "asc", run: () => this.model.sortDirection("asc") },
			{ label: "Descending", checked: cur.dir === "desc", run: () => this.model.sortDirection("desc") },
		];
	}

	/** Empty space: what the folder itself can do (the last column's
	 * folder in column view — the one you are in). */
	private backgroundMenu(e: MouseEvent): void {
		if ((e.target as HTMLElement).closest("[data-item]")) return;
		e.preventDefault();
		this.openBackgroundMenu(e.clientX, e.clientY);
	}

	private openBackgroundMenu(x: number, y: number): void {
		const s = this.s();
		if (this.recentsMode) {
			showMenu([{ label: "Refresh", run: () => void this.showRecents() }], x, y);
			return;
		}
		if (s.trashMode) {
			const any = s.trashFiles.length + s.trashFolders.length > 0;
			showMenu(
				[
					{ label: "Put Back All", run: () => this.attempt(this.model.restore(s.trashFiles.map((f) => f.id), s.trashFolders.map((f) => f.id))), disabled: !any },
					...this.emptyTrashItem().map((m) => ({ ...m, disabled: !any })),
					{ label: "Select All", run: () => this.model.selectAll(), disabled: !any },
				],
				x,
				y,
			);
			return;
		}
		this.model.clearSelection();
		showMenu(
			[
				{ label: "New Folder", icon: icon("folder"), run: () => this.attempt(this.newFolder()) },
				{ label: "Upload Files…", icon: icon("file"), run: () => this.pick("[data-upload]") },
				{ label: "Upload Folder…", icon: icon("folder"), run: () => this.pick("[data-upload-folder]") },
				{ label: "Upload Malware Samples…", icon: icon("sample"), run: () => this.pick("[data-upload-sample]") },
				{ label: "Request Files into Folder…", run: () => this.openRequests("links", s.folderId) },
				{ label: "Download Folder as Zip", run: () => this.attempt(this.model.downloadFolderZip(s.folderId, this.memberName || "Home")), disabled: !(s.folders.length + s.files.length) },
				{ separator: true, label: "" },
				{ label: "Paste Item", run: () => this.attempt(this.model.paste()), disabled: !this.model.canPaste },
				{ label: "Select All", run: () => this.model.selectAll(), disabled: !(s.folders.length + s.files.length) },
				{ label: "Find Duplicates…", run: () => this.openDuplicates() },
				{ separator: true, label: "" },
				{ label: "View", submenu: this.viewItems() },
				{ label: "Sort By", submenu: this.sortItems() },
				{ label: "Refresh", run: () => this.attempt(this.model.refresh()) },
			],
			x,
			y,
		);
	}

	private openDuplicates(): void {
		showDuplicates(this.model, (folderId, id) =>
			this.attempt(
				(async () => {
					await this.go(folderId);
					this.model.select({ kind: "file", id });
				})(),
			),
		);
	}

	/** A folder in the sidebar's Favorites (or Home). */
	private sidebarMenu(e: MouseEvent, id: string | null, name: string): void {
		e.preventDefault();
		e.stopPropagation();
		const s = this.s();
		const target = id ? [{ kind: "folder" as const, id }] : [];
		showMenu(
			[
				{ label: "Open", run: () => void this.go(id) },
				{ separator: true, label: "" },
				{ label: "New Folder", icon: icon("folder"), run: () => this.attempt(this.newFolder(id)) },
				{ label: id ? "Paste Item into Folder" : "Paste Item", run: () => this.attempt(this.model.paste(id)), disabled: !this.model.canPaste },
				{ label: "Request Files into Folder…", run: () => this.openRequests("links", id, name) },
				{ label: id ? "Download as Zip" : "Download All as Zip", run: () => this.attempt(this.model.downloadFolderZip(id, this.memberName || "Home")) },
				...(id
					? ([
							{ separator: true, label: "" },
							{ label: "Move to", submenu: moveTargets(s.tree, target, s.tree.find((f) => f.id === id)?.parent ?? null, this.memberName || "Home", (to) => this.attempt(this.model.moveItems(target, to))) },
							{ label: "Move to Trash", run: () => this.attempt(this.model.trashItems(target)) },
							...this.purgeItem(target),
						] as MenuItem[])
					: []),
			],
			e.clientX,
			e.clientY,
		);
	}

	private trashNavMenu(e: MouseEvent): void {
		e.preventDefault();
		showMenu(
			[
				{ label: "Open", run: () => this.attempt(this.openTrashView()) },
				{
					label: "Put Back All",
					run: () =>
						this.attempt(
							(async () => {
								await this.openTrashView();
								const t = this.s();
								if (t.trashFiles.length + t.trashFolders.length) await this.model.restore(t.trashFiles.map((f) => f.id), t.trashFolders.map((f) => f.id));
							})(),
						),
				},
				...this.emptyTrashItem(),
			],
			e.clientX,
			e.clientY,
		);
	}

	private openTrashView(): Promise<void> {
		this.recentsMode = false;
		this.searchHits = null;
		return this.model.openTrash();
	}

	private hitMenu(e: MouseEvent, hit: { id: string; kind: "file" | "folder"; folderId: string | null; name: string }): void {
		e.preventDefault();
		e.stopPropagation();
		showMenu(
			[
				{
					label: "Open",
					run: () =>
						this.attempt(
							(async () => {
								await this.jumpTo(hit);
								if (hit.kind === "file") await this.openEntry("file", hit.id);
							})(),
						),
				},
				{ label: "Show in Enclosing Folder", run: () => this.attempt(this.jumpTo(hit)) },
			],
			e.clientX,
			e.clientY,
		);
	}

	private keyboardMenu(): void {
		const first = this.firstSel();
		const el = first ? this.querySelector<HTMLElement>(`[data-item="${first.kind}:${first.id}"]`) : null;
		if (first && el) {
			const r = el.getBoundingClientRect();
			this.itemMenu(first.kind, first.id, this.model.names.get(first.id) ?? "", r.left + 24, r.bottom - 4);
			return;
		}
		const body = this.querySelector<HTMLElement>("[data-body]")?.getBoundingClientRect();
		this.openBackgroundMenu((body?.left ?? 0) + 24, (body?.top ?? 0) + 24);
	}

	// ── keyboard (the Finder grammar) ───────────────────────────────────

	private async onSearch(q: string): Promise<void> {
		this.query = q;
		if (q.trim().length < 2 || !this.model.index) {
			this.searchHits = null;
			return;
		}
		const hits = await this.model.index.search(q, 40);
		this.searchHits = hits.map((h) => ({ id: h.id, kind: h.kind, folderId: h.folderId, name: h.name, size: h.size }));
	}

	private async jumpTo(hit: { id: string; kind: "file" | "folder"; folderId: string | null; name: string }): Promise<void> {
		this.searchHits = null;
		this.query = "";
		this.recentsMode = false;
		await this.go(hit.kind === "folder" ? hit.id : hit.folderId);
		if (hit.kind === "file") this.model.select({ kind: "file", id: hit.id });
	}

	private async showRecents(): Promise<void> {
		this.recentsMode = true;
		this.recentRows = this.model.index ? await this.model.index.recents(40) : [];
		this.v++;
		await this.requestUpdate();
	}

	private onKeydown(e: KeyboardEvent): void {
		if (typingInField(e)) return;
		if (this.renaming || this.quickLook) {
			if (this.quickLook && (e.key === "Escape" || e.key === " " || e.key === "q")) {
				this.quickLook = null;
				e.preventDefault();
			}
			return;
		}
		const { folders, files } = this.visible();
		const order = [...folders.map((f) => ({ kind: "folder" as const, id: f.id })), ...files.map((f) => ({ kind: "file" as const, id: f.id }))];
		const at = order.findIndex((o) => this.isSelected(o.kind, o.id));
		const move = (delta: number) => {
			const next = order[Math.max(0, Math.min(order.length - 1, at + delta))] ?? order[0];
			if (next) this.model.select(next, { add: e.shiftKey });
		};
		const cmd = e[modKey()];
		switch (e.key) {
			// ⌘↑ goes to the enclosing folder and ⌘↓ opens the selection, as
			// in Finder (⌃ off a Mac); the bare arrows move the selection.
			case "ArrowDown": {
				const cur = order[at];
				if (cmd) {
					if (at >= 0 && cur) void this.openEntry(cur.kind, cur.id);
				} else move(1);
				e.preventDefault();
				return;
			}
			case "ArrowUp":
				if (cmd) void this.go(this.s().tree.find((f) => f.id === this.s().folderId)?.parent ?? null);
				else move(-1);
				e.preventDefault();
				return;
			// Finder: Enter renames; ⌘O (and ⌘↓) open.
			case "Enter":
				if (at >= 0) void this.renameSelection();
				e.preventDefault();
				return;
			case "o":
				const cur = order[at];
				if (cmd && at >= 0 && cur) void this.openEntry(cur.kind, cur.id);
				e.preventDefault();
				return;
			case "i":
				const cur2 = order[at];
				if (cmd && at >= 0 && cur2) void this.getInfo(cur2.id);
				e.preventDefault();
				return;
			case " ":
				const cur3 = order[at];
				if (at >= 0 && cur3 && cur3.kind === "file") void this.quickLookOn(cur3.id);
				e.preventDefault();
				return;
			case "Backspace":
				// ⌥⌘Delete, and ⌘Delete in the Trash: for good (asked first).
				if (cmd && (e.altKey || this.s().trashMode)) this.attempt(this.purgeSelection());
				else if (cmd) this.attempt(this.deleteSelection());
				else void this.go(this.s().tree.find((f) => f.id === this.s().folderId)?.parent ?? null);
				e.preventDefault();
				return;
			case "Escape":
				this.model.clearSelection();
				return;
			case "ContextMenu":
				this.keyboardMenu();
				e.preventDefault();
				return;
			case "F10":
				if (e.shiftKey) {
					this.keyboardMenu();
					e.preventDefault();
				}
				return;
			case "a":
				if (cmd) {
					this.model.selectAll();
					e.preventDefault();
				}
				return;
			case "c":
				if (cmd) this.model.copy();
				return;
			case "x":
				if (cmd) this.model.cut();
				return;
			case "v":
				if (cmd) void this.model.paste();
				return;
			default:
				// Type-to-jump (Finder's muscle memory too).
				if (e.key.length === 1 && !cmd && !e.altKey && !e.ctrlKey) {
					this.typeBuffer = (this.typeBuffer + e.key.toLowerCase()).slice(-16);
					clearTimeout(this.typeTimer);
					this.typeTimer = setTimeout(() => (this.typeBuffer = ""), 500);
					const fileHit = files.find((x) => x.name.toLowerCase().startsWith(this.typeBuffer));
					const folderHit = folders.find((x) => x.name.toLowerCase().startsWith(this.typeBuffer));
					const hit = folderHit ?? fileHit;
					if (hit) this.model.select({ kind: folderHit ? "folder" : "file", id: hit.id }, { add: false });
				}
				return;
		}
	}

	// ── marquee (Finder has one too) ────────────────────────────────────
	// (identical mechanics to the Windows skin; kept local for clarity)

	private onBodyPointerDown(e: PointerEvent): void {
		if (e.button !== 0 || (e.target as HTMLElement).closest("[data-item]")) return;
		this.model.clearSelection();
		const body = this.querySelector("[data-body]") as HTMLElement;
		const el = document.createElement("div");
		el.className = "fixed z-40 border border-accent/50 bg-accent/10 pointer-events-none rounded-sm";
		document.body.append(el);
		const x0 = e.clientX;
		const y0 = e.clientY;
		const move = (ev: PointerEvent) => {
			const x = Math.min(x0, ev.clientX);
			const y = Math.min(y0, ev.clientY);
			const w = Math.abs(ev.clientX - x0);
			const h = Math.abs(ev.clientY - y0);
			Object.assign(el.style, { left: `${x}px`, top: `${y}px`, width: `${w}px`, height: `${h}px` });
			const hits: Selection[] = [];
			body.querySelectorAll<HTMLElement>("[data-item]").forEach((item) => {
				const r = item.getBoundingClientRect();
				if (r.left < x + w && r.right > x && r.top < y + h && r.bottom > y) {
					const [kindStr, idStr] = (item.dataset.item ?? "").split(":");
					hits.push({ kind: kindStr === "folder" ? "folder" : "file", id: idStr ?? "" });
				}
			});
			this.model.selectOnly(hits);
		};
		const up = () => {
			el.remove();
			window.removeEventListener("pointermove", move);
			window.removeEventListener("pointerup", up);
		};
		window.addEventListener("pointermove", move);
		window.addEventListener("pointerup", up);
	}

	private onDropIntoFolder(e: DragEvent, folderId: string | null): void {
		e.preventDefault();
		e.stopPropagation();
		const ids = dragIds(e.dataTransfer!);
		if (ids?.length) {
			this.attempt(this.model.moveItems(ids.map((x) => ({ kind: x.kind === "folder" ? "folder" : "file", id: x.id })), folderId));
			return;
		}
		// Files (and folders) from outside go INTO the folder they were
		// dropped on (39r: they used to go to the folder on screen).
		if (e.dataTransfer && carriesFiles(e.dataTransfer)) this.uploadDrop(e.dataTransfer, folderId);
	}

	/** Upload what was dropped — folders with their whole shape (dropped.ts). */
	private uploadDrop(dt: DataTransfer, folderId: string | null): void {
		if (this.s().trashMode) {
			this.model.api.toast("Open a folder to upload into — not the Trash");
			return;
		}
		const tree = takeDrop(dt); // during the event: the drop empties after it
		this.attempt(tree.then((t) => this.model.uploadTree(t, folderId)));
	}

	private onBodyDragOver(e: DragEvent): void {
		if (!e.dataTransfer || isOwnDrag(e.dataTransfer) || !carriesFiles(e.dataTransfer)) return;
		e.preventDefault();
		e.dataTransfer.dropEffect = "copy";
		this.dropHint = true;
		clearTimeout(this.dropHintTimer);
		// (dragover repeats while the pointer stays; when it stops, the drag left.)
		this.dropHintTimer = setTimeout(() => (this.dropHint = false), 400);
	}

	private onBodyDrop(e: DragEvent): void {
		this.dropHint = false;
		if (!e.dataTransfer || isOwnDrag(e.dataTransfer) || !carriesFiles(e.dataTransfer)) return;
		e.preventDefault();
		this.uploadDrop(e.dataTransfer, this.s().folderId);
	}

	/** The folder on screen, by name — where a drop on the view goes. */
	private here(): string {
		const id = this.s().folderId;
		return `“${id ? (this.model.names.get(id) ?? "…") : this.memberName || "Home"}”`;
	}

	// ── render ──────────────────────────────────────────────────────────

	protected override render(): TemplateResult {
		void this.v;
		const s = this.s();
		const { folders, files } = this.view === "column" ? this.columnVisible() : this.visible();
		return html`
			<div class="flex h-full flex-col bg-neutral-900/95 text-neutral-200 outline-none" tabindex="-1" @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}>
				${this.toolbar()}
				<div class="flex min-h-0 flex-1">
					${this.sidebar()}
					<div class="flex min-w-0 flex-1 flex-col">
						<div data-body class="relative min-h-0 flex-1 overflow-auto outline-none" @pointerdown=${(e: PointerEvent) => this.onBodyPointerDown(e)} @contextmenu=${(e: MouseEvent) => this.backgroundMenu(e)} @dragover=${(e: DragEvent) => this.onBodyDragOver(e)} @drop=${(e: DragEvent) => this.onBodyDrop(e)}>
							${this.recentsMode ? this.recentsBody() : this.view === "icon" ? this.iconView(folders, files) : this.view === "list" ? this.listView(folders, files) : this.columnView()}
							${this.dropHint ? html`<div class="pointer-events-none absolute inset-2 flex items-center justify-center rounded-xl border-2 border-dashed border-accent/70 bg-accent/5 text-sm text-neutral-200" data-test="drop-hint">Drop to upload into ${this.here()}</div>` : nothing}
						</div>
						${this.pathBar()}
					</div>
				</div>
				${this.quickLook ? this.quickLookModal() : nothing}
				${this.info ? this.infoPanel() : nothing}
				${this.shareTarget ? html`<gorani-share .model=${this.model} .target=${this.shareTarget} @closed=${() => (this.shareTarget = null)}></gorani-share>` : nothing}
				${this.requests ? html`<gorani-requests .model=${this.model} .tab=${this.requests.tab} .folderId=${this.requests.folderId} .folderName=${this.requests.folderName} @closed=${() => (this.requests = null)}></gorani-requests>` : nothing}
				${s.loading ? html`<div class="pointer-events-none fixed right-4 top-4 rounded-lg bg-neutral-800 px-3 py-1.5 text-xs text-neutral-300 shadow">Opening…</div>` : nothing}
			</div>
		`;
	}

	private toolbar(): TemplateResult {
		const view = (mode: ViewMode, glyph: string, title: string) =>
			html`<button class="rounded-lg px-2.5 py-1.5 text-sm ${this.view === mode ? "bg-neutral-700 text-white" : "text-neutral-400 hover:bg-neutral-800"}" title=${title} @click=${() => (this.view = mode)}>${glyph}</button>`;
		return html`
			<div class="flex items-center gap-1.5 border-b border-neutral-800 px-3 py-2">
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canBack} @click=${() => { this.recentsMode = false; this.searchHits = null; void this.model.back(); }}>‹</button>
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canForward} @click=${() => { this.recentsMode = false; this.searchHits = null; void this.model.forward(); }}>›</button>
				<div class="mx-1 h-5 border-l border-neutral-800"></div>
				${view("icon", "⊞", "Icons")} ${view("list", "☰", "List")} ${view("column", "❙❙❙", "Columns")}
				<div class="mx-1 h-5 border-l border-neutral-800"></div>
				<button class="rounded-md px-2.5 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800" @click=${() => void this.newFolder()}>＋ New Folder</button>
				<button class="rounded-md px-2.5 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800" title="Upload files (sealed here before they leave)" @click=${() => this.pick("[data-upload]")}>⇪ Upload</button>
				<input data-upload type="file" multiple class="hidden" @change=${(e: Event) => {
					const input = e.target as HTMLInputElement;
					if (input.files?.length) this.attempt(this.model.upload([...input.files]));
					input.value = "";
				}} />
				<input data-upload-sample type="file" multiple class="hidden" @change=${(e: Event) => {
					const input = e.target as HTMLInputElement;
					if (input.files?.length) this.attempt(this.model.upload([...input.files], { sample: true }));
					input.value = "";
				}} />
				<!-- A whole folder, its subfolders included (39r). -->
				<input data-upload-folder type="file" webkitdirectory multiple class="hidden" @change=${(e: Event) => {
					const input = e.target as HTMLInputElement;
					const files = [...(input.files ?? [])];
					input.value = "";
					if (files.length) this.attempt(Promise.resolve().then(() => this.model.uploadTree(fromRelativePaths(files), this.s().folderId)));
				}} />
				<button class="rounded-md px-2.5 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800 disabled:opacity-40" ?disabled=${!this.selection().length} @click=${() => this.attempt(this.s().trashMode ? this.purgeSelection() : this.deleteSelection())}>🗑</button>
				<button class="rounded-md px-2.5 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800" title="Upload links for people outside the team, and what they sent" data-test="files-requests" @click=${() => this.openRequests("inbox")}>📥 Inbox</button>
				<div class="flex-1"></div>
				<div class="relative">
					<input class="w-56 rounded-lg bg-neutral-950 px-3 py-1.5 text-sm outline-none placeholder:text-neutral-600 focus:ring-1 focus:ring-accent" placeholder="Search (local index)" .value=${this.query} @input=${(e: InputEvent) => void this.onSearch((e.target as HTMLInputElement).value)} />
					${this.searchHits
						? html`<div class="absolute right-0 top-9 z-40 max-h-96 w-96 overflow-y-auto rounded-xl border border-neutral-700 bg-neutral-900/95 p-1.5 shadow-2xl backdrop-blur">
								${this.searchHits.map(
									(h) => html`
										<button class="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm hover:bg-neutral-800" data-hit="${h.id}" @click=${() => void this.jumpTo(h)} @contextmenu=${(e: MouseEvent) => this.hitMenu(e, h)}>
											${icon(h.kind === "folder" ? "folder" : "file", "h-4 w-4 shrink-0 text-neutral-400")}
											<span class="min-w-0 flex-1 truncate text-neutral-100">${h.name}</span>
											<span class="shrink-0 text-xs text-neutral-500">${h.kind === "folder" ? "Folder" : fmtSize(h.size ?? 0)}</span>
										</button>
									`,
								)}
								${!this.searchHits.length ? html`<p class="p-3 text-center text-xs text-neutral-500">Nothing in the index yet</p>` : nothing}
							</div>`
						: nothing}
				</div>
			</div>
		`;
	}

	private sidebar(): TemplateResult {
		const s = this.s();
		// A row: its click, and — for a folder or Home — its own drop target
		// and menu (until 39m a drop anywhere in the sidebar went to the top,
		// whichever folder it landed on).
		const fav = (label: string, glyph: string, active: boolean, run: () => void, target?: { id: string | null; menu: (e: MouseEvent) => void }) =>
			html`<button
				class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm ${active ? "bg-neutral-700/70" : "hover:bg-neutral-800"}"
				data-fav=${label}
				@click=${run}
				@contextmenu=${(e: MouseEvent) => target?.menu(e)}
				@drop=${(e: DragEvent) => target && this.onDropIntoFolder(e, target.id)}
				@dragover=${(e: DragEvent) => target && e.preventDefault()}
			>${glyph}<span class="truncate">${label}</span></button>`;
		return html`
			<aside class="w-52 shrink-0 overflow-y-auto border-r border-neutral-800/70 bg-neutral-900/60 px-2 py-3 text-sm" @drop=${(e: DragEvent) => this.onDropIntoFolder(e, null)} @dragover=${(e: DragEvent) => e.preventDefault()}>
				<p class="px-2 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Favorites</p>
				${fav("Home", "🏠", s.folderId === null && !s.trashMode, () => void this.go(null), { id: null, menu: (e) => this.sidebarMenu(e, null, "") })}
				${s.tree.filter((f) => !f.parent).map((f) => fav(f.name, "📁", s.folderId === f.id && !s.trashMode, () => void this.go(f.id), { id: f.id, menu: (e) => this.sidebarMenu(e, f.id, f.name) }))}
				<p class="px-2 pt-3 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Recents</p>
				${fav("Recent files", "⏱", this.recentsMode, () => void this.showRecents())}
				<p class="px-2 pt-3 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Locations</p>
				${fav("Trash", "🗑", s.trashMode, () => void this.openTrashView())}
			</aside>
		`;
	}

	// ── icon view ───────────────────────────────────────────────────────

	private iconView(folders: ReturnType<FilesModel["state"]["get"]>["folders"], files: ReturnType<FilesModel["state"]["get"]>["files"]): TemplateResult {
		const cell = (kind: "file" | "folder", id: string, name: string, k: FileKind) => html`
			<div
				data-item="${kind}:${id}"
				class="flex h-32 w-28 flex-col items-center justify-start gap-1.5 rounded-xl p-2 text-center ${this.isSelected(kind, id) ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-neutral-800/50"}"
				@click=${(e: MouseEvent) => this.model.select({ kind, id }, { add: e[modKey()], range: e.shiftKey })}
				@dblclick=${() => void this.openEntry(kind, id)}
				@contextmenu=${(e: MouseEvent) => this.contextMenu(e, kind, id, name)}
				draggable="true"
				@dragstart=${(e: DragEvent) => setDragIds(e.dataTransfer!, this.selection().length ? this.selection() : [{ kind, id }])}
				@drop=${(e: DragEvent) => kind === "folder" && this.onDropIntoFolder(e, id)}
				@dragover=${(e: DragEvent) => kind === "folder" && e.preventDefault()}
			>
				${icon(k, "h-16 w-16")}
				<span data-rename="${id}" class="line-clamp-2 text-xs leading-tight text-neutral-200">${name}</span>
			</div>
		`;
		return html`
			<div class="grid grid-cols-[repeat(auto-fill,minmax(118px,1fr))] gap-2 p-4 [content-visibility:auto]">
				${folders.map((f) => cell("folder", f.id, f.name, "folder"))}
				${files.map((f) => cell("file", f.id, f.name, f.kind))}
				${!folders.length && !files.length ? html`<p class="col-span-full py-16 text-center text-sm text-neutral-500">This folder is empty</p>` : nothing}
			</div>
		`;
	}

	// ── list view ───────────────────────────────────────────────────────

	private listView(folders: ReturnType<FilesModel["state"]["get"]>["folders"], files: ReturnType<FilesModel["state"]["get"]>["files"]): TemplateResult {
		const cols = "grid grid-cols-[minmax(0,1fr)_90px_120px_140px]";
		const sortArrow = (by: string) => (this.s().sort.by === by ? (this.s().sort.dir === "asc" ? " ▲" : " ▼") : "");
		const item = (kind: "file" | "folder", id: string, name: string, k: FileKind, size: number | null) => html`
			<div
				data-item="${kind}:${id}"
				class="${cols} cursor-default items-center rounded-md px-2 py-1.5 text-sm ${this.isSelected(kind, id) ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-neutral-800/60"}"
				@click=${(e: MouseEvent) => this.model.select({ kind, id }, { add: e[modKey()], range: e.shiftKey })}
				@dblclick=${() => void this.openEntry(kind, id)}
				@contextmenu=${(e: MouseEvent) => this.contextMenu(e, kind, id, name)}
				draggable="true"
				@dragstart=${(e: DragEvent) => setDragIds(e.dataTransfer!, this.selection().length ? this.selection() : [{ kind, id }])}
				@drop=${(e: DragEvent) => kind === "folder" && this.onDropIntoFolder(e, id)}
				@dragover=${(e: DragEvent) => kind === "folder" && e.preventDefault()}
			>
				<span data-rename="${id}" class="flex min-w-0 items-center gap-2.5">${icon(k)}<span class="truncate">${name}</span></span>
				<span class="text-right text-neutral-400">${size === null ? "--" : fmtSize(size)}</span>
				<span class="text-neutral-400">${kind === "folder" ? "Folder" : kindLabel(k)}</span>
				<span class="text-right text-neutral-400">${fmtDate(kind === "folder" ? (this.s().folders.find((x) => x.id === id)?.updatedAt ?? "") : shownModified(this.s().files.find((x) => x.id === id) ?? { updatedAt: "" }))}</span>
			</div>
		`;
		return html`
			<div class="${cols} sticky top-0 z-10 border-b border-neutral-800 bg-neutral-900/95 px-2 py-1.5 text-xs text-neutral-400 backdrop-blur">
				<button class="text-left hover:text-neutral-200" @click=${() => this.model.sortBy("name")}>Name${sortArrow("name")}</button>
				<button class="text-right hover:text-neutral-200" @click=${() => this.model.sortBy("size")}>Size${sortArrow("size")}</button>
				<button class="text-left hover:text-neutral-200" @click=${() => this.model.sortBy("type")}>Kind${sortArrow("type")}</button>
				<button class="text-right hover:text-neutral-200" @click=${() => this.model.sortBy("modified")}>Date Modified${sortArrow("modified")}</button>
			</div>
			<div class="p-2 [content-visibility:auto]">
				${folders.map((f) => item("folder", f.id, f.name, "folder", null))}
				${files.map((f) => item("file", f.id, f.name, f.kind, f.size))}
			</div>
		`;
	}

	// ── column view (the Finder signature) ──────────────────────────────

	private columnVisible(): { folders: ReturnType<FilesModel["state"]["get"]>["folders"]; files: ReturnType<FilesModel["state"]["get"]>["files"] } {
		// The deepest walked folder is the model's current folder; the visible
		// listing is its children (the model already fetched it).
		return this.visible();
	}

	/**
	 * Column view, as macOS draws it: one column per level from the area's
	 * top down to the open folder, the open folder's own contents last, and
	 * a preview of the selected file beside them. A folder clicked in any
	 * column opens it (the columns to its right redraw from there). The
	 * ancestor columns list folders — the tree arrives whole with every
	 * listing; files come for the open folder only.
	 */
	private columnView(): TemplateResult {
		const s = this.s();
		const chain: (string | null)[] = [];
		for (let cur: string | null = s.folderId; cur; cur = s.tree.find((f) => f.id === cur)?.parent ?? null) chain.unshift(cur);
		chain.unshift(null);
		const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);
		const col = (level: number) => {
			const parent = chain[level] ?? null;
			const last = level === chain.length - 1;
			const folders = last ? this.visible().folders : s.tree.filter((f) => (f.parent ?? null) === parent).sort(byName);
			const files = last ? this.visible().files : [];
			const open = chain[level + 1];
			return html`
				<div class="min-w-56 max-w-72 flex-1 overflow-y-auto border-r border-neutral-800/70 p-1.5 text-sm" data-column=${level}>
					${folders.map((f) => this.columnCell("folder", f.id, f.name, "folder", f.id === open))}
					${files.map((f) => this.columnCell("file", f.id, f.name, f.kind))}
					${!folders.length && !files.length ? html`<p class="px-3 py-6 text-xs text-neutral-600">Empty</p>` : nothing}
				</div>
			`;
		};
		const selected = this.selection()[0];
		return html`
			<div class="flex h-full overflow-x-auto">
				${chain.map((_, i) => col(i))}
				${selected && selected.kind === "file" ? this.columnPreview(selected.id) : nothing}
			</div>
		`;
	}

	private columnCell(kind: "file" | "folder", id: string, name: string, k: FileKind, walked = false): TemplateResult {
		return html`
			<div
				data-item="${kind}:${id}"
				class="flex cursor-default items-center gap-2 rounded-md px-2.5 py-1.5 ${this.isSelected(kind, id) ? "bg-accent/20" : walked ? "bg-neutral-800" : "hover:bg-neutral-800/60"}"
				@click=${(e: MouseEvent) => {
					// A plain click on a folder opens it into the next column;
					// with a modifier it selects, to act on several.
					if (kind === "folder" && !e[modKey()] && !e.shiftKey) void this.go(id).then(() => this.model.select({ kind, id }));
					else this.model.select({ kind, id }, { add: e[modKey()], range: e.shiftKey });
				}}
				@dblclick=${() => void this.openEntry(kind, id)}
				@contextmenu=${(e: MouseEvent) => this.contextMenu(e, kind, id, name)}
				draggable="true"
				@dragstart=${(e: DragEvent) => setDragIds(e.dataTransfer!, [{ kind, id }])}
			>
				${icon(k, "h-4 w-4 shrink-0 text-neutral-400")}
				<span data-rename="${id}" class="truncate ${this.isSelected(kind, id) ? "text-white" : ""}">${name}</span>
				${kind === "folder" ? html`<span class="ml-auto text-neutral-600">›</span>` : nothing}
			</div>
		`;
	}

	private columnPreview(id: string): TemplateResult {
		const row = this.s().files.find((f) => f.id === id);
		const p = this.quickLook?.id === id ? this.quickLook : null;
		return html`
			<div class="w-64 shrink-0 overflow-y-auto bg-neutral-950/40 p-4 text-center text-sm">
				${p?.url ? html`<img class="mx-auto max-h-48 rounded-lg" src=${p.url} alt="" />` : icon(row?.kind ?? "file", "h-20 w-20 text-neutral-600 mx-auto")}
				<p class="mt-3 truncate font-medium">${row?.name ?? ""}</p>
				${row ? html`<p class="mt-1 text-xs text-neutral-400">${kindLabel(row.kind)} · ${fmtSize(row.size)}</p>` : nothing}
				<button class="mt-3 rounded-lg bg-neutral-800 px-3 py-1.5 text-xs hover:bg-neutral-700" @click=${() => void this.quickLookOn(id)}>Quick Look (space)</button>
			</div>
		`;
	}

	/** Recents (fed by the local index, no server). */
	private recentsBody(): TemplateResult {
		const rows = this.recentRows;
		return html`
			<div class="p-3 text-sm">
				<p class="px-1 pb-2 text-xs uppercase tracking-wide text-neutral-500">Recently touched on this device — from the local index</p>
				${rows.map(
					(r) => html`
						<button class="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left hover:bg-neutral-800/60" data-recent="${r.id}" @click=${() => void this.jumpTo(r)} @contextmenu=${(e: MouseEvent) => this.hitMenu(e, r)}>
							${icon(r.kind === "folder" ? "folder" : "file", "h-5 w-5 text-neutral-400")}
							<span class="min-w-0 flex-1 truncate">${r.name}</span>
							${r.size !== undefined ? html`<span class="text-xs text-neutral-400">${fmtSize(r.size)}</span>` : nothing}
							<span class="text-xs text-neutral-500">${fmtDate(new Date(r.updatedAt).toISOString())}</span>
						</button>
					`,
				)}
				${!rows.length ? html`<p class="py-16 text-center text-sm text-neutral-500">Nothing indexed yet — browse a folder first.</p>` : nothing}
			</div>
		`;
	}

	// ── path bar ────────────────────────────────────────────────────────

	private pathBar(): TemplateResult {
		const s = this.s();
		// Walked from the folder up, then turned around (39r: the parents
		// were pushed AFTER the folder, so /A/B read "Home / B / A").
		const up: { id: string | null; name: string }[] = [];
		let cursor = s.folderId;
		const seen = new Set<string>();
		while (cursor && !seen.has(cursor)) {
			seen.add(cursor);
			up.push({ id: cursor, name: this.model.names.get(cursor) ?? "…" });
			cursor = s.tree.find((f) => f.id === cursor)?.parent ?? null;
		}
		const crumbs: { id: string | null; name: string; trash?: boolean }[] = [{ id: null, name: this.memberName }, ...up.reverse()];
		if (s.trashMode) crumbs.push({ id: null, name: "Trash", trash: true });
		// Each crumb takes a drop into ITS folder (it used to be the whole
		// bar, into the top folder, whichever crumb the drop landed on).
		return html`
			<footer class="flex items-center gap-1 border-t border-neutral-800/70 px-3 py-1.5 text-xs text-neutral-400" data-test="path-bar">
				${crumbs.map(
					(c, i) =>
						html`${i > 0 ? html`<span class="text-neutral-600">/</span>` : nothing}<button class="rounded px-1 py-0.5 hover:bg-neutral-800 ${i === crumbs.length - 1 ? "text-neutral-200" : ""}" @click=${() => void this.go(c.id)} @drop=${(e: DragEvent) => !c.trash && this.onDropIntoFolder(e, c.id)} @dragover=${(e: DragEvent) => !c.trash && e.preventDefault()}>${c.name}</button>`,
				)}
				<span class="flex-1"></span>
				${uploadStatus(s.upload, () => this.model.stopUpload())}
			</footer>
		`;
	}

	// ── Quick Look + Get Info ───────────────────────────────────────────

	private quickLookModal(): TemplateResult {
		const q = this.quickLook!;
		return html`
			<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-8" @click=${() => (this.quickLook = null)}>
				<div class="max-h-full w-full max-w-2xl overflow-auto rounded-2xl border border-neutral-700 bg-neutral-900 p-6 shadow-2xl" @click=${(e: Event) => e.stopPropagation()}>
					<div class="flex min-h-64 items-center justify-center rounded-xl bg-black/40">
						${q.url ? html`<img class="max-h-96 rounded" src=${q.url} alt=${q.name} />` : icon(q.kind, "h-24 w-24 text-neutral-700")}
					</div>
					<div class="mt-4 flex items-center justify-between">
						<div>
							<p class="font-medium text-neutral-100">${q.name}</p>
							${q.meta ? html`<p class="text-xs text-neutral-400">${fmtSize(q.meta.size)} · v${q.meta.version} · ${fmtDate(q.meta.updatedAt)} — decrypted here, sealed everywhere else</p>` : nothing}
						</div>
						<div class="flex gap-2"><button class="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-neutral-950 hover:opacity-90" @click=${() => void this.openEntry("file", q.id)}>Open</button><button class="rounded-lg bg-neutral-800 px-3 py-1.5 text-xs hover:bg-neutral-700" @click=${() => void this.downloadSelection()}>Download</button></div>
					</div>
					${q.text ? html`<pre class="mt-3 max-h-80 overflow-auto rounded-xl bg-neutral-950 p-3 text-xs text-neutral-300">${q.text}</pre>` : nothing}
					<p class="mt-3 text-center text-xs text-neutral-500">space / esc closes</p>
				</div>
			</div>
		`;
	}

	private infoPanel(): TemplateResult {
		const i = this.info!;
		return html`
			<div class="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-24" @click=${() => (this.info = null)}>
				<div class="w-96 rounded-2xl border border-neutral-700 bg-neutral-900 p-5 text-sm shadow-2xl" @click=${(e: Event) => e.stopPropagation()}>
					<div class="flex items-center gap-3">
						${icon(i.kind, "h-10 w-10")}
						<p class="truncate text-base font-medium text-neutral-100">${i.name}</p>
					</div>
					<dl class="mt-4 space-y-1.5 text-xs">
						${[["Kind", kindLabel(i.kind)], ["Size", fmtSize(i.size)], ["Version", `v${i.version}`], ["MIME", i.mime ?? "—"], ["Modified", new Date(shownModified(i)).toLocaleString()], ["Uploaded", new Date(i.createdAt).toLocaleString()]].map(([k, v]) => html`<div class="flex justify-between gap-4 border-b border-neutral-800 pb-1.5"><dt class="text-neutral-500">${k}</dt><dd class="truncate text-neutral-300">${v}</dd></div>`)}
					</dl>
					<p class="mt-3 text-xs text-neutral-500">Sealed end to end — the server stored none of these values, they were opened here.</p>
				</div>
			</div>
		`;
	}
}