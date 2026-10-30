// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-win11>: the Windows 11 File Explorer simulation.
 *
 * What makes it *feel* like Explorer (each mapped to a real operation on the
 * sealed model):
 *
 * | Explorer-ism | Here |
 * |---|---|
 * | Command bar (Win11's ribbon successor) | New ▾ / Sort ▾ / View ▾ / Delete / Rename — model ops |
 * | Breadcrumb address bar | model history + folder path, click a crumb to jump |
 * | Navigation pane with a collapsible tree | folders list from the server (sealed names, opened here) |
 * | Column headers (Name, Date modified, Type, Size) | click to sort; the arrow flips direction |
 * | Four views | Details / List / Small icons / Large icons |
 * | Marquee rubber-band selection | pointer tracking on the body |
 * | Ctrl/Shift selection, Ctrl+A | same keys, same semantics |
 * | F2 rename, Enter open, Delete → Trash; Shift+Delete, and Delete in the Trash → Delete forever (39v: a lead's, or the owner's) | model.rename / setFolder / trash / purge |
 * | Backspace = up one folder | model.setFolder(parent) |
 * | Status bar | counts + selection size |
 * | Context menus (39m) | an item: Open / Download / Download as zip (41a) / Cut / Copy / Paste into / Move to › / Rename / Delete / Delete forever… (39v); the Trash: Restore / Delete forever… / Empty Trash…; empty space: View › / Sort by › / Refresh / Paste / New / Upload / Download this folder as zip / Select all; the tree, Home and Trash rows; search and recent results; the menu key and Shift+F10 |
 * | Drop onto a folder | model.move; drop from the desktop | model.upload (sealed client-side) |
 * | Preview pane | model.preview — decrypted in the browser, nothing sent |
 */

import { LitElement, html, nothing, type PropertyValues, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel, FolderRow, Selection, SortState } from "./model.ts";
import { shownModified } from "./model.ts";
import { icon, type FileKind } from "./icons.ts";
import { cssom, fmtSize, fmtDate, typingInField, showMenu, startRename, promptName, setDragIds, dragIds, kindLabel, modKey, markSample, custodyAction, deleteForever, emptyTrash, moveTargets, takeDrop, isOwnDrag, carriesFiles, uploadStatus, type MenuItem } from "./shared.ts";
import { fromRelativePaths } from "./dropped.ts";
import type { ViewerTarget } from "../viewer/viewer.ts";
import "../viewer/viewer.ts";
import "../viewer/picture.ts";
import type { PictureFile } from "../viewer/picture.ts";
import "./share-dialog.ts";
import "./requests-dialog.ts";
import { showDuplicates } from "./duplicates-dialog.ts";

type ViewMode = "details" | "list" | "small" | "large";

@customElement("gorani-win11")
export class GoraniWin11 extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: String }) memberName = "";
	@property({ type: String }) memberRole = "lead";

	@state() private view: ViewMode = "details";
	@state() private showPreview = true;
	@state() private v = 0; // model subscription tick
	@state() private expanded = new Set<string>();
	@state() private renaming: Selection | null = null;
	@state() private query = "";
	@state() private searchHits: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number }[] | null = null;
	@state() private recentsMode = false;
	/** Files from outside are being dragged over the list (39r): the
	 * outline that says where they will go. */
	@state() private dropHint = false;
	private dropHintTimer: ReturnType<typeof setTimeout> | undefined;
	private typeBuffer = "";
	private typeTimer: ReturnType<typeof setTimeout> | undefined;

	protected override createRenderRoot(): HTMLElement {
		return this;
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

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.unsubscribe?.();
		this.unsubscribe = null;
	}

	private s = () => this.model.state.get();

	private firstSel(): Selection | null {
		return this.s().selection[0] ?? null;
	}

	// ── derived helpers ─────────────────────────────────────────────────

	private visible(): { folders: ReturnType<FilesModel["state"]["get"]>["folders"]; files: ReturnType<FilesModel["state"]["get"]>["files"] } {
		const s = this.s();
		const { folders, files } = this.model.sorted();
		const q = this.query.trim().toLowerCase();
		const hit = <T extends { name: string }>(x: T) => !q || x.name.toLowerCase().includes(q);
		return {
			folders: (s.trashMode ? s.trashFolders : folders).filter(hit),
			files: (s.trashMode ? s.trashFiles : files).filter(hit),
		};
	}

	private path(): { id: string | null; name: string }[] {
		const s = this.s();
		const crumbs: { id: string | null; name: string }[] = [];
		let cursor = s.trashMode ? null : s.folderId;
		while (cursor) {
			const f = s.tree.find((x) => x.id === cursor) ?? null;
			const name = this.model.names.get(cursor) ?? "…";
			crumbs.unshift({ id: cursor, name });
			cursor = f ? (f.parent ?? null) : null;
		}
		crumbs.unshift({ id: null, name: this.memberName });
		if (s.trashMode) crumbs.push({ id: null, name: "Trash" });
		return crumbs;
	}

	/** The folder on screen, by name — where a drop on the list goes. */
	private here(): string {
		const crumbs = this.path();
		return `“${crumbs[crumbs.length - 1]?.name ?? this.memberName}”`;
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

	private async openEntry(kind: "file" | "folder", id: string, name: string): Promise<void> {
		if (this.s().trashMode) return; // trashed items are read-only until restored
		if (kind === "folder") {
			await this.go(id);
			return;
		}
		const row = this.s().files.find((f) => f.id === id);
		if (!row) return;
		// With the folder's other files, in the order shown (41b): ← and → in the viewer.
		const target = (f: typeof row): ViewerTarget => ({ id: f.id, name: f.name, kind: f.kind, size: f.size, version: f.version });
		const siblings = this.s().trashMode ? undefined : this.visible().files.map(target);
		this.dispatchEvent(new CustomEvent("open-viewer", { detail: { ...target(row), siblings } as ViewerTarget, bubbles: true, composed: true }));
	}

	@state() private previewFile: { id: string; name: string; picture?: PictureFile; text?: string; kind: FileKind } | null = null;
	@state() private shareTarget: { id: string; name: string; size: number; version: number; modified: string | null } | null = null;
	/** The upload-links dialog (commit 38): its tab, and the folder a new link files into. */
	@state() private requests: { tab: "inbox" | "links"; folderId: string | null; folderName: string } | null = null;

	private openRequests(tab: "inbox" | "links", folderId: string | null = this.s().folderId, folderName = folderId ? (this.model.names.get(folderId) ?? "") : ""): void {
		this.requests = { tab, folderId, folderName };
	}

	private openShare(id: string, name: string): void {
		const row = this.s().files.find((f) => f.id === id);
		if (!row) return;
		this.shareTarget = { id, name, size: row.size, version: row.version, modified: row.modified };
	}

	private async previewId(id: string): Promise<void> {
		const row = this.s().files.find((f) => f.id === id);
		if (!row) return;
		this.showPreview = true;
		this.previewFile = { id, name: row.name, kind: row.kind };
		if (row.kind === "image" || row.kind === "text" || row.kind === "code") {
			try {
				const p = await this.model.preview(id);
				if (p && this.previewFile?.id === id) {
					// A new object, not a field set on the old one: Lit redraws
					// on an assignment, and a mutation would leave the icon up.
					// A picture is drawn in the preview frame (42d, viewer/picture.ts), not in this page.
					this.previewFile = row.kind === "image" ? { ...this.previewFile, picture: { name: row.name, mime: p.mime, bytes: p.bytes } } : { ...this.previewFile, text: new TextDecoder().decode(p.bytes.subarray(0, 8192)) };
				}
			} catch {
				// previews are best-effort; the icon stays
			}
		}
	}

	private async downloadSelection(): Promise<void> {
		for (const sel of this.selection().filter((s) => s.kind === "file")) {
			const name = this.model.names.get(sel.id) ?? "download";
			await this.model.download(sel.id, name);
		}
	}

	private async deleteSelection(): Promise<void> {
		const sel = this.selection();
		if (!sel.length) return;
		await this.model.trashItems(sel);
	}

	/** Delete forever (39v) — asked first; offered only to whom the server
	 * allows it (model.ts › canPurge), and the keys say why to the rest. */
	private async purgeSelection(): Promise<void> {
		const sel = this.selection();
		if (!sel.length) return;
		if (!this.model.canPurge()) {
			this.model.api.toast(this.model.areaKind() === "evidence" ? "An evidence case's files are never deleted" : "Only a lead deletes forever here — Delete moves it to the Trash");
			return;
		}
		await deleteForever(this.model, sel);
	}

	/** "Delete forever…" — in a menu where the person may, else nothing. */
	private purgeItem(target: { kind: "file" | "folder"; id: string }[]): MenuItem[] {
		return this.model.canPurge() ? [{ label: "Delete forever…", run: () => this.attempt(deleteForever(this.model, target)) }] : [];
	}

	private emptyTrashItem(): MenuItem[] {
		return this.model.canPurge() ? [{ label: "Empty Trash…", run: () => this.attempt(emptyTrash(this.model)) }] : [];
	}

	/** A menu's action: its failure becomes a toast, in the server's words
	 * (an evidence case refusing a deletion, say), instead of vanishing as
	 * an unhandled rejection. */
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
		const name = await promptName("New folder", "New folder");
		if (name) await this.model.newFolder(parent, name);
	}

	/** Rename a folder from the tree: open the folder it is in, select it,
	 * and rename it there — the one place names are edited. */
	private async renameFolderInPlace(id: string): Promise<void> {
		await this.go(this.s().tree.find((f) => f.id === id)?.parent ?? null);
		this.model.select({ kind: "folder", id });
		await this.renameSelection();
	}

	private toggleExpanded(id: string): void {
		const next = new Set(this.expanded);
		next.has(id) ? next.delete(id) : next.add(id);
		this.expanded = next;
	}

	// ── context menus (commit 39m: everywhere a real Explorer has one) ──

	private contextMenu(e: MouseEvent, kind: "file" | "folder", id: string, name: string): void {
		e.preventDefault();
		e.stopPropagation();
		this.itemMenu(kind, id, name, e.clientX, e.clientY);
	}

	/** An item's menu — for the selection it belongs to (right-clicking an
	 * unselected item selects it first, as Explorer does). */
	private itemMenu(kind: "file" | "folder", id: string, name: string, x: number, y: number): void {
		if (!this.isSelected(kind, id)) this.model.select({ kind, id });
		const sel = this.selection();
		const many = sel.length > 1;
		const s = this.s();
		const sample = s.files.find((f) => f.id === id)?.sample === true;
		if (s.trashMode) {
			showMenu(
				[
					{ label: "Restore", run: () => this.attempt(this.model.restore(sel.filter((x) => x.kind === "file").map((x) => x.id), sel.filter((x) => x.kind === "folder").map((x) => x.id))) },
					...this.purgeItem(sel),
					{ separator: true, label: "" },
					{ label: "Select all", run: () => this.model.selectAll() },
				],
				x,
				y,
			);
			return;
		}
		const intoFolder = kind === "folder" && !many;
		const items: MenuItem[] = [
			{ label: "Open", run: () => void this.openEntry(kind, id, name), disabled: many },
			{ label: "Download", run: () => this.attempt(this.downloadSelection()), disabled: !sel.some((x) => x.kind === "file") },
			// (41a) Files and folders, one zip; samples left out, checks inside.
			{ label: "Download as zip", run: () => this.attempt(this.model.downloadZip(sel)) },
			{ label: "Verify signature", run: () => this.attempt(this.model.verifyAndReport(id)), disabled: kind === "folder" || many },
			{ label: "Custody…", run: () => this.attempt(custodyAction(this.model, id, name)), disabled: kind === "folder" || many || this.model.areaKind() !== "evidence" },
			{ separator: true, label: "" },
			{ label: "Cut", run: () => this.model.cut() },
			{ label: "Copy", run: () => this.model.copy() },
			// On a folder, Paste goes INTO it (as Explorer); on a file, here.
			{ label: intoFolder ? "Paste into folder" : "Paste", run: () => this.attempt(this.model.paste(intoFolder ? id : undefined)), disabled: !this.model.canPaste },
			{ separator: true, label: "" },
			{ label: "Share…", run: () => this.openShare(id, name), disabled: kind === "folder" || many || sample },
			{ label: "Request files into this folder…", run: () => this.openRequests("links", id, name), disabled: kind !== "folder" || many },
			{ label: "Mark as malware sample…", run: () => this.attempt(markSample(this.model, id, name)), disabled: kind === "folder" || many || sample },
			{ separator: true, label: "" },
			{ label: "Rename", run: () => void this.renameSelection(), disabled: many },
			{ label: "Move to", submenu: moveTargets(s.tree, sel, s.folderId, this.memberName, (to) => this.attempt(this.model.moveItems(sel, to))) },
			{ label: "Delete", run: () => this.attempt(this.deleteSelection()) },
			...this.purgeItem(sel),
			{ separator: true, label: "" },
			{ label: "Properties", run: () => void this.previewId(id), disabled: many || kind === "folder" },
		];
		showMenu(items, x, y);
	}

	/** Empty space in the folder: what the folder itself can do. */
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
					{ label: "Restore all", run: () => this.attempt(this.model.restore(s.trashFiles.map((f) => f.id), s.trashFolders.map((f) => f.id))), disabled: !any },
					...this.emptyTrashItem().map((m) => ({ ...m, disabled: !any })),
					{ label: "Select all", run: () => this.model.selectAll(), disabled: !any },
					{ separator: true, label: "" },
					{ label: "Refresh", run: () => this.attempt(this.model.refresh()) },
				],
				x,
				y,
			);
			return;
		}
		// Right-clicking empty space leaves the selection, as Explorer does.
		this.model.clearSelection();
		showMenu(
			[
				{ label: "View", submenu: this.viewMenuItems() },
				{ label: "Sort by", submenu: this.sortMenuItems() },
				{ label: "Refresh", run: () => this.attempt(this.model.refresh()) },
				{ separator: true, label: "" },
				{ label: "Paste", run: () => this.attempt(this.model.paste()), disabled: !this.model.canPaste },
				{ separator: true, label: "" },
				{ label: "New folder", icon: icon("folder"), run: () => this.attempt(this.newFolder()) },
				{ label: "Upload files…", icon: icon("file"), run: () => this.pick("[data-upload]") },
				{ label: "Upload folder…", icon: icon("folder"), run: () => this.pickFolder() },
				{ label: "Upload malware samples…", icon: icon("sample"), run: () => this.pick("[data-upload-sample]") },
				{ label: "Request files into this folder…", run: () => this.openRequests("links", s.folderId) },
				{ label: "Download this folder as zip", run: () => this.attempt(this.model.downloadFolderZip(s.folderId, this.memberName)), disabled: !(s.folders.length + s.files.length) },
				{ separator: true, label: "" },
				{ label: "Select all", run: () => this.model.selectAll(), disabled: !(s.folders.length + s.files.length) },
				{ label: "Find duplicates…", run: () => this.openDuplicates() },
				{ label: this.showPreview ? "Hide the preview pane" : "Show the preview pane", run: () => (this.showPreview = !this.showPreview) },
			],
			x,
			y,
		);
	}

	/** Find duplicates (39n): the whole area, wherever the menu was opened. */
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

	/** A folder in the navigation pane's tree. */
	private treeMenu(e: MouseEvent, f: FolderRow): void {
		e.preventDefault();
		e.stopPropagation();
		const tree = this.s().tree;
		const target = [{ kind: "folder" as const, id: f.id }];
		showMenu(
			[
				{ label: "Open", run: () => void this.go(f.id) },
				{ label: this.expanded.has(f.id) ? "Collapse" : "Expand", run: () => this.toggleExpanded(f.id), disabled: !tree.some((c) => c.parent === f.id) },
				{ separator: true, label: "" },
				{ label: "New folder inside", icon: icon("folder"), run: () => this.attempt(this.newFolder(f.id)) },
				{ label: "Paste into folder", run: () => this.attempt(this.model.paste(f.id)), disabled: !this.model.canPaste },
				{ label: "Request files into this folder…", run: () => this.openRequests("links", f.id, f.name) },
				{ label: "Download as zip", run: () => this.attempt(this.model.downloadFolderZip(f.id)) },
				{ separator: true, label: "" },
				{ label: "Rename", run: () => this.attempt(this.renameFolderInPlace(f.id)) },
				{ label: "Move to", submenu: moveTargets(tree, target, f.parent ?? null, this.memberName, (to) => this.attempt(this.model.moveItems(target, to))) },
				{ label: "Delete", run: () => this.attempt(this.model.trashItems(target)) },
				...this.purgeItem(target),
			],
			e.clientX,
			e.clientY,
		);
	}

	/** Home: the area's top folder. */
	private homeMenu(e: MouseEvent): void {
		e.preventDefault();
		showMenu(
			[
				{ label: "Open", run: () => void this.go(null) },
				{ separator: true, label: "" },
				{ label: "New folder", icon: icon("folder"), run: () => this.attempt(this.newFolder(null)) },
				{ label: "Paste", run: () => this.attempt(this.model.paste(null)), disabled: !this.model.canPaste },
				{ label: "Request files into the top folder…", run: () => this.openRequests("links", null) },
				{ label: "Download all as zip", run: () => this.attempt(this.model.downloadFolderZip(null, this.memberName)) },
			],
			e.clientX,
			e.clientY,
		);
	}

	/** The Trash. It empties itself after 30 days (housekeeping); Empty
	 * Trash does it now, for whom may delete forever (39v). An evidence
	 * case's Trash stays empty: nothing there is ever deleted. */
	private trashNavMenu(e: MouseEvent): void {
		e.preventDefault();
		showMenu(
			[
				{ label: "Open", run: () => this.attempt(this.openTrashView()) },
				{
					label: "Restore all",
					run: () =>
						this.attempt(
							(async () => {
								await this.openTrashView();
								const s = this.s();
								if (s.trashFiles.length + s.trashFolders.length) await this.model.restore(s.trashFiles.map((f) => f.id), s.trashFolders.map((f) => f.id));
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

	/** A search hit or a recent file: open it, or open where it lives. */
	private hitMenu(e: MouseEvent, hit: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number }): void {
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
								if (hit.kind === "file") await this.openEntry("file", hit.id, hit.name);
							})(),
						),
				},
				{ label: "Open file location", run: () => this.attempt(this.jumpTo(hit)) },
			],
			e.clientX,
			e.clientY,
		);
	}

	/** The menu key, or Shift+F10: the selection's menu at the item, or the
	 * folder's when nothing is selected. */
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

	// ── keyboard (the Explorer grammar) ─────────────────────────────────

	private async onSearch(q: string): Promise<void> {
		this.query = q;
		if (q.trim().length < 2 || !this.model.index) {
			this.searchHits = null;
			return;
		}
		const hits = await this.model.index.search(q, 40);
		this.searchHits = hits.map((h) => ({ id: h.id, kind: h.kind, folderId: h.folderId, name: h.name, size: h.size }));
	}

	/** Search/recents jump: open the folder, then select the entry. */
	private async jumpTo(hit: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number }): Promise<void> {
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

	@state() private recentRows: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; updatedAt: number; size?: number }[] = [];

	private onKeydown(e: KeyboardEvent): void {
		if (this.renaming || typingInField(e)) return;
		const s = this.s();
		const { folders, files } = this.visible();
		const order = [...folders.map((f) => ({ kind: "folder" as const, id: f.id })), ...files.map((f) => ({ kind: "file" as const, id: f.id }))];
		const at = order.findIndex((o) => this.isSelected(o.kind, o.id));
		const move = (delta: number) => {
			const next = order[Math.max(0, Math.min(order.length - 1, at + delta))] ?? order[0];
			if (next) this.model.select(next, { add: e.shiftKey });
		};
		switch (e.key) {
			case "ArrowDown":
				move(1);
				e.preventDefault();
				return;
			case "ArrowUp":
				move(-1);
				e.preventDefault();
				return;
			case "Home":
				const head = order[0];
				if (head) this.model.select(head, { add: e.shiftKey });
				e.preventDefault();
				return;
			case "End":
				const tail = order[order.length - 1];
				if (tail) this.model.select(tail, { add: e.shiftKey });
				e.preventDefault();
				return;
			case "Enter":
				const cur = order[at];
				if (at >= 0 && cur) void this.openEntry(cur.kind, cur.id, "");
				e.preventDefault();
				return;
			case "F2":
				void this.renameSelection();
				e.preventDefault();
				return;
			case "Delete":
				// Shift+Delete, and Delete in the Trash: for good, as Explorer
				// does (asked first). Plain Delete: to the Trash.
				if (e.shiftKey || s.trashMode) this.attempt(this.purgeSelection());
				else this.attempt(this.deleteSelection());
				e.preventDefault();
				return;
			case "Backspace":
				if (!s.trashMode) {
					const parent = s.tree.find((f) => f.id === s.folderId)?.parent ?? null;
					void this.go(parent);
				}
				e.preventDefault();
				return;
			case " ":
				if (at >= 0) {
					const sel = order[at];
					if (sel && sel.kind === "file") {
						void this.previewId(sel.id);
						e.preventDefault();
					}
				}
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
			case "A":
				if (e[modKey()]) {
					this.model.selectAll();
					e.preventDefault();
				}
				return;
			default:
				// Type-to-jump: plain characters accumulate (500 ms) and select
				// the first item that starts with them — Explorer and Finder
				// share this muscle memory.
				if (e.key.length === 1 && !e[modKey()] && !e.altKey && !e.ctrlKey) {
					this.typeBuffer = (this.typeBuffer + e.key.toLowerCase()).slice(-16);
					clearTimeout(this.typeTimer);
					this.typeTimer = setTimeout(() => (this.typeBuffer = ""), 500);
					const fileHit = files.find((x) => x.name.toLowerCase().startsWith(this.typeBuffer));
					const folderHit = folders.find((x) => x.name.toLowerCase().startsWith(this.typeBuffer));
					const hit = folderHit ?? fileHit;
					if (hit) this.model.select({ kind: folderHit ? "folder" : "file", id: hit.id }, { add: false });
				}
				return;
			case "c":
			case "C":
				if (e[modKey()]) this.model.copy();
				return;
			case "x":
			case "X":
				if (e[modKey()]) this.model.cut();
				return;
			case "v":
			case "V":
				if (e[modKey()]) void this.model.paste();
				return;
			case "+":
			case "=":
				if (e.ctrlKey) this.view = "large";
				return;
		}
	}

	// ── marquee selection ───────────────────────────────────────────────

	private marquee: { x0: number; y0: number; el: HTMLDivElement } | null = null;

	private onBodyPointerDown(e: PointerEvent): void {
		if (e.button !== 0) return;
		if ((e.target as HTMLElement).closest("[data-item]")) return;
		this.model.clearSelection();
		const body = this.querySelector("[data-body]") as HTMLElement;
		const rect = body.getBoundingClientRect();
		const el = document.createElement("div");
		el.className = "fixed z-40 border border-accent/60 bg-accent/10 pointer-events-none";
		document.body.append(el);
		this.marquee = { x0: e.clientX, y0: e.clientY, el };
		const move = (ev: PointerEvent) => {
			if (!this.marquee) return;
			const x = Math.min(this.marquee.x0, ev.clientX);
			const y = Math.min(this.marquee.y0, ev.clientY);
			const w = Math.abs(ev.clientX - this.marquee.x0);
			const h = Math.abs(ev.clientY - this.marquee.y0);
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
			this.marquee?.el.remove();
			this.marquee = null;
			window.removeEventListener("pointermove", move);
			window.removeEventListener("pointerup", up);
		};
		window.addEventListener("pointermove", move);
		window.addEventListener("pointerup", up);
	}

	// ── drag & drop ─────────────────────────────────────────────────────

	private onDropIntoFolder(e: DragEvent, folderId: string | null): void {
		e.preventDefault();
		e.stopPropagation();
		const ids = dragIds(e.dataTransfer!);
		if (ids?.length) {
			// Files and folders together, each by its own kind (moveItems).
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

	/** Dragged over the list: files from outside may drop here (and show
	 * where); our own items are moved by the rows they land on. */
	private onBodyDragOver(e: DragEvent): void {
		if (!e.dataTransfer || isOwnDrag(e.dataTransfer) || !carriesFiles(e.dataTransfer)) return;
		e.preventDefault();
		e.dataTransfer.dropEffect = "copy";
		this.dropHint = true;
		clearTimeout(this.dropHintTimer);
		// dragover repeats every few hundred ms while the pointer stays; when
		// it stops coming, the drag has left (dragleave fires for every child).
		this.dropHintTimer = setTimeout(() => (this.dropHint = false), 400);
	}

	private onBodyDrop(e: DragEvent): void {
		this.dropHint = false;
		if (!e.dataTransfer || isOwnDrag(e.dataTransfer) || !carriesFiles(e.dataTransfer)) return;
		e.preventDefault();
		this.uploadDrop(e.dataTransfer, this.s().folderId);
	}

	private pickFolder(): void {
		this.pick("[data-upload-folder]");
	}

	// ── render ──────────────────────────────────────────────────────────

	protected override render(): TemplateResult {
		void this.v; // re-renders on the model's tick
		const s = this.s();
		const { folders, files } = this.visible();
		return html`
			<div class="flex h-full flex-col bg-neutral-900 text-neutral-200 outline-none" tabindex="-1" @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}>
				${this.commandBar()}
				${this.addressBar()}
				<div class="flex min-h-0 flex-1">
					${this.navPane()}
					<div class="flex min-w-0 flex-1 flex-col">
						<div data-body class="relative min-h-0 flex-1 overflow-auto outline-none" @pointerdown=${(e: PointerEvent) => this.onBodyPointerDown(e)} @contextmenu=${(e: MouseEvent) => this.backgroundMenu(e)} @dragover=${(e: DragEvent) => this.onBodyDragOver(e)} @drop=${(e: DragEvent) => this.onBodyDrop(e)}>
							${this.recentsMode ? this.recentsBody() : this.view === "details" ? this.detailsBody(folders, files) : this.iconsBody(folders, files)}
							${this.dropHint ? html`<div class="pointer-events-none absolute inset-2 flex items-center justify-center rounded-xl border-2 border-dashed border-accent/70 bg-accent/5 text-sm text-neutral-200" data-test="drop-hint">Drop to upload into ${this.here()}</div>` : nothing}
						</div>
						${this.statusBar(folders.length, files.length)}
					</div>
					${this.showPreview ? this.previewPane() : nothing}
				</div>
				${this.shareTarget ? html`<gorani-share .model=${this.model} .target=${this.shareTarget} @closed=${() => (this.shareTarget = null)}></gorani-share>` : nothing}
				${this.requests ? html`<gorani-requests .model=${this.model} .tab=${this.requests.tab} .folderId=${this.requests.folderId} .folderName=${this.requests.folderName} @closed=${() => (this.requests = null)}></gorani-requests>` : nothing}
			</div>
		`;
	}

	private commandBar(): TemplateResult {
		const sel = this.selection();
		const one = sel.length === 1;
		return html`
			<div class="flex items-center gap-1 border-b border-neutral-800 px-2 py-1.5 text-sm">
				<div class="relative">
					<button class="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 hover:bg-neutral-800" @click=${(e: MouseEvent) => showMenu([
						{ label: "Folder", icon: icon("folder"), run: () => void this.newFolder() },
						{ label: "Upload files…", icon: icon("file"), run: () => (this.querySelector<HTMLInputElement>("[data-upload]") as HTMLInputElement)?.click() },
						{ label: "Upload folder…", icon: icon("folder"), run: () => this.pickFolder() },
						// Marked from the first byte (commit 29e): never previewed, never linked.
						{ label: "Upload malware samples…", icon: icon("sample"), run: () => (this.querySelector<HTMLInputElement>("[data-upload-sample]") as HTMLInputElement)?.click() },
					], e.clientX, e.clientY)}>
						<span class="text-accent">＋</span> New <span class="text-neutral-500">▾</span>
					</button>
				</div>
				<button class="rounded-md px-2.5 py-1.5 hover:bg-neutral-800 disabled:opacity-40" ?disabled=${!sel.length} @click=${() => this.attempt(this.s().trashMode ? this.purgeSelection() : this.deleteSelection())}>🗑 Delete</button>
				<button class="rounded-md px-2.5 py-1.5 hover:bg-neutral-800 disabled:opacity-40" ?disabled=${!one} @click=${() => void this.renameSelection()}>✏️ Rename</button>
				<button class="rounded-md px-2.5 py-1.5 hover:bg-neutral-800" title="Upload links for people outside the team, and what they sent" data-test="files-requests" @click=${() => this.openRequests("inbox")}>📥 Inbox</button>
				<div class="mx-1 h-5 border-l border-neutral-800"></div>
				<button class="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 hover:bg-neutral-800" @click=${(e: MouseEvent) => showMenu(this.sortMenuItems(), e.clientX, e.clientY)}>⇅ Sort <span class="text-neutral-500">▾</span></button>
				<button class="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 hover:bg-neutral-800" @click=${(e: MouseEvent) => showMenu(this.viewMenuItems(), e.clientX, e.clientY)}>▦ View <span class="text-neutral-500">▾</span></button>
				<div class="flex-1"></div>
				<button class="rounded-md px-2.5 py-1.5 hover:bg-neutral-800 ${this.showPreview ? "bg-neutral-800" : ""}" title="Preview pane" @click=${() => (this.showPreview = !this.showPreview)}>◧</button>
				<input data-upload type="file" multiple class="hidden" @change=${(e: Event) => {
					const input = e.target as HTMLInputElement;
					if (input.files?.length) void this.model.upload([...input.files]);
					input.value = "";
				}} />
				<input data-upload-sample type="file" multiple class="hidden" @change=${(e: Event) => {
					const input = e.target as HTMLInputElement;
					if (input.files?.length) void this.model.upload([...input.files], { sample: true });
					input.value = "";
				}} />
				<!-- A whole folder, its subfolders included (39r): each file
				     arrives with its webkitRelativePath. -->
				<input data-upload-folder type="file" webkitdirectory multiple class="hidden" @change=${(e: Event) => {
					const input = e.target as HTMLInputElement;
					const files = [...(input.files ?? [])];
					input.value = "";
					if (files.length) this.attempt(Promise.resolve().then(() => this.model.uploadTree(fromRelativePaths(files), this.s().folderId)));
				}} />
			</div>
		`;
	}

	private sortMenuItems(): MenuItem[] {
		const cur = this.s().sort;
		const item = (by: SortState["by"], label: string): MenuItem => ({ label, checked: cur.by === by, run: () => cur.by !== by && this.model.sortBy(by) });
		return [
			item("name", "Name"),
			item("modified", "Date modified"),
			item("type", "Type"),
			item("size", "Size"),
			{ separator: true, label: "" },
			{ label: "Ascending", checked: cur.dir === "asc", run: () => this.model.sortDirection("asc") },
			{ label: "Descending", checked: cur.dir === "desc", run: () => this.model.sortDirection("desc") },
		];
	}

	private viewMenuItems(): MenuItem[] {
		const item = (mode: ViewMode, label: string): MenuItem => ({ label, checked: this.view === mode, run: () => (this.view = mode) });
		return [item("details", "Details"), item("list", "List"), item("small", "Small icons"), item("large", "Large icons")];
	}

	private addressBar(): TemplateResult {
		const crumbs = this.path();
		return html`
			<div class="flex items-center gap-1 border-b border-neutral-800 px-2 py-1.5">
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canBack} @click=${() => { this.recentsMode = false; this.searchHits = null; void this.model.back(); }}>←</button>
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canForward} @click=${() => { this.recentsMode = false; this.searchHits = null; void this.model.forward(); }}>→</button>
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800" title="Up one folder" @click=${() => void this.go(this.s().tree.find((f) => f.id === this.s().folderId)?.parent ?? null)}>↑</button>
				<!-- Each crumb takes a drop into ITS folder (39r: the whole bar
				     used to, into the top folder, whichever crumb it landed on). -->
				<nav class="mx-1 flex min-w-0 flex-1 items-center gap-1 overflow-x-auto rounded-lg bg-neutral-950 px-2.5 py-1.5 text-sm">
					${crumbs.map((c, i) => {
						const trash = this.s().trashMode && i === crumbs.length - 1;
						return html`${i > 0 ? html`<span class="text-neutral-600">›</span>` : nothing}
						<button class="whitespace-nowrap rounded px-1.5 py-0.5 hover:bg-neutral-800 ${i === crumbs.length - 1 ? "text-neutral-100" : "text-neutral-400"}" @click=${() => void this.go(c.id)} @drop=${(e: DragEvent) => !trash && this.onDropIntoFolder(e, c.id)} @dragover=${(e: DragEvent) => !trash && e.preventDefault()}>${c.name}</button>`;
					})}
				</nav>
				<div class="relative">
					<input class="w-52 rounded-lg bg-neutral-950 px-3 py-1.5 text-sm outline-none placeholder:text-neutral-600 focus:ring-1 focus:ring-accent" placeholder="Search (this device's index)" .value=${this.query} @input=${(e: InputEvent) => void this.onSearch((e.target as HTMLInputElement).value)} />
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

	private navPane(): TemplateResult {
		const s = this.s();
		return html`
			<aside class="w-60 shrink-0 overflow-y-auto border-r border-neutral-800 px-2 py-3 text-sm">
				<p class="px-2 pb-1 text-xs uppercase tracking-wide text-neutral-500">Quick access</p>
				<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 ${s.folderId === null && !s.trashMode ? "bg-neutral-800" : "hover:bg-neutral-800"}" data-nav="home" @click=${() => void this.go(null)} @contextmenu=${(e: MouseEvent) => this.homeMenu(e)}>
					${icon("folder")} Home
				</button>
				<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 ${this.recentsMode ? "bg-neutral-800" : "hover:bg-neutral-800"}" @click=${() => void this.showRecents()}>
					⏱ Recent files
				</button>
				<p class="px-2 pt-3 pb-1 text-xs uppercase tracking-wide text-neutral-500">${this.memberName}'s folders</p>
				${this.treeRows(null, 0)}
				<p class="px-2 pt-3 pb-1 text-xs uppercase tracking-wide text-neutral-500"></p>
				<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 ${s.trashMode ? "bg-neutral-800" : "hover:bg-neutral-800"}" data-nav="trash" @click=${() => void this.openTrashView()} @contextmenu=${(e: MouseEvent) => this.trashNavMenu(e)}>
					🗑 Trash
				</button>
			</aside>
		`;
	}

	private treeRows(parent: string | null, depth: number): TemplateResult[] {
		const s = this.s();
		return s.tree
			.filter((f) => (f.parent ?? null) === parent)
			.map(
				(f) => html`
					<div>
						<button
							class="flex w-full items-center gap-1.5 rounded-lg py-1.5 pr-2.5 hover:bg-neutral-800 ${s.folderId === f.id && !s.trashMode ? "bg-neutral-800" : ""}"
							${cssom({ "padding-left": `${8 + depth * 14}px` })}
							data-tree="${f.id}"
							@click=${() => void this.go(f.id)}
							@contextmenu=${(e: MouseEvent) => this.treeMenu(e, f)}
							@drop=${(e: DragEvent) => this.onDropIntoFolder(e, f.id)}
							@dragover=${(e: DragEvent) => e.preventDefault()}
						>
							<span class="w-4 text-neutral-500 hover:text-neutral-200" @click=${(e: Event) => {
								e.stopPropagation();
								this.toggleExpanded(f.id);
							}}>${this.expanded.has(f.id) ? "▾" : "▸"}</span>
							${icon("folder")} <span class="truncate">${f.name}</span>
						</button>
						${this.expanded.has(f.id) ? this.treeRows(f.id, depth + 1) : nothing}
					</div>
				`,
			);
	}

	private detailsBody(folders: ReturnType<FilesModel["state"]["get"]>["folders"], files: ReturnType<FilesModel["state"]["get"]>["files"]): TemplateResult {
		const cols = "grid grid-cols-[minmax(0,1fr)_130px_110px_88px]";
		const sortArrow = (by: string) => (this.s().sort.by === by ? (this.s().sort.dir === "asc" ? " ▲" : " ▼") : "");
		const item = (kind: "file" | "folder", id: string, name: string, k: FileKind, modified: string, size: number | null) => html`
			<div
				data-item="${kind}:${id}"
				class="${cols} cursor-default items-center rounded-md px-2 py-1.5 text-sm ${this.isSelected(kind, id) ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-neutral-800/60"}"
				@click=${(e: MouseEvent) => this.model.select({ kind, id }, { add: e[modKey()], range: e.shiftKey })}
				@dblclick=${() => void this.openEntry(kind, id, name)}
				@contextmenu=${(e: MouseEvent) => this.contextMenu(e, kind, id, name)}
				draggable="true"
				@dragstart=${(e: DragEvent) => setDragIds(e.dataTransfer!, this.selection().length ? this.selection() : [{ kind, id }])}
				@drop=${(e: DragEvent) => kind === "folder" && this.onDropIntoFolder(e, id)}
				@dragover=${(e: DragEvent) => kind === "folder" && e.preventDefault()}
			>
				<span data-rename="${id}" class="flex min-w-0 items-center gap-2.5">${icon(k as FileKind)}<span class="truncate">${name}</span></span>
				<span class="text-neutral-400">${fmtDate(modified)}</span>
				<span class="text-neutral-400">${kind === "folder" ? "Folder" : kindLabel(k as FileKind)}</span>
				<span class="text-right text-neutral-400">${size === null ? "" : fmtSize(size)}</span>
			</div>
		`;
		return html`
			<div class="${cols} sticky top-0 z-10 border-b border-neutral-800 bg-neutral-900 px-2 py-1.5 text-xs text-neutral-400">
				<button class="text-left hover:text-neutral-200" @click=${() => this.model.sortBy("name")}>Name${sortArrow("name")}</button>
				<button class="text-left hover:text-neutral-200" @click=${() => this.model.sortBy("modified")}>Date modified${sortArrow("modified")}</button>
				<button class="text-left hover:text-neutral-200" @click=${() => this.model.sortBy("type")}>Type${sortArrow("type")}</button>
				<button class="text-right hover:text-neutral-200" @click=${() => this.model.sortBy("size")}>Size${sortArrow("size")}</button>
			</div>
			<div class="p-2 [content-visibility:auto]">
				${folders.map((f) => item("folder", f.id, f.name, "folder", f.updatedAt, null))}
				${files.map((f) => item("file", f.id, f.name, f.kind, shownModified(f), f.size))}
				${!folders.length && !files.length ? html`<p class="p-8 text-center text-sm text-neutral-500">${this.s().loading ? "Opening…" : "This folder is empty"}</p>` : nothing}
			</div>
		`;
	}

	private iconsBody(folders: ReturnType<FilesModel["state"]["get"]>["folders"], files: ReturnType<FilesModel["state"]["get"]>["files"]): TemplateResult {
		const large = this.view === "large";
		const cell = (kind: "file" | "folder", id: string, name: string, k: FileKind) => html`
			<div
				data-item="${kind}:${id}"
				class="flex ${large ? "h-28 w-28 flex-col" : "h-16 w-full flex-row items-center"} items-center justify-center gap-2 rounded-lg p-2 text-center text-xs ${this.isSelected(kind, id) ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-neutral-800/60"}"
				@click=${(e: MouseEvent) => this.model.select({ kind, id }, { add: e[modKey()], range: e.shiftKey })}
				@dblclick=${() => void this.openEntry(kind, id, name)}
				@contextmenu=${(e: MouseEvent) => this.contextMenu(e, kind, id, name)}
				draggable="true"
				@dragstart=${(e: DragEvent) => setDragIds(e.dataTransfer!, this.selection().length ? this.selection() : [{ kind, id }])}
				@drop=${(e: DragEvent) => kind === "folder" && this.onDropIntoFolder(e, id)}
				@dragover=${(e: DragEvent) => kind === "folder" && e.preventDefault()}
			>
				${icon(k, large ? "h-14 w-14" : "h-8 w-8 shrink-0")}
				<span data-rename="${id}" class="${large ? "line-clamp-2" : "truncate"} text-neutral-200">${name}</span>
			</div>
		`;
		return html`
			<div class="grid gap-1.5 p-3 [content-visibility:auto] ${large ? "grid-cols-[repeat(auto-fill,minmax(112px,1fr))]" : this.view === "small" ? "grid-cols-[repeat(auto-fill,minmax(240px,1fr))]" : "grid-cols-[repeat(auto-fill,minmax(180px,1fr))]"}">
				${folders.map((f) => cell("folder", f.id, f.name, "folder"))}
				${files.map((f) => cell("file", f.id, f.name, f.kind))}
				${!folders.length && !files.length ? html`<p class="col-span-full p-8 text-center text-sm text-neutral-500">${this.s().loading ? "Opening…" : "This folder is empty"}</p>` : nothing}
			</div>
		`;
	}

	/** Recents (both OSes have it; fed by the local index, no server). */
	private recentsBody(): TemplateResult {
		const rows = this.recentRows;
		return html`
			<div class="p-2 text-sm">
				<p class="px-2 pb-2 text-xs uppercase tracking-wide text-neutral-500">Recently touched on this device — opened from the local index</p>
				${rows.map(
					(r) => html`
						<button class="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left hover:bg-neutral-800/60" data-recent="${r.id}" @click=${() => void this.jumpTo(r)} @contextmenu=${(e: MouseEvent) => this.hitMenu(e, r)}>
							${icon(r.kind === "folder" ? "folder" : "file")}<span class="min-w-0 flex-1 truncate">${r.name}</span>
							${r.size !== undefined ? html`<span class="text-xs text-neutral-400">${fmtSize(r.size)}</span>` : nothing}
							<span class="text-xs text-neutral-500">${fmtDate(new Date(r.updatedAt).toISOString())}</span>
						</button>
					`,
				)}
				${!rows.length ? html`<p class="p-8 text-center text-sm text-neutral-500">Nothing indexed yet — browse a folder first.</p>` : nothing}
			</div>
		`;
	}

	private statusBar(folderCount: number, fileCount: number): TemplateResult {
		const sel = this.selection();
		const bytes = sel.reduce((n, x) => n + (x.kind === "file" ? (this.s().files.find((f) => f.id === x.id)?.size ?? 0) : 0), 0);
		return html`
			<footer class="flex items-center gap-4 border-t border-neutral-800 px-3 py-1.5 text-xs text-neutral-400">
				<span>${folderCount + fileCount} item${folderCount + fileCount === 1 ? "" : "s"}</span>
				${sel.length ? html`<span>${sel.length} selected${bytes ? ` · ${fmtSize(bytes)}` : ""}</span>` : nothing}
				${uploadStatus(this.s().upload, () => this.model.stopUpload())}
				<span class="flex-1"></span>
				${this.s().trashMode ? html`<span class="text-amber-400">Trash — restore what you need; the rest is purged after 30 days</span>` : html`<span>sealed · end to end</span>`}
			</footer>
		`;
	}

	private previewPane(): TemplateResult {
		const sel = this.selection()[0];
		const p = this.previewFile;
		const row = sel && sel.kind === "file" ? this.s().files.find((f) => f.id === sel.id) : undefined;
		return html`
			<aside class="w-72 shrink-0 overflow-y-auto border-l border-neutral-800 p-4 text-sm">
				${p && sel && p.id === sel.id
					? html`
							<div class="flex h-40 items-center justify-center rounded-xl bg-neutral-950">
								${p.picture ? html`<gorani-picture class="block h-full w-full" data-test="preview-picture" .file=${p.picture} .fallback=${icon(p.kind as never, "h-16 w-16 text-neutral-600")}></gorani-picture>` : icon(p.kind as never, "h-16 w-16 text-neutral-600")}
							</div>
							<p class="mt-3 truncate font-medium text-neutral-100">${p.name}</p>
							${p.text ? html`<pre class="mt-2 max-h-64 overflow-auto rounded-lg bg-neutral-950 p-2 text-xs text-neutral-300">${p.text}</pre>` : nothing}
							${row
								? html`<dl class="mt-3 space-y-1 text-xs text-neutral-400">
										<div class="flex justify-between"><dt>Size</dt><dd>${fmtSize(row.size)}</dd></div>
										<div class="flex justify-between"><dt>Modified</dt><dd data-test="preview-modified">${fmtDate(shownModified(row))}</dd></div>
										<div class="flex justify-between"><dt>Uploaded</dt><dd>${fmtDate(row.createdAt)}</dd></div>
										<div class="flex justify-between"><dt>Version</dt><dd>v${row.version}</dd></div>
									</dl>`
								: nothing}
						`
					: html`<p class="pt-16 text-center text-xs text-neutral-600">Select a file to preview it here — opened in this browser, sealed everywhere else.</p>`}
			</aside>
		`;
	}
}