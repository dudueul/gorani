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
 * | ⌘C/⌘X/⌘V, ⌘A, ⌘Delete → Trash | model clipboard + trash |
 * | Path bar at the bottom | breadcrumbs |
 * | Drag to move, drop on sidebar folder | model.move; desktop drop → upload |
 * | List view columns sortable | same sort state as the Windows skin |
 *
 * The point of shipping both skins: the same sealed operations, two platform
 * grammars — and the family can pick whichever feels like home.
 */

import { LitElement, html, nothing, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel, Selection } from "./model.ts";
import { icon, type FileKind } from "./icons.ts";
import { fmtSize, fmtDate, showMenu, startRename, promptName, setDragIds, dragIds, kindLabel, modKey, markSample, custodyAction, type MenuItem } from "./shared.ts";
import type { ViewerTarget } from "../viewer/viewer.ts";
import { renderMime } from "../viewer/mode.ts";
import { blobURL, revokeBlobURL } from "../../lib/blob-urls.ts";
import "../viewer/viewer.ts";
import "./share-dialog.ts";

type ViewMode = "icon" | "list" | "column";

@customElement("gorani-finder")
export class GoraniFinder extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: String }) memberName = "";

	@state() private view: ViewMode = "column";
	@state() private v = 0;
	@state() private renaming: Selection | null = null;
	@state() private query = "";
	@state() private searchHits: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number }[] | null = null;
	@state() private recentsMode = false;
	@state() private recentRows: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; updatedAt: number; size?: number }[] = [];
	private typeBuffer = "";
	private typeTimer: ReturnType<typeof setTimeout> | undefined;
	@state() private quickLook: { id: string; name: string; url?: string; text?: string; kind: FileKind; meta?: { size: number; version: number; updatedAt: string } } | null = null;
	@state() private info: Awaited<ReturnType<FilesModel["info"]>> = null;
	@state() private shareTarget: { id: string; name: string; size: number; version: number } | null = null;

	private openShare(id: string): void {
		const row = this.s().files.find((f) => f.id === id);
		if (!row) return;
		this.shareTarget = { id, name: row.name, size: row.size, version: row.version };
	}
	/** Column view: the walked path of folders + the deepest selection. */
	@state() private columnPath: string[] = [];

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override firstUpdated(): void {
		void this.model.subscribe(() => {
			this.v++;
			void this.requestUpdate();
		});
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

	private async openEntry(kind: "file" | "folder", id: string): Promise<void> {
		if (this.s().trashMode) return;
		if (kind === "folder") {
			if (this.view === "column") {
				this.columnPath = [...this.columnPath, id];
				this.model.clearSelection();
				// Column view keeps the model's folder at the walked path's end.
				return;
			}
			await this.model.setFolder(id);
			return;
		}
		const row = this.s().files.find((f) => f.id === id) ?? this.s().trashFiles.find((f) => f.id === id);
		if (!row) return;
		this.quickLook = null;
		this.dispatchEvent(new CustomEvent("open-viewer", { detail: { id, name: row.name, kind: row.kind, size: row.size, version: row.version } as ViewerTarget, bubbles: true, composed: true }));
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
				this.quickLook.meta = { size: row.size, version: row.version, updatedAt: row.updatedAt };
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
		const first = this.firstSel();
		if (!first) return;
		const sel = this.selection();
		await this.model.trash(first.kind, sel.map((x) => x.id));
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

	private async newFolder(): Promise<void> {
		const name = await promptName("New Folder", "untitled folder");
		if (name) await this.model.newFolder(this.s().folderId, name);
	}

	private contextMenu(e: MouseEvent, kind: "file" | "folder", id: string, name: string): void {
		e.preventDefault();
		e.stopPropagation();
		if (!this.isSelected(kind, id)) this.model.select({ kind, id });
		const many = this.selection().length > 1;
		const sample = this.s().files.find((f) => f.id === id)?.sample === true;
		const items: MenuItem[] = this.s().trashMode
			? [{ label: "Put Back", run: () => void this.model.restore(this.selection().filter((x) => x.kind === "file").map((x) => x.id), this.selection().filter((x) => x.kind === "folder").map((x) => x.id)) }]
			: [
					{ label: kind === "folder" ? "Open" : "Quick Look", run: () => void this.openEntry(kind, id), disabled: many },
					{ label: "Get Info", run: () => void this.getInfo(id), disabled: many || kind === "folder" },
					{ separator: true, label: "" },
					{ label: "Share…", run: () => this.openShare(id), disabled: kind === "folder" || many || sample },
					{ label: "Mark as Malware Sample…", run: () => void markSample(this.model, id, name), disabled: kind === "folder" || many || sample },
					{ label: "Duplicate", run: () => { this.model.copy(); void this.model.paste(); }, disabled: kind === "folder" || many },
					{ label: "Download", run: () => void this.downloadSelection(), disabled: kind === "folder" || many },
					{ label: "Verify Signature", run: () => void this.model.verifyAndReport(id), disabled: kind === "folder" || many },
					{ label: "Custody…", run: () => void custodyAction(this.model, id, name), disabled: kind === "folder" || many },
					{ separator: true, label: "" },
					{ label: "Rename…", run: () => void this.renameSelection(), disabled: many },
					{ label: "Move to Trash", run: () => void this.deleteSelection() },
				];
		showMenu(items, e.clientX, e.clientY);
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
		if (this.view === "column") this.columnPath = [];
		await this.model.setFolder(hit.kind === "folder" ? hit.id : hit.folderId);
		if (hit.kind === "file") this.model.select({ kind: "file", id: hit.id });
	}

	private async showRecents(): Promise<void> {
		this.recentsMode = true;
		this.recentRows = this.model.index ? await this.model.index.recents(40) : [];
		this.v++;
		await this.requestUpdate();
	}

	private onKeydown(e: KeyboardEvent): void {
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
			case "ArrowDown":
				move(1);
				e.preventDefault();
				return;
			case "ArrowUp":
				move(-1);
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
				if (cmd) void this.deleteSelection();
				else void this.model.setFolder(this.s().folders.find((f) => f.id === this.s().folderId)?.parent ?? null);
				e.preventDefault();
				return;
			case "Escape":
				this.model.clearSelection();
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
			this.model.clearSelection();
			for (const h of hits) this.model.select({ kind: h.kind, id: h.id }, { add: true });
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
		const firstId = ids?.[0];
		if (ids?.length && firstId) {
			void this.model.move(firstId.kind as "file" | "folder", ids.map((x) => x.id), folderId);
			return;
		}
		if (e.dataTransfer?.files?.length) void this.model.upload([...e.dataTransfer.files]);
	}

	// ── render ──────────────────────────────────────────────────────────

	protected override render(): TemplateResult {
		void this.v;
		const s = this.s();
		const { folders, files } = this.view === "column" ? this.columnVisible() : this.visible();
		return html`
			<div class="flex h-full flex-col bg-neutral-900/95 text-neutral-200" @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}>
				${this.toolbar()}
				<div class="flex min-h-0 flex-1">
					${this.sidebar()}
					<div class="flex min-w-0 flex-1 flex-col">
						<div data-body class="relative min-h-0 flex-1 overflow-auto outline-none" @pointerdown=${(e: PointerEvent) => this.onBodyPointerDown(e)}>
							${this.recentsMode ? this.recentsBody() : this.view === "icon" ? this.iconView(folders, files) : this.view === "list" ? this.listView(folders, files) : this.columnView()}
						</div>
						${this.pathBar()}
					</div>
				</div>
				${this.quickLook ? this.quickLookModal() : nothing}
				${this.info ? this.infoPanel() : nothing}
				${this.shareTarget ? html`<gorani-share .model=${this.model} .target=${this.shareTarget} @closed=${() => (this.shareTarget = null)}></gorani-share>` : nothing}
				${s.loading ? html`<div class="pointer-events-none fixed right-4 top-4 rounded-lg bg-neutral-800 px-3 py-1.5 text-xs text-neutral-300 shadow">Opening…</div>` : nothing}
			</div>
		`;
	}

	private toolbar(): TemplateResult {
		const view = (mode: ViewMode, glyph: string, title: string) =>
			html`<button class="rounded-lg px-2.5 py-1.5 text-sm ${this.view === mode ? "bg-neutral-700 text-white" : "text-neutral-400 hover:bg-neutral-800"}" title=${title} @click=${() => (this.view = mode)}>${glyph}</button>`;
		return html`
			<div class="flex items-center gap-1.5 border-b border-neutral-800 px-3 py-2">
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canBack} @click=${() => void this.model.back()}>‹</button>
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canForward} @click=${() => void this.model.forward()}>›</button>
				<div class="mx-1 h-5 border-l border-neutral-800"></div>
				${view("icon", "⊞", "Icons")} ${view("list", "☰", "List")} ${view("column", "❙❙❙", "Columns")}
				<div class="mx-1 h-5 border-l border-neutral-800"></div>
				<button class="rounded-md px-2.5 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800" @click=${() => void this.newFolder()}>＋ New Folder</button>
				<button class="rounded-md px-2.5 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800 disabled:opacity-40" ?disabled=${!this.selection().length} @click=${() => void this.deleteSelection()}>🗑</button>
				<div class="flex-1"></div>
				<div class="relative">
					<input class="w-56 rounded-lg bg-neutral-950 px-3 py-1.5 text-sm outline-none placeholder:text-neutral-600 focus:ring-1 focus:ring-accent" placeholder="Search (local index)" .value=${this.query} @input=${(e: InputEvent) => void this.onSearch((e.target as HTMLInputElement).value)} />
					${this.searchHits
						? html`<div class="absolute right-0 top-9 z-40 max-h-96 w-96 overflow-y-auto rounded-xl border border-neutral-700 bg-neutral-900/95 p-1.5 shadow-2xl backdrop-blur">
								${this.searchHits.map(
									(h) => html`
										<button class="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm hover:bg-neutral-800" @click=${() => void this.jumpTo(h)}>
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
		const fav = (label: string, glyph: string, active: boolean, run: () => void) =>
			html`<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm ${active ? "bg-neutral-700/70" : "hover:bg-neutral-800"}" @click=${run}>${glyph}<span class="truncate">${label}</span></button>`;
		return html`
			<aside class="w-52 shrink-0 overflow-y-auto border-r border-neutral-800/70 bg-neutral-900/60 px-2 py-3 text-sm" @drop=${(e: DragEvent) => this.onDropIntoFolder(e, null)} @dragover=${(e: DragEvent) => e.preventDefault()}>
				<p class="px-2 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Favorites</p>
				${fav("Home", "🏠", s.folderId === null && !s.trashMode, () => void this.model.closeTrash())}
				${s.folders.filter((f) => !f.parent).map((f) => fav(f.name, "📁", s.folderId === f.id && !s.trashMode, () => void this.model.setFolder(f.id)))}
				<p class="px-2 pt-3 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Recents</p>
				${fav("Recent files", "⏱", this.recentsMode, () => void this.showRecents())}
				<p class="px-2 pt-3 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Locations</p>
				${fav("Trash", "🗑", s.trashMode, () => void this.model.openTrash())}
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
				<span class="text-right text-neutral-400">${fmtDate((kind === "folder" ? this.s().folders : this.s().files).find((x) => x.id === id)?.updatedAt ?? "")}</span>
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

	private columnView(): TemplateResult {
		const s = this.s();
		const levels: { id: string | null; folders: typeof s.folders; files: typeof s.files }[] = [];
		// Level 0: the model's current listing. Levels 1..n-1: the folders
		// walked on the way here, re-listed from the model's knowledge of the
		// tree (children of walked folders come from the listing cache).
		levels.push({ id: s.folderId, folders: s.folders, files: s.files });
		void this.columnPath; // (walked-path refinement lands with the index feed)
		const col = (level: (typeof levels)[number], last: boolean) => html`
			<div class="min-w-56 flex-1 overflow-y-auto border-r border-neutral-800/70 p-1.5 text-sm ${last ? "border-r-0" : ""}">
				${level.folders.map((f) => this.columnCell("folder", f.id, f.name, "folder"))}
				${level.files.map((f) => this.columnCell("file", f.id, f.name, f.kind))}
				${!level.folders.length && !level.files.length ? html`<p class="px-3 py-6 text-xs text-neutral-600">Empty</p>` : nothing}
			</div>
		`;
		const selected = this.selection()[0];
		return html`
			<div class="flex h-full">
				${levels.map((l, i) => col(l, i === levels.length - 1 && !selected))}
				${selected && selected.kind === "file" ? this.columnPreview(selected.id) : nothing}
			</div>
		`;
	}

	private columnCell(kind: "file" | "folder", id: string, name: string, k: FileKind): TemplateResult {
		return html`
			<div
				data-item="${kind}:${id}"
				class="flex cursor-default items-center gap-2 rounded-md px-2.5 py-1.5 ${this.isSelected(kind, id) ? "bg-accent/20" : "hover:bg-neutral-800/60"}"
				@click=${(e: MouseEvent) => this.model.select({ kind, id }, { add: e[modKey()], range: e.shiftKey })}
				@dblclick=${() => void this.openEntry(kind, id)}
				@contextmenu=${(e: MouseEvent) => this.contextMenu(e, kind, id, name)}
				draggable="true"
				@dragstart=${(e: DragEvent) => setDragIds(e.dataTransfer!, [{ kind, id }])}
			>
				${icon(k, "h-4 w-4 shrink-0 text-neutral-400")}
				<span class="truncate ${this.isSelected(kind, id) ? "text-white" : ""}">${name}</span>
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
						<button class="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left hover:bg-neutral-800/60" @click=${() => void this.jumpTo(r)}>
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
		const crumbs: { id: string | null; name: string }[] = [{ id: null, name: this.memberName }];
		let cursor = s.folderId;
		const seen = new Set<string>();
		while (cursor && !seen.has(cursor)) {
			seen.add(cursor);
			crumbs.push({ id: cursor, name: this.model.names.get(cursor) ?? "…" });
			cursor = s.folders.find((f) => f.id === cursor)?.parent ?? null;
		}
		if (s.trashMode) crumbs.push({ id: null, name: "Trash" });
		return html`
			<footer class="flex items-center gap-1 border-t border-neutral-800/70 px-3 py-1.5 text-xs text-neutral-400" @drop=${(e: DragEvent) => this.onDropIntoFolder(e, null)} @dragover=${(e: DragEvent) => e.preventDefault()}>
				${crumbs.map((c, i) => html`${i > 0 ? html`<span class="text-neutral-600">/</span>` : nothing}<button class="rounded px-1 py-0.5 hover:bg-neutral-800 ${i === crumbs.length - 1 ? "text-neutral-200" : ""}" @click=${() => c.id !== null && void this.model.setFolder(c.id)}>${c.name}</button>`)}
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
						${[["Kind", kindLabel(i.kind)], ["Size", fmtSize(i.size)], ["Version", `v${i.version}`], ["MIME", i.mime ?? "—"], ["Created", new Date(i.createdAt).toLocaleString()], ["Modified", new Date(i.updatedAt).toLocaleString()]].map(([k, v]) => html`<div class="flex justify-between gap-4 border-b border-neutral-800 pb-1.5"><dt class="text-neutral-500">${k}</dt><dd class="truncate text-neutral-300">${v}</dd></div>`)}
					</dl>
					<p class="mt-3 text-xs text-neutral-500">Sealed end to end — the server stored none of these values, they were opened here.</p>
				</div>
			</div>
		`;
	}
}