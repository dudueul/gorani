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
 * | F2 rename, Enter open, Delete → Trash | model.rename / setFolder / trash |
 * | Backspace = up one folder | model.setFolder(parent) |
 * | Status bar | counts + selection size |
 * | Context menu | Open / Download / Rename / Move to… / Delete |
 * | Drop onto a folder | model.move; drop from the desktop | model.upload (sealed client-side) |
 * | Preview pane | model.preview — decrypted in the browser, nothing sent |
 */

import { LitElement, html, nothing, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel, Selection } from "./model.ts";
import { icon, type FileKind } from "./icons.ts";
import { fmtSize, fmtDate, showMenu, startRename, promptName, setDragIds, dragIds, kindLabel, modKey, type MenuItem } from "./shared.ts";

type ViewMode = "details" | "list" | "small" | "large";

@customElement("gorani-win11")
export class GoraniWin11 extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: String }) memberName = "";
	@property({ type: String }) memberRole = "parent";

	@state() private view: ViewMode = "details";
	@state() private showPreview = true;
	@state() private v = 0; // model subscription tick
	@state() private expanded = new Set<string>();
	@state() private renaming: Selection | null = null;
	@state() private query = "";
	@state() private searchHits: { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number }[] | null = null;
	@state() private recentsMode = false;
	private typeBuffer = "";
	private typeTimer: ReturnType<typeof setTimeout> | undefined;

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
			const f = s.folders.find((x) => x.id === cursor) ?? this.model.names.get(cursor)?.[0] ?? null;
			const name = this.model.names.get(cursor) ?? "…";
			crumbs.unshift({ id: cursor, name });
			cursor = f ? (s.folders.find((x) => x.id === cursor)?.parent ?? null) : null;
		}
		crumbs.unshift({ id: null, name: this.memberName });
		if (s.trashMode) crumbs.push({ id: null, name: "Trash" });
		return crumbs;
	}

	private isSelected(kind: string, id: string): boolean {
		return this.s().selection.some((x) => x.kind === kind && x.id === id);
	}

	// ── operations ──────────────────────────────────────────────────────

	private selection(): Selection[] {
		return this.s().selection;
	}

	private async openEntry(kind: "file" | "folder", id: string, name: string): Promise<void> {
		if (this.s().trashMode) return; // trashed items are read-only until restored
		if (kind === "folder") {
			await this.model.setFolder(id);
			return;
		}
		// Files open in the viewer pane for now (the full viewer lands with
		// the streaming commit); images and text preview here.
		await this.previewId(id);
		void name;
	}

	@state() private previewFile: { id: string; name: string; url?: string; text?: string; kind: FileKind } | null = null;

	private async previewId(id: string): Promise<void> {
		const row = this.s().files.find((f) => f.id === id);
		if (!row) return;
		this.showPreview = true;
		this.previewFile = { id, name: row.name, kind: row.kind };
		if (row.kind === "image" || row.kind === "text" || row.kind === "code") {
			try {
				const p = await this.model.preview(id);
				if (p && this.previewFile?.id === id) {
					if (row.kind === "image") this.previewFile.url = URL.createObjectURL(new Blob([p.bytes as BlobPart], { type: p.mime }));
					else this.previewFile.text = new TextDecoder().decode(p.bytes.subarray(0, 8192));
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
		const name = await promptName("New folder", "New folder");
		if (name) await this.model.newFolder(this.s().folderId, name);
	}

	private moveMenu(folderId: string | null, x: number, y: number): void {
		const s = this.s();
		const items: MenuItem[] = [
			{ label: "Home", run: () => { const f = this.firstSel(); if (!f) return; void this.model.move(f.kind, this.selection().map((x) => x.id), null); } },
			...(s.folders
				.filter((f) => !this.selection().some((x) => x.id === f.id))
				.map((f) => ({ label: f.name, run: () => { const it = this.firstSel(); if (!it) return; void this.model.move(it.kind, this.selection().map((x) => x.id), f.id); } }))),
			{ separator: true, label: "" },
			{ label: folderId === null ? "(you are here)" : "Cancel", run: () => {} },
		];
		void folderId;
		showMenu(items, x, y);
	}

	private contextMenu(e: MouseEvent, kind: "file" | "folder", id: string, name: string): void {
		e.preventDefault();
		e.stopPropagation();
		if (!this.isSelected(kind, id)) this.model.select({ kind, id });
		const many = this.selection().length > 1;
		const s = this.s();
		const items: MenuItem[] = s.trashMode
			? [
					{ label: "Restore", run: () => void this.model.restore(this.selection().filter((x) => x.kind === "file").map((x) => x.id), this.selection().filter((x) => x.kind === "folder").map((x) => x.id)) },
				]
			: [
					{ label: "Open", run: () => void this.openEntry(kind, id, name), disabled: many },
					{ label: "Download", run: () => void this.downloadSelection(), disabled: kind === "folder" || many },
					{ separator: true, label: "" },
					{ label: "Cut", run: () => this.model.cut() },
					{ label: "Copy", run: () => this.model.copy() },
					{ separator: true, label: "" },
					{ label: "Rename", run: () => void this.renameSelection(), disabled: many },
					{ label: "Move to…", run: () => void 0, disabled: many },
					{ label: "Delete", run: () => void this.deleteSelection() },
					{ separator: true, label: "" },
					{ label: "Paste", run: () => void this.model.paste(), disabled: !this.s().selection.length },
					{ label: "Properties", run: () => void this.previewId(id), disabled: many },
				];
		// "Move to…" needs the pointer position — splice it with a flyout-less
		// submenu stand-in: a second menu listing destinations.
		if (!s.trashMode) {
			const moveItem = items.findIndex((x) => x.label === "Move to…");
			items[moveItem] = {
				label: "Move to…",
				run: () => this.moveMenu(this.s().folderId, e.clientX + 10, e.clientY),
				disabled: many || kind === undefined,
			};
		}
		showMenu(items, e.clientX, e.clientY);
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
		await this.model.setFolder(hit.kind === "folder" ? hit.id : hit.folderId);
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
		if (this.renaming) return;
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
				void this.deleteSelection();
				e.preventDefault();
				return;
			case "Backspace":
				if (!s.trashMode) {
					const parent = s.folders.find((f) => f.id === s.folderId)?.parent ?? null;
					void this.model.setFolder(parent);
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
			for (const h of hits) this.model.select({ kind: h.kind, id: h.id }, { add: true });
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
		const firstId = ids?.[0];
		if (ids?.length && firstId) {
			void this.model.move(firstId.kind as "file" | "folder", ids.map((x) => x.id), folderId);
			return;
		}
		if (e.dataTransfer?.files?.length) {
			void this.model.upload([...e.dataTransfer.files]);
		}
	}

	// ── render ──────────────────────────────────────────────────────────

	protected override render(): TemplateResult {
		void this.v; // re-renders on the model's tick
		const s = this.s();
		const { folders, files } = this.visible();
		return html`
			<div class="flex h-full flex-col bg-neutral-900 text-neutral-200" @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}>
				${this.commandBar()}
				${this.addressBar()}
				<div class="flex min-h-0 flex-1">
					${this.navPane()}
					<div class="flex min-w-0 flex-1 flex-col">
						<div data-body class="relative min-h-0 flex-1 overflow-auto outline-none" @pointerdown=${(e: PointerEvent) => this.onBodyPointerDown(e)}>
							${this.recentsMode ? this.recentsBody() : this.view === "details" ? this.detailsBody(folders, files) : this.iconsBody(folders, files)}
						</div>
						${this.statusBar(folders.length, files.length)}
					</div>
					${this.showPreview ? this.previewPane() : nothing}
				</div>
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
					], e.clientX, e.clientY)}>
						<span class="text-accent">＋</span> New <span class="text-neutral-500">▾</span>
					</button>
				</div>
				<button class="rounded-md px-2.5 py-1.5 hover:bg-neutral-800 disabled:opacity-40" ?disabled=${!sel.length} @click=${() => void this.deleteSelection()}>🗑 Delete</button>
				<button class="rounded-md px-2.5 py-1.5 hover:bg-neutral-800 disabled:opacity-40" ?disabled=${!one} @click=${() => void this.renameSelection()}>✏️ Rename</button>
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
			</div>
		`;
	}

	private sortMenuItems(): MenuItem[] {
		const cur = this.s().sort;
		const item = (by: "name" | "modified" | "type" | "size", label: string): MenuItem => ({
			label: `${cur.by === by ? (cur.dir === "asc" ? "↑ " : "↓ ") : ""}${label}`,
			run: () => this.model.sortBy(by),
		});
		return [item("name", "Name"), item("modified", "Date modified"), item("type", "Type"), item("size", "Size")];
	}

	private viewMenuItems(): MenuItem[] {
		const item = (mode: ViewMode, label: string): MenuItem => ({
			label: `${this.view === mode ? "✓ " : ""}${label}`,
			run: () => (this.view = mode),
		});
		return [item("details", "Details"), item("list", "List"), item("small", "Small icons"), item("large", "Large icons")];
	}

	private addressBar(): TemplateResult {
		const crumbs = this.path();
		return html`
			<div class="flex items-center gap-1 border-b border-neutral-800 px-2 py-1.5">
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canBack} @click=${() => void this.model.back()}>←</button>
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800 disabled:opacity-30" ?disabled=${!this.model.canForward} @click=${() => void this.model.forward()}>→</button>
				<button class="rounded-md px-2 py-1 text-neutral-400 hover:bg-neutral-800" title="Up one folder" @click=${() => void this.model.setFolder(this.s().folders.find((f) => f.id === this.s().folderId)?.parent ?? null)}>↑</button>
				<nav class="mx-1 flex min-w-0 flex-1 items-center gap-1 overflow-x-auto rounded-lg bg-neutral-950 px-2.5 py-1.5 text-sm" @drop=${(e: DragEvent) => this.onDropIntoFolder(e, null)} @dragover=${(e: DragEvent) => e.preventDefault()}>
					${crumbs.map((c, i) =>
						html`${i > 0 ? html`<span class="text-neutral-600">›</span>` : nothing}
						<button class="whitespace-nowrap rounded px-1.5 py-0.5 hover:bg-neutral-800 ${i === crumbs.length - 1 ? "text-neutral-100" : "text-neutral-400"}" @click=${() => c.id !== null && void this.model.setFolder(c.id)}>${c.name}</button>`,
					)}
				</nav>
				<div class="relative">
					<input class="w-52 rounded-lg bg-neutral-950 px-3 py-1.5 text-sm outline-none placeholder:text-neutral-600 focus:ring-1 focus:ring-accent" placeholder="Search (this device's index)" .value=${this.query} @input=${(e: InputEvent) => void this.onSearch((e.target as HTMLInputElement).value)} />
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

	private navPane(): TemplateResult {
		const s = this.s();
		return html`
			<aside class="w-60 shrink-0 overflow-y-auto border-r border-neutral-800 px-2 py-3 text-sm">
				<p class="px-2 pb-1 text-xs uppercase tracking-wide text-neutral-500">Quick access</p>
				<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 ${s.folderId === null && !s.trashMode ? "bg-neutral-800" : "hover:bg-neutral-800"}" @click=${() => void this.model.closeTrash()}>
					${icon("folder")} Home
				</button>
				<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 ${this.recentsMode ? "bg-neutral-800" : "hover:bg-neutral-800"}" @click=${() => void this.showRecents()}>
					⏱ Recent files
				</button>
				<p class="px-2 pt-3 pb-1 text-xs uppercase tracking-wide text-neutral-500">${this.memberName}'s folders</p>
				${this.treeRows(null, 0)}
				<p class="px-2 pt-3 pb-1 text-xs uppercase tracking-wide text-neutral-500"></p>
				<button class="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 ${s.trashMode ? "bg-neutral-800" : "hover:bg-neutral-800"}" @click=${() => void this.model.openTrash()}>
					🗑 Trash
				</button>
			</aside>
		`;
	}

	private treeRows(parent: string | null, depth: number): TemplateResult[] {
		const s = this.s();
		return s.folders
			.filter((f) => (f.parent ?? null) === parent)
			.map(
				(f) => html`
					<div>
						<button
							class="flex w-full items-center gap-1.5 rounded-lg py-1.5 pr-2.5 hover:bg-neutral-800 ${s.folderId === f.id && !s.trashMode ? "bg-neutral-800" : ""}"
							style="padding-left: ${8 + depth * 14}px"
							@click=${() => void this.model.setFolder(f.id)}
							@drop=${(e: DragEvent) => this.onDropIntoFolder(e, f.id)}
							@dragover=${(e: DragEvent) => e.preventDefault()}
						>
							<span class="w-4 text-neutral-500 hover:text-neutral-200" @click=${(e: Event) => {
								e.stopPropagation();
								const next = new Set(this.expanded);
								next.has(f.id) ? next.delete(f.id) : next.add(f.id);
								this.expanded = next;
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
			<div class="p-2" style="content-visibility: auto">
				${folders.map((f) => item("folder", f.id, f.name, "folder", f.updatedAt, null))}
				${files.map((f) => item("file", f.id, f.name, f.kind, f.updatedAt, f.size))}
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
			<div class="grid gap-1.5 p-3 ${large ? "grid-cols-[repeat(auto-fill,minmax(112px,1fr))]" : this.view === "small" ? "grid-cols-[repeat(auto-fill,minmax(240px,1fr))]" : "grid-cols-[repeat(auto-fill,minmax(180px,1fr))]"}" style="content-visibility: auto">
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
						<button class="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left hover:bg-neutral-800/60" @click=${() => void this.jumpTo(r)}>
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
				<span class="flex-1"></span>
				${this.s().trashMode ? html`<span class="text-amber-400">Trash — restore or delete forever</span>` : html`<span>sealed · end to end</span>`}
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
								${p.url ? html`<img class="max-h-full max-w-full rounded" src=${p.url} alt=${p.name} />` : icon(p.kind as never, "h-16 w-16 text-neutral-600")}
							</div>
							<p class="mt-3 truncate font-medium text-neutral-100">${p.name}</p>
							${p.text ? html`<pre class="mt-2 max-h-64 overflow-auto rounded-lg bg-neutral-950 p-2 text-xs text-neutral-300">${p.text}</pre>` : nothing}
							${row
								? html`<dl class="mt-3 space-y-1 text-xs text-neutral-400">
										<div class="flex justify-between"><dt>Size</dt><dd>${fmtSize(row.size)}</dd></div>
										<div class="flex justify-between"><dt>Modified</dt><dd>${fmtDate(row.updatedAt)}</dd></div>
										<div class="flex justify-between"><dt>Version</dt><dd>v${row.version}</dd></div>
									</dl>`
								: nothing}
						`
					: html`<p class="pt-16 text-center text-xs text-neutral-600">Select a file to preview it here — opened in this browser, sealed everywhere else.</p>`}
			</aside>
		`;
	}
}