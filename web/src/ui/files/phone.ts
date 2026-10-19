// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-phone>: the explorer on a phone (commit 41b, docs/PHONE.md).
 *
 * The Windows and Finder skins are simulations of desktop file managers:
 * a tree pane, columns, a preview pane, menus at the pointer, targets 24
 * pixels tall. None of that fits a 390-pixel screen or a thumb. This is
 * the third view over the SAME model (model.ts), in the grammar phones
 * already teach:
 *
 * | Phone | Does |
 * |---|---|
 * | One list of big rows, folders first | each row 56 px tall; name, then size · date |
 * | Top bar: ‹ and the folder's name | up one folder (also the system's Back: the address holds the folder) |
 * | Tap | open: a folder goes in, a file opens in the viewer (swipe for the next) |
 * | Long-press, or a row's ⋯ | the item's actions, as a sheet (sheet.ts): what right-click offers on a desktop |
 * | Bottom bar: Upload · New folder · Select | the three things done most |
 * | Select | tap rows to pick several; the bottom bar then acts on them |
 * | Top ⋯ | the folder's own menu: Sort by ›, Paste, Request files, Inbox, Download as zip, Trash… |
 * | 🔍 | search the whole area (the local index; names never leave the browser) |
 *
 * Every action calls what the desktop menus call. The model decides what
 * is allowed (canPurge, a sample's rules, an evidence case's), and the
 * server decides again, so a phone can offer nothing a desktop could not.
 */

import { LitElement, html, nothing, type PropertyValues, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FileRow, FilesModel, FolderRow, Selection, SortState } from "./model.ts";
import { shownModified } from "./model.ts";
import { icon, type FileKind } from "./icons.ts";
import { custodyAction, deleteForever, emptyTrash, fmtDate, fmtSize, markSample, moveTargets, promptName, uploadStatus, type MenuItem } from "./shared.ts";
import { showSheet } from "./sheet.ts";
import { showDuplicates } from "./duplicates-dialog.ts";
import type { ViewerTarget } from "../viewer/viewer.ts";
import "./share-dialog.ts";
import "./requests-dialog.ts";

/** How long a finger rests before a press becomes a long-press — the platforms' own (iOS ~500 ms, Android 400–500). */
const LONG_PRESS_MS = 500;
/** How far a finger may drift and still be pressing, not scrolling. */
const PRESS_SLOP = 10;

type Hit = { id: string; kind: "file" | "folder"; folderId: string | null; name: string; size?: number };

@customElement("gorani-phone")
export class GoraniPhone extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	/** The area's own name: the title at its top. */
	@property({ type: String }) memberName = "";
	@property({ type: String }) memberRole = "lead";

	@state() private v = 0;
	/** Picking several (the Select button): taps toggle, the bottom bar acts on the picked. */
	@state() private selecting = false;
	@state() private searching = false;
	@state() private query = "";
	@state() private hits: Hit[] | null = null;
	@state() private shareTarget: { id: string; name: string; size: number; version: number; modified: string | null } | null = null;
	@state() private requests: { tab: "inbox" | "links"; folderId: string | null; folderName: string } | null = null;
	/** The finger on a row: where it went down, and whether it already counted as a long-press. */
	private press: { x: number; y: number; timer: ReturnType<typeof setTimeout>; fired: boolean } | null = null;
	private unsubscribe: (() => void) | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	/** Listen to the model this element shows — again whenever it is a new
	 * one (another area: the shell swaps the model, not the element). */
	protected override willUpdate(changed: PropertyValues<this>): void {
		if (changed.has("model")) this.watch();
	}

	private watch(): void {
		this.unsubscribe?.();
		this.unsubscribe = this.model?.subscribe(() => {
			this.v++;
			// A listing landed in another folder: picking ends there.
			if (this.leftFolder() && this.selecting) this.selecting = false;
		}) ?? null;
	}

	override connectedCallback(): void {
		super.connectedCallback();
		if (this.model && !this.unsubscribe) this.watch();
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.unsubscribe?.();
		this.unsubscribe = null;
		if (this.press) clearTimeout(this.press.timer);
	}

	private s = () => this.model.state.get();
	private shownFolder: string | null | undefined = undefined;

	/** Did the open folder change since the last tick? (Picking ends there.) */
	private leftFolder(): boolean {
		const now = this.s().trashMode ? "trash" : this.s().folderId;
		const changed = this.shownFolder !== undefined && this.shownFolder !== now;
		this.shownFolder = now;
		return changed;
	}

	private attempt(p: Promise<unknown>): void {
		p.catch((e) => this.model.api.toast(e instanceof Error ? e.message : String(e)));
	}

	// ── where we are ───────────────────────────────────────────────────

	private heading(): string {
		const s = this.s();
		if (this.selecting) {
			const n = s.selection.length;
			return n ? `${n} selected` : "Select items";
		}
		if (this.searching) return "Search";
		if (s.trashMode) return "Trash";
		if (!s.folderId) return this.memberName || "Files";
		return this.model.names.get(s.folderId) ?? "…";
	}

	private parentOf(id: string | null): string | null {
		return (id && this.s().tree.find((f) => f.id === id)?.parent) ?? null;
	}

	/** ‹ : leave picking, then search, then the Trash, then go up one folder. */
	private back(): void {
		const s = this.s();
		if (this.selecting) return this.endSelecting();
		if (this.searching) {
			this.searching = false;
			this.query = "";
			this.hits = null;
			return;
		}
		if (s.trashMode) return this.attempt(this.model.closeTrash());
		if (s.folderId) this.attempt(this.model.setFolder(this.parentOf(s.folderId)));
	}

	private canBack(): boolean {
		const s = this.s();
		return this.selecting || this.searching || s.trashMode || !!s.folderId;
	}

	// ── the rows ───────────────────────────────────────────────────────

	private visible(): { folders: FolderRow[]; files: FileRow[] } {
		const s = this.s();
		if (s.trashMode) return { folders: s.trashFolders, files: s.trashFiles };
		return this.model.sorted();
	}

	private isSelected(kind: string, id: string): boolean {
		return this.s().selection.some((x) => x.kind === kind && x.id === id);
	}

	/** A finger down: a long-press if it stays put for LONG_PRESS_MS. A mouse
	 * (a tablet with a trackpad, the desktop browser at phone width) uses its
	 * right button instead — the contextmenu handler. */
	private pressStart(e: PointerEvent, kind: "file" | "folder", id: string, name: string): void {
		if (e.pointerType === "mouse") return;
		this.pressEnd();
		const timer = setTimeout(() => {
			if (!this.press) return;
			this.press.fired = true;
			navigator.vibrate?.(8);
			this.itemSheet(kind, id, name);
		}, LONG_PRESS_MS);
		this.press = { x: e.clientX, y: e.clientY, timer, fired: false };
	}

	private pressMove(e: PointerEvent): void {
		if (this.press && !this.press.fired && Math.hypot(e.clientX - this.press.x, e.clientY - this.press.y) > PRESS_SLOP) this.pressEnd();
	}

	private pressEnd(): void {
		if (this.press && !this.press.fired) {
			clearTimeout(this.press.timer);
			this.press = null;
		}
	}

	/** A tap — unless it was the end of a long-press, whose sheet is open. */
	private tap(kind: "file" | "folder", id: string, name: string): void {
		if (this.press?.fired) {
			this.press = null;
			return;
		}
		this.press = null;
		if (this.selecting) {
			this.model.select({ kind, id }, { add: true });
			return;
		}
		this.open(kind, id, name);
	}

	private open(kind: "file" | "folder", id: string, _name: string): void {
		const s = this.s();
		if (s.trashMode) {
			this.model.api.toast("Restore it to open it — long-press for Restore");
			return;
		}
		if (kind === "folder") {
			this.attempt(this.model.setFolder(id));
			return;
		}
		const row = s.files.find((f) => f.id === id);
		if (!row) return;
		// The viewer gets the folder's other files too: a swipe shows the next (41b).
		const target = (f: FileRow): ViewerTarget => ({ id: f.id, name: f.name, kind: f.kind, size: f.size, version: f.version, folderId: f.folder ?? null });
		const siblings = this.visible().files.map(target);
		this.dispatchEvent(new CustomEvent("open-viewer", { detail: { ...target(row), siblings } as ViewerTarget, bubbles: true, composed: true }));
	}

	private row(kind: "file" | "folder", id: string, name: string, sub: string, kindIcon: FileKind): TemplateResult {
		const picked = this.isSelected(kind, id);
		return html`<li class="flex items-stretch border-b border-neutral-900 ${picked ? "bg-accent/10" : ""}" data-item="${kind}:${id}" data-test="phone-row">
			<button
				class="flex min-h-14 min-w-0 flex-1 select-none items-center gap-3 py-2 pl-4 text-left [-webkit-touch-callout:none] active:bg-neutral-800"
				aria-pressed=${this.selecting ? String(picked) : nothing}
				@pointerdown=${(e: PointerEvent) => this.pressStart(e, kind, id, name)}
				@pointermove=${(e: PointerEvent) => this.pressMove(e)}
				@pointerup=${() => this.pressEnd()}
				@pointercancel=${() => this.pressEnd()}
				@contextmenu=${(e: MouseEvent) => {
					// Android's own long-press (and a mouse's right button): the
					// same sheet, never the browser's menu over a decrypted name.
					e.preventDefault();
					if (this.press?.fired) return; // our own timer got there first
					// Android's came first: it counts as the long-press, so the
					// tap that ends it does not also open the item.
					if (this.press) {
						clearTimeout(this.press.timer);
						this.press.fired = true;
					}
					this.itemSheet(kind, id, name);
				}}
				@click=${() => this.tap(kind, id, name)}
			>
				${this.selecting
					? html`<span class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border ${picked ? "border-accent bg-accent text-neutral-950" : "border-neutral-600"}" aria-hidden="true">${picked ? "✓" : ""}</span>`
					: nothing}
				${icon(kindIcon, `h-8 w-8 shrink-0 ${kind === "folder" ? "text-accent" : kindIcon === "sample" ? "text-amber-500" : "text-neutral-400"}`)}
				<span class="min-w-0 flex-1">
					<span class="block truncate text-[15px] text-neutral-100" data-name>${name}</span>
					<span class="block truncate text-xs text-neutral-500">${sub}</span>
				</span>
			</button>
			${this.selecting
				? nothing
				: html`<button class="flex w-12 shrink-0 items-center justify-center text-xl text-neutral-500 active:bg-neutral-800" aria-label="More for ${name}" data-test="phone-row-menu" @click=${() => this.itemSheet(kind, id, name)}>⋯</button>`}
		</li>`;
	}

	private fileSub(f: FileRow): string {
		const trashed = this.s().trashMode ? "In the Trash · " : "";
		if (f.kind === "sample") return `${trashed}Malware sample · ${fmtSize(f.size)}`;
		return `${trashed}${fmtSize(f.size)} · ${fmtDate(shownModified(f))}`;
	}

	// ── sheets: an item's actions, the folder's ─────────────────────────

	/** The actions for a row. With several picked and this one among them,
	 * they apply to all the picked ones, as a desktop menu does. */
	private itemSheet(kind: "file" | "folder", id: string, name: string): void {
		const s = this.s();
		const targets: Selection[] = this.selecting && this.isSelected(kind, id) ? s.selection : [{ kind, id }];
		const one = targets.length === 1;
		const heading = one ? name : `${targets.length} items`;
		if (s.trashMode) {
			showSheet(
				[
					{ label: "Restore", run: () => this.attempt(this.model.restore(targets.filter((t) => t.kind === "file").map((t) => t.id), targets.filter((t) => t.kind === "folder").map((t) => t.id))) },
					...this.purgeItem(targets),
				],
				heading,
			);
			return;
		}
		const files = targets.filter((t) => t.kind === "file");
		const row = one && kind === "file" ? s.files.find((f) => f.id === id) : undefined;
		const sample = row?.sample === true || row?.kind === "sample";
		const items: (MenuItem | false)[] = [
			one && { label: "Open", run: () => this.open(kind, id, name) },
			{ label: "Download", run: () => this.attempt(this.download(files)), disabled: !files.length },
			{ label: "Download as zip", run: () => this.attempt(this.model.downloadZip(targets)) },
			one && kind === "file" && { label: "Share…", run: () => row && (this.shareTarget = { id, name, size: row.size, version: row.version, modified: row.modified }), disabled: sample },
			{ separator: true, label: "" },
			one && { label: "Rename…", run: () => this.attempt(this.rename(kind, id, name)) },
			{ label: "Move to", submenu: moveTargets(s.tree, targets, s.folderId, this.memberName || "Home", (to) => this.attempt(this.model.moveItems(targets, to).then(() => this.endSelecting()))) },
			{ label: "Copy", run: () => this.clip(targets, "copy") },
			{ label: "Cut", run: () => this.clip(targets, "cut") },
			one && kind === "folder" && { label: "Request files into this folder…", run: () => (this.requests = { tab: "links", folderId: id, folderName: name }) },
			{ separator: true, label: "" },
			one && kind === "file" && { label: "Verify signature", run: () => this.attempt(this.model.verifyAndReport(id)) },
			one && kind === "file" && this.model.areaKind() === "evidence" && { label: "Custody…", run: () => this.attempt(custodyAction(this.model, id, name)) },
			one && kind === "file" && !sample && { label: "Mark as malware sample…", run: () => this.attempt(markSample(this.model, id, name)) },
			!this.selecting && { label: "Select", run: () => this.startSelecting(targets) },
			{ label: "Delete", run: () => this.attempt(this.model.trashItems(targets).then(() => this.endSelecting())) },
			...this.purgeItem(targets),
		];
		showSheet(items.filter((x): x is MenuItem => Boolean(x)), heading);
	}

	/** The folder's own menu (the top bar's ⋯). */
	private folderSheet(): void {
		const s = this.s();
		if (s.trashMode) {
			const any = s.trashFiles.length + s.trashFolders.length > 0;
			showSheet(
				[
					{ label: "Restore all", run: () => this.attempt(this.model.restore(s.trashFiles.map((f) => f.id), s.trashFolders.map((f) => f.id))), disabled: !any },
					...(this.model.canPurge() ? [{ label: "Empty Trash…", run: () => this.attempt(emptyTrash(this.model)), disabled: !any }] : []),
					{ label: "Refresh", run: () => this.attempt(this.model.refresh()) },
				],
				"Trash",
			);
			return;
		}
		const name = this.heading();
		showSheet(
			[
				{ label: "Sort by", submenu: this.sortItems() },
				{ label: "Paste here", run: () => this.attempt(this.model.paste()), disabled: !this.model.canPaste },
				{ separator: true, label: "" },
				{ label: "Upload malware samples…", icon: icon("sample"), run: () => this.pick("[data-upload-sample]") },
				{ label: "Request files into this folder…", run: () => (this.requests = { tab: "links", folderId: s.folderId, folderName: s.folderId ? name : "" }) },
				{ label: "Inbox — what people sent", run: () => (this.requests = { tab: "inbox", folderId: s.folderId, folderName: s.folderId ? name : "" }) },
				{ label: "Download this folder as zip", run: () => this.attempt(this.model.downloadFolderZip(s.folderId, this.memberName || "gorani")), disabled: !(s.folders.length + s.files.length) },
				{ separator: true, label: "" },
				{ label: "Find duplicates…", run: () => showDuplicates(this.model, (folderId, id) => this.attempt(this.model.setFolder(folderId).then(() => this.model.select({ kind: "file", id })))) },
				{ label: "Trash", run: () => this.attempt(this.model.openTrash()) },
				{ label: "Refresh", run: () => this.attempt(this.model.refresh()) },
			],
			name,
		);
	}

	private sortItems(): MenuItem[] {
		const cur = this.s().sort;
		const item = (by: SortState["by"], label: string): MenuItem => ({ label, checked: cur.by === by, run: () => cur.by !== by && this.model.sortBy(by) });
		return [
			item("name", "Name"),
			item("modified", "Date modified"),
			item("size", "Size"),
			item("type", "Kind"),
			{ separator: true, label: "" },
			{ label: "Ascending", checked: cur.dir === "asc", run: () => this.model.sortDirection("asc") },
			{ label: "Descending", checked: cur.dir === "desc", run: () => this.model.sortDirection("desc") },
		];
	}

	private purgeItem(targets: Selection[]): MenuItem[] {
		return this.model.canPurge() ? [{ label: "Delete forever…", run: () => this.attempt(deleteForever(this.model, targets).then(() => this.endSelecting())) }] : [];
	}

	// ── actions ────────────────────────────────────────────────────────

	private async download(files: Selection[]): Promise<void> {
		for (const f of files) await this.model.download(f.id, this.model.names.get(f.id) ?? "download");
		this.endSelecting();
	}

	private async rename(kind: "file" | "folder", id: string, name: string): Promise<void> {
		const next = await promptName("Rename", name, { value: name, action: "Rename" });
		if (next && next !== name) await this.model.rename(kind, id, next);
	}

	private async newFolder(): Promise<void> {
		const name = await promptName("New folder", "New folder");
		if (name) await this.model.newFolder(this.s().folderId, name);
	}

	private clip(targets: Selection[], how: "copy" | "cut"): void {
		this.model.selectOnly(targets);
		if (how === "copy") this.model.copy();
		else this.model.cut();
		this.endSelecting();
	}

	private startSelecting(with_: Selection[] = []): void {
		this.selecting = true;
		this.searching = false;
		this.model.selectOnly(with_);
	}

	private endSelecting(): void {
		if (!this.selecting) return;
		this.selecting = false;
		this.model.clearSelection();
	}

	private pick(selector: string): void {
		this.querySelector<HTMLInputElement>(selector)?.click();
	}

	// ── search (the local index: names never leave this browser) ───────

	private async onSearch(q: string): Promise<void> {
		this.query = q;
		if (q.trim().length < 2) {
			this.hits = null;
			return;
		}
		if (!this.model.index) {
			// No index (it failed to open): the open folder, by name.
			const t = q.trim().toLowerCase();
			const { folders, files } = this.visible();
			this.hits = [...folders.filter((f) => f.name.toLowerCase().includes(t)).map((f) => ({ id: f.id, kind: "folder" as const, folderId: f.parent ?? null, name: f.name })), ...files.filter((f) => f.name.toLowerCase().includes(t)).map((f) => ({ id: f.id, kind: "file" as const, folderId: f.folder ?? null, name: f.name, size: f.size }))];
			return;
		}
		const found = await this.model.index.search(q, 40);
		if (this.query === q) this.hits = found.map((h) => ({ id: h.id, kind: h.kind, folderId: h.folderId, name: h.name, size: h.size }));
	}

	/** A hit: its folder opens; a file then opens in the viewer. */
	private async openHit(hit: Hit): Promise<void> {
		this.searching = false;
		this.query = "";
		this.hits = null;
		await this.model.setFolder(hit.kind === "folder" ? hit.id : hit.folderId);
		if (hit.kind === "file") this.open("file", hit.id, hit.name);
	}

	// ── render ─────────────────────────────────────────────────────────

	protected override render(): TemplateResult {
		void this.v;
		const s = this.s();
		return html`
			<div class="flex h-full flex-col bg-neutral-950 text-neutral-200" data-test="phone">
				${this.topBar()}
				${this.searching ? this.searchBox() : nothing}
				<div class="min-h-0 flex-1 overflow-y-auto overscroll-contain" data-body>${this.searching && this.hits ? this.hitList() : this.list()}</div>
				${s.upload ? html`<div class="border-t border-neutral-800 px-4 py-2 text-xs">${uploadStatus(s.upload, () => this.model.stopUpload())}</div>` : nothing}
				${this.model.canPaste && !s.trashMode && !this.selecting
					? html`<div class="flex items-center gap-2 border-t border-neutral-800 bg-neutral-900 px-4 py-2 text-sm" data-test="phone-paste">
							<span class="min-w-0 flex-1 truncate text-neutral-300">Paste into “${this.heading()}”?</span>
							<button class="rounded-lg bg-accent px-3 py-1.5 font-medium text-neutral-950" @click=${() => this.attempt(this.model.paste())}>Paste</button>
							<button class="px-2 py-1.5 text-neutral-500" aria-label="Forget what was copied" @click=${() => this.model.clearClipboard()}>✕</button>
						</div>`
					: nothing}
				${this.bottomBar()}
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
				${this.shareTarget ? html`<gorani-share .model=${this.model} .target=${this.shareTarget} @closed=${() => (this.shareTarget = null)}></gorani-share>` : nothing}
				${this.requests ? html`<gorani-requests .model=${this.model} .tab=${this.requests.tab} .folderId=${this.requests.folderId} .folderName=${this.requests.folderName} @closed=${() => (this.requests = null)}></gorani-requests>` : nothing}
			</div>
		`;
	}

	private topBar(): TemplateResult {
		const s = this.s();
		return html`
			<div class="flex h-12 shrink-0 items-center gap-1 border-b border-neutral-800 px-1">
				${this.canBack()
					? html`<button class="flex h-11 min-w-11 items-center justify-center px-2 text-2xl text-accent" aria-label=${this.selecting ? "Done selecting" : "Back"} data-test="phone-back" @click=${() => this.back()}>${this.selecting ? html`<span class="text-base">Done</span>` : "‹"}</button>`
					: html`<span class="w-3"></span>`}
				<h1 class="min-w-0 flex-1 truncate text-base font-medium text-neutral-100" data-test="phone-title">${this.heading()}</h1>
				${this.selecting
					? html`<button class="h-11 px-3 text-sm text-accent" data-test="phone-select-all" @click=${() => this.model.selectAll()}>All</button>`
					: html`<button class="flex h-11 w-11 items-center justify-center text-lg text-neutral-400" aria-label="Search" data-test="phone-search" @click=${() => {
								this.searching = !this.searching;
								this.query = "";
								this.hits = null;
							}}>🔍</button>
							<button class="flex h-11 w-11 items-center justify-center text-xl text-neutral-400" aria-label=${s.trashMode ? "Trash actions" : "Folder actions"} data-test="phone-folder-menu" @click=${() => this.folderSheet()}>⋯</button>`}
			</div>
		`;
	}

	private searchBox(): TemplateResult {
		return html`<div class="border-b border-neutral-800 px-3 py-2">
			<input class="w-full rounded-xl border border-neutral-700 bg-neutral-900 px-3 py-2 outline-none focus:border-accent" type="search" enterkeyhint="search" placeholder="Search ${this.memberName || "files"}" autofocus .value=${this.query} @input=${(e: InputEvent) => void this.onSearch((e.target as HTMLInputElement).value)} data-test="phone-search-input" />
		</div>`;
	}

	private list(): TemplateResult {
		const s = this.s();
		const { folders, files } = this.visible();
		if (s.loading && !folders.length && !files.length) return html`<p class="p-6 text-center text-sm text-neutral-500">Opening…</p>`;
		if (s.error) return html`<p class="p-6 text-center text-sm text-red-400">${s.error}</p>`;
		if (!folders.length && !files.length)
			return html`<div class="p-8 text-center text-sm text-neutral-500" data-test="phone-empty">
				<p class="text-base text-neutral-300">${s.trashMode ? "The Trash is empty" : "Nothing here yet"}</p>
				${s.trashMode ? nothing : html`<p class="mt-1">Upload files or make a folder — everything is sealed on this phone before it leaves.</p>`}
			</div>`;
		return html`<ul data-test="phone-list">
			${folders.map((f) => this.row("folder", f.id, f.name, s.trashMode ? "In the Trash · folder" : "Folder", "folder"))}
			${files.map((f) => this.row("file", f.id, f.name, this.fileSub(f), f.kind))}
		</ul>`;
	}

	private hitList(): TemplateResult {
		const hits = this.hits ?? [];
		if (!hits.length) return html`<p class="p-6 text-center text-sm text-neutral-500">Nothing called “${this.query}”</p>`;
		return html`<ul data-test="phone-hits">
			${hits.map((h) => html`<li class="border-b border-neutral-900">
				<button class="flex min-h-14 w-full items-center gap-3 px-4 py-2 text-left active:bg-neutral-800" @click=${() => this.attempt(this.openHit(h))}>
					${icon(h.kind === "folder" ? "folder" : "file", "h-7 w-7 shrink-0 text-neutral-400")}
					<span class="min-w-0 flex-1">
						<span class="block truncate text-[15px] text-neutral-100">${h.name}</span>
						<span class="block truncate text-xs text-neutral-500">${h.folderId ? `in ${this.model.names.get(h.folderId) ?? "a folder"}` : `in ${this.memberName || "the top folder"}`}${h.size !== undefined ? ` · ${fmtSize(h.size)}` : ""}</span>
					</span>
				</button>
			</li>`)}
		</ul>`;
	}

	/** The thumb's bar. Its buttons change with what the screen is doing. */
	private bottomBar(): TemplateResult {
		const s = this.s();
		const sel = s.selection;
		const button = (label: string, glyph: string, run: () => void, test: string, disabled = false) =>
			html`<button class="flex min-w-0 flex-1 flex-col items-center justify-center gap-0.5 py-1.5 text-[11px] text-neutral-300 active:bg-neutral-800 disabled:opacity-30" ?disabled=${disabled} data-test=${test} @click=${run}><span class="text-xl leading-none" aria-hidden="true">${glyph}</span>${label}</button>`;
		let buttons: TemplateResult[];
		if (this.selecting && s.trashMode) {
			buttons = [
				button("Restore", "↩", () => this.attempt(this.model.restore(sel.filter((t) => t.kind === "file").map((t) => t.id), sel.filter((t) => t.kind === "folder").map((t) => t.id)).then(() => this.endSelecting())), "phone-restore", !sel.length),
				...(this.model.canPurge() ? [button("Delete forever", "✕", () => this.attempt(deleteForever(this.model, sel).then(() => this.endSelecting())), "phone-purge", !sel.length)] : []),
			];
		} else if (this.selecting) {
			const files = sel.filter((t) => t.kind === "file");
			buttons = [
				button("Download", "⤓", () => this.attempt(this.download(files)), "phone-download", !files.length),
				button("Zip", "🗜", () => this.attempt(this.model.downloadZip(sel).then(() => this.endSelecting())), "phone-zip", !sel.length),
				button("Move", "➜", () => showSheet(moveTargets(s.tree, sel, s.folderId, this.memberName || "Home", (to) => this.attempt(this.model.moveItems(sel, to).then(() => this.endSelecting()))), `Move ${sel.length} to…`), "phone-move", !sel.length),
				button("Delete", "🗑", () => this.attempt(this.model.trashItems(sel).then(() => this.endSelecting())), "phone-delete", !sel.length),
				button("More", "⋯", () => {
					const first = sel[0];
					if (first) this.itemSheet(first.kind, first.id, this.model.names.get(first.id) ?? "");
				}, "phone-more", !sel.length),
			];
		} else if (s.trashMode) {
			const any = s.trashFiles.length + s.trashFolders.length > 0;
			buttons = [
				button("Restore all", "↩", () => this.attempt(this.model.restore(s.trashFiles.map((f) => f.id), s.trashFolders.map((f) => f.id))), "phone-restore-all", !any),
				...(this.model.canPurge() ? [button("Empty", "✕", () => this.attempt(emptyTrash(this.model)), "phone-empty-trash", !any)] : []),
				button("Select", "☑", () => this.startSelecting(), "phone-select", !any),
			];
		} else {
			buttons = [
				button("Upload", "⤒", () => this.pick("[data-upload]"), "phone-upload"),
				button("New folder", "＋", () => this.attempt(this.newFolder()), "phone-new-folder"),
				button("Select", "☑", () => this.startSelecting(), "phone-select", !(s.folders.length + s.files.length)),
			];
		}
		return html`<nav class="flex shrink-0 border-t border-neutral-800 bg-neutral-900 pb-[env(safe-area-inset-bottom)]" data-test="phone-bar">${buttons}</nav>`;
	}
}

declare global {
	interface HTMLElementTagNameMap {
		"gorani-phone": GoraniPhone;
	}
}
