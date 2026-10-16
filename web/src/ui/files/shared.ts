// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The explorer's shared furniture: formatting, the context-menu primitive,
 * the platform-mode setting (persisted per browser), and the drag payload.
 * Both simulations (Windows 11 and macOS Finder) are views over the same
 * model, so their differences are *deliberate* — F2 renames in Windows,
 * Enter does in Finder — and those differences live in the two components,
 * not here.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { Directive, directive, PartType, type ElementPart, type PartInfo } from "lit/directive.js";
import type { FileKind } from "./icons.ts";

// ── cssom(): styles through the CSSOM, never the style attribute ─────
//
// The CSP says `style-src 'self'` (web/public/_headers): a `style="…"`
// attribute is refused. Lit's styleMap writes one on its FIRST render (a
// string, through setAttribute) and uses the CSSOM only after — so every
// styleMap'd element rendered unstyled: the context menu had no position
// and opened below the page, out of sight (commit 39l; the e2e watches
// every CSP violation, but never opened a menu). `el.style.setProperty` is
// the CSSOM, which the policy allows. Keys are CSS property names
// ("padding-left").
class CssomStyle extends Directive {
	constructor(part: PartInfo) {
		super(part);
		if (part.type !== PartType.ELEMENT) throw new Error("cssom() belongs on an element: <div ${cssom({...})}>");
	}
	render(_styles: Record<string, string>) {
		return nothing;
	}
	override update(part: ElementPart, [styles]: [Record<string, string>]) {
		const el = part.element as HTMLElement;
		for (const [name, value] of Object.entries(styles)) el.style.setProperty(name, value);
		return nothing;
	}
}
export const cssom = directive(CssomStyle);

export function fmtSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	const units = ["KB", "MB", "GB", "TB"];
	let v = bytes;
	let u = -1;
	do {
		v /= 1024;
		u++;
	} while (v >= 1024 && u < units.length - 1);
	return `${v.toFixed(v >= 100 || u === 0 ? 0 : 1)} ${units[u]}`;
}

export function fmtDate(iso: string): string {
	const d = new Date(iso);
	const sameDay = new Date().toDateString() === d.toDateString();
	return sameDay
		? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
		: d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

const KIND_LABEL: Record<FileKind, string> = {
	folder: "Folder", image: "Image", video: "Video", audio: "Audio", pdf: "PDF document",
	doc: "Document", sheet: "Spreadsheet", slides: "Presentation", code: "Source code",
	archive: "Archive", text: "Plain text", file: "File", sample: "Malware sample (never opened)",
};

export const kindLabel = (k: FileKind) => KIND_LABEL[k];

// ── the platform mode (per browser, like a theme) ───────────────────

export type PlatformMode = "win11" | "macos" | "music";
// ("music" is the library view — one feed of sealed metadata blobs,
// docs/MUSIC.md — not an explorer skin.)
const MODE_KEY = "gorani-explorer-mode";

export function loadMode(): PlatformMode {
	return (localStorage.getItem(MODE_KEY) as PlatformMode) ?? "win11";
}

export function saveMode(mode: PlatformMode): void {
	localStorage.setItem(MODE_KEY, mode);
}

// ── drag payloads (HTML5 dnd; ids travel, bytes never do) ───────────

export const DRAG_TYPE = "application/x-gorani-ids";

export function setDragIds(dt: DataTransfer, ids: { kind: string; id: string }[]): void {
	dt.setData(DRAG_TYPE, JSON.stringify(ids));
	dt.effectAllowed = "copyMove";
}

export function dragIds(dt: DataTransfer): { kind: string; id: string }[] | null {
	const raw = dt.getData(DRAG_TYPE);
	if (!raw) return null;
	try {
		return JSON.parse(raw) as { kind: string; id: string }[];
	} catch {
		return null;
	}
}

// ── <gorani-menu>: the context menu both platforms share ────────────
//
// Right-click (Windows) / secondary-click (macOS) both dispatch
// contextmenu; the menu is one element positioned at the pointer, closed
// by Escape or an outside click, navigable with the arrow keys — the two
// platforms' menus differ in *items*, not in mechanics, so the mechanics
// live here once.

export interface MenuItem {
	label: string;
	icon?: Node; // an SVG element (icons.ts › icon)
	run?: () => void;
	separator?: boolean;
	disabled?: boolean;
	/** A tick before the label: the current view, the sort in force. */
	checked?: boolean;
	/** A flyout (commit 39m): View ›, Sort by ›, Move to › — opened by
	 * hovering, clicking or → and closed by ← or Esc, the parent menu
	 * staying open behind it, as in both real file managers. */
	submenu?: MenuItem[];
}

@customElement("gorani-menu")
export class GoraniMenu extends LitElement {
	@property({ type: Array }) items: MenuItem[] = [];
	@property({ type: Number }) x = 0;
	@property({ type: Number }) y = 0;
	/** Where the focus was: it goes back there when the menu closes, so the
	 * explorer keeps its keyboard (commit 39l). */
	returnFocus: HTMLElement | null = null;
	/** The open flyout: which item it hangs off, and where. */
	@state() private sub: { index: number; x: number; y: number; left: number } | null = null;

	/** A pointer down anywhere outside closes the menu. (Until 39m this was a
	 * `once` listener: a click INSIDE the menu used it up, and the menu then
	 * stayed open whatever was clicked outside.) */
	private readonly outside = (e: Event) => {
		if (!this.contains(e.target as Node)) this.remove();
	};

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		document.removeEventListener("pointerdown", this.outside, { capture: true });
		if (this.returnFocus?.isConnected) this.returnFocus.focus({ preventScroll: true });
	}

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override firstUpdated(): void {
		document.addEventListener("pointerdown", this.outside, { capture: true });
		this.addEventListener("keydown", (e) => this.onKey(e));
		requestAnimationFrame(() => (this.querySelector("button") as HTMLElement | null)?.focus());
	}

	protected override updated(): void {
		// Where it goes: at the pointer, moved in by its measured size so it
		// never hangs off the window (the estimate this replaced guessed 34 px
		// a row). After EVERY render: cssom() sets left/top again each time,
		// and opening a flyout re-renders.
		const box = this.querySelector<HTMLElement>('[role="menu"]:not([data-flyout])');
		if (box) clampInto(box, this.x, this.y);
		// A flyout opens to the right of its item, or to the left where the
		// window ends.
		const flyout = this.querySelector<HTMLElement>("[data-flyout]");
		if (flyout && this.sub) {
			const { width } = flyout.getBoundingClientRect();
			const x = this.sub.x + width > innerWidth - 8 ? this.sub.left - width : this.sub.x;
			clampInto(flyout, x, this.sub.y);
		}
	}

	private onKey(e: KeyboardEvent): void {
		const active = document.activeElement as HTMLElement | null;
		const inFlyout = !!active?.closest("[data-flyout]");
		if (e.key === "Escape" || (e.key === "ArrowLeft" && inFlyout)) {
			e.preventDefault();
			e.stopPropagation();
			if (inFlyout && this.sub) {
				const at = this.sub.index;
				this.sub = null;
				this.querySelector<HTMLElement>(`[data-index="${at}"]`)?.focus();
			} else this.remove();
			return;
		}
		if (e.key === "ArrowRight" && !inFlyout && active?.dataset.index) {
			const index = Number(active.dataset.index);
			if (this.items[index]?.submenu) {
				e.preventDefault();
				this.openSub(index, active, true);
			}
			return;
		}
		if (e.key === "ArrowDown" || e.key === "ArrowUp") {
			e.preventDefault();
			const box = active?.closest<HTMLElement>('[role="menu"]') ?? this.querySelector<HTMLElement>('[role="menu"]');
			const buttons = [...(box?.querySelectorAll<HTMLButtonElement>(":scope > button:not([disabled])") ?? [])];
			const at = buttons.indexOf(active as HTMLButtonElement);
			buttons[(at + (e.key === "ArrowDown" ? 1 : buttons.length - 1)) % buttons.length]?.focus();
		}
	}

	private openSub(index: number, button: HTMLElement, focus = false): void {
		const r = button.getBoundingClientRect();
		if (this.sub?.index !== index) this.sub = { index, x: r.right - 4, y: r.top - 6, left: r.left + 4 };
		if (focus) void this.updateComplete.then(() => this.querySelector<HTMLElement>("[data-flyout] > button:not([disabled])")?.focus());
	}

	private row(item: MenuItem, index: number | null) {
		if (item.separator) return html`<div class="my-1.5 border-t border-neutral-800"></div>`;
		const parent = index !== null && !!item.submenu;
		return html`
			<button
				class="mx-1.5 flex w-[calc(100%-12px)] items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-sm text-neutral-200 hover:bg-neutral-800 focus:bg-neutral-800 focus:outline-none disabled:opacity-40 ${parent && this.sub?.index === index ? "bg-neutral-800" : ""}"
				?disabled=${item.disabled}
				data-index=${index ?? nothing}
				aria-haspopup=${parent ? "menu" : nothing}
				aria-expanded=${parent ? String(this.sub?.index === index) : nothing}
				aria-checked=${item.checked === undefined ? nothing : String(item.checked)}
				role=${item.checked === undefined ? "menuitem" : "menuitemcheckbox"}
				@mouseenter=${(e: MouseEvent) => {
					// Only the top menu's rows open or close flyouts.
					if (index === null) return;
					if (parent) this.openSub(index, e.currentTarget as HTMLElement);
					else this.sub = null;
				}}
				@click=${(e: MouseEvent) => {
					if (parent && index !== null) {
						this.openSub(index, e.currentTarget as HTMLElement, true);
						return;
					}
					this.remove();
					item.run?.();
				}}
			>
				<span class="w-3 shrink-0 text-accent" aria-hidden="true">${item.checked ? "✓" : ""}</span>
				${item.icon ? html`<span class="text-neutral-400">${item.icon}</span>` : nothing}
				<span class="min-w-0 flex-1 truncate">${item.label}</span>
				${parent ? html`<span class="text-neutral-500" aria-hidden="true">›</span>` : nothing}
			</button>
		`;
	}

	protected override render() {
		const flyout = this.sub ? this.items[this.sub.index]?.submenu : undefined;
		return html`
			<div
				class="fixed left-0 top-0 z-50 max-h-[calc(100vh-16px)] min-w-52 overflow-y-auto rounded-xl border border-neutral-700 bg-neutral-900/95 py-1.5 shadow-2xl backdrop-blur"
				${cssom({ left: `${this.x}px`, top: `${this.y}px` })}
				role="menu"
				tabindex="-1"
			>
				${this.items.map((item, i) => this.row(item, i))}
			</div>
			${flyout && this.sub
				? html`<div
						data-flyout
						class="fixed left-0 top-0 z-50 max-h-[calc(100vh-16px)] min-w-48 overflow-y-auto rounded-xl border border-neutral-700 bg-neutral-900/95 py-1.5 shadow-2xl backdrop-blur"
						${cssom({ left: `${this.sub.x}px`, top: `${this.sub.y}px` })}
						role="menu"
						tabindex="-1"
					>
						${flyout.length ? flyout.map((item) => this.row(item, null)) : html`<p class="px-4 py-1.5 text-xs text-neutral-500">Nowhere to go</p>`}
					</div>`
				: nothing}
		`;
	}
}

/** A folder as the menus need it: its id, its parent, its name. */
interface TreeFolder {
	id: string;
	parent?: string | null;
	name: string;
}

/** "Holiday › 2026 › Beach": a folder's whole path, so a Move to list with
 * two folders called "2026" says which is which. */
export function folderPath(tree: TreeFolder[], id: string): string {
	const names: string[] = [];
	for (let cur: string | null = id; cur && names.length < 64; cur = tree.find((f) => f.id === cur)?.parent ?? null) {
		names.unshift(tree.find((f) => f.id === cur)?.name ?? "…");
	}
	return names.join(" › ");
}

/**
 * Where a selection can move: the top, and every folder that is neither
 * moving nor inside a moving folder (the server refuses a folder into its
 * own subtree; the menu does not offer it). Each is the whole path. The
 * folder the items are already in is shown, greyed — as Explorer does.
 */
export function moveTargets(tree: TreeFolder[], moving: { kind: string; id: string }[], here: string | null, homeLabel: string, run: (folderId: string | null) => void): MenuItem[] {
	const movingFolders = new Set(moving.filter((m) => m.kind === "folder").map((m) => m.id));
	const inside = (id: string): boolean => {
		for (let cur: string | null = id; cur; cur = tree.find((f) => f.id === cur)?.parent ?? null) if (movingFolders.has(cur)) return true;
		return false;
	};
	const targets = tree
		.filter((f) => !inside(f.id))
		.map((f) => ({ id: f.id, label: folderPath(tree, f.id) }))
		.sort((a, b) => a.label.localeCompare(b.label));
	return [
		{ label: homeLabel, run: () => run(null), disabled: here === null },
		...targets.map((t) => ({ label: t.label, run: () => run(t.id), disabled: t.id === here })),
	];
}

/** Put a fixed box at (x, y), moved in so it stays inside the window. */
function clampInto(box: HTMLElement, x: number, y: number): void {
	const { width, height } = box.getBoundingClientRect();
	box.style.setProperty("left", `${Math.max(8, Math.min(x, innerWidth - width - 8))}px`);
	box.style.setProperty("top", `${Math.max(8, Math.min(y, innerHeight - height - 8))}px`);
}

/** Open a context menu at the pointer (both platforms call this). */
export function showMenu(items: MenuItem[], x: number, y: number): void {
	document.querySelectorAll("gorani-menu").forEach((m) => m.remove());
	const menu = document.createElement("gorani-menu") as GoraniMenu;
	const before = document.activeElement;
	menu.returnFocus = before instanceof HTMLElement && before !== document.body ? before : null;
	menu.items = items;
	menu.x = x;
	menu.y = y;
	document.body.append(menu);
}

// ── small shared bits ───────────────────────────────────────────────

export const isMac = () => navigator.platform.toLowerCase().includes("mac");

/** Is this key for a text field? The explorers' shortcuts (Delete, Backspace,
 * arrows, Enter…) listen on the whole window, and until commit 39l they
 * took keys typed INTO the search box too: Delete in the search field moved
 * the selected files to the Trash, Backspace went up a folder instead of
 * deleting a character. A key whose target is a field is the field's. */
export function typingInField(e: KeyboardEvent): boolean {
	const t = e.target as HTMLElement | null;
	return !!t?.closest?.("input, textarea, select, [contenteditable]:not([contenteditable=false])");
}
export const modKey = () => (isMac() ? "metaKey" : "ctrlKey");

/** Inline rename: replaces a row's label with an input, resolves on Enter/blur. */
export function startRename(container: HTMLElement, selector: string, current: string, onDone: (value: string | null) => void): void {
	const host = container.querySelector(selector);
	if (!host) {
		onDone(null);
		return;
	}
	const input = document.createElement("input");
	input.className = "w-full rounded border border-accent bg-neutral-950 px-1 text-sm outline-none";
	input.dataset.renaming = ""; // (what a test finds it by)
	input.value = current;
	const ext = current.includes(".") && !current.startsWith(".") ? current.lastIndexOf(".") : current.length;
	input.setSelectionRange(0, ext);
	host.replaceWith(input);
	input.focus();
	let done = false;
	const finish = (commit: boolean) => {
		if (done) return;
		done = true;
		const value = commit ? input.value.trim() : null;
		input.replaceWith(host);
		onDone(value);
	};
	input.addEventListener("keydown", (e) => {
		if (e.key === "Enter") finish(true);
		if (e.key === "Escape") finish(false);
		e.stopPropagation();
	});
	input.addEventListener("blur", () => finish(true));
}

/** Prompt (styled) for a new folder name — a tiny promise-based dialog. */
export function promptName(title: string, placeholder: string): Promise<string | null> {
	return new Promise((resolve) => {
		const wrap = document.createElement("div");
		wrap.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/50";
		const card = document.createElement("div");
		card.className = "w-80 rounded-2xl border border-neutral-700 bg-neutral-900 p-5 shadow-2xl";
		// Built node by node, not with `card.innerHTML = …` (commit 24): under
		// the app's Trusted Types CSP an innerHTML assignment throws — there is
		// deliberately no policy that turns strings into HTML. The markup was
		// static, so nothing was exploitable; the point is that NO sink exists
		// for the next, less careful, edit to reach.
		const el = <K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string) => {
			const e = document.createElement(tag);
			e.className = cls;
			if (text) e.textContent = text;
			return e;
		};
		const heading = el("h3", "text-sm font-medium text-neutral-200", title);
		const input = el("input", "mt-3 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm outline-none focus:border-[var(--color-accent)]");
		input.placeholder = placeholder;
		const no = el("button", "rounded-lg px-3 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800", "Cancel");
		const yes = el("button", "rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-neutral-950 hover:opacity-90", "Create");
		const row = el("div", "mt-4 flex justify-end gap-2");
		row.append(no, yes);
		card.append(heading, input, row);
		const done = (v: string | null) => {
			wrap.remove();
			resolve(v);
		};
		yes.addEventListener("click", () => done(input.value.trim() || null));
		no.addEventListener("click", () => done(null));
		input.addEventListener("keydown", (e) => {
			if (e.key === "Enter") done(input.value.trim() || null);
			if (e.key === "Escape") done(null);
		});
		wrap.append(card);
		document.body.append(wrap);
		input.focus();
	});
}

/**
 * "Mark as malware sample" (commit 29e): ONE WAY, so the person is asked
 * first, in words that say what changes. The model re-seals every
 * version's type with the mark and the server records it.
 */
export async function markSample(model: { markSample(id: string): Promise<void>; api: { toast(m: string): void } }, id: string, name: string): Promise<void> {
	const ok = window.confirm(`Mark “${name}” as a malware sample?\n\nThis cannot be undone. It will never be previewed or shared by link again, and downloads arrive zipped (password: infected).`);
	if (!ok) return;
	try {
		await model.markSample(id);
	} catch (e) {
		model.api.toast(`Not marked: ${e instanceof Error ? e.message : String(e)}`);
	}
}

/**
 * "Custody…" (commit 29g): the file's chain as THIS client verified it, and
 * the one action open to this member — accept an offer made to them, or,
 * as the custodian, hand the file over (who, and why: sealed and signed).
 */
export async function custodyAction(
	model: {
		custody(id: string): Promise<{ me: string; ok: boolean; custodian: string; pending: { from: string; to: string } | null; links: { seq: number; from: string; to: string; reason: string | null; ok: boolean; why: string }[] }>;
		offerCustody(id: string, to: string, reason: string): Promise<void>;
		acceptCustody(id: string): Promise<void>;
		api: { toast(m: string): void };
	},
	id: string,
	name: string,
): Promise<void> {
	try {
		const c = await model.custody(id);
		const lines = c.links.map((l) => `${l.seq}. ${l.from} → ${l.to}${l.reason ? ` — ${l.reason}` : ""}${l.ok ? "" : `   ⚠ ${l.why}`}`).join("\n");
		const head = `Custody of “${name}”: held by ${c.custodian}${c.ok ? "" : " — ⚠ the chain does NOT verify"}\n\n${lines || "No transfers yet — the uploader holds it."}`;
		if (c.pending?.to === c.me) {
			if (window.confirm(`${head}\n\n${c.pending.from} offers it to you. Accept custody?`)) await model.acceptCustody(id);
			return;
		}
		if (c.custodian === c.me && !c.pending) {
			const to = window.prompt(`${head}\n\nYou hold it. Hand it over to (member id):`)?.trim();
			if (!to) return;
			const reason = window.prompt(`Why does ${to} take it? (sealed and signed)`)?.trim();
			if (!reason) return;
			await model.offerCustody(id, to, reason);
			return;
		}
		window.alert(c.pending ? `${head}\n\nOffered to ${c.pending.to} — waiting for them.` : head);
	} catch (e) {
		model.api.toast(`Custody: ${e instanceof Error ? e.message : String(e)}`);
	}
}
