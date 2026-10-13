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
import { customElement, property } from "lit/decorators.js";
import type { FileKind } from "./icons.ts";

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
	archive: "Archive", text: "Plain text", file: "File",
};

export const kindLabel = (k: FileKind) => KIND_LABEL[k];

// ── the platform mode (per browser, like a theme) ───────────────────

export type PlatformMode = "win11" | "macos";
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
	icon?: string; // an svg string (icons.ts)
	run?: () => void;
	separator?: boolean;
	disabled?: boolean;
}

@customElement("gorani-menu")
export class GoraniMenu extends LitElement {
	@property({ type: Array }) items: MenuItem[] = [];
	@property({ type: Number }) x = 0;
	@property({ type: Number }) y = 0;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override firstUpdated(): void {
		const close = (e: Event) => {
			if (!this.contains(e.target as Node)) this.remove();
		};
		document.addEventListener("pointerdown", close, { capture: true, once: true });
		this.addEventListener("keydown", (e) => {
			if (e.key === "Escape") this.remove();
			if (e.key === "ArrowDown" || e.key === "ArrowUp") {
				e.preventDefault();
				const buttons = [...this.querySelectorAll<HTMLButtonElement>("button:not([disabled])")];
				const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
				buttons[(at + (e.key === "ArrowDown" ? 1 : buttons.length - 1)) % buttons.length]?.focus();
			}
		});
		requestAnimationFrame(() => (this.querySelector("button") as HTMLElement | null)?.focus());
	}

	protected override render() {
		return html`
			<div class="fixed z-50 min-w-52 rounded-xl border border-neutral-700 bg-neutral-900/95 py-1.5 shadow-2xl backdrop-blur" style="left:${Math.min(this.x, innerWidth - 240)}px; top:${Math.min(this.y, innerHeight - this.items.length * 34 - 24)}px" role="menu" tabindex="-1">
				${this.items.map((item) =>
					item.separator
						? html`<div class="my-1.5 border-t border-neutral-800"></div>`
						: html`
								<button
									class="mx-1.5 flex w-[calc(100%-12px)] items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-sm text-neutral-200 hover:bg-neutral-800 disabled:opacity-40"
									?disabled=${item.disabled}
									@click=${() => {
										this.remove();
										item.run?.();
									}}
									role="menuitem"
								>
									${item.icon ? html`<span class="text-neutral-400">${item.icon}</span>` : nothing}
									${item.label}
								</button>
							`,
				)}
			</div>
		`;
	}
}

/** Open a context menu at the pointer (both platforms call this). */
export function showMenu(items: MenuItem[], x: number, y: number): void {
	document.querySelectorAll("gorani-menu").forEach((m) => m.remove());
	const menu = document.createElement("gorani-menu") as GoraniMenu;
	menu.items = items;
	menu.x = x;
	menu.y = y;
	document.body.append(menu);
}

// ── small shared bits ───────────────────────────────────────────────

export const isMac = () => navigator.platform.toLowerCase().includes("mac");
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
		card.innerHTML = `<h3 class="text-sm font-medium text-neutral-200"></h3><input class="mt-3 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm outline-none focus:border-[var(--color-accent)]" /><div class="mt-4 flex justify-end gap-2"><button class="rounded-lg px-3 py-1.5 text-sm text-neutral-300 hover:bg-neutral-800" data-no>Cancel</button><button class="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-neutral-950 hover:opacity-90" data-yes>Create</button></div>`;
		(card.querySelector("h3") as HTMLElement).textContent = title;
		const input = card.querySelector("input")!;
		input.placeholder = placeholder;
		const done = (v: string | null) => {
			wrap.remove();
			resolve(v);
		};
		card.querySelector("[data-yes]")!.addEventListener("click", () => done(input.value.trim() || null));
		card.querySelector("[data-no]")!.addEventListener("click", () => done(null));
		input.addEventListener("keydown", (e) => {
			if (e.key === "Enter") done(input.value.trim() || null);
			if (e.key === "Escape") done(null);
		});
		wrap.append(card);
		document.body.append(wrap);
		input.focus();
	});
}