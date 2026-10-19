// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-sheet>: the phone's menu (commit 41b, docs/PHONE.md). A bottom
 * sheet in place of a context menu: on a touch screen there is no pointer
 * to open a menu at, and a thumb reaches the bottom of the screen, not a
 * spot in the middle.
 *
 * It takes the SAME `MenuItem` lists the desktop menus take (shared.ts),
 * so an action means one thing everywhere. A submenu (Move to ›, Sort by ›)
 * opens in place, with a Back row, instead of flying out to the side:
 * there is no side on a 390-pixel screen.
 *
 * Closed by: tapping outside the panel, Cancel, Escape (a keyboard on a
 * tablet), or choosing an item. Items carry `role="menuitem"`, as the
 * desktop menu's do, so tests and screen readers find them the same way.
 *
 * Only a press that STARTED in the sheet counts. A long-press opens the
 * sheet under a finger that is still down, and some browsers end that
 * press with a click where the finger lifts: on the backdrop (which would
 * close the sheet at once) or on an item (which would run an action
 * nobody chose). The e2e suite's Chromium did exactly that. A click from
 * the keyboard (detail 0: Enter or Space) needs no press and always counts.
 */

import { LitElement, html, nothing, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { MenuItem } from "./shared.ts";

@customElement("gorani-sheet")
export class GoraniSheet extends LitElement {
	@property({ type: Array }) items: MenuItem[] = [];
	@property({ type: String }) heading = "";
	/** The submenus opened so far, innermost last (Back pops one). */
	@state() private stack: { label: string; items: MenuItem[] }[] = [];
	/** Where the focus was, given back on close. */
	returnFocus: HTMLElement | null = null;
	/** A pointer went down inside the sheet since it opened (see above). */
	private armed = false;

	/** A click this sheet should act on: from a press that began here, or from a key. */
	private counts(e: MouseEvent): boolean {
		return this.armed || e.detail === 0;
	}

	private readonly onKey = (e: KeyboardEvent): void => {
		if (e.key !== "Escape") return;
		e.preventDefault();
		e.stopPropagation();
		if (this.stack.length) this.stack = this.stack.slice(0, -1);
		else this.close();
	};

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	override connectedCallback(): void {
		super.connectedCallback();
		addEventListener("keydown", this.onKey, true);
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		removeEventListener("keydown", this.onKey, true);
	}

	protected override firstUpdated(): void {
		this.querySelector<HTMLElement>("[data-sheet-panel]")?.focus();
	}

	close(): void {
		this.remove();
		this.returnFocus?.focus?.();
	}

	private choose(item: MenuItem, e: MouseEvent): void {
		if (item.disabled || !this.counts(e)) return;
		if (item.submenu) {
			this.stack = [...this.stack, { label: item.label, items: item.submenu }];
			return;
		}
		// Closed first: the action may open a dialog or another sheet.
		this.close();
		item.run?.();
	}

	protected override render(): TemplateResult {
		const level = this.stack[this.stack.length - 1];
		const items = level ? level.items : this.items;
		return html`
			<div class="fixed inset-0 z-[60] flex flex-col justify-end bg-black/50" data-sheet @pointerdown=${() => (this.armed = true)} @click=${(e: MouseEvent) => e.target === e.currentTarget && this.counts(e) && this.close()}>
				<div class="max-h-[85dvh] overflow-y-auto overscroll-contain rounded-t-2xl border-t border-neutral-700 bg-neutral-900 pb-[max(0.5rem,env(safe-area-inset-bottom))] text-neutral-100 shadow-2xl outline-none" role="menu" aria-label=${level?.label ?? this.heading} tabindex="-1" data-sheet-panel>
					<div class="mx-auto mt-2 h-1 w-10 rounded-full bg-neutral-700" aria-hidden="true"></div>
					${level
						? html`<button class="flex h-12 w-full items-center gap-2 px-5 text-left text-base text-accent" aria-label="Back from ${level.label}" data-test="sheet-back" @click=${(e: MouseEvent) => this.counts(e) && (this.stack = this.stack.slice(0, -1))}><span aria-hidden="true">‹</span> ${level.label}</button>`
						: this.heading
							? html`<p class="truncate px-5 pb-1 pt-3 text-sm text-neutral-400" data-test="sheet-heading">${this.heading}</p>`
							: nothing}
					${items.map((it) =>
						it.separator
							? html`<div class="mx-5 my-1 border-t border-neutral-800" role="separator"></div>`
							: html`<button
									class="flex min-h-12 w-full items-center gap-3 px-5 py-2 text-left text-base active:bg-neutral-800 disabled:opacity-40"
									role="menuitem"
									?disabled=${it.disabled}
									aria-checked=${it.checked === undefined ? nothing : String(it.checked)}
									@click=${(e: MouseEvent) => this.choose(it, e)}
								>
									<!-- The tick and the arrow are drawn, not read: aria-checked
									     and the submenu's own heading say the same to a screen
									     reader, and an item's name stays its label. -->
									<span class="w-5 shrink-0 text-accent" aria-hidden="true">${it.checked ? "✓" : it.icon ?? ""}</span>
									<span class="min-w-0 flex-1 truncate">${it.label}</span>
									${it.submenu ? html`<span class="text-neutral-500" aria-hidden="true">›</span>` : nothing}
								</button>`,
					)}
					<div class="mx-5 my-1 border-t border-neutral-800"></div>
					<button class="flex h-12 w-full items-center justify-center text-base text-neutral-400" data-test="sheet-cancel" @click=${(e: MouseEvent) => this.counts(e) && this.close()}>Cancel</button>
				</div>
			</div>
		`;
	}
}

/** Open a sheet (one at a time: a new one replaces the last, as menus do). */
export function showSheet(items: MenuItem[], heading = ""): void {
	document.querySelectorAll("gorani-sheet").forEach((s) => s.remove());
	const sheet = document.createElement("gorani-sheet") as GoraniSheet;
	const before = document.activeElement;
	sheet.returnFocus = before instanceof HTMLElement && before !== document.body ? before : null;
	sheet.items = items;
	sheet.heading = heading;
	document.body.append(sheet);
}

declare global {
	interface HTMLElementTagNameMap {
		"gorani-sheet": GoraniSheet;
	}
}
