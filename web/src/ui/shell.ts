// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-shell>: the unlocked application frame. It owns the lock button,
 * the auto-lock clock, and the explorer — in whichever platform skin the
 * family member prefers (persisted per browser): the Windows 11 File
 * Explorer simulation or the macOS Finder simulation, both views over the
 * same sealed model.
 */

import { LitElement, html } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { Member } from "../lib/api.ts";
import { watchAutoLock, type VaultSession } from "../vault/session.ts";
import { FilesModel } from "./files/model.ts";
import { sessionBridge } from "./files/bridge.ts";
import { loadMode, saveMode, type PlatformMode } from "./files/shared.ts";
import "./files/win11.ts";
import "./files/finder.ts";

@customElement("gorani-shell")
export class GoraniShell extends LitElement {
	@property({ type: Object }) member!: Member;
	@property({ type: Object }) session!: VaultSession;
	@property({ type: Boolean }) stay = false;

	@state() private mode: PlatformMode = loadMode();
	private model: FilesModel | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override updated(changed: Map<string, unknown>): void {
		if (changed.has("session")) {
			// The auto-lock clock: 10 minutes hidden — the same window the
			// device hold promises.
			watchAutoLock(this.session, 10);
			// The explorer's model: bridge = the session's non-extractable keys.
			this.model = new FilesModel(sessionBridge(this.session, {
				confirmDuplicate: async (count) =>
					window.confirm(`${count} identical file${count > 1 ? "s" : ""} already here.\n\nOK — keep both copies\nCancel — skip the upload`)
						? "keep"
						: "skip",
				toast: (m) => this.toast(m),
			}), this.member.id);
			window.__goraniMember = this.member.id;
			void this.model.open();
			void this.requestUpdate();
		}
	}

	private toasts: { id: number; text: string }[] = [];

	private toast(text: string): void {
		const id = Date.now() + Math.random();
		this.toasts = [...this.toasts, { id, text }];
		setTimeout(() => {
			this.toasts = this.toasts.filter((t) => t.id !== id);
			void this.requestUpdate();
		}, 2600);
		void this.requestUpdate();
	}

	private switchMode(mode: PlatformMode): void {
		this.mode = mode;
		saveMode(mode);
		void this.requestUpdate();
	}

	protected override render() {
		return html`
			<div class="flex h-full flex-col">
				<header class="flex items-center justify-between border-b border-neutral-800 px-4 py-2">
					<div class="flex items-center gap-2">
						<span class="font-semibold text-accent">Gorani</span>
						<span class="text-sm text-neutral-400">${this.member.name}</span>
						<span class="rounded-full bg-neutral-800 px-2 py-0.5 text-[10px] uppercase tracking-wide text-neutral-400">${this.member.role} · sealed</span>
					</div>
					<div class="flex items-center gap-2 text-xs">
						<div class="flex overflow-hidden rounded-lg border border-neutral-700">
							<button class="px-2.5 py-1.5 ${this.mode === "win11" ? "bg-neutral-700 text-white" : "text-neutral-400 hover:bg-neutral-800"}" title="Windows 11 File Explorer" @click=${() => this.switchMode("win11")}>Windows</button>
							<button class="px-2.5 py-1.5 ${this.mode === "macos" ? "bg-neutral-700 text-white" : "text-neutral-400 hover:bg-neutral-800"}" title="macOS Finder" @click=${() => this.switchMode("macos")}>Finder</button>
						</div>
						<button class="rounded-lg border border-neutral-700 px-3 py-1.5 hover:border-accent" @click=${() => this.session.lock()}>
							Lock
						</button>
					</div>
				</header>
				<main class="min-h-0 flex-1">
					${this.model
						? this.mode === "win11"
							? html`<gorani-win11 .model=${this.model} member-name=${this.member.name} member-role=${this.member.role}></gorani-win11>`
							: html`<gorani-finder .model=${this.model} member-name=${this.member.name}></gorani-finder>`
						: html`<div class="flex h-full items-center justify-center text-sm text-neutral-500">Opening the vault…</div>`}
				</main>
				<div class="pointer-events-none fixed bottom-4 left-1/2 z-50 -translate-x-1/2 space-y-2">
					${this.toasts.map((t) => html`<div class="rounded-xl border border-neutral-700 bg-neutral-900/95 px-4 py-2 text-sm text-neutral-200 shadow-xl">${t.text}</div>`)}
				</div>
			</div>
		`;
	}
}

declare global {
	interface Window {
		__goraniMember?: string;
	}
}