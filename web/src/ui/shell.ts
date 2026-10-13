// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-shell>: the unlocked application frame. It owns the lock button,
 * the auto-lock clock, and — for this commit — a stub that says the explorer
 * arrives next. The session is the shell's single precious dependency: every
 * feature below it (explorer, viewer, shares) receives it read-only and calls
 * session.lock() through the shell's event, never directly.
 */

import { LitElement, html } from "lit";
import { customElement, property } from "lit/decorators.js";
import type { Member } from "../lib/api.ts";
import { watchAutoLock, type VaultSession } from "../vault/session.ts";

@customElement("gorani-shell")
export class GoraniShell extends LitElement {
	@property({ type: Object }) member!: Member;
	@property({ type: Object }) session!: VaultSession;
	@property({ type: Boolean }) stay = false;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override updated(): void {
		// The auto-lock clock: 10 minutes hidden (the same window the device
		// hold promises). One watcher per session; re-set on updates.
		watchAutoLock(this.session, 10);
	}

	protected override render() {
		return html`
			<div class="flex h-full flex-col">
				<header class="flex items-center justify-between border-b border-neutral-800 px-6 py-3">
					<div>
						<span class="font-semibold text-accent">Gorani</span>
						<span class="ml-2 text-sm text-neutral-400">${this.member.name}</span>
					</div>
					<button class="rounded-lg border border-neutral-700 px-3 py-1.5 text-sm hover:border-accent" @click=${() => this.session.lock()}>
						Lock
					</button>
				</header>
				<main class="flex flex-1 items-center justify-center px-6">
					<p class="max-w-md text-center text-sm text-neutral-500">
						The vault is open${this.stay ? " (held on this device for 10 minutes)" : ""}. The file explorer arrives with the
						next commit — the session is ready, the keys are non-extractable, and the local index will hang off
						<code>session.indexKey</code>.
					</p>
				</main>
			</div>
		`;
	}
}