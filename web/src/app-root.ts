// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-app>: the application shell and its four screens.
 *
 * ```text
 * loading ──▶ locked ──▶ unlocked ──┐
 *              │                    │ lock (button, auto-lock, visibility)
 *              └──▶ setup ──────────┘
 * ```
 *
 * The state machine is a small store (src/lib/store.ts); components read it
 * and re-render. The vault session is the only precious state in the app, and
 * it lives in exactly one variable here — the shell drops it on lock and
 * hands it to the explorer (next commit) as a read-only dependency.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { store } from "./lib/store.ts";
import { api, type FamilyState, type Member } from "./lib/api.ts";
import type { VaultSettings } from "./vault/methods.ts";
import type { VaultSession } from "./vault/session.ts";
import "./ui/unlock.ts";
import "./ui/setup.ts";
import "./ui/shell.ts";

type Screen =
	| { at: "loading" }
	| { at: "error"; message: string }
	| { at: "choose"; family: FamilyState }
	| { at: "locked"; member: Member; settings: VaultSettings }
	| { at: "setup"; member: Member }
	| { at: "unlocked"; member: Member; session: VaultSession; stay: boolean };

const screen = store<Screen>({ at: "loading" });

@customElement("gorani-app")
export class GoraniApp extends LitElement {
	// Rule 1: no Shadow DOM, so the global Tailwind stylesheet applies.
	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	// The screens live in the store; Lit re-renders only when told, so the
	// subscription IS the wiring (caught by the browser e2e: without it the
	// app renders "Loading…" forever — a fetch succeeds and nobody looks).
	private unsub: (() => void) | null = null;

	override connectedCallback(): void {
		super.connectedCallback();
		this.unsub = screen.subscribe(() => this.requestUpdate());
	}

	override disconnectedCallback(): void {
		this.unsub?.();
		this.unsub = null;
		super.disconnectedCallback();
	}

	protected override async firstUpdated(): Promise<void> {
		void this.boot();
	}

	private async boot(): Promise<void> {
		try {
			const family = await api.get<FamilyState>("/api/v1/family");
			const active = family.members.filter((m) => m.active);
			if (!active.length) {
				screen.set({ at: "error", message: "No members yet — the first member is created by the family admin (a parent signs in first)." });
				return;
			}
			screen.set({ at: "choose", family });
		} catch (e) {
			screen.set({ at: "error", message: e instanceof Error ? e.message : String(e) });
		}
	}

	protected override render() {
		const s = screen.get();
		switch (s.at) {
			case "loading":
				return html`<div class="flex h-full items-center justify-center text-neutral-500">Loading…</div>`;
			case "error":
				return html`<div class="flex h-full items-center justify-center px-6"><p class="max-w-md text-center text-red-400">${s.message}</p></div>`;
			case "choose":
				return this.renderChoose(s.family);
			case "locked":
				return html`<gorani-unlock .memberId=${s.member.id} .memberName=${s.member.name} .settings=${s.settings} @unlocked=${(e: CustomEvent) => this.onUnlocked(s.member, e.detail)}></gorani-unlock>`;
			case "setup":
				return html`<gorani-setup .memberId=${s.member.id} .memberName=${s.member.name} @settings=${(e: CustomEvent) => screen.set({ at: "locked", member: s.member, settings: e.detail.settings })} @setup-done=${() => void this.bootMember(s.member)}></gorani-setup>`;
			case "unlocked":
				return html`<gorani-shell .member=${s.member} .session=${s.session} .stay=${s.stay} @locked=${() => void this.bootMember(s.member)}></gorani-shell>`;
		}
	}

	private renderChoose(family: FamilyState) {
		const active = family.members.filter((m) => m.active);
		return html`
			<section class="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-6 shadow-xl">
				<h2 class="text-lg font-medium">Who's opening?</h2>
				<ul class="mt-3 space-y-2">
					${active.map(
						(m) => html`
							<li>
								<button class="w-full rounded-xl border border-neutral-700 px-3 py-2.5 text-left text-sm hover:border-accent" @click=${() => void this.bootMember(m)}>
									${m.name} <span class="text-neutral-500">· ${m.role}</span>
								</button>
							</li>
						`,
					)}
				</ul>
			</section>
		`;
	}

	private async bootMember(member: Member): Promise<void> {
		screen.set({ at: "loading" });
		try {
			const settings = await api.get<VaultSettings | null>(`/api/v1/members/${member.id}/vault`);
			if (!settings || !settings.methods?.length) {
				screen.set({ at: "setup", member });
				return;
			}
			// A reload inside the device-hold window opens by itself.
			const { GoraniUnlock } = await import("./ui/unlock.ts");
			const fromHold = await GoraniUnlock.fromHold(member.id, settings);
			if (fromHold) {
				screen.set({ at: "unlocked", member, session: fromHold.session, stay: true });
				return;
			}
			screen.set({ at: "locked", member, settings });
		} catch (e) {
			screen.set({ at: "error", message: e instanceof Error ? e.message : String(e) });
		}
	}

	private onUnlocked(member: Member, detail: { session: VaultSession; stay: boolean }): void {
		screen.set({ at: "unlocked", member, session: detail.session, stay: detail.stay });
	}
}

export { screen };