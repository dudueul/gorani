// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-app>: the application shell and its four screens.
 *
 * ```text
 * loading ──▶ locked ──▶ unlocked ──┐
 *   │          │                    │ lock (button, auto-lock, visibility)
 *   │          └──▶ setup ──────────┘
 *   └──▶ first (nobody registered yet: the first lead, once — commit 39k)
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
	| { at: "first" }
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
				// A fresh deployment (commit 39k): until then this said "the
				// first member is created by the admin" and offered no way to,
				// short of a hand-made API call carrying the bootstrap token.
				screen.set({ at: "first" });
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
			case "first":
				return this.renderFirst();
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

	// ── The first lead (commit 39k) ──────────────────────────────────────
	// Shown only while the registry has no active member. The Worker checks
	// the token (BOOTSTRAP_TOKEN, constant time) and the registry makes the
	// signed-in person — their Access email, not one typed here — the lead.
	@state() private firstId = "";
	@state() private firstName = "";
	@state() private firstToken = "";
	@state() private firstError = "";
	@state() private firstBusy = false;

	private async createFirst(e: Event): Promise<void> {
		e.preventDefault();
		if (!/^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$/.test(this.firstId)) {
			this.firstError = "Member id: 2–32 characters — lowercase letters, digits and dashes.";
			return;
		}
		const token = this.firstToken.trim();
		// A header carries Latin-1 only (fetch throws a TypeError otherwise),
		// and the token wrangler holds is base64 — so anything else is a
		// paste gone wrong, said in words.
		if (!/^[\x21-\x7e]+$/.test(token)) {
			this.firstError = "The bootstrap token is the value you gave wrangler: letters, digits and + / = only, no spaces.";
			return;
		}
		this.firstBusy = true;
		this.firstError = "";
		try {
			await api.post("/api/v1/family/members", { id: this.firstId, name: this.firstName.trim() || this.firstId, role: "lead" }, { "x-gorani-bootstrap": token });
			this.firstToken = "";
			await this.boot();
		} catch (err) {
			this.firstError = err instanceof Error ? err.message : String(err);
		} finally {
			this.firstBusy = false;
		}
	}

	private renderFirst() {
		const field = "mt-1 w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm outline-none focus:border-accent";
		return html`
			<form class="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-6 shadow-xl" @submit=${(e: Event) => void this.createFirst(e)}>
				<h2 class="text-lg font-medium">Create the first lead</h2>
				<p class="mt-2 text-sm text-neutral-400">
					Nobody is registered yet. The first member is a lead, made once with this deployment's bootstrap token
					(<code>BOOTSTRAP_TOKEN</code>). You become that lead, under the email you signed in with.
				</p>
				<label class="mt-4 block text-sm">Member id
					<input class=${field} name="member-id" autocomplete="off" spellcheck="false" placeholder="e.g. seongwoo" .value=${this.firstId} @input=${(e: Event) => (this.firstId = (e.target as HTMLInputElement).value.trim().toLowerCase())} />
				</label>
				<label class="mt-3 block text-sm">Name
					<input class=${field} name="member-name" autocomplete="name" .value=${this.firstName} @input=${(e: Event) => (this.firstName = (e.target as HTMLInputElement).value)} />
				</label>
				<label class="mt-3 block text-sm">Bootstrap token
					<input class=${field} name="bootstrap-token" type="password" autocomplete="off" .value=${this.firstToken} @input=${(e: Event) => (this.firstToken = (e.target as HTMLInputElement).value)} />
				</label>
				${this.firstError ? html`<p class="mt-3 text-sm text-red-400">${this.firstError}</p>` : nothing}
				<button class="mt-5 w-full rounded-xl bg-accent px-3 py-2.5 text-sm font-medium text-neutral-950 disabled:opacity-50" ?disabled=${this.firstBusy}>
					${this.firstBusy ? "Creating…" : "Create"}
				</button>
			</form>
		`;
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