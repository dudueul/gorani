// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-setup>: creating a member's vault — the moment the family model
 * becomes real. The parent (or first member) picks a password, gets a
 * recovery code shown exactly once, and stores the settings: a hybrid
 * post-quantum root sealed under both methods, from birth (no upgrade path
 * will ever be needed — there was never a pre-quantum gorani key).
 *
 * After the vault exists, the store keys (files; the family shared area) are
 * created and sealed — here in code so the first session has them; the UI
 * does the same composition family.ts teaches.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { createVaultBundle, confirmKeyBytes, addPasswordMethod, addRecoveryMethod, type VaultSettings } from "../vault/methods.ts";
import { createStoreKey, sealStoreKeyToMember } from "../vault/family.ts";
import { api } from "../lib/api.ts";
import { passwordProblem } from "../vault/vault-crypto.ts";

export interface SetupResult {
	settings: VaultSettings;
	recoveryCode: string;
}

@customElement("gorani-setup")
export class GoraniSetup extends LitElement {
	@property({ type: String }) memberId = "";
	@property({ type: String }) memberName = "";

	@state() private password = "";
	@state() private confirm = "";
	@state() private busy = false;
	@state() private error = "";
	@state() private recoveryCode: string | null = null;
	@state() private lastSettings: VaultSettings | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override render() {
		if (this.recoveryCode) {
			return html`
				<section class="w-full max-w-sm rounded-2xl border border-accent/40 bg-neutral-900 p-6 shadow-xl">
					<h2 class="text-lg font-medium">Write this down — once</h2>
					<p class="mt-2 text-sm text-neutral-400">
						The recovery code is the only other way in if the password is forgotten. It is shown once; gorani cannot show it again.
					</p>
					<code class="mt-3 block select-all rounded-xl bg-neutral-950 p-3 text-center text-sm tracking-widest text-accent">${this.recoveryCode}</code>
					<button class="mt-4 w-full rounded-xl bg-accent px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90" @click=${() => {
						this.dispatchEvent(new CustomEvent("settings", { detail: { settings: this.lastSettings }, bubbles: true, composed: true }));
						this.dispatchEvent(new CustomEvent("setup-done", { bubbles: true, composed: true }));
					}}>
						I wrote it down
					</button>
				</section>
			`;
		}
		return html`
			<section class="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-6 shadow-xl">
				<h2 class="text-lg font-medium">Set up ${this.memberName}'s vault</h2>
				<p class="mt-2 text-sm text-neutral-400">A password and a recovery code seal the root key. Everything else derives from it.</p>
				<form class="mt-4" @submit=${(e: Event) => {
					e.preventDefault();
					void this.create();
				}}>
					<input class="w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm outline-none focus:border-accent" type="password" placeholder="Password (12+ chars)" .value=${this.password} @input=${(e: InputEvent) => (this.password = (e.target as HTMLInputElement).value)} autocomplete="new-password" />
					<input class="mt-2 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm outline-none focus:border-accent" type="password" placeholder="Repeat it" .value=${this.confirm} @input=${(e: InputEvent) => (this.confirm = (e.target as HTMLInputElement).value)} autocomplete="new-password" />
					<button class="mt-4 w-full rounded-xl bg-accent px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90 disabled:opacity-50" ?disabled=${this.busy}>
						${this.busy ? "Sealing…" : "Create the vault"}
					</button>
					${this.error ? html`<p class="mt-3 text-sm text-red-400">${this.error}</p>` : nothing}
				</form>
			</section>
		`;
	}

	private async create(): Promise<void> {
		this.error = "";
		if (this.password !== this.confirm) {
			this.error = "The two passwords differ";
			return;
		}
		const problem = passwordProblem(this.password);
		if (problem) {
			this.error = problem;
			return;
		}
		this.busy = true;
		try {
			const bundle = await createVaultBundle(this.password);
			// The first store key: this member's files. (The family shared
			// area's key arrives with the family-admin screen — its copies are
			// sealed per member there; docs/FAMILY.md.)
			const filesStore = await createStoreKey();
			bundle.settings.stores.files = await sealStoreKeyToMember(filesStore, { ec: bundle.settings.publicKey, kem: bundle.settings.pqPublicKey });
			const res = await api.put<{ keyId: string }>(`/api/v1/members/${this.memberId}/vault`, { settings: bundle.settings });
			if (res.keyId !== bundle.keyId) throw new Error("the server did not keep the settings it was given");
			this.recoveryCode = bundle.recoveryCode;
			this.lastSettings = bundle.settings;
			// (The "settings" event waits for the button below: the code is
			// shown ONCE, and the app must not leave this screen before the
			// member has seen it — caught by the browser e2e, which found the
			// event firing on save and skipping the code screen entirely.)
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
		}
	}

	/** Add another method to an existing vault (the confirmation rule). */
	static async addMethod(settings: VaultSettings, memberId: string, kind: "password" | "recovery", confirming: Uint8Array, password?: string): Promise<{ settings: VaultSettings; code?: string }> {
		const methods = [...settings.methods];
		let code: string | undefined;
		if (kind === "password" && password) {
			methods.push(await addPasswordMethod(confirming, password));
		} else if (kind === "recovery") {
			const added = await addRecoveryMethod(confirming);
			methods.push(added.method);
			code = added.code;
		}
		const next = { ...settings, methods };
		await api.put(`/api/v1/members/${memberId}/vault`, { settings: next });
		return { settings: next, code };
	}

	/** The confirmation step's shape, exported for the settings UI (commit ⑨b). */
	static async confirmWith(settings: VaultSettings, secret: Parameters<typeof confirmKeyBytes>[1]): Promise<Uint8Array> {
		return confirmKeyBytes(settings, secret);
	}
}