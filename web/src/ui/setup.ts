// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-setup>: creating a member's vault. Every member sets up their
 * OWN (since commit 27c nobody sets one up for someone else): they pick a
 * password, get a recovery code shown exactly once, and store the
 * settings — a hybrid post-quantum root sealed under both methods, from
 * birth (no upgrade path will ever be needed — there was never a
 * pre-quantum gorani key).
 *
 * After the vault exists, the member's own files store key is created and
 * sealed — here in code so the first session has it (keys.ts is the
 * composition). Their identity key, its registration and their recovery
 * copy are the next steps (identity.ts, recovery.ts; the screens are
 * docs/CASES.md › stage 6).
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { addPasskeyMethod, createVaultBundle, type VaultSettings } from "../vault/methods.ts";
import { createPasskey, prfOutput } from "../vault/passkey.ts";
import { updateSettings } from "../vault/settings-store.ts";
import { createStoreKey, sealStoreKeyToMember } from "../vault/keys.ts";
import { importVaultKey } from "../vault/vault-crypto.ts";
import { deriveRecordKey, macRecord } from "../vault/records.ts";
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
	/** The new root's bytes, kept only while the code screen is up — what
	 * lets "also unlock with a passkey" wrap a copy without asking for the
	 * password just typed. Wiped when the member leaves the screen. */
	private rootBundle: Uint8Array | null = null;
	@state() private passkeyNote = "";

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
					${this.rootBundle
						? html`<button class="mt-4 w-full rounded-xl border border-neutral-700 px-4 py-2.5 text-sm hover:border-accent disabled:opacity-50" ?disabled=${this.busy} data-test="setup-passkey" @click=${() => void this.addPasskey()}>
								Also unlock with a passkey on this device
							</button>`
						: nothing}
					${this.passkeyNote ? html`<p class="mt-2 text-xs text-neutral-400" data-test="setup-passkey-note">${this.passkeyNote}</p>` : nothing}
					<button class="mt-4 w-full rounded-xl bg-accent px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90" @click=${() => {
						this.forgetRoot();
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
			// The first store key: this member's files. (Shared work lives in
			// cases, whose keys come with their grants — cases.ts.)
			const filesStore = await createStoreKey();
			bundle.settings.stores.files = await sealStoreKeyToMember(filesStore, { ec: bundle.settings.publicKey, kem: bundle.settings.pqPublicKey });
			// …authenticated from birth: the record's MAC under the new root's
			// record key (records.ts — a swapped record is refused on open).
			const root = await importVaultKey(bundle.rootBundle);
			bundle.settings.stores.files.mac = await macRecord(await deriveRecordKey(root), "files", bundle.settings.stores.files);
			const res = await api.put<{ keyId: string }>(`/api/v1/members/${this.memberId}/vault`, { settings: bundle.settings });
			if (res.keyId !== bundle.keyId) throw new Error("the server did not keep the settings it was given");
			this.recoveryCode = bundle.recoveryCode;
			this.lastSettings = bundle.settings;
			this.rootBundle = bundle.rootBundle;
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

	/** A passkey, offered while the new root is still in hand (Team ›
	 * Unlock adds one later, after confirming with a method you have). */
	private async addPasskey(): Promise<void> {
		const root = this.rootBundle;
		if (!root || !this.lastSettings) return;
		this.busy = true;
		this.passkeyNote = "Waiting for your passkey…";
		try {
			const created = await createPasskey(this.memberId, this.memberName || this.memberId);
			const output = await prfOutput(created.credentialId, created.prfSalt);
			const method = await addPasskeyMethod(root, output, created.credentialId, created.prfSalt);
			output.fill(0);
			const call = <T>(m: "GET" | "PUT", path: string, body?: unknown) => (m === "GET" ? api.get<T>(path) : api.put<T>(path, body));
			this.lastSettings = await updateSettings(call, this.memberId, this.lastSettings.keyId, (s) => ({ ...s, methods: [...s.methods, method] }));
			this.forgetRoot();
			this.passkeyNote = "A passkey was added: the unlock screen tries it first.";
		} catch (e) {
			this.passkeyNote = `${e instanceof Error ? e.message : String(e)} — your password and recovery code still work; Team › Unlock can add a passkey later.`;
		} finally {
			this.busy = false;
		}
	}

	private forgetRoot(): void {
		this.rootBundle?.fill(0);
		this.rootBundle = null;
		this.requestUpdate();
	}

	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.forgetRoot();
	}
}