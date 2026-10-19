// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-unlock>: the lock screen. One member, one of their enrolled
 * methods, one secret. The passkey is tried by itself once per page load
 * (browsers that need a click leave the form with a "Use passkey" button —
 * exactly as Mailflare behaves, because this is the browser's own rule).
 *
 * The three methods share one shape here: present a secret → openRoot()
 * tries that kind's methods → openSession() imports non-extractable →
 * optionally remember on device → the shell takes over. A wrong secret is
 * "try again"; two hints travel with it: the recovery code forgives case and
 * dashes (normalised in vault-crypto), a password's Argon2id cost is the
 * deliberate quarter-second of work per guess.
 *
 * **Lost every method?** (commit 27, docs/CASES.md › Recovery) The member,
 * still signed in through Access, RE-ENROLS: a new root, a password, a
 * recovery code and an identity, posted as a draft. Nothing opens yet —
 * a recovery ceremony that several leads approve seals their area to the
 * new root, after the coordinating lead hears its fingerprint from them.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { enrolledKinds, openRoot, type PresentSecret, type VaultSettings } from "../vault/methods.ts";
import { openSession, heldBundle, rememberOnDevice, type VaultSession } from "../vault/session.ts";
import { prfOutput } from "../vault/passkey.ts";
import { createVaultBundle } from "../vault/methods.ts";
import { importVaultKey, passwordProblem } from "../vault/vault-crypto.ts";
import { createIdentity, fingerprint, hybridDigest } from "../vault/identity.ts";
import { api } from "../lib/api.ts";

export interface UnlockResult {
	session: VaultSession;
	stay: boolean;
}

@customElement("gorani-unlock")
export class GoraniUnlock extends LitElement {
	@property({ type: String }) memberId = "";
	@property({ type: Object }) settings!: VaultSettings;
	@property({ type: String }) memberName = "";

	@state() private kind: "password" | "recovery" | "passkey" = "password";
	@state() private secret = "";
	@state() private busy = false;
	@state() private error = "";
	@state() private stay = false;
	@state() private reenrol: { password: string; confirm: string; done: { code: string; fingerprint: string } | null } | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this; // global Tailwind stylesheet (see styles/global.css)
	}

	protected override async firstUpdated(): Promise<void> {
		// The passkey tries itself once per page load, silently. A browser
		// that needs a tap leaves the form here; the user presses the button.
		const kinds = enrolledKinds(this.settings);
		this.kind = kinds.includes("passkey") ? "passkey" : kinds.includes("password") ? "password" : "recovery";
		if (kinds.includes("passkey")) {
			const method = this.settings.methods.find((m) => m.kind === "passkey" && m.prfSalt && m.credentialId);
			if (method?.prfSalt && method.credentialId) {
				this.busy = true;
				try {
					const output = await prfOutput(method.credentialId, method.prfSalt);
					await this.unlock({ kind: "passkey", output });
				} catch {
					this.busy = false; // silently fall back to the form
				}
			}
		}
	}

	private renderReenrol(r: NonNullable<GoraniUnlock["reenrol"]>) {
		if (r.done) {
			return html`
				<section class="w-full max-w-sm rounded-2xl border border-accent/40 bg-neutral-900 p-6 shadow-xl" data-test="reenrolled">
					<h2 class="text-lg font-medium">Re-enrolled — waiting for the leads</h2>
					<p class="mt-2 text-sm text-neutral-400">Read this fingerprint to the lead who coordinates your recovery. They type it before your area is sealed to your new key:</p>
					<code class="mt-3 block select-all break-all rounded-xl bg-neutral-950 p-3 text-center font-mono text-sm text-accent" data-test="reenrol-fingerprint">${r.done.fingerprint}</code>
					<p class="mt-3 text-sm text-neutral-400">Your new recovery code — write it down, it is shown once:</p>
					<code class="mt-2 block select-all break-all rounded-xl bg-neutral-950 p-3 text-center text-sm tracking-widest">${r.done.code}</code>
					<p class="mt-3 text-xs text-neutral-500">When the ceremony completes, unlock with your new password.</p>
				</section>
			`;
		}
		return html`
			<section class="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-6 shadow-xl">
				<h2 class="text-lg font-medium">Re-enrol ${this.memberName}</h2>
				<p class="mt-2 text-sm text-neutral-400">A new key for you. Your files stay sealed until several leads approve a recovery ceremony — nobody, you included, can skip that.</p>
				<form class="mt-4" @submit=${(e: Event) => {
					e.preventDefault();
					void this.submitReenrol(r);
				}}>
					<input class="w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm outline-none focus:border-accent" type="password" placeholder="New password (12+ chars)" .value=${r.password} @input=${(e: InputEvent) => (this.reenrol = { ...r, password: (e.target as HTMLInputElement).value })} autocomplete="new-password" />
					<input class="mt-2 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm outline-none focus:border-accent" type="password" placeholder="Repeat it" .value=${r.confirm} @input=${(e: InputEvent) => (this.reenrol = { ...r, confirm: (e.target as HTMLInputElement).value })} autocomplete="new-password" />
					<button class="mt-4 w-full rounded-xl bg-accent px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90 disabled:opacity-50" ?disabled=${this.busy}>${this.busy ? "Sealing…" : "Re-enrol"}</button>
					<button type="button" class="mt-2 w-full text-xs text-neutral-500 hover:text-neutral-300" @click=${() => (this.reenrol = null)}>Back to unlock</button>
					${this.error ? html`<p class="mt-3 text-sm text-red-400">${this.error}</p>` : nothing}
				</form>
			</section>
		`;
	}

	private async submitReenrol(r: NonNullable<GoraniUnlock["reenrol"]>): Promise<void> {
		this.error = "";
		if (r.password !== r.confirm) {
			this.error = "The two passwords differ";
			return;
		}
		const problem = passwordProblem(r.password);
		if (problem) {
			this.error = problem;
			return;
		}
		this.busy = true;
		try {
			const bundle = await createVaultBundle(r.password);
			const root = await importVaultKey(bundle.rootBundle); // wipes the bundle
			const rootPublic = { ec: bundle.settings.publicKey, kem: bundle.settings.pqPublicKey };
			const identity = await createIdentity(this.memberId, root, rootPublic);
			const rootDigest = await hybridDigest(rootPublic.ec, rootPublic.kem);
			await api.put("/api/v1/recovery/reenrol", { settings: { ...bundle.settings, identity: identity.record }, rootDigest });
			this.reenrol = { ...r, password: "", confirm: "", done: { code: bundle.recoveryCode, fingerprint: fingerprint(rootDigest) } };
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
		}
	}

	protected override render() {
		if (this.reenrol) return this.renderReenrol(this.reenrol);
		const kinds = enrolledKinds(this.settings);
		return html`
			<section class="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-6 shadow-xl">
				<h2 class="text-lg font-medium">Unlock ${this.memberName}</h2>

				${kinds.length > 1
					? html`<nav class="mt-3 flex gap-2 text-sm">
							${(["password", "recovery", "passkey"] as const)
								.filter((k) => kinds.includes(k))
								.map(
									(k) => html`
										<button
											class="rounded-lg px-2.5 py-1 ${this.kind === k ? "bg-accent/20 text-accent" : "text-neutral-400 hover:text-neutral-200"}"
											@click=${() => {
												this.kind = k;
												this.error = "";
											}}
										>
											${k === "password" ? "Password" : k === "recovery" ? "Recovery code" : "Passkey"}
										</button>
									`,
								)}
						</nav>`
					: nothing}

				<form class="mt-4" @submit=${(e: Event) => {
					e.preventDefault();
					void this.submitForm();
				}}>
					${this.kind === "passkey"
						? html`<p class="text-sm text-neutral-400">Your passkey signs nothing here — it releases its secret after verification, and that secret opens the vault.</p>`
						: html`
								<input
									class="w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2.5 text-sm outline-none focus:border-accent"
									.type=${this.kind === "password" ? "password" : "text"}
									.placeholder=${this.kind === "password" ? "Password" : "Recovery code (XXXXX-XXXXX-…)"}
									.value=${this.secret}
									@input=${(e: InputEvent) => (this.secret = (e.target as HTMLInputElement).value)}
									autocomplete="off"
									autocapitalize="off"
									spellcheck="false"
									enterkeyhint="go"
									autofocus
								/>
							`}
					<label class="mt-3 flex items-center gap-2 text-xs text-neutral-400">
						<input type="checkbox" class="accent-[var(--color-accent)]" .checked=${this.stay} @change=${(e: Event) => (this.stay = (e.target as HTMLInputElement).checked)} />
						Stay unlocked for 10 minutes on this device
					</label>
					<button class="mt-4 w-full rounded-xl bg-accent px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90 disabled:opacity-50" ?disabled=${this.busy}>
						${this.busy ? "Opening…" : "Unlock"}
					</button>
					${this.error ? html`<p class="mt-3 text-sm text-red-400">${this.error}</p>` : nothing}
				</form>
				<button class="mt-4 w-full text-xs text-neutral-500 hover:text-neutral-300" data-test="lost-methods" @click=${() => {
					this.error = "";
					this.reenrol = { password: "", confirm: "", done: null };
				}}>Lost every way in? Re-enrol</button>
			</section>
		`;
	}

	private async submitForm(): Promise<void> {
		this.error = "";
		this.busy = true;
		try {
			if (this.kind === "passkey") {
				const method = this.settings.methods.find((m) => m.kind === "passkey" && m.prfSalt && m.credentialId);
				if (!method?.prfSalt || !method.credentialId) throw new Error("no passkey is enrolled");
				const output = await prfOutput(method.credentialId, method.prfSalt);
				await this.unlock({ kind: "passkey", output });
			} else {
				await this.unlock({ kind: this.kind, value: this.secret });
			}
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
			this.busy = false;
		}
	}

	private async unlock(secret: PresentSecret): Promise<void> {
		const { bundle } = await openRoot(this.settings, secret);
		const session = await openSession(this.memberId, this.settings, bundle);
		if (this.stay) {
			// The bundle is needed once more for the hold; openRoot's bytes were
			// zeroed by openSession, so re-open from the presented secret.
			const again = await openRoot(this.settings, secret);
			await rememberOnDevice(this.memberId, again.bundle, session.rootKeyId);
			again.bundle.fill(0);
		}
		this.dispatchEvent(
			new CustomEvent("unlocked", { detail: { session, stay: this.stay } satisfies UnlockResult, bubbles: true, composed: true }),
		);
	}

	/** Called by the shell when a hold exists (reload inside the window). */
	static async fromHold(memberId: string, settings: VaultSettings): Promise<UnlockResult | null> {
		const held = await heldBundle(memberId);
		if (!held) return null;
		const session = await openSession(memberId, settings, held.bundle);
		return { session, stay: true };
	}
}