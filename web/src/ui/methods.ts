// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-methods>: how this member unlocks — Team › Unlock (commit 39l).
 *
 * The vault has always had three kinds of unlock method (vault/methods.ts:
 * a password, a recovery code, a passkey through the WebAuthn PRF
 * extension), and the unlock screen has always tried a passkey first — but
 * until this panel nothing in the app could ADD one, or change a password,
 * or replace a recovery code. Setup made a password and a code, and that
 * was that.
 *
 * Every change here follows the one rule of methods.ts: **you confirm with
 * a method you already have, every time**. The root key in this session is
 * non-extractable — it cannot hand out the bytes a new method must wrap —
 * so the panel opens the root AGAIN from the method you confirm with, wraps
 * the copy it needs, and wipes the bytes. Someone at an unlocked, unattended
 * screen therefore cannot add their own way in (they would need a secret
 * first), and cannot quietly remove yours either (removal asks too).
 *
 * The other rules:
 * - the last method is never removed (the server refuses that save too —
 *   member.rs › methods_refusal: an enabled vault with no way in is lost);
 * - removing the last recovery code is allowed, after a plain warning:
 *   without one, a forgotten password means a recovery ceremony;
 * - at most MAX_PASSWORD_METHODS passwords (O8: each costs an Argon2 run
 *   at every unlock attempt);
 * - a new recovery code REPLACES the old ones (an old paper code stops
 *   working), and is shown once;
 * - the save fetches the server's settings first and changes only their
 *   `methods`: everything else (stores, identity) stays exactly as stored,
 *   and a vault whose root changed elsewhere is refused, not overwritten.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { VaultSession } from "../vault/session.ts";
import type { TeamCall } from "../vault/team.ts";
import { addPasskeyMethod, addPasswordMethod, addRecoveryMethod, confirmKeyBytes, type PresentSecret, type UnlockMethod } from "../vault/methods.ts";
import { MAX_PASSWORD_METHODS } from "../vault/kdf-bounds.ts";
import { passwordProblem } from "../vault/vault-crypto.ts";
import { createPasskey, prfOutput } from "../vault/passkey.ts";
import { updateSettings } from "../vault/settings-store.ts";

/** What the person asked for; it runs once they have confirmed. */
type Change =
	| { kind: "add-password"; password: string; confirm: string }
	| { kind: "change-password"; id: string; password: string; confirm: string }
	| { kind: "add-passkey"; label: string }
	| { kind: "new-recovery" }
	| { kind: "remove"; id: string };

const KIND_LABEL: Record<UnlockMethod["kind"], string> = { password: "Password", recovery: "Recovery code", passkey: "Passkey" };
const input = "rounded-lg border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm outline-none focus:border-accent";
const button = "rounded-lg border border-neutral-700 px-2.5 py-1.5 text-xs hover:border-accent disabled:opacity-40";
const primary = "rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-neutral-950 hover:opacity-90 disabled:opacity-40";

@customElement("gorani-methods")
export class GoraniMethods extends LitElement {
	@property({ type: Object }) session!: VaultSession;
	@property({ type: String }) memberName = "";
	@property({ attribute: false }) call!: TeamCall;

	@state() private change: Change | null = null;
	/** How the person proves it is them: the kind, and the typed secret. */
	@state() private proof: { kind: "password" | "recovery" | "passkey"; value: string } = { kind: "password", value: "" };
	@state() private busy = false;
	@state() private error = "";
	@state() private status = "";
	/** A new recovery code, shown until the person says they wrote it down. */
	@state() private shownCode: string | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	private get methods(): UnlockMethod[] {
		return this.session.settings.methods;
	}

	protected override render() {
		const methods = this.methods;
		const passwords = methods.filter((m) => m.kind === "password").length;
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="methods">
				<h3 class="font-medium">How you unlock</h3>
				<p class="mt-1 text-xs text-neutral-400">Each method opens the same vault key. Adding or removing one asks you to confirm with one you already have — so nobody at your unlocked screen can add their own way in.</p>
				${this.error ? html`<p class="mt-2 rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-red-300" data-test="methods-error">${this.error}</p>` : nothing}
				${this.status ? html`<p class="mt-2 text-xs text-neutral-400" data-test="methods-status">${this.status}</p>` : nothing}
				<ul class="mt-2 divide-y divide-neutral-800">
					${methods.map((m) => html`<li class="flex flex-wrap items-center gap-2 py-2" data-test="method-${m.kind}">
						<span class="w-32">${KIND_LABEL[m.kind]}</span>
						<span class="flex-1 truncate text-xs text-neutral-400">${m.label && m.label !== KIND_LABEL[m.kind] ? m.label : ""} ${m.createdAt ? `added ${m.createdAt.slice(0, 10)}` : ""}</span>
						${m.kind === "password" ? html`<button class=${button} ?disabled=${this.busy} data-test="method-change-${m.id}" @click=${() => this.ask({ kind: "change-password", id: m.id, password: "", confirm: "" })}>Change</button>` : nothing}
						<button class=${button} ?disabled=${this.busy || methods.length <= 1} title=${methods.length <= 1 ? "Your only way in cannot be removed" : ""} data-test="method-remove-${m.id}" @click=${() => this.ask({ kind: "remove", id: m.id })}>Remove</button>
					</li>`)}
				</ul>
				<div class="mt-2 flex flex-wrap gap-2">
					<button class=${button} ?disabled=${this.busy} data-test="method-add-passkey" @click=${() => this.ask({ kind: "add-passkey", label: "" })}>Add a passkey</button>
					<button class=${button} ?disabled=${this.busy || passwords >= MAX_PASSWORD_METHODS} data-test="method-add-password" @click=${() => this.ask({ kind: "add-password", password: "", confirm: "" })}>Add a password</button>
					<button class=${button} ?disabled=${this.busy} data-test="method-new-recovery" @click=${() => this.ask({ kind: "new-recovery" })}>New recovery code</button>
				</div>
				${this.change ? this.renderChange(this.change) : nothing}
				${this.shownCode
					? html`<div class="mt-3 rounded-lg border border-accent/40 p-3" data-test="method-code">
							<p class="text-xs text-neutral-300">Your new recovery code — write it down now; it is shown once, and your old code no longer works:</p>
							<code class="mt-2 block select-all rounded-lg bg-neutral-950 p-2 text-center text-sm tracking-widest text-accent">${this.shownCode}</code>
							<button class="${primary} mt-2" @click=${() => (this.shownCode = null)}>I wrote it down</button>
						</div>`
					: nothing}
			</section>
		`;
	}

	private ask(change: Change): void {
		this.error = "";
		this.status = "";
		this.change = change;
		// Confirm with the strongest method enrolled: a passkey asks for a
		// touch, not a typed secret.
		const kinds = new Set(this.methods.map((m) => m.kind));
		this.proof = { kind: kinds.has("passkey") ? "passkey" : kinds.has("password") ? "password" : "recovery", value: "" };
	}

	/** The form for the change asked for, and the confirmation under it. */
	private renderChange(c: Change) {
		const set = (patch: Partial<Change>) => (this.change = { ...c, ...patch } as Change);
		const kinds = [...new Set(this.methods.map((m) => m.kind))];
		const target = c.kind === "remove" ? this.methods.find((m) => m.id === c.id) : null;
		const lastRecovery = target?.kind === "recovery" && this.methods.filter((m) => m.kind === "recovery").length === 1;
		return html`<form class="mt-3 flex flex-col gap-2 rounded-lg border border-neutral-700 p-3" data-test="method-change" @submit=${(ev: Event) => {
			ev.preventDefault();
			void this.apply(c);
		}}>
			${c.kind === "add-password" || c.kind === "change-password"
				? html`<p class="text-xs text-neutral-300">${c.kind === "add-password" ? "A new password:" : "The new password (it replaces this one):"}</p>
						<input class=${input} type="password" name="new-password" placeholder="12+ characters" autocomplete="new-password" .value=${c.password} @input=${(e: Event) => set({ password: (e.target as HTMLInputElement).value })} />
						<input class=${input} type="password" name="new-password-again" placeholder="Repeat it" autocomplete="new-password" .value=${c.confirm} @input=${(e: Event) => set({ confirm: (e.target as HTMLInputElement).value })} />`
				: c.kind === "add-passkey"
					? html`<p class="text-xs text-neutral-300">Your browser asks for a passkey — Touch ID, Windows Hello, a phone or a security key. Only one that supports the PRF extension can unlock a vault; the browser says so if this one cannot.</p>
							<input class=${input} name="passkey-label" placeholder="A name for it (e.g. work laptop)" .value=${c.label} @input=${(e: Event) => set({ label: (e.target as HTMLInputElement).value })} />`
					: c.kind === "new-recovery"
						? html`<p class="text-xs text-neutral-300">A new recovery code replaces your current one: the old code stops working.</p>`
						: html`<p class="text-xs text-neutral-300">Remove ${target ? KIND_LABEL[target.kind].toLowerCase() : "this method"}${target?.label && target.label !== KIND_LABEL[target.kind] ? ` “${target.label}”` : ""}?</p>
								${lastRecovery ? html`<p class="text-xs text-amber-400">This is your only recovery code. Without one, a forgotten password or a lost passkey means a recovery ceremony by the leads.</p>` : nothing}`}
			<p class="mt-1 text-xs text-neutral-400">Confirm it is you, with:</p>
			<div class="flex flex-wrap items-center gap-2">
				<select class=${input} name="confirm-kind" .value=${this.proof.kind} @change=${(e: Event) => (this.proof = { kind: (e.target as HTMLSelectElement).value as "password" | "recovery" | "passkey", value: "" })}>
					${kinds.map((k) => html`<option value=${k} ?selected=${this.proof.kind === k}>${KIND_LABEL[k]}</option>`)}
				</select>
				${this.proof.kind === "passkey"
					? html`<span class="text-xs text-neutral-500">your browser will ask for it</span>`
					: html`<input class="${input} flex-1" type="password" name="confirm-secret" autocomplete=${this.proof.kind === "password" ? "current-password" : "off"} placeholder=${this.proof.kind === "password" ? "Your current password" : "Your recovery code"} .value=${this.proof.value} @input=${(e: Event) => (this.proof = { ...this.proof, value: (e.target as HTMLInputElement).value })} />`}
			</div>
			<div class="flex gap-2">
				<button class=${primary} ?disabled=${this.busy} type="submit" data-test="method-apply">${c.kind === "remove" ? "Remove" : "Confirm"}</button>
				<button class=${button} type="button" @click=${() => (this.change = null)}>Cancel</button>
			</div>
		</form>`;
	}

	/** The presented proof, as methods.ts › openRoot takes it. */
	private async presented(): Promise<PresentSecret> {
		const p = this.proof;
		if (p.kind !== "passkey") {
			if (!p.value) throw new Error(p.kind === "password" ? "Type your current password to confirm" : "Type your recovery code to confirm");
			return { kind: p.kind, value: p.value };
		}
		// Each enrolled passkey in turn: the first the authenticator answers.
		// A cancelled prompt ends the search — the person said no, and a
		// second prompt for the next passkey would only ask again.
		let last: unknown = new Error("no passkey is enrolled");
		for (const m of this.methods.filter((x) => x.kind === "passkey" && x.credentialId && x.prfSalt)) {
			try {
				return { kind: "passkey", output: await prfOutput(m.credentialId!, m.prfSalt!) };
			} catch (e) {
				last = e;
				if (e instanceof DOMException && e.name === "NotAllowedError") break;
			}
		}
		throw last instanceof DOMException && last.name === "NotAllowedError" ? new Error("The passkey prompt was cancelled") : last;
	}

	private async apply(c: Change): Promise<void> {
		this.busy = true;
		this.error = "";
		this.status = "Confirming…";
		let confirming: Uint8Array | null = null;
		try {
			// The checks that need no secret come first: nothing is opened for
			// a change that cannot be made.
			if ((c.kind === "add-password" || c.kind === "change-password") && c.password !== c.confirm) throw new Error("The two passwords differ");
			if (c.kind === "add-password" || c.kind === "change-password") {
				const problem = passwordProblem(c.password);
				if (problem) throw new Error(problem);
			}
			if (c.kind === "remove" && this.methods.length <= 1) throw new Error("Your only way in cannot be removed");
			const secret = await this.presented();
			try {
				confirming = await confirmKeyBytes(this.session.settings, secret);
			} catch {
				throw new Error(secret.kind === "passkey" ? "That passkey does not open this vault" : `That ${secret.kind === "password" ? "password" : "recovery code"} does not open this vault`);
			}
			let methods = [...this.methods];
			let code: string | null = null;
			let done = "";
			switch (c.kind) {
				case "add-password":
					methods.push(await addPasswordMethod(confirming, c.password));
					done = "A password was added.";
					break;
				case "change-password":
					methods = methods.filter((m) => m.id !== c.id);
					methods.push(await addPasswordMethod(confirming, c.password));
					done = "Your password was changed — the old one no longer unlocks.";
					break;
				case "add-passkey": {
					this.status = "Waiting for your passkey…";
					const created = await createPasskey(this.session.memberId, this.memberName || this.session.memberId);
					// A second touch: creation does not return the PRF output on
					// every browser, so evaluate it the way unlock will.
					const output = await prfOutput(created.credentialId, created.prfSalt);
					methods.push(await addPasskeyMethod(confirming, output, created.credentialId, created.prfSalt, c.label.trim() || "Passkey"));
					output.fill(0);
					done = "A passkey was added: the unlock screen tries it first.";
					break;
				}
				case "new-recovery": {
					const added = await addRecoveryMethod(confirming);
					methods = [...methods.filter((m) => m.kind !== "recovery"), added.method];
					code = added.code;
					done = "A new recovery code replaced the old one.";
					break;
				}
				case "remove":
					methods = methods.filter((m) => m.id !== c.id);
					done = "The method was removed.";
					break;
			}
			this.status = "Saving…";
			await this.save(methods);
			this.change = null;
			this.shownCode = code;
			this.status = done;
		} catch (e) {
			this.status = "";
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			confirming?.fill(0);
			this.proof = { ...this.proof, value: "" };
			this.busy = false;
		}
	}

	/** Change the stored methods and nothing else (see the header). */
	private async save(methods: UnlockMethod[]): Promise<void> {
		await updateSettings(this.call, this.session.memberId, this.session.rootKeyId, (s) => ({ ...s, methods }));
		// The session's settings are the shell's object: the next lock and
		// unlock read the stored ones, this keeps the panel and the unlock
		// screen of this tab in step until then.
		this.session.settings.methods = methods;
		this.requestUpdate();
	}
}

declare global {
	interface HTMLElementTagNameMap {
		"gorani-methods": GoraniMethods;
	}
}
