// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The share dialog (owner side): seal a copy of the file under a key that
 * exists only in the link's fragment (GS01), upload it in GC1 frames, and
 * hand back the link. The server keeps ciphertext, the sealed meta and a
 * download counter — never the secret, never the password.
 *
 * The key needs BOTH the link's secret and a password: the password is
 * stretched with Argon2id (the kdf rides the share's meta) and mixed into
 * the key material here. It is shown once for out-of-band sharing (a chat
 * message, a phone call) — the server never sees it, and the sealed copy
 * stays sealed without both halves.
 *
 * The policy (D11, commit 30): a password always (one is generated, the
 * owner may type their own of 8+ characters), at most 7 days, at most 20
 * downloads here (the server allows 100). The server refuses a link
 * without the password's parameters or past a week — this dialog only
 * never asks it to. A partner who needs more gets a guest account.
 *
 * A protected video (commit 40c, docs/DRM.md) can also be shared VIEW-ONLY:
 * no copy is sealed for the link at all — the recipient's page plays the
 * protected copy in Safari, through FairPlay, and has nothing to save. The
 * same secret and password guard it: the page derives a claim proof from
 * both, and the server, holding only the proof's hash, starts a viewing
 * session for nothing less.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { newShareId, newShareSecret, newShareKdf, shareKeys, sealShareMeta, claimHashOf } from "../../vault/share-crypto.ts";
import { sealChunked, DEFAULT_CHUNK } from "../../vault/chunked-file.ts";
import { devIdentityHeaders } from "../../lib/api.ts";
import { areaPath } from "../../lib/area.ts";
import { sealText } from "../../vault/vault-crypto.ts";
import { readyCopy, type FilesModel } from "./model.ts";

export interface ShareTarget {
	id: string;
	name: string;
	size: number;
	version: number;
	/** The original's modified date (39y): it rides in the link's sealed meta. */
	modified?: string | null;
}

/**
 * A password to read aloud or paste: four groups of four from 32
 * characters without look-alikes (no 0/o, 1/l) — 32 divides 256, so a
 * random byte maps without bias — 80 bits, on top of the link's own
 * 256-bit secret.
 */
function generatedPassword(): string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
	const bytes = crypto.getRandomValues(new Uint8Array(16));
	const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
	return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join("")).join("-");
}

@customElement("gorani-share")
export class GoraniShare extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	@property({ type: Object }) target!: ShareTarget;

	@state() private expiry = 7;
	@state() private downloads = 5;
	@state() private password = generatedPassword();
	@state() private busy = false;
	@state() private error: string | null = null;
	@state() private link: string | null = null;
	/** A protected video with a ready copy (40c): the link may be view-only —
	 * and is, unless the owner chooses to hand out the original. */
	@state() private canViewOnly = false;
	@state() private viewOnly = false;
	private copyVersion: number | null = null;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	// Escape closes it, as every dialog does (commit 39l: it did not).
	private onKey = (e: KeyboardEvent) => {
		if (e.key === "Escape") this.close();
	};
	override connectedCallback(): void {
		super.connectedCallback();
		document.addEventListener("keydown", this.onKey);
		void this.model.drmState(this.target.id).then((d) => {
			const copy = readyCopy(d);
			if (d?.protected && copy) {
				this.canViewOnly = true;
				this.viewOnly = true;
				this.copyVersion = copy.version;
			}
		});
	}
	override disconnectedCallback(): void {
		document.removeEventListener("keydown", this.onKey);
		super.disconnectedCallback();
	}

	protected override render() {
		return html`
			<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60" @click=${(e: Event) => e.target === e.currentTarget && this.close()}>
				<div class="w-96 rounded-2xl border border-neutral-700 bg-neutral-900 p-5 shadow-2xl">
					<h3 class="text-sm font-medium text-neutral-100">Share “${this.target.name}”</h3>
					${this.link ? this.done() : this.form()}
					${this.error ? html`<p class="mt-3 text-sm text-red-400">${this.error}</p>` : nothing}
				</div>
			</div>
		`;
	}

	private form() {
		return html`
			<form class="mt-4 text-sm" @submit=${(e: Event) => {
				e.preventDefault();
				void this.create();
			}}>
				${this.canViewOnly
					? html`<fieldset class="mb-3 rounded-xl border border-amber-700/50 p-3 text-xs" data-test="share-kind">
							<legend class="px-1 text-amber-300">🔒 This video is protected</legend>
							<label class="flex gap-2"><input type="radio" name="kind" .checked=${this.viewOnly} @change=${() => (this.viewOnly = true)} data-test="share-view-only" /><span><b class="text-neutral-200">View-only</b> — plays in Safari as the protected copy; nothing to save</span></label>
							<label class="mt-1.5 flex gap-2"><input type="radio" name="kind" .checked=${!this.viewOnly} @change=${() => (this.viewOnly = false)} /><span><b class="text-neutral-200">Download</b> — the original, sealed for the link: whoever opens it can keep it</span></label>
						</fieldset>`
					: nothing}
				<label class="block text-neutral-400">
					Expires after
					<select class="mt-1 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 outline-none focus:border-[var(--color-accent)]" .value=${String(this.expiry)} @change=${(e: Event) => (this.expiry = Number((e.target as HTMLSelectElement).value))}>
						<option value="1">1 day</option>
						<option value="3">3 days</option>
						<option value="7">7 days (the longest a link lives)</option>
					</select>
				</label>
				<label class="mt-3 block text-neutral-400">
					${this.viewOnly ? "Viewings allowed" : "Downloads allowed"}
					<select class="mt-1 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 outline-none focus:border-[var(--color-accent)]" .value=${String(this.downloads)} @change=${(e: Event) => (this.downloads = Number((e.target as HTMLSelectElement).value))}>
						<option value="1">1</option>
						<option value="5">5</option>
						<option value="20">20</option>
					</select>
				</label>
				<label class="mt-3 block text-neutral-400">
					Password <span class="text-neutral-600">(required — send it separately from the link)</span>
					<span class="mt-1 flex gap-2">
						<input type="text" autocomplete="off" spellcheck="false" minlength="8" required class="w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono outline-none focus:border-[var(--color-accent)]" .value=${this.password} @input=${(e: Event) => (this.password = (e.target as HTMLInputElement).value)} data-test="share-password" />
						<button type="button" class="rounded-xl border border-neutral-700 px-3 text-xs hover:border-[var(--color-accent)]" @click=${() => (this.password = generatedPassword())}>New</button>
					</span>
				</label>
				<p class="mt-3 text-xs text-neutral-500">
					The link's secret lives after “#” — browsers never send it, so the server holds only sealed bytes. Opening needs both the link and this password; the password is stretched (Argon2id) in the recipient's tab and never sent. Partners who need more than a week, or more than one file, get a guest account instead.
				</p>
				<button class="mt-4 w-full rounded-xl bg-[var(--color-accent)] px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90 disabled:opacity-50" ?disabled=${this.busy || this.password.length < 8}>
					${this.busy ? "Sealing and uploading…" : "Create the link"}
				</button>
			</form>
		`;
	}

	private done() {
		return html`
			<p class="mt-3 text-xs text-neutral-400">Copy this link — the secret after “#” is shown only now:</p>
			<code class="mt-2 block max-h-24 overflow-auto select-all rounded-xl bg-neutral-950 p-3 text-xs break-all text-[var(--color-accent)]">${this.link}</code>
			${this.password ? html`<p class="mt-3 text-xs text-neutral-400">Share the password separately — opening needs both:</p>
			<code class="mt-2 block select-all rounded-xl bg-neutral-950 p-3 text-xs break-all text-neutral-200">${this.password}</code>` : nothing}
			<div class="mt-4 flex gap-2">
				<button class="flex-1 rounded-xl bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-neutral-950 hover:opacity-90" @click=${() => navigator.clipboard.writeText(this.link ?? "")}>Copy</button>
				<button class="flex-1 rounded-xl border border-neutral-700 px-4 py-2 text-sm hover:border-[var(--color-accent)]" @click=${() => this.close()}>Done</button>
			</div>
		`;
	}

	private async create(): Promise<void> {
		this.busy = true;
		this.error = null;
		try {
			const id = newShareId();
			const secret = newShareSecret();
			// A password makes the key need BOTH halves: the secret in the
			// fragment and this password, stretched with fresh Argon2id
			// settings that ride the share's record (the server stores them —
			// they are parameters, not secrets).
			if (this.password.length < 8) throw new Error("a link's password is at least 8 characters");
			const kdf = newShareKdf();
			const keys = await shareKeys(id, secret, this.password, kdf);
			const expiresAt = new Date(Date.now() + this.expiry * 86_400_000).toISOString();
			if (this.viewOnly && this.copyVersion !== null) {
				// View-only (40c): no copy for the link — only its sealed name,
				// and the hash of the claim proof its page will derive.
				const metaSealed = await sealShareMeta(keys.meta, id, { name: this.target.name, type: null, size: this.target.size, modified: this.target.modified ?? null });
				await this.model.api.apiSend("POST", `${areaPath(this.model.memberId)}/files/shares`, {
					id,
					fileId: this.target.id,
					version: this.copyVersion,
					nameSealed: await this.model.sealShareName(id, this.target.name),
					metaSealed,
					expiresAt,
					downloadsLeft: this.downloads,
					kdf,
					drm: true,
					claimHash: await claimHashOf(keys.claim),
				});
				this.link = `${location.origin}/s/f/${id}#${secret}`;
				return;
			}
			// The copy: the plaintext opened in this tab, re-sealed under a
			// fresh content key… no — under the LINK's data key (GS01): a copy
			// that exists for this link alone, openable without the vault.
			const plainParts: Uint8Array[] = [];
			await this.model.openBytes(this.target.id, this.target.version, (p) => { plainParts.push(p); });
			const plain = concatParts(plainParts);
			const copy = await sealChunked(keys.data, plain, DEFAULT_CHUNK);
			const metaSealed = await sealShareMeta(keys.meta, id, { name: this.target.name, type: null, size: plain.length, modified: this.target.modified ?? null });
			// The owner's list keeps the link's name sealed into the share's place.
			const nameSealed = await this.model.sealShareName(id, this.target.name);

			const start = await this.model.api.apiSend<{ parts: number }>("POST", `${areaPath(this.model.memberId)}/files/shares`, {
				id,
				fileId: this.target.id,
				version: this.target.version,
				nameSealed,
				metaSealed,
				expiresAt,
				downloadsLeft: this.downloads,
				size: plain.length,
				kdf,
			});
			const frame = DEFAULT_CHUNK + 28;
			const frames = Math.ceil(copy.length / frame);
			if (start.parts !== frames) throw new Error("the server counted a different number of parts");
			const etags: { partNumber: number; etag: string }[] = [];
			for (let p = 1; p <= frames; p++) {
				const res = await fetch(`${areaPath(this.model.memberId)}/files/shares/${id}/parts/${p}`, {
					method: "PUT",
					headers: { ...devIdentityHeaders(), "content-type": "application/octet-stream" },
					body: copy.subarray((p - 1) * frame, Math.min(copy.length, p * frame)) as unknown as BodyInit,
				});
				if (!res.ok) throw new Error(`part ${p} refused (${res.status})`);
				etags.push((await res.json()) as { partNumber: number; etag: string });
			}
			await this.model.api.apiSend("POST", `${areaPath(this.model.memberId)}/files/shares/${id}/complete`, { parts: etags, size: plain.length });
			this.link = `${location.origin}/s/f/${id}#${secret}`;
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
			void this.requestUpdate();
		}
	}

	close(): void {
		this.dispatchEvent(new CustomEvent("closed", { bubbles: true, composed: true }));
	}
}

function concatParts(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}
