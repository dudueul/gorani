// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-shell>: the unlocked application frame. It owns the lock button,
 * the auto-lock clock, and the explorer — in whichever platform skin the
 * family member prefers (persisted per browser): the Windows 11 File
 * Explorer simulation or the macOS Finder simulation, both views over the
 * same sealed model.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { Member } from "../lib/api.ts";
import { watchAutoLock, AUTO_LOCK, type VaultSession } from "../vault/session.ts";
import { revokeAllBlobURLs } from "../lib/blob-urls.ts";
import { FilesModel } from "./files/model.ts";
import { sessionBridge } from "./files/bridge.ts";
import { loadMode, saveMode, type PlatformMode } from "./files/shared.ts";
import { LocalIndex } from "../vault/index.ts";
import "./viewer/viewer.ts";
import type { ViewerTarget } from "./viewer/viewer.ts";
import "./files/win11.ts";
import "./files/finder.ts";
import "./files/music.ts";

@customElement("gorani-shell")
export class GoraniShell extends LitElement {
	@property({ type: Object }) member!: Member;
	@property({ type: Object }) session!: VaultSession;
	@property({ type: Boolean }) stay = false;

	@state() private mode: PlatformMode = loadMode();
	private model: FilesModel | null = null;
	private index: import("../vault/index.ts").LocalIndex | null = null;
	@state() private viewer: ViewerTarget | null = null;
	/** Cleanups for the current session's clock and lock subscription. */
	private stopAutoLock: (() => void) | null = null;
	private stopOnLock: (() => void) | null = null;

	/**
	 * Unmount = lock, and lock = unmount (docs/SECURITY-REVIEW.md › O2).
	 * Everything that held plaintext or keys for this session ends here:
	 *
	 * - the model (decrypted names, its poll timer) and the bridge's opened
	 *   store key go with it — nothing keeps a reference;
	 * - the local index worker (decrypted names in its memory) closes after
	 *   one last ENCRYPTED snapshot;
	 * - the media service worker forgets every content key it was handed;
	 * - every blob: URL minted for decrypted bytes is revoked;
	 * - the session itself is locked, if it was not already.
	 */
	override disconnectedCallback(): void {
		super.disconnectedCallback();
		this.stopAutoLock?.();
		this.stopOnLock?.();
		this.stopAutoLock = this.stopOnLock = null;
		this.model?.dispose();
		this.model = null;
		this.viewer = null;
		void this.index?.close();
		this.index = null;
		revokeAllBlobURLs();
		void forgetMediaKeys();
		void this.session?.lock();
	}

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override updated(changed: Map<string, unknown>): void {
		if (changed.has("session")) {
			this.stopAutoLock?.();
			this.stopOnLock?.();
			// The auto-lock clock (docs/DECISIONS.md › D15: 15 idle minutes,
			// or 5 minutes hidden), and the one subscriber that turns "the
			// session locked" into "the screen locked": the app-root swaps in
			// the lock screen, which unmounts this element (see above).
			this.stopAutoLock = watchAutoLock(this.session, AUTO_LOCK);
			this.stopOnLock = this.session.onLock(() => this.dispatchEvent(new CustomEvent("locked", { bubbles: true, composed: true })));
			void this.setupExplorer();
		}
	}

	private async setupExplorer(): Promise<void> {
		{
			// The media service worker: scope /media/ ONLY (the app's own
			// requests never pass through it — see public/sw-media.js).
			if (typeof navigator !== "undefined" && navigator.serviceWorker) {
				try {
					await navigator.serviceWorker.register("/sw-media.js", { scope: "/media/" });
				} catch (e) {
					console.warn("media worker unavailable:", e);
				}
			}
			// The local index: opened with the session's indexKey (derived from
			// the root — the unlock ceremony gates it), fed by the model,
			// persisted as ciphertext. The server never sees a query.
			try {
				this.index = await LocalIndex.open(this.member.id, await this.session.indexKey);
			} catch (e) {
				console.warn("local index unavailable:", e);
			}
			// Locked while the index was opening (the user pressed Lock early)?
			// Then nothing more is built for a session that is already over.
			if (this.session.locked) return;
			// The explorer's model: bridge = the session's non-extractable keys.
			this.model = new FilesModel(sessionBridge(this.session, {
				confirmDuplicate: async (count) =>
					window.confirm(`${count} identical file${count > 1 ? "s" : ""} already here.\n\nOK — keep both copies\nCancel — skip the upload`)
						? "keep"
						: "skip",
				toast: (m) => this.toast(m),
			}), this.member.id, this.index ?? undefined);
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
							<button class="px-2.5 py-1.5 ${this.mode === "music" ? "bg-neutral-700 text-white" : "text-neutral-400 hover:bg-neutral-800"}" title="Music library" @click=${() => this.switchMode("music")}>Music</button>
						</div>
						<button class="rounded-lg border border-neutral-700 px-3 py-1.5 hover:border-accent" @click=${() => void this.session.lock()}>
							Lock
						</button>
					</div>
				</header>
				<main class="relative min-h-0 flex-1" @open-viewer=${(e: CustomEvent) => {
					this.viewer = e.detail as ViewerTarget;
					void this.requestUpdate();
				}}>
					${this.model
						? this.mode === "win11"
							? html`<gorani-win11 .model=${this.model} .memberName=${this.member.name} .memberRole=${this.member.role}></gorani-win11>`
							: this.mode === "music"
								? html`<gorani-music .model=${this.model} .memberName=${this.member.name}></gorani-music>`
								: html`<gorani-finder .model=${this.model} .memberName=${this.member.name}></gorani-finder>`
						: html`<div class="flex h-full items-center justify-center text-sm text-neutral-500">Opening the vault…</div>`}
				</main>
				${this.viewer ? html`<gorani-viewer .model=${this.model} .target=${this.viewer} @closed=${() => (this.viewer = null)}></gorani-viewer>` : nothing}
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

/** Tell the media service worker to drop every content key it holds (lock). */
async function forgetMediaKeys(): Promise<void> {
	if (typeof navigator === "undefined" || !navigator.serviceWorker) return;
	try {
		const reg = await navigator.serviceWorker.getRegistration("/media/");
		reg?.active?.postMessage({ type: "media-forget-all" });
	} catch {
		// no worker registered — nothing to forget
	}
}
