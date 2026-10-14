// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-shell>: the unlocked application frame. It owns the lock button,
 * the auto-lock clock, and the explorer — in whichever platform skin the
 * member prefers (persisted per browser): the Windows 11 File Explorer
 * simulation or the macOS Finder simulation, both views over the same
 * sealed model.
 *
 * Since commit 27 it also opens the TEAM at unlock (vault/team.ts: the
 * member's identity, created and registered the first time; their own
 * area's recovery copy, refreshed when missing or stale), and switches the
 * explorer between AREAS — "My files" or a case the member is granted, the
 * same explorer over `case:<id>` with the case key (signature checked
 * before the first byte is opened) — and the Team panel (ui/team.ts).
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { api, type Member } from "../lib/api.ts";
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
import { registerMediaWorker, forgetMedia } from "../lib/media-worker.ts";
import "./team.ts";
import { openTeam, refreshRecoveryCopy, type TeamCall, type TeamContext } from "../vault/team.ts";
import { openCaseKey, type CaseRow } from "../vault/cases.ts";

/** The browser's TeamCall: the same-origin JSON API (lib/api.ts). */
const teamCall: TeamCall = <T>(method: "GET" | "PUT" | "POST" | "DELETE", path: string, body?: unknown) =>
	(method === "GET" ? api.get<T>(path) : method === "PUT" ? api.put<T>(path, body) : method === "POST" ? api.post<T>(path, body) : api.del<T>(path)) as Promise<T>;

@customElement("gorani-shell")
export class GoraniShell extends LitElement {
	@property({ type: Object }) member!: Member;
	@property({ type: Object }) session!: VaultSession;
	@property({ type: Boolean }) stay = false;

	@state() private mode: PlatformMode = loadMode();
	private model: FilesModel | null = null;
	private index: import("../vault/index.ts").LocalIndex | null = null;
	@state() private viewer: ViewerTarget | null = null;
	/** The area the explorer shows: the member's own id, or `case:<id>`. */
	@state() private area = "";
	@state() private areaTitle = "";
	@state() private view: "files" | "team" = "files";
	@state() private team: TeamContext | null = null;
	@state() private grantedCases: CaseRow[] = [];
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
		this.team = null;
		this.grantedCases = [];
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
			// The media service worker: scope "/" so it controls this page,
			// claiming only /media/ requests (lib/media-worker.ts, O11).
			try {
				await registerMediaWorker();
			} catch (e) {
				console.warn("media worker unavailable:", e);
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
			// An external member has no own area: they start in a case, once
			// the team (and so their trust) is open.
			if (this.member.role !== "external") this.openArea(this.member.id, this.member.name);
			void this.openTeamContext();
		}
	}

	/** The team, at unlock: identity first, then this area's recovery copy.
	 * Best effort — a failure is said, and the files still open. */
	private async openTeamContext(): Promise<void> {
		try {
			this.team = await openTeam(teamCall, this.session, this.member.id);
			if (this.session.locked) return;
			const copy = this.member.role === "external" ? "none" : await refreshRecoveryCopy(teamCall, this.session, this.team);
			if (copy === "sealed") this.toast("Your area's recovery copy is up to date");
			if (copy === "untrusted") this.toast("The team's recovery key is not verified yet — compare a lead's fingerprint (Team › People)");
			await this.loadCases();
			if (!this.area && this.grantedCases[0]) this.openArea(`case:${this.grantedCases[0].id}`, this.grantedCases[0].id);
		} catch (e) {
			this.toast(`Team: ${e instanceof Error ? e.message : String(e)}`);
		}
	}

	private async loadCases(): Promise<void> {
		try {
			this.grantedCases = (await api.get<{ cases: CaseRow[] }>("/api/v1/cases")).cases.filter((c) => c.grant && !c.closed);
		} catch {
			this.grantedCases = [];
		}
	}

	/** Point the explorer at an area. A case's key comes from the member's
	 * grant, opened only after its signature verifies (cases.ts). */
	private openArea(area: string, title: string): void {
		this.model?.dispose();
		const own = area === this.member.id;
		const caseId = own ? null : area.slice("case:".length);
		const openKey = own
			? undefined
			: async () => {
					if (!this.team) throw new Error("the team is still opening — try again in a moment");
					const row = (await api.get<{ cases: CaseRow[] }>("/api/v1/cases")).cases.find((c) => c.id === caseId);
					if (!row?.grant) throw new Error(`you hold no grant on ${caseId}`);
					return openCaseKey(this.session.root, row, this.team.trust);
				};
		this.model = new FilesModel(sessionBridge(this.session, {
			confirmDuplicate: async (count) =>
				window.confirm(`${count} identical file${count > 1 ? "s" : ""} already here.\n\nOK — keep both copies\nCancel — skip the upload`)
					? "keep"
					: "skip",
			toast: (m) => this.toast(m),
			// Signs what this member uploads, checks what others did (commit
			// 29d) — read at each use, so it works from the moment the team
			// context opens, whichever finishes first.
			identity: () => (this.team ? { signer: this.team.signer, trust: this.team.trust } : null),
		}, openKey), area, own ? (this.index ?? undefined) : undefined);
		this.area = area;
		this.areaTitle = title;
		window.__goraniMember = area;
		void this.model
			.open()
			.then(() => (own ? this.persistPinned() : undefined))
			.catch((e) => this.toast(e instanceof Error ? e.message : String(e)));
		void this.requestUpdate();
	}

	/**
	 * Store records opened for the first time get pinned by the session (a
	 * MAC under this root's record key — docs/SECURITY-REVIEW.md › O3); save
	 * them so the NEXT unlock, on any device, verifies instead of trusting.
	 * Best effort: a failed save just means the pin happens again next time.
	 */
	private async persistPinned(): Promise<void> {
		const settings = this.session.takePinned();
		if (!settings || this.session.locked) return;
		try {
			await api.put(`/api/v1/members/${this.member.id}/vault`, { settings });
		} catch (e) {
			console.warn("could not save the pinned store records:", e);
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
						<select class="rounded-lg border border-neutral-700 bg-neutral-950 px-2 py-1.5" title="Area" data-test="area" .value=${this.area} @change=${(e: Event) => {
							const v = (e.target as HTMLSelectElement).value;
							const c = this.grantedCases.find((x) => `case:${x.id}` === v);
							this.view = "files";
							this.openArea(v, c ? c.id : this.member.name);
						}}>
							${this.member.role === "external" ? nothing : html`<option value=${this.member.id}>My files</option>`}
							${this.grantedCases.map((c) => html`<option value=${`case:${c.id}`}>Case ${c.id}</option>`)}
						</select>
						<button class="rounded-lg border px-3 py-1.5 ${this.view === "team" ? "border-accent text-white" : "border-neutral-700 hover:border-accent"}" data-test="team-button" ?disabled=${!this.team} @click=${() => {
							this.view = this.view === "team" ? "files" : "team";
							if (this.view === "files") void this.loadCases();
						}}>Team</button>
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
					${this.view === "team" && this.team
						? html`<gorani-team .session=${this.session} .member=${this.member} .team=${this.team} .call=${teamCall} @open-area=${(e: CustomEvent<{ area: string; title: string }>) => {
								void this.loadCases().then(() => {
									this.view = "files";
									this.openArea(e.detail.area, e.detail.area.slice("case:".length));
								});
							}}></gorani-team>`
						: this.model
							? this.mode === "win11"
								? html`<gorani-win11 .model=${this.model} .memberName=${this.areaTitle} .memberRole=${this.member.role}></gorani-win11>`
								: this.mode === "music"
									? html`<gorani-music .model=${this.model} .memberName=${this.areaTitle}></gorani-music>`
									: html`<gorani-finder .model=${this.model} .memberName=${this.areaTitle}></gorani-finder>`
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
function forgetMediaKeys(): Promise<void> {
	return forgetMedia();
}
