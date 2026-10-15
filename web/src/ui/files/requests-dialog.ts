// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Upload links and the inbox they fill (commit 38, docs/REQUESTS.md) — the
 * explorer's dialog for the area it shows: a member's own files, or a case.
 *
 * Two tabs:
 *
 * - **Inbox** — what arrived, item by item: opened here with the area's
 *   inbox keys, checked (the record must be about THIS item and THIS link;
 *   a collector's must be signed by one this member counts), then
 *   ACCEPTED (a new file — as a malware sample unless the person unticks
 *   it) or REJECTED (the reason sealed). "Check hash" decrypts the bytes
 *   here, compares their SHA-256 with what the sender declared, and — only
 *   when asked — asks MalwareBazaar about that SHA-256 through the Worker.
 *   Nothing else leaves: not a byte, not a name.
 * - **Links** — make one (label, note, password, expiry, limits), copy it
 *   once, revoke it. The link's secret is shown only when it is made.
 *
 * Every string here comes from the server or a sender and goes through
 * Lit's escaping: no markup is ever built from it.
 */

import { LitElement, html, nothing, type TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { FilesModel } from "./model.ts";
import { fmtDate, fmtSize } from "./shared.ts";
import { areaPath } from "../../lib/area.ts";
import { acceptItem, areaInboxKeys, createAreaInboxKey, currentInboxKey, hashInboxContent, linkOf, openAreaInboxKeys, openItem, rejectItem, type InboxCall, type InboxItem, type InboxKeyRow, type OpenedItem } from "../../vault/inbox.ts";
import { createRequestLink, generatedLinkPassword, linkPasswordProblem, linkState, listRequests, openRequestLabel, revokeRequest, LINK_LIMITS, type RequestRow } from "../../vault/requests.ts";
import type { CaseRow } from "../../vault/cases.ts";
import type { CollectorRow } from "../../vault/collectors.ts";
import type { VaultPrivateKey } from "../../vault/vault-crypto.ts";

const input = "mt-1 w-full rounded-xl border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm outline-none focus:border-[var(--color-accent)]";
const button = "rounded-lg border border-neutral-700 px-2.5 py-1 text-xs hover:border-[var(--color-accent)] disabled:opacity-40";
const primary = "rounded-lg bg-[var(--color-accent)] px-2.5 py-1 text-xs font-medium text-neutral-950 hover:opacity-90 disabled:opacity-40";

/** What MalwareBazaar said about a SHA-256 (worker/src/malware.rs). */
interface Lookup {
	found: boolean;
	signature?: string | null;
	fileType?: string | null;
	tags?: string[];
	firstSeen?: string | null;
	link?: string;
}

interface Row {
	item: InboxItem;
	opened: OpenedItem | null;
	error: string | null;
	/** After "Check hash": the decrypted bytes' SHA-256 against the declaration, and MalwareBazaar's answer. */
	check?: { sha256: string; size: number; matches: string | null; lookup?: Lookup | string };
	asSample: boolean;
}

@customElement("gorani-requests")
export class GoraniRequests extends LitElement {
	@property({ type: Object }) model!: FilesModel;
	/** The folder a new link files into (the explorer's current folder, or the one right-clicked). */
	@property({ type: String }) folderId: string | null = null;
	@property({ type: String }) folderName = "";
	@property({ type: String }) tab: "inbox" | "links" = "inbox";

	@state() private busy = false;
	@state() private error: string | null = null;
	@state() private notice: string | null = null;
	@state() private rows: Row[] = [];
	@state() private links: (RequestRow & { labelText: string })[] = [];
	@state() private made: { link: string; password: string } | null = null;
	// The new link's form.
	@state() private label = "";
	@state() private note = "";
	@state() private password = generatedLinkPassword();
	@state() private days = 7;
	@state() private maxFiles = 20;
	@state() private maxGb = 10;

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	private get area(): string {
		return this.model.memberId;
	}

	private call: InboxCall = (method, path, body) => (method === "GET" ? this.model.api.apiGet(path) : this.model.api.apiSend(method, path, body));

	override connectedCallback(): void {
		super.connectedCallback();
		void this.reload();
	}

	private async run(what: () => Promise<string | void>): Promise<void> {
		this.busy = true;
		this.error = null;
		this.notice = null;
		try {
			this.notice = (await what()) || null;
		} catch (e) {
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
		}
	}

	private reload(): Promise<void> {
		return this.run(async () => {
			const storeKey = await this.model.api.storePrivate();
			await Promise.all([this.loadInbox(storeKey), this.loadLinks(storeKey)]);
		});
	}

	/** The area's inbox keys: a case's from the registry, a member's from their store. */
	private async inboxKeys(): Promise<InboxKeyRow[]> {
		if (this.area.startsWith("case:")) {
			const { cases } = await this.model.api.apiGet<{ cases: CaseRow[] }>("/api/v1/cases");
			return cases.find((c) => `case:${c.id}` === this.area)?.inboxKeys ?? [];
		}
		return areaInboxKeys(this.call, this.area);
	}

	private async loadInbox(storeKey: VaultPrivateKey): Promise<void> {
		const keys = await openAreaInboxKeys(storeKey, this.area, await this.inboxKeys());
		const { items } = await this.call<{ items: InboxItem[] }>("GET", `${areaPath(this.area)}/inbox`);
		const me = this.model.api.identity?.() ?? null;
		// Collectors matter in a case only (they drop nowhere else); the list is the registry's.
		const collectors = this.area.startsWith("case:") && items.some((i) => !linkOf(i)) ? await this.model.api.apiGet<{ collectors: CollectorRow[] }>("/api/v1/family/collectors").then((r) => r.collectors, () => []) : [];
		this.rows = await Promise.all(
			items.map(async (item): Promise<Row> => {
				try {
					const opened = await openItem(keys, this.area, item, me?.trust ?? null, collectors);
					return { item, opened, error: null, asSample: opened.kind === "request" };
				} catch (e) {
					return { item, opened: null, error: e instanceof Error ? e.message : String(e), asSample: true };
				}
			}),
		);
	}

	private async loadLinks(storeKey: VaultPrivateKey): Promise<void> {
		const rows = await listRequests(this.call, this.area);
		this.links = await Promise.all(rows.map(async (r) => ({ ...r, labelText: await openRequestLabel(storeKey, this.area, r).catch(() => "(label does not open)") })));
	}

	protected override render(): TemplateResult {
		const tabBtn = (t: "inbox" | "links", label: string) => html`<button class="rounded-lg px-3 py-1.5 text-sm ${this.tab === t ? "bg-neutral-700 text-white" : "text-neutral-400 hover:bg-neutral-800"}" data-test="requests-tab-${t}" @click=${() => (this.tab = t)}>${label}</button>`;
		const waiting = this.rows.filter((r) => r.item.status === "waiting").length;
		return html`
			<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click=${(e: Event) => e.target === e.currentTarget && this.close()}>
				<div class="flex max-h-[90vh] w-full max-w-2xl flex-col rounded-2xl border border-neutral-700 bg-neutral-900 p-5 text-sm text-neutral-200 shadow-2xl" data-test="requests-dialog">
					<div class="flex items-center gap-2">
						<h3 class="flex-1 text-sm font-medium text-neutral-100">Upload links &amp; inbox</h3>
						${tabBtn("inbox", waiting ? `Inbox (${waiting})` : "Inbox")} ${tabBtn("links", "Links")}
						<button class="ml-2 rounded-lg px-2 py-1 text-neutral-400 hover:bg-neutral-800" @click=${() => this.close()}>✕</button>
					</div>
					${this.error ? html`<p class="mt-3 text-sm text-red-400" data-test="requests-error">${this.error}</p>` : nothing}
					${this.notice ? html`<p class="mt-3 text-sm text-emerald-400" data-test="requests-notice">${this.notice}</p>` : nothing}
					<div class="mt-3 min-h-0 flex-1 overflow-y-auto">${this.tab === "inbox" ? this.inbox() : this.linksTab()}</div>
				</div>
			</div>
		`;
	}

	// ── the inbox ─────────────────────────────────────────────────────

	private inbox(): TemplateResult {
		if (!this.rows.length) return html`<p class="py-8 text-center text-neutral-500">Nothing has arrived. Make an upload link (Links) and send it — with its password, separately.</p>`;
		return html`<ul class="space-y-2" data-test="requests-inbox">${this.rows.map((r) => this.itemRow(r))}</ul>`;
	}

	private itemRow(r: Row): TemplateResult {
		const { item, opened } = r;
		const link = linkOf(item);
		const label = link ? (this.links.find((l) => l.id === link)?.labelText ?? link) : item.collector;
		const waiting = item.status === "waiting";
		const lookup = r.check?.lookup;
		return html`<li class="rounded-xl bg-neutral-950 p-3" data-test="requests-item-${item.id}">
			<p class="break-all font-medium text-neutral-100">${opened?.meta.name ?? item.id}</p>
			<p class="mt-0.5 text-xs text-neutral-500">${fmtSize(item.size)} · ${fmtDate(item.receivedAt)} · ${link ? html`upload link “${label}”` : html`collector ${item.collector}`} · ${item.status}${item.accepted ? ` → file ${item.accepted.file}` : ""}</p>
			${opened?.kind === "request" ? html`<p class="mt-1 text-xs text-neutral-400">From “${opened.meta.sender || "unnamed"}”${opened.meta.message ? html` — “${opened.meta.message}”` : nothing}</p>` : nothing}
			<p class="mt-1 text-xs ${r.error || opened?.problem ? "text-amber-400" : opened?.kind === "request" ? "text-amber-300" : "text-emerald-400"}" data-test="requests-verdict-${item.id}">
				${r.error ? `⚠ does not open: ${r.error}` : opened?.problem ? `⚠ ${opened.problem}` : opened?.kind === "request" ? "An outsider's upload: nobody signed it. Its record is about this item — the bytes are unchecked until you check them." : "✓ signed by its collector"}
			</p>
			${r.check
				? html`<p class="mt-1 break-all text-xs ${r.check.matches ? "text-red-400" : "text-neutral-400"}" data-test="requests-check-${item.id}">SHA-256 ${r.check.sha256} — ${r.check.matches ? `⚠ ${r.check.matches}` : "the bytes are what the sender declared"}</p>
					${typeof lookup === "string"
						? html`<p class="mt-1 text-xs text-amber-400">MalwareBazaar: ${lookup}</p>`
						: lookup
							? html`<p class="mt-1 text-xs ${lookup.found ? "text-red-400" : "text-neutral-400"}" data-test="requests-lookup-${item.id}">MalwareBazaar: ${lookup.found ? `KNOWN — ${lookup.signature || "no signature name"}${lookup.fileType ? ` (${lookup.fileType})` : ""}${lookup.tags?.length ? `, tags ${lookup.tags.join(", ")}` : ""}${lookup.firstSeen ? `, first seen ${lookup.firstSeen}` : ""}` : "not known there (which proves nothing about an unseen file)"}</p>`
							: nothing}`
				: nothing}
			${waiting && opened && !opened.problem
				? html`<div class="mt-2 flex flex-wrap items-center gap-2">
						<label class="flex items-center gap-1.5 text-xs text-neutral-300" title="A sample is never previewed and never shared by link; it downloads zipped (password: infected). There is no unmarking.">
							<input type="checkbox" .checked=${r.asSample} data-test="requests-sample-${item.id}" @change=${(e: Event) => this.patch(item.id, { asSample: (e.target as HTMLInputElement).checked })} />
							File as a malware sample
						</label>
						<button class=${button} ?disabled=${this.busy} data-test="requests-check-btn-${item.id}" @click=${() => void this.run(() => this.checkHash(r, false))}>Check hash</button>
						<button class=${button} ?disabled=${this.busy || !r.check} title="Sends ONLY the SHA-256, through the Worker, to MalwareBazaar (abuse.ch)" data-test="requests-lookup-btn-${item.id}" @click=${() => void this.run(() => this.checkHash(r, true))}>Ask MalwareBazaar</button>
						<span class="flex-1"></span>
						<button class=${primary} ?disabled=${this.busy} data-test="requests-accept-${item.id}" @click=${() => void this.run(() => this.accept(r))}>Accept</button>
						<button class=${button} ?disabled=${this.busy} data-test="requests-reject-${item.id}" @click=${() => {
							const reason = window.prompt(`Why is ${opened.meta.name} turned away? (sealed — only this area's key holders read it)`);
							if (reason) void this.run(() => this.reject(r, reason));
						}}>Reject</button>
					</div>`
				: waiting
					? html`<div class="mt-2"><button class=${button} ?disabled=${this.busy} data-test="requests-reject-${item.id}" @click=${() => {
							const reason = window.prompt("Why is this item turned away? (sealed)");
							if (reason) void this.run(() => this.reject(r, reason));
						}}>Reject</button></div>`
					: nothing}
		</li>`;
	}

	private patch(id: string, p: Partial<Row>): void {
		this.rows = this.rows.map((r) => (r.item.id === id ? { ...r, ...p } : r));
	}

	/** Decrypt here and hash: the bytes never leave this tab. */
	private async content(r: Row): Promise<{ sha256: string; size: number }> {
		const res = await fetch(`${areaPath(this.area)}/inbox/${r.item.id}`, { headers: { ...this.model.api.identityHeaders(), "x-gorani-client": "web-inbox" } });
		if (!res.ok || !res.body) throw new Error(`download failed: ${res.status}`);
		return hashInboxContent(r.opened!, r.item, res.body);
	}

	private async checkHash(r: Row, ask: boolean): Promise<string> {
		const content = r.check ?? (await this.content(r));
		const matches = r.check?.matches ?? (content.sha256 !== r.opened!.meta.sha256 || content.size !== r.opened!.meta.size ? "the bytes are NOT what the sender declared" : null);
		let lookup: Lookup | string | undefined = r.check?.lookup;
		if (ask) {
			try {
				lookup = await this.model.api.apiSend<Lookup>("POST", "/api/v1/malware/lookup", { sha256: content.sha256 });
			} catch (e) {
				lookup = e instanceof Error ? e.message : String(e);
			}
		}
		this.patch(r.item.id, { check: { sha256: content.sha256, size: content.size, matches, lookup } });
		return "";
	}

	private async accept(r: Row): Promise<string> {
		const me = this.model.api.identity?.();
		if (!me) throw new Error("your identity is not open yet — accepting signs the file's content hash and intake");
		const storeKey = await this.model.api.storePrivate();
		const keys = await openAreaInboxKeys(storeKey, this.area, await this.inboxKeys());
		const content = await this.content(r);
		const link = linkOf(r.item);
		const row = link ? this.links.find((l) => l.id === link) : undefined;
		await acceptItem(this.call, storeKey, keys, this.area, r.item, r.opened!, content, me.signer, { asSample: r.asSample, folderId: row?.folderId ?? undefined, linkLabel: row?.labelText });
		await this.loadInbox(storeKey);
		await this.model.refresh();
		return `${r.opened!.meta.name} is filed${r.asSample ? " as a malware sample" : ""}: its bytes matched the declaration, and you signed them.`;
	}

	private async reject(r: Row, reason: string): Promise<string> {
		const storeKey = await this.model.api.storePrivate();
		await rejectItem(this.call, storeKey, this.area, r.item.id, reason);
		await this.loadInbox(storeKey);
		return "Rejected; the reason is sealed.";
	}

	// ── the links ─────────────────────────────────────────────────────

	private linksTab(): TemplateResult {
		return html`
			${this.made ? this.madeBox() : this.form()}
			<h4 class="mt-5 text-xs font-semibold uppercase tracking-wide text-neutral-500">This area's links</h4>
			<ul class="mt-2 space-y-1.5" data-test="requests-links">
				${this.links.length ? nothing : html`<li class="text-xs text-neutral-500">None yet.</li>`}
				${this.links.map((l) => {
					const st = linkState(l);
					return html`<li class="flex flex-wrap items-center gap-2 rounded-lg bg-neutral-950 px-3 py-2 text-xs" data-test="requests-link-${l.id}">
						<span class="font-medium text-neutral-100">${l.labelText}</span>
						<span class="text-neutral-500">${l.filesReceived}/${l.maxFiles} files · ${fmtSize(l.bytesReceived)} of ${fmtSize(l.maxBytes)} · until ${fmtDate(l.expiresAt)}${l.failedAttempts ? ` · ${l.failedAttempts} wrong password${l.failedAttempts === 1 ? "" : "s"}` : ""}</span>
						<span class=${st === "open" ? "text-emerald-400" : "text-amber-400"}>${st}</span>
						<span class="flex-1"></span>
						${st === "revoked" ? nothing : html`<button class=${button} ?disabled=${this.busy} data-test="requests-revoke-${l.id}" @click=${() => window.confirm(`Revoke “${l.labelText}”? Nobody can send through it again; what arrived stays in the inbox.`) && void this.run(async () => {
								await revokeRequest(this.call, this.area, l.id);
								await this.loadLinks(await this.model.api.storePrivate());
								return "Revoked.";
							})}>Revoke</button>`}
					</li>`;
				})}
			</ul>
		`;
	}

	private form(): TemplateResult {
		const caseArea = this.area.startsWith("case:");
		return html`<form class="space-y-3" @submit=${(e: Event) => {
			e.preventDefault();
			void this.run(() => this.create());
		}}>
			<p class="text-xs text-neutral-500">Accepted files go into <span class="text-neutral-300">${this.folderName || "the top folder"}</span>${caseArea ? " of this case (making a link into a case is a manager's act)" : ""}. Each arrival waits here until you accept it.</p>
			<label class="block text-neutral-400">Label <span class="text-neutral-600">(for your list — the sender never sees it)</span>
				<input class=${input} required maxlength="200" .value=${this.label} data-test="requests-label" @input=${(e: Event) => (this.label = (e.target as HTMLInputElement).value)} />
			</label>
			<label class="block text-neutral-400">Note to the sender <span class="text-neutral-600">(sealed with the link: the server cannot read it)</span>
				<textarea class=${input} rows="2" maxlength="2000" .value=${this.note} data-test="requests-note" @input=${(e: Event) => (this.note = (e.target as HTMLTextAreaElement).value)}></textarea>
			</label>
			<label class="block text-neutral-400">Password <span class="text-neutral-600">(required to send — give it separately from the link)</span>
				<span class="mt-1 flex gap-2">
					<input class="${input} mt-0 font-mono" autocomplete="off" spellcheck="false" minlength="8" required .value=${this.password} data-test="requests-password" @input=${(e: Event) => (this.password = (e.target as HTMLInputElement).value)} />
					<button type="button" class=${button} @click=${() => (this.password = generatedLinkPassword())}>New</button>
				</span>
			</label>
			<div class="grid grid-cols-3 gap-2">
				<label class="block text-neutral-400">Open for (days)<input class=${input} type="number" min="1" max=${LINK_LIMITS.days} .value=${String(this.days)} @input=${(e: Event) => (this.days = Number((e.target as HTMLInputElement).value))} /></label>
				<label class="block text-neutral-400">Files, at most<input class=${input} type="number" min="1" max=${LINK_LIMITS.files} .value=${String(this.maxFiles)} @input=${(e: Event) => (this.maxFiles = Number((e.target as HTMLInputElement).value))} /></label>
				<label class="block text-neutral-400">GB, at most<input class=${input} type="number" min="1" max="255" .value=${String(this.maxGb)} @input=${(e: Event) => (this.maxGb = Number((e.target as HTMLInputElement).value))} /></label>
			</div>
			<button class="w-full rounded-xl bg-[var(--color-accent)] px-4 py-2.5 font-medium text-neutral-950 hover:opacity-90 disabled:opacity-50" ?disabled=${this.busy || !!linkPasswordProblem(this.password)} data-test="requests-create">${this.busy ? "Making the link…" : "Make the upload link"}</button>
		</form>`;
	}

	private madeBox(): TemplateResult {
		const m = this.made!;
		return html`<div data-test="requests-made">
			<p class="text-xs text-neutral-400">Copy the link — its secret (after “#”) is shown only now:</p>
			<code class="mt-2 block max-h-24 select-all overflow-auto break-all rounded-xl bg-neutral-950 p-3 text-xs text-[var(--color-accent)]" data-test="requests-made-link">${m.link}</code>
			<p class="mt-3 text-xs text-neutral-400">And the password, to send separately (a call, another channel):</p>
			<code class="mt-2 block select-all break-all rounded-xl bg-neutral-950 p-3 text-xs text-neutral-200" data-test="requests-made-password">${m.password}</code>
			<div class="mt-3 flex gap-2">
				<button class=${primary} @click=${() => void navigator.clipboard.writeText(m.link)}>Copy the link</button>
				<button class=${button} @click=${() => {
					this.made = null;
					this.password = generatedLinkPassword();
					this.label = "";
					this.note = "";
				}}>Make another</button>
			</div>
		</div>`;
	}

	private async create(): Promise<string> {
		const storeKey = await this.model.api.storePrivate();
		let keys = await this.inboxKeys();
		if (!keys.some((k) => !k.retiredAt)) {
			if (this.area.startsWith("case:")) throw new Error("this case has no inbox key yet — a manager makes it (Team › Cases › Make the inbox key)");
			const me = this.model.api.identity?.();
			if (!me) throw new Error("your identity is not open yet — your inbox key is signed with it");
			keys = (await createAreaInboxKey(this.call, storeKey, this.area, me.signer)).inboxKeys;
		}
		const current = await currentInboxKey(storeKey, this.area, keys);
		if (!current) throw new Error("no current inbox key");
		const { link } = await createRequestLink(this.call, storeKey, this.area, current, {
			origin: location.origin,
			label: this.label,
			note: this.note,
			password: this.password,
			folderId: this.folderId,
			days: this.days,
			maxFiles: this.maxFiles,
			maxBytes: Math.min(LINK_LIMITS.bytes, Math.round(this.maxGb * 1024 ** 3)),
		});
		this.made = { link, password: this.password };
		await this.loadLinks(storeKey);
		return "";
	}

	close(): void {
		this.dispatchEvent(new CustomEvent("closed", { bubbles: true, composed: true }));
	}
}
