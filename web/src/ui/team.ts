// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * <gorani-team>: People, Cases and Recovery — docs/CASES.md › Stage 6, the
 * screens. A thin client of cases.ts, identity.ts and recovery.ts: every
 * action here is one of their functions, and every refusal they throw is
 * shown to the person verbatim — those messages ARE the security checks
 * ("signed by X, whom you have not verified"), not errors to hide.
 *
 * What this component holds: the team context the shell opened (signer,
 * trust), the lists it fetched, and — for a ceremony this member
 * coordinates — the ephemeral private key, in memory only. Close the tab
 * and that key is gone; the ceremony is then cancelled and opened again
 * (the screen says so). Nothing here outlives the session: the shell
 * unmounts the panel on lock.
 */

import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import type { Member } from "../lib/api.ts";
import type { VaultSession } from "../vault/session.ts";
import type { VaultPrivateKey } from "../vault/vault-crypto.ts";
import { fingerprint, pin, certify, buildTrust, type RegistryIdentity } from "../vault/identity.ts";
import { newCase, openCaseKey, openCaseTitle, rotateCase, sealCaseGrant, type CaseKind, type CasePermission, type CaseRow, type MemberRoot } from "../vault/cases.ts";
import { approveCeremony, combineCeremony, newCeremony, recoverCaseGrant, recoverMemberStore, setupRecovery, type Ceremony, type RecoveryRecord } from "../vault/recovery.ts";
import type { TeamCall, TeamContext } from "../vault/team.ts";
import { approveRequest, requestApproval, verifyApproval, type Approval, type ApprovalCheck, type TwoPersonAction } from "../vault/approvals.ts";
import { buildExport, reverifyCase, type ExportSource } from "../vault/export.ts";
import { certifyTsa, trustedTsas, tsaIdentityOf, type TrustedTsas, type TsaCert, type TsaIdentity } from "../vault/timestamp.ts";
import { devIdentityHeaders } from "../lib/api.ts";
import { blobURL, revokeBlobURL } from "../lib/blob-urls.ts";

type Tab = "people" | "cases" | "recovery";

const input = "rounded-lg border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm outline-none focus:border-accent";
const button = "rounded-lg border border-neutral-700 px-2.5 py-1.5 text-xs hover:border-accent disabled:opacity-40";
const primary = "rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-neutral-950 hover:opacity-90 disabled:opacity-40";

@customElement("gorani-team")
export class GoraniTeam extends LitElement {
	@property({ type: Object }) session!: VaultSession;
	@property({ type: Object }) member!: Member;
	@property({ type: Object }) team!: TeamContext;
	@property({ attribute: false }) call!: TeamCall;

	@state() private tab: Tab = "people";
	@state() private busy = false;
	@state() private status = "";
	@state() private error = "";
	@state() private members: Member[] = [];
	@state() private identities: RegistryIdentity[] = [];
	@state() private cases: (CaseRow & { title?: string | null })[] = [];
	@state() private recovery: { recovery: (RecoveryRecord & { holdersCurrent?: boolean }) | null; myShare: string | null } | null = null;
	@state() private ceremonies: Ceremony[] = [];
	/** Each case's two-person requests (commit 29f), with this member's own check of their signatures. */
	@state() private approvals: Record<string, (Approval & { check: ApprovalCheck })[]> = {};
	/** Evidence cases' last re-verification (commit 29h). */
	@state() private reverified: Record<string, { last: { at: string; checked: number; failed: number; by: string } | null; overdue: boolean; days: number }> = {};
	/** The timestamp authority (commit 29j): the leads' certifications, those THIS member's trust accepts, and a lead's probe. */
	@state() private tsa: { configured: boolean; certs: TsaCert[] } | null = null;
	@state() private tsaTrusted: TrustedTsas = new Map();
	@state() private tsaProbe: TsaIdentity | null = null;
	/** Ephemeral keys of the ceremonies THIS tab coordinates (memory only). */
	private ephemerals = new Map<string, VaultPrivateKey>();
	private caseKeys = new Map<string, VaultPrivateKey>();

	protected override createRenderRoot(): HTMLElement {
		return this;
	}

	protected override firstUpdated(): void {
		void this.reload();
	}

	private get isLead() {
		return this.member.role === "lead";
	}

	/** Run one action: busy, then a status or the refusal, verbatim. */
	private async act(label: string, f: () => Promise<string | void>): Promise<void> {
		this.busy = true;
		this.error = "";
		this.status = `${label}…`;
		try {
			this.status = (await f()) || `${label}: done`;
			await this.reload();
		} catch (e) {
			this.status = "";
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			this.busy = false;
		}
	}

	private async reload(): Promise<void> {
		const quiet = async <T>(f: () => Promise<T>, fallback: T): Promise<T> => {
			try {
				return await f();
			} catch {
				return fallback;
			}
		};
		this.identities = (await quiet(() => this.call<{ identities: RegistryIdentity[] }>("GET", "/api/v1/family/identities"), { identities: [] })).identities;
		// Externals do not see the registry (stage 2): names fall back to ids.
		this.members = (await quiet(() => this.call<{ members: Member[] }>("GET", "/api/v1/family"), { members: [] as Member[] })).members;
		this.team = { ...this.team, identities: this.identities, trust: await buildTrust(this.team.memberId, this.session.root, this.team.settings.identity!, this.identities) };
		this.tsa = await quiet(() => this.call<{ configured: boolean; certs: TsaCert[] }>("GET", "/api/v1/family/tsa"), null);
		this.tsaTrusted = await trustedTsas(this.team.trust, this.tsa?.certs ?? []);
		const cases = (await quiet(() => this.call<{ cases: CaseRow[] }>("GET", "/api/v1/cases"), { cases: [] })).cases;
		this.cases = await Promise.all(cases.map(async (c) => ({ ...c, title: c.grant ? await quiet(async () => openCaseTitle(await this.caseKey(c), c), null) : null })));
		// The two-person requests, each checked HERE against this member's
		// trust — the panel shows what the signatures say, not the server.
		const approvals: typeof this.approvals = {};
		for (const c of cases) {
			const list = (await quiet(() => this.call<{ approvals: Approval[] }>("GET", `/api/v1/cases/${c.id}/approvals`), { approvals: [] })).approvals;
			// Pending requests, and approved exports not yet spent (commit 29h).
			approvals[c.id] = await Promise.all(list.filter((a) => a.status === "pending" || (a.action === "case.export" && a.status === "approved" && !a.consumedAt)).map(async (a) => ({ ...a, check: await verifyApproval(this.team.trust, a) })));
		}
		this.approvals = approvals;
		const reverified: typeof this.reverified = {};
		for (const c of cases.filter((x) => x.grant && x.kind === "evidence")) {
			const r = await quiet(() => this.call<(typeof this.reverified)[string]>("GET", `/api/v1/cases/${c.id}/reverify`), null);
			if (r) reverified[c.id] = r;
		}
		this.reverified = reverified;
		if (this.member.role !== "external") this.recovery = await quiet(() => this.call("GET", "/api/v1/recovery"), null);
		if (this.isLead || this.member.role === "auditor") this.ceremonies = (await quiet(() => this.call<{ ceremonies: Ceremony[] }>("GET", "/api/v1/recovery/ceremonies"), { ceremonies: [] })).ceremonies;
	}

	private async caseKey(c: CaseRow): Promise<VaultPrivateKey> {
		const cached = this.caseKeys.get(`${c.id}:${c.keyId}`);
		if (cached) return cached;
		const key = await openCaseKey(this.session.root, c, this.team.trust);
		this.caseKeys.set(`${c.id}:${c.keyId}`, key);
		return key;
	}

	private nameOf(id: string): string {
		return this.members.find((m) => m.id === id)?.name ?? id;
	}

	private root = (id: string) => this.call<MemberRoot>("GET", `/api/v1/members/${id}/root`);

	private async saveRecord(record: NonNullable<TeamContext["settings"]["identity"]>): Promise<void> {
		const settings = { ...this.team.settings, identity: record };
		await this.call("PUT", `/api/v1/members/${this.team.memberId}/vault`, { settings });
		this.team = { ...this.team, settings };
		// (The session's own settings object is the shell's; the next unlock
		// reads the saved one.)
		this.session.settings.identity = record;
	}

	// ── render ────────────────────────────────────────────────────────

	protected override render() {
		const tabs: [Tab, string][] = [["people", "People"], ["cases", "Cases"], ...(this.member.role === "external" ? [] : ([["recovery", "Recovery"]] as [Tab, string][]))];
		return html`
			<div class="mx-auto flex h-full max-w-4xl flex-col gap-3 overflow-y-auto p-4 text-sm" data-test="team">
				<nav class="flex gap-1">
					${tabs.map(([t, label]) => html`<button class="${button} ${this.tab === t ? "border-accent text-white" : "text-neutral-400"}" @click=${() => (this.tab = t)}>${label}</button>`)}
					<span class="ml-auto self-center text-xs text-neutral-500">${this.busy ? "working…" : ""}</span>
				</nav>
				${this.error ? html`<p class="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-red-300" data-test="team-error">${this.error}</p>` : nothing}
				${this.status ? html`<p class="text-xs text-neutral-400" data-test="team-status">${this.status}</p>` : nothing}
				${this.tab === "people" ? this.renderPeople() : this.tab === "cases" ? this.renderCases() : this.renderRecovery()}
			</div>
		`;
	}

	// ── People ────────────────────────────────────────────────────────

	private renderPeople() {
		const mine = this.team.settings.identity!;
		return html`
			<section class="rounded-xl border border-neutral-800 p-3">
				<h3 class="font-medium">Your identity</h3>
				<p class="mt-1 text-xs text-neutral-400">Read this to a lead when you join — they compare it on their screen before they certify you. Compare theirs with them, then trust it.</p>
				<code class="mt-2 block font-mono text-accent" data-test="my-fingerprint">${fingerprint(mine.keyId)}</code>
			</section>
			<section class="rounded-xl border border-neutral-800 p-3">
				<h3 class="font-medium">Team identities</h3>
				<ul class="mt-2 divide-y divide-neutral-800">
					${this.identities.filter((e) => e.member !== this.team.memberId).map((e) => {
						const t = this.team.trust.of(e.member);
						const certifiedByMe = e.certs.some((c) => c.by === this.team.memberId && c.keyId === e.keyId);
						return html`
							<li class="flex flex-wrap items-center gap-2 py-2" data-test="identity-${e.member}">
								<span class="w-32 truncate">${this.nameOf(e.member)}${e.active === false ? html` <span class="text-xs text-neutral-500">(left)</span>` : nothing}</span>
								<code class="font-mono text-xs text-neutral-300">${fingerprint(e.keyId)}</code>
								<span class="text-xs ${t ? "text-emerald-400" : "text-amber-400"}">${t ? (t.via === "pin" ? "you verified" : `certified by ${this.nameOf(t.via.slice(5))}`) : "not verified"}</span>
								<span class="ml-auto flex gap-1">
									${t?.via === "pin" ? nothing : html`<button class=${button} ?disabled=${this.busy} @click=${() => this.act(`Trusting ${e.member}`, async () => {
										await this.saveRecord(await pin(this.team.memberId, this.session.root, this.team.settings.identity!, { member: e.member, keyId: e.keyId }));
										return `You trust ${this.nameOf(e.member)}'s identity (pinned under your own key).`;
									})}>I compared — trust</button>`}
									${this.isLead && !certifiedByMe && e.active !== false ? html`<button class=${button} ?disabled=${this.busy} @click=${() => this.act(`Certifying ${e.member}`, async () => {
										await this.call("PUT", `/api/v1/family/members/${e.member}/cert`, await certify(this.team.signer, e));
										return `You certified ${this.nameOf(e.member)}: everyone who trusts you now trusts them.`;
									})}>Certify</button>` : nothing}
								</span>
							</li>
						`;
					})}
				</ul>
			</section>
			${this.renderTsa()}
		`;
	}

	/**
	 * The timestamp authority (commit 29j, timestamp.ts): which TSA keys the
	 * leads certified, and whether THIS member's trust accepts each. A lead
	 * reads the TSA's certificate from a probe token, compares its
	 * fingerprint with the one the TSA publishes, and only then certifies.
	 */
	private renderTsa() {
		if (!this.tsa) return nothing;
		const bySpki = new Map<string, TsaCert[]>();
		for (const c of this.tsa.certs) bySpki.set(c.spki, [...(bySpki.get(c.spki) ?? []), c]);
		const p = this.tsaProbe;
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="tsa">
				<h3 class="font-medium">Timestamp authority</h3>
				<p class="mt-1 text-xs text-neutral-400">${this.tsa.configured
					? "Evidence versions and audit checkpoints are stamped by a third party (RFC 3161). A stamp counts when a lead you trust certified the authority's key."
					: "No timestamp authority is configured (TSA_URL): evidence is dated by the audit trail alone."}</p>
				<ul class="mt-2 divide-y divide-neutral-800">
					${[...bySpki].map(([spki, certs]) => {
						const counts = this.tsaTrusted.has(spki);
						return html`<li class="flex flex-wrap items-center gap-2 py-2 text-xs" data-test="tsa-${spki.slice(0, 16)}">
							<span class="w-48 truncate">${certs[0]!.name}</span>
							<code class="font-mono text-neutral-400">key ${spki.slice(0, 16)}…</code>
							<span class=${counts ? "text-emerald-400" : "text-amber-400"}>certified by ${certs.map((c) => this.nameOf(c.by)).join(", ")}${counts ? "" : " — none of them someone you verified"}</span>
							${this.isLead ? html`<button class="${button} ml-auto" ?disabled=${this.busy} @click=${() => this.act("Withdrawing the authority", async () => {
								await this.call("DELETE", `/api/v1/family/tsa/${spki}`);
								return `${certs[0]!.name}'s key no longer counts: its tokens now read as uncertified.`;
							})}>Withdraw</button>` : nothing}
						</li>`;
					})}
				</ul>
				${this.isLead && this.tsa.configured
					? p
						? html`<div class="mt-2 rounded-lg border border-neutral-700 p-2 text-xs" data-test="tsa-probe">
								<p><span class="text-neutral-400">Authority:</span> ${p.name}</p>
								<p><span class="text-neutral-400">Certificate SHA-256:</span> <code class="break-all font-mono text-accent">${p.certFingerprint}</code></p>
								<p><span class="text-neutral-400">Valid:</span> ${p.notBefore.slice(0, 10)} – ${p.notAfter.slice(0, 10)}</p>
								<p class="mt-1 text-neutral-400">Compare the fingerprint with the one the authority publishes — on its own site, not this page — before you certify.</p>
								<div class="mt-2 flex gap-2">
									<button class=${primary} ?disabled=${this.busy} data-test="tsa-certify" @click=${() => this.act("Certifying the authority", async () => {
										this.tsa = await certifyTsa(this.call, this.team.signer, { spki: p.spki, name: p.name });
										this.tsaProbe = null;
										return `You certified ${p.name}'s key: stamps it signs now count for everyone who trusts you.`;
									})}>I compared — certify</button>
									<button class=${button} @click=${() => (this.tsaProbe = null)}>Cancel</button>
								</div>
							</div>`
						: html`<button class="${button} mt-2" ?disabled=${this.busy} data-test="tsa-read" @click=${() => this.act("Asking the authority", async () => {
								const probe = await this.call<{ token: string }>("POST", "/api/v1/family/tsa/probe");
								this.tsaProbe = await tsaIdentityOf(probe.token);
							})}>Read the authority's certificate</button>`
					: nothing}
			</section>
		`;
	}

	// ── Cases ─────────────────────────────────────────────────────────

	@state() private newId = "";
	@state() private newTitle = "";
	@state() private newKind: CaseKind = "working";
	@state() private grantTo: Record<string, { member: string; permission: CasePermission; expires: string }> = {};

	private renderCases() {
		return html`
			${this.isLead
				? html`<form class="flex flex-wrap items-center gap-2 rounded-xl border border-neutral-800 p-3" @submit=${(ev: Event) => {
						ev.preventDefault();
						void this.act(`Opening ${this.newId}`, async () => {
							const opened = await newCase(this.newId.trim(), this.newKind, this.newTitle.trim() || this.newId.trim(), { ec: this.team.settings.publicKey, kem: this.team.settings.pqPublicKey }, this.team.signer);
							await this.call("POST", "/api/v1/cases", opened.body);
							const id = this.newId.trim();
							this.newId = this.newTitle = "";
							return `Case ${id} is open; you manage it.`;
						});
					}}>
						<input class=${input} placeholder="case id (ir-2026-014)" .value=${this.newId} @input=${(e: InputEvent) => (this.newId = (e.target as HTMLInputElement).value)} data-test="case-id" />
						<input class="${input} flex-1" placeholder="title (sealed)" .value=${this.newTitle} @input=${(e: InputEvent) => (this.newTitle = (e.target as HTMLInputElement).value)} data-test="case-title" />
						<select class=${input} .value=${this.newKind} @change=${(e: Event) => (this.newKind = (e.target as HTMLSelectElement).value as CaseKind)} data-test="case-kind">
							<option value="working">working</option>
							<option value="evidence">evidence</option>
						</select>
						<button class=${primary} ?disabled=${this.busy || !this.newId.trim()} data-test="case-open">Open a case</button>
					</form>`
				: nothing}
			${this.cases.length === 0 ? html`<p class="text-neutral-500">No cases you can see.</p>` : nothing}
			${this.cases.map((c) => this.renderCase(c))}
		`;
	}

	private renderCase(c: CaseRow & { title?: string | null }) {
		const manage = c.grant?.permission === "manage";
		const g = this.grantTo[c.id] ?? { member: "", permission: "read" as CasePermission, expires: "" };
		const candidates = this.identities.filter((e) => e.active !== false && !c.grantees.some((x) => x.member === e.member));
		const target = this.members.find((m) => m.id === g.member);
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="case-${c.id}">
				<div class="flex flex-wrap items-center gap-2">
					<span class="font-medium">${c.title ?? c.id}</span>
					<code class="text-xs text-neutral-500">${c.id}</code>
					<span class="rounded-full bg-neutral-800 px-2 py-0.5 text-[10px] uppercase text-neutral-400">${c.kind}</span>
					${c.closed ? html`<span class="text-xs text-neutral-500">closed</span>` : nothing}
					${c.rotationRequired ? html`<span class="text-xs text-amber-400">rotation owed</span>` : nothing}
					${c.rotating ? html`<span class="text-xs text-amber-400">rotation walking</span>` : nothing}
					${c.hold ? html`<span class="text-xs text-amber-400" data-test="hold-${c.id}">legal hold since ${c.hold.since.slice(0, 10)}</span>` : nothing}
					<span class="ml-auto text-xs text-neutral-400">${c.grant ? `you: ${c.grant.permission}` : "structure only"}</span>
					${c.grant ? html`<button class=${primary} ?disabled=${this.busy} data-test="case-enter-${c.id}" @click=${() => this.act(`Opening ${c.id}`, async () => {
						await this.caseKey(c); // the signature check, before the explorer
						this.dispatchEvent(new CustomEvent("open-area", { detail: { area: `case:${c.id}`, title: c.title ?? c.id }, bubbles: true, composed: true }));
					})}>Open</button>` : nothing}
				</div>
				${c.grantees.length ? html`<ul class="mt-2 flex flex-wrap gap-1 text-xs">${c.grantees.map((x) => html`
					<li class="flex items-center gap-1 rounded-full bg-neutral-800 px-2 py-0.5">${this.nameOf(x.member)} · ${x.permission}${x.expiresAt ? ` · until ${x.expiresAt.slice(0, 10)}` : ""}
						${manage && x.member !== this.team.memberId && !c.closed ? html`<button class="text-neutral-400 hover:text-red-400" title="Revoke" ?disabled=${this.busy} @click=${() => this.act(`Revoking ${x.member}`, async () => {
							await this.call("DELETE", `/api/v1/cases/${c.id}/grants/${x.member}`);
							return `${this.nameOf(x.member)} is off ${c.id}. They kept the key: rotate it now.`;
						})}>×</button>` : nothing}
					</li>`)}</ul>` : nothing}
				${manage && !c.closed
					? html`<div class="mt-3 flex flex-wrap items-center gap-2">
						<select class=${input} .value=${g.member} @change=${(e: Event) => (this.grantTo = { ...this.grantTo, [c.id]: { ...g, member: (e.target as HTMLSelectElement).value } })} data-test="grant-member-${c.id}">
							<option value="">grant to…</option>
							${candidates.map((e) => html`<option value=${e.member}>${this.nameOf(e.member)}</option>`)}
						</select>
						<select class=${input} .value=${g.permission} @change=${(e: Event) => (this.grantTo = { ...this.grantTo, [c.id]: { ...g, permission: (e.target as HTMLSelectElement).value as CasePermission } })}>
							<option value="read">read</option>
							<option value="write">write</option>
							<option value="manage">manage</option>
						</select>
						${target?.role === "external" ? html`<input class=${input} type="date" .value=${g.expires} @input=${(e: InputEvent) => (this.grantTo = { ...this.grantTo, [c.id]: { ...g, expires: (e.target as HTMLInputElement).value } })} />` : nothing}
						<button class=${button} ?disabled=${this.busy || !g.member} data-test="grant-${c.id}" @click=${() => this.act(`Granting ${g.member}`, async () => {
							const sealed = await sealCaseGrant(this.session.root, c, await this.root(g.member), this.team.signer, this.team.trust);
							await this.call("PUT", `/api/v1/cases/${c.id}/grants/${g.member}`, { permission: g.permission, ...sealed, ...(g.expires ? { expiresAt: new Date(`${g.expires}T23:59:59Z`).toISOString() } : {}) });
							this.grantTo = { ...this.grantTo, [c.id]: { member: "", permission: "read", expires: "" } };
							return `${this.nameOf(g.member)} can ${g.permission} ${c.id} — their copy is sealed to their verified root and signed by you.`;
						})}>Grant</button>
						${c.rotationRequired || c.rotating ? html`<button class=${button} ?disabled=${this.busy} @click=${() => this.act(`Rotating ${c.id}`, async () => {
							const roots = await Promise.all(c.grantees.map((x) => this.root(x.member)));
							const r = await rotateCase(this.call, this.session.root, c, roots, this.team.signer, this.team.trust);
							return `${c.id} rotated: ${Object.values(r.report.resealed).reduce((a, b) => a + b, 0)} values re-sealed; the old key opens nothing.`;
						})}>Rotate the key</button>` : nothing}
						${c.kind === "working"
							? html`<button class=${button} ?disabled=${this.busy} @click=${() => window.confirm(`Close ${c.id}? It becomes read-only for good.`) && this.act(`Closing ${c.id}`, async () => {
									await this.call("POST", `/api/v1/cases/${c.id}/close`);
								})}>Close</button>`
							: nothing}
					</div>`
					: nothing}
				${this.twoPerson(c, manage)}
			</section>
		`;
	}

	/**
	 * The legal hold and the two-person rule (commit 29f): a hold is placed
	 * by one manager or lead; closing an EVIDENCE case and lifting a hold
	 * are asked for by one and agreed by a second lead. Each pending request
	 * shows what its signature says to THIS member.
	 */
	private twoPerson(c: CaseRow, manage: boolean) {
		const may = (manage || this.isLead) && !c.closed;
		const pending = this.approvals[c.id] ?? [];
		const ask = (action: TwoPersonAction, label: string) => html`<button class=${button} ?disabled=${this.busy || pending.some((a) => a.action === action)} data-test="ask-${action}-${c.id}" @click=${() => this.act(label, async () => {
			await requestApproval(this.call, this.team.signer, c.id, action);
			return `Asked: ${action} on ${c.id}. A second lead must agree — they see it here.`;
		})}>${label}</button>`;
		return html`
			${may
				? html`<div class="mt-2 flex flex-wrap items-center gap-2">
					${c.hold
						? ask("hold.release", "Ask to lift the hold")
						: html`<button class=${button} ?disabled=${this.busy} data-test="hold-place-${c.id}" @click=${() => window.confirm(`Place a legal hold on ${c.id}? Nothing in it can be deleted or purged until two leads lift it.`) && this.act(`Holding ${c.id}`, async () => {
								await this.call("POST", `/api/v1/cases/${c.id}/hold`);
								return `${c.id} is under a legal hold. Lifting it takes two leads.`;
							})}>Place a legal hold</button>`}
					${c.kind === "evidence" ? ask("case.close", "Ask to close") : nothing}
					${c.grant ? ask("case.export", "Ask to export") : nothing}
				</div>`
				: nothing}
			${c.grant && c.kind === "evidence" ? this.reverifyRow(c) : nothing}
			${pending.length
				? html`<ul class="mt-2 space-y-1 text-xs">${pending.map((a) => html`
					<li class="flex flex-wrap items-center gap-2 rounded-lg bg-neutral-900 px-2 py-1" data-test="approval-${a.id}">
						<span><b>${a.action}</b> asked by ${this.nameOf(a.requestedBy)} · ${a.requestedAt.slice(0, 16).replace("T", " ")}</span>
						<span class=${a.check.request ? "text-emerald-400" : "text-red-400"}>${a.check.request ? "signature verified" : "signature does NOT verify — do not agree"}</span>
						${a.status === "approved" && a.action === "case.export" && (a.requestedBy === this.team.memberId || a.approvedBy === this.team.memberId) && c.grant
							? html`<button class=${primary} ?disabled=${this.busy} data-test="export-${a.id}" @click=${() => this.act(`Exporting ${c.id}`, async () => {
									const built = await buildExport(this.source(), this.team.signer, this.team.trust, await this.caseKey(c), c.id, a.id);
									this.save(built.parts, `${c.id}-export-${a.id.slice(0, 8)}.zip`);
									return built.problems.length ? `Exported ${c.id} — with ${built.problems.length} problem(s) recorded in the manifest: ${built.problems.join("; ")}` : `Exported ${c.id}: every record verified. Check it with tools/verify-export.mjs; give the recipient your fingerprint out of band.`;
								})}>Export now</button>`
							: nothing}
						${a.status === "pending" && this.isLead && a.requestedBy !== this.team.memberId && a.check.request
							? html`<button class=${primary} ?disabled=${this.busy} data-test="approve-${a.id}" @click=${() => window.confirm(`Agree to ${a.action} on ${c.id}, asked by ${this.nameOf(a.requestedBy)}? It runs at once.`) && this.act(`Agreeing to ${a.action}`, async () => {
									const done = await approveRequest(this.call, this.team.signer, this.team.trust, a);
									return `${done.executed} on ${c.id}: done, with your signature and ${this.nameOf(a.requestedBy)}'s.`;
								})}>Agree</button>`
							: nothing}
						${a.requestedBy === this.team.memberId
							? html`<button class=${button} ?disabled=${this.busy} @click=${() => this.act("Withdrawing", async () => {
									await this.call("DELETE", `/api/v1/cases/${c.id}/approvals/${a.id}`);
								})}>Withdraw</button>`
							: nothing}
					</li>`)}</ul>`
				: nothing}
		`;
	}

	/** Re-verification (commit 29h): the last run, and a button to run one now. */
	private reverifyRow(c: CaseRow) {
		const r = this.reverified[c.id];
		const last = r?.last;
		return html`<div class="mt-2 flex flex-wrap items-center gap-2 text-xs">
			<span class=${r?.overdue ? "text-amber-400" : "text-neutral-400"} data-test="reverify-${c.id}">${last ? `re-verified ${last.at.slice(0, 10)} by ${this.nameOf(last.by)}: ${last.checked} checked, ${last.failed} failed` : "never re-verified"}${r?.overdue ? ` — overdue (every ${r.days} days)` : ""}</span>
			<button class=${button} ?disabled=${this.busy} data-test="reverify-now-${c.id}" @click=${() => this.act(`Re-verifying ${c.id}`, async () => {
				const done = await reverifyCase(this.source(), await this.caseKey(c), this.team.trust, c.id);
				const stamps = done.stampsRequested ? ` ${done.stampsRequested} older version(s) sent for a timestamp.` : "";
				return done.failed ? `${c.id}: ${done.failed} of ${done.checked} versions do NOT verify — ${done.problems.join("; ")}${stamps}` : `${c.id}: all ${done.checked} versions re-hashed and verified against their signatures.${stamps}`;
			})}>Re-verify now</button>
		</div>`;
	}

	/** The API as the export and re-verification read it (this tab's fetches). */
	private source(): ExportSource {
		return {
			get: (path) => this.call("GET", path),
			post: (path, body) => this.call("POST", path, body),
			put: (path, body) => this.call("PUT", path, body),
			object: async (path) => {
				const r = await fetch(path, { headers: { ...devIdentityHeaders(), "x-gorani-client": "web-export" } });
				if (!r.ok) throw new Error(`download failed: ${r.status}`);
				return { body: new Uint8Array(await r.arrayBuffer()), ck: r.headers.get("x-gorani-ck") ?? "", chunk: Number(r.headers.get("x-gorani-chunk")) || null, version: Number(r.headers.get("x-gorani-version")), hash: r.headers.get("x-gorani-hash") };
			},
		};
	}

	private save(parts: Uint8Array[], name: string): void {
		const url = blobURL(new Blob(parts as BlobPart[], { type: "application/zip" }));
		const a = document.createElement("a");
		a.href = url;
		a.download = name;
		a.click();
		setTimeout(() => revokeBlobURL(url), 5000);
	}

	// ── Recovery ──────────────────────────────────────────────────────

	@state() private threshold = 2;
	@state() private ceremonyTarget = "";
	@state() private ceremonyReason = "";
	@state() private confirmDigest: Record<string, string> = {};

	private renderRecovery() {
		const rec = this.recovery?.recovery;
		const leads = this.members.filter((m) => m.active && m.role === "lead");
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="recovery">
				<h3 class="font-medium">Team recovery key</h3>
				${rec
					? html`<p class="mt-1 text-xs text-neutral-400">${rec.threshold} of ${rec.holders.length} leads (${rec.holders.map((h) => this.nameOf(h)).join(", ")}) must approve any recovery. Set up by ${this.nameOf(rec.createdBy)}.</p>
						${rec.rotationRequired ? html`<p class="mt-1 text-xs text-amber-400">Rotation owed — ${rec.holdersCurrent === false ? "the leads changed" : "a ceremony opened it"}. Rotate it: every area re-seals its copy on its next unlock.</p>` : nothing}
						${this.recovery?.myShare ? html`<p class="mt-1 text-xs text-emerald-400">You hold a share.</p>` : nothing}`
					: html`<p class="mt-1 text-xs text-neutral-400">None yet. Without it, a member who loses every unlock method loses their area, and a case whose holders all left is gone.</p>`}
				${this.isLead
					? html`<div class="mt-2 flex items-center gap-2">
						<label class="text-xs text-neutral-400">approvals needed</label>
						<input class="${input} w-16" type="number" min="2" max=${leads.length} .value=${String(this.threshold)} @input=${(e: InputEvent) => (this.threshold = Number((e.target as HTMLInputElement).value))} />
						<span class="text-xs text-neutral-500">of ${leads.length} leads</span>
						<button class=${button} ?disabled=${this.busy || leads.length < 2} data-test="recovery-setup" @click=${() => this.act(rec ? "Rotating the recovery key" : "Setting up recovery", async () => {
							const body = await setupRecovery(this.team.signer, this.team.trust, await Promise.all(leads.map((l) => this.root(l.id))), this.threshold);
							await this.call("PUT", "/api/v1/recovery", body);
							return `Recovery: ${this.threshold} of ${leads.length} leads. The key existed only in this tab, and is gone.`;
						})}>${rec ? "Rotate" : "Set up"}</button>
						${leads.length < 2 ? html`<span class="text-xs text-amber-400">needs at least two leads</span>` : nothing}
					</div>`
					: nothing}
			</section>
			${this.isLead && rec
				? html`<form class="flex flex-wrap items-center gap-2 rounded-xl border border-neutral-800 p-3" @submit=${(ev: Event) => {
						ev.preventDefault();
						void this.act("Opening a ceremony", async () => {
							const made = await newCeremony(this.team.signer, rec, this.ceremonyTarget.trim(), this.ceremonyReason.trim());
							await this.call("POST", "/api/v1/recovery/ceremonies", made.body);
							this.ephemerals.set(made.body.id, made.ephemeral);
							this.ceremonyTarget = this.ceremonyReason = "";
							return "Ceremony open. Keep this tab open until it completes — its key lives only here.";
						});
					}}>
						<input class=${input} placeholder="member id, or case:<id>" .value=${this.ceremonyTarget} @input=${(e: InputEvent) => (this.ceremonyTarget = (e.target as HTMLInputElement).value)} />
						<input class="${input} flex-1" placeholder="reason (audited, every lead sees it)" .value=${this.ceremonyReason} @input=${(e: InputEvent) => (this.ceremonyReason = (e.target as HTMLInputElement).value)} />
						<button class=${primary} ?disabled=${this.busy || !this.ceremonyTarget.trim() || !this.ceremonyReason.trim()}>Open a ceremony</button>
					</form>`
				: nothing}
			${this.ceremonies.map((c) => this.renderCeremony(c, rec ?? null))}
		`;
	}

	private renderCeremony(c: Ceremony, rec: RecoveryRecord | null) {
		const mine = c.coordinator === this.team.memberId;
		const approved = c.approvals.includes(this.team.memberId);
		const ready = rec ? c.approvals.length >= rec.threshold : false;
		const isMemberTarget = !c.target.startsWith("case:");
		return html`
			<section class="rounded-xl border border-neutral-800 p-3 text-xs" data-test="ceremony-${c.id}">
				<div class="flex flex-wrap items-center gap-2">
					<span class="font-medium text-sm">${c.target}</span>
					<span class="text-neutral-400">by ${this.nameOf(c.coordinator)} · ${c.state} · ${c.approvals.length}${rec ? `/${rec.threshold}` : ""} approvals</span>
				</div>
				<p class="mt-1 text-neutral-400">“${c.reason}”</p>
				${c.state === "open"
					? html`<div class="mt-2 flex flex-wrap items-center gap-2">
						${this.recovery?.myShare && !approved && rec
							? html`<button class=${button} ?disabled=${this.busy} @click=${() => this.act("Approving", async () => {
									const body = await approveCeremony(this.session.root, this.team.trust, c, rec, this.recovery!.myShare!);
									await this.call("PUT", `/api/v1/recovery/ceremonies/${c.id}/shares`, body);
									return "Approved: your share went to the coordinator's key, which you verified they signed.";
								})}>Approve</button>`
							: nothing}
						${mine && ready && rec
							? isMemberTarget
								? html`<input class=${input} placeholder="fingerprint ${c.target} reads to you" .value=${this.confirmDigest[c.id] ?? ""} @input=${(e: InputEvent) => (this.confirmDigest = { ...this.confirmDigest, [c.id]: (e.target as HTMLInputElement).value })} />
									<button class=${primary} ?disabled=${this.busy} @click=${() => this.complete(c, rec)}>Complete</button>`
								: html`<button class=${primary} ?disabled=${this.busy} @click=${() => this.complete(c, rec)}>Complete — take over ${c.target}</button>`
							: nothing}
						${this.isLead ? html`<button class=${button} ?disabled=${this.busy} @click=${() => this.act("Cancelling", async () => void (await this.call("POST", `/api/v1/recovery/ceremonies/${c.id}/cancel`)))}>Cancel</button>` : nothing}
						${mine && !this.ephemerals.has(c.id) ? html`<span class="text-amber-400">This tab no longer holds the ceremony's key — cancel and open it again.</span>` : nothing}
					</div>`
					: nothing}
			</section>
		`;
	}

	private complete(c: Ceremony, rec: RecoveryRecord) {
		return this.act("Completing the ceremony", async () => {
			const ephemeral = this.ephemerals.get(c.id);
			if (!ephemeral) throw new Error("this tab no longer holds the ceremony's key — cancel it and open a new one");
			const material = await this.call<{ shares: string[]; copy: string; case: { id: string; keyId: string; publicKey: { ec: JsonWebKey; kem: string } } | null; draft: { rootDigest: string; root: { ec: JsonWebKey; kem: string } } | null }>("GET", `/api/v1/recovery/ceremonies/${c.id}/material`);
			const key = await combineCeremony(ephemeral, material.shares, rec, this.team.trust);
			let body;
			if (material.case) {
				body = await recoverCaseGrant(key, material.copy, material.case, await this.root(this.team.memberId), this.team.signer, this.team.trust);
			} else if (material.draft) {
				// The digest the member read aloud, typed here: compared by its
				// fingerprint (what people can read), checked in full below.
				const typed = (this.confirmDigest[c.id] ?? "").replace(/\s+/g, "").toUpperCase();
				if (typed !== fingerprint(material.draft.rootDigest).replace(/\s+/g, "")) throw new Error("the fingerprint you typed is not the enrolled root's — do not complete; ask the member to read it again");
				body = await recoverMemberStore(key, material.copy, material.draft.root, material.draft.rootDigest);
			} else {
				throw new Error("the ceremony's target is gone");
			}
			await this.call("POST", `/api/v1/recovery/ceremonies/${c.id}/complete`, body);
			this.ephemerals.delete(c.id);
			return `${c.target} recovered. The recovery key existed whole in this tab for that moment — rotate it.`;
		});
	}
}
