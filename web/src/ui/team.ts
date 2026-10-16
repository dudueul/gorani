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
import type { Member, TeamRole } from "../lib/api.ts";
import type { VaultSession } from "../vault/session.ts";
import type { VaultPrivateKey } from "../vault/vault-crypto.ts";
import { fingerprint, pin, certify, buildTrust, type RegistryIdentity } from "../vault/identity.ts";
import { newCase, openCaseKey, openCaseTitle, rotateCase, sealCaseGrant, type CaseKind, type CasePermission, type CaseRow, type MemberRoot } from "../vault/cases.ts";
import { approveCeremony, combineCeremony, newCeremony, recoverCaseGrant, recoverMemberStore, setupRecovery, type Ceremony, type RecoveryRecord } from "../vault/recovery.ts";
import type { TeamCall, TeamContext } from "../vault/team.ts";
import { updateSettings } from "../vault/settings-store.ts";
import "./methods.ts";
import { approveRequest, requestApproval, verifyApproval, type Approval, type ApprovalCheck, type TwoPersonAction } from "../vault/approvals.ts";
import { buildExport, reverifyCase, type ExportSource } from "../vault/export.ts";
import { certifyTsa, trustedTsas, tsaIdentityOf, type TrustedTsas, type TsaCert, type TsaIdentity } from "../vault/timestamp.ts";
import { approveCollector, collectorVerdict, requestCollector, type CollectorRow } from "../vault/collectors.ts";
import { acceptInboxItem, createInboxKey, hashInboxContent, linkOf, openInboxItem, openInboxKeys, rejectInboxItem, type InboxItem, type OpenedItem } from "../vault/inbox.ts";
import { listRequests, openRequestLabel } from "../vault/requests.ts";
import { caseArea } from "../lib/area.ts";
import { devIdentityHeaders } from "../lib/api.ts";
import { controllingMediaWorker, pipeToDownload } from "../lib/media-worker.ts";
import { blobURL, revokeBlobURL } from "../lib/blob-urls.ts";

type Tab = "people" | "cases" | "recovery" | "devices" | "unlock" | "collectors" | "status";

/** One of the member's computers, as `GET /api/v1/members/<id>/devices` lists it. */
interface DeviceRow {
	id: string;
	name: string;
	platform: string | null;
	/** What holds its device secret, in the client's own words (commit 34): `tpm`, `keyring`, `tpm+keyring`, `file` — or null before then. */
	protection: string | null;
	createdAt: string;
	lastSeen: string | null;
	revoked: boolean;
}

/** A protection label for people (commit 34, clients/core/src/devicekey.rs). */
function describeProtection(p: string | null): { text: string; weak: boolean } {
	if (!p || p === "cli") return { text: "not recorded — enrolled before protection was tracked", weak: true };
	if (p === "file") return { text: "a file — anyone who copies its profile, with your sign-in, can open this computer's copy", weak: true };
	const names: Record<string, string> = { tpm: "the TPM", keyring: "the login keyring" };
	// A TPM part's options (commit 36): `tpm[pin,pcr:7]`.
	const part = (k: string) => {
		const m = /^(\w+)(?:\[([^\]]*)\])?$/.exec(k);
		if (!m) return k;
		const opts = (m[2] ?? "").split(",").filter(Boolean);
		const pcrs = opts.filter((o) => o.startsWith("pcr:")).map((o) => o.slice(4));
		const how = [opts.includes("pin") ? "with a PIN" : "", pcrs.length ? `sealed to the boot state (PCR ${pcrs.join(", ")})` : ""].filter(Boolean);
		return [names[m[1]!] ?? m[1], ...how].join(", ");
	};
	return { text: p.split("+").map(part).join(" + "), weak: false };
}

const ROLE_LABEL: Record<TeamRole, string> = { lead: "Lead", analyst: "Analyst", auditor: "Auditor", external: "External" };
/** Addresses typed in one box: commas, semicolons, spaces or new lines between them. */
const splitEmails = (s: string) => s.split(/[\s,;]+/).map((e) => e.trim()).filter(Boolean);
/** An expiry as a date input shows it (YYYY-MM-DD); the registry keeps the end of that day, UTC. */
const dayOf = (iso?: string | null) => (iso ?? "").slice(0, 10);

/** `POST /status/storage` (commits 39s, 39u, worker/src/s3.rs › probe):
 * `settings` and `warnings` come to a lead only. */
interface StorageCheck {
	backend: "s3" | "r2";
	ok: boolean;
	problem?: string;
	steps: { step: string; ok: boolean; status: number; reason: string | null; server: string; ms?: number }[];
	warnings?: string[];
	settings?: { name: string; set: boolean; padded?: boolean; shown?: string }[];
}

/** `GET /status` (commit 39u, routes.rs › system_status). */
interface SystemStatus {
	version: string;
	app: { ok: boolean };
	registry: { ok: boolean; ms: number };
	files: { ok: boolean; ms: number; problem?: string } | null;
	storage: { backend: "r2" | "s3" | "none"; configured: boolean };
	timestamps: { configured: boolean };
	drm?: { copies: boolean; playable: boolean; problem: string | null };
	lead: boolean;
}

/** What each probe step is, in the words of what it stands for. */
const STEP_LABEL: Record<string, string> = { write: "Upload (write)", size: "Size check", read: "Download (read)", delete: "Clean up (delete)" };

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
	/** The storage round trip (commits 39s, 39u): each step explained and timed. */
	@state() private storageCheck: StorageCheck | null = null;
	/** Team › Status (commit 39u): the cheap checks, the browser's own round trip, and when. */
	@state() private systemStatus: { at: Date; ms: number; status: SystemStatus | null; error: string } | null = null;
	/** This member's computers (commit 34): what protects each, and revocation. */
	@state() private devices: DeviceRow[] = [];
	/** The team's collectors (commit 37a), each with THIS member's verdict on it (null = counted). */
	@state() private collectors: (CollectorRow & { verdict: string | null })[] = [];
	/** An open case inbox (commit 37c): its items, each opened with the inbox key. */
	@state() private inboxes: Record<string, { item: InboxItem; opened: OpenedItem | null; error: string | null }[]> = {};
	@state() private collectorDraft = { id: "", name: "", commonName: "", key: "" };
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
		this.devices = await quiet(() => this.call<DeviceRow[]>("GET", `/api/v1/members/${this.team.memberId}/devices`), []);
		const collectorRows = (await quiet(() => this.call<{ collectors: CollectorRow[] }>("GET", "/api/v1/family/collectors"), { collectors: [] })).collectors;
		// Externals do not see the registry (stage 2): names fall back to ids.
		this.members = (await quiet(() => this.call<{ members: Member[] }>("GET", "/api/v1/family"), { members: [] as Member[] })).members;
		this.team = { ...this.team, identities: this.identities, trust: await buildTrust(this.team.memberId, this.session.root, this.team.settings.identity!, this.identities) };
		this.collectors = await Promise.all(collectorRows.map(async (c) => ({ ...c, verdict: await collectorVerdict(this.team.trust, c) })));
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
		// Only the identity changes (settings-store.ts): saving this panel's
		// whole copy would put back the unlock methods as they were when the
		// panel opened — undoing a passkey added in Team › Unlock meanwhile.
		const settings = await updateSettings(this.call, this.team.memberId, this.session.rootKeyId, (s) => ({ ...s, identity: record }));
		this.team = { ...this.team, settings };
		// (The session's own settings object is the shell's; the next unlock
		// reads the saved one.)
		this.session.settings.identity = record;
	}

	// ── render ────────────────────────────────────────────────────────

	protected override render() {
		const tabs: [Tab, string][] = [["people", "People"], ["cases", "Cases"], ...(this.member.role === "external" ? [] : ([["recovery", "Recovery"]] as [Tab, string][])), ["devices", "Devices"], ["unlock", "Unlock"], ...(this.member.role === "external" ? [] : ([["collectors", "Collectors"]] as [Tab, string][])), ["status", "Status"]];
		return html`
			<div class="mx-auto flex h-full max-w-4xl flex-col gap-3 overflow-y-auto p-4 text-sm" data-test="team">
				<nav class="flex gap-1">
					${tabs.map(([t, label]) => html`<button class="${button} ${this.tab === t ? "border-accent text-white" : "text-neutral-400"}" data-test="team-tab-${t}" @click=${() => {
						this.tab = t;
						if (t === "status" && !this.systemStatus) void this.checkStatus();
					}}>${label}</button>`)}
					<span class="ml-auto self-center text-xs text-neutral-500">${this.busy ? "working…" : ""}</span>
				</nav>
				${this.error ? html`<p class="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-red-300" data-test="team-error">${this.error}</p>` : nothing}
				${this.status ? html`<p class="text-xs text-neutral-400" data-test="team-status">${this.status}</p>` : nothing}
				${this.tab === "people"
					? this.renderPeople()
					: this.tab === "cases"
						? this.renderCases()
						: this.tab === "devices"
							? this.renderDevices()
							: this.tab === "unlock"
								? html`<gorani-methods .session=${this.session} .memberName=${this.member.name} .call=${this.call}></gorani-methods>`
								: this.tab === "collectors"
									? this.renderCollectors()
									: this.tab === "status"
										? this.renderStatus()
										: this.renderRecovery()}
			</div>
		`;
	}

	// ── Collectors (commit 37a, docs/COLLECTORS.md) ───────────────────

	/**
	 * The machines that drop evidence into case inboxes. Two leads register
	 * one (the second agrees only after this client checked the first's
	 * signature); any lead revokes; a manager of a case lets it drop there.
	 * Each row says whether THIS member's client counts it — both leads'
	 * signatures verifying under their own trust — and if not, why.
	 */
	private renderCollectors() {
		const d = this.collectorDraft;
		const managed = this.cases.filter((c) => c.grant?.permission === "manage" && !c.closed);
		const parseKey = (): JsonWebKey => {
			const v = JSON.parse(d.key) as { publicKey?: JsonWebKey } & JsonWebKey;
			const k = v.publicKey ?? v;
			if (k.kty !== "EC" || k.crv !== "P-256" || !k.x || !k.y) throw new Error("paste the collector's public key — the JSON `gorani-sync collector init` prints");
			return { kty: k.kty, crv: k.crv, x: k.x, y: k.y };
		};
		return html`
			<section class="rounded-xl border border-neutral-800 p-3">
				<h3 class="font-medium">Collectors</h3>
				<p class="mt-1 text-xs text-neutral-400">Machines that drop evidence into a case's inbox with no one signed in — an acquisition server, an EDR drop. They hold only the inbox's public key: they cannot read anything, not even what they sent. A person accepts each item into the case.</p>
				<ul class="mt-2 divide-y divide-neutral-800">
					${this.collectors.map((c) => html`<li class="py-2" data-test="collector-${c.id}">
						<div class="flex items-start gap-3">
							<div class="min-w-0 flex-1">
								<p>${c.name} <span class="text-xs text-neutral-500">${c.id} · ${c.status}</span></p>
								<p class="text-xs text-neutral-500">service token ${c.commonName} · key <code class="font-mono">${fingerprint(c.keyId)}</code></p>
								<p class="text-xs text-neutral-500">asked by ${this.nameOf(c.requestedBy)}${c.approvedBy ? html` · approved by ${this.nameOf(c.approvedBy)}` : nothing}${c.cases.length ? html` · drops into ${c.cases.join(", ")}` : nothing}</p>
								<p class="text-xs ${c.verdict ? "text-amber-400" : "text-emerald-400"}" data-test="collector-verdict-${c.id}">${c.verdict ? `⚠ not counted: ${c.verdict}` : `counted — vouched for by ${this.nameOf(c.requestedBy)} and ${this.nameOf(c.approvedBy ?? "")}`}</p>
							</div>
							${this.isLead && c.status === "pending" && c.requestedBy !== this.team.memberId
								? html`<button class=${primary} ?disabled=${this.busy} data-test="collector-approve-${c.id}" @click=${() => window.confirm(`Approve collector “${c.name}” (${c.commonName})? Compare its key fingerprint with the machine first: ${fingerprint(c.keyId)}`) && this.act(`Approving ${c.id}`, async () => {
										await approveCollector(this.call, this.team.signer, this.team.trust, c);
										return `${c.name} is active`;
									})}>Approve</button>`
								: nothing}
							${this.isLead && (c.status === "active" || c.status === "pending")
								? html`<button class=${button} ?disabled=${this.busy} data-test="collector-revoke-${c.id}" @click=${() => window.confirm(`Revoke collector “${c.name}”? Its service token is refused from the next request on.`) && this.act(`Revoking ${c.id}`, async () => {
										await this.call("DELETE", `/api/v1/family/collectors/${c.id}`);
										return `${c.name} is revoked`;
									})}>Revoke</button>`
								: nothing}
						</div>
						${c.status === "active" && managed.some((m) => !c.cases.includes(m.id))
							? html`<div class="mt-1 flex items-center gap-2 text-xs">
									<span class="text-neutral-500">Let it drop into</span>
									${managed.filter((m) => !c.cases.includes(m.id)).map((m) => html`<button class=${button} ?disabled=${this.busy || !!c.verdict} title=${c.verdict ?? ""} data-test="collector-grant-${c.id}-${m.id}" @click=${() => this.act(`Granting ${m.id}`, async () => {
											await this.call("PUT", `/api/v1/cases/${m.id}/collectors/${c.id}`);
											return `${c.name} may drop into ${m.id}`;
										})}>${m.id}</button>`)}
								</div>`
							: nothing}
					</li>`)}
				</ul>
				${this.collectors.length === 0 ? html`<p class="mt-2 text-xs text-neutral-500">No collector is registered.</p>` : nothing}
			</section>
			${this.isLead
				? html`<section class="rounded-xl border border-neutral-800 p-3">
						<h3 class="font-medium">Register a collector</h3>
						<p class="mt-1 text-xs text-neutral-400">Give its Access service token's Client ID and paste the public key its machine printed. A second lead approves it.</p>
						<form class="mt-2 grid gap-2" @submit=${(e: Event) => {
							e.preventDefault();
							void this.act(`Registering ${d.id}`, async () => {
								await requestCollector(this.call, this.team.signer, { id: d.id.trim(), name: d.name.trim(), commonName: d.commonName.trim(), publicKey: parseKey() });
								this.collectorDraft = { id: "", name: "", commonName: "", key: "" };
								return `${d.name.trim()} is waiting for a second lead`;
							});
						}}>
							<div class="flex gap-2">
								<input class=${input} placeholder="id (edr-drop)" .value=${d.id} @input=${(e: InputEvent) => (this.collectorDraft = { ...d, id: (e.target as HTMLInputElement).value })} data-test="collector-id" />
								<input class="${input} flex-1" placeholder="name" .value=${d.name} @input=${(e: InputEvent) => (this.collectorDraft = { ...d, name: (e.target as HTMLInputElement).value })} data-test="collector-name" />
							</div>
							<input class=${input} placeholder="service token Client ID (…​.access)" .value=${d.commonName} @input=${(e: InputEvent) => (this.collectorDraft = { ...d, commonName: (e.target as HTMLInputElement).value })} data-test="collector-cn" />
							<textarea class="${input} font-mono text-xs" rows="3" placeholder='{"publicKey": {"kty": "EC", …}}' .value=${d.key} @input=${(e: InputEvent) => (this.collectorDraft = { ...d, key: (e.target as HTMLTextAreaElement).value })} data-test="collector-key"></textarea>
							<button class=${primary} ?disabled=${this.busy || !d.id.trim() || !d.commonName.trim() || !d.key.trim()} data-test="collector-request">Ask a second lead</button>
						</form>
					</section>`
				: nothing}
		`;
	}

	// ── Devices (commit 34) ───────────────────────────────────────────

	/**
	 * The member's computers: what holds each one's device secret, when it
	 * was last seen, and Revoke — which deletes the server's wrapped copy of
	 * the root, so that computer never unlocks again whatever its TPM or
	 * keyring hold. Until this tab, a lost laptop could only be revoked
	 * through the API (or `gorani-sync revoke` from another computer).
	 */
	private renderDevices() {
		const live = this.devices.filter((d) => !d.revoked);
		return html`
			<section class="rounded-xl border border-neutral-800 p-3">
				<h3 class="font-medium">Your computers</h3>
				<p class="mt-1 text-xs text-neutral-400">Each holds its own copy of your vault key, released only to it and opened only with a secret it keeps — in its TPM and login keyring where it has them. Revoke one you lost: its copy is deleted, and it never unlocks again. (What protects a computer is its own report, not checked by the server.)</p>
				${live.length === 0 && this.devices.length === 0 ? html`<p class="mt-2 text-xs text-neutral-500">No computer is enrolled. Desktop sync: <code>gorani-sync setup</code>.</p>` : nothing}
				<ul class="mt-2 divide-y divide-neutral-800">
					${this.devices.map((d) => {
						const p = describeProtection(d.protection);
						return html`<li class="flex items-start gap-3 py-2" data-test="device-${d.id}">
							<div class="min-w-0 flex-1">
								<p class="${d.revoked ? "text-neutral-500 line-through" : ""}">${d.name} <span class="text-xs text-neutral-500">${d.platform ?? ""}</span></p>
								<p class="text-xs ${p.weak && !d.revoked ? "text-amber-400" : "text-neutral-400"}" data-test="device-protection-${d.id}">${p.weak && !d.revoked ? "⚠ " : ""}Protected by ${p.text}</p>
								<p class="text-xs text-neutral-500">Enrolled ${d.createdAt.slice(0, 10)} · last seen ${d.lastSeen ? d.lastSeen.slice(0, 16).replace("T", " ") : "never"}</p>
							</div>
							${d.revoked
								? html`<span class="text-xs text-neutral-500" data-test="device-revoked-${d.id}">revoked</span>`
								: html`<button class=${button} ?disabled=${this.busy} data-test="device-revoke-${d.id}" @click=${() => window.confirm(`Revoke “${d.name}”? Its copy of your vault key is deleted and it can never unlock again. Files already downloaded on it stay on it.`) && this.act(`Revoking ${d.name}`, async () => {
										await this.call("DELETE", `/api/v1/members/${this.team.memberId}/devices/${d.id}`);
										return `${d.name} is revoked — it can never unlock again`;
									})}>Revoke</button>`}
						</li>`;
					})}
				</ul>
			</section>
		`;
	}

	// ── Members (commit 39l) ──────────────────────────────────────────
	//
	// Who can sign in, as whom, with what role: the registry, managed by a
	// lead from here. Until 39l only an API call could add or change a
	// member — a team's first lead had no way to bring in the second.
	// Every rule stays the registry's (family.rs): leads only, the last lead
	// stays a lead, externals expire, an address belongs to one member, a
	// lead cannot sign themselves out by editing their own address away.
	// This screen shows the registry's refusals verbatim, like every other.

	@state() private memberDraft: { id: string; name: string; role: TeamRole; emails: string; expires: string } = { id: "", name: "", role: "analyst", emails: "", expires: "" };
	@state() private editing: string | null = null;
	@state() private editDraft: { name: string; role: TeamRole; emails: string; expires: string } = { name: "", role: "analyst", emails: "", expires: "" };

	private renderMembers() {
		if (!this.members.length) return nothing;
		const now = new Date().toISOString();
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="members">
				<h3 class="font-medium">Members</h3>
				<p class="mt-1 text-xs text-neutral-400">${this.isLead
					? "Who can sign in, and as whom: each address is one Cloudflare Access verifies. Access must also let the address in — its policy is set in Cloudflare, not here."
					: "Who is on the team. Leads add and change members."}</p>
				<ul class="mt-2 divide-y divide-neutral-800">
					${this.members.map((m) => (this.editing === m.id ? this.memberEditor(m) : this.memberRow(m, now)))}
				</ul>
				${this.isLead ? this.memberAdder() : nothing}
			</section>
		`;
	}

	private memberRow(m: Member, now: string) {
		const expired = !!m.expiresAt && m.expiresAt <= now;
		const me = m.id === this.team.memberId;
		return html`<li class="flex flex-wrap items-center gap-2 py-2" data-test="member-${m.id}">
			<div class="min-w-0 flex-1">
				<p class=${m.active ? "" : "text-neutral-500 line-through"}>${m.name} <span class="text-xs text-neutral-500">${m.id}${me ? " · you" : ""}</span></p>
				<p class="text-xs text-neutral-400" data-test="member-detail-${m.id}">${ROLE_LABEL[m.role]} · ${m.emails.join(", ") || "no sign-in address"}${m.expiresAt
					? html` · <span class=${expired ? "text-amber-400" : ""}>${expired ? "expired" : "until"} ${m.expiresAt.slice(0, 10)}</span>`
					: nothing}${m.active ? nothing : " · deactivated"}</p>
			</div>
			${this.isLead && m.active
				? html`<button class=${button} ?disabled=${this.busy} data-test="member-edit-${m.id}" @click=${() => {
							this.editing = m.id;
							this.editDraft = { name: m.name, role: m.role, emails: m.emails.join(", "), expires: dayOf(m.expiresAt) };
						}}>Edit</button>
						<button class=${button} ?disabled=${this.busy} data-test="member-deactivate-${m.id}" @click=${() => this.deactivateMember(m)}>Deactivate</button>`
				: nothing}
		</li>`;
	}

	/** The fields both forms share: role, addresses, and — for an external — the last day. */
	private memberFields(d: { role: TeamRole; emails: string; expires: string }, set: (patch: Partial<{ role: TeamRole; emails: string; expires: string }>) => void, prefix: string) {
		return html`
			<label class="text-xs text-neutral-400">Role
				<select class="${input} mt-1 block" name="${prefix}-role" .value=${d.role} @change=${(e: Event) => set({ role: (e.target as HTMLSelectElement).value as TeamRole })}>
					${(Object.keys(ROLE_LABEL) as TeamRole[]).map((r) => html`<option value=${r} ?selected=${d.role === r}>${ROLE_LABEL[r]}</option>`)}
				</select>
			</label>
			<label class="text-xs text-neutral-400">Sign-in addresses
				<input class="${input} mt-1 block w-64" name="${prefix}-emails" placeholder="name@example.org" .value=${d.emails} @input=${(e: Event) => set({ emails: (e.target as HTMLInputElement).value })} />
			</label>
			${d.role === "external"
				? html`<label class="text-xs text-neutral-400">Access ends after
						<input class="${input} mt-1 block" type="date" name="${prefix}-expires" .value=${d.expires} @input=${(e: Event) => set({ expires: (e.target as HTMLInputElement).value })} />
					</label>`
				: nothing}
		`;
	}

	private memberEditor(m: Member) {
		const d = this.editDraft;
		return html`<li class="py-2" data-test="member-editor-${m.id}">
			<form class="flex flex-wrap items-end gap-2" @submit=${(ev: Event) => {
				ev.preventDefault();
				void this.saveMember(m);
			}}>
				<label class="text-xs text-neutral-400">Name
					<input class="${input} mt-1 block w-40" name="edit-name" .value=${d.name} @input=${(e: Event) => (this.editDraft = { ...this.editDraft, name: (e.target as HTMLInputElement).value })} />
				</label>
				${this.memberFields(d, (patch) => (this.editDraft = { ...this.editDraft, ...patch }), "edit")}
				<button class=${primary} ?disabled=${this.busy} type="submit">Save</button>
				<button class=${button} type="button" @click=${() => (this.editing = null)}>Cancel</button>
			</form>
		</li>`;
	}

	private memberAdder() {
		const d = this.memberDraft;
		const set = (patch: Partial<typeof d>) => (this.memberDraft = { ...this.memberDraft, ...patch });
		return html`<form class="mt-3 flex flex-wrap items-end gap-2 border-t border-neutral-800 pt-3" data-test="member-add" @submit=${(ev: Event) => {
			ev.preventDefault();
			void this.addMember();
		}}>
			<label class="text-xs text-neutral-400">Member id
				<input class="${input} mt-1 block w-32" name="new-member-id" placeholder="bo" .value=${d.id} @input=${(e: Event) => set({ id: (e.target as HTMLInputElement).value })} />
			</label>
			<label class="text-xs text-neutral-400">Name
				<input class="${input} mt-1 block w-40" name="new-member-name" .value=${d.name} @input=${(e: Event) => set({ name: (e.target as HTMLInputElement).value })} />
			</label>
			${this.memberFields(d, set, "new-member")}
			<button class=${primary} ?disabled=${this.busy} type="submit">Add member</button>
		</form>`;
	}

	private addMember(): Promise<void> {
		const d = this.memberDraft;
		const id = d.id.trim();
		const emails = splitEmails(d.emails);
		return this.act(`Adding ${id || "a member"}`, async () => {
			// The registry decides; this only spares a round trip for the
			// two mistakes a person makes most (its own words, too).
			if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])$/.test(id)) throw new Error("Member id: 2–32 characters of a–z, 0–9 and dashes (not at either end)");
			if (!emails.length) throw new Error("At least one sign-in address — the email Cloudflare Access verifies");
			const name = d.name.trim() || id;
			await this.call("POST", "/api/v1/family/members", { id, name, role: d.role, emails, ...(d.role === "external" ? { expiresAt: d.expires } : {}) });
			this.memberDraft = { id: "", name: "", role: "analyst", emails: "", expires: "" };
			return `${name} is a member. They sign in at ${location.origin} as ${emails[0]} (Cloudflare Access must let that address in) and set up their vault there; then compare their fingerprint with them and certify it below.`;
		});
	}

	private saveMember(m: Member): Promise<void> {
		const d = this.editDraft;
		const body: Record<string, unknown> = {};
		const emails = splitEmails(d.emails);
		if (d.name.trim() !== m.name) body.name = d.name;
		if (emails.join(",") !== m.emails.join(",")) body.emails = emails;
		if (d.role !== m.role) body.role = d.role;
		if (d.role === "external" && (d.role !== m.role || d.expires !== dayOf(m.expiresAt))) body.expiresAt = d.expires;
		return this.act(`Saving ${m.name}`, async () => {
			if (!Object.keys(body).length) {
				this.editing = null;
				return "Nothing changed";
			}
			await this.call("PATCH", `/api/v1/family/members/${m.id}`, body);
			this.editing = null;
			return body.emails ? `${m.name} now signs in as ${emails.join(", ")} (Cloudflare Access must let that address in).` : `${m.name}: saved`;
		});
	}

	private deactivateMember(m: Member): void {
		const me = m.id === this.team.memberId;
		// Final (family.rs › deactivate): the dialog says so, and what stays.
		const why = me
			? "Deactivate your own account? You can no longer sign in, and deactivation is final: coming back means a new account with another address."
			: `Deactivate ${m.name}? They can no longer sign in, and deactivation is final: their address stays with this account (the audit names people by it). Copies of case keys they were granted stay with them until each such case is rotated — those cases will say "rotation required".`;
		if (!window.confirm(why)) return;
		void this.act(`Deactivating ${m.name}`, async () => {
			await this.call("POST", `/api/v1/family/members/${m.id}/deactivate`);
			return `${m.name} is deactivated: they can no longer sign in.`;
		});
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
			${this.renderMembers()}
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

	// ── Status (commit 39u) ───────────────────────────────────────────

	/**
	 * The cheap checks of `GET /status`, timed from here: no write, so it
	 * runs whenever the tab opens. A failure of the request itself is the
	 * first line of the answer — the app (or the network to it) is down.
	 */
	private async checkStatus(): Promise<void> {
		const started = performance.now();
		try {
			const status = await this.call<SystemStatus>("GET", "/api/v1/status");
			this.systemStatus = { at: new Date(), ms: Math.round(performance.now() - started), status, error: "" };
		} catch (e) {
			this.systemStatus = { at: new Date(), ms: Math.round(performance.now() - started), status: null, error: e instanceof Error ? e.message : String(e) };
		}
	}

	/**
	 * Team › Status: is the system up, and can I upload and download?
	 * Asked for in those words — so the answer leads with them: one row per
	 * part (the app, the team registry, this member's files, the storage,
	 * the timestamp authority), then uploads and downloads as the storage
	 * round trip found them. That round trip writes an object, so it waits
	 * for Test connection.
	 */
	private renderStatus() {
		const s = this.systemStatus;
		const c = this.storageCheck;
		const stepOf = (name: string) => c?.steps.find((x) => x.step === name);
		const row = (test: string, label: string, ok: boolean | null, detail: string) => html`<li class="flex items-baseline gap-2 py-1.5" data-test=${test} data-ok=${ok === null ? "unknown" : String(ok)}>
			<span class="w-4 ${ok === null ? "text-neutral-500" : ok ? "text-emerald-400" : "text-red-400"}">${ok === null ? "–" : ok ? "✓" : "✗"}</span>
			<span class="w-40 text-neutral-200">${label}</span>
			<span class="text-xs text-neutral-400">${detail}</span>
		</li>`;
		const st = s?.status;
		const backend = st?.storage.backend === "r2" ? "Cloudflare R2" : "S3-compatible storage";
		const write = stepOf("write");
		const read = stepOf("read");
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="status">
				<div class="flex items-center gap-2">
					<h3 class="font-medium">System status</h3>
					<span class="text-xs text-neutral-500">${s ? `checked ${s.at.toLocaleTimeString()}` : "checking…"}</span>
					<button class="${button} ml-auto" ?disabled=${this.busy} data-test="status-refresh" @click=${() => void this.checkStatus()}>Refresh</button>
				</div>
				<ul class="mt-2 divide-y divide-neutral-900 text-sm">
					${s
						? st
							? html`
									${row("status-app", "App", true, `answered in ${s.ms} ms · version ${st.version}`)}
									${row("status-registry", "Team registry", st.registry.ok, `its database answered in ${st.registry.ms} ms`)}
									${st.files ? row("status-files", "Your files", st.files.ok, st.files.ok ? `its database answered in ${st.files.ms} ms` : (st.files.problem ?? "not answering")) : nothing}
									${row("status-storage", "Storage", st.storage.configured ? (c ? c.ok : null) : false, !st.storage.configured ? "not configured — uploads and downloads cannot work (a lead sets it up: docs/PRODUCTION.md)" : c ? `${backend} — ${c.ok ? "working" : "not working"}` : `${backend} — not tested yet: Test connection writes, reads and deletes a small object`)}
									${row("status-uploads", "Uploads", c ? (write?.ok ?? false) : null, c ? (write?.ok ? `a write took ${write.ms ?? "?"} ms` : (write?.reason ?? c.problem ?? "the storage was not reached")) : "found by Test connection")}
									${row("status-downloads", "Downloads", c ? (read?.ok ?? false) : null, c ? (read?.ok ? `a read took ${read.ms ?? "?"} ms` : (read?.reason ?? (write && !write.ok ? "not tried: the write failed first" : (c.problem ?? "the storage was not reached")))) : "found by Test connection")}
									${row("status-timestamps", "Timestamp authority", st.timestamps.configured ? true : null, st.timestamps.configured ? "configured: evidence is stamped by a third party" : "not configured: evidence is dated by the audit trail alone")}
									${st.drm ? row("status-drm", "Protected videos", st.drm.copies && st.drm.playable ? true : null, !st.drm.copies ? "off: DRM_KEY_SECRET is not set (docs/DRM.md)" : st.drm.playable ? "copies can be made and play in Safari (FairPlay)" : `copies can be made; ${st.drm.problem ?? "FairPlay is not set up"}`) : nothing}
								`
							: row("status-app", "App", false, `not answering (${s.error}) — check your connection, then Refresh`)
						: html`<li class="py-1.5 text-xs text-neutral-500">Checking…</li>`}
				</ul>
			</section>
			${this.renderStorage()}
		`;
	}

	/**
	 * The deployment's object storage (commit 39s, s3.rs › probe): write,
	 * size, read and delete a 16-byte probe object, each answer explained
	 * and timed. Since 39u any member runs it, from Team › Status; a lead
	 * also sees the five settings as the Worker holds them (the access key's
	 * last four characters, the secret's length, never the secret). Built
	 * after the first production upload failed with "HTTP 403" and nothing
	 * to say why.
	 */
	private renderStorage() {
		const c = this.storageCheck;
		return html`
			<section class="rounded-xl border border-neutral-800 p-3" data-test="storage">
				<div class="flex items-center gap-2">
					<h3 class="font-medium">Storage connection</h3>
					<button class="${button} ml-auto" ?disabled=${this.busy} data-test="storage-check" @click=${() => this.act("Testing the storage connection", async () => {
						this.storageCheck = await this.call<StorageCheck>("POST", "/api/v1/status/storage");
						return this.storageCheck.ok ? "The storage took a write, a read and a delete: uploads and downloads work." : "The storage refused a step — see below.";
					})}>Test connection</button>
				</div>
				<p class="mt-1 text-xs text-neutral-400">Writes a 16-byte probe object, reads it back and deletes it — the steps every upload and download takes.${this.isLead ? " As a lead you also see the storage settings." : ""}</p>
				${c
					? html`
							<p class="mt-2 text-xs ${c.ok ? "text-emerald-400" : "text-red-300"}" data-test="storage-verdict">${c.backend === "r2" ? "R2 binding" : "S3-compatible endpoint"} — ${c.ok ? "working" : "not working"}</p>
							<ul class="mt-1 space-y-1 text-xs">
								${c.problem ? html`<li class="text-red-300">${c.problem}</li>` : nothing}
								${c.steps.map((st) => html`<li data-test="storage-step" data-step=${st.step} data-ok=${String(st.ok)}>
									<span class=${st.ok ? "text-emerald-400" : "text-red-400"}>${st.ok ? "✓" : "✗"}</span>
									<span class="text-neutral-300">${STEP_LABEL[st.step] ?? st.step}</span>
									${st.status ? html`<span class="text-neutral-500">HTTP ${st.status}${st.server ? ` · ${st.server}` : ""}</span>` : nothing}
									${st.ms !== undefined ? html`<span class="text-neutral-500">${st.ms} ms</span>` : nothing}
									${st.reason ? html`<p class="ml-4 text-neutral-400">${st.reason}</p>` : nothing}
								</li>`)}
							</ul>
							${c.warnings?.length ? html`<ul class="mt-2 space-y-1 text-xs text-amber-300" data-test="storage-warnings">${c.warnings.map((w) => html`<li>⚠ ${w}</li>`)}</ul>` : nothing}
							${c.settings
								? html`<table class="mt-2 text-xs" data-test="storage-settings">
										${c.settings.map((v) => html`<tr>
											<td class="pr-3 font-mono text-neutral-400">${v.name}</td>
											<td class=${v.set ? "text-neutral-200" : "text-red-300"}>${v.set ? v.shown : "not set"}${v.padded ? html` <span class="text-amber-300">— stored with spaces or a line end around it; set it again without</span>` : nothing}</td>
										</tr>`)}
									</table>`
								: nothing}
						`
					: nothing}
			</section>
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
				${c.grant ? this.inboxRow(c, manage) : nothing}
				${this.twoPerson(c, manage)}
			</section>
		`;
	}

	/**
	 * The case's inbox key (commit 37b, docs/COLLECTORS.md): what collectors
	 * seal to. A manager makes it here — a fresh pair whose public halves
	 * they sign and whose private half is sealed under the case key; a new
	 * one retires the old (items sealed to it still open).
	 */
	private inboxRow(c: CaseRow, manage: boolean) {
		const current = (c.inboxKeys ?? []).find((k) => !k.retiredAt);
		return html`<div class="mt-2 flex flex-wrap items-center gap-2 text-xs" data-test="inbox-${c.id}">
			<span class="text-neutral-400">Inbox:</span>
			${current
				? html`<span>key <code>${current.keyId.slice(0, 12)}</code> made by ${this.nameOf(current.signedBy)} · ${current.createdAt.slice(0, 10)}${(c.inboxKeys?.length ?? 0) > 1 ? ` · ${c.inboxKeys!.length - 1} retired` : ""}</span>`
				: html`<span class="text-neutral-500">no key — collectors cannot drop into this case yet</span>`}
			${current || (c.inboxKeys?.length ?? 0) > 0
				? html`<button class=${button} ?disabled=${this.busy} data-test="inbox-show-${c.id}" @click=${() => this.act(`Opening ${c.id}'s inbox`, async () => {
						if (this.inboxes[c.id]) {
							const { [c.id]: _, ...rest } = this.inboxes;
							this.inboxes = rest;
							return "";
						}
						await this.loadInbox(c);
						return "";
					})}>${this.inboxes[c.id] ? "Hide the inbox" : "Inbox"}</button>`
				: nothing}
			${manage && !c.closed && !c.rotating
				? html`<button class=${button} ?disabled=${this.busy} data-test="inbox-key-${c.id}" @click=${() => this.act(`Making ${c.id}'s inbox key`, async () => {
						await createInboxKey(this.call, await this.caseKey(c), c.id, this.team.signer);
						return `${c.id} has a new inbox key, signed by you. Collectors that pinned you (or a lead who certified you) seal to it from their next drop.`;
					})}>${current ? "New inbox key" : "Make the inbox key"}</button>`
				: nothing}
		</div>
		${this.inboxes[c.id] ? this.inboxList(c) : nothing}`;
	}

	/** Open every item of a case's inbox — and say, per item, whether THIS member believes it. */
	private async loadInbox(c: CaseRow): Promise<void> {
		const key = await this.caseKey(c);
		const keys = await openInboxKeys(key, c.id, c.inboxKeys ?? []);
		const { items } = await this.call<{ items: InboxItem[] }>("GET", `/api/v1/cases/${c.id}/inbox`);
		this.inboxes = {
			...this.inboxes,
			[c.id]: await Promise.all(
				items.map(async (item) => {
					try {
						return { item, opened: await openInboxItem(keys, c.id, item, this.team.trust, this.collectors), error: null };
					} catch (e) {
						return { item, opened: null, error: e instanceof Error ? e.message : String(e) };
					}
				}),
			),
		};
	}

	/**
	 * The inbox, item by item: what the collector says it is, and whether it
	 * verifies for this member. Accepting re-reads the bytes and checks their
	 * SHA-256 before anything is signed; only a verified item can be accepted.
	 */
	private inboxList(c: CaseRow) {
		const rows = this.inboxes[c.id] ?? [];
		const write = c.grant?.permission === "write" || c.grant?.permission === "manage";
		return html`<ul class="mt-2 space-y-1 text-xs" data-test="inbox-list-${c.id}">
			${rows.length === 0 ? html`<li class="text-neutral-500">Nothing has been dropped here.</li>` : nothing}
			${rows.map(({ item, opened, error }) => html`<li class="flex flex-wrap items-center gap-2 rounded-lg bg-neutral-900 px-2 py-1" data-test="inbox-item-${item.id}">
				<span class="font-medium">${opened?.meta.name ?? item.id}</span>
				<span class="text-neutral-400">${item.size} bytes · from ${item.collector} · ${item.receivedAt.slice(0, 16).replace("T", " ")}</span>
				${opened?.kind === "collector" ? html`<span class="text-neutral-400">${opened.meta.source} · ${opened.meta.method}</span>` : nothing}
				${opened?.kind === "request" ? html`<span class="text-neutral-400">sent by “${opened.meta.sender || "unnamed"}” through an upload link${opened.meta.message ? ` — “${opened.meta.message}”` : ""}</span>` : nothing}
				<span class=${opened && !opened.problem ? (opened.kind === "request" ? "text-amber-300" : "text-emerald-400") : "text-amber-400"} data-test="inbox-verdict-${item.id}">${error ? `⚠ does not open: ${error}` : opened?.problem ? `⚠ unverified: ${opened.problem}` : opened?.kind === "request" ? "an outsider's upload — unsigned; accepted as a malware sample" : "✓ signed by its collector"}</span>
				<span class="text-neutral-500">${item.status}${item.accepted ? ` → file ${item.accepted.file}` : ""}</span>
				${write && item.status === "waiting" && !c.closed
					? html`<button class=${primary} ?disabled=${this.busy || !opened || !!opened.problem} title=${opened?.problem ?? ""} data-test="inbox-accept-${item.id}" @click=${() => this.act(`Accepting ${opened!.meta.name}`, async () => {
								const r = await fetch(`/api/v1/cases/${c.id}/inbox/${item.id}`, { headers: { ...devIdentityHeaders(), "x-gorani-client": "web-inbox" } });
								if (!r.ok || !r.body) throw new Error(`download failed: ${r.status}`);
								const content = await hashInboxContent(opened!, item, r.body);
								const caseKey = await this.caseKey(c);
								const keys = await openInboxKeys(caseKey, c.id, c.inboxKeys ?? []);
								// An upload link's item goes into the link's folder, its label in the intake (commit 38).
								const link = linkOf(item);
								const row = link ? (await listRequests(this.call, caseArea(c.id))).find((r) => r.id === link) : undefined;
								const linkLabel = row ? await openRequestLabel(caseKey, caseArea(c.id), row).catch(() => undefined) : undefined;
								await acceptInboxItem(this.call, caseKey, keys, c.id, item, opened!, content, this.team.signer, { folderId: row?.folderId ?? undefined, linkLabel });
								await this.loadInbox(c);
								return opened!.kind === "request"
									? `${opened!.meta.name} is in ${c.id} as a malware sample: its bytes matched what the sender declared, and you signed them.`
									: `${opened!.meta.name} is in ${c.id}: its bytes matched what ${item.collector} signed, and you signed them too.`;
							})}>Accept</button>
						<button class=${button} ?disabled=${this.busy} data-test="inbox-reject-${item.id}" @click=${() => {
							const reason = window.prompt(`Why is ${opened?.meta.name ?? item.id} turned away? (sealed — only people on the case read it)`);
							if (reason) void this.act(`Rejecting ${item.id}`, async () => {
								await rejectInboxItem(this.call, await this.caseKey(c), c.id, item.id, reason);
								await this.loadInbox(c);
								return c.kind === "evidence" ? `Rejected. On an evidence case the object stays (write-once); the reason is sealed.` : `Rejected, and its bytes deleted.`;
							});
						}}>Reject</button>`
					: nothing}
			</li>`)}
		</ul>`;
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
									const built = await this.exportCase(c, a.id, `${c.id}-export-${a.id.slice(0, 8)}.zip`);
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

	/**
	 * The export, streamed to disk where the media worker runs (D12, 31d):
	 * the package goes out as it is made — no case is too large for the
	 * tab. Without the worker it is built in memory and saved, as before.
	 */
	private async exportCase(c: CaseRow, approvalId: string, name: string): Promise<{ problems: string[] }> {
		const worker = await controllingMediaWorker(2000);
		if (!worker) {
			const built = await buildExport(this.source(), this.team.signer, this.team.trust, await this.caseKey(c), c.id, approvalId);
			this.save(built.parts, name);
			return built;
		}
		const url = `/media/dl/${Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("")}`;
		const pipe = await pipeToDownload(worker, { url, name, mime: "application/zip" });
		// A navigation the worker answers (not <a download>, which Chromium sends past it).
		const a = document.createElement("a");
		a.href = url;
		a.click();
		try {
			const built = await buildExport(this.source(), this.team.signer, this.team.trust, await this.caseKey(c), c.id, approvalId, { sink: pipe.write });
			await pipe.close();
			return built;
		} catch (e) {
			pipe.fail(e);
			throw e;
		}
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
			// (D12, 31d) Streamed: the export decrypts each version as it arrives.
			objectStream: async (path) => {
				const r = await fetch(path, { headers: { ...devIdentityHeaders(), "x-gorani-client": "web-export" } });
				if (!r.ok || !r.body) throw new Error(`download failed: ${r.status}`);
				return { body: r.body, size: Number(r.headers.get("content-length")), ck: r.headers.get("x-gorani-ck") ?? "", chunk: Number(r.headers.get("x-gorani-chunk")) || null, version: Number(r.headers.get("x-gorani-version")), hash: r.headers.get("x-gorani-hash") };
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
