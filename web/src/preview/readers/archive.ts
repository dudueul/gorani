// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The archive reader (commit 42e, docs/PREVIEWS.md › Archives): what an
 * archive holds, listed in the preview frame — nothing unpacked to disk,
 * nothing run. The parsing is the worker's (archive.worker.ts): ZIP, ALZ
 * and EGG by our own readers; 7z, RAR, TAR and the rest by 7-Zip.
 *
 *   the listing   folders and files, a breadcrumb, a filter over every
 *                 path; each name as written — ".." and all, a
 *                 right-to-left mark shown as [RLO], not obeyed
 *   a password    asked for when entries (or names) are encrypted;
 *                 "infected" — how malware samples are swapped — one click.
 *                 What opens with it is a SAMPLE: saved only as one, never
 *                 opened here
 *   an entry      Open: handed to the app, which shows it in a preview of
 *                 its own (a new frame, its own reader); Save: handed to
 *                 the app, which asks before it writes to the vault
 *
 * The facts (facts/archive.ts) go outside the frame.
 */

import { boot, el, type Host } from "../host.ts";
import { addCss } from "../kit.ts";
import { archiveFacts, isSamplePassword, pathRisk, treeOf, type Node } from "../facts/archive.ts";
import type { Entry, Listing } from "../archive/types.ts";
import archiveCss from "./archive.css?inline";

const fmtSize = (n: number | null) => (n === null ? "" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`);
/** A name as text that cannot reorder the line it is in. */
export const visible = (s: string) => s.replace(/[‪-‮⁦-⁩‎‏]/g, (c) => ({ "‪": "[LRE]", "‫": "[RLE]", "‬": "[PDF]", "‭": "[LRO]", "‮": "[RLO]", "⁦": "[LRI]", "⁧": "[RLI]", "⁨": "[FSI]", "⁩": "[PDI]", "‎": "[LRM]", "‏": "[RLM]" })[c] ?? "").replace(/[\u0000-\u001f\u007f]/g, "�");

interface Got {
	t: string;
	listing?: Listing;
	twoNames?: { central: string; local: string }[];
	links?: Record<number, string>;
	password?: string | null;
	bytes?: ArrayBuffer;
	index?: number;
	kind?: string;
	why?: string;
	message?: string;
}

export const start = boot(async (host) => {
	addCss(archiveCss);
	const worker = host.worker();
	const status = el("p", { class: "notice" }, "Reading the archive…");
	host.root.append(status);
	if (!worker) return host.fail("the archive reader's worker did not start");

	// One question to the worker at a time; the answers come in order.
	let waiting: ((g: Got) => void) | null = null;
	worker.onmessage = async (e: MessageEvent<Got>) => {
		const g = e.data;
		if (g.t === "need-7z") {
			try {
				const [glue, wasm] = await Promise.all([host.asset("7zz.js"), host.asset("7zz.wasm")]);
				const w = wasm.slice().buffer;
				worker.postMessage({ t: "seven", glue: new TextDecoder().decode(glue), wasm: w }, [w]);
			} catch {
				waiting?.({ t: "error", message: "7-Zip could not be loaded" });
			}
			return;
		}
		const w = waiting;
		waiting = null;
		w?.(g);
	};
	worker.onerror = () => waiting?.({ t: "error", message: "the archive reader stopped" });
	const ask = (m: object, transfer: Transferable[] = []) =>
		new Promise<Got>((ok) => {
			waiting = ok;
			worker.postMessage(m, transfer);
		});

	const copy = new Uint8Array(host.file.bytes).slice().buffer;
	let got = await ask({ t: "open", bytes: copy, name: host.file.name }, [copy]);
	if (got.t !== "listing" || !got.listing) {
		status.replaceChildren(el("strong", {}, "This archive could not be read."), el("br"), got.message ?? "It may be damaged, or a kind no reader here knows.");
		status.setAttribute("data-test", "arc-error");
		host.shown([{ level: "warn", text: `Not read as an archive: ${got.message ?? "unknown reason"}` }]);
		return;
	}
	status.remove();
	new ArchiveView(host, got, ask).show();
});

class ArchiveView {
	private listing: Listing;
	private password: string | null;
	private links: Map<number, string>;
	private twoNames: { central: string; local: string }[];
	private at = "";
	private filter = "";
	private bar = el("div", { class: "bar" });
	private crumbs = el("span", { class: "crumbs", "data-test": "arc-path" });
	private count = el("span", { class: "muted", "data-test": "arc-count" });
	private lock = el("div", { class: "lock", hidden: "" });
	private table = el("div", { class: "scroll list", "data-test": "arc-list", role: "grid" });
	private note = el("div", { class: "note", "data-test": "arc-note", role: "status" });
	private busy = false;

	constructor(private host: Host, got: Got, private ask: (m: object, t?: Transferable[]) => Promise<Got>) {
		this.listing = got.listing!;
		this.password = got.password ?? null;
		this.links = new Map(Object.entries(got.links ?? {}).map(([k, v]) => [Number(k), v]));
		this.twoNames = got.twoNames ?? [];
	}

	show(): void {
		const find = el("input", { type: "search", placeholder: "Filter every path", "aria-label": "Filter", "data-test": "arc-filter" });
		find.addEventListener("input", () => {
			this.filter = find.value.trim().toLowerCase();
			this.draw();
		});
		this.bar.append(this.crumbs, el("span", { class: "grow" }), find, this.count);
		this.host.root.append(this.bar, this.lock, this.table, this.note);
		this.facts();
		this.drawLock();
		this.draw();
	}

	private facts(): void {
		this.host.shown(archiveFacts({ name: this.host.file.name, listing: this.listing, password: this.password, links: this.links, twoNames: this.twoNames }));
	}

	private get sample(): boolean {
		return isSamplePassword(this.password);
	}

	private drawLock(): void {
		const l = this.listing;
		const needs = (l.headersEncrypted && !l.entries.length) || l.entries.some((e) => e.encrypted);
		this.lock.hidden = !needs;
		this.lock.replaceChildren();
		if (!needs) return;
		if (this.password !== null) {
			this.lock.append(el("span", { "data-test": "arc-unlocked" }, this.sample ? "🔓 Opened with “infected”: its entries are malware samples — they can be saved as samples, not opened." : "🔓 Opened with the password you gave."));
			this.lock.classList.toggle("sample", this.sample);
			return;
		}
		const input = el("input", { type: "password", placeholder: "Password", "aria-label": "Password", autocomplete: "off", "data-test": "arc-password" });
		const go = el("button", { "data-test": "arc-unlock" }, "Unlock");
		const infected = el("button", { title: "The password malware samples are swapped with", "data-test": "arc-try-infected" }, "Try “infected”");
		const msg = el("span", { class: "muted", "data-test": "arc-password-msg" }, l.headersEncrypted ? "Even its names are encrypted." : "Its entries are encrypted.");
		const tryIt = async (pw: string) => {
			if (!pw || this.busy) return;
			this.busy = true;
			msg.textContent = "Trying…";
			const g = await this.ask({ t: "unlock", password: pw });
			this.busy = false;
			if (g.t === "wrong") {
				msg.textContent = "That password is wrong.";
				input.select();
				return;
			}
			if (g.listing) this.listing = g.listing;
			this.password = pw;
			this.facts();
			this.drawLock();
			this.draw();
		};
		go.addEventListener("click", () => void tryIt(input.value));
		infected.addEventListener("click", () => void tryIt("infected"));
		// (A sandboxed frame without allow-forms never submits a form: Enter is handled here.)
		input.addEventListener("keydown", (e) => {
			if (e.key === "Enter") void tryIt(input.value);
		});
		this.lock.append(el("span", {}, "🔒"), input, go, infected, msg);
	}

	private folder(): Node {
		let n = treeOf(this.listing.entries);
		for (const part of this.at ? this.at.split("/") : []) n = n.children.get(part) ?? n;
		return n;
	}

	private draw(): void {
		const l = this.listing;
		this.crumbs.replaceChildren();
		const parts = this.at ? this.at.split("/") : [];
		const crumb = (label: string, path: string) => {
			const b = el("button", { class: "crumb" }, label);
			b.addEventListener("click", () => {
				this.at = path;
				this.draw();
			});
			return b;
		};
		this.crumbs.append(crumb(visible(this.host.file.name), ""));
		parts.forEach((p, i) => this.crumbs.append(el("span", { class: "muted" }, "›"), crumb(visible(p), parts.slice(0, i + 1).join("/"))));

		let rows: { label: string; node: Node | null; entry: Entry | null }[];
		if (this.filter) {
			rows = l.entries.filter((e) => e.path.toLowerCase().includes(this.filter)).slice(0, 2000).map((e) => ({ label: e.path, node: null, entry: e }));
		} else {
			const here = this.folder();
			rows = [...here.children.values()]
				.sort((a, b) => Number(!!(b.children.size || b.entry?.dir)) - Number(!!(a.children.size || a.entry?.dir)) || a.name.localeCompare(b.name, undefined, { numeric: true }))
				.slice(0, 5000)
				.map((n) => ({ label: n.name, node: n, entry: n.entry }));
		}
		this.count.textContent = this.filter ? `${rows.length} found` : `${l.entries.filter((e) => !e.dir).length} files`;
		const head = el("div", { class: "row head", role: "row" }, ...["Name", "Size", "Packed", "Modified", "Method", ""].map((h) => el("span", { role: "columnheader" }, h)));
		const out: HTMLElement[] = [head];
		if (!rows.length) out.push(el("p", { class: "muted empty" }, l.headersEncrypted && !l.entries.length ? "The names are encrypted: give the password above." : "Nothing here."));
		for (const r of rows) out.push(this.row(r.label, r.node, r.entry));
		this.table.replaceChildren(...out);
	}

	private row(label: string, node: Node | null, e: Entry | null): HTMLElement {
		const isFolder = !!node && (node.children.size > 0 || !!e?.dir);
		const risk = e ? pathRisk(e.path) : null;
		const flags = [e?.encrypted ? "🔒" : "", e?.link !== null && e?.link !== undefined ? `↪ ${visible(this.links.get(e.index) ?? "link")}` : "", risk === "traversal" ? "⚠ climbs out" : risk === "absolute" ? "⚠ absolute" : "", /[‪-‮⁦-⁩]/.test(label) ? "⚠ [RLO]" : ""].filter(Boolean).join(" ");
		const name = el("span", { class: "name" }, el("span", { class: "icon" }, isFolder ? "📁" : "📄"), el("span", { class: "label" }, visible(label)));
		const cells = [name, el("span", { class: "num" }, isFolder ? "" : fmtSize(e?.size ?? null)), el("span", { class: "num muted" }, isFolder ? "" : fmtSize(e?.packed ?? null)), el("span", { class: "muted" }, e?.modified ?? ""), el("span", { class: "muted" }, e?.method ?? ""), el("span", { class: "flags" }, flags)];
		const row = el("div", { class: `row${isFolder ? " folder" : ""}`, role: "row", "data-test": "arc-row", "data-path": e?.path ?? node?.path ?? label, tabindex: "0" }, ...cells);
		if (isFolder && node) {
			const open = () => {
				this.at = node.path;
				this.filter = "";
				(this.bar.querySelector("input") as HTMLInputElement).value = "";
				this.draw();
			};
			row.addEventListener("click", open);
			row.addEventListener("keydown", (ev) => ev.key === "Enter" && open());
			return row;
		}
		if (!e) return row;
		const acts = el("span", { class: "acts" });
		if (!this.sample) {
			const o = el("button", { "data-test": "arc-open", title: "Open it in a preview of its own" }, "Open");
			o.addEventListener("click", (ev) => (ev.stopPropagation(), void this.take(e, "open")));
			acts.append(o);
			row.addEventListener("dblclick", () => void this.take(e, "open"));
			row.addEventListener("keydown", (ev) => ev.key === "Enter" && void this.take(e, "open"));
		}
		if (this.sample) {
			// A sample is never opened — but it may be INSPECTED (42g): its
			// bytes, strings and headers in the hex reader, after the app has
			// put the inspection in the audit trail.
			const i = el("button", { "data-test": "arc-inspect", title: "Its bytes, strings and program headers, in a hex view of its own — recorded in the audit trail" }, "Inspect");
			i.addEventListener("click", (ev) => (ev.stopPropagation(), void this.take(e, "inspect")));
			acts.append(i);
		}
		const s = el("button", { "data-test": "arc-save", title: this.sample ? "Save it into the vault as a malware sample" : "Save it into the vault (you are asked first)" }, this.sample ? "Save as sample" : "Save");
		s.addEventListener("click", (ev) => (ev.stopPropagation(), void this.take(e, "save")));
		acts.append(s);
		cells[5]!.prepend(acts);
		return row;
	}

	private async take(e: Entry, action: "open" | "save" | "inspect"): Promise<void> {
		if (this.busy) return;
		if (e.encrypted && this.password === null) {
			this.say("It is encrypted: give the password above first.");
			(this.lock.querySelector("input") as HTMLInputElement | null)?.focus();
			return;
		}
		this.busy = true;
		this.say(`Unpacking ${visible(e.path)}…`);
		const g = await this.ask({ t: "extract", index: e.index });
		this.busy = false;
		if (g.t !== "entry" || !g.bytes) {
			this.say(`Not ${action === "open" ? "opened" : action === "inspect" ? "inspected" : "saved"}: ${g.why ?? g.message ?? "it could not be unpacked"}.`, true);
			if (g.kind === "password") {
				this.password = null;
				this.drawLock();
			}
			return;
		}
		const file = { name: e.path.split(/[\\/]/).pop() || "entry", mime: null, bytes: new Uint8Array(g.bytes) };
		// What came out with "infected" is a sample: the app is told, and
		// saves it only as one — or shows its bytes, and nothing else.
		this.host.handOver(action === "inspect" ? "inspect" : this.sample ? "save" : action, file, { sample: this.sample });
		this.say(action === "inspect" ? `Asked to inspect ${visible(e.path)} (bytes only).` : action === "open" && !this.sample ? `Opened ${visible(e.path)}.` : `Asked to save ${visible(e.path)}${this.sample ? " as a malware sample" : ""}.`);
	}

	private say(text: string, warn = false): void {
		this.note.textContent = text;
		this.note.classList.toggle("warn", warn);
	}
}
