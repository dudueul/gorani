// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The hex reader's Registry tab (commit 42k, docs/PREVIEWS.md › Forensic
 * formats): a registry hive as regedit would show it — offline, inside the
 * frame, with the keys that matter marked.
 *
 *   the tree      keys, opened as you go (a hive of 200,000 keys is read
 *                 only where you look); a key a finding names is marked ⚠,
 *                 and each key on the way to one •
 *   the values    name, type and data of the chosen key, its last write;
 *                 a value's whole data (text and hex), its bytes in Hex
 *   Go to key     a path, with or without HKLM\SOFTWARE in front of it
 *   Places        the findings above the preview, each a click from its key
 *   Deleted       keys still in the hive's free space, by name and time
 *
 * Every name and value reaches the page through textContent, with
 * controls and direction marks made visible (a name can be chosen to
 * mislead).
 */

import { el } from "../host.ts";
import { addCss } from "../kit.ts";
import { BIN, type Hive, type RegKey, type RegValue } from "../forensic/regf.ts";
import { MOUNT, type HiveFindings } from "../facts/regf.ts";
import { shown } from "../facts/evtx.ts";
import registryCss from "./hex-registry.css?inline";

/** Children shown under one key, at most (CLSID holds thousands: Go to key reaches the rest). */
const MAX_CHILDREN = 2000;

export class RegistryPane {
	readonly pane: HTMLElement;
	private readonly hive: Hive;
	private readonly found: HiveFindings;
	private readonly toHex: (offset: number, len: number) => void;
	/** Lower-cased paths: of a place, and of every key on the way to one. */
	private readonly marked = new Map<string, string>();
	private readonly onWay = new Set<string>();
	private readonly tree = el("div", { class: "rtree", role: "tree", "aria-label": "Keys", "data-test": "hex-reg-tree" });
	private readonly right = el("div", { class: "rright" });
	private readonly status = el("span", { class: "muted", "data-test": "hex-reg-status" });
	/** The rendered tree's rows, by lower-cased path, for Go to key. */
	private readonly rows = new Map<string, { row: HTMLElement; kids: HTMLElement; key: RegKey; open: boolean }>();
	private selected: string | null = null;

	constructor(hive: Hive, found: HiveFindings, toHex: (offset: number, len: number) => void) {
		addCss(registryCss);
		this.hive = hive;
		this.found = found;
		this.toHex = toHex;
		for (const p of found.places) {
			const lc = p.path.toLowerCase();
			if (!this.marked.has(lc)) this.marked.set(lc, p.why);
			const parts = lc.split("\\");
			for (let i = 1; i < parts.length; i++) this.onWay.add(parts.slice(0, i).join("\\"));
		}
		const goto = el("input", { type: "text", placeholder: "Go to key (Microsoft\\Windows\\CurrentVersion\\Run)", "aria-label": "Go to key", "data-test": "hex-reg-goto", spellcheck: "false" });
		goto.addEventListener("keydown", (e) => {
			if (e.key !== "Enter") return;
			const path = this.normalize(goto.value);
			if (!this.reveal(path)) this.say(`No key ${goto.value.trim()} in this hive.`);
		});
		const places = el("select", { "aria-label": "Places", "data-test": "hex-reg-places" }, el("option", { value: "" }, found.places.length ? `Places (${found.places.length})` : "No places marked"));
		for (const [i, p] of found.places.entries()) places.append(el("option", { value: String(i) }, `${p.level === "warn" ? "⚠ " : ""}${shown(p.why).slice(0, 110)}`));
		places.disabled = !found.places.length;
		places.addEventListener("change", () => {
			const p = found.places[Number(places.value)];
			if (p) this.reveal(p.path.toLowerCase());
			places.value = "";
		});
		const deleted = hive.deleted();
		const del = el("button", { "data-test": "hex-reg-deleted" }, `Deleted keys (${deleted.length})`);
		del.disabled = !deleted.length;
		del.addEventListener("click", () => this.showDeleted(deleted));
		const tools = el("div", { class: "bar tools rtools" }, goto, places, del, el("span", { class: "grow" }), this.status);
		this.pane = el("div", { class: "pane rpane", "data-test": "hex-reg-pane" }, tools, el("div", { class: "rbody" }, this.tree, this.right));
		// The root's own children, open from the start.
		const rootKids = el("div", { role: "group" });
		this.tree.append(rootKids);
		this.fill(rootKids, hive.root, "", 0);
		this.say(`${MOUNT[found.kind] || "The hive"} · root “${shown(hive.root.name)}” · ${hive.root.subkeyCount.toLocaleString("en")} keys at the top`);
		this.right.append(el("p", { class: "muted" }, found.places.length ? "Choose a key, or one of the Places." : "Choose a key."));
	}

	/** A typed path, as a path from the root: without HKLM\SOFTWARE, HKCU or the root's own name. */
	private normalize(p: string): string {
		let s = p.trim().replace(/^\\+|\\+$/g, "").replace(/\\+/g, "\\").toLowerCase();
		const mount = MOUNT[this.found.kind].toLowerCase();
		for (const pre of [mount, "hkey_local_machine\\" + mount.replace(/^hklm\\/, ""), "hkey_current_user", "computer\\" + mount, this.hive.root.name.toLowerCase()]) {
			if (pre && (s === pre || s.startsWith(`${pre}\\`))) s = s.slice(pre.length).replace(/^\\/, "");
		}
		return s;
	}

	private fill(into: HTMLElement, parent: RegKey, path: string, depth: number): void {
		const kids = this.hive.subkeys(parent);
		for (const k of kids.slice(0, MAX_CHILDREN)) {
			const p = path ? `${path}\\${k.name}` : k.name;
			const lc = p.toLowerCase();
			const why = this.marked.get(lc);
			const toggle = el("span", { class: "rtoggle", "aria-hidden": "true" }, k.subkeyCount ? "▸" : "");
			const row = el(
				"div",
				{ class: `rrow${why ? " warn" : ""}`, role: "treeitem", tabindex: "-1", ...(k.subkeyCount ? { "aria-expanded": "false" } : {}), "data-path": p, ...(why ? { title: shown(why) } : {}) },
				toggle,
				el("span", { class: "rmark" }, why ? "⚠" : this.onWay.has(lc) ? "•" : ""),
				el("span", { class: "rname" }, shown(k.name) || "(no name)"),
				...(k.subkeyCount ? [el("span", { class: "muted rcount" }, k.subkeyCount.toLocaleString("en"))] : []),
			);
			row.style.paddingLeft = `${8 + depth * 14}px`;
			const box = el("div", { role: "group" });
			box.hidden = true;
			const entry = { row, kids: box, key: k, open: false };
			this.rows.set(lc, entry);
			row.addEventListener("click", (e) => {
				const onToggle = (e.target as HTMLElement).closest(".rtoggle");
				if (onToggle || entry.key.subkeyCount === 0 || this.selected === lc) this.toggle(entry, p, depth);
				this.select(entry.key, p);
			});
			row.addEventListener("keydown", (e) => this.key(e, entry, p, depth));
			into.append(row, box);
		}
		if (kids.length > MAX_CHILDREN) into.append(el("div", { class: "muted rmore" }, `…and ${(kids.length - MAX_CHILDREN).toLocaleString("en")} more keys — Go to key reaches them`));
	}

	private toggle(entry: { row: HTMLElement; kids: HTMLElement; key: RegKey; open: boolean }, path: string, depth: number, open = !entry.open): void {
		if (!entry.key.subkeyCount) return;
		if (open && !entry.kids.childElementCount) this.fill(entry.kids, entry.key, path, depth + 1);
		entry.open = open;
		entry.kids.hidden = !open;
		entry.row.setAttribute("aria-expanded", String(open));
		entry.row.querySelector(".rtoggle")!.textContent = open ? "▾" : "▸";
	}

	/** Keyboard: up and down through the rows shown, right to open, left to close. */
	private key(e: KeyboardEvent, entry: { row: HTMLElement; kids: HTMLElement; key: RegKey; open: boolean }, path: string, depth: number): void {
		const visible = [...this.tree.querySelectorAll<HTMLElement>(".rrow")].filter((r) => r.offsetParent !== null);
		const i = visible.indexOf(entry.row);
		const go = (r: HTMLElement | undefined) => r && (r.focus(), r.click());
		if (e.key === "ArrowDown") go(visible[i + 1]);
		else if (e.key === "ArrowUp") go(visible[i - 1]);
		else if (e.key === "ArrowRight") this.toggle(entry, path, depth, true);
		else if (e.key === "ArrowLeft") this.toggle(entry, path, depth, false);
		else return;
		e.preventDefault();
	}

	/** Open the tree down to a key and choose it. */
	private reveal(lcPath: string): boolean {
		if (!lcPath) return false;
		const parts = lcPath.split("\\");
		for (let i = 1; i <= parts.length; i++) {
			const p = parts.slice(0, i).join("\\");
			let entry = this.rows.get(p);
			if (!entry) {
				// Past what the tree shows (a key beyond MAX_CHILDREN): straight to it.
				const k = this.hive.path(lcPath);
				if (!k) return false;
				this.select(k, lcPath);
				return true;
			}
			if (i < parts.length) this.toggle(entry, p, i - 1, true);
			else {
				entry.row.scrollIntoView({ block: "center" });
				entry.row.focus();
				this.select(entry.key, entry.row.getAttribute("data-path") ?? p);
			}
		}
		return true;
	}

	private select(k: RegKey, path: string): void {
		const lc = path.toLowerCase();
		if (this.selected) this.rows.get(this.selected)?.row.classList.remove("sel");
		this.selected = lc;
		this.rows.get(lc)?.row.classList.add("sel");
		const why = this.marked.get(lc);
		const values = this.hive.values(k);
		const table = el("table", { class: "grid rvalues", "data-test": "hex-reg-values" }, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Type"), el("th", {}, "Data")));
		const detail = el("div", { class: "rvalue", "data-test": "hex-reg-value" });
		for (const v of values) {
			const tr = el("tr", { class: "link" }, el("td", { class: "mono" }, v.name ? shown(v.name) : "(default)"), el("td", { class: "muted" }, v.typeName), el("td", { class: "mono rdata" }, shown(v.text.slice(0, 300))));
			tr.addEventListener("click", () => this.showValue(v, detail));
			table.append(tr);
		}
		this.right.replaceChildren(
			el("div", { class: "rpath mono", "data-test": "hex-reg-path" }, shown(`${MOUNT[this.found.kind] ? `${MOUNT[this.found.kind]}\\` : ""}${path}`)),
			el("p", { class: "muted" }, `Last written ${k.written ? `${k.written.replace("T", " ").replace("Z", "")} UTC` : "—"} · ${k.subkeyCount.toLocaleString("en")} subkeys · ${values.length.toLocaleString("en")} values${k.className ? ` · class “${shown(k.className)}”` : ""}`),
			...(why ? [el("p", { class: "warn", "data-test": "hex-reg-why" }, `⚠ ${shown(why)}`)] : []),
			values.length ? table : el("p", { class: "muted" }, "No values."),
			detail,
		);
	}

	private showValue(v: RegValue, into: HTMLElement): void {
		const hex = v.data ? hexDump(v.data.subarray(0, 4096)) : "";
		const go = el("button", {}, "Show its cell in Hex");
		go.addEventListener("click", () => this.toHex(BIN + v.off, 24));
		into.replaceChildren(
			el("h4", {}, `${v.name ? shown(v.name) : "(default)"} · ${v.typeName} · ${v.size.toLocaleString("en")} bytes${v.data && v.data.length < v.size ? ` (the first ${v.data.length.toLocaleString("en")} kept)` : ""}`),
			el("pre", { class: "rtext mono", "data-test": "hex-reg-text" }, shown(v.text)),
			...(hex ? [el("pre", { class: "rhex mono" }, hex)] : []),
			go,
		);
	}

	private showDeleted(list: { name: string; written: string; off: number }[]): void {
		const t = el("table", { class: "grid", "data-test": "hex-reg-deleted-list" }, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Last written (UTC)"), el("th", {}, "Cell")));
		for (const d of list) {
			const tr = el("tr", { class: "link" }, el("td", { class: "mono" }, shown(d.name)), el("td", {}, d.written ? d.written.replace("T", " ").replace("Z", "") : "—"), el("td", { class: "mono" }, `0x${(BIN + d.off).toString(16)}`));
			tr.addEventListener("click", () => this.toHex(BIN + d.off, 80));
			t.append(tr);
		}
		this.right.replaceChildren(el("h4", {}, `Deleted keys still in the free space (${list.length})`), el("p", { class: "muted" }, "A key Windows deleted keeps its name and time until its cell is reused. A click shows its bytes."), t);
	}

	private say(text: string): void {
		this.status.textContent = text;
	}
}

function hexDump(d: Uint8Array): string {
	const lines: string[] = [];
	for (let i = 0; i < d.length; i += 16) {
		const row = d.subarray(i, i + 16);
		lines.push(`${i.toString(16).padStart(6, "0")}  ${[...row].map((x) => x.toString(16).padStart(2, "0")).join(" ").padEnd(47)}  ${[...row].map((x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : ".")).join("")}`);
	}
	return lines.join("\n");
}
