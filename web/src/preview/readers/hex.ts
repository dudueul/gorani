// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The hex reader (commit 42g, docs/PREVIEWS.md › Programs): any file as
 * bytes, and a program as its structure — the one reader a malware sample
 * ever reaches, and then only after the app has written the inspection
 * into the audit trail (viewer.ts › inspect).
 *
 *   Program   a PE, ELF or Mach-O taken apart (preview/binary/): headers,
 *             sections and their entropy, imports and what they let it
 *             do, exports, libraries, the signature's names (NOT verified)
 *   Hex       every byte: offset, hex, ASCII; Go to an offset; Find text,
 *             UTF-16 text or hex bytes; an entropy strip of the whole file
 *             (where it is packed, where an overlay starts) — click it
 *   Strings   ASCII and UTF-16LE runs, by offset, filtered as you type
 *
 * Nothing here runs, draws or decodes the file as what it claims to be:
 * every byte reaches the page as a number, through textContent. The work
 * a big file takes (strings, hashes, the entropy strip) is done a slice
 * at a time so the frame stays responsive, and the facts are sent twice:
 * the structure at once, the rest when it is ready.
 */

import { md5, sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { boot, el, type Host } from "../host.ts";
import { addCss } from "../kit.ts";
import { binaryFacts, type BinaryFindings } from "../facts/binary.ts";
import { capabilities } from "../binary/capabilities.ts";
import { parseElf, type ElfInfo } from "../binary/elf.ts";
import { parseMachoFile, type MachoFile, type MachoInfo } from "../binary/macho.ts";
import { parsePe, type PeInfo } from "../binary/pe.ts";
import { findBytes } from "../binary/find.ts";
import { hex } from "../binary/read.ts";
import { identify } from "../binary/sniff.ts";
import { StringScanner, stringFindings, type Found } from "../binary/strings.ts";
import { lnkFacts, prefetchFacts } from "../facts/forensic.ts";
import { parseLnk, type LnkInfo } from "../forensic/lnk.ts";
import { parsePrefetch, type PrefetchInfo } from "../forensic/prefetch.ts";
import hexCss from "./hex.css?inline";

const ROW = 16;
const RH = 18;
/** Browsers cap an element's height near 33M px; past this, the scroll is scaled. */
const MAX_PX = 8_000_000;
const SLICE = 4 * 1024 * 1024;
const yieldNow = () => new Promise<void>((ok) => setTimeout(ok, 0));

export const start = boot(async (host) => {
	addCss(hexCss);
	const bytes = new Uint8Array(host.file.bytes);
	const tryParse = <T>(f: () => T, what: string, warnings: string[]): T | null => {
		try {
			return f();
		} catch (e) {
			warnings.push(`its ${what} could not be read (${e instanceof Error ? e.message : String(e)})`);
			return null;
		}
	};
	const warnings: string[] = [];
	const pe = tryParse(() => parsePe(bytes), "PE headers", warnings);
	const elf = pe ? null : tryParse(() => parseElf(bytes), "ELF headers", warnings);
	const macho = pe || elf ? null : tryParse(() => parseMachoFile(bytes), "Mach-O headers", warnings);
	// Forensic formats (42i): a shortcut, a Prefetch file.
	const lnk = pe || elf || macho ? null : tryParse(() => parseLnk(bytes), "shortcut", warnings);
	const prefetch = pe || elf || macho || lnk ? null : tryParse(() => parsePrefetch(bytes), "Prefetch data", warnings);
	const findings: BinaryFindings = { name: host.file.name, size: bytes.length, sha256: null, id: identify(bytes), pe, elf, macho, strings: null, entropy: 0, sample: host.sample };
	const send = () => {
		const forensic = lnk ? lnkFacts(lnk, host.file.name) : prefetch ? prefetchFacts(prefetch, host.file.name) : null;
		const facts = forensic
			? [forensic[0]!, ...(host.sample ? [{ level: "warn" as const, text: "A malware sample, shown as bytes only: nothing in it is run, drawn, or handed to another reader — and this inspection is in the audit trail" }] : []), ...(findings.sha256 ? [{ level: "info" as const, text: `SHA-256 ${findings.sha256}`, copy: findings.sha256 }] : []), ...forensic.slice(1)]
			: binaryFacts(findings);
		host.shown([...facts, ...warnings.map((w) => ({ level: "warn" as const, text: `Malformed: ${w}` }))]);
	};

	const view = new HexView(host, bytes, { pe, elf, macho, lnk, prefetch });
	view.show();
	send();

	// The slow part, a slice at a time: hashes, entropy, strings.
	const h256 = sha256.create();
	const h1 = sha1.create();
	const h5 = md5.create();
	const counts = new Float64Array(256);
	const blocks = Math.min(512, Math.max(1, Math.ceil(bytes.length / 256)));
	const blockSize = Math.ceil(bytes.length / blocks) || 1;
	const blockEntropy = new Float32Array(blocks);
	const scanner = new StringScanner(bytes);
	for (let at = 0; at < bytes.length; at += SLICE) {
		const part = bytes.subarray(at, Math.min(bytes.length, at + SLICE));
		h256.update(part);
		h1.update(part);
		h5.update(part);
		for (let i = 0; i < part.length; i++) counts[part[i]!]!++;
		scanner.scan(at, at + part.length);
		await yieldNow();
	}
	for (let k = 0; k < blocks; k++) blockEntropy[k] = entropyOf(bytes.subarray(k * blockSize, Math.min(bytes.length, (k + 1) * blockSize)));
	const strings = scanner.finish();
	const toHex = (d: Uint8Array) => [...d].map((x) => x.toString(16).padStart(2, "0")).join("");
	findings.sha256 = toHex(h256.digest());
	findings.entropy = countsEntropy(counts, bytes.length);
	findings.strings = { total: scanner.total, findings: stringFindings(strings) };
	view.finish(strings, scanner.total, blockEntropy, blockSize, { md5: toHex(h5.digest()), sha1: toHex(h1.digest()), sha256: findings.sha256 });
	send();
});

function countsEntropy(counts: Float64Array, n: number): number {
	let h = 0;
	for (const c of counts) if (c) h -= (c / n) * Math.log2(c / n);
	return h;
}

function entropyOf(b: Uint8Array): number {
	const c = new Float64Array(256);
	for (let i = 0; i < b.length; i++) c[b[i]!]!++;
	return countsEntropy(c, b.length || 1);
}

const fmt = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`);
const printable = (c: number) => c >= 0x20 && c <= 0x7e;

interface Parsed {
	pe: PeInfo | null;
	elf: ElfInfo | null;
	macho: MachoFile | null;
	lnk: LnkInfo | null;
	prefetch: PrefetchInfo | null;
}

class HexView {
	private tabs = el("span", { class: "tabs" });
	private panes = el("div", { class: "panes" });
	private status = el("div", { class: "status muted", "data-test": "hex-status" });
	private built = new Map<string, HTMLElement>();
	private hexPane: HTMLElement | null = null;
	private scroller!: HTMLElement;
	private spacer!: HTMLElement;
	private win!: HTMLElement;
	private strip: HTMLCanvasElement | null = null;
	private sel = { at: -1, len: 1 };
	private rows: number;
	private drawn = -1;
	private stringsPane: HTMLElement | null = null;
	private strings: Found[] | null = null;
	private stringsTotal = 0;
	private hashes: { md5: string; sha1: string; sha256: string } | null = null;
	private readonly host: Host;
	private readonly b: Uint8Array;
	private readonly parsed: Parsed;

	constructor(host: Host, b: Uint8Array, parsed: Parsed) {
		this.host = host;
		this.b = b;
		this.parsed = parsed;
		this.rows = Math.max(1, Math.ceil(b.length / ROW));
	}

	show(): void {
		const root = this.host.root;
		if (this.host.sample) root.append(el("div", { class: "banner", "data-test": "hex-sample" }, "⚠ A malware sample — shown as bytes only. Nothing in it runs, is drawn, or leaves this frame; this inspection is in the audit trail."));
		const program = this.parsed.pe || this.parsed.elf || this.parsed.macho;
		const first = program ? "Program" : this.parsed.lnk ? "Shortcut" : this.parsed.prefetch ? "Prefetch" : null;
		const names = [...(first ? [first] : []), "Hex", "Strings"];
		for (const n of names) {
			const b = el("button", { "aria-pressed": "false", "data-test": `hex-tab-${n.toLowerCase()}` }, n);
			b.addEventListener("click", () => this.open(n));
			this.tabs.append(b);
		}
		root.append(el("div", { class: "bar" }, this.tabs, el("span", { class: "grow" }), el("span", { class: "muted" }, `${fmt(this.b.length)} · ${this.b.length.toLocaleString("en")} bytes`)), this.panes, this.status);
		this.open(names[0]!);
		window.addEventListener("keydown", (e: KeyboardEvent) => {
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
				e.preventDefault();
				this.open("Hex");
				this.hexPane?.querySelector<HTMLInputElement>('[data-test="hex-find"]')?.focus();
			}
		});
	}

	finish(strings: Found[], total: number, blocks: Float32Array, blockSize: number, hashes: { md5: string; sha1: string; sha256: string }): void {
		this.strings = strings;
		this.stringsTotal = total;
		this.hashes = hashes;
		this.drawStrip(blocks, blockSize);
		if (this.stringsPane) this.fillStrings(this.stringsPane);
		const hashBox = this.built.get("Program")?.querySelector('[data-test="hex-hashes"]');
		if (hashBox) hashBox.replaceWith(this.hashTable());
	}

	private open(name: string): void {
		let pane = this.built.get(name);
		if (!pane) {
			pane = name === "Program" || name === "Shortcut" || name === "Prefetch" ? this.programPane() : name === "Hex" ? this.hexView() : this.stringsView();
			this.built.set(name, pane);
			this.panes.append(pane);
		}
		for (const [n, p] of this.built) p.hidden = n !== name;
		for (const b of this.tabs.children) b.setAttribute("aria-pressed", String(b.textContent === name));
		if (name === "Hex") requestAnimationFrame(() => this.draw(true));
	}

	// ── Hex ─────────────────────────────────────────────────────────────
	private hexView(): HTMLElement {
		const goto = el("input", { type: "text", placeholder: "Go to offset (0x… or decimal)", "aria-label": "Go to offset", "data-test": "hex-goto", spellcheck: "false" });
		goto.addEventListener("keydown", (e) => {
			if (e.key !== "Enter") return;
			const v = goto.value.trim();
			const n = /^0x[0-9a-f]+$/i.test(v) ? parseInt(v.slice(2), 16) : /^\d+$/.test(v) ? Number(v) : NaN;
			if (Number.isFinite(n) && n >= 0 && n < this.b.length) this.goTo(n, 1);
			else this.say(`No offset ${v} in this file (it is ${this.b.length.toLocaleString("en")} bytes).`);
		});
		const find = el("input", { type: "search", placeholder: "Find", "aria-label": "Find", "data-test": "hex-find", spellcheck: "false" });
		const mode = el("select", { "aria-label": "Find what", "data-test": "hex-find-mode" }, el("option", { value: "text" }, "text"), el("option", { value: "utf16" }, "UTF-16 text"), el("option", { value: "hex" }, "hex bytes"));
		const found = el("span", { class: "muted", "data-test": "hex-found" });
		find.addEventListener("keydown", (e) => {
			if (e.key !== "Enter") return;
			e.preventDefault();
			const needle = this.needle(find.value, mode.value);
			if (!needle) return void (found.textContent = mode.value === "hex" ? "hex bytes: like 4d 5a 90" : "");
			const at = findBytes(this.b, needle, e.shiftKey ? this.sel.at - 1 : this.sel.at + 1, e.shiftKey ? -1 : 1);
			if (at < 0) return void (found.textContent = "not found");
			found.textContent = `at ${hex(at)}`;
			this.goTo(at, needle.length);
		});
		this.strip = el("canvas", { class: "strip", width: "512", height: "14", title: "Entropy across the file (dark: repetitive; bright: compressed or encrypted). Click to go there.", "data-test": "hex-strip" });
		this.scroller = el("div", { class: "hexscroll", tabindex: "0", "data-test": "hex-grid" });
		this.spacer = el("div", { class: "spacer" });
		this.win = el("div", { class: "hexwin" });
		this.scroller.append(this.spacer, this.win);
		this.spacer.style.height = `${Math.min(this.rows * RH, MAX_PX)}px`;
		this.scroller.addEventListener("scroll", () => this.draw(), { passive: true });
		this.scroller.addEventListener("click", (e) => {
			const o = (e.target as HTMLElement).closest?.("[data-o]")?.getAttribute("data-o");
			if (o !== null && o !== undefined) this.select(Number(o), 1);
		});
		new ResizeObserver(() => this.draw(true)).observe(this.scroller);
		this.hexPane = el("div", { class: "pane hexpane", "data-test": "hex-view" }, el("div", { class: "bar tools" }, goto, find, mode, found), this.strip, this.scroller);
		return this.hexPane;
	}

	private needle(v: string, mode: string): Uint8Array | null {
		if (!v) return null;
		if (mode === "hex") {
			const clean = v.replace(/0x/gi, "").replace(/[\s,:-]/g, "");
			if (!/^(?:[0-9a-f]{2})+$/i.test(clean)) return null;
			return Uint8Array.from(clean.match(/../g)!.map((x) => parseInt(x, 16)));
		}
		const codes = [...v].map((c) => c.charCodeAt(0) & 0xffff);
		if (mode === "utf16") return Uint8Array.from(codes.flatMap((c) => [c & 0xff, c >> 8]));
		return new TextEncoder().encode(v);
	}

	private visible(): number {
		return Math.max(1, Math.ceil((this.scroller?.clientHeight || 400) / RH) + 1);
	}

	/** The first row on screen, for a scroll position (scaled past MAX_PX). */
	private firstRow(): number {
		const total = this.rows * RH;
		const top = this.scroller.scrollTop;
		if (total <= MAX_PX) return Math.floor(top / RH);
		const room = Math.max(1, Math.min(total, MAX_PX) - this.scroller.clientHeight);
		return Math.round((top / room) * Math.max(0, this.rows - this.visible() + 1));
	}

	private goTo(offset: number, len: number): void {
		this.open("Hex");
		const row = Math.floor(offset / ROW);
		const total = this.rows * RH;
		const target = Math.max(0, row - 3);
		if (total <= MAX_PX) this.scroller.scrollTop = target * RH;
		else this.scroller.scrollTop = (target / Math.max(1, this.rows - this.visible() + 1)) * Math.max(1, MAX_PX - this.scroller.clientHeight);
		this.select(offset, len);
	}

	private select(at: number, len: number): void {
		this.sel = { at, len };
		this.draw(true);
		const b = this.b;
		const u16 = at + 1 < b.length ? b[at]! | (b[at + 1]! << 8) : null;
		const u32 = at + 3 < b.length ? (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16) | (b[at + 3]! << 24)) >>> 0 : null;
		this.say(`Offset ${hex(at)} (${at.toLocaleString("en")}) · byte ${hex(b[at]!, 2)} (${b[at]})${u16 !== null ? ` · u16 ${u16}` : ""}${u32 !== null ? ` · u32 ${u32} (${hex(u32)})` : ""}${this.where(at)}`);
	}

	/** Which section an offset falls in, for the status line. */
	private where(at: number): string {
		const { pe, elf, macho } = this.parsed;
		const s = pe?.sections.find((x) => at >= x.raw && at < x.raw + x.rawSize)?.name ?? elf?.sections.find((x) => x.type !== 8 && at >= x.offset && at < x.offset + x.size)?.name ?? macho?.programs[0]?.sections.find((x) => at >= x.offset && at < x.offset + x.size)?.name;
		if (s) return ` · in ${s}`;
		if (pe?.overlay && at >= pe.overlay.offset) return " · in the overlay";
		return "";
	}

	private say(text: string): void {
		this.status.textContent = text;
	}

	private draw(force = false): void {
		if (!this.scroller || this.hexPane?.hidden) return;
		const first = Math.min(this.firstRow(), Math.max(0, this.rows - 1));
		if (!force && first === this.drawn) return;
		this.drawn = first;
		this.win.style.transform = `translateY(${this.scroller.scrollTop}px)`;
		const b = this.b;
		const { at, len } = this.sel;
		const frag = document.createDocumentFragment();
		const last = Math.min(this.rows, first + this.visible());
		const width = b.length > 0xffffffff ? 10 : 8;
		for (let r = first; r < last; r++) {
			const base = r * ROW;
			const row = el("div", { class: "row" });
			row.append(el("span", { class: "off" }, base.toString(16).padStart(width, "0")));
			const hx = el("span", { class: "hx" });
			const asc = el("span", { class: "asc" });
			for (let i = 0; i < ROW; i++) {
				const o = base + i;
				if (o >= b.length) break;
				const c = b[o]!;
				const on = o >= at && o < at + len;
				const h = el("span", { "data-o": String(o), class: `${on ? "sel " : ""}${c === 0 ? "z" : printable(c) ? "p" : "n"}${i === 8 ? " gap" : ""}` }, c.toString(16).padStart(2, "0"));
				const a = el("span", { "data-o": String(o), class: on ? "sel" : printable(c) ? "p" : "n" }, printable(c) ? String.fromCharCode(c) : "·");
				hx.append(h);
				asc.append(a);
			}
			row.append(hx, asc);
			frag.append(row);
		}
		this.win.replaceChildren(frag);
	}

	private drawStrip(blocks: Float32Array, blockSize: number): void {
		const c = this.strip;
		if (!c) return;
		c.width = blocks.length;
		const g = c.getContext("2d");
		if (!g) return;
		for (let k = 0; k < blocks.length; k++) {
			const e = blocks[k]! / 8;
			// Dark blue for repetitive, through green, to bright yellow for near-random.
			g.fillStyle = `hsl(${Math.round(230 - e * 180)} ${Math.round(40 + e * 50)}% ${Math.round(12 + e * 50)}%)`;
			g.fillRect(k, 0, 1, c.height);
		}
		c.onclick = (e) => {
			const k = Math.floor((e.offsetX / c.clientWidth) * blocks.length);
			this.goTo(Math.min(this.b.length - 1, k * blockSize), 1);
		};
	}

	// ── Strings ─────────────────────────────────────────────────────────
	private stringsView(): HTMLElement {
		const pane = el("div", { class: "pane strings", "data-test": "hex-strings" });
		this.stringsPane = pane;
		if (this.strings) this.fillStrings(pane);
		else pane.append(el("p", { class: "notice" }, "Reading its strings…"));
		return pane;
	}

	private fillStrings(pane: HTMLElement): void {
		const list = this.strings ?? [];
		const filter = el("input", { type: "search", placeholder: "Filter", "aria-label": "Filter the strings", "data-test": "hex-strings-filter", spellcheck: "false" });
		const count = el("span", { class: "muted", "data-test": "hex-strings-count" });
		const body = el("div", { class: "scroll list" });
		const render = () => {
			const q = filter.value.toLowerCase();
			const hits = q ? list.filter((s) => s.text.toLowerCase().includes(q)) : list;
			count.textContent = `${hits.length.toLocaleString("en")} of ${this.stringsTotal.toLocaleString("en")}${list.length < this.stringsTotal ? ` (the first ${list.length.toLocaleString("en")} kept)` : ""}`;
			const frag = document.createDocumentFragment();
			for (const s of hits.slice(0, 3000)) {
				const row = el("div", { class: "srow", "data-test": "hex-string" }, el("span", { class: "off" }, s.at.toString(16).padStart(8, "0")), el("span", { class: "kind muted" }, s.wide ? "U" : "A"), el("span", { class: "txt" }, s.text));
				row.addEventListener("click", () => this.goTo(s.at, s.wide ? s.text.length * 2 : s.text.length));
				frag.append(row);
			}
			if (hits.length > 3000) frag.append(el("p", { class: "muted" }, `… ${(hits.length - 3000).toLocaleString("en")} more — filter to narrow them`));
			body.replaceChildren(frag);
		};
		filter.addEventListener("input", render);
		pane.replaceChildren(el("div", { class: "bar tools" }, filter, count, el("span", { class: "grow" }), el("span", { class: "muted" }, "A: ASCII · U: UTF-16 · click one to see it in Hex")), body);
		render();
	}

	// ── Program ─────────────────────────────────────────────────────────
	private programPane(): HTMLElement {
		const pane = el("div", { class: "pane scroll program", "data-test": "hex-program" });
		const { pe, elf, macho, lnk, prefetch } = this.parsed;
		if (lnk) this.lnkView(lnk, pane);
		else if (prefetch) this.prefetchView(prefetch, pane);
		else if (pe) this.peView(pe, pane);
		else if (elf) this.elfView(elf, pane);
		else if (macho) for (const [i, p] of macho.programs.entries()) this.machoView(p, pane, macho.universal ? macho.archs[i]?.offset ?? 0 : 0, macho.universal ? `${p.cpu} (at ${hex(macho.archs[i]?.offset ?? 0)})` : null);
		pane.append(el("h2", {}, "Hashes"), el("p", { class: "muted", "data-test": "hex-hashes" }, "Computing…"));
		return pane;
	}

	private lnkView(l: LnkInfo, pane: HTMLElement): void {
		const t = (d: Date | null) => (d ? `${d.toISOString().replace("T", " ").slice(0, 19)} UTC` : "—");
		pane.append(
			el("h2", {}, "Windows shortcut"),
			kv([
				["Target", l.target ?? "—"],
				...(l.idListPath && l.idListPath !== l.target ? [["Target (shell items)", l.idListPath] as [string, string]] : []),
				...(l.envTarget ? [["Target (environment)", l.envTarget] as [string, string]] : []),
				["Arguments", l.arguments ? `${l.arguments.length} characters${l.arguments.length - l.arguments.trimStart().length ? `, ${l.arguments.length - l.arguments.trimStart().length} leading blanks` : ""}` : "none"],
				["Working folder", l.workingDir ?? "—"],
				["Description", l.name ?? "—"],
				["Icon", l.icon ? `${l.icon} (index ${l.iconIndex})` : "—"],
				["Window", l.window],
				["Run as administrator", l.runAsAdmin ? "yes" : "no"],
				...(l.hotKey ? [["Hot key", l.hotKey] as [string, string]] : []),
				["Target created", t(l.times.created)],
				["Target changed", t(l.times.written)],
				["Target opened", t(l.times.accessed)],
				["Target size", `${l.size.toLocaleString("en")} bytes`],
				...(l.volume ? [["Volume", `${l.volume.type} · serial ${l.volume.serial}${l.volume.label ? ` · “${l.volume.label}”` : ""}`] as [string, string]] : []),
				...(l.share ? [["Network share", `${l.share.net}${l.share.device ? ` (${l.share.device})` : ""}`] as [string, string]] : []),
				...(l.tracker ? [["Made on", `${l.tracker.machine}${l.tracker.mac ? ` · network card ${l.tracker.mac}` : ""}${l.tracker.time ? ` · ${t(l.tracker.time)}` : ""}`] as [string, string], ["Tracker IDs", `volume ${l.tracker.volumeId} · file ${l.tracker.fileId}`] as [string, string]] : []),
				...(l.knownFolder ? [["Known folder", l.knownFolder] as [string, string]] : []),
				...(l.shim ? [["Shim", l.shim] as [string, string]] : []),
				["Extra data", l.blocks.join(", ") || "none"],
				["After its end", l.appended ? `${l.appended.size.toLocaleString("en")} bytes at ${hex(l.appended.offset)}` : "nothing"],
				["Flags", l.flags.join(", ")],
			], "hex-lnk"),
		);
		if (l.arguments?.trim()) pane.append(el("h2", {}, "Arguments (as written)"), el("pre", { class: "args mono", "data-test": "hex-lnk-args" }, l.arguments));
		if (l.appended) {
			const go = el("button", {}, "Show the appended bytes in Hex");
			go.addEventListener("click", () => this.goTo(l.appended!.offset, Math.min(16, l.appended!.size)));
			pane.append(go);
		}
	}

	private prefetchView(p: PrefetchInfo, pane: HTMLElement): void {
		const t = (d: Date) => `${d.toISOString().replace("T", " ").slice(0, 19)} UTC`;
		pane.append(
			el("h2", {}, "Prefetch"),
			kv([
				["Program", p.exe],
				["Path hash", p.hash],
				["Format", `version ${p.version}${p.compressed ? " · compressed (Xpress Huffman)" : ""}`],
				["Run count", String(p.runCount)],
				...p.runs.map((d, i) => [i ? `Run before (${i})` : "Last run", t(d)] as [string, string]),
			], "hex-prefetch"),
			el("h2", {}, `Volumes (${p.volumes.length})`),
			kv(p.volumes.map((v) => [v.device, `serial ${v.serial}${v.created ? ` · created ${t(v.created)}` : ""} · ${v.dirs.length} folders`])),
			el("h2", {}, `Files it touched (${p.files.length})`),
			el("div", { class: "flist mono", "data-test": "hex-prefetch-files" }, ...p.files.slice(0, 2000).map((f) => el("span", { class: /\\(?:USERS\\[^\\]+\\APPDATA|PROGRAMDATA|TEMP|USERS\\PUBLIC|\$RECYCLE\.BIN)\\/i.test(f) ? "warn" : "" }, f.replace(/^\\VOLUME\{[^}]+\}/i, "")))),
		);
	}

	private hashTable(): HTMLElement {
		const h = this.hashes!;
		return kv([["SHA-256", h.sha256], ["SHA-1", h.sha1], ["MD5", h.md5]], "hex-hashes");
	}

	private sectionTable(rows: { name: string; at: number; size: number; rights: string; entropy: number; extra?: string[] }[], extraHeads: string[] = []): HTMLElement {
		const t = el("table", { class: "grid", "data-test": "hex-sections" }, el("tr", {}, ...["Name", ...extraHeads, "File offset", "Size", "Rights", "Entropy"].map((h) => el("th", {}, h))));
		for (const r of rows) {
			const tr = el("tr", { class: r.size ? "link" : "" }, el("td", { class: "mono" }, r.name || "(no name)"), ...(r.extra ?? []).map((x) => el("td", { class: "mono" }, x)), el("td", { class: "mono" }, hex(r.at)), el("td", {}, fmt(r.size)), el("td", { class: `mono${r.rights.includes("w") && r.rights.includes("x") ? " warn" : ""}` }, r.rights), el("td", {}, entropyBar(r.entropy)));
			if (r.size) tr.addEventListener("click", () => this.goTo(r.at, 1));
			t.append(tr);
		}
		return t;
	}

	private importList(groups: { lib: string; names: string[] }[], windows: boolean): HTMLElement {
		const strong = new Set(capabilities(groups.flatMap((g) => g.names), windows).filter((c) => c.strong).flatMap((c) => c.calls));
		const isStrong = (n: string) => {
			const s = n.replace(/@.*$/, "").replace(/^_+/, "");
			return strong.has(s) || strong.has(s.replace(/(?:Ex)?[AW]?$/, "")) || strong.has(s.replace(/[AW]$/, ""));
		};
		const box = el("div", { class: "imports", "data-test": "hex-imports" });
		for (const g of groups) {
			const d = el("details", {});
			const flagged = g.names.filter(isStrong).length;
			d.append(el("summary", {}, el("span", { class: "mono" }, g.lib), ` · ${g.names.length}`, flagged ? el("span", { class: "warn" }, ` · ${flagged} flagged`) : ""));
			d.append(el("div", { class: "names mono" }, ...g.names.map((n) => el("span", { class: isStrong(n) ? "warn" : "" }, n))));
			if (flagged) d.open = true;
			box.append(d);
		}
		return box;
	}

	private peView(p: PeInfo, pane: HTMLElement): void {
		const v = p.version ?? {};
		pane.append(
			el("h2", {}, "Windows program"),
			kv([
				["Kind", `${p.kind} · ${p.bits === 64 ? "PE32+" : "PE32"} · ${p.machine}`],
				["Subsystem", p.subsystem],
				["Compiled", p.time ? `${new Date(p.time * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC (as it says)` : "zeroed"],
				["Entry point", p.entry ? `${hex(p.entry)}${p.entrySection ? ` in ${p.entrySection}` : " (in no section)"}` : "none"],
				["Image base", hex(p.imageBase)],
				["Protections", p.security.join(" · ")],
				...(p.dotnet ? [[".NET", p.dotnet.runtime ?? "yes"] as [string, string]] : []),
				["Signature", p.signature ? `Authenticode, ${fmt(p.signature.size)} at ${hex(p.signature.offset)} — NOT verified${p.signature.names.length ? `; names: ${p.signature.names.join(", ")}` : ""}` : "none"],
				["Overlay", p.overlay ? `${fmt(p.overlay.size)} at ${hex(p.overlay.offset)}` : "none"],
				...(p.pdb ? [["Debug symbols", p.pdb] as [string, string]] : []),
				...(p.tls ? [["TLS callbacks", String(p.tls)] as [string, string]] : []),
				...(p.manifestLevel ? [["Asks to run as", p.manifestLevel] as [string, string]] : []),
				...(p.imphash ? [["imphash", p.imphash] as [string, string]] : []),
				...Object.entries(v).map(([k, x]) => [k, x] as [string, string]),
			]),
			el("h2", {}, `Sections (${p.sections.length})`),
			this.sectionTable(p.sections.map((s) => ({ name: s.name, at: s.raw, size: s.rawSize, rights: `${s.read ? "r" : "-"}${s.write ? "w" : "-"}${s.exec ? "x" : "-"}`, entropy: s.entropy, extra: [hex(s.vaddr), fmt(s.vsize)] })), ["Virtual address", "Virtual size"]),
			el("h2", {}, `Imports (${p.imports.reduce((n, i) => n + i.names.length, 0)} from ${p.imports.length})`),
			this.importList(p.imports.map((i) => ({ lib: `${i.dll}${i.delayed ? " (delay-loaded)" : ""}`, names: i.names })), true),
		);
		if (p.exports.names.length) pane.append(el("h2", {}, `Exports (${p.exports.count})${p.exports.name ? ` — ${p.exports.name}` : ""}`), el("div", { class: "names mono" }, ...p.exports.names.slice(0, 2000).map((n) => el("span", {}, n))));
		if (p.resources.length) pane.append(el("h2", {}, `Resources (${p.resources.length})`), kv(p.resources.slice(0, 40).map((r) => [r.type, `${fmt(r.size)} · entropy ${r.entropy.toFixed(2)}`])));
	}

	private elfView(e: ElfInfo, pane: HTMLElement): void {
		pane.append(
			el("h2", {}, "ELF program"),
			kv([
				["Kind", `${e.type} · ${e.bits}-bit · ${e.little ? "little" : "big"}-endian · ${e.machine}`],
				["ABI", e.abi],
				["Entry point", hex(e.entry)],
				["Loader", e.interpreter ?? (e.staticallyLinked ? "none (statically linked)" : "none")],
				["Symbols", e.stripped ? "stripped" : "present"],
				...(e.buildId ? [["Build ID", e.buildId] as [string, string]] : []),
				...(e.comment ? [["Built with", e.comment] as [string, string]] : []),
				...(e.soname ? [["Library name", e.soname] as [string, string]] : []),
				...(e.rpath ? [["Library path", e.rpath] as [string, string]] : []),
				...(e.needed.length ? [["Needs", e.needed.join(", ")] as [string, string]] : []),
				...(e.modinfo ? Object.entries(e.modinfo).slice(0, 12).map(([k, x]) => [`module ${k}`, x] as [string, string]) : []),
			]),
			el("h2", {}, `Sections (${e.sections.length})`),
			this.sectionTable(e.sections.filter((s) => s.type !== 8 || s.size).map((s) => ({ name: s.name, at: s.offset, size: s.type === 8 ? 0 : s.size, rights: `r${s.write ? "w" : "-"}${s.exec ? "x" : "-"}`, entropy: s.entropy, extra: [hex(s.addr)] })), ["Address"]),
			el("h2", {}, `Imported symbols (${e.imports.length})`),
			this.importList([{ lib: e.needed.join(", ") || "(dynamic)", names: e.imports }], false),
		);
	}

	private machoView(p: MachoInfo, pane: HTMLElement, base: number, title: string | null): void {
		const s = p.signature;
		pane.append(
			el("h2", {}, title ? `Mach-O — ${title}` : "Mach-O program"),
			kv([
				["Kind", `${p.type} · ${p.bits}-bit · ${p.cpu}`],
				["Platform", `${p.platform ?? "?"}${p.minOs ? ` ${p.minOs} and later` : ""}`],
				["Signature", s ? `${s.adhoc && !s.certificate ? "ad hoc" : "with a certificate — NOT verified"}${s.identifier ? ` · ${s.identifier}` : ""}${s.team ? ` · Team ID ${s.team}` : ""}${s.runtime ? " · hardened runtime" : ""}${s.names.length ? ` · names: ${s.names.join(", ")}` : ""}` : "none"],
				["Flags", [p.pie ? "PIE" : "not PIE", ...(p.execStack ? ["executable stack"] : []), ...(p.encrypted ? ["encrypted (FairPlay)"] : [])].join(" · ")],
				...(p.dylinker ? [["Loader", p.dylinker] as [string, string]] : []),
				...(p.rpaths.length ? [["RPATHs", p.rpaths.join(", ")] as [string, string]] : []),
			]),
			el("h2", {}, `Sections (${p.sections.length})`),
			this.sectionTable(p.sections.map((x) => ({ name: `${x.segment},${x.name}`, at: base + x.offset, size: x.offset ? x.size : 0, rights: `r${x.write ? "w" : "-"}${x.exec ? "x" : "-"}`, entropy: x.entropy }))),
			el("h2", {}, `Libraries (${p.libraries.length})`),
			el("div", { class: "names mono" }, ...p.libraries.map((l) => el("span", {}, `${l.path}${l.how ? ` (${l.how})` : ""}`))),
			el("h2", {}, `Imported symbols (${p.imports.length})`),
			this.importList([{ lib: "symbols", names: p.imports }], false),
		);
	}
}

function kv(rows: [string, string][], test = "hex-header"): HTMLElement {
	const t = el("table", { class: "kv", "data-test": test });
	for (const [k, v] of rows) t.append(el("tr", {}, el("th", {}, k), el("td", { class: "mono" }, v)));
	return t;
}

function entropyBar(e: number): HTMLElement {
	const bar = el("span", { class: `ebar${e > 7.2 ? " hot" : ""}` });
	bar.style.setProperty("--e", String(Math.max(0, Math.min(1, e / 8))));
	return el("span", { class: "entropy" }, bar, ` ${e.toFixed(2)}`);
}
