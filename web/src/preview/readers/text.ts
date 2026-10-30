// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The text reader (commit 42f, docs/PREVIEWS.md › Text): Markdown, JSON,
 * XML, web pages and code — the text that needs a parser to be shown
 * well, shown in the preview frame. (Plain text and logs need none, and
 * stay in the app's page, escaped.)
 *
 *   Markdown   rendered (marked), then cleaned as an email is: an inert
 *              parse first, outside pictures swapped for placeholders,
 *              DOMPurify, a shadow root; its source in a tab
 *   JSON       a tree, built as it is opened (a million items open in
 *              steps); JSON Lines, a record a line
 *   XML        a tree from an inert parse — unless it declares entities
 *              or an outside DTD, which is not parsed at all
 *   web pages  their source, never rendered
 *   code       highlighted (highlight.js), line numbers, Find, wrapping
 *
 * The facts (facts/text.ts): secrets in it, masked; what a script would
 * do (a PowerShell -EncodedCommand decoded); what a page would load.
 */

import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import c from "highlight.js/lib/languages/c";
import cpp from "highlight.js/lib/languages/cpp";
import autohotkey from "highlight.js/lib/languages/autohotkey";
import csharp from "highlight.js/lib/languages/csharp";
import dart from "highlight.js/lib/languages/dart";
import css from "highlight.js/lib/languages/css";
import diff from "highlight.js/lib/languages/diff";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import dos from "highlight.js/lib/languages/dos";
import go from "highlight.js/lib/languages/go";
import groovy from "highlight.js/lib/languages/groovy";
import ini from "highlight.js/lib/languages/ini";
import java from "highlight.js/lib/languages/java";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import kotlin from "highlight.js/lib/languages/kotlin";
import less from "highlight.js/lib/languages/less";
import lua from "highlight.js/lib/languages/lua";
import makefile from "highlight.js/lib/languages/makefile";
import markdown from "highlight.js/lib/languages/markdown";
import nim from "highlight.js/lib/languages/nim";
import objectivec from "highlight.js/lib/languages/objectivec";
import perl from "highlight.js/lib/languages/perl";
import php from "highlight.js/lib/languages/php";
import plaintext from "highlight.js/lib/languages/plaintext";
import powershell from "highlight.js/lib/languages/powershell";
import properties from "highlight.js/lib/languages/properties";
import python from "highlight.js/lib/languages/python";
import r from "highlight.js/lib/languages/r";
import ruby from "highlight.js/lib/languages/ruby";
import rust from "highlight.js/lib/languages/rust";
import scala from "highlight.js/lib/languages/scala";
import scss from "highlight.js/lib/languages/scss";
import sql from "highlight.js/lib/languages/sql";
import swift from "highlight.js/lib/languages/swift";
import typescript from "highlight.js/lib/languages/typescript";
import vbscript from "highlight.js/lib/languages/vbscript";
import x86asm from "highlight.js/lib/languages/x86asm";
import xml from "highlight.js/lib/languages/xml";
import yaml from "highlight.js/lib/languages/yaml";
import DOMPurify from "dompurify";
import { marked } from "marked";
import { boot, el, type Host } from "../host.ts";
import { addCss, Finder, findCss } from "../kit.ts";
import { textFacts, type PageFindings } from "../facts/text.ts";
import { decodeText, parseJson, parseJsonLines, textKind, xmlDanger, type TextKind } from "../text/structured.ts";
import textCss from "./text.css?inline";
import pageCss from "./text-page.css?inline";

for (const [name, lang] of Object.entries({ autohotkey, bash, c, cpp, csharp, css, dart, diff, dockerfile, dos, go, groovy, ini, java, javascript, json, kotlin, less, lua, makefile, markdown, nim, objectivec, perl, php, plaintext, powershell, properties, python, r, ruby, rust, scala, scss, sql, swift, typescript, vbscript, x86asm, xml, yaml })) hljs.registerLanguage(name, lang);

/** Shown at most (a bigger file says so); highlighted at most (beyond, plain). */
const SHOW_CAP = 8 * 1024 * 1024;
const HIGHLIGHT_CAP = 1024 * 1024;
const PLACEHOLDER = `data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="220" height="40"><rect width="220" height="40" fill="#1f2937" stroke="#374151"/><text x="110" y="24" font-family="sans-serif" font-size="11" fill="#9ca3af" text-anchor="middle">picture not loaded</text></svg>')}`;

export const start = boot(async (host) => {
	addCss(textCss, findCss);
	const bytes = new Uint8Array(host.file.bytes);
	const decoded = decodeText(bytes.subarray(0, SHOW_CAP));
	// NUL bytes where text has none: a binary file with a text name (a
	// renamed executable, a binary plist). Shown as source, never parsed,
	// and the facts say so.
	const binary = !/UTF-16/.test(decoded.encoding) && bytes.subarray(0, 65536).includes(0);
	const text = binary ? decoded.text.replace(/\0/g, "␀") : decoded.text;
	const named = textKind(host.file.name, text);
	const { kind, language } = binary ? { kind: "code" as const, language: "plaintext" } : named;
	const view = new TextView(host, text, kind, language, bytes.length > SHOW_CAP);
	const findings = view.show();
	host.shown(textFacts({ name: host.file.name, kind, language, encoding: binary ? "not text: it holds NUL bytes" : decoded.encoding, bytes: bytes.length, text, binary, ...findings }));
});

interface Pane {
	name: string;
	test: string;
	make: () => HTMLElement;
	find?: () => HTMLElement | null;
}

class TextView {
	private bar = el("div", { class: "bar" });
	private body = el("div", { class: "scroll panes" });
	private status = el("div", { class: "status muted", "data-test": "text-status" });
	private current: Pane | null = null;
	private built = new Map<string, HTMLElement>();
	private finder: Finder;
	private wrap = false;

	constructor(private host: Host, private text: string, private kind: TextKind, private language: string, private cut: boolean) {
		this.finder = new Finder(() => (this.current?.find ? this.current.find() : (this.built.get(this.current?.name ?? "") ?? null)), this.body, "Find");
	}

	show(): { page: PageFindings | null; xml: ReturnType<typeof xmlDanger> | null; json: { values: number; bad: number; error: string | null } | null } {
		const panes: Pane[] = [];
		let page: PageFindings | null = null;
		let xmlFound: ReturnType<typeof xmlDanger> | null = null;
		let jsonFound: { values: number; bad: number; error: string | null } | null = null;
		if (this.kind === "markdown") {
			const r = renderMarkdown(this.text);
			page = r.findings;
			panes.push({ name: "Rendered", test: "text-tab-rendered", make: () => this.shadow(r.fragment), find: () => this.built.get("Rendered")?.shadowRoot?.querySelector(".md") as HTMLElement | null });
		} else if (this.kind === "json" && this.cut) {
			jsonFound = { values: 0, bad: 0, error: `it is larger than ${SHOW_CAP / 1048576} MB — its first ${SHOW_CAP / 1048576} MB are shown as source, not parsed` };
		} else if (this.kind === "json" || this.kind === "jsonl") {
			const parsed = this.kind === "jsonl" ? (() => {
				const l = parseJsonLines(this.text);
				return { value: l.values as unknown, error: null as string | null, values: l.values.length, bad: l.bad };
			})() : (() => {
				const r = parseJson(this.text);
				return "value" in r ? { value: r.value, error: null, values: 1, bad: 0 } : { value: undefined, error: r.error, values: 0, bad: 0 };
			})();
			jsonFound = { values: parsed.values, bad: parsed.bad, error: parsed.error };
			if (!parsed.error) panes.push({ name: "Tree", test: "text-tab-tree", make: () => this.jsonTree(parsed.value) });
		} else if (this.kind === "xml" || this.kind === "html") {
			xmlFound = xmlDanger(this.text);
			if (this.kind === "html") page = pageFindings(new DOMParser().parseFromString(this.text, "text/html"));
			else if (!xmlFound.entities && !xmlFound.external) {
				const doc = new DOMParser().parseFromString(this.text, "application/xml");
				if (!doc.querySelector("parsererror")) panes.push({ name: "Tree", test: "text-tab-tree", make: () => this.xmlTree(doc) });
			}
		}
		panes.push({ name: "Source", test: "text-tab-source", make: () => this.source() });

		const tabs = el("span", { class: "tabs" });
		const wrap = el("button", { "aria-pressed": "false", title: "Wrap long lines", "data-test": "text-wrap" }, "Wrap");
		wrap.addEventListener("click", () => {
			this.wrap = !this.wrap;
			wrap.setAttribute("aria-pressed", String(this.wrap));
			this.body.classList.toggle("wrap", this.wrap);
		});
		for (const p of panes) {
			const b = el("button", { "data-test": p.test, "aria-pressed": "false" }, p.name);
			b.addEventListener("click", () => this.open(p, tabs));
			tabs.append(b);
		}
		this.bar.append(tabs, el("span", { class: "grow" }), this.finder.input, this.finder.found, wrap);
		this.host.root.append(this.bar, this.body, this.status);
		if (this.cut) this.status.textContent = `The first ${SHOW_CAP / 1048576} MB are shown.`;
		this.open(panes[0]!, tabs);
		return { page, xml: xmlFound, json: jsonFound };
	}

	private open(p: Pane, tabs: HTMLElement): void {
		let pane = this.built.get(p.name);
		if (!pane) {
			pane = p.make();
			this.built.set(p.name, pane);
			this.body.append(pane);
		}
		for (const [n, x] of this.built) x.hidden = n !== p.name;
		for (const b of tabs.children) b.setAttribute("aria-pressed", String(b.textContent === p.name));
		this.current = p;
		this.finder.clear();
	}

	/** Highlighted source with line numbers (the gutter hides when lines wrap). */
	private source(): HTMLElement {
		const t = this.text;
		const code = el("code", { class: "hljs" });
		const lang = hljs.getLanguage(this.language) ? this.language : "plaintext";
		if (t.length <= HIGHLIGHT_CAP && lang !== "plaintext") {
			// highlight.js escapes the text and wraps it in <span class>; the
			// string still goes through the frame's default Trusted Types policy
			// (DOMPurify) on its way in.
			code.innerHTML = hljs.highlight(t, { language: lang, ignoreIllegals: true }).value;
		} else code.textContent = t;
		const n = t.split("\n").length;
		const gutter = el("pre", { class: "gutter", "aria-hidden": "true" });
		gutter.textContent = Array.from({ length: Math.min(n, 2_000_000) }, (_, i) => i + 1).join("\n");
		const pre = el("pre", { class: "code" }, code);
		return el("div", { class: "source", "data-test": "text-source" }, gutter, pre);
	}

	private shadow(fragment: DocumentFragment): HTMLElement {
		const holder = el("div", { class: "page", "data-test": "text-rendered" });
		const root = holder.attachShadow({ mode: "open" });
		const style = document.createElement("style");
		style.textContent = pageCss + findCss;
		const md = el("div", { class: "md" });
		md.append(fragment);
		root.append(style, md);
		// Where a link goes, on hover (a click goes nowhere: host.ts).
		root.addEventListener("mouseover", (e) => {
			const a = (e.target as Element).closest?.("a[href]");
			this.status.textContent = a ? `→ ${a.getAttribute("href")}` : "";
		});
		return holder;
	}

	// ── JSON ──
	private jsonTree(value: unknown): HTMLElement {
		const root = el("div", { class: "tree", "data-test": "text-tree" });
		root.append(this.jsonNode(null, value, "$", true));
		return root;
	}

	private jsonNode(key: string | null, value: unknown, path: string, open = false): HTMLElement {
		const label = (extra: HTMLElement[]) => {
			const parts: (HTMLElement | string)[] = [];
			if (key !== null) parts.push(el("span", { class: "k" }, key), ": ");
			return el("span", { class: "line", "data-path": path }, ...parts, ...extra);
		};
		if (value === null || typeof value !== "object") {
			const t = value === null ? "null" : typeof value;
			const shown = typeof value === "string" ? JSON.stringify(value.length > 2000 ? `${value.slice(0, 2000)}…` : value) : String(value);
			const row = label([el("span", { class: `v ${t}` }, shown)]);
			row.addEventListener("click", () => (this.status.textContent = path));
			return el("div", { class: "leaf" }, row);
		}
		const isArray = Array.isArray(value);
		const entries = isArray ? (value as unknown[]).map((v, i) => [String(i), v] as const) : Object.entries(value as Record<string, unknown>);
		const d = el("details", { class: "node" });
		const summary = el("summary", {}, label([el("span", { class: "muted" }, isArray ? `[${entries.length}]` : `{${entries.length}}`)]));
		summary.addEventListener("click", () => (this.status.textContent = path));
		d.append(summary);
		let shown = 0;
		const more = () => {
			const next = entries.slice(shown, shown + 500);
			shown += next.length;
			for (const [k, v] of next) {
				const p = isArray ? `${path}[${k}]` : /^[A-Za-z_$][\w$]*$/.test(k) ? `${path}.${k}` : `${path}[${JSON.stringify(k)}]`;
				d.insertBefore(this.jsonNode(isArray ? k : JSON.stringify(k), v, p), button);
			}
			button.hidden = shown >= entries.length;
			button.textContent = `Show ${Math.min(500, entries.length - shown)} more of ${entries.length - shown}`;
		};
		const button = el("button", { class: "more", hidden: "" });
		button.addEventListener("click", more);
		d.append(button);
		d.addEventListener("toggle", () => d.open && shown === 0 && more(), { once: false });
		if (open) {
			d.open = true;
			more();
		}
		return d;
	}

	// ── XML ──
	private xmlTree(doc: Document): HTMLElement {
		const root = el("div", { class: "tree", "data-test": "text-tree" });
		root.append(this.xmlNode(doc.documentElement, `/${doc.documentElement.nodeName}`, true));
		return root;
	}

	private xmlNode(n: Element, path: string, open = false): HTMLElement {
		const kids = [...n.childNodes].filter((c) => c.nodeType === 1 || ((c.nodeType === 3 || c.nodeType === 4) && (c.textContent ?? "").trim()) || c.nodeType === 8);
		const attrs = [...n.attributes].slice(0, 30).map((a) => [el("span", { class: "a" }, ` ${a.name}`), "=", el("span", { class: "v string" }, JSON.stringify(a.value.length > 300 ? `${a.value.slice(0, 300)}…` : a.value))]).flat();
		const tag = el("span", { class: "line", "data-path": path }, el("span", { class: "t" }, `<${n.nodeName}`), ...attrs, el("span", { class: "t" }, kids.length ? ">" : " />"));
		if (!kids.length) {
			tag.addEventListener("click", () => (this.status.textContent = path));
			return el("div", { class: "leaf" }, tag);
		}
		const d = el("details", { class: "node" });
		const summary = el("summary", {}, tag);
		summary.addEventListener("click", () => (this.status.textContent = path));
		d.append(summary);
		let done = false;
		const fill = () => {
			if (done) return;
			done = true;
			const counts = new Map<string, number>();
			for (const c of kids.slice(0, 5000)) {
				if (c.nodeType === 1) {
					const name = c.nodeName;
					const i = (counts.get(name) ?? 0) + 1;
					counts.set(name, i);
					d.append(this.xmlNode(c as Element, `${path}/${name}[${i}]`));
				} else if (c.nodeType === 8) d.append(el("div", { class: "leaf muted" }, `<!-- ${(c.textContent ?? "").trim().slice(0, 300)} -->`));
				else d.append(el("div", { class: "leaf text" }, (c.textContent ?? "").trim().slice(0, 2000)));
			}
			if (kids.length > 5000) d.append(el("div", { class: "leaf muted" }, `… ${kids.length - 5000} more`));
		};
		d.addEventListener("toggle", () => d.open && fill());
		if (open) {
			d.open = true;
			fill();
		}
		return d;
	}
}

const REMOTE = /^\s*(?:https?:)?\/\//i;

function pageFindings(doc: Document): PageFindings {
	return {
		links: [...doc.querySelectorAll("a[href]")].map((a) => a.getAttribute("href") ?? "").filter((h) => h && !h.startsWith("#")),
		remote: [...doc.querySelectorAll("img[src], script[src], link[href], iframe[src], video[src], audio[src], source[src], embed[src], object[data]")].map((e) => e.getAttribute("src") ?? e.getAttribute("href") ?? e.getAttribute("data") ?? "").filter((u) => REMOTE.test(u)),
		scripts: doc.querySelectorAll("script").length + [...doc.querySelectorAll("*")].filter((e) => [...e.attributes].some((a) => /^on/i.test(a.name))).length,
		forms: doc.querySelectorAll("form").length,
		frames: doc.querySelectorAll("iframe, frame, object, embed").length,
	};
}

/** Markdown, rendered and cleaned: an inert parse, outside pictures swapped
 * out, then DOMPurify into nodes (no scripts, forms, frames, styles). */
function renderMarkdown(src: string): { fragment: DocumentFragment; findings: PageFindings } {
	const html = marked.parse(src, { gfm: true, async: false }) as string;
	const doc = new DOMParser().parseFromString(html, "text/html");
	const findings = pageFindings(doc);
	for (const img of doc.querySelectorAll("img")) {
		const s = img.getAttribute("src") ?? "";
		if (!/^data:image\/(png|gif|jpe?g|webp);/i.test(s)) img.setAttribute("src", PLACEHOLDER);
		img.removeAttribute("srcset");
	}
	const fragment = DOMPurify.sanitize(doc.body.innerHTML, {
		RETURN_DOM_FRAGMENT: true,
		FORBID_TAGS: ["style", "script", "noscript", "form", "input", "button", "textarea", "select", "option", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "link", "meta", "template", "video", "audio", "source", "track", "portal", "svg", "math"],
		FORBID_ATTR: ["style", "srcset", "ping", "action", "formaction", "background", "poster"],
		ALLOW_DATA_ATTR: false,
		ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel):|data:image\/(?:png|gif|jpe?g|webp|svg\+xml)[;,]|#)/i,
	}) as DocumentFragment;
	for (const a of fragment.querySelectorAll("a[href]")) a.setAttribute("title", `→ ${a.getAttribute("href")}`);
	return { fragment, findings };
}
