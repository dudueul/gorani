// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The email reader (commit 42c, docs/PREVIEWS.md › Email): .eml and
 * Outlook's .msg, inside the preview frame — the phishing-triage view.
 *
 *   Message   the HTML body as the sender designed it, cleaned: no
 *             scripts, forms or frames; pictures from outside replaced by
 *             a placeholder BEFORE the browser could ask for them (a
 *             tracker never learns the message was opened); cid: pictures
 *             shown from the message's own parts. Drawn in a shadow root,
 *             so the email's CSS styles nothing but the email. Hovering a
 *             link shows where it really goes.
 *   Text      the plain-text part (or the HTML's text)
 *   Headers   the Received chain as a timeline, then every header
 *   Source    the message as it travelled (.eml)
 *
 * The HTML is parsed twice, both times inertly: once (DOMParser) to find
 * what it would do — links, trackers, forms, scripts (facts/mail.ts judges
 * them) — and to swap its outside pictures for placeholders; then
 * DOMPurify turns what is left into nodes. Nothing of the message is ever
 * written into the page as a string.
 *
 * Attachments are listed with their size and SHA-256. Open and Save are
 * REQUESTS to the app (host.handOver): the app opens an attachment in a new
 * frame of its own, or asks the person before it saves one into the vault.
 * This frame can ask; it cannot do either.
 */

import DOMPurify from "dompurify";
import { boot, el, type Host } from "../host.ts";
import { addCss, Finder, findCss } from "../kit.ts";
import { inlineParts, mailFacts, partRisk, type HtmlFindings, type Hop } from "../facts/mail.ts";
import { parseMail, SOURCE_CAP, type Mail, type MailPart } from "../mail/parse.ts";
import { plural, refusal } from "../office.ts";
import emailCss from "./email.css?inline";

export const start = boot(async (host) => {
	addCss(emailCss, findCss);
	const status = el("p", { class: "notice" }, "Opening the message…");
	host.root.append(status);
	let mail: Mail;
	try {
		mail = await parseMail(new Uint8Array(host.file.bytes));
	} catch (e) {
		refusal(host.root, "This message does not open.", String(e instanceof Error ? e.message : e));
		host.shown([{ level: "warn", text: "The message did not open: it may be damaged, or not an email" }]);
		return;
	}
	const body = mail.html ? cleanHtml(mail) : null;
	const { facts, hops } = mailFacts(mail, body?.findings ?? null);
	status.remove();
	new MailView(host, mail, body, hops).show();
	host.shown(facts);
});

// ── the HTML body ────────────────────────────────────────────────────

/** What DOMPurify keeps of an email: its text, layout and styles — never
 * anything that runs, submits, frames, or loads by itself. */
const CLEAN = {
	RETURN_DOM_FRAGMENT: true as const,
	// (A leading <style> would otherwise be parsed into a <head> and lost.)
	FORCE_BODY: true,
	FORBID_TAGS: ["script", "noscript", "form", "input", "button", "textarea", "select", "option", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "link", "meta", "template", "video", "audio", "source", "track", "portal"],
	FORBID_ATTR: ["srcset", "ping", "action", "formaction", "background", "poster", "lowsrc", "dynsrc"],
	ALLOW_DATA_ATTR: false,
	// …but the mark this reader puts on a picture it replaced (a message
	// can set it too: all it does is draw a dashed outline).
	ADD_ATTR: ["data-remote"],
	ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel|blob):|data:image\/(?:png|gif|jpe?g|webp|svg\+xml)[;,]|#)/i,
};

/** The picture shown where one from outside would have been. */
const PLACEHOLDER = `data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="200" height="40"><rect width="200" height="40" fill="#f3f4f6" stroke="#d1d5db"/><text x="100" y="24" font-family="sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">picture from outside, not loaded</text></svg>')}`;

const REMOTE = /^\s*(?:https?:)?\/\//i;
const CSS_URL = /url\(\s*(['"]?)([^'")]*)\1\s*\)/gi;

interface Body {
	findings: HtmlFindings;
	fragment: DocumentFragment;
	text: string;
}

function cleanHtml(m: Mail): Body {
	const doc = new DOMParser().parseFromString(m.html ?? "", "text/html");
	const parts = inlineParts(m);
	const blobs = new Map<string, string>();
	const cid = (ref: string) => {
		const key = ref.replace(/^cid:/i, "").replace(/^<|>$/g, "").toLowerCase();
		const part = parts.get(key);
		if (!part) return null;
		if (!blobs.has(key)) blobs.set(key, URL.createObjectURL(new Blob([part.bytes as BlobPart], { type: part.mime.startsWith("image/") ? part.mime : "application/octet-stream" })));
		return blobs.get(key)!;
	};

	// 1. What it would do.
	const findings: HtmlFindings = {
		links: [...doc.querySelectorAll("a[href], area[href]")].map((a) => ({ href: a.getAttribute("href") ?? "", text: a.textContent ?? "" })),
		remote: [],
		forms: [...doc.querySelectorAll("form")].map((f) => ({ action: f.getAttribute("action") ?? "", password: !!f.querySelector('input[type="password" i]') })),
		scripts: doc.querySelectorAll("script").length + [...doc.querySelectorAll("*")].filter((e) => [...e.attributes].some((a) => /^on/i.test(a.name))).length,
		frames: [...doc.querySelectorAll("iframe, frame, object, embed")].map((e) => e.getAttribute("src") ?? e.getAttribute("data") ?? ""),
		refresh: /url=([^;]+)/i.exec(doc.querySelector('meta[http-equiv="refresh" i]')?.getAttribute("content") ?? "")?.[1]?.trim() ?? null,
	};
	// Inputs outside a form still collect what is typed (into script).
	if (!findings.forms.length && doc.querySelector('input[type="password" i]')) findings.forms.push({ action: "", password: true });

	// 2. Outside pictures and styles swapped out, cid: pictures in — in the
	// inert document, so nothing below is ever asked of the network.
	for (const img of doc.querySelectorAll<HTMLElement>("img, image, input[type=image]")) {
		for (const attr of ["src", "href", "xlink:href"]) {
			const v = img.getAttribute(attr);
			if (!v) continue;
			if (REMOTE.test(v)) {
				findings.remote.push(v);
				img.setAttribute(attr, PLACEHOLDER);
				img.setAttribute("data-remote", "");
			} else if (/^cid:/i.test(v)) img.setAttribute(attr, cid(v) ?? PLACEHOLDER);
		}
	}
	for (const e of doc.querySelectorAll("[background]")) {
		const v = e.getAttribute("background") ?? "";
		if (REMOTE.test(v)) findings.remote.push(v);
	}
	const css = (text: string) =>
		text.replace(/@import\s+[^;]+;?/gi, (rule) => {
			const u = /(?:url\()?\s*['"]?([^'")\s;]+)/i.exec(rule.replace(/@import\s+/i, ""))?.[1];
			if (u) findings.remote.push(u);
			return "";
		}).replace(CSS_URL, (whole, _q: string, u: string) => {
			if (REMOTE.test(u)) {
				findings.remote.push(u);
				return "none";
			}
			if (/^cid:/i.test(u)) {
				const b = cid(u);
				return b ? `url("${b}")` : "none";
			}
			return /^data:image\//i.test(u) ? whole : "none";
		});
	for (const s of doc.querySelectorAll("style")) s.textContent = css(s.textContent ?? "");
	for (const e of doc.querySelectorAll<HTMLElement>("[style]")) e.setAttribute("style", css(e.getAttribute("style") ?? ""));

	// 3. Into nodes, through DOMPurify (the <style>s of the head kept too).
	const markup = [...doc.head.querySelectorAll("style")].map((s) => s.outerHTML).join("") + doc.body.innerHTML;
	const fragment = DOMPurify.sanitize(markup, CLEAN) as DocumentFragment;
	// Each link says where it really goes when hovered (its own title, if
	// any, is the sender's words — replaced).
	for (const a of fragment.querySelectorAll("a[href]")) a.setAttribute("title", `→ ${a.getAttribute("href")}`);
	return { findings, fragment, text: (doc.body.textContent ?? "").replace(/\n{3,}/g, "\n\n").trim() };
}

// ── the view ─────────────────────────────────────────────────────────

const fmtSize = (n: number) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`);
const who = (a: { name: string; address: string }) => (a.name && a.name !== a.address ? `${a.name} <${a.address}>` : a.address || a.name);

class MailView {
	private tabs = el("div", { class: "tabs", role: "tablist" });
	private panes = el("div", { class: "scroll panes" });
	private status = el("div", { class: "linkbar", "data-test": "mail-link" });
	private finder: Finder;
	private current: HTMLElement | null = null;

	constructor(private host: Host, private mail: Mail, private body: Body | null, private hops: Hop[]) {
		this.finder = new Finder(() => this.current, this.panes, "Find in the message");
	}

	show(): void {
		const m = this.mail;
		const head = el("section", { class: "mailhead", "data-test": "mail-head" });
		head.append(el("h1", { "data-test": "mail-subject" }, m.subject || "(no subject)"));
		const row = (label: string, value: string, test: string) => (value ? head.append(el("div", { class: "row" }, el("span", { class: "k" }, label), el("span", { class: "v", "data-test": test }, value))) : undefined);
		row("From", m.from ? who(m.from) : "", "mail-from");
		if (m.replyTo.length) row("Reply-To", m.replyTo.map(who).join(", "), "mail-replyto");
		row("To", m.to.map(who).join(", "), "mail-to");
		row("Cc", m.cc.map(who).join(", "), "mail-cc");
		// The Date line as it is written (evidence), not as parsed.
		row("Date", m.headers.find((x) => x.name.toLowerCase() === "date")?.value ?? m.date ?? "", "mail-date");
		const list = el("div", { class: "atts", "data-test": "mail-attachments" });
		for (const part of m.attachments) list.append(this.attachment(part));
		if (m.attachments.length) head.append(el("div", { class: "row" }, el("span", { class: "k" }, plural(m.attachments.length, "part")), list));

		const panes: [string, () => HTMLElement][] = [];
		if (this.body) panes.push(["Message", () => this.messagePane()]);
		panes.push(["Text", () => this.textPane()], ["Headers", () => this.headersPane()]);
		if (m.source) panes.push(["Source", () => this.sourcePane()]);
		const built = new Map<string, HTMLElement>();
		const open = (name: string) => {
			let pane = built.get(name);
			if (!pane) {
				pane = panes.find(([n]) => n === name)![1]();
				built.set(name, pane);
				this.panes.append(pane);
			}
			for (const [n, p] of built) p.hidden = n !== name;
			for (const b of this.tabs.children) b.setAttribute("aria-selected", String(b.textContent === name));
			this.current = pane.shadowRoot ? (pane.shadowRoot.querySelector(".mailbody") as HTMLElement) : pane;
			this.finder.clear();
		};
		for (const [name] of panes) {
			const b = el("button", { role: "tab", "data-test": `mail-tab-${name.toLowerCase()}`, "aria-selected": "false" }, name);
			b.addEventListener("click", () => open(name));
			this.tabs.append(b);
		}
		const bar = el("div", { class: "bar" }, this.tabs, el("span", { class: "grow" }), this.finder.input, this.finder.found);
		this.host.root.append(bar, head, this.panes, this.status);
		open(panes[0]![0]);
	}

	private attachment(part: MailPart): HTMLElement {
		const risk = partRisk(part.name, part.bytes);
		const sha = el("code", { class: "sha", title: "SHA-256" }, "…");
		void crypto.subtle?.digest("SHA-256", part.bytes as BufferSource).then((d) => (sha.textContent = [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("")), () => (sha.textContent = ""));
		const openBtn = el("button", { "data-test": "mail-open", title: "Open it in a preview of its own (a new sandboxed frame)" }, "Open");
		const saveBtn = el("button", { "data-test": "mail-save", title: "Save it into the vault, beside this message (you are asked first)" }, "Save to vault");
		openBtn.addEventListener("click", () => this.host.handOver("open", part));
		saveBtn.addEventListener("click", () => this.host.handOver("save", part));
		return el("div", { class: `att${risk ? " risky" : ""}`, "data-test": "mail-attachment" },
			el("span", { class: "name", title: part.mime }, `${risk ? "⚠ " : ""}${part.name}`),
			el("span", { class: "muted" }, `${part.mime} · ${fmtSize(part.bytes.length)}${part.inline ? " · inline" : ""}`),
			sha, openBtn, saveBtn);
	}

	private messagePane(): HTMLElement {
		const pane = el("div", { class: "pane message", "data-test": "mail-message" });
		// A shadow root: the email's own <style>s style the email and nothing
		// else (not the bar, not the facts' host).
		const shadow = pane.attachShadow({ mode: "open" });
		const style = document.createElement("style");
		style.textContent = `:host{display:block;background:#fff;color:#111}.mailbody{padding:16px 20px;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans KR",sans-serif;overflow-wrap:anywhere}img{max-width:100%;height:auto}img[data-remote]{outline:1px dashed #d1d5db}${findCss}`;
		const box = el("div", { class: "mailbody" });
		box.append(this.body!.fragment);
		shadow.append(style, box);
		// Where a link really goes, on hover (and on focus, for keyboards).
		const show = (e: Event) => {
			const a = e.composedPath().find((n): n is HTMLAnchorElement => n instanceof HTMLAnchorElement && n.hasAttribute("href"));
			this.status.textContent = a ? `→ ${a.getAttribute("href")}` : "";
		};
		shadow.addEventListener("mouseover", show);
		shadow.addEventListener("focusin", show);
		return pane;
	}

	private textPane(): HTMLElement {
		const text = this.mail.text?.trim() || this.body?.text || "(no text)";
		return el("pre", { class: "pane text", "data-test": "mail-text" }, text);
	}

	private headersPane(): HTMLElement {
		const pane = el("div", { class: "pane headers", "data-test": "mail-headers" });
		if (this.hops.length) {
			const t = el("table", { class: "hops", "data-test": "mail-hops" }, el("tr", {}, el("th", {}, "#"), el("th", {}, "From"), el("th", {}, "By"), el("th", {}, "When (UTC)")));
			let prev: Date | null = null;
			this.hops.forEach((hop, i) => {
				const delay = hop.at && prev ? Math.round((hop.at.getTime() - prev.getTime()) / 1000) : null;
				t.append(el("tr", {}, el("td", {}, String(i + 1)), el("td", {}, `${hop.from}${hop.ip ? ` [${hop.ip}]` : ""}`), el("td", {}, hop.by), el("td", {}, hop.at ? `${hop.at.toISOString().slice(0, 19).replace("T", " ")}${delay !== null ? ` (+${delay}s)` : ""}` : "")));
				prev = hop.at ?? prev;
			});
			pane.append(el("h2", {}, "How it travelled (oldest first)"), t);
		}
		const all = el("table", { class: "all" });
		for (const h of this.mail.headers.slice(0, 2000)) all.append(el("tr", {}, el("th", {}, h.name), el("td", {}, h.value)));
		pane.append(el("h2", {}, this.mail.format === "msg" ? "Headers as received (Outlook keeps them in one property)" : "Every header, in order"), this.mail.headers.length ? all : el("p", { class: "muted" }, "None recorded (a message saved in Outlook before it was sent has none)."));
		return pane;
	}

	private sourcePane(): HTMLElement {
		const src = this.mail.source ?? "";
		return el("pre", { class: "pane text", "data-test": "mail-source" }, src.length >= SOURCE_CAP ? `${src}\n\n— shown: the first ${SOURCE_CAP / 1048576} MB —` : src);
	}
}
