// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What an Office file carries besides its pages (commit 42b,
 * docs/PREVIEWS.md › Office) — read from its structure, the same for Word,
 * Excel and PowerPoint (OOXML: a ZIP of XML parts tied together by
 * "relationships", the _rels/*.rels parts).
 *
 * The tricks a security team meets, and how each shows up here:
 *
 *   - macros                 a part named vbaProject.bin (.docm, .xlsm, .pptm —
 *                            and anything renamed to .docx to look harmless)
 *   - template injection     a relationship of type attachedTemplate with
 *                            TargetMode="External": Word fetches the
 *                            template, macros and all, from that address
 *                            when the file is opened
 *   - beacons, hash leaks    a picture or object linked from outside: the
 *                            fetch tells the sender the file was opened; a
 *                            \\server\share path makes Windows offer the
 *                            user's sign-in hash to that server
 *   - embedded objects       parts under embeddings/ (OLE objects, packaged
 *                            files) and activeX/ controls
 *   - links                  hyperlink relationships: listed, never followed
 *
 * Nothing here fetches, runs or opens any of it: the facts are TEXT, sent
 * to the viewer and shown outside the frame.
 */

import type { Fact } from "./host.ts";
import { Ole } from "./ole.ts";
import { Zip } from "./zip.ts";

export interface Rel {
	/** The part the relationship is FROM ("word/document.xml"). */
	from: string;
	id: string;
	/** The last word of its type URI: "hyperlink", "image", "attachedTemplate"… */
	type: string;
	target: string;
	external: boolean;
}

/** Decode the five XML entities and numeric references (attribute values, text). */
export function unxml(s: string): string {
	return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e: string) => {
		const k = e.toLowerCase();
		if (k === "amp") return "&";
		if (k === "lt") return "<";
		if (k === "gt") return ">";
		if (k === "quot") return '"';
		if (k === "apos") return "'";
		const n = k.startsWith("#x") ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10);
		return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m;
	});
}

const attr = (tag: string, name: string): string | null => {
	const m = new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)')`).exec(tag);
	return m ? unxml(m[2] ?? m[3] ?? "") : null;
};

/** Every relationship in the package. (A regex, not an XML parser: .rels
 * parts are small and flat, and this reads the same on any of them.) */
export function rels(zip: Zip): Rel[] {
	const out: Rel[] = [];
	for (const name of zip.names()) {
		const m = /^(.*?)_rels\/([^/]*)\.rels$/.exec(name);
		if (!m) continue;
		const from = `${m[1]}${m[2]}`;
		const xml = zip.text(name, 8 * 1024 * 1024);
		if (!xml) continue;
		for (const tag of xml.match(/<(?:\w+:)?Relationship\b[^>]*>/g) ?? []) {
			const type = attr(tag, "Type") ?? "";
			out.push({ from, id: attr(tag, "Id") ?? "", type: type.split("/").pop() ?? type, target: attr(tag, "Target") ?? "", external: (attr(tag, "TargetMode") ?? "").toLowerCase() === "external" });
		}
	}
	return out;
}

/** An address as a fact shows it: trimmed, and never more than 120 characters. */
export function shortUrl(u: string): string {
	const s = u.trim().replace(/\s+/g, " ");
	return s.length > 120 ? `${s.slice(0, 117)}…` : s;
}

const isUnc = (t: string) => /^(\\\\|file:)/i.test(t.trim());

/** A list for a fact: the first few, then "…". */
export function some(items: string[], n = 3): string {
	const uniq = [...new Set(items)];
	return uniq.slice(0, n).join(" · ") + (uniq.length > n ? " · …" : "");
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * The facts every OOXML file gets: macros, embedded objects and controls,
 * what it would fetch from outside, its links, a signature.
 * `app` names the program, for the facts that read better with it
 * ("when opened in Word").
 */
export function packageFacts(zip: Zip, all: Rel[], app: "Word" | "Excel" | "PowerPoint"): { facts: Fact[]; links: string[] } {
	const facts: Fact[] = [];
	const names = zip.names();
	if (names.some((n) => /(^|\/)vbaProject\.bin$/i.test(n))) {
		const signed = names.some((n) => /vbaProjectSignature/i.test(n));
		facts.push({ level: "warn", text: `Contains macros (a VBA project${signed ? ", signed — the signature was not checked" : ""}) — none of it was run` });
	}
	const embedded = names.filter((n) => /\/embeddings\/[^/]+$/i.test(n)).map((n) => n.split("/").pop()!);
	if (embedded.length) facts.push({ level: "warn", text: `Embeds ${plural(embedded.length, "object")}: ${some(embedded)} — not opened` });
	const activeX = names.filter((n) => /\/activeX\/activeX\d+\.xml$/i.test(n));
	if (activeX.length) facts.push({ level: "warn", text: `Has ${plural(activeX.length, "ActiveX control")} — none of it was run` });

	const out = all.filter((r) => r.external && r.type !== "hyperlink");
	const template = out.filter((r) => /attachedTemplate/i.test(r.type));
	if (template.length) facts.push({ level: "warn", text: `Fetches its template from ${some(template.map((r) => shortUrl(r.target)), 2)} when opened in ${app} — the "template injection" trick (not fetched)` });
	const fetched = out.filter((r) => !/attachedTemplate|externalLinkPath/i.test(r.type));
	if (fetched.length) {
		const unc = fetched.some((r) => isUnc(r.target));
		facts.push({ level: "warn", text: `Fetches ${plural(fetched.length, "item")} from outside when opened in ${app} (${some(fetched.map((r) => r.type), 3)}): ${some(fetched.map((r) => shortUrl(r.target)), 2)}${unc ? " — a \\\\server path makes Windows offer the reader's sign-in hash" : ""} (not fetched)` });
	}
	if (all.some((r) => r.type === "aFChunk")) facts.push({ level: "warn", text: "Carries a raw HTML or MHT part (altChunk) — not shown" });
	if (names.some((n) => n.startsWith("_xmlsignatures/"))) facts.push({ level: "info", text: "Signed digitally — the signature was not checked here" });

	const links = all.filter((r) => r.type === "hyperlink" && r.external).map((r) => r.target);
	return { facts, links };
}

/**
 * Word's fields (in a .docx, a .doc or an RTF): Word computes each when it
 * updates them — and some compute by running or fetching something. The
 * dangerous kinds become facts; HYPERLINK fields add to `links`.
 */
export function fieldFacts(codes: string[], links: string[]): Fact[] {
	const facts: Fact[] = [];
	const seen = new Set<string>();
	for (const code of codes) {
		const word = (code.trim().split(/\s+/)[0] ?? "").toUpperCase();
		const quoted = /"([^"]+)"/.exec(code)?.[1] ?? "";
		let fact: Fact | null = null;
		if (word === "DDE" || word === "DDEAUTO") fact = { level: "warn", text: `Has a ${word} field, which runs a program when Word updates it${word === "DDEAUTO" ? " — on opening" : ""}: “${shortUrl(code.trim())}” (not run)` };
		else if (/^(INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)$/.test(word) && /(https?:|\\\\|file:)/i.test(code)) fact = { level: "warn", text: `Has an ${word} field that fetches from outside when updated: ${shortUrl(quoted || code)} (not fetched)` };
		else if (word === "MACROBUTTON") fact = { level: "warn", text: "Has a MACROBUTTON field (runs a macro when double-clicked) — not run" };
		else if (word === "HYPERLINK" && quoted && !/\\l\s/.test(code)) links.push(quoted);
		if (fact && !seen.has(fact.text)) {
			seen.add(fact.text);
			facts.push(fact);
		}
	}
	return facts;
}

/** The "Links to …" fact, from every link the reader collected. */
export function linkFact(links: string[]): Fact | null {
	const uniq = [...new Set(links.map((l) => l.trim()).filter(Boolean))];
	if (!uniq.length) return null;
	return { level: "warn", text: `Links to ${plural(uniq.length, "address", "addresses")} (not followed): ${some(uniq.map(shortUrl), 3)}` };
}

/** docProps/core.xml and app.xml, as the words of a fact. */
export function propsWords(zip: Zip): string[] {
	const core = zip.text("docProps/core.xml", 1024 * 1024) ?? "";
	const app = zip.text("docProps/app.xml", 1024 * 1024) ?? "";
	const tag = (xml: string, name: string) => {
		const m = new RegExp(`<(?:\\w+:)?${name}\\b[^>]*>([^<]*)</(?:\\w+:)?${name}>`).exec(xml);
		return m ? unxml(m[1]!).trim().slice(0, 80) : "";
	};
	const day = (s: string) => (/^\d{4}-\d\d-\d\d/.test(s) ? s.slice(0, 10) : "");
	const said: string[] = [];
	const title = tag(core, "title");
	const author = tag(core, "creator");
	const last = tag(core, "lastModifiedBy");
	if (title) said.push(`title ${title}`);
	if (author) said.push(`author ${author}`);
	if (last && last !== author) said.push(`last saved by ${last}`);
	if (day(tag(core, "created"))) said.push(`made ${day(tag(core, "created"))}`);
	if (day(tag(core, "modified"))) said.push(`changed ${day(tag(core, "modified"))}`);
	const program = tag(app, "Application");
	if (program) said.push(program);
	const company = tag(app, "Company");
	if (company) said.push(`company ${company}`);
	const template = tag(app, "Template");
	if (template && !/^Normal\.dot[mx]?$/i.test(template)) said.push(`template ${template}`);
	return said;
}

/**
 * A file that is not a ZIP but an OLE container holding EncryptedPackage
 * is an OOXML file protected with a password. Nothing can be shown, but it
 * is worth saying — attackers send password-protected documents (the
 * password in the email) because mail scanners cannot look inside either.
 */
export function encryptedOoxml(bytes: Uint8Array): boolean {
	if (!Ole.is(bytes)) return false;
	const ole = Ole.open(bytes);
	return !!ole && ole.has("EncryptedPackage");
}

/** The frame's notice for a file that cannot be shown, and its one fact. */
export function refusal(root: HTMLElement, title: string, why: string): void {
	const p = document.createElement("p");
	p.className = "notice";
	const strong = document.createElement("strong");
	strong.textContent = title;
	p.append(strong, document.createElement("br"), why);
	root.replaceChildren(p);
}
