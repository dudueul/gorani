// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a Word (.docx) file carries besides its pages (commit 42b,
 * docs/PREVIEWS.md › Word): read from its parts, pure — no DOM, no
 * rendering — so unit:preview-facts runs it on the fixtures in Node, and
 * readers/docx.ts shows what it returns.
 */

import type { Fact } from "../host.ts";
import { fieldFacts, linkFact, packageFacts, plural, propsWords, rels, shortUrl, some, unxml } from "../office.ts";
import type { Zip } from "../zip.ts";

/** What a security team should know about this Word file. */
export function docxFacts(zip: Zip): Fact[] {
	const all = rels(zip);
	const { facts, links } = packageFacts(zip, all, "Word");

	// The text parts: the body, headers, footers, notes.
	const parts = zip.names().filter((n) => /^word\/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$/.test(n));
	const codes: string[] = [];
	let hidden: string[] = [];
	let inserted = 0;
	let deleted: string[] = [];
	let deletions = 0;
	for (const name of parts) {
		const xml = zip.text(name, 32 * 1024 * 1024);
		if (!xml) continue;
		codes.push(...fieldCodes(xml));
		if (name === "word/document.xml") {
			hidden = hiddenText(xml);
			inserted = (xml.match(/<w:ins\b/g) ?? []).length;
			deletions = (xml.match(/<w:del\b/g) ?? []).length;
			deleted = [...xml.matchAll(/<w:delText\b[^>]*>([^<]*)<\/w:delText>/g)].map((m) => unxml(m[1]!));
		}
	}

	facts.push(...fieldFacts(codes, links));
	if (hidden.length) facts.push({ level: "warn", text: `Has hidden text (not shown, as in Word): “${shortUrl(hidden.join(" "))}”` });
	if (inserted || deletions) {
		const gone = deleted.join("").trim();
		facts.push({ level: "info", text: `Has tracked changes (${plural(inserted, "insertion")}, ${plural(deletions, "deletion")}) — shown accepted${gone ? `; the deleted text: “${shortUrl(gone)}”` : ""}` });
	}
	const comments = zip.text("word/comments.xml", 8 * 1024 * 1024);
	if (comments) {
		const n = (comments.match(/<w:comment\b/g) ?? []).length;
		const by = [...comments.matchAll(/<w:comment\b[^>]*\sw:author="([^"]*)"/g)].map((m) => unxml(m[1]!));
		if (n) facts.push({ level: "info", text: `Has ${plural(n, "comment")}${by.length ? ` by ${some(by)}` : ""} — not shown` });
	}
	if (zip.names().some((n) => /^word\/fonts\/.+\.odttf$/i.test(n))) facts.push({ level: "info", text: "Embeds fonts — not loaded (the text is drawn in this computer's fonts)" });
	const link = linkFact(links);
	if (link) facts.push(link);

	const app = zip.text("docProps/app.xml", 1024 * 1024) ?? "";
	const pages = /<Pages>(\d+)<\/Pages>/.exec(app)?.[1];
	facts.unshift({ level: "info", text: [pages ? `${plural(Number(pages), "page")} (as Word last counted)` : "", ...propsWords(zip)].filter(Boolean).join(" · ") || "A Word document" });
	return facts;
}

/**
 * The field codes in a part, in order. A field is `begin`, its code (in
 * one or more instrText runs), `separate`, its last result, `end` — and
 * fields nest; a simple field is one element with the code in w:instr.
 */
export function fieldCodes(xml: string): string[] {
	const codes: string[] = [];
	const stack: (string[] | null)[] = [];
	const re = /<w:fldChar\b[^>]*w:fldCharType="(begin|separate|end)"[^>]*>|<w:instrText\b[^>]*>([^<]*)<\/w:instrText>|<w:fldSimple\b[^>]*\sw:instr="([^"]*)"/g;
	for (const m of xml.matchAll(re)) {
		if (m[1] === "begin") stack.push([]);
		else if (m[1] === "separate" || m[1] === "end") {
			const top = stack.pop();
			if (top?.length) codes.push(unxml(top.join("")));
			if (m[1] === "separate") stack.push(null); // its result follows, until end
		} else if (m[2] !== undefined) stack.at(-1)?.push(m[2]);
		else if (m[3] !== undefined) codes.push(unxml(m[3]));
		if (codes.length > 2000) break;
	}
	return codes;
}

/** The text of runs marked hidden (w:vanish), as one would read it. */
function hiddenText(xml: string): string[] {
	const out: string[] = [];
	for (const run of xml.matchAll(/<w:r\b[^>]*>([\s\S]*?)<\/w:r>/g)) {
		const body = run[1]!;
		if (!/<w:vanish\b(?![^>]*w:val="(?:false|0|off)")[^>]*\/>/.test(body)) continue;
		for (const t of body.matchAll(/<w:t\b[^>]*>([^<]*)<\/w:t>/g)) out.push(unxml(t[1]!));
		if (out.join("").length > 400) break;
	}
	return out.filter((t) => t.trim());
}
