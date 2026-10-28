// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * OpenDocument text and slides (.odt .ott .odp .otp — LibreOffice's, and
 * what Hancom Office saves as "ODF") — their text and facts (commit 42b).
 * The sheets (.ods) go to the spreadsheet reader instead.
 *
 * An ODF file is a ZIP (zip.ts, its bomb check first) whose content.xml is
 * the document. It is parsed with DOMParser as XML — an inert document:
 * nothing in it loads or runs, and the frame's Trusted Types default lets
 * exactly this sink through (host.ts) — and only its text is taken. Facts:
 *
 *   Basic/, Scripts/          macros (LibreOffice Basic, scripts)
 *   script:event-listener     a macro bound to an event (on opening…)
 *   Object N/                 embedded objects
 *   xlink:href to http(s)     links, and pictures linked from outside
 *   META-INF/manifest.xml     encryption (a password)
 *   meta.xml                  who and when
 */

import type { Fact } from "../host.ts";
import { linkFact, plural, shortUrl, some } from "../office.ts";
import type { Zip } from "../zip.ts";
import { paragraphs, type Legacy, type Section } from "./types.ts";

const NS = {
	text: "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
	draw: "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0",
	presentation: "urn:oasis:names:tc:opendocument:xmlns:presentation:1.0",
	office: "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
	xlink: "http://www.w3.org/1999/xlink",
	script: "urn:oasis:names:tc:opendocument:xmlns:script:1.0",
};

export function readOdf(zip: Zip, slides: boolean): Legacy {
	const kind = slides ? "an OpenDocument presentation" : "an OpenDocument text";
	const facts: Fact[] = [{ level: "info", text: metaWords(zip).join(" · ") }];
	const names = zip.names();
	if (/<manifest:encryption-data\b/.test(zip.text("META-INF/manifest.xml", 1024 * 1024) ?? "")) {
		facts.push({ level: "warn", text: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" });
		return { kind, sections: [], facts, refused: { title: "This document is protected with a password.", why: "It cannot be shown here." } };
	}
	const macros = names.filter((n) => /^(Basic|Scripts)\/.+\.(xml|js|py|bsh)$/i.test(n) && !/script-lc\.xml|script-lb\.xml|dialog-lc\.xml/i.test(n));
	if (macros.length) facts.push({ level: "warn", text: `Contains macros (${some(macros.map((n) => n.split("/").slice(-2).join("/")))}) — none of it was run` });
	const objects = new Set(names.filter((n) => /^Object \d+\//.test(n)).map((n) => n.split("/")[0]!));
	if (objects.size) facts.push({ level: "warn", text: `Embeds ${plural(objects.size, "object")} — not opened` });

	const xml = zip.text("content.xml", 64 * 1024 * 1024);
	const doc = xml ? new DOMParser().parseFromString(xml, "application/xml") : null;
	if (!doc || doc.getElementsByTagName("parsererror").length) return { kind, sections: [], facts, refused: { title: "This document does not open.", why: "Its content is damaged." } };

	const events = [...doc.getElementsByTagNameNS(NS.script, "event-listener")].map((e) => `${e.getAttributeNS(NS.script, "event-name") ?? "?"} → ${e.getAttributeNS(NS.xlink, "href") ?? e.getAttributeNS(NS.script, "macro-name") ?? "?"}`);
	if (events.length) facts.push({ level: "warn", text: `Runs macros on events: ${some(events.map(shortUrl), 2)} — not run` });
	const links = [...doc.getElementsByTagNameNS(NS.text, "a")].map((a) => a.getAttributeNS(NS.xlink, "href") ?? "").filter((h) => /^[a-z]+:/i.test(h));
	const outside = [...doc.getElementsByTagNameNS(NS.draw, "image")].map((im) => im.getAttributeNS(NS.xlink, "href") ?? "").filter((h) => /^(https?:|\\\\|file:)/i.test(h));
	if (outside.length) facts.push({ level: "warn", text: `Fetches ${plural(outside.length, "picture")} from outside when opened: ${some(outside.map(shortUrl), 2)} (not fetched)` });
	const link = linkFact(links);
	if (link) facts.push(link);

	const sections: Section[] = [];
	if (slides) {
		[...doc.getElementsByTagNameNS(NS.draw, "page")].forEach((page, i) => {
			const notes = page.getElementsByTagNameNS(NS.presentation, "notes")[0];
			notes?.remove();
			sections.push({ title: `Slide ${i + 1}`, paras: textOf(page), notes: notes ? textOf(notes).join(" ") || undefined : undefined });
		});
		facts[0] = { level: "info", text: [plural(sections.length, "slide"), facts[0]!.text].filter(Boolean).join(" · ") };
	} else {
		const body = doc.getElementsByTagNameNS(NS.office, "text")[0];
		sections.push({ paras: body ? textOf(body) : [] });
	}
	return { kind, sections, facts };
}

/** The paragraphs under a node: text:p and text:h, with ODF's spaces, tabs and breaks. */
function textOf(root: Element): string[] {
	const out: string[] = [];
	for (const p of root.querySelectorAll("*")) {
		if (p.namespaceURI !== NS.text || (p.localName !== "p" && p.localName !== "h")) continue;
		let s = "";
		const walk = (n: Node) => {
			for (const c of n.childNodes) {
				if (c.nodeType === Node.TEXT_NODE) s += c.nodeValue ?? "";
				else if (c.nodeType === Node.ELEMENT_NODE) {
					const e = c as Element;
					if (e.namespaceURI === NS.text && e.localName === "s") s += " ".repeat(Number(e.getAttributeNS(NS.text, "c") ?? 1) || 1);
					else if (e.namespaceURI === NS.text && e.localName === "tab") s += "\t";
					else if (e.namespaceURI === NS.text && e.localName === "line-break") s += "\n";
					else if (!(e.namespaceURI === NS.text && (e.localName === "p" || e.localName === "h"))) walk(e);
				}
			}
		};
		walk(p);
		out.push(...paragraphs(s));
		if (out.length > 100_000) break;
	}
	return out;
}

function metaWords(zip: Zip): string[] {
	const meta = zip.text("meta.xml", 1024 * 1024) ?? "";
	const tag = (name: string) => (new RegExp(`<${name}\\b[^>]*>([^<]*)</${name}>`).exec(meta)?.[1] ?? "").trim().slice(0, 80);
	const day = (s: string) => (/^\d{4}-\d\d-\d\d/.test(s) ? s.slice(0, 10) : "");
	const author = tag("meta:initial-creator");
	const last = tag("dc:creator");
	return [tag("dc:title") ? `title ${tag("dc:title")}` : "", author ? `author ${author}` : "", last && last !== author ? `last saved by ${last}` : "", day(tag("meta:creation-date")) ? `made ${day(tag("meta:creation-date"))}` : "", day(tag("dc:date")) ? `changed ${day(tag("dc:date"))}` : "", tag("meta:generator").split("/")[0] ?? ""].filter(Boolean);
}
