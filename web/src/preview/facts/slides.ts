// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a PowerPoint (.pptx) deck carries besides its slides (commit 42b,
 * docs/PREVIEWS.md › PowerPoint): its slides in show order (hidden or not,
 * with their speaker notes), and its facts. Pure — no DOM — so
 * unit:preview-facts runs it on the fixtures in Node.
 */

import type { Fact } from "../host.ts";
import { linkFact, packageFacts, plural, propsWords, shortUrl, some, unxml, type Rel } from "../office.ts";
import type { Zip } from "../zip.ts";

export interface SlideMeta {
	part: string;
	hidden: boolean;
	notes: string;
}

/** The slides in show order (presentation.xml's list), each with whether
 * it is hidden and its speaker notes. */
export function slidesOf(zip: Zip, all: Rel[]): SlideMeta[] {
	const pres = zip.text("ppt/presentation.xml", 8 * 1024 * 1024) ?? "";
	const byId = new Map(all.filter((r) => r.from === "ppt/presentation.xml").map((r) => [r.id, r.target]));
	const out: SlideMeta[] = [];
	for (const m of pres.matchAll(/<p:sldId\b[^>]*\sr:id="([^"]+)"/g)) {
		const target = byId.get(m[1]!);
		if (!target) continue;
		const part = `ppt/${target.replace(/^\/?ppt\//, "")}`.replace(/\/[^/]+\/\.\.\//g, "/");
		const xml = zip.text(part, 16 * 1024 * 1024) ?? "";
		const hidden = /<p:sld\b[^>]*\sshow="(0|false)"/.test(xml);
		const notesRel = all.find((r) => r.from === part && r.type === "notesSlide");
		let notes = "";
		if (notesRel) {
			const notesPart = `ppt/slides/${notesRel.target}`.replace(/[^/]+\/\.\.\//g, "");
			const nx = zip.text(notesPart, 4 * 1024 * 1024) ?? "";
			// The notes' body placeholder (not the slide image, not the number).
			const body = [...nx.matchAll(/<p:sp>([\s\S]*?)<\/p:sp>/g)].map((s) => s[1]!).filter((s) => /<p:ph\b[^>]*type="body"/.test(s));
			notes = body.flatMap((s) => [...s.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map((t) => unxml(t[1]!))).join(" ").trim();
		}
		out.push({ part, hidden, notes });
	}
	return out;
}

/** What a security team should know about this deck. */
export function deckFacts(zip: Zip, all: Rel[], deck: SlideMeta[]): Fact[] {
	const { facts, links } = packageFacts(zip, all, "PowerPoint");
	// Click and mouse-over actions: ppaction://program runs a program,
	// ppaction://macro a macro, ppaction://ole an embedded object's verb.
	const programs: string[] = [];
	const macros: string[] = [];
	let hover = 0;
	const usedByAction = new Set<string>();
	deck.forEach((s, i) => {
		const xml = zip.text(s.part, 16 * 1024 * 1024) ?? "";
		for (const m of xml.matchAll(/<a:(hlinkClick|hlinkHover)\b([^>]*)>/g)) {
			const action = /\saction="([^"]*)"/.exec(m[2]!)?.[1] ?? "";
			const rid = /\sr:id="([^"]*)"/.exec(m[2]!)?.[1] ?? "";
			const target = all.find((r) => r.from === s.part && r.id === rid)?.target ?? "";
			if (/^ppaction:\/\/program/i.test(action)) {
				programs.push(`${shortUrl(target || "?")} (slide ${i + 1})`);
				usedByAction.add(target);
			} else if (/^ppaction:\/\/(macro|ole)/i.test(action)) macros.push(`${unxml(action)} (slide ${i + 1})`);
			if (m[1] === "hlinkHover" && (action || target)) hover++;
		}
	});
	if (programs.length) facts.push({ level: "warn", text: `Has a “Run program” action: ${some(programs, 2)} — PowerPoint runs it on a click; not run here` });
	if (macros.length) facts.push({ level: "warn", text: `Has macro or object actions: ${some(macros, 2)} — not run` });
	if (hover) facts.push({ level: "warn", text: `Has ${plural(hover, "action")} that fire when the mouse merely passes over — not run` });
	const hidden = deck.map((s, i) => (s.hidden ? i + 1 : 0)).filter(Boolean);
	if (hidden.length) facts.push({ level: "warn", text: `Hides ${plural(hidden.length, "slide")} (${hidden.join(", ")}) — shown here, marked` });
	const notes = deck.filter((s) => s.notes).length;
	if (notes) facts.push({ level: "info", text: `Has speaker notes on ${plural(notes, "slide")} — shown under ${notes === 1 ? "it" : "each"}` });
	const comments = zip.names().filter((n) => /^ppt\/comments\/[^/]+\.xml$/i.test(n)).length;
	if (comments) facts.push({ level: "info", text: `Has comments (${comments} part${comments === 1 ? "" : "s"}) — not shown` });
	const link = linkFact(links.filter((l) => !usedByAction.has(l)));
	if (link) facts.push(link);
	facts.unshift({ level: "info", text: [plural(deck.length, "slide"), ...propsWords(zip)].join(" · ") });
	return facts;
}
