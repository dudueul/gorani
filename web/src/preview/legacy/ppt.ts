// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * PowerPoint 97–2003 (.ppt, .pps, .pot) — each slide's text and the deck's
 * facts, read by this file (commit 42b; Microsoft's [MS-PPT], published).
 *
 * The "PowerPoint Document" stream is a tree of records: an 8-byte header
 * (version and instance, type, length), and a container's children inside
 * it. Text is in TextCharsAtom (UTF-16) and TextBytesAtom (8-bit) records:
 * in each Slide container's drawing (text boxes), and in the outline
 * (SlideListWithText, the title and body placeholders, in show order).
 * The facts are records too:
 *
 *   InteractiveInfoAtom   a click or mouse-over action: 1 runs a macro,
 *                         2 runs a program, 5 an object's verb
 *   ExHyperlink           a link's address (a CString, instance 1)
 *   VBAInfo               a macro project
 *   ExOleObjStg           an embedded object; ExOleLink a linked one
 *   SlideShowSlideInfo    a slide's "hidden" bit
 */

import type { Fact } from "../host.ts";
import { linkFact, plural, some } from "../office.ts";
import { Ole, propertySet, summaryWords } from "../ole.ts";
import { containerFacts } from "./doc.ts";
import { paragraphs, type Legacy, type Section } from "./types.ts";

const T = {
	Slide: 0x03ee,
	Notes: 0x03f0,
	MainMaster: 0x03f8,
	SlideShowSlideInfo: 0x03f9,
	NotesAtom: 0x03f1,
	VBAInfoAtom: 0x0400,
	SlideListWithText: 0x0ff0,
	SlidePersist: 0x03f3,
	TextChars: 0x0fa0,
	TextBytes: 0x0fa8,
	CString: 0x0fba,
	ExHyperlink: 0x0fd7,
	InteractiveInfoAtom: 0x0ff3,
	VBAInfo: 0x03ff,
	ExOleObjStg: 0x1011,
	ExOleLink: 0x0fce,
};

export function readPpt(ole: Ole): Legacy {
	const kind = "a PowerPoint 97–2003 deck";
	const summary = propertySet(ole.stream("\u0005SummaryInformation"));
	const facts: Fact[] = [{ level: "info", text: "" }];
	facts.push(...containerFacts(ole, summary));
	const doc = ole.stream("PowerPoint Document");
	if (!doc) return { kind, sections: [], facts, refused: { title: "This PowerPoint file does not open.", why: "Its document stream is missing." } };
	if (ole.has("EncryptedSummary")) {
		facts.push({ level: "warn", text: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" });
		return { kind, sections: [], facts, refused: { title: "These slides are protected with a password.", why: "They cannot be shown here." } };
	}

	const v = new DataView(doc.buffer, doc.byteOffset, doc.byteLength);
	const utf16 = new TextDecoder("utf-16le");
	const cp1252 = new TextDecoder("windows-1252");
	const slides: { text: string[]; hidden: boolean }[] = [];
	const notes: { text: string[]; master: boolean }[] = [];
	const outline: string[][] = [];
	const links: string[] = [];
	const actions = { macro: 0, program: 0, ole: 0 };
	let vba = false;
	let embedded = 0;
	let linked = 0;
	let records = 0;

	/** Walk the records in [start, end); `path` is the containers we are in;
	 * `slideList`: inside the outline of the SLIDES (SlideListWithText,
	 * instance 0 — instances 1 and 2 list the masters and the notes). */
	const walk = (start: number, end: number, path: number[], slideList = false) => {
		// Real decks nest a dozen deep; a crafted one could nest until the
		// stack overflows.
		if (path.length > 64) return;
		let o = start;
		while (o + 8 <= end && records++ < 2_000_000) {
			const verInst = v.getUint16(o, true);
			const type = v.getUint16(o + 2, true);
			const len = v.getUint32(o + 4, true);
			const body = o + 8;
			const next = body + len;
			if (next > end || next < body) return; // damaged: stop here, keep what was read
			const inst = verInst >> 4;
			if ((verInst & 0xf) === 0xf) {
				if (type === T.Slide) slides.push({ text: [], hidden: false });
				if (type === T.Notes) notes.push({ text: [], master: false });
				if (type === T.ExOleLink) linked++;
				walk(body, next, [...path, type], type === T.SlideListWithText ? inst === 0 : slideList);
			} else {
				const inSlide = path.includes(T.Slide);
				const inNotes = path.includes(T.Notes);
				const inMaster = path.includes(T.MainMaster);
				const inOutline = slideList;
				if (type === T.SlidePersist && inOutline && path.at(-1) === T.SlideListWithText) outline.push([]);
				// The notes master's NotesAtom points at no slide — 0, or a master's
				// id (0x80000000 and up, as LibreOffice writes it): its "notes"
				// are placeholders.
				if (type === T.NotesAtom && len >= 4 && notes.length) {
					const ref = v.getUint32(body, true);
					if (ref === 0 || ref >= 0x80000000) notes.at(-1)!.master = true;
				}
				// Every deck LibreOffice writes has a VBAInfo record; whether it
				// HAS macros is this atom's fHasMacros.
				if (type === T.VBAInfoAtom && len >= 8 && v.getUint32(body + 4, true) === 1) vba = true;
				if (type === T.TextChars || type === T.TextBytes) {
					const text = (type === T.TextChars ? utf16.decode(doc.subarray(body, body + (len & ~1))) : cp1252.decode(doc.subarray(body, next))).replace(/\r|\u000b/g, "\n");
					if (inMaster) {
						// the master's placeholders ("Click to edit…"): not the deck's text
					} else if (inNotes) notes.at(-1)?.text.push(text);
					else if (inSlide) slides.at(-1)?.text.push(text);
					else if (inOutline) outline.at(-1)?.push(text);
				}
				if (type === T.CString && path.at(-1) === T.ExHyperlink && inst === 1) links.push(utf16.decode(doc.subarray(body, body + (len & ~1))));
				if (type === T.InteractiveInfoAtom && len >= 9) {
					const action = doc[body + 8];
					if (action === 1) actions.macro++;
					if (action === 2) actions.program++;
					if (action === 5) actions.ole++;
				}
				if (type === T.SlideShowSlideInfo && inSlide && len >= 11 && (doc[body + 10]! & 0x04)) {
					const s = slides.at(-1);
					if (s) s.hidden = true;
				}
				if (type === T.ExOleObjStg) embedded++;
			}
			o = next;
		}
	};
	walk(0, doc.length, []);
	const slideNotes = notes.filter((n) => !n.master).map((n) => n.text);

	// The outline holds what the placeholders say, in show order; the
	// slides' own records hold their text boxes. Shown together.
	const count = Math.max(slides.length, outline.length);
	const sections: Section[] = [];
	for (let i = 0; i < count; i++) {
		const text = [...(outline[i] ?? []), ...(slides[i]?.text ?? [])];
		const uniq = [...new Set(text.map((t) => t.trim()).filter(Boolean))];
		sections.push({ title: `Slide ${i + 1}`, paras: uniq.flatMap((t) => paragraphs(t)), hidden: slides[i]?.hidden, notes: (slideNotes[i] ?? []).join(" ").trim() || undefined });
	}

	facts[0] = { level: "info", text: [plural(count, "slide"), ...summaryWords(summary)].join(" · ") };
	if (vba && !facts.some((f) => f.text.startsWith("Contains macros"))) facts.push({ level: "warn", text: "Contains macros (a VBA project) — none of it was run" });
	if (actions.program) facts.push({ level: "warn", text: `Has ${plural(actions.program, "“Run program” action")} — PowerPoint runs it on a click or a mouse-over; not run here` });
	if (actions.macro || actions.ole) facts.push({ level: "warn", text: `Has macro or object actions (${actions.macro + actions.ole}) — not run` });
	if (embedded && !facts.some((f) => f.text.startsWith("Embeds"))) facts.push({ level: "warn", text: `Embeds ${plural(embedded, "object")} — not opened` });
	if (linked) facts.push({ level: "warn", text: `Links ${plural(linked, "object")} from outside files — not opened` });
	const hidden = sections.map((s, i) => (s.hidden ? i + 1 : 0)).filter(Boolean);
	if (hidden.length) facts.push({ level: "warn", text: `Hides ${plural(hidden.length, "slide")} (${some(hidden.map(String), 8)}) — shown here, marked` });
	const withNotes = sections.filter((s) => s.notes).length;
	if (withNotes) facts.push({ level: "info", text: `Has speaker notes on ${plural(withNotes, "slide")} — shown under ${withNotes === 1 ? "it" : "each"}` });
	const link = linkFact(links);
	if (link) facts.push(link);
	return { kind, sections, facts };
}
