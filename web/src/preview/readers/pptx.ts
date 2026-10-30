// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The PowerPoint reader (commit 42b, docs/PREVIEWS.md › PowerPoint), on
 * pptx-preview (MIT) — with JSZip inside, and ECharts for a slide's
 * charts — inside the preview frame.
 *
 * pptx-preview is the one library here that writes a file's text as HTML:
 * each run of slide text goes into the page with `innerHTML`. A slide whose
 * text is `<img src=x onerror=…>` would be markup. In this frame that
 * string meets the default Trusted Types policy (host.ts) and goes through
 * DOMPurify before the browser parses it — the handler is gone, and the
 * picture's address is one the frame's CSP refuses to fetch. (A slide's
 * literal "<b>" may show bold for the same reason: a cosmetic cost of a
 * library that treats text as HTML, paid inside the frame.)
 *
 * What a slide deck can do that this reader does not, and SAYS: a "Run
 * program" or macro action on a click or a mouse-over, hidden slides
 * (drawn here, marked), pictures and media linked from outside, macros,
 * embedded objects, links. Speaker notes are shown under their slide.
 */

import { zipSync } from "fflate";
import { init } from "pptx-preview";
import { boot, el, type Host } from "../host.ts";
import { addCss, Finder, findCss, perFrame, Zoom } from "../kit.ts";
import { deckFacts, slidesOf, type SlideMeta } from "../facts/slides.ts";
import { withMacros } from "../facts/vba.ts";
import { macrosInZip, safely } from "../vba/macros.ts";
import { macroButton } from "../vba/pane.ts";
import { encryptedOoxml, refusal, rels, unxml } from "../office.ts";
import { Ole } from "../ole.ts";
import { MAX_PART, Zip } from "../zip.ts";
import pptxCss from "./pptx.css?inline";

/** Slides are drawn this wide, then zoomed to the window (kit.ts › Zoom). */
const WIDTH = 960;

export const start = boot(async (host) => {
	addCss(pptxCss, findCss);
	const bytes = new Uint8Array(host.file.bytes);
	const status = el("p", { class: "notice" }, "Opening the slides…");
	host.root.append(status);

	const zip = Zip.is(bytes) ? Zip.open(bytes) : null;
	if (!zip) {
		const locked = encryptedOoxml(bytes);
		refusal(host.root, locked ? "These slides are protected with a password." : "This is not a PowerPoint file this reader can open.", locked ? "They cannot be shown here." : Ole.is(bytes) ? "It is a PowerPoint 97–2003 file under a .pptx name." : "It may be damaged.");
		host.shown([locked ? { level: "warn", text: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" } : { level: "warn", text: "Not a PowerPoint (OOXML) file — it may be damaged, or another kind of file under this name" }]);
		return;
	}
	const trap = zip.check();
	if (trap) {
		refusal(host.root, "These slides are not opened.", `Their ZIP is a trap: ${trap}.`);
		host.shown([{ level: "warn", text: `Not opened: ${trap} — a "ZIP bomb"` }]);
		return;
	}
	const all = rels(zip);
	const deck = slidesOf(zip, all);
	// Its macros (42h): read, never run; the Macros button shows them.
	const macros = safely(() => macrosInZip(zip));
	const facts = withMacros(deckFacts(zip, all, deck), macros);

	const content = el("div", { class: "pptx-host" });
	const scroller = el("div", { class: "scroll", "data-test": "pptx-slides" }, content);
	host.root.append(scroller);
	let failed = "";
	try {
		await init(content, { width: WIDTH, mode: "list" }).preview(forRenderer(zip) ?? host.file.bytes);
	} catch (e) {
		failed = String(e instanceof Error ? e.message : e);
	}
	status.remove();
	scroller.remove();
	// A deck the library could not draw — damaged, or built unlike what
	// PowerPoint writes (perhaps to stop a reader like this one): its
	// slides' TEXT is shown instead, read from the XML directly, and the
	// fact says so.
	if (deck.length && !content.querySelector(".pptx-preview-slide-wrapper")) {
		asText(host, zip, deck);
		const mb = macroButton(host, macros);
		if (mb) host.root.prepend(el("div", { class: "bar" }, mb));
		host.shown([...facts, { level: "warn", text: `The slides could not be drawn${failed ? ` (${failed.slice(0, 80)})` : ""} — shown as their text; the file is damaged or built unusually` }]);
		return;
	}
	show(host, scroller, content, deck, macroButton(host, macros));
	host.shown(facts);
});

/**
 * The deck as the library gets it: pictures linked from OUTSIDE (an
 * <a:blip> with r:link and nothing embedded — the beacon trick) are taken
 * out first. pptx-preview fails the whole deck on one, and none could be
 * shown here anyway (the frame fetches nothing); the facts name them.
 * Null when there is nothing to take out (the file goes as it is).
 */
function forRenderer(zip: Zip): ArrayBuffer | null {
	const fixed = new Map<string, string>();
	for (const name of zip.names()) {
		if (!/^ppt\/(slides|slideLayouts|slideMasters)\/[^/]+\.xml$/.test(name)) continue;
		const xml = zip.text(name, 16 * 1024 * 1024);
		if (!xml) continue;
		const out = xml.replace(/<p:pic\b[^>]*>[\s\S]*?<\/p:pic>/g, (pic) => (/<a:blip\b[^>]*\sr:embed=/.test(pic) || !/<a:blip\b/.test(pic) ? pic : ""));
		if (out !== xml) fixed.set(name, out);
	}
	if (!fixed.size) return null;
	const files: Record<string, Uint8Array> = {};
	for (const e of zip.entries) {
		if (e.name.endsWith("/")) continue;
		const body = fixed.has(e.name) ? new TextEncoder().encode(fixed.get(e.name)!) : zip.bytesOf(e.name, MAX_PART);
		if (!body) return null;
		files[e.name] = body;
	}
	// Stored, not compressed again: it is read once, here.
	return zipSync(files, { level: 0 }).buffer as ArrayBuffer;
}

/** The fallback: each slide's paragraphs and notes, as text. */
function asText(host: Host, zip: Zip, deck: SlideMeta[]): void {
	const list = el("div", { class: "scroll pptx-text", "data-test": "pptx-slides" });
	deck.forEach((s, i) => {
		const xml = zip.text(s.part, 16 * 1024 * 1024) ?? "";
		const paras = [...xml.matchAll(/<a:p>([\s\S]*?)<\/a:p>/g)].map((p) => [...p[1]!.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map((t) => unxml(t[1]!)).join("")).filter((t) => t.trim());
		const card = el("section", { class: `card${s.hidden ? " hidden-slide" : ""}`, "data-test": "pptx-slide" }, el("h3", {}, `Slide ${i + 1}${s.hidden ? " — hidden" : ""}`), ...paras.map((p) => el("p", {}, p)));
		if (s.notes) card.append(el("p", { class: "muted" }, `Notes: ${s.notes}`));
		list.append(card);
	});
	host.root.append(list);
}

function show(host: Host, scroller: HTMLElement, content: HTMLElement, deck: SlideMeta[], macros: HTMLElement | null): void {
	const wrapper = () => content.querySelector<HTMLElement>(".pptx-preview-wrapper");
	const slides = [...content.querySelectorAll<HTMLElement>(".pptx-preview-slide-wrapper")];
	// Hidden slides marked; speaker notes under their slide (as text).
	slides.forEach((s, i) => {
		s.setAttribute("data-test", "pptx-slide");
		const meta = deck[i];
		if (meta?.hidden) {
			s.classList.add("hidden-slide");
			s.append(el("span", { class: "badge", "data-test": "pptx-hidden" }, "Hidden slide — PowerPoint skips it in a show"));
		}
		if (meta?.notes) s.after(el("div", { class: "notes", "data-test": "pptx-notes", style: `width:${WIDTH}px` }, el("strong", {}, "Notes "), meta.notes));
	});
	const zoom = new Zoom({
		natural: () => WIDTH + (host.phone ? 16 : 48),
		room: () => scroller.clientWidth,
		apply: (s) => {
			const w = wrapper();
			if (w) w.style.zoom = String(s);
		},
	});
	const finder = new Finder(wrapper, scroller, "Find in the slides");
	const label = el("span", { class: "muted", "data-test": "pptx-slide-label" });
	const current = () => {
		const v = scroller.getBoundingClientRect();
		const mid = v.top + v.height / 3;
		const i = slides.findIndex((s) => s.getBoundingClientRect().bottom >= mid);
		return i < 0 ? slides.length - 1 : i;
	};
	const goto = (i: number) => slides[Math.max(0, Math.min(slides.length - 1, i))]?.scrollIntoView({ block: "start", behavior: "smooth" });
	const prev = el("button", { title: "Previous slide", "aria-label": "Previous slide" }, "↑");
	const next = el("button", { title: "Next slide", "aria-label": "Next slide" }, "↓");
	prev.addEventListener("click", () => goto(current() - 1));
	next.addEventListener("click", () => goto(current() + 1));
	const update = () => (label.textContent = `${current() + 1} / ${slides.length}`);
	scroller.addEventListener("scroll", perFrame(update), { passive: true });
	const bar = el("div", { class: "bar" }, prev, next, label, el("span", { class: "sep" }), zoom.el, el("span", { class: "grow" }), ...(macros ? [macros] : []), finder.input, finder.found);
	host.root.append(bar, scroller);
	zoom.update();
	update();
	new ResizeObserver(perFrame(() => zoom.update())).observe(scroller);
}
