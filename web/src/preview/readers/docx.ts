// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The Word reader (commit 42b, docs/PREVIEWS.md › Word), on docx-preview
 * (Volodymyr Baydalka, Apache-2.0), inside the preview frame.
 *
 * docx-preview turns the document's XML into HTML elements, built one by
 * one (it parses the XML with DOMParser and writes no HTML strings of its
 * own), so a crafted .docx cannot smuggle markup into the frame through
 * it — and if it could, the frame's default Trusted Types policy would
 * hand the string to DOMPurify first (host.ts). Its options, chosen for a
 * file that may be hostile:
 *
 *   renderAltChunks: false   an "altChunk" is raw HTML or MHT carried
 *                            inside the document; docx-preview would show
 *                            it in an <iframe srcdoc> (the frame's CSP
 *                            refuses frames anyway). Named in the facts.
 *   ignoreFonts: true        fonts embedded in the file are not loaded: a
 *                            font is a program the browser's font engine
 *                            runs, and an old attack surface. The text is
 *                            drawn in this computer's fonts.
 *   renderChanges: false     tracked changes show as Word shows them by
 *                            default — accepted; deleted text is hidden,
 *                            and QUOTED in the facts.
 *   useBase64URL: false      pictures become blob: URLs (allowed by the
 *                            frame's CSP; nothing off the computer is).
 *
 * What a Word file can do that this reader does not, and SAYS (facts):
 * macros, a template fetched from a server on open, DDE fields that run a
 * program, pictures linked from outside (a beacon, or a \\server path that
 * leaks a Windows sign-in hash), embedded objects, hidden text, links.
 */

import { renderAsync } from "docx-preview";
import { boot, el, type Host } from "../host.ts";
import { addCss, Finder, findCss, perFrame, Zoom } from "../kit.ts";
import { docxFacts } from "../facts/word.ts";
import { withMacros } from "../facts/vba.ts";
import { macrosInZip, safely } from "../vba/macros.ts";
import { macroButton } from "../vba/pane.ts";
import { encryptedOoxml, plural, refusal } from "../office.ts";
import { Ole } from "../ole.ts";
import { Zip } from "../zip.ts";
import docxCss from "./docx.css?inline";

export const start = boot(async (host) => {
	addCss(docxCss, findCss);
	const bytes = new Uint8Array(host.file.bytes);
	const status = el("p", { class: "notice" }, "Opening the document…");
	host.root.append(status);

	const zip = Zip.is(bytes) ? Zip.open(bytes) : null;
	if (!zip) {
		const locked = encryptedOoxml(bytes);
		refusal(host.root, locked ? "This document is protected with a password." : "This is not a Word document this reader can open.", locked ? "It cannot be shown here." : Ole.is(bytes) ? "It is a Word 97–2003 file under a .docx name." : "It may be damaged.");
		host.shown([locked ? { level: "warn", text: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" } : { level: "warn", text: "Not a Word (OOXML) document — it may be damaged, or another kind of file under this name" }]);
		return;
	}
	// Every part inflated and counted BEFORE docx-preview sees the file (zip.ts).
	const trap = zip.check();
	if (trap) {
		refusal(host.root, "This document is not opened.", `Its ZIP is a trap: ${trap}.`);
		host.shown([{ level: "warn", text: `Not opened: ${trap} — a "ZIP bomb"` }]);
		return;
	}
	// Its macros (42h): read, never run; the Macros button shows them.
	const macros = safely(() => macrosInZip(zip));
	const facts = withMacros(docxFacts(zip), macros);

	const content = el("div", { class: "docx-host" });
	const styles = el("div", { hidden: "" });
	const scroller = el("div", { class: "scroll", "data-test": "docx-pages" }, styles, content);
	try {
		await renderAsync(host.file.bytes, content, styles, {
			inWrapper: true,
			ignoreWidth: false,
			ignoreHeight: false,
			ignoreFonts: true,
			breakPages: true,
			ignoreLastRenderedPageBreak: true,
			experimental: true,
			trimXmlDeclaration: true,
			useBase64URL: false,
			renderChanges: false,
			renderHeaders: true,
			renderFooters: true,
			renderFootnotes: true,
			renderEndnotes: true,
			renderComments: false,
			renderAltChunks: false,
			debug: false,
		});
	} catch (e) {
		refusal(host.root, "This document does not open.", String(e instanceof Error ? e.message : e));
		// (Its macros are still shown: a lure's document is often only a shell for them.)
		const mb = macroButton(host, macros);
		if (mb) host.root.prepend(el("div", { class: "bar" }, mb));
		host.shown([{ level: "warn", text: "The document did not open: it may be damaged" }, ...facts]);
		return;
	}
	status.remove();
	show(host, scroller, content, macroButton(host, macros));
	host.shown(facts);
});

function show(host: Host, scroller: HTMLElement, content: HTMLElement, macros: HTMLElement | null): void {
	const wrapper = () => content.querySelector<HTMLElement>(".docx-wrapper");
	const zoom = new Zoom({
		// The widest page, at 100 % (docx-preview gives each its real width).
		natural: () => Math.max(0, ...[...content.querySelectorAll<HTMLElement>("section.docx")].map((s) => s.offsetWidth)) + (host.phone ? 16 : 48),
		room: () => scroller.clientWidth,
		apply: (s) => {
			const w = wrapper();
			if (w) w.style.zoom = String(s);
		},
		// A page fitted to a wide window would be bigger than paper; 125 % is plenty.
	}, 1.25);
	const finder = new Finder(wrapper, scroller, "Find in the document");
	const pages = content.querySelectorAll("section.docx").length;
	const bar = el("div", { class: "bar" }, el("span", { class: "muted", "data-test": "docx-pages-count" }, plural(pages, "page")), el("span", { class: "sep" }), zoom.el, el("span", { class: "grow" }), ...(macros ? [macros] : []), finder.input, finder.found);
	host.root.append(bar, scroller);
	zoom.update();
	new ResizeObserver(perFrame(() => zoom.update())).observe(scroller);
}
