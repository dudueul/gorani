// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The legacy reader (commit 42b, docs/PREVIEWS.md › Older formats): Word
 * and PowerPoint 97–2003, RTF, OpenDocument text and slides — and web
 * pages and web archives (MHT) sent under a document's name. No library
 * draws these faithfully in a browser any more, and they are exactly the
 * formats old exploits ride in, so this reader does the part that matters
 * for triage: it reads each file's TEXT and its FACTS with small parsers of
 * our own (preview/legacy/*.ts), and shows the text as plain paragraphs —
 * built as text nodes, never as HTML.
 *
 * It also says when a file is not what its name says. The app picked this
 * reader from the name and corrected it from the first bytes
 * (ui/viewer/mode.ts › sniffReader); a ".doc" that is RTF, or a web
 * archive, is a disguise worth a fact of its own.
 */

import { boot, el, type Fact, type Host } from "../host.ts";
import { addCss, Finder, findCss } from "../kit.ts";
import { refusal } from "../office.ts";
import { readDoc } from "../legacy/doc.ts";
import { readOdf } from "../legacy/odf.ts";
import { readPpt } from "../legacy/ppt.ts";
import { readRtf } from "../legacy/rtf.ts";
import type { Legacy } from "../legacy/types.ts";
import { readWeb } from "../legacy/web.ts";
import { Ole } from "../ole.ts";
import { withMacros } from "../facts/vba.ts";
import { macrosInOle, macrosInPpt, macrosInZip, safely, type Macros } from "../vba/macros.ts";
import { macroButton } from "../vba/pane.ts";
import { Zip } from "../zip.ts";
import legacyCss from "./legacy.css?inline";

export const start = boot(async (host) => {
	addCss(legacyCss, findCss);
	const bytes = new Uint8Array(host.file.bytes);
	const ext = host.file.name.includes(".") ? host.file.name.split(".").pop()!.toLowerCase() : "";
	const head = new TextDecoder("latin1").decode(bytes.subarray(0, 1024));
	let read: Legacy | null = null;
	let refused: { title: string; why: string; fact: string } | null = null;
	// Its macros (42h): Word 97's Macros/, PowerPoint 97's compressed
	// project, OpenDocument's Basic — read, never run.
	let macros: Macros | null = null;

	if (head.startsWith("{\\rtf")) read = readRtf(bytes);
	else if (Ole.is(bytes)) {
		const ole = Ole.open(bytes);
		if (!ole) refused = { title: "This file does not open.", why: "Its OLE container is damaged.", fact: "Not readable: its OLE container is damaged" };
		else if (ole.has("EncryptedPackage")) refused = { title: "This Office file is protected with a password.", why: "It cannot be shown here.", fact: "Protected with a password — it cannot be shown, and mail scanners could not look inside it either" };
		else if (ole.has("WordDocument")) {
			read = readDoc(ole);
			macros = safely(() => macrosInOle(ole));
		} else if (ole.has("PowerPoint Document")) {
			read = readPpt(ole);
			macros = safely(() => macrosInPpt(ole));
		}
		else refused = { title: "This is an OLE file this reader does not show.", why: ole.has("Workbook") || ole.has("Book") ? "It is an Excel 97–2003 workbook." : "Its streams are not a Word or PowerPoint document's.", fact: `An OLE container holding: ${ole.paths.slice(0, 6).join(", ")}` };
	} else if (Zip.is(bytes)) {
		const zip = Zip.open(bytes);
		const trap = zip ? zip.check() : "its ZIP directory is damaged";
		if (trap || !zip) refused = { title: "This file is not opened.", why: `Its ZIP is a trap: ${trap}.`, fact: `Not opened: ${trap} — a "ZIP bomb"` };
		else {
			const mime = (zip.text("mimetype", 256) ?? "").trim();
			if (/opendocument\.(text|presentation)/.test(mime)) {
				read = readOdf(zip, mime.includes("presentation"));
				macros = safely(() => macrosInZip(zip));
			}
			else refused = { title: "This ZIP is not a document this reader shows.", why: mime ? `It says it is ${mime}.` : "It has no mimetype entry.", fact: `A ZIP archive, not ${ext ? `the .${ext} its name says` : "a document"}` };
		}
	} else if (/^\s*MIME-Version:/im.test(head.slice(0, 512)) || /^\s*From:|^\s*Content-Type:\s*multipart\/related/im.test(head.slice(0, 512))) read = readWeb(bytes, true);
	else if (/<(html|!doctype html|\?xml[^>]*>\s*<html)|xmlns:o="urn:schemas-microsoft-com:office/i.test(head)) read = readWeb(bytes, false);
	else refused = { title: "This file is not a document this reader knows.", why: "Its first bytes are not Word's, PowerPoint's, RTF's or OpenDocument's.", fact: `Not a ${ext ? `.${ext}` : "document"} file — its contents are of another kind` };

	if (refused || !read) {
		refusal(host.root, refused?.title ?? "This file does not open.", refused?.why ?? "");
		host.shown([{ level: "warn", text: refused?.fact ?? "The file did not open" }]);
		return;
	}
	const facts = withMacros(read.facts.filter((f) => f.text), macros);
	const disguise = mismatch(ext, read.kind);
	if (disguise) facts.splice(1, 0, disguise);
	facts[0] = { level: "info", text: [capital(read.kind), facts[0]?.level === "info" ? facts[0].text : ""].filter(Boolean).join(" · ") };
	if (read.refused) {
		refusal(host.root, read.refused.title, read.refused.why);
		host.shown(facts);
		return;
	}
	show(host, read, macroButton(host, macros));
	host.shown(facts);
});

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** A name that promises one format over the bytes of another. */
function mismatch(ext: string, kind: string): Fact | null {
	const expected: Record<string, RegExp> = { doc: /Word 97/, dot: /Word 97/, ppt: /PowerPoint 97/, pps: /PowerPoint 97/, pot: /PowerPoint 97/, rtf: /RTF/, odt: /OpenDocument text/, ott: /OpenDocument text/, odp: /OpenDocument presentation/, otp: /OpenDocument presentation/ };
	const want = expected[ext];
	if (!want || want.test(kind)) return null;
	// RTF or a web archive under a Word name is how exploits travel; say so loudly.
	const loud = /RTF|MHT|HTML/.test(kind);
	return { level: loud ? "warn" : "info", text: `Named .${ext}, but it is ${kind}${loud ? " — a disguise lures use: Word opens it all the same" : ""}` };
}

function show(host: Host, read: Legacy, macros: HTMLElement | null): void {
	const scroller = el("div", { class: "scroll paper-ground", "data-test": "legacy-text" });
	const decks = read.sections.length > 1 || !!read.sections[0]?.title;
	for (const s of read.sections) {
		const sheet = el("section", { class: `${decks ? "card" : "paper"}${s.hidden ? " hidden-slide" : ""}`, "data-test": decks ? "legacy-slide" : "legacy-page" });
		if (s.title) sheet.append(el("h3", {}, `${s.title}${s.hidden ? " — hidden" : ""}`));
		for (const p of s.paras) sheet.append(el("p", {}, p));
		if (!s.paras.length) sheet.append(el("p", { class: "muted" }, decks ? "(no text on this slide)" : "(no text)"));
		if (s.notes) sheet.append(el("p", { class: "notes" }, `Notes: ${s.notes}`));
		scroller.append(sheet);
	}
	const finder = new Finder(() => scroller, scroller, "Find in the text");
	// The parsers read every piece of text the file holds — hidden text and
	// deleted revisions included, which Word would not show. Said here.
	const bar = el("div", { class: "bar" }, el("span", { class: "muted", title: "Read by Gorani's own parser: the words, not the layout — hidden and deleted text included" }, `Text only (all of it, hidden included) — ${read.kind}`), el("span", { class: "grow" }), ...(macros ? [macros] : []), finder.input, finder.found);
	host.root.append(bar, scroller);
}
