// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The viewer's mode picker: which renderer a file gets, decided from the
 * decrypted name/mime and size. Pure, Node-testable — and a security rule
 * set as much as a UX table (see the module docs in viewer.ts).
 */

import { pickViewerMode, readerFor, renderMime, sniffReader, MAX_INLINE } from "../../web/src/ui/viewer/mode.ts";
import assert from "node:assert/strict";

// (The signature is (kind, mime, size[, policy]). Until commit 29e half of
// these calls passed a file NAME as the mime and the size as a fourth
// argument the function did not have — they passed because the kind
// decided alone. A fourth parameter now exists, and would have read "100"
// as a policy: the calls say what they mean again.)

// Images by kind and by mime.
assert.equal(pickViewerMode("image", null, 100), "image");
assert.equal(pickViewerMode("file", "image/webp", 100), "image");

// Media plays inline under the size cap.
assert.equal(pickViewerMode("video", null, 1024), "video");
assert.equal(pickViewerMode("audio", "audio/flac", 1024), "audio");

// Text/code render escaped; markdown is text too.
assert.equal(pickViewerMode("text", null, 10), "text");
assert.equal(pickViewerMode("code", null, 10), "text");
assert.equal(pickViewerMode("file", "text/markdown", 10), "text");

// The size cap is for what is read WHOLE to be shown: an image. Video and
// audio stream at any size, and text opens only its head (39w — the cap
// used to come first, so a film over 256 MB had "no preview" at all).
assert.equal(pickViewerMode("image", "image/png", MAX_INLINE + 1), "too-large");
assert.equal(pickViewerMode("image", "image/png", MAX_INLINE), "image", "at the cap, still shown");
assert.equal(pickViewerMode("video", null, 20 * 1024 ** 3), "video", "a 20 GB film streams");
assert.equal(pickViewerMode("audio", "audio/flac", MAX_INLINE + 1), "audio", "so does a long recording");
assert.equal(pickViewerMode("text", "text/plain", MAX_INLINE + 1), "text", "a big log opens its first part");
// PDFs open in the sandboxed preview frame (42a, sandbox.ts) — by kind, by
// mime or by name — read whole into it, so they meet the same cap.
assert.equal(pickViewerMode("pdf", "application/pdf", 10), "document");
assert.equal(pickViewerMode("file", "application/pdf", 10), "document", "by its mime");
assert.equal(pickViewerMode("file", null, 10, "normal", "report.PDF"), "document", "by its name");
assert.equal(pickViewerMode("pdf", "application/pdf", MAX_INLINE + 1), "too-large", "read whole, so capped");
assert.equal(pickViewerMode("pdf", "application/pdf", 10, "sample"), "refused", "a PDF that is a sample is never parsed, sandbox or not");
assert.equal(readerFor("pdf", null, "a.pdf"), "pdf");
assert.equal(readerFor("text", "text/plain", "a.txt"), null, "plain text needs no parser: it stays in the page, escaped");

// Office and 한글 (42b): each family to its reader, by name or by type.
for (const [name, reader] of [["a.docx", "docx"], ["a.DOCM", "docx"], ["a.xlsx", "sheet"], ["a.xlsm", "sheet"], ["a.xlsb", "sheet"], ["a.xls", "sheet"], ["a.ods", "sheet"], ["a.csv", "sheet"], ["a.tsv", "sheet"], ["a.pptx", "pptx"], ["a.ppsx", "pptx"], ["a.hwp", "hwp"], ["a.hwpx", "hwp"], ["a.doc", "legacy"], ["a.ppt", "legacy"], ["a.rtf", "legacy"], ["a.odt", "legacy"], ["a.odp", "legacy"]] as const) {
	assert.equal(readerFor("file", null, name), reader, name);
	assert.equal(pickViewerMode("doc", null, 10, "normal", name), "document", `${name} opens in the frame`);
}
assert.equal(readerFor("file", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "noext"), "sheet", "by its type");
assert.equal(readerFor("file", "text/csv; charset=utf-8", "noext"), "sheet", "a type with parameters");
// Email (42c): .eml and Outlook's .msg, by name or type — a .msg is an OLE file and stays an email.
assert.equal(readerFor("doc", null, "phish.eml"), "email");
assert.equal(readerFor("doc", null, "phish.MSG"), "email");
assert.equal(readerFor("file", "message/rfc822", "noext"), "email");
assert.equal(pickViewerMode("doc", null, 10, "normal", "phish.eml"), "document");
assert.equal(readerFor("file", "application/x-hwp", "noext"), "hwp");
assert.equal(pickViewerMode("doc", null, MAX_INLINE + 1, "normal", "big.docx"), "too-large", "read whole, so capped");
assert.equal(pickViewerMode("doc", null, 10, "sample", "lure.docm"), "refused", "a sample is never parsed");

// The first bytes correct the name (sniffReader): disguise is the point of a lure.
const head = (s: string | number[]) => (typeof s === "string" ? new TextEncoder().encode(s) : new Uint8Array(s));
const ZIP = [0x50, 0x4b, 0x03, 0x04];
const OLE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
assert.equal(sniffReader(head("{\\rtf1\\ansi"), "legacy", "invoice.doc"), "legacy", "an RTF named .doc: the legacy reader (which says so)");
assert.equal(sniffReader(head("{\\rtf1\\ansi"), "docx", "invoice.docx"), "legacy", "an RTF named .docx");
assert.equal(sniffReader(head(ZIP), "legacy", "report.doc"), "docx", "a .docx renamed .doc");
assert.equal(sniffReader(head(ZIP), "legacy", "deck.ppt"), "pptx", "a .pptx renamed .ppt");
assert.equal(sniffReader(head(OLE), "docx", "macro.docx"), "legacy", "a Word 97 file (macros and all) renamed .docx");
assert.equal(sniffReader(head(OLE), "pptx", "old.pptx"), "legacy");
assert.equal(sniffReader(head("%PDF-1.7"), "docx", "fake.docx"), "pdf", "a PDF under any name is shown as the PDF it is");
assert.equal(sniffReader(head(OLE), "sheet", "book.xlsx"), "sheet", "the sheet reader reads every form of its family (and password-protected ones say so)");
assert.equal(sniffReader(head(ZIP), "hwp", "a.hwp"), "hwp", "…as does 한글's (HWPX is a ZIP)");
assert.equal(sniffReader(head(ZIP), "docx", "a.docx"), "docx", "what the name says, when the bytes agree");
assert.equal(sniffReader(head(OLE), "email", "outlook.msg"), "email", "an Outlook .msg is an OLE file, and an email");

// Formats whose readers are still to come are honest about it — except a
// text/plain mime, which still shows.
assert.equal(pickViewerMode("archive", null, 10), "unsupported");
assert.equal(pickViewerMode("doc", "text/plain", 10), "text");

// Malware samples (commit 29e): refused before anything else — whatever
// the kind or mime says, and a type that does not verify is refused too.
assert.equal(pickViewerMode("image", "image/png", 10, "sample"), "refused");
assert.equal(pickViewerMode("text", "text/plain", 10, "unverified"), "refused");
assert.equal(pickViewerMode("sample", null, 10), "refused", "the sample kind alone refuses");
assert.equal(pickViewerMode("image", "image/png", 10, "normal"), "image");

// Render mimes never let stored content run as the app.
assert.equal(renderMime("image", null, "pic.svg"), "image/png", "SVG never runs");
assert.equal(renderMime("image", "image/svg+xml", "pic"), "image/png", "a stored SVG mime never reaches a blob URL either (commit 23)");
assert.equal(renderMime("image", "text/html", "x.png"), "image/png", "the extension wins only inside the raster list");
assert.equal(renderMime("image", "image/webp", "noext"), "image/webp", "a raster stored mime is kept");
assert.equal(renderMime("image", null, "pic.jpg"), "image/jpeg");
assert.equal(renderMime("video", null, "v.mkv"), "video/mp4");
assert.equal(renderMime("text", "text/plain", "n"), "text/plain");

console.log("ok  viewer modes: the cap only where a file is read whole (media streams at any size), mimes, escape-by-construction, samples refused; Office and 한글 to their readers, and the first bytes correcting a disguised name");