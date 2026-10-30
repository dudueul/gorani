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

// Pictures (42d): every one opens in the sandboxed frame's image reader —
// by kind, by mime, by name — the browser's own decoders included (a
// crafted WebP was CVE-2023-4863): none is drawn in the app's page.
assert.equal(pickViewerMode("image", null, 100), "document");
assert.equal(pickViewerMode("file", "image/webp", 100), "document", "by its mime");
for (const name of ["a.jpg", "a.JPEG", "a.png", "a.gif", "a.webp", "a.avif", "a.bmp", "a.ico", "a.heic", "a.HEIF", "a.tif", "a.tiff", "a.svg", "a.svgz", "a.jxl", "a.dng", "a.cr2", "a.CR3", "a.nef", "a.arw", "a.orf", "a.rw2", "a.raf", "a.pef"]) {
	assert.equal(readerFor("file", null, name), "image", name);
}
assert.equal(readerFor("image", null, "noext"), "image", "by its kind");
assert.equal(readerFor("file", "image/x-adobe-dng", "noext"), "image", "any image/ type");
assert.equal(readerFor("file", "image/svg+xml", "noext"), "image", "an SVG too: in the frame, drawn as a picture");

// Media plays inline under the size cap.
assert.equal(pickViewerMode("video", null, 1024), "video");
assert.equal(pickViewerMode("audio", "audio/flac", 1024), "audio");

// Plain text renders escaped in the page; so does code with no name to
// say what it is. Markdown, JSON, XML, web pages and named code go to the
// text reader in the frame (42f, below).
assert.equal(pickViewerMode("text", null, 10), "text");
assert.equal(pickViewerMode("code", null, 10), "text");
assert.equal(pickViewerMode("text", "text/plain", 10, "normal", "notes.txt"), "text");
assert.equal(pickViewerMode("text", "text/plain", 10, "normal", "server.log"), "text", "a log stays in the page");
assert.equal(pickViewerMode("file", "text/markdown", 10), "document", "Markdown: rendered, in the frame");

// The size cap is for what is read WHOLE to be shown: a picture, a
// document. Video and audio stream at any size, and text opens only its
// head (39w — the cap used to come first, so a film over 256 MB had "no
// preview" at all).
assert.equal(pickViewerMode("image", "image/png", MAX_INLINE + 1), "too-large");
assert.equal(pickViewerMode("image", "image/png", MAX_INLINE), "document", "at the cap, still shown");
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
assert.equal(sniffReader(head("<html><script>"), "image", "photo.jpg"), "image", "a web page named .jpg stays with the picture reader, which names it and draws nothing");
assert.equal(sniffReader(head("%PDF-1.7"), "image", "scan.jpg"), "pdf", "a PDF named .jpg is shown as the PDF it is");

// Archives (42e): to the archive reader in the frame — by name, by type,
// by kind; any first bytes stay with it (it reads every form of its family).
for (const name of ["a.zip", "a.JAR", "a.apk", "a.7z", "a.rar", "a.tar", "a.tgz", "a.tar.gz", "a.gz", "a.bz2", "a.xz", "a.zst", "a.cab", "a.iso", "a.wim", "a.dmg", "a.vhdx", "a.arj", "a.lzh", "a.cpio", "a.rpm", "a.deb", "a.msi", "a.alz", "a.egg"]) {
	assert.equal(readerFor("file", null, name), "archive", name);
}
assert.equal(readerFor("archive", null, "noext"), null, "an archive with no name and no type: nothing guesses");
assert.equal(readerFor("file", "application/x-7z-compressed", "noext"), "archive", "by its type");
assert.equal(pickViewerMode("archive", null, 10, "normal", "a.zip"), "document");
assert.equal(pickViewerMode("archive", null, 10, "sample", "infected.zip"), "refused", "a sample archive is never listed");
assert.equal(sniffReader(head(ZIP), "archive", "a.zip"), "archive");
assert.equal(sniffReader(head("Rar!\x1a\x07"), "archive", "a.zip"), "archive", "a RAR named .zip: the archive reader, which names it");

// Text that needs a parser (42f): to the text reader in the frame — by
// name, by type; its first bytes do not move it — unless they are a
// program's (42g, below): a binary that is not a program is shown as
// characters, and the reader says it is binary.
for (const name of ["README.md", "a.json", "a.jsonl", "a.geojson", "a.ipynb", "a.xml", "a.plist", "a.csproj", "a.html", "a.HTA", "a.js", "a.ts", "a.py", "a.sh", "a.ps1", "a.psm1", "a.bat", "a.cmd", "a.vbs", "a.vbe", "a.bas", "a.cls", "a.jse", "a.wsf", "a.sct", "a.css", "a.yaml", "a.toml", "a.ini", "a.reg", "a.env", "a.sql", "a.c", "a.rs", "a.go", "a.php", "a.rb", "a.yar", "a.ahk", "Dockerfile.dockerfile", "a.patch"]) {
	assert.equal(readerFor("file", null, name), "text", name);
}
for (const name of ["a.txt", "a.log", "a.TXT", "noext"]) assert.equal(readerFor("text", "text/plain", name), null, `${name}: stays in the page`);
for (const type of ["application/json", "text/html", "application/xml", "text/javascript", "text/markdown; charset=utf-8"]) assert.equal(readerFor("file", type, "noext"), "text", type);
assert.equal(readerFor("image", "image/svg+xml", "a.svg"), "image", "an SVG is still a picture (its source is the picture reader's tab)");
assert.equal(pickViewerMode("code", null, 10, "sample", "dropper.ps1"), "refused", "a sample script is never parsed, not even to be highlighted");
assert.equal(pickViewerMode("code", null, MAX_INLINE + 1, "normal", "huge.json"), "too-large", "taken whole by the frame, so capped");
assert.equal(sniffReader(head("MZ\x90\x00"), "text", "invoice.js"), "hex", "a program named .js: the hex reader (42g), which names the disguise");
assert.equal(sniffReader(head("%PDF-1.7"), "text", "invoice.html"), "pdf", "a PDF named .html is shown as the PDF it is");

// Programs and other binaries (42g): to the hex reader — by name, by
// type; and a program under ANY name but an archive's goes there too (an
// "invoice.pdf" that is an .exe is the lure; a self-extractor stays an archive).
for (const name of ["a.exe", "a.DLL", "a.sys", "a.scr", "a.cpl", "a.so", "a.dylib", "a.macho", "a.ko", "a.elf", "a.bin", "a.o", "a.wasm", "a.dex", "a.class", "a.lnk", "a.dmp"]) assert.equal(readerFor("file", null, name), "hex", name);
for (const type of ["application/x-msdownload", "application/vnd.microsoft.portable-executable", "application/x-executable", "application/x-mach-binary"]) assert.equal(readerFor("file", type, "noext"), "hex", type);
for (const [bytes, label] of [["MZ\x90\x00", "a PE"], ["\x7fELF", "an ELF"], [[0xcf, 0xfa, 0xed, 0xfe], "a Mach-O"]] as const) {
	for (const guess of ["pdf", "docx", "image", "text", "legacy", "email"] as const) assert.equal(sniffReader(head(bytes as string | number[]), guess, "invoice.pdf"), "hex", `${label} named as a ${guess}`);
	assert.equal(sniffReader(head(bytes as string | number[]), "archive", "setup.zip"), "archive", `${label} named .zip: the archive reader (a self-extractor)`);
}
assert.equal(pickViewerMode("file", null, 10, "normal", "setup.exe"), "document", "a program is shown — as bytes and headers");
assert.equal(pickViewerMode("file", null, 10, "sample", "setup.exe"), "refused", "a sample program is refused first: inspecting it is a choice the person makes, on the record");

// Formats with no reader are honest about it — except a text/plain mime,
// which still shows.
assert.equal(pickViewerMode("archive", null, 10), "unsupported");
assert.equal(pickViewerMode("doc", "text/plain", 10), "text");

// Malware samples (commit 29e): refused before anything else — whatever
// the kind or mime says, and a type that does not verify is refused too.
assert.equal(pickViewerMode("image", "image/png", 10, "sample"), "refused");
assert.equal(pickViewerMode("text", "text/plain", 10, "unverified"), "refused");
assert.equal(pickViewerMode("sample", null, 10), "refused", "the sample kind alone refuses");
assert.equal(pickViewerMode("image", "image/png", 10, "normal"), "document");
assert.equal(pickViewerMode("image", "image/svg+xml", 10, "sample"), "refused", "a sample picture is refused before any decoder sees it");

// Render mimes (media the page plays) never let stored content run as the
// app: whatever the stored type says, never a document type. (Pictures had
// their own raster list here — commit 23 — and since 42d get no blob: URL
// in the page at all.)
assert.equal(renderMime("image", "image/svg+xml", "pic.svg"), "text/plain", "a picture is not the page's to render");
assert.equal(renderMime("video", "text/html", "v.mp4"), "video/mp4", "a stored document type never reaches a media blob");
assert.equal(renderMime("video", null, "v.mkv"), "video/mp4");
assert.equal(renderMime("text", "text/plain", "n"), "text/plain");

console.log("ok  viewer modes: the cap only where a file is read whole (media streams at any size), mimes, escape-by-construction, samples refused; Office, 한글, email, every picture, every archive, the text that needs a parser and every program to their readers in the frame (plain text and logs kept in the page), and the first bytes correcting a disguised name");