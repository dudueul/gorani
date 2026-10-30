// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:preview-facts — what the readers SAY about a file (commit 42b,
 * docs/PREVIEWS.md), on the fixtures, in Node. The facts are pure code —
 * bytes in, sentences out (preview/facts, preview/legacy, zip.ts, ole.ts) —
 * so every planted trick is checked here in milliseconds; e2e:preview then
 * proves the same facts reach the viewer and that the drawing is sandboxed.
 *
 *   1. ZIP: a real Office file passes the bomb check; a directory that
 *      claims too much, and a part that lies about its size, are refused
 *   2. Word: the hostile .docx's every trick named; the report's only its
 *      title and author
 *   3. Excel: hidden/very hidden sheets, the XLM macro sheet (quoted), the
 *      Auto_Open name, DDE and WEBSERVICE formulas, the web query, the
 *      outside workbook; CP949 CSV and its injected formula
 *   4. PowerPoint: the Run-program action, the hidden slide, the beacon;
 *      the report's slides and notes
 *   5. 한글: the script (quoted, the empty default not), PostScript, the OLE
 *      object, the link (HWP's escaped colon); HWPX's metadata
 *   6. the older formats: .doc text and container (macros, Equation
 *      Editor, the packaged program), .ppt slides and notes, RTF's object
 *      marked to update itself, its template, its DDEAUTO
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";
import { docxFacts } from "../../web/src/preview/facts/word.ts";
import { deckFacts, slidesOf } from "../../web/src/preview/facts/slides.ts";
import { hwpFacts, hwpxFacts, scriptSource } from "../../web/src/preview/facts/hwp.ts";
import { readDoc } from "../../web/src/preview/legacy/doc.ts";
import { readPpt } from "../../web/src/preview/legacy/ppt.ts";
import { readRtf } from "../../web/src/preview/legacy/rtf.ts";
import { fieldCodes } from "../../web/src/preview/facts/word.ts";
import { rels } from "../../web/src/preview/office.ts";
import { Ole } from "../../web/src/preview/ole.ts";
import { analyse } from "../../web/src/preview/readers/sheet.worker.ts";
import { Zip } from "../../web/src/preview/zip.ts";
import { authResults, mailFacts, orgDomain, partRisk, receivedChain } from "../../web/src/preview/facts/mail.ts";
import { parseMail } from "../../web/src/preview/mail/parse.ts";
import { classifyTrailing, sniffImage, structureOf } from "../../web/src/preview/image/structure.ts";
import { rawPreviews, cr3Metadata } from "../../web/src/preview/image/raw.ts";
import { readMeta, readThumbnail } from "../../web/src/preview/image/meta.ts";
import { gpsOf, orientationOf } from "../../web/src/preview/image/tags.ts";
import { readTiff } from "../../web/src/preview/image/tiff.ts";
import { imageFacts, metaGroups, type ImageFindings } from "../../web/src/preview/facts/image.ts";
import { listZip, extractZip, decodeName, Refusal } from "../../web/src/preview/archive/zip.ts";
import { listAlz, extractAlz } from "../../web/src/preview/archive/alz.ts";
import { listEgg, extractEgg } from "../../web/src/preview/archive/egg.ts";
import { SevenZip } from "../../web/src/preview/archive/run7z.ts";
import { parseListing, streamName, troubleOf } from "../../web/src/preview/archive/sevenzip.ts";
import { crc32, zipDecrypt } from "../../web/src/preview/archive/crypto.ts";
import { archiveFacts, pathRisk, treeOf } from "../../web/src/preview/facts/archive.ts";
import type { Listing } from "../../web/src/preview/archive/types.ts";

const fixture = (name: string) => new Uint8Array(readFileSync(new URL(`../fixtures/preview/${name}`, import.meta.url)));
const said = (facts: { text: string }[]) => facts.map((f) => f.text).join("\n");
const zipOf = (name: string) => {
	const z = Zip.open(fixture(name));
	assert.ok(z, `${name} is a ZIP`);
	return z;
};

// ── 1. ZIP ────────────────────────────────────────────────────────────
assert.equal(zipOf("report.docx").check(), null, "an honest Office file passes");

/** A one-part ZIP whose directory says `claimed` bytes for data that inflates to `real`. */
function zipWith(real: number, claimed: number): Uint8Array {
	const data = deflateRawSync(Buffer.alloc(real));
	const name = Buffer.from("word/document.xml");
	const local = Buffer.alloc(30);
	local.writeUInt32LE(0x04034b50, 0);
	local.writeUInt16LE(20, 4);
	local.writeUInt16LE(8, 8);
	local.writeUInt32LE(data.length, 18);
	local.writeUInt32LE(claimed >>> 0, 22);
	local.writeUInt16LE(name.length, 26);
	const central = Buffer.alloc(46);
	central.writeUInt32LE(0x02014b50, 0);
	central.writeUInt16LE(20, 4);
	central.writeUInt16LE(20, 6);
	central.writeUInt16LE(8, 10);
	central.writeUInt32LE(data.length, 20);
	central.writeUInt32LE(claimed >>> 0, 24);
	central.writeUInt16LE(name.length, 28);
	const dirAt = 30 + name.length + data.length;
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(1, 8);
	end.writeUInt16LE(1, 10);
	end.writeUInt32LE(46 + name.length, 12);
	end.writeUInt32LE(dirAt, 16);
	return new Uint8Array(Buffer.concat([local, name, data, central, name, end]));
}
const liar = Zip.open(zipWith(8 * 1024 * 1024, 1000));
assert.ok(liar);
assert.match(liar.check() ?? "", /inflates past/, "a part that inflates past what the directory claims is refused");
const greedy = Zip.open(zipWith(1000, 0xffff_fff0));
assert.ok(greedy);
assert.match(greedy.check() ?? "", /would inflate to 4096 MB/, "a directory claiming past 1 GiB is refused before anything is inflated");
assert.equal(Zip.open(new Uint8Array(100)), null, "not a ZIP");

// ── 2. Word ───────────────────────────────────────────────────────────
const word = said(docxFacts(zipOf("hostile.docx")));
for (const want of [
	/Contains macros \(a VBA project\)/,
	/Embeds 1 object: oleObject1\.bin/,
	/Fetches its template from https:\/\/phish\.example\/template\.dotm .*template injection/,
	/Fetches 1 item from outside .*\\\\phish\.example\\share\\logo\.png — a \\\\server path makes Windows offer the reader's sign-in hash/,
	/Carries a raw HTML or MHT part \(altChunk\)/,
	/Has a DDEAUTO field, which runs a program .*on opening: “DDEAUTO c:\\\\windows/,
	/Has an INCLUDEPICTURE field that fetches from outside .*http:\/\/phish\.example\/track\.png/,
	/Has hidden text .*“gorani hidden instruction”/,
	/Has tracked changes \(1 insertion, 1 deletion\).*DE89 3704 0044 0532 0130 00/,
	/Links to 1 address \(not followed\): https:\/\/phish\.example\/login/,
	/title Invoice · author Accounts · last saved by phisher/,
]) assert.match(word, want);
const plainWord = docxFacts(zipOf("report.docx"));
assert.deepEqual(plainWord.map((f) => f.level), ["info"], "the report says who and when, and warns of nothing");
assert.match(plainWord[0]!.text, /^2 pages \(as Word last counted\) · title Quarterly report · author Gorani tests/);
// Fields nest: the outer code is kept whole around the inner field.
assert.deepEqual(fieldCodes('<w:fldChar w:fldCharType="begin"/><w:instrText>IF </w:instrText><w:fldChar w:fldCharType="begin"/><w:instrText>DDEAUTO cmd</w:instrText><w:fldChar w:fldCharType="separate"/><w:t>x</w:t><w:fldChar w:fldCharType="end"/><w:instrText> = 1</w:instrText><w:fldChar w:fldCharType="end"/><w:fldSimple w:instr="HYPERLINK &quot;https://a.example&quot;"/>'), ["DDEAUTO cmd", "IF  = 1", 'HYPERLINK "https://a.example"']);

// ── 3. Excel ──────────────────────────────────────────────────────────
const book = analyse(fixture("hostile.xlsx"), "hostile.xlsx");
assert.equal(book.t, "book");
const xl = said(book.facts);
for (const want of [
	/^4 sheets · author Accounts/,
	/Contains macros \(a VBA project\)/,
	/Has 1 Excel 4\.0 \(XLM\) macro sheet: Macro1 .*It says: =EXEC\("calc\.exe"\) · =HALT\(\)/,
	/Hides 2 sheets: Hidden \(hidden\) · Secret \(very hidden/,
	/Runs “Macro1!\$A\$1” when opened in Excel \(Auto_Open\)/,
	/Has 1 DDE formula, which runs a program .*=cmd\|' \/C calc'!A0 \(Invoice!A3\)/,
	/Has formulas that fetch or run something: WEBSERVICE \(Invoice!A4\)/,
	/Refreshes data from outside: Rates ← https:\/\/phish\.example\/rates\.iqy/,
	/Links to outside workbooks: \\\\phish\.example\\share\\book\.xlsx/,
	/Links to 1 address \(not followed\): https:\/\/phish\.example\/login/,
]) assert.match(xl, want);
if (book.t === "book") assert.deepEqual(book.sheets.map((s) => [s.name, s.hidden, s.kind]), [["Invoice", 0, "sheet"], ["Hidden", 1, "sheet"], ["Secret", 2, "sheet"], ["Macro1", 1, "macro"]]);
const report = analyse(fixture("report.xlsx"), "report.xlsx");
assert.equal(report.t === "book" && report.sheets[1]?.rows, 401, "the data sheet's 401 rows");
assert.ok(report.facts.every((f) => f.level === "info"), "the report warns of nothing");
// The older and the open forms of the same workbook: Excel 97 (BIFF, in an OLE container) and OpenDocument.
for (const name of ["report.xls", "report.ods"]) {
	const b = analyse(fixture(name), name);
	assert.equal(b.t, "book", name);
	if (b.t === "book") assert.deepEqual(b.sheets.map((s) => [s.name, s.rows]), [["Summary", 6], ["Data", 401]], `${name}: both sheets, every row`);
	assert.ok(b.facts.every((f) => f.level === "info"), `${name} warns of nothing: ${said(b.facts)}`);
}
const csv = analyse(fixture("ledger.csv"), "ledger.csv");
assert.match(said(csv.facts), /text in CP949 \(Korean Windows\)/, "Korean Excel's code page, detected");
assert.match(said(csv.facts), /1 cell starts with =, \+, − or @ .*CSV injection.*=HYPERLINK\("https:\/\/phish\.example\/login","확인"\) \(Sheet1!C3\)/);

// ── 4. PowerPoint ─────────────────────────────────────────────────────
const deckZip = zipOf("hostile.pptx");
const deckRels = rels(deckZip);
const deck = slidesOf(deckZip, deckRels);
assert.deepEqual(deck.map((s) => s.hidden), [false, true], "slide 2 is hidden");
const ppt = said(deckFacts(deckZip, deckRels, deck));
for (const want of [/^2 slides · title Invoice · author Accounts · last saved by phisher/, /Contains macros/, /Embeds 1 object/, /Fetches 1 item from outside .*https:\/\/phish\.example\/beacon\.png/, /Has a “Run program” action: file:\/\/\/C:\/Windows\/System32\/cmd\.exe \(slide 1\)/, /Hides 1 slide \(2\)/, /Links to 1 address \(not followed\): https:\/\/phish\.example\/login/]) assert.match(ppt, want);
assert.doesNotMatch(ppt, /Links to .*cmd\.exe/, "the program a click runs is named once, as an action, not again as a link");
const reportDeck = slidesOf(zipOf("report.pptx"), rels(zipOf("report.pptx")));
assert.deepEqual(reportDeck.map((s) => s.notes), ["Speaker notes for slide one", "", ""]);

// ── 5. 한글 ────────────────────────────────────────────────────────────
const hwp = said(hwpFacts(fixture("hostile.hwp")));
for (const want of [/Contains a script that 한글 can run .*“function OnDocument_Open\(\) \{ var s = new ActiveXObject\('WScript\.Shell'\); s\.Run\('calc\.exe'\); \}”/, /Embeds PostScript \(BIN0001\.eps\)/, /Embeds 1 OLE object: BIN0002\.OLE/, /Links to 1 address \(not followed\): https:\/\/phish\.example\/login/]) assert.match(hwp, want);
const plainHwp = hwpFacts(fixture("report.hwp"));
assert.ok(plainHwp.every((f) => f.level === "info"), `every 한글 file has an (empty) default script — not a warning: ${said(plainHwp)}`);
assert.equal(scriptSource(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255])), "", "the default script is empty");
assert.match(said(hwpxFacts(zipOf("report.hwpx"))), /author rhwp/);

// ── 6. The older formats ──────────────────────────────────────────────
const doc = readDoc(Ole.open(fixture("hostile.doc"))!);
const docSaid = said(doc.facts);
for (const want of [/title Invoice · author Accounts · last saved by phisher/, /Contains macros \(a VBA project\)/, /Embeds 2 objects \(Equation\.3\)/, /Carries packaged files: C:\\Users\\phisher\\Desktop\\invoice\.pdf\.exe/, /Equation Editor 3\.0 object — the way CVE-2017-11882/, /DDEAUTO field/, /Links to 1 address .*phish\.example\/login/]) assert.match(docSaid, want);
assert.ok(doc.sections[0]!.paras.includes("Invoice overdue"), "its text, from the piece table");
const plainDoc = readDoc(Ole.open(fixture("report.doc"))!);
assert.deepEqual(plainDoc.sections[0]!.paras, ["Gorani Word page one", "The quarter closed with every case accounted for.", "Case\tOwner\tStatus", "Lake\tRin\tClosed", "River\tMo\tOpen", "고라니 보고서 둘째 쪽", "Gorani Word page two"], "text, a table row per line, Korean (UTF-16 pieces)");
const slides = readPpt(Ole.open(fixture("report.ppt"))!);
assert.equal(slides.sections.length, 3, "three slides — not the masters, not the notes");
assert.deepEqual(slides.sections.map((s) => s.paras[0]), ["Gorani slides page one", "고라니 둘째 장", "Gorani slide three"]);
assert.match(slides.sections[0]!.notes ?? "", /^Speaker notes for slide one/, "notes under their slide (the notes master skipped)");
assert.doesNotMatch(said(slides.facts), /macros/, "LibreOffice's empty VBAInfo record is not a macro project");
const rtf = readRtf(fixture("hostile.rtf"));
const rtfSaid = said(rtf.facts);
for (const want of [/title Invoice · author Accounts/, /Embeds an object \(Equation\.3, 1 kB\) — Equation Editor 3\.0, the way CVE-2017-11882 is exploited; marked to update by itself when Word opens the file/, /Fetches its template from https:\/\/phish\.example\/template\.dotm/, /DDEAUTO c:\\windows\\system32\\cmd\.exe "\/k calc\.exe"/, /Links to 1 address .*phish\.example\/login/]) assert.match(rtfSaid, want);
assert.deepEqual(rtf.sections[0]!.paras, ["Invoice overdue", "Enable editing to see the invoice.", "Loading", "Pay the invoice"], "the shown text: field results, not codes; no object data");
const rtfReport = readRtf(fixture("report.rtf"));
assert.ok(rtfReport.sections[0]!.paras.includes("고라니 보고서 둘째 쪽"), `Korean through \\u escapes: ${rtfReport.sections[0]!.paras.join(" | ")}`);
assert.ok(readRtf(new TextEncoder().encode("{\\rtf1 {{{{ unclosed")).facts.some((f) => /malformed/.test(f.text)), "unclosed groups are named");

// ── 7. Email (42c) ────────────────────────────────────────────────────
const plainMail = await parseMail(fixture("report.eml"));
assert.equal(plainMail.subject, "분기 보고서 — Quarterly report", "an RFC 2047 subject, decoded");
assert.deepEqual(plainMail.attachments.map((a) => [a.name, a.inline, a.cid]), [["logo.png", true, "logo@gorani"], ["report.pdf", false, null]]);
const reportSaid = said(mailFacts(plainMail, null).facts);
assert.match(reportSaid, /SPF pass · DKIM pass · DMARC pass/);
assert.match(reportSaid, /Handed to mx\.gorani\.example by 192\.0\.2\.20 \(out\.gorani\.example\)/);
assert.ok(mailFacts(plainMail, null).facts.every((f) => f.level === "info"), `an honest message warns of nothing: ${reportSaid}`);

const phish = await parseMail(fixture("phish.eml"));
// What the reader finds in its HTML (in the frame, from an inert parse) — given here as data.
const found = { links: [{ href: "https://phish.example/login", text: "https://www.paypal.com/signin" }, { href: "https://xn--pypal-4ve.example/", text: "PayPal support" }, { href: "https://paypal.com@203.0.113.7/verify", text: "Verify" }, { href: "search-ms:query=invoice", text: "Open" }, { href: "https://bit.ly/3gorani", text: "Track" }, { href: "javascript:alert(1)", text: "x" }, { href: "\\\\203.0.113.7\\share", text: "share" }], remote: ["https://phish.example/open.gif", "https://phish.example/bg.png"], forms: [{ action: "https://phish.example/collect", password: true }], scripts: 2, frames: ["https://phish.example/frame"], refresh: "https://phish.example/login" };
const { facts: phishFacts, hops } = mailFacts(phish, found);
const ph = said(phishFacts);
for (const want of [
	/The receiving server's checks failed: SPF fail, DMARC fail/,
	/The sender's name says “service@paypal\.com”, but it was sent from service@paypal\.com\.secure-login\.example/,
	/starts with paypal\.com but is at secure-login\.example — a domain dressed as another/,
	/Replies go to collect@phish\.example/,
	/envelope sender bounce@mailer\.bulk-sender\.example/,
	/Handed to mx\.gorani\.example by 203\.0\.113\.7 \(mail\.secure-login\.example\) — the hop the sender could not write; the 1 hop before it is the sender's own account/,
	/“https:\/\/www\.paypal\.com\/signin” goes to https:\/\/phish\.example\/login/,
	/search-ms:/,
	/file share/,
	/javascript: or data: link/,
	/punycode .*xn--pypal-4ve\.example/,
	/straight to an IP address: 203\.0\.113\.7/,
	/behind user@: paypal\.com@203\.0\.113\.7/,
	/shorteners \(bit\.ly\)/,
	/Would load 2 pictures and styles from outside .*phish\.example \(not loaded\)/,
	/form that sends what is typed to https:\/\/phish\.example\/collect — and it asks for a password/,
	/Contains 2 scripts/,
	/Would redirect the reader/,
	/Attachment invoice\.pdf\.exe: it pretends to be \.pdf — it is a Windows program/,
	/Attachment invoice\.html: a web page that builds a file in the browser and saves it — HTML smuggling/,
]) assert.match(ph, want);
assert.doesNotMatch(ph, /SPF pass/, "the forged Authentication-Results below the receiving server's is not believed");
assert.equal(authResults(phish.headers).spf, "fail");
assert.deepEqual(hops.map((h) => h.ip), ["198.51.100.23", "203.0.113.7", "192.0.2.10"], "the Received chain, oldest first");
assert.equal(receivedChain([{ name: "Received", value: "from a.example (a.example [2001:db8::1]) by b.example; Fri, 2 Jan 2026 03:04:05 +0000" }])[0]?.ip, "2001:db8::1", "IPv6");

const fwd = await parseMail(fixture("report-to-soc.eml"));
const inner = fwd.attachments.find((a) => a.name === "phish.eml");
assert.ok(inner && inner.mime === "message/rfc822", "a forward as an attachment stays one");
assert.equal((await parseMail(inner.bytes)).subject, "Invoice overdue - action required", "…and parses as the message it is");
assert.match(said(mailFacts(fwd, null).facts), /Carries a message of its own/);

const outlook = await parseMail(fixture("outlook.msg"));
assert.equal(outlook.format, "msg");
assert.equal(outlook.subject, "Invoice overdue (Outlook)");
assert.deepEqual(outlook.attachments.map((a) => a.name), ["invoice.pdf.exe"]);
const ol = said(mailFacts(outlook, null).facts);
for (const want of [/an Outlook \.msg/, /SPF fail, DMARC fail/, /Replies go to collect@phish\.example/, /Attachment invoice\.pdf\.exe/, /Links to 1 address .*phish\.example\/login/]) assert.match(ol, want);

// Attachments judged by name and by bytes.
const MZ = new TextEncoder().encode("MZ…");
assert.match(partRisk("invoice.pdf", MZ) ?? "", /named \.pdf, but it is a Windows program/);
assert.match(partRisk("invoice\u202Efdp.exe", new Uint8Array(4)) ?? "", /right-to-left mark/);
assert.match(partRisk("photos.iso", new Uint8Array(4)) ?? "", /disk image/);
assert.match(partRisk("notes.one", new Uint8Array(4)) ?? "", /OneNote/);
assert.match(partRisk("secret.zip", new Uint8Array([0x50, 0x4b, 3, 4, 20, 0, 1, 0])) ?? "", /password-protected archive/);
assert.equal(partRisk("report.pdf", fixture("report.pdf")), null, "a PDF that is a PDF is not a risk");
assert.equal(partRisk("statement.docx", fixture("report.docx")), null);
assert.equal(orgDomain("mail.gorani.co.kr"), "gorani.co.kr");
assert.equal(orgDomain("paypal.com.secure-login.example"), "secure-login.example");

// ── 8. Pictures (42d) ────────────────────────────────────────────────
// What the bytes are and how they are built, read without decoding; the
// metadata, read by exifr; and what the facts make of both. (What only a
// browser can measure — a thumbnail's likeness, an SVG's parsed elements —
// goes in as the reader would hand it; e2e:preview measures them.)

const pictureFacts = async (name: string, over: Partial<ImageFindings> = {}, as = name) => {
	const bytes = fixture(name);
	const sniff = sniffImage(bytes, as);
	const structure = structureOf(bytes, sniff.format);
	const previews = /^(dng|cr3|raf)$/.test(sniff.format ?? "") ? rawPreviews(bytes, sniff.format) : [];
	const f: ImageFindings = { name: as, sniff, structure, meta: await readMeta(bytes), previews, pages: 0, shown: null, refused: null, thumb: null, svg: null, ...over };
	return { f, facts: imageFacts(f), text: said(imageFacts(f)) };
};

// Formats, by their first bytes (the name only breaks ties).
for (const [name, format] of [["photo.jpg", "jpeg"], ["generated.png", "png"], ["animated.gif", "gif"], ["photo.webp", "webp"], ["photo.avif", "avif"], ["photo.heic", "heic"], ["scan.tiff", "tiff"], ["camera.dng", "dng"], ["camera.cr3", "cr3"], ["camera.raf", "raf"], ["drawing.svg", "svg"], ["entities.svg", "svg"]] as const) {
	assert.equal(sniffImage(fixture(name), name).format, format, name);
}
assert.equal(sniffImage(fixture("photo.jpg"), "holiday.png").format, "jpeg", "the bytes, not the name");
assert.equal(sniffImage(fixture("report.pdf"), "scan.jpg").other, "a PDF");
assert.equal(sniffImage(new TextEncoder().encode("<!doctype html><script>x</script>"), "cat.png").other, "a web page");
assert.equal(sniffImage(fixture("photo.heic")).native, false, "HEIF is decoded by libheif, not the browser");
assert.equal(sniffImage(fixture("photo.avif")).native, true, "AVIF the browser draws");

// Sizes declared, frames, pages, orientation, ends — read, not decoded.
let st = structureOf(fixture("bomb.png"), "png");
assert.deepEqual([st.width, st.height], [60000, 60000], "a bomb's claim, read from 69 bytes");
assert.equal(structureOf(fixture("animated.gif"), "gif").frames, 3);
assert.equal(structureOf(fixture("scan.tiff"), "tiff").frames, 2, "a scan's two pages");
assert.equal(structureOf(fixture("portrait.jpg"), "jpeg").orientation, 6);
st = structureOf(fixture("photo.jpg"), "jpeg");
assert.deepEqual([st.width, st.height, st.end, st.trailing], [640, 480, fixture("photo.jpg").length, null], "a JPEG with EXIF (and a JPEG inside it): its end is its end");
assert.equal(structureOf(fixture("photo.heic"), "heic").width, 640, "HEIF's declared size (ispe)");

// What follows a picture's end.
st = structureOf(fixture("polyglot.jpg"), "jpeg");
assert.match(st.trailing?.kind ?? "", /ZIP archive/);
assert.equal(st.trailing?.benign, false);
assert.match(st.comments[0] ?? "", /<\?php system/);
const tail = (s: string | number[]) => (typeof s === "string" ? new TextEncoder().encode(s) : new Uint8Array(s));
const glued = (t: Uint8Array) => new Uint8Array([...tail([0xff, 0xd9]), ...t]);
assert.equal(classifyTrailing(glued(tail([0, 0, 0, 0, 0xff, 0xff])), 2), null, "padding is not news");
assert.equal(classifyTrailing(glued(tail([0, 0, 0, 0x18, ...new TextEncoder().encode("ftypmp42"), 0, 0, 0, 0])), 2)?.benign, true, "a motion photo's video");
assert.match(classifyTrailing(glued(tail("MZ\x90\x00 program")), 2)?.kind ?? "", /Windows program/);
assert.match(classifyTrailing(glued(tail("<?php eval($_POST[1]); ?>")), 2)?.kind ?? "", /PHP script/);
assert.equal(classifyTrailing(glued(tail([0xff, 0xd8, 0xff, 0xe0])), 2, 1)?.benign, true, "MPF declared it: a phone's second picture");
assert.equal(classifyTrailing(glued(tail([0xff, 0xd8, 0xff, 0xe0])), 2, 0)?.benign, false, "nothing declared it: a hidden picture");

// RAW: the camera's own JPEGs, largest first, sensor data never mistaken for one.
assert.deepEqual(rawPreviews(fixture("camera.dng"), "dng").map((x) => [x.width, x.height]), [[1024, 768]], "a DNG's preview SubIFD (its lossless sensor IFD is not a preview)");
assert.deepEqual(rawPreviews(fixture("camera.cr3"), "cr3").map((x) => [x.width, x.height]), [[800, 534], [160, 120]], "CR3's PRVW, then THMB");
assert.deepEqual(rawPreviews(fixture("camera.raf"), "raf").map((x) => [x.width, x.height]), [[640, 426]], "the JPEG RAF's header points at");
const dng = readTiff(fixture("camera.dng"))!;
assert.equal(dng.ifds.filter((i) => i.sub).length, 2, "both SubIFDs walked");
const loop = new Uint8Array([0x49, 0x49, 42, 0, 8, 0, 0, 0, 1, 0, 0x00, 0x01, 3, 0, 1, 0, 0, 0, 16, 0, 0, 0, 8, 0, 0, 0]);
assert.equal(readTiff(loop)?.ifds.length, 1, "an IFD that points back at itself is read once");
assert.equal((await readMeta(cr3Metadata(fixture("camera.cr3"))[0]!))?.ifd0?.Model, "Canon-ish R", "CR3's CMT1 read as the TIFF it is");

// Metadata: GPS to the metre, the time and its zone, the thumbnail.
const photoMeta = await readMeta(fixture("photo.jpg"));
const gps = gpsOf(photoMeta)!;
assert.deepEqual([gps.lat.toFixed(5), gps.lon.toFixed(5), gps.alt, gps.direction, gps.accuracy, gps.when], ["37.56630", "126.97790", 38, 128, 5, "2026-01-01 18:04:05 UTC"]);
assert.equal(gpsOf(await readMeta(fixture("photo.heic")))?.lat.toFixed(4), "37.5663", "HEIF's EXIF item too");
assert.equal(orientationOf(await readMeta(fixture("portrait.jpg"))), 6);
assert.equal((await readThumbnail(fixture("photo.jpg")))?.length, 2609, "the 160×120 EXIF thumbnail");
assert.equal(await readThumbnail(fixture("scan.tiff")), null, "a TIFF's second page is not a thumbnail");

// The facts.
let pf = await pictureFacts("photo.jpg");
for (const want of [/JPEG picture · 640×480 · Gorani Test Camera 1 · taken 2026-01-02 03:04:05 \+09:00/, /Carries where it was taken: 37\.56630° N, 126\.97790° E · 38 m up · facing 128° · ±5 m/, /artist “Rin Kim”, owner “Rin Kim”/, /serial number “GRN-0042-7781”/]) assert.match(pf.text, want);
assert.equal(pf.facts.find((x) => x.copy)?.copy, "37.56630° N, 126.97790° E", "the coordinates offered to copy are words the fact shows");
assert.ok(pf.facts.find((x) => x.copy)!.text.includes(pf.facts.find((x) => x.copy)!.copy!));
assert.doesNotMatch(pf.text, /Edited|thumbnail|after the end|AI model/, "an honest photo: no editing, no hidden data");
const groups = metaGroups(pf.f).map((g) => g.title);
for (const g of ["Picture", "Taken", "Camera", "Location", "People and rights", "All metadata"]) assert.ok(groups.includes(g), `the Info panel has ${g}`);
pf = await pictureFacts("redacted.jpg", { thumb: { width: 160, height: 120, shape: false, thumbAspect: 4 / 3, pictureAspect: 4 / 3, mean: 14, far: 0.12 } });
assert.match(pf.text, /Edited with “Adobe Photoshop 25\.0 \(Windows\)” — its XMP history records 2 steps, the last “saved”/);
assert.match(pf.text, /Modified 31 hours after it was taken/);
assert.match(pf.text, /thumbnail shows a different picture/, "a box painted over a name, after the thumbnail");
pf = await pictureFacts("cropped.jpg", { thumb: { width: 160, height: 90, shape: true, thumbAspect: 16 / 9, pictureAspect: 1, mean: 40, far: 0.2 } });
assert.match(pf.text, /another shape \(1\.78:1 against 1\.00:1\): the picture was cropped/);
assert.doesNotMatch((await pictureFacts("photo.jpg", { thumb: { width: 160, height: 120, shape: false, thumbAspect: 4 / 3, pictureAspect: 4 / 3, mean: 3, far: 0 } })).text, /thumbnail/, "a matching thumbnail is no news");
pf = await pictureFacts("polyglot.jpg");
assert.match(pf.text, /176 bytes after the end of the picture: a ZIP archive/);
assert.match(pf.text, /Its comment holds code: “<\?php system/);
pf = await pictureFacts("generated.png");
assert.match(pf.text, /made by an AI model \(IPTC DigitalSourceType: trainedAlgorithmicMedia\)/);
assert.match(pf.text, /an image generator's settings \(parameters\): “a water deer in the snow/);
pf = await pictureFacts("bomb.png", { refused: "too-large" });
assert.match(pf.text, /Declares 60000×60000 pixels \(3\.6 gigapixels\) — not drawn: a decompression bomb/);
pf = await pictureFacts("camera.dng", { shown: { width: 1024, height: 768, what: "preview" } });
assert.match(pf.text, /A camera RAW file: showing the camera's own 1024×768 preview — the sensor data \(16×16\) is not decoded/);
pf = await pictureFacts("photo.jpg", {}, "holiday.png");
assert.match(pf.text, /Named \.png, but it is a JPEG picture/);
pf = await pictureFacts("drawing.svg", {}, "logo.png");
assert.equal(pf.facts.find((x) => /Named \.png/.test(x.text))?.level, "warn", "an SVG under a raster name is a warning: SVG can carry script");
pf = await pictureFacts("report.pdf", { refused: "not-a-picture" }, "scan.jpg");
assert.match(pf.text, /Named \.jpg, but it is a PDF — not drawn/);
pf = await pictureFacts("hostile.svg", { svg: { scripts: 1, handlers: 1, foreign: 1, password: true, remote: ["https://phish.example/svg.css", "https://phish.example/svg-beacon.png", "https://phish.example/sprite.svg#logo"], links: ["https://phish.example/login"], jsLinks: 1, entities: false, embedded: 0 } });
for (const want of [/Contains script \(1 <script>, 1 event handler\) — not run/, /Contains HTML \(1 foreignObject\) with a form asking for a password/, /Would load 3 things from outside \(not loaded\)/, /1 javascript: link — inert/, /Links to 1 address \(not followed\): https:\/\/phish\.example\/login/]) assert.match(pf.text, want);
pf = await pictureFacts("entities.svg", { refused: "entities", svg: { scripts: 0, handlers: 0, foreign: 0, password: false, remote: [], links: [], jsLinks: 0, entities: true, embedded: 0 } });
assert.match(pf.text, /Declares XML entities .* not drawn/);
assert.match((await pictureFacts("animated.gif")).text, /Animated: 3 frames/);
assert.doesNotMatch((await pictureFacts("drawing.svg", { svg: { scripts: 0, handlers: 0, foreign: 0, password: false, remote: [], links: [], jsLinks: 0, entities: false, embedded: 0 } })).facts.filter((x) => x.level === "warn").map((x) => x.text).join(), /./, "an honest drawing warns of nothing");

// ── 9. Archives (42e) ────────────────────────────────────────────────
// Our own ZIP, ALZ and EGG readers on archives their own tools wrote (ALZ
// checked with unalz, EGG with ESTsoft's own sample), and 7-Zip — the same
// WebAssembly the frame runs — for the rest.

const { default: sevenFactory } = await import(new URL("../../web/node_modules/7z-wasm/7zz.es6.js", import.meta.url).href);
let seven: SevenZip | null = null;
const sink = SevenZip.sink(() => seven);
seven = new SevenZip(await sevenFactory({ wasmBinary: readFileSync(new URL("../../web/node_modules/7z-wasm/7zz.wasm", import.meta.url)), stdin: () => null, stdout: sink.out, stderr: sink.err, print: () => {}, printErr: () => {} }));
const sz = seven!;
const unpack = { bzip2: async (d: Uint8Array, cap: number) => sz.stream("bz2", d, cap), lzma: async (p: Uint8Array, d: Uint8Array, size: number, cap: number) => sz.lzma(p, d, size, cap) };
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const refused = async (f: () => Promise<unknown>) => {
	try {
		await f();
		return null;
	} catch (e) {
		return e instanceof Refusal ? e.kind : `threw ${e}`;
	}
};
const noFallback = async () => {
	throw new Error("no fallback expected");
};
const LIM = 256 * 1024 * 1024;

// ZIP: names, two kinds of crypto, links, liars and bombs.
let z = listZip(fixture("bundle.zip"))!;
assert.deepEqual(z.items.map((i) => i.path).sort(), ["data/ledger.csv", "docs/notes.md", "docs/고라니.txt", "photos/photo.jpg", "report.txt"]);
assert.equal(z.comment, "Gorani test bundle");
assert.equal(text(await extractZip(fixture("bundle.zip"), z.items.find((i) => i.path === "docs/고라니.txt")!, null, LIM, noFallback)), "고라니 메모 — a Korean file name\n");
z = listZip(fixture("korean.zip"))!;
assert.deepEqual(z.items.map((i) => [i.path, i.encoding]), [["보고서.txt", "cp949"], ["사진/고라니.jpg", "cp949"]], "Korean Windows names, unflagged CP949, read as Korean (7-Zip's build shows question marks)");
assert.equal(decodeName(new TextEncoder().encode("naïve.txt"), false).encoding, "utf-8", "unflagged UTF-8 stays UTF-8");
z = listZip(fixture("lure.zip"))!;
assert.equal(z.items.find((i) => i.path === "passwd")?.link, "", "a Unix symbolic link");
assert.equal(text(await extractZip(fixture("lure.zip"), z.items.find((i) => i.path === "passwd")!, null, LIM, noFallback)), "/etc/passwd", "its body is its target");
z = listZip(fixture("infected.zip"))!;
assert.equal(z.encryption, "ZipCrypto");
assert.equal(text(await extractZip(fixture("infected.zip"), z.items[0]!, "infected", LIM, noFallback)), "MZ gorani fixture: not a program (a sample, swapped zipped)\n");
assert.equal(await refused(() => extractZip(fixture("infected.zip"), z.items[0]!, "wrong", LIM, noFallback)), "password");
assert.equal(await refused(() => extractZip(fixture("infected.zip"), z.items[0]!, null, LIM, noFallback)), "password");
z = listZip(fixture("aes.zip"))!;
assert.equal(z.encryption, "AES-256");
const aesItem = z.items.find((i) => !i.dir)!;
assert.equal(text(await extractZip(fixture("aes.zip"), aesItem, "gorani", LIM, noFallback)), "Gorani archive report\nThe photo is in photos/.\n", "WinZip AES-256, as 7-Zip writes it");
assert.equal(await refused(() => extractZip(fixture("aes.zip"), aesItem, "nope", LIM, noFallback)), "password");
z = listZip(fixture("liar.zip"))!;
assert.equal(await refused(() => extractZip(fixture("liar.zip"), z.items[0]!, null, LIM, noFallback)), "liar", "an entry that inflates past its claim is stopped, never held");
z = listZip(fixture("bomb.zip"))!;
assert.equal(await refused(() => extractZip(fixture("bomb.zip"), z.items[0]!, null, 1024 * 1024, noFallback)), "too-big", "past the viewer's limit, refused before anything inflates");
assert.equal(zipDecrypt("x", new Uint8Array(12), new Uint8Array(0), 0x42), null, "a header whose check byte disagrees: a wrong password, without decrypting the data");
assert.equal(crc32(new TextEncoder().encode("hello")), 0x3610a686);

// ALZ (written here, checked with unalz) and EGG (ESTsoft's specification).
const alz = listAlz(fixture("report.alz"))!;
assert.deepEqual(alz.items.map((i) => [i.path, i.method]), [["report.txt", "Store"], ["docs/notes.md", "Deflate"], ["docs/고라니.txt", "BZip2"], ["photos/photo.jpg", "Deflate"]]);
assert.equal(alz.items[0]!.modified, "2026-01-02 03:04:04", "a DOS date and time");
assert.equal(text(await extractAlz(fixture("report.alz"), alz.items[2]!, null, LIM, unpack.bzip2)), "고라니 메모 — a Korean file name\n", "bzip2, through 7-Zip");
const ialz = listAlz(fixture("infected.alz"))!;
assert.equal(text(await extractAlz(fixture("infected.alz"), ialz.items[1]!, "infected", LIM, unpack.bzip2)), "MZ gorani fixture: not a program\n", "ZipCrypto: its 12-byte header outside the packed size");
assert.equal(await refused(() => extractAlz(fixture("infected.alz"), ialz.items[1]!, "wrong", LIM, unpack.bzip2)), "password");
const egg = listEgg(fixture("report.egg"))!;
assert.deepEqual(egg.items.map((i) => i.path), ["docs", "report.txt", "docs/notes.md", "docs/고라니.txt", "photos/photo.jpg", "run.sh"], "a path given by its parent's id; a CP949 name by its code page");
assert.equal(egg.comment, "Gorani EGG fixture");
assert.equal(egg.items[5]!.attributes, "-rwxr-xr-x", "POSIX information");
for (const i of egg.items.filter((x) => !x.dir)) assert.ok((await extractEgg(fixture("report.egg"), egg, i, null, LIM, unpack)).length === i.size, `${i.path} (${i.method}) unpacks`);
const legg = listEgg(fixture("locked.egg"))!;
assert.equal(text(await extractEgg(fixture("locked.egg"), legg, legg.items[0]!, "infected", LIM, unpack)), "the sample is inside\n", "ZipCrypto");
assert.equal(text(await extractEgg(fixture("locked.egg"), legg, legg.items[1]!, "gorani", LIM, unpack)), "Gorani archive report\nThe photo is in photos/.\n", "AES-256, WinZip's scheme, its MAC checked");
assert.equal(await refused(() => extractEgg(fixture("locked.egg"), legg, legg.items[1]!, "nope", LIM, unpack)), "password");
const segg = listEgg(fixture("solid.egg"))!;
assert.equal(text(await extractEgg(fixture("solid.egg"), segg, segg.items[1]!, null, LIM, unpack)), "beta, in the same stream\n", "solid: one stream, cut at each file's place");
const aegg = listEgg(fixture("azo.egg"))!;
assert.equal(await refused(() => extractEgg(fixture("azo.egg"), aegg, aegg.items[0]!, null, LIM, unpack)), "unsupported", "AZO: listed, not opened");
// ESTsoft's own sample (Section 4), its CRC as the earlier example prints it.
const hex = (s: string) => new Uint8Array(s.match(/../g)!.map((x) => parseInt(x, 16)));
const ascii = (s: string) => [...new TextEncoder().encode(s)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sample = hex(`45474741000101000000000000002282E208E390850A000000000500000000000000AC91850A000900${ascii("hello.txt")}0B95862C00090080957F1543DDC901002282E208130CB5020000050000000500000086A610362282E208${ascii("hello")}2282E208`);
const sl = listEgg(sample)!;
assert.deepEqual([sl.items[0]!.path, sl.items[0]!.size, sl.warnings], ["hello.txt", 5, []]);
assert.equal(text(await extractEgg(sample, sl, sl.items[0]!, null, LIM, unpack)), "hello");

// 7-Zip: every other format, a .tar.gz opened to its TAR, names hidden by AES.
const seven7 = (name: string): Listing => {
	sz.load(fixture(name), name);
	let l = sz.list(null, fixture(name).length);
	const inner = sz.innerTar(l, LIM);
	if (inner) {
		sz.load(inner.bytes, inner.name);
		l = { ...sz.list(null, inner.bytes.length), inner: inner.name };
	}
	return l;
};
for (const [name, format] of [["bundle.7z", "7z"], ["bundle.rar", "RAR 5"], ["bundle.cab", "CAB (Windows cabinet)"], ["bundle.iso", "ISO 9660 disk image"], ["bundle.arj", "ARJ"], ["bundle.lzh", "LHA (LZH)"], ["bundle.tar.gz", "TAR"], ["bundle.tar.xz", "TAR"], ["bundle.tar.bz2", "TAR"]] as const) {
	const l = seven7(name);
	assert.equal(l.format, format, name);
	const report = l.entries.find((e) => /report\.txt$/.test(e.path))!;
	assert.equal(text(sz.extract(report.path, null, LIM)), "Gorani archive report\nThe photo is in photos/.\n", `${name}: an entry, out`);
}
assert.ok(seven7("bundle.iso").entries.some((e) => e.path === "docs/고라니.txt"), "a Korean name through Joliet");
let one = seven7("notes.txt.zst");
assert.deepEqual(one.entries.map((e) => e.path), ["notes.txt"], "a single stream, named after its archive");
assert.equal(text(sz.extract("notes.txt", null, LIM)), "# Notes\n\n- 고라니 (water deer)\n- *field* notes\n");
one = seven7("locked.7z");
assert.equal(one.headersEncrypted, true, "AES with encrypted names: nothing listed without the password");
sz.load(fixture("locked.7z"), "locked.7z");
assert.ok(sz.list("gorani", 1).entries.some((e) => e.path === "bundle/report.txt"), "…and everything with it");
assert.equal(streamName("/in/x.tgz"), "x.tar");
assert.equal(troubleOf("ERROR: Wrong password : a"), "password");
assert.equal(parseListing("--\nPath = /in/a\nType = zip\n\n----------\nPath = a\u0000b\nSize = 1\n", "/in/a", 1).entries[0]!.path, "a\u0000b");

// The facts.
const af = (name: string, password: string | null = null) => {
	const l = listZip(fixture(name)) ?? listAlz(fixture(name)) ?? listEgg(fixture(name))!;
	const two = "items" in l ? (l as unknown as { items: { path: string; localName?: string | null }[] }).items.filter((i) => i.localName).map((i) => ({ central: i.path, local: i.localName! })) : [];
	return said(archiveFacts({ name, listing: l, password, links: new Map([[2, "/etc/passwd"]]), twoNames: two }));
};
let at = af("lure.zip");
for (const want of [/climbs out of the folder .* “\.\.\/\.\.\/evil\.txt”/, /absolute path, written wherever it names: “\/etc\/cron\.d\/gorani”/, /symbolic link: “passwd” → “\/etc\/passwd”/, /invoice\.pdf\.exe” \(it pretends to be \.pdf/, /right-to-left mark/, /Open me\.lnk” \(a Windows shortcut\)/, /Holds 1 archive of its own: “nested\.zip”/, /The same path more than once: “report\.txt”/, /Comment: “Your invoice is attached”/]) assert.match(at, want);
assert.match(af("infected.zip"), /Every entry is encrypted \(ZipCrypto\) — no scanner looked inside/);
assert.match(af("infected.zip", "infected"), /Opened with the password “infected” — .* treated as samples/);
assert.match(af("bomb.zip"), /unpacks to 20\.0 MB from 19\.9 kB \(1029×\) — a ZIP bomb's ratio/);
assert.match(af("azo.egg"), /compressed with AZO/);
assert.doesNotMatch(af("bundle.zip"), /climbs|absolute|symbolic|pretend|encrypted|bomb/, "an honest bundle warns of nothing");
assert.match(said(archiveFacts({ name: "bundle.iso", listing: seven7("bundle.iso"), password: null, links: new Map() })), /A disk image: files taken out of it do not carry Windows' downloaded-from-the-internet mark/);
assert.match(said(archiveFacts({ name: "bundle.zip", listing: seven7("bundle.rar"), password: null, links: new Map() })), /Named \.zip, but it is a RAR 5 archive/);
assert.equal(pathRisk("a/../../b"), "traversal");
assert.equal(pathRisk("C:\\Windows\\x.dll"), "absolute");
assert.equal(pathRisk("..file/ok"), null, "a name that starts with dots is not a climb");
assert.deepEqual([...treeOf(listZip(fixture("lure.zip"))!.entries).children.keys()].filter((k) => k.startsWith("report")).length, 2, "the same path twice: both shown");

console.log("ok  preview-facts: ZIP bombs refused (a lying part, an over-claiming directory); every planted trick in the hostile Word, Excel, PowerPoint, 한글, .doc and RTF fixtures named — and the honest reports warn of nothing; the phishing .eml's and .msg's every trick named, the forged Authentication-Results not believed, the hop the sender could not write found, a forwarded message parsed in turn, attachments judged by name and bytes; pictures sniffed by their bytes, a bomb's size read before decoding, what follows a picture's end named, a RAW file's own previews found, GPS, the camera and the editing read, a thumbnail that no longer matches named; archives read by our ZIP, ALZ and EGG readers and by 7-Zip (7z, RAR 5, TAR in three compressions, CAB, ISO, ARJ, LZH, zstd), CP949 names, ZipCrypto and AES opened and wrong passwords refused, liars and bombs stopped, AZO listed and not opened, and every lure's trick named");
