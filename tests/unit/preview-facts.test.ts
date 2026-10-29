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

console.log("ok  preview-facts: ZIP bombs refused (a lying part, an over-claiming directory); every planted trick in the hostile Word, Excel, PowerPoint, 한글, .doc and RTF fixtures named — and the honest reports warn of nothing; the phishing .eml's and .msg's every trick named, the forged Authentication-Results not believed, the hop the sender could not write found, a forwarded message parsed in turn, attachments judged by name and bytes");
