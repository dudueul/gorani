// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The 한글 fixtures, and the OLE surgery Python cannot do (commit 42b,
 * docs/PREVIEWS.md). Run after office.py, from the repository root:
 *
 *     node tests/fixtures/preview/ole.mjs tests/fixtures/preview
 *
 * report.hwp    two pages (a page break), Korean and English, made by rhwp
 * report.hwpx   the same, as HWPX
 * locked.hwp    the same, protected with the password "gorani"
 * hostile.hwp   what an HWP lure carries: a script run on opening
 *               (Scripts/DefaultJScript, with code in it), PostScript in
 *               BinData (the Ghostscript route), an OLE object, a link
 * hostile.doc   office.py's LibreOffice copy of hostile.docx, plus what a
 *               Word 97 lure carries in its container: a macro project
 *               (Macros/VBA), an Equation Editor 3.0 object, a packaged
 *               program (\x01Ole10Native)
 * outlook.msg   a phishing message as Outlook saves it (42c): its headers as
 *               received (SPF failing), an HTML body with a link that reads
 *               paypal.com and a tracking pixel, invoice.pdf.exe attached
 *
 * Every byte is ours; nothing here is a working exploit (the "script" is
 * text, the PostScript draws nothing, the "program" is a sentence).
 */

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const out = path.resolve(process.argv[2] ?? "tests/fixtures/preview");
const require = createRequire(path.resolve("web/package.json"));
const CFB = require("cfb");
const { deflateSync } = require("fflate");
const rhwp = await import(require.resolve("@rhwp/core"));
// rhwp asks the page how wide a run of text is; here, a fixed width per character.
globalThis.measureTextWidth = (_font, text) => text.length * 10;
await rhwp.default({ module_or_path: fs.readFileSync(require.resolve("@rhwp/core/rhwp_bg.wasm")) });
const { HwpDocument } = rhwp;

function twoPages(first, second) {
	const doc = HwpDocument.createEmpty();
	doc.createBlankDocument();
	doc.insertText(0, 0, 0, first);
	doc.insertPageBreak(0, 0, doc.getParagraphLength(0, 0));
	doc.insertText(0, 1, 0, second);
	return doc;
}

const report = twoPages("Gorani HWP page one — 고라니 한글 문서", "고라니 한글 둘째 쪽 — Gorani HWP page two");
fs.writeFileSync(path.join(out, "report.hwp"), report.exportHwp());
fs.writeFileSync(path.join(out, "report.hwpx"), report.exportHwpx());
fs.writeFileSync(path.join(out, "locked.hwp"), report.exportHwpWithPassword("gorani"));

// ── hostile.hwp ─────────────────────────────────────────────────────────

const lure = HwpDocument.createEmpty();
lure.createBlankDocument();
lure.insertText(0, 0, 0, "Invoice overdue — pay here");
lure.insertHyperlinkEx(JSON.stringify({ target: { section: 0, para: 0, cellPath: [] }, start: 18, end: 26, uri: "https://phish.example/login" }));

/** A 한글 script stream: length-prefixed UTF-16 strings, then 0xFFFFFFFF. */
function scriptStream(...parts) {
	const chunks = [];
	for (const p of parts) {
		const len = Buffer.alloc(4);
		len.writeUInt32LE(p.length);
		chunks.push(len, Buffer.from(p, "utf16le"));
	}
	chunks.push(Buffer.from([0xff, 0xff, 0xff, 0xff]));
	return Buffer.concat(chunks);
}

const hwp = CFB.read(Buffer.from(lure.exportHwp()), { type: "buffer" });
const put = (c, name, data) => {
	const at = c.FullPaths.findIndex((p) => p === `Root Entry/${name}`);
	if (at >= 0) {
		c.FileIndex[at].content = data;
		c.FileIndex[at].size = data.length;
	} else CFB.utils.cfb_add(c, `/${name}`, data);
};
// The document is "compressed" (FileHeader flag 1): its streams are raw DEFLATE.
put(hwp, "Scripts/DefaultJScript", Buffer.from(deflateSync(scriptStream("", "function OnDocument_Open() { var s = new ActiveXObject('WScript.Shell'); s.Run('calc.exe'); }", "", ""))));
put(hwp, "BinData/BIN0001.eps", Buffer.from("%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\n(gorani fixture: not a real exploit) pop\n"));
put(hwp, "BinData/BIN0002.OLE", Buffer.from("gorani fixture: not a real OLE object\n"));
fs.writeFileSync(path.join(out, "hostile.hwp"), CFB.write(hwp, { type: "buffer", fileType: "cfb" }));

// ── hostile.doc ─────────────────────────────────────────────────────────

const docPath = path.join(out, "hostile.doc");
if (fs.existsSync(docPath)) {
	const doc = CFB.read(fs.readFileSync(docPath), { type: "buffer" });
	if (!doc.FullPaths.some((p) => p.startsWith("Root Entry/Macros/"))) {
		put(doc, "Macros/VBA/dir", Buffer.from("gorani fixture: not a real VBA project\n"));
		put(doc, "Macros/PROJECT", Buffer.from('ID="{00000000-0000-0000-0000-000000000000}"\r\nDocument=ThisDocument/&H00000000\r\n'));
		// An Equation Editor 3.0 object: its CompObj names the class.
		const ansi = (s) => {
			const b = Buffer.alloc(4 + s.length + 1);
			b.writeUInt32LE(s.length + 1);
			b.write(s, 4, "latin1");
			return b;
		};
		const compObj = Buffer.concat([Buffer.from("0100feff030a0000ffffffff0002ce020000000000c000000000000046", "hex").subarray(0, 28), ansi("Microsoft Equation 3.0"), ansi("DS Equation"), ansi("Equation.3")]);
		put(doc, "ObjectPool/_1234567890/\u0001CompObj", compObj);
		put(doc, "ObjectPool/_1234567890/Equation Native", Buffer.from("gorani fixture: not a real equation\n"));
		// A packaged file: \x01Ole10Native — size, 2, label, the path it came from, …
		const label = "invoice.pdf.exe";
		const from = "C:\\Users\\phisher\\Desktop\\invoice.pdf.exe";
		const body = Buffer.concat([Buffer.from([2, 0]), Buffer.from(`${label}\0${from}\0`, "latin1"), Buffer.from([0, 0, 3, 0]), Buffer.from("gorani fixture: not a program\n")]);
		const size = Buffer.alloc(4);
		size.writeUInt32LE(body.length);
		put(doc, "ObjectPool/_1234567891/\u0001Ole10Native", Buffer.concat([size, body]));
		fs.writeFileSync(docPath, CFB.write(doc, { type: "buffer", fileType: "cfb" }));
	}
} else console.log("(no hostile.doc: run office.py first, with LibreOffice)");

// ── outlook.msg ─────────────────────────────────────────────────────────
// Outlook's own file: an OLE container of MAPI properties, each a stream
// named __substg1.0_<tag><type> (001F a UTF-16 string, 0102 bytes), listed
// with their sizes in __properties_version1.0; recipients and attachments
// in storages of their own. Its headers as received are one property
// (PR_TRANSPORT_MESSAGE_HEADERS, 007D) — the phishing's, SPF failing.

const msg = CFB.utils.cfb_new();
const add = (p, d) => CFB.utils.cfb_add(msg, `/${p}`, d);
const u16 = (s) => Buffer.from(s, "utf16le");
/** A property stream: a header (32 bytes at the top: counts and next ids;
 * 8 in a recipient or attachment), then 16 bytes a property. */
const propsOf = (entries, top) => {
	const head = Buffer.alloc(top ? 32 : 8);
	if (top) for (const at of [8, 12, 16, 20]) head.writeUInt32LE(1, at);
	return Buffer.concat([head, ...entries.map(([tag, value]) => {
		const b = Buffer.alloc(16);
		b.writeUInt32LE(tag, 0);
		b.writeUInt32LE(6, 4); // readable, writable
		b.writeUInt32LE(value, 8);
		return b;
	})]);
};
const strProp = (dir, tag, text) => {
	const data = u16(text);
	add(`${dir}__substg1.0_${tag.toString(16).toUpperCase().padStart(8, "0")}`, data);
	return [tag, data.length + 2];
};
const binProp = (dir, tag, data) => {
	add(`${dir}__substg1.0_${tag.toString(16).toUpperCase().padStart(8, "0")}`, data);
	return [tag, data.length];
};
const headersAsReceived = [
	"Received: from mx.gorani.example (mx.gorani.example [192.0.2.10]) by mail.gorani.example; Fri, 2 Jan 2026 05:00:02 +0000",
	"Received: from mail.secure-login.example (unknown [203.0.113.7]) by mx.gorani.example; Fri, 2 Jan 2026 05:00:01 +0000",
	"Authentication-Results: mx.gorani.example; spf=fail smtp.mailfrom=secure-login.example; dkim=none; dmarc=fail header.from=paypal.com.secure-login.example",
	'From: "PayPal Security" <service@paypal.com.secure-login.example>',
	"Reply-To: <collect@phish.example>",
	"To: <rin@gorani.example>",
	"Subject: Invoice overdue (Outlook)",
	"Date: Fri, 02 Jan 2026 05:00:00 +0000",
	"",
	"",
].join("\r\n");
const top = [
	strProp("", 0x001a001f, "IPM.Note"),
	strProp("", 0x0037001f, "Invoice overdue (Outlook)"),
	strProp("", 0x0c1a001f, "PayPal Security"),
	strProp("", 0x0c1f001f, "service@paypal.com.secure-login.example"),
	strProp("", 0x1000001f, "Pay the invoice today: https://phish.example/login"),
	strProp("", 0x007d001f, headersAsReceived),
	binProp("", 0x10130102, Buffer.from('<html><body><p>Pay the invoice today.</p><p><a href="https://phish.example/login">https://www.paypal.com/signin</a></p><img src="https://phish.example/open.gif" width="1" height="1"></body></html>')),
];
add("__properties_version1.0", propsOf(top, true));
const recip = "__recip_version1.0_#00000000/";
strProp(recip, 0x3001001f, "Rin");
strProp(recip, 0x39fe001f, "rin@gorani.example");
add(`${recip}__properties_version1.0`, propsOf([[0x0c150003, 1]], false)); // a To: recipient
const attach = "__attach_version1.0_#00000000/";
const program = Buffer.from("MZ gorani fixture: not a program\n");
strProp(attach, 0x3707001f, "invoice.pdf.exe");
binProp(attach, 0x37010102, program);
add(`${attach}__properties_version1.0`, propsOf([[0x37050003, 1], [0x0e200003, program.length]], false)); // attached by value
fs.writeFileSync(path.join(out, "outlook.msg"), CFB.write(msg, { type: "buffer", fileType: "cfb" }));

for (const f of ["report.hwp", "report.hwpx", "locked.hwp", "hostile.hwp", "hostile.doc", "outlook.msg"]) if (fs.existsSync(path.join(out, f))) console.log(`${f}: ${fs.statSync(path.join(out, f)).size} bytes`);
