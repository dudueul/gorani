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

for (const f of ["report.hwp", "report.hwpx", "locked.hwp", "hostile.hwp", "hostile.doc"]) if (fs.existsSync(path.join(out, f))) console.log(`${f}: ${fs.statSync(path.join(out, f)).size} bytes`);
