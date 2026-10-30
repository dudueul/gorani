# Copyright 2026- Seongwoo Hong. All rights reserved.
"""
The archive fixtures (commit 42e, docs/PREVIEWS.md › Archives): one small
tree, packed by each format's own tool, and the archives a lure or a
malware exchange arrives in. Run after make.py and images.py (it packs
their files), from the repository root:

    python3 -I tests/fixtures/preview/archives.py tests/fixtures/preview

It needs the formats' own tools (Ubuntu: zip 7zip rar gcab xorriso lhasa
arj zstd): an archive written by the program people use is the test
that matters. Every file in the tree is dated 2026-01-02 03:04:05 UTC.

bundle.zip, .7z, .rar, .tar.gz, .tar.xz, .tar.bz2, .cab, .iso, .lzh, .arj
                 the same tree: report.txt, docs/notes.md, docs/고라니.txt
                 (a Korean name), photos/photo.jpg, data/ledger.csv
notes.txt.gz, notes.txt.zst
                 one file each (a stream, not an archive)
korean.zip       Korean names as Korean Windows writes them: CP949 bytes,
                 no UTF-8 flag
lure.zip         a ZIP Slip path (../../), an absolute path, a symbolic
                 link to /etc/passwd, invoice.pdf.exe, a right-to-left
                 mark, the same name twice, an archive inside, a shortcut
infected.zip     ZipCrypto, password "infected" (how samples are swapped)
locked.7z        AES-256 with its names encrypted too (password "gorani")
bomb.zip         20 MB of zeros in 20 kB: a ratio of a thousand
liar.zip         an entry that says 1 kB and inflates to 4 MB
aes.zip          WinZip AES-256 (7-Zip's), password "gorani"
report.alz       ALZip's own format, written here and checked with unalz:
                 stored, deflated and bzip2 entries, a Korean (CP949) name
infected.alz     the same, one entry ZipCrypto-encrypted with "infected"
report.egg       EGG, from ESTsoft's specification: stored, deflated,
                 bzip2 and LZMA blocks, a CP949 name with its code page, a
                 path given by a parent's id, POSIX info, a comment
locked.egg       ZipCrypto ("infected") and AES-256 ("gorani") entries
solid.egg        a solid EGG: every file in one deflated block
azo.egg          an entry compressed with AZO (ESTsoft's own method)

Nothing here is a working exploit: the "program" is a sentence.
"""

import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path

out = Path(sys.argv[1]).resolve()
WHEN = 1767323045  # 2026-01-02 03:04:05 UTC
DOS = (2026, 1, 2, 3, 4, 4)  # DOS time has 2-second steps
env = {**os.environ, "TZ": "UTC", "SOURCE_DATE_EPOCH": str(WHEN), "LC_ALL": "C.UTF-8"}

TREE = {
    "report.txt": b"Gorani archive report\nThe photo is in photos/.\n",
    "docs/notes.md": "# Notes\n\n- 고라니 (water deer)\n- *field* notes\n".encode(),
    "docs/고라니.txt": "고라니 메모 — a Korean file name\n".encode(),
    "photos/photo.jpg": (out / "photo.jpg").read_bytes(),
    "data/ledger.csv": b"date,amount\n2026-01-02,100\n",
}

written: list[str] = []


def stage() -> Path:
    d = Path(tempfile.mkdtemp(prefix="gorani-archive-"))
    for name, data in TREE.items():
        p = d / "bundle" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    for p in sorted((d / "bundle").rglob("*"), reverse=True):
        os.utime(p, (WHEN, WHEN))
    os.utime(d / "bundle", (WHEN, WHEN))
    return d


def run(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def keep(name: str, data: bytes) -> None:
    (out / name).write_bytes(data)
    written.append(name)


def take(name: str, built: Path) -> None:
    keep(name, built.read_bytes())


d = stage()
names = sorted(str(p.relative_to(d)) for p in (d / "bundle").rglob("*") if p.is_file())

# ZIP, by Python (UTF-8 names flagged), with a comment.
with zipfile.ZipFile(out / "bundle.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.comment = b"Gorani test bundle"
    for n in names:
        info = zipfile.ZipInfo(n.removeprefix("bundle/"), date_time=DOS)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        z.writestr(info, (d / n).read_bytes())
written.append("bundle.zip")

# 7z, RAR 5, CAB, ISO 9660, LHA, ARJ: each by its own program.
run(["7z", "a", "-t7z", "-mx=5", "-mtc=off", "-mta=off", str(d / "bundle.7z"), "bundle"], d)
take("bundle.7z", d / "bundle.7z")
run(["rar", "a", "-ma5", "-m3", "-ts-", "-tsm", "-idq", str(d / "bundle.rar"), "bundle"], d)
take("bundle.rar", d / "bundle.rar")
run(["gcab", "-c", "-z", "-n", str(d / "bundle.cab"), *[str(d / n) for n in names]], d)
take("bundle.cab", d / "bundle.cab")
run(["xorriso", "-as", "mkisofs", "-quiet", "-J", "-R", "-V", "GORANI", "-o", str(d / "bundle.iso"), "bundle"], d)
take("bundle.iso", d / "bundle.iso")
run(["arj", "a", "-r", "-y", "-i", str(d / "bundle.arj"), "bundle"], d)
take("bundle.arj", d / "bundle.arj")

# TAR, compressed three ways (Python, with every date fixed).
def tar_bytes() -> bytes:
    import io

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for n in names:
            data = (d / n).read_bytes()
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime, ti.mode, ti.uname, ti.gname = len(data), WHEN, 0o644, "rin", "gorani"
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


import bz2
import gzip
import lzma

raw_tar = tar_bytes()
keep("bundle.tar.gz", gzip.compress(raw_tar, mtime=0))
keep("bundle.tar.xz", lzma.compress(raw_tar))
keep("bundle.tar.bz2", bz2.compress(raw_tar))
keep("notes.txt.gz", gzip.compress(TREE["docs/notes.md"], mtime=0))
(d / "notes.txt").write_bytes(TREE["docs/notes.md"])
run(["zstd", "-q", "-19", "-f", "notes.txt", "-o", "notes.txt.zst"], d)
take("notes.txt.zst", d / "notes.txt.zst")


# ── LHA (.lzh), written by hand: Ubuntu's lhasa only reads ─────────────
# Level-0 headers, stored (-lh0-): size, checksum, method, sizes, DOS
# time, attribute, level, name, CRC-16 — then a zero byte ends it.


def crc16(data: bytes) -> int:
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def lzh(entries: list[tuple[str, bytes]]) -> bytes:
    t, dt = dos_time()
    buf = bytearray()
    for name, data in entries:
        raw = name.replace("/", "\\").encode("cp949")
        body = b"-lh0-" + struct.pack("<IIHHBB", len(data), len(data), t, dt, 0x20, 0) + bytes([len(raw)]) + raw + struct.pack("<H", crc16(data))
        buf += bytes([len(body), sum(body) & 0xFF]) + body + data
    return bytes(buf + b"\x00")


# ── ZIPs written byte by byte: what no polite tool writes ──────────────


def dos_time() -> tuple[int, int]:
    y, mo, da, h, mi, s = DOS
    return (h << 11) | (mi << 5) | (s // 2), ((y - 1980) << 9) | (mo << 5) | da


def raw_zip(entries: list[dict], comment: bytes = b"") -> bytes:
    """entries: name (bytes), data (bytes), flags, method (0/8), unix mode,
    and optional claimed size (a liar's)."""
    t, dt = dos_time()
    body = bytearray()
    central = bytearray()
    for e in entries:
        data = e["data"]
        method = e.get("method", 8)
        packed = zlib.compress(data, 9)[2:-4] if method == 8 else data
        crc = zlib.crc32(data) & 0xFFFFFFFF
        size = e.get("claim", len(data))
        flags = e.get("flags", 0)
        name = e["name"]
        local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, t, dt, crc, len(packed), size, len(name), 0) + name
        offset = len(body)
        body += local + packed
        mode = e.get("mode", 0o100644)
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20, 20, flags, method, t, dt, crc, len(packed), size, len(name), 0, 0, 0, 0, mode << 16, offset) + name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), len(body), len(comment)) + comment
    return bytes(body + central + end)


UTF8 = 0x800
keep("bundle.lzh", lzh([(n.removeprefix("bundle/"), (d / n).read_bytes()) for n in names]))

keep("korean.zip", raw_zip([
    {"name": "보고서.txt".encode("cp949"), "data": "분기 보고서 — CP949로 쓴 이름\n".encode()},
    {"name": "사진/고라니.jpg".encode("cp949"), "data": TREE["photos/photo.jpg"], "method": 0},
]))

inner = raw_zip([{"name": b"inner.txt", "data": b"an archive inside an archive\n"}])
program = b"MZ gorani fixture: not a program\n"
keep("lure.zip", raw_zip([
    {"name": b"../../evil.txt", "data": b"written outside the folder it was extracted to\n"},
    {"name": b"/etc/cron.d/gorani", "data": b"* * * * * root echo gorani\n"},
    {"name": b"passwd", "data": b"/etc/passwd", "method": 0, "mode": 0o120777},
    {"name": b"invoice.pdf.exe", "data": program},
    {"name": "invoice‮fdp.exe".encode(), "data": program, "flags": UTF8},
    {"name": b"report.txt", "data": b"the first report.txt\n"},
    {"name": b"report.txt", "data": b"the second report.txt: which one a tool shows is up to the tool\n"},
    {"name": b"nested.zip", "data": inner, "method": 0},
    {"name": b"Open me.lnk", "data": b"L\x00\x00\x00gorani fixture: not a shortcut\n"},
], comment=b"Your invoice is attached"))

zeros = b"\x00" * (20 * 1024 * 1024)
keep("bomb.zip", raw_zip([{"name": b"zeros.bin", "data": zeros}]))
keep("liar.zip", raw_zip([{"name": b"small.txt", "data": b"A" * (4 * 1024 * 1024), "claim": 1024}]))

# Encrypted: ZipCrypto with "infected" (zip -P), and 7z AES-256 with its names hidden.
# (Its own bytes: not the email fixtures' "program", so saving both is not a duplicate.)
(d / "sample.exe").write_bytes(b"MZ gorani fixture: not a program (a sample, swapped zipped)\n")
os.utime(d / "sample.exe", (WHEN, WHEN))
run(["zip", "-q", "-X", "-P", "infected", "infected.zip", "sample.exe"], d)
take("infected.zip", d / "infected.zip")
run(["7z", "a", "-t7z", "-pgorani", "-mhe=on", "-mtc=off", "-mta=off", str(d / "locked.7z"), "bundle"], d)
take("locked.7z", d / "locked.7z")


run(["7z", "a", "-tzip", "-mem=AES256", "-pgorani", "-mtc=off", str(d / "aes.zip"), "bundle/report.txt"], d)
take("aes.zip", d / "aes.zip")


# ── ZipCrypto, for ALZ and EGG (written here; ZIP's comes from zip -P) ──

CRCT = []
for n in range(256):
    c = n
    for _ in range(8):
        c = 0xEDB88320 ^ (c >> 1) if c & 1 else c >> 1
    CRCT.append(c)


class ZipKeys:
    def __init__(self, password: bytes) -> None:
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in password:
            self.update(b)

    def update(self, b: int) -> None:
        k0, k1, k2 = self.k
        k0 = CRCT[(k0 ^ b) & 0xFF] ^ (k0 >> 8)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = CRCT[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
        self.k = [k0, k1, k2]

    def byte(self) -> int:
        t = (self.k[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF


def zipcrypt(password: bytes, data: bytes, check: int) -> tuple[bytes, bytes]:
    """(the encrypted 12-byte header, the encrypted data)."""
    k = ZipKeys(password)
    out = bytearray()
    for b in bytes(range(7, 18)) + bytes([check]) + data:
        out.append(b ^ k.byte())
        k.update(b)
    return bytes(out[:12]), bytes(out[12:])


def deflate_raw(data: bytes) -> bytes:
    return zlib.compress(data, 9)[2:-4]


# ── ALZ (ALZip), the layout unalz reads ─────────────────────────────────


def alz_entry(name: str, data: bytes, method: int, password: bytes | None = None) -> bytes:
    t, dt = dos_time()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    packed = data if method == 0 else bz2.compress(data) if method == 1 else deflate_raw(data)
    head = b""
    if password:
        head, packed = zipcrypt(password, packed, crc >> 24)
    raw = name.encode("cp949")
    desc = 0x40 | (1 if password else 0)  # 4-byte sizes; bit 0: encrypted
    return b"BLZ\x01" + struct.pack("<HBIBB", len(raw), 0x20, (dt << 16) | t, desc, 0) + struct.pack("<BBIII", method, 0, crc, len(packed), len(data)) + raw + head + packed


def alz(entries: list[bytes]) -> bytes:
    return b"ALZ\x01" + struct.pack("<HH", 10, 0) + b"".join(entries) + b"CLZ\x01" + b"\x00" * 12 + b"CLZ\x02" + b"\x00" * 4


alz_files = [
    ("report.txt", TREE["report.txt"], 0),
    ("docs/notes.md", TREE["docs/notes.md"], 2),
    ("docs/고라니.txt", TREE["docs/고라니.txt"], 1),
    ("photos/photo.jpg", TREE["photos/photo.jpg"], 2),
]
keep("report.alz", alz([alz_entry(n, data, m) for n, data, m in alz_files]))
keep("infected.alz", alz([alz_entry("readme.txt", b"open sample.exe with care\n", 2), alz_entry("sample.exe", program, 2, b"infected")]))


# ── EGG, from ESTsoft's specification ───────────────────────────────────

END = b"\x22\x82\xe2\x08"


def efield(magic: int, data: bytes, flags: int = 0) -> bytes:
    return struct.pack("<IBH", magic, flags, len(data)) + data


FILETIME = (WHEN + 11644473600) * 10_000_000


def egg_file(fid: int, name: str, data: bytes, *, locale: int | None = None, parent: int | None = None, directory: bool = False, posix: int | None = None, cipher: bytes | None = None) -> bytes:
    raw = name.encode("cp949") if locale else name.encode()
    flags = (0x08 if locale else 0) | (0x10 if parent is not None else 0)
    body = (struct.pack("<H", locale) if locale else b"") + (struct.pack("<I", parent) if parent is not None else b"") + raw
    out = struct.pack("<IIQ", 0x0A8590E3, fid, len(data)) + efield(0x0A8591AC, body, flags)
    out += efield(0x2C86950B, struct.pack("<QB", FILETIME, 0x80 if directory else 0x20))
    if posix is not None:
        out += efield(0x1EE922E5, struct.pack("<IIIQ", posix, 1000, 1000, WHEN))
    if cipher:
        out += efield(0x08D1470F, cipher)
    return out + END


def egg_block(method: int, data: bytes, packed: bytes) -> bytes:
    return struct.pack("<IBBIII", 0x02B50C13, method, 0, len(data), len(packed), zlib.crc32(data) & 0xFFFFFFFF) + END + packed


def lzma_block(data: bytes) -> bytes:
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}])
    props = bytes([(2 * 5 + 0) * 9 + 3]) + struct.pack("<I", 1 << 16)
    return b"\x09\x14\x05\x00" + props + raw  # ZIP-style: version 9.20, 5 property bytes


def egg(body: bytes, *, solid: bool = False, comment: str | None = None) -> bytes:
    head = b"EGGA" + struct.pack("<HII", 0x0100, 0x47524E31, 0) + (efield(0x24E5A060, b"") if solid else b"") + END
    return head + body + (efield(0x04C63672, comment.encode()) if comment else b"") + END


pack_ = lambda m, data: data if m == 0 else deflate_raw(data) if m == 1 else bz2.compress(data) if m == 2 else lzma_block(data)
report_egg = b""
report_egg += egg_file(1, "docs", b"", directory=True) + b""
for fid, name, data, method, extra in [
    (2, "report.txt", TREE["report.txt"], 0, {}),
    (3, "notes.md", TREE["docs/notes.md"], 1, {"parent": 1}),
    (4, "docs/고라니.txt", TREE["docs/고라니.txt"], 2, {"locale": 949}),
    (5, "photos/photo.jpg", TREE["photos/photo.jpg"], 4, {}),
    (6, "run.sh", b"#!/bin/sh\necho gorani\n", 1, {"posix": 0o100755}),
]:
    report_egg += egg_file(fid, name, data, **extra) + egg_block(method, data, pack_(method, data))
keep("report.egg", egg(report_egg, comment="Gorani EGG fixture"))

secret = b"the sample is inside\n"
crc = zlib.crc32(secret) & 0xFFFFFFFF
packed = deflate_raw(secret)
zhead, zdata = zipcrypt(b"infected", packed, crc >> 24)
locked = egg_file(1, "sample.txt", secret, cipher=b"\x00" + zhead + struct.pack("<I", crc)) + egg_block(1, secret, zdata)

import hashlib
import hmac as hmac_mod

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

salt = bytes(range(16))
dk = hashlib.pbkdf2_hmac("sha1", b"gorani", salt, 1000, 2 * 32 + 2)
aes_key, mac_key, verifier = dk[:32], dk[32:64], dk[64:66]
plain = deflate_raw(TREE["report.txt"])
enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
stream = b"".join(enc.update(struct.pack("<Q", i + 1) + b"\x00" * 8) for i in range((len(plain) + 15) // 16))
cipher_text = bytes(a ^ b for a, b in zip(plain, stream))
mac = hmac_mod.new(mac_key, cipher_text, hashlib.sha1).digest()[:10]
locked += egg_file(2, "report.txt", TREE["report.txt"], cipher=b"\x02" + salt + verifier + mac)
locked += struct.pack("<IBBIII", 0x02B50C13, 1, 0, len(TREE["report.txt"]), len(cipher_text), zlib.crc32(TREE["report.txt"]) & 0xFFFFFFFF) + END + cipher_text
keep("locked.egg", egg(locked))

a, b_ = b"alpha\n" * 3, b"beta, in the same stream\n"
solid_body = egg_file(1, "a.txt", a) + egg_file(2, "b.txt", b_) + egg_block(1, a + b_, deflate_raw(a + b_))
keep("solid.egg", egg(solid_body, solid=True))
keep("azo.egg", egg(egg_file(1, "packed.txt", b"x" * 64) + egg_block(3, b"x" * 64, b"1\x00" + b"\x00" * 30)))

shutil.rmtree(d)
for name in written:
    print(f"{name}: {(out / name).stat().st_size} bytes")
