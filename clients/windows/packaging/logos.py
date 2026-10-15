# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# The package's logos (commit 39f), drawn here rather than committed as
# images: a teal tile with a white "G" ring — no image library, only zlib,
# so it runs on any Python the runner has.
#
#   python logos.py <assets dir>     → Square44x44Logo.png, Square150x150Logo.png, StoreLogo.png

import math
import struct
import sys
import zlib
from pathlib import Path

TEAL = (15, 118, 110, 255)
WHITE = (255, 255, 255, 255)
CLEAR = (0, 0, 0, 0)


def pixel(x: float, y: float) -> tuple:
    """The colour at (x, y) in a unit square, centred on 0.5."""
    dx, dy = x - 0.5, y - 0.5
    # The tile: a square with rounded corners (radius 0.18).
    r, edge = 0.18, 0.5
    qx, qy = max(abs(dx) - (edge - r), 0), max(abs(dy) - (edge - r), 0)
    if math.hypot(qx, qy) > r:
        return CLEAR
    # The "G": a ring open on the right above the middle, and a bar into it.
    d = math.hypot(dx, dy)
    angle = math.degrees(math.atan2(-dy, dx))  # 0 = right, 90 = up
    ring = 0.22 <= d <= 0.33 and not (-5 < angle < 50)
    bar = -0.04 <= dy <= 0.04 and 0.03 <= dx <= 0.33
    return WHITE if ring or bar else TEAL


def png(size: int) -> bytes:
    rows = []
    for py in range(size):
        row = bytearray([0])  # no filter
        for px in range(size):
            # 4×4 samples per pixel: smooth edges.
            acc = [0, 0, 0, 0]
            for sy in range(4):
                for sx in range(4):
                    c = pixel((px + (sx + 0.5) / 4) / size, (py + (sy + 0.5) / 4) / size)
                    for i in range(4):
                        acc[i] += c[i]
            row.extend(v // 16 for v in acc)
        rows.append(bytes(row))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for name, size in [("Square44x44Logo.png", 44), ("Square150x150Logo.png", 150), ("StoreLogo.png", 50)]:
        (out / name).write_bytes(png(size))


if __name__ == "__main__":
    main()
