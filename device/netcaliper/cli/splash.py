# SPDX-License-Identifier: GPL-3.0-only
"""Boot splash image: the wordmark in a 5x9 pixel font with phosphor scanlines, written as a PNG with
zlib only (no Pillow, no binary assets in the repo). Rendered by the installer. Plymouth honours the
DRM panel-orientation property, so no rotation is needed on the uConsole; `rotate` exists for panels
that lack the property (Plymouth's own Image.Rotate keeps the image size and would clip)."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

# 5x9 cells: x-height rows 2-6, baseline after row 6, descenders in rows 7-8.
_ = "     "
GLYPHS = {
    "a": [_, _, " ### ", "    #", " ####", "#   #", " ####", _, _],
    "c": [_, _, " ### ", "#    ", "#    ", "#   #", " ### ", _, _],
    "e": [_, _, " ### ", "#   #", "#####", "#    ", " ### ", _, _],
    "g": [_, _, " ####", "#   #", "#   #", "#   #", " ####", "    #", " ### "],
    "i": ["  #  ", _, " ##  ", "  #  ", "  #  ", "  #  ", " ### ", _, _],
    "l": [" ##  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### ", _, _],
    "n": [_, _, "#### ", "#   #", "#   #", "#   #", "#   #", _, _],
    "p": [_, _, "#### ", "#   #", "#   #", "#   #", "#### ", "#    ", "#    "],
    "r": [_, _, "# ## ", "##  #", "#    ", "#    ", "#    ", _, _],
    "s": [_, _, " ####", "#    ", " ### ", "    #", "#### ", _, _],
    "t": ["  #  ", "  #  ", "#####", "  #  ", "  #  ", "  #  ", "   ##", _, _],
    ".": [_, _, _, _, _, " ##  ", " ##  ", _, _],
    " ": [_] * 9,
}
ROWS = 9
BG = (0x04, 0x09, 0x04, 0x00)  # transparent: Plymouth paints the same background colour
FG = (0x39, 0xFF, 0x6A, 0xFF)
DIM = (0x1C, 0x8A, 0x3A, 0xFF)


def _text(s: str) -> list[list[bool]]:
    rows: list[list[bool]] = [[] for _ in range(ROWS)]
    for ch in s:
        g = GLYPHS[ch]
        for y in range(ROWS):
            rows[y] += [c == "#" for c in g[y]] + [False]
    return [r[:-1] for r in rows]


def render(rotate: int = 0, scale: int = 8) -> tuple[int, int, list[bytes]]:
    """(width, height, RGBA rows). Wordmark at `scale`, 'starting' beneath at scale/3."""
    big, small = _text("netcaliper"), _text("starting...")
    s2 = max(1, scale // 3)
    pad = scale * 2
    w = max(len(big[0]) * scale, len(small[0]) * s2) + 2 * pad
    gap = scale
    h = ROWS * scale + gap + ROWS * s2 + 2 * pad
    px = [[BG] * w for _ in range(h)]

    def blit(bm: list[list[bool]], sc: int, top: int, color: tuple[int, int, int, int]) -> None:
        left = (w - len(bm[0]) * sc) // 2
        for y, row in enumerate(bm):
            for x, on in enumerate(row):
                if on:
                    for dy in range(sc):
                        # scanline: the last row of each scaled pixel is dimmer
                        c = color if dy < sc - 1 or sc < 3 else (*(v // 2 for v in color[:3]), 0xFF)
                        for dx in range(sc):
                            px[top + y * sc + dy][left + x * sc + dx] = c  # type: ignore[assignment]

    blit(big, scale, pad, FG)
    blit(small, s2, pad + ROWS * scale + gap, DIM)
    rot = rotate % 360
    for _ in range(rot // 90):  # rotate clockwise by 90 each step
        px = [list(r) for r in zip(*px[::-1], strict=True)]
    return len(px[0]), len(px), [bytes(v for p in row for v in p) for row in px]


def png(width: int, height: int, rows: list[bytes]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack("!I", len(data)) + tag + data + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    raw = b"".join(b"\x00" + r for r in rows)
    ihdr = struct.pack("!IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def write(path: Path, rotate: int = 0, scale: int = 8) -> None:
    w, h, rows = render(rotate, scale)
    path.write_bytes(png(w, h, rows))
