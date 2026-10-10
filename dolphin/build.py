#!/usr/bin/env python3
"""Builds a Flipper Zero desktop animation pack starring zkSNARKs instead of the
dolphin. Output: dist/dolphin/ (copy to the SD card as /ext/dolphin/).

  python3 build.py            # downloads the portraits from zilkroad.com
  python3 build.py --preview  # also writes preview GIFs to dist/preview/

The firmware reads /ext/dolphin/manifest.txt and plays these instead of its own
animations. Frames are 128x64, 1 bit; `.bm` = 0x00 + XBM bytes (LSB = leftmost
pixel, 1 = black), as scripts/flipper/assets/icon.py in the firmware writes them.
"""
import os
import sys
import urllib.request

from PIL import Image

from snark1bit import draw as draw_portrait
from snark1bit import portrait

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
CACHE = os.path.join(HERE, ".cache")
W, H = 128, 64

# 5x7 pixel font (uppercase, digits, a few signs). Each glyph: 7 rows of 5 bits.
FONT = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01110", "10001", "10000", "10111", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    "J": ["00111", "00010", "00010", "00010", "00010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "10001", "11001", "10101", "10011", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "Z": ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    "3": ["11111", "00010", "00100", "00010", "00001", "10001", "01110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["00110", "01000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00010", "01100"],
    "#": ["01010", "01010", "11111", "01010", "11111", "01010", "01010"],
    ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    ",": ["00000", "00000", "00000", "00000", "01100", "00100", "01000"],
    ":": ["00000", "01100", "01100", "00000", "01100", "01100", "00000"],
    "!": ["00100", "00100", "00100", "00100", "00100", "00000", "00100"],
    "?": ["01110", "10001", "00001", "00010", "00100", "00000", "00100"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    "=": ["00000", "00000", "11111", "00000", "11111", "00000", "00000"],
    "/": ["00001", "00010", "00010", "00100", "01000", "01000", "10000"],
    "'": ["00100", "00100", "01000", "00000", "00000", "00000", "00000"],
    " ": ["00000"] * 7,
    # Lowercase, only what "zkSNARKs" needs.
    "z": ["00000", "00000", "11111", "00010", "00100", "01000", "11111"],
    "k": ["10000", "10000", "10010", "10100", "11000", "10100", "10010"],
    "s": ["00000", "00000", "01111", "10000", "01110", "00001", "11110"],
}


class Frame:
    def __init__(self):
        self.px = [[False] * W for _ in range(H)]

    def copy(self):
        f = Frame()
        f.px = [row[:] for row in self.px]
        return f

    def set(self, x, y, on=True):
        if 0 <= x < W and 0 <= y < H:
            self.px[y][x] = on

    def text(self, x, y, s, scale=1):
        for ch in s:
            glyph = FONT.get(ch) or FONT.get(ch.upper(), FONT["?"])
            for gy, row in enumerate(glyph):
                for gx, bit in enumerate(row):
                    if bit == "1":
                        for dy in range(scale):
                            for dx in range(scale):
                                self.set(x + gx * scale + dx, y + gy * scale + dy)
            x += 6 * scale
        return x

    def box(self, x, y, w, h, on=True):
        for yy in range(y, y + h):
            for xx in range(x, x + w):
                self.set(xx, yy, on)

    def hline(self, x0, x1, y, dash=0):
        for x in range(x0, x1 + 1):
            if not dash or ((x - x0) // dash) % 2 == 0:
                self.set(x, y)

    def shield(self, cx, cy, s=1):
        """The ZScan mark: shield outline, Z, dashed scan line (~16 px tall at s=1)."""
        pts = [(-6, -7), (0, -9), (6, -7), (6, 1), (0, 8), (-6, 1), (-6, -7)]
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            n = max(abs(x1 - x0), abs(y1 - y0)) * s
            for i in range(n + 1):
                self.set(cx + round((x0 + (x1 - x0) * i / n) * s), cy + round((y0 + (y1 - y0) * i / n) * s))
        for i in range(-3 * s, 3 * s + 1):
            self.set(cx + i, cy - 4 * s)
            self.set(cx + i, cy + 3 * s)
            self.set(cx - i, cy - s // 2 + round(i * 7 / 6))

    def bm(self):
        out = bytearray([0x00])
        for row in self.px:
            for bx in range(0, W, 8):
                byte = 0
                for bit in range(8):
                    if row[bx + bit]:
                        byte |= 1 << bit
                out.append(byte)
        return bytes(out)

    def image(self, scale=4):
        im = Image.new("RGB", (W, H), (255, 140, 26))
        for y in range(H):
            for x in range(W):
                if self.px[y][x]:
                    im.putpixel((x, y), (32, 32, 32))
        return im.resize((W * scale, H * scale), Image.NEAREST)


def fetch(snark_id):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, f"{snark_id}.png")
    if not os.path.exists(path):
        req = urllib.request.Request(f"https://zilkroad.com/api/art/{snark_id}", headers={"User-Agent": "zflip"})
        with urllib.request.urlopen(req, timeout=30) as r, open(path, "wb") as f:
            f.write(r.read())
    return portrait(path)


def with_portrait(grid, ox=4, oy=12, trail_shift=0, eyes_closed=False):
    """A frame with the portrait; the glitch trail (left columns) can drift left."""
    f = Frame()
    g = [row[:] for row in grid]
    if eyes_closed:
        # Eyes = small off/ink islands in the face band (rows 9..14): fill with ink
        # if the face is dark, clear if light.
        for y in range(9, 15):
            for x in range(9, 22):
                ink = [g[yy][xx] == 2 for yy in (y - 1, y + 1) for xx in (x - 1, x, x + 1) if 0 <= yy < 26 and 0 <= xx < 26]
                if g[y][x] != 2 and sum(ink) >= 5:
                    g[y][x] = 2
    if trail_shift:
        # The trail: pixels left of the silhouette's first solid column drift left.
        for y in range(26):
            row = g[y]
            solid = next((x for x in range(26) if row[x] == 2 and x + 1 < 26 and row[x + 1] == 2), 26)
            trail = [(x, v) for x, v in enumerate(row[:solid]) if v]
            for x, _ in trail:
                row[x] = 0
            for x, v in trail:
                nx = x - trail_shift * (1 + (y * 7 + x) % 3)
                if 0 <= nx < solid and (y + x + trail_shift) % 4:
                    row[nx] = v
    draw_portrait(f.px, g, ox, oy)
    return f


def anim_shielding(grid, number):
    frames = []
    for i in range(6):
        f = with_portrait(grid, trail_shift=i % 3, eyes_closed=(i == 5))
        f.text(62, 16, "zkSNARKs")
        f.text(62, 26, f"#{number}")
        dots = "." * (i % 4)
        f.text(62, 48, "SHIELDED" if i >= 3 else "SHIELDING" [: 6 + i] + dots)
        f.shield(118, 34)
        frames.append(f)
    return frames


def anim_proof(grid, number):
    frames = []
    for i in range(8):
        f = with_portrait(grid)
        y = 13 + i * 7
        if i < 7:
            f.hline(2, 58, min(y, 63), dash=3)
        f.text(62, 15, f"#{number}")
        f.text(62, 26, "PROOF")
        if i < 6:
            hexes = ["9F3A", "C0DE", "7B1E", "A5F0", "31D9", "E8C2"]
            f.text(62, 37, hexes[i])
            f.box(62, 50, 4 + i * 10, 5)
        else:
            f.text(62, 37, "OK")
            f.shield(110, 52)
        frames.append(f)
    return frames


def anim_secret(grid, number):
    frames = []
    lines = [("I KNOW A", "SECRET"), ("I KNOW A", "SECRET"), ("YOU WILL", "NEVER"), ("KNOW IT", "")]
    for i in range(8):
        f = with_portrait(grid, eyes_closed=(i in (2, 6)))
        a, b = lines[(i // 2) % 4]
        f.text(62, 20, a)
        f.text(62, 30, b)
        f.text(62, 54, f"#{number}")
        frames.append(f)
    return frames


def anim_block(grid, number):
    frames = []
    base = 3_431_000
    for i in range(6):
        f = with_portrait(grid, eyes_closed=(i == 4))
        f.text(62, 15, "BLOCK")
        f.text(62, 24, f"{base + i * 3:,}".replace(",", ""))
        f.text(62, 37, "PRIVATE")
        f.text(62, 46, "BY")
        f.text(62, 55, "DEFAULT")
        f.shield(118, 47)
        frames.append(f)
    return frames


def anim_snarks(grid, number):
    frames = []
    for i in range(6):
        f = with_portrait(grid)
        # "zkSNARKs" at 2x is 96 px wide: one size down, centred in the right column.
        f.text(62, 24, "zkSNARKs")
        f.text(62, 40, f"#{number}")
        if i % 3 != 2:
            f.shield(118, 52)
        frames.append(f)
    return frames


# (folder name, zkSNARK id, builder, frame rate)
ANIMATIONS = [
    ("ZK_Shielding_128x64", 1, anim_shielding, 3),
    ("ZK_Proof_128x64", 777, anim_proof, 3),
    ("ZK_Secret_128x64", 3141, anim_secret, 2),
    ("ZK_Block_128x64", 94, anim_block, 2),
    ("ZK_Snarks_128x64", 7, anim_snarks, 2),
]


def write_animation(name, frames, rate):
    folder = os.path.join(DIST, "dolphin", name)
    os.makedirs(folder, exist_ok=True)
    for i, f in enumerate(frames):
        with open(os.path.join(folder, f"frame_{i}.bm"), "wb") as out:
            out.write(f.bm())
    order = " ".join(str(i) for i in range(len(frames)))
    with open(os.path.join(folder, "meta.txt"), "w") as out:
        out.write(
            "Filetype: Flipper Animation\nVersion: 1\n\n"
            f"Width: {W}\nHeight: {H}\n"
            f"Passive frames: {len(frames)}\nActive frames: 0\n"
            f"Frames order: {order}\n"
            "Active cycles: 0\n"
            f"Frame rate: {rate}\n"
            "Duration: 3600\nActive cooldown: 0\n\n"
            "Bubble slots: 0\n"
        )


def main():
    preview = "--preview" in sys.argv
    manifest = ["Filetype: Flipper Animation Manifest", "Version: 1", ""]
    for name, snark_id, build, rate in ANIMATIONS:
        frames = build(fetch(snark_id), f"{snark_id:04d}")
        write_animation(name, frames, rate)
        manifest += [
            f"Name: {name}",
            "Min butthurt: 0",
            "Max butthurt: 14",
            "Min level: 1",
            "Max level: 30",
            "Weight: 3",
            "",
        ]
        if preview:
            os.makedirs(os.path.join(DIST, "preview"), exist_ok=True)
            images = [f.image() for f in frames]
            images[0].save(
                os.path.join(DIST, "preview", f"{name}.gif"),
                save_all=True, append_images=images[1:], duration=int(1000 / rate), loop=0,
            )
            sheet = Image.new("RGB", (images[0].width, images[0].height * len(images) + 4 * len(images)), (0, 0, 0))
            for k, im in enumerate(images):
                sheet.paste(im, (0, k * (im.height + 4)))
            sheet.save(os.path.join(DIST, "preview", f"{name}.png"))
    with open(os.path.join(DIST, "dolphin", "manifest.txt"), "w") as out:
        out.write("\n".join(manifest))
    print("wrote", os.path.join(DIST, "dolphin"))


if __name__ == "__main__":
    main()
