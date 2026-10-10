#!/usr/bin/env python3
"""The whole zkSNARKs collection on the Flipper's desktop: 100 animations of 100
portraits each (#1-#100, #101-#200, ...), heatshrink-compressed. Written to
dist/collection/, plus manifest entries merged into dist/dolphin/manifest.txt.

  python3 build_collection.py [first_series last_series]   (default 1 100)
"""
import json
import os
import sys

import heatshrink
from build import Frame, W, H
from snark1bit import draw as draw_portrait

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
RECORD = 169
PER_SERIES = 100


def levels(blob, i):
    rec = blob[(i - 1) * RECORD : i * RECORD]
    flat = [(rec[k // 4] >> (2 * (k % 4))) & 3 for k in range(26 * 26)]
    return [flat[r * 26 : (r + 1) * 26] for r in range(26)]


def ranks():
    path = os.path.join(HERE, ".cache", "tokens.json")
    if not os.path.exists(path):
        import urllib.request
        req = urllib.request.Request("https://zilkroad.com/api/market/tokens", headers={"User-Agent": "zflip"})
        with urllib.request.urlopen(req, timeout=60) as r, open(path, "wb") as f:
            f.write(r.read())
    tokens = json.load(open(path))["tokens"]
    return {t["id"]: t.get("rank") for t in tokens}


def frame_for(grid, number, rank):
    f = Frame()
    draw_portrait(f.px, grid, 4, 12)
    f.text(62, 16, "zkSNARKs")
    f.text(62, 30, f"#{number:04d}" if number < 10000 else "#10000")
    if rank:
        f.text(62, 44, f"RANK {rank}")
    return f


def main():
    first, last = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) > 2 else (1, 100)
    blob = open(os.path.join(DIST, "snarks.bin"), "rb").read()
    rank = ranks()
    names = []
    for series in range(first, last + 1):
        name = f"ZK_Series_{series:03d}_128x64"
        folder = os.path.join(DIST, "collection", name)
        os.makedirs(folder, exist_ok=True)
        start = (series - 1) * PER_SERIES + 1
        ids = range(start, start + PER_SERIES)
        for k, i in enumerate(ids):
            raw = frame_for(levels(blob, i), i, rank.get(i)).bm()[1:]
            with open(os.path.join(folder, f"frame_{k}.bm"), "wb") as out:
                out.write(heatshrink.flipper_bm(raw))
        with open(os.path.join(folder, "meta.txt"), "w") as out:
            out.write(
                "Filetype: Flipper Animation\nVersion: 1\n\n"
                f"Width: {W}\nHeight: {H}\n"
                f"Passive frames: {PER_SERIES}\nActive frames: 0\n"
                f"Frames order: {' '.join(str(k) for k in range(PER_SERIES))}\n"
                "Active cycles: 0\nFrame rate: 2\nDuration: 3600\nActive cooldown: 0\n\n"
                "Bubble slots: 0\n"
            )
        names.append(name)
        print(name, end="\r", flush=True)
    print()
    # Manifest: the five themed animations plus every series built so far.
    built = sorted(n for n in os.listdir(os.path.join(DIST, "collection")) if n.startswith("ZK_Series_"))
    themed = [line[6:].strip() for line in open(os.path.join(DIST, "dolphin", "manifest.txt")) if line.startswith("Name: ZK_") and "Series" not in line]
    lines = ["Filetype: Flipper Animation Manifest", "Version: 1", ""]
    for n in themed + built:
        lines += [f"Name: {n}", "Min butthurt: 0", "Max butthurt: 14", "Min level: 1", "Max level: 30", "Weight: 3", ""]
    with open(os.path.join(DIST, "collection", "manifest.txt"), "w") as out:
        out.write("\n".join(lines))
    print("series:", len(built), "manifest entries:", len(themed) + len(built))


if __name__ == "__main__":
    main()
