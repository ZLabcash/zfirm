#!/usr/bin/env python3
"""Packs all 10,000 zkSNARKs into dist/snarks.bin for the zkSNARKs app (apps_data/zksnarks/).

Record i-1 (169 bytes) = zkSNARK #i as 26x26 levels, 2 bits each, row-major,
4 per byte from the low bits: 0 = off, 1 = dithered, 2 = ink (see snark1bit.py).
"""
import concurrent.futures
import os

from snark1bit import portrait

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, ".cache")
RECORD = 169


def pack(i):
    grid = portrait(os.path.join(CACHE, f"{i}.png"))
    flat = [v for row in grid for v in row]
    out = bytearray(RECORD)
    for k, v in enumerate(flat):
        out[k // 4] |= v << (2 * (k % 4))
    return bytes(out)


if __name__ == "__main__":
    os.makedirs(os.path.join(HERE, "dist"), exist_ok=True)
    with concurrent.futures.ProcessPoolExecutor() as pool:
        records = list(pool.map(pack, range(1, 10001), chunksize=200))
    with open(os.path.join(HERE, "dist", "snarks.bin"), "wb") as f:
        for r in records:
            f.write(r)
    print("wrote", len(records), "records,", len(records) * RECORD, "bytes")
