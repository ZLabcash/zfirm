#!/usr/bin/env python3
"""Downloads all 10,000 zkSNARK portraits (26x26 PNGs, ~5-70 KB each) into .cache/."""
import concurrent.futures
import os
import urllib.request

CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")


def fetch(i):
    path = os.path.join(CACHE, f"{i}.png")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return True
    for _ in range(3):
        try:
            req = urllib.request.Request(f"https://zilkroad.com/api/art/{i}", headers={"User-Agent": "zflip"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
            with open(path, "wb") as f:
                f.write(data)
            return True
        except Exception:
            pass
    return False


if __name__ == "__main__":
    os.makedirs(CACHE, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        ok = sum(pool.map(fetch, range(1, 10001)))
    print("downloaded", ok, "of 10000")
