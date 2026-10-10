#!/usr/bin/env python3
"""Tiny Flipper Zero CLI client over USB serial (pyserial).

  flipper_cli.py cmd "info device"          run a CLI command and print its output
  flipper_cli.py put LOCAL /ext/path        upload a file (storage write_chunk)
  flipper_cli.py run /ext/apps/Tools/x.fap  launch an app (loader open)
"""
import glob
import sys
import time

import serial

PROMPT = b">: "


def connect():
    ports = sorted(glob.glob("/dev/cu.usbmodemflip*"))
    if not ports:
        sys.exit("No Flipper found on USB (is qFlipper closed?)")
    s = serial.Serial(ports[0], 230400, timeout=0.2)
    s.write(b"\x03\r")  # Ctrl-C ends a log stream left open by a previous session
    read_until_prompt(s, 3)
    return s


def read_until_prompt(s, timeout=10):
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        buf += s.read(4096)
        if buf.endswith(PROMPT) or buf.rstrip().endswith(b">:"):
            break
    return buf


def cmd(s, line, timeout=10):
    s.write(line.encode() + b"\r")
    out = read_until_prompt(s, timeout).decode(errors="replace")
    lines = out.replace("\r", "").split("\n")
    if lines and lines[0].strip() == line.strip():
        lines = lines[1:]
    return "\n".join(l for l in lines if not l.startswith(">:")).strip()


def put(s, local, remote):
    data = open(local, "rb").read()
    parts = remote.split("/")[1:-1]
    for i in range(2, len(parts) + 1):
        cmd(s, "storage mkdir /" + "/".join(parts[:i]))
    cmd(s, f"storage remove {remote}")
    chunk = 512
    for off in range(0, len(data), chunk):
        part = data[off : off + chunk]
        s.write(f"storage write_chunk {remote} {len(part)}\r".encode())
        ready = b""
        end = time.time() + 5
        while b"Ready" not in ready and time.time() < end:
            ready += s.read(64)
        if b"Ready" not in ready:
            sys.exit(f"Flipper did not accept chunk at {off}: {ready!r}")
        s.write(part)
        read_until_prompt(s, 10)
        pass
    print()
    print(cmd(s, f"storage stat {remote}"))


def put_dir(s, local, remote):
    """Uploads a folder tree in one session (fast: no stat/remove per file)."""
    import os
    files = []
    for root, _, names in os.walk(local):
        for n in sorted(names):
            files.append(os.path.join(root, n))
    made = set()
    for k, path in enumerate(files):
        rel = os.path.relpath(path, local)
        target = remote.rstrip("/") + "/" + rel
        folder = target.rsplit("/", 1)[0]
        parts = folder.split("/")[1:]
        for i in range(2, len(parts) + 1):
            d = "/" + "/".join(parts[:i])
            if d not in made:
                cmd(s, f"storage mkdir {d}")
                made.add(d)
        data = open(path, "rb").read()
        cmd(s, f"storage remove {target}")
        for off in range(0, len(data), 512):
            part = data[off : off + 512]
            s.write(f"storage write_chunk {target} {len(part)}\r".encode())
            ready = b""
            end = time.time() + 5
            while b"Ready" not in ready and time.time() < end:
                ready += s.read(64)
            if b"Ready" not in ready:
                sys.exit(f"Flipper did not accept {target}: {ready!r}")
            s.write(part)
            read_until_prompt(s, 10)
        if k % 50 == 0:
            print(f"{k}/{len(files)} {rel}", flush=True)
    print(f"{len(files)}/{len(files)} done")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    s = connect()
    op = sys.argv[1]
    if op == "cmd":
        print(cmd(s, sys.argv[2], timeout=20))
    elif op == "put":
        put(s, sys.argv[2], sys.argv[3])
    elif op == "putdir":
        put_dir(s, sys.argv[2], sys.argv[3])
    elif op == "run":
        print(cmd(s, f'loader open "{sys.argv[2]}"', timeout=5))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
