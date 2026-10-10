#!/usr/bin/env python3
"""Drive a Flipper Zero over its RPC protocol (what qFlipper uses), for testing.

  flipper_rpc.py shot out.png                 screenshot (scaled 4x)
  flipper_rpc.py keys "ok down long:ok" [out.png]
        press keys (short by default, "long:" prefix for a long press), wait,
        then optionally screenshot. Keys: up down left right ok back.
  flipper_rpc.py wait SECONDS out.png         wait, then screenshot

  Set ZFLIP_EXPECT="ZFlip setup" (or "ZFlip") to refuse sending keys unless that
  app is the one running: stray presses on the desktop open other apps.

Only the bits of the protobuf schema needed here are hand-encoded.
"""
import struct
import sys
import time
import zlib

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import flipper_cli  # noqa: E402

KEYS = {"up": 0, "down": 1, "right": 2, "left": 3, "ok": 4, "back": 5}
PRESS, RELEASE, SHORT, LONG = 0, 1, 2, 3


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def field(num, wire, payload):
    key = varint((num << 3) | wire)
    if wire == 0:
        return key + varint(payload)
    return key + varint(len(payload)) + payload


class Rpc:
    def __init__(self):
        self.s = flipper_cli.connect()
        self.s.write(b"start_rpc_session\r")
        time.sleep(0.3)
        self.s.read(4096)
        self.buf = b""
        self.cid = 0

    def send(self, content_field, content=b""):
        self.cid += 1
        msg = field(1, 0, self.cid) + field(content_field, 2, content)
        self.s.write(varint(len(msg)) + msg)

    def read_messages(self, seconds):
        end = time.time() + seconds
        out = []
        while time.time() < end:
            self.buf += self.s.read(8192)
            while True:
                n, shift, i = 0, 0, 0
                while i < len(self.buf):
                    b = self.buf[i]
                    n |= (b & 0x7F) << shift
                    shift += 7
                    i += 1
                    if not b & 0x80:
                        break
                else:
                    break
                if len(self.buf) < i + n:
                    break
                out.append(self.buf[i : i + n])
                self.buf = self.buf[i + n :]
        return out

    def key(self, name, kind):
        for t in ([PRESS, LONG, RELEASE] if kind == "long" else [PRESS, SHORT, RELEASE]):
            body = field(1, 0, KEYS[name]) + field(2, 0, t) if (KEYS[name] or t) else b""
            # proto3 omits zero values; an empty body means key=UP, type=PRESS.
            body = (field(1, 0, KEYS[name]) if KEYS[name] else b"") + (field(2, 0, t) if t else b"")
            self.send(23, body)
            time.sleep(0.6 if (kind == "long" and t == PRESS) else 0.05)
        self.read_messages(0.1)

    def frame(self):
        self.send(20)
        data = None
        for msg in self.read_messages(1.5):
            i = 0
            while i < len(msg):
                key, i = decode_varint(msg, i)
                num, wire = key >> 3, key & 7
                if wire == 0:
                    _, i = decode_varint(msg, i)
                elif wire == 2:
                    ln, i = decode_varint(msg, i)
                    if num == 22:
                        sub = msg[i : i + ln]
                        j = 0
                        while j < len(sub):
                            k, j = decode_varint(sub, j)
                            if k >> 3 == 1 and k & 7 == 2:
                                l2, j = decode_varint(sub, j)
                                data = sub[j : j + l2]
                                j += l2
                            elif k & 7 == 0:
                                _, j = decode_varint(sub, j)
                    i += ln
                else:
                    break
        self.send(21)
        self.read_messages(0.3)
        return data

    def close(self):
        self.send(19)
        time.sleep(0.2)


def decode_varint(b, i):
    n, shift = 0, 0
    while True:
        x = b[i]
        n |= (x & 0x7F) << shift
        shift += 7
        i += 1
        if not x & 0x80:
            return n, i


def png(data, path, scale=4):
    w, h = 128, 64
    rows = []
    for y in range(h * scale):
        yy = y // scale
        row = bytearray([0])
        for x in range(w * scale):
            xx = x // scale
            on = (data[(yy // 8) * 128 + xx] >> (yy % 8)) & 1
            row += b"\x20\x20\x20" if on else b"\xff\x8c\x1a"
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w * scale, h * scale, 8, 2, 0, 0, 0))
    out += chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    open(path, "wb").write(out)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    import os
    expect = os.environ.get("ZFLIP_EXPECT")
    if expect and sys.argv[1] == "keys":
        s = flipper_cli.connect()
        running = flipper_cli.cmd(s, "loader info")
        s.close()
        if f'"{expect}" is running' not in running:
            sys.exit(f"refusing to press keys: expected {expect!r}, Flipper says: {running!r}")
    rpc = Rpc()
    try:
        op = sys.argv[1]
        shot = None
        if op == "shot":
            shot = sys.argv[2]
        elif op == "keys":
            for k in sys.argv[2].split():
                kind, name = k.split(":") if ":" in k else ("short", k)
                rpc.key(name, kind)
                time.sleep(0.15)
            shot = sys.argv[3] if len(sys.argv) > 3 else None
            if shot:
                time.sleep(0.5)
        elif op == "wait":
            time.sleep(float(sys.argv[2]))
            shot = sys.argv[3]
        if shot:
            data = rpc.frame()
            if not data:
                sys.exit("no frame received")
            png(data, shot)
            print(shot)
    finally:
        rpc.close()


if __name__ == "__main__":
    main()
