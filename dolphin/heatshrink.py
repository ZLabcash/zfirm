"""Minimal heatshrink (LZSS) encoder/decoder, window 2^8, lookahead 2^4, as the
Flipper firmware decodes compressed images (scripts/flipper/assets/icon.py)."""

W, L = 8, 4


class _Bits:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, value, bits):
        for i in reversed(range(bits)):
            self.acc = (self.acc << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                self.acc, self.n = 0, 0

    def done(self):
        if self.n:
            self.out.append(self.acc << (8 - self.n))
        return bytes(self.out)


def encode(data: bytes) -> bytes:
    bits = _Bits()
    i, max_len, window = 0, 1 << L, 1 << W
    while i < len(data):
        best_len, best_off = 0, 0
        for off in range(1, min(i, window) + 1):
            n = 0
            while n < max_len and i + n < len(data) and data[i + n] == data[i - off + n]:
                n += 1
            if n > best_len:
                best_len, best_off = n, off
                if n == max_len:
                    break
        # A back-reference costs 1 + W + L = 13 bits; a literal 9 bits per byte.
        if best_len >= 2:
            bits.put(0, 1)
            bits.put(best_off - 1, W)
            bits.put(best_len - 1, L)
            i += best_len
        else:
            bits.put(1, 1)
            bits.put(data[i], 8)
            i += 1
    return bits.done()


def decode(data: bytes, size: int) -> bytes:
    out = bytearray()
    pos = 0  # bit position

    def get(n):
        nonlocal pos
        v = 0
        for _ in range(n):
            if pos >= len(data) * 8:
                raise EOFError
            v = (v << 1) | ((data[pos // 8] >> (7 - pos % 8)) & 1)
            pos += 1
        return v

    try:
        while len(out) < size:
            if get(1):
                out.append(get(8))
            else:
                off, n = get(W) + 1, get(L) + 1
                for _ in range(n):
                    out.append(out[-off])
    except EOFError:
        pass
    return bytes(out[:size])


def flipper_bm(raw_xbm: bytes) -> bytes:
    """The .bm bytes the firmware loads: compressed if that is smaller."""
    enc = encode(raw_xbm)
    assert decode(enc, len(raw_xbm)) == raw_xbm
    packed = bytes([len(enc) & 0xFF, len(enc) >> 8]) + enc
    if len(packed) + 2 < len(raw_xbm) + 1:
        return b"\x01\x00" + packed
    return b"\x00" + raw_xbm
