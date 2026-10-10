//! BLAKE2b (RFC 7693) with the part of the `blake2b_simd` API that the Zcash crates
//! use: `Params`, `State`, `Hash`. One small portable compression function, no
//! SIMD and no unrolling: the Flipper app has ~100 KiB of RAM for all its code.

#![no_std]

pub const OUTBYTES: usize = 64;
pub const KEYBYTES: usize = 64;
pub const SALTBYTES: usize = 16;
pub const PERSONALBYTES: usize = 16;
pub const BLOCKBYTES: usize = 128;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// (a, b, c, d) indices of the eight G mixes of a round.
const MIX: [[u8; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

#[inline(never)]
fn compress(h: &mut [u64; 8], block: &[u8; BLOCKBYTES], count: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for r in 0..12 {
        let s = &SIGMA[r % 10];
        for (i, &[a, b, c, d]) in MIX.iter().enumerate() {
            let (a, b, c, d) = (a as usize, b as usize, c as usize, d as usize);
            let (x, y) = (m[s[2 * i] as usize], m[s[2 * i + 1] as usize]);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[derive(Clone)]
pub struct Params {
    hash_length: u8,
    key_length: u8,
    key: [u8; KEYBYTES],
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

impl Params {
    pub fn new() -> Self {
        Params { hash_length: OUTBYTES as u8, key_length: 0, key: [0; KEYBYTES], salt: [0; SALTBYTES], personal: [0; PERSONALBYTES] }
    }

    /// 1 to 64 bytes.
    pub fn hash_length(&mut self, length: usize) -> &mut Self {
        assert!(1 <= length && length <= OUTBYTES, "bad hash length");
        self.hash_length = length as u8;
        self
    }

    /// At most 64 bytes; empty means unkeyed.
    pub fn key(&mut self, key: &[u8]) -> &mut Self {
        assert!(key.len() <= KEYBYTES, "bad key length");
        self.key = [0; KEYBYTES];
        self.key[..key.len()].copy_from_slice(key);
        self.key_length = key.len() as u8;
        self
    }

    /// At most 16 bytes, zero-padded.
    pub fn salt(&mut self, salt: &[u8]) -> &mut Self {
        assert!(salt.len() <= SALTBYTES, "bad salt length");
        self.salt = [0; SALTBYTES];
        self.salt[..salt.len()].copy_from_slice(salt);
        self
    }

    /// At most 16 bytes, zero-padded.
    pub fn personal(&mut self, personal: &[u8]) -> &mut Self {
        assert!(personal.len() <= PERSONALBYTES, "bad personalization length");
        self.personal = [0; PERSONALBYTES];
        self.personal[..personal.len()].copy_from_slice(personal);
        self
    }

    pub fn to_state(&self) -> State {
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((self.key_length as u64) << 8) ^ self.hash_length as u64;
        for i in 0..2 {
            let mut s = [0u8; 8];
            s.copy_from_slice(&self.salt[i * 8..i * 8 + 8]);
            h[4 + i] ^= u64::from_le_bytes(s);
            s.copy_from_slice(&self.personal[i * 8..i * 8 + 8]);
            h[6 + i] ^= u64::from_le_bytes(s);
        }
        let mut state = State { h, buf: [0; BLOCKBYTES], buflen: 0, count: 0, hash_length: self.hash_length };
        if self.key_length > 0 {
            // The key, zero-padded, is the first block.
            state.buf[..KEYBYTES].copy_from_slice(&self.key);
            state.buflen = BLOCKBYTES;
        }
        state
    }

    pub fn hash(&self, input: &[u8]) -> Hash {
        self.to_state().update(input).finalize()
    }
}

#[derive(Clone)]
pub struct State {
    h: [u64; 8],
    buf: [u8; BLOCKBYTES],
    buflen: usize,
    count: u128,
    hash_length: u8,
}

impl State {
    pub fn new() -> Self {
        Params::new().to_state()
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        while !input.is_empty() {
            // The last block is compressed in finalize, so only compress a full
            // buffer once more input follows.
            if self.buflen == BLOCKBYTES {
                self.count += BLOCKBYTES as u128;
                compress(&mut self.h, &self.buf, self.count, false);
                self.buflen = 0;
            }
            let take = (BLOCKBYTES - self.buflen).min(input.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&input[..take]);
            self.buflen += take;
            input = &input[take..];
        }
        self
    }

    pub fn finalize(&self) -> Hash {
        let mut h = self.h;
        let mut block = self.buf;
        block[self.buflen..].fill(0);
        compress(&mut h, &block, self.count + self.buflen as u128, true);
        let mut bytes = [0u8; OUTBYTES];
        for (i, w) in h.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        Hash { bytes, len: self.hash_length }
    }

    pub fn count(&self) -> u128 {
        self.count + self.buflen as u128
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct Hash {
    bytes: [u8; OUTBYTES],
    len: u8,
}

impl Hash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// All 64 bytes (only meaningful for 64-byte hashes, as in blake2b_simd).
    pub fn as_array(&self) -> &[u8; OUTBYTES] {
        &self.bytes
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Hash) -> bool {
        // Constant time, like blake2b_simd.
        self.len == other.len && self.as_bytes().iter().zip(other.as_bytes()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

impl Eq for Hash {}

impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Hash")
    }
}

pub fn blake2b(input: &[u8]) -> Hash {
    Params::new().hash(input)
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("State")
    }
}

impl core::fmt::Debug for Params {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Params")
    }
}
