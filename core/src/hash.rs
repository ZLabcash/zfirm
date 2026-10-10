//! Compact SHA-256 / SHA-512, HMAC-SHA512 and PBKDF2 for BIP 39.
//!
//! Loop-based on purpose: the usual unrolled implementations cost ~35 KiB of code,
//! a third of the RAM a Flipper Zero app can use. Speed is irrelevant here (one
//! checksum and one 2048-round PBKDF2 per unlock). Tested against `sha2`/`pbkdf2`.

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-256 of a short message (the BIP 39 checksum hashes 32 bytes).
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (msg.len() as u64) * 8;
    let blocks = (msg.len() + 9).div_ceil(64);
    for n in 0..blocks {
        let mut block = [0u8; 64];
        for (i, b) in block.iter_mut().enumerate() {
            let pos = n * 64 + i;
            *b = if pos < msg.len() {
                msg[pos]
            } else if pos == msg.len() {
                0x80
            } else {
                0
            };
        }
        if n == blocks - 1 {
            block[56..].copy_from_slice(&bit_len.to_be_bytes());
        }
        let mut w = [0u32; 64];
        for t in 0..64 {
            w[t] = if t < 16 {
                u32::from_be_bytes(crate::arr(&block[t * 4..]))
            } else {
                let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
                let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
                w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1)
            };
        }
        let mut v = h;
        for t in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[t]).wrapping_add(w[t]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v.copy_within(0..7, 1);
            v[4] = v[4].wrapping_add(t1);
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

const IV512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for t in 0..80 {
        w[t] = if t < 16 {
            u64::from_be_bytes(crate::arr(&block[t * 8..]))
        } else {
            let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
            let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
            w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1)
        };
    }
    let mut v = *h;
    for t in 0..80 {
        let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
        let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
        let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[t]).wrapping_add(w[t]);
        let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
        let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        let t2 = s0.wrapping_add(maj);
        v.copy_within(0..7, 1);
        v[4] = v[4].wrapping_add(t1);
        v[0] = t1.wrapping_add(t2);
    }
    for i in 0..8 {
        h[i] = h[i].wrapping_add(v[i]);
    }
}

/// Streaming SHA-512.
#[derive(Clone)]
pub struct Sha512 {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Sha512 {
            h: IV512,
            buf: [0; 128],
            buf_len: 0,
            total: 0,
        }
    }
}

impl Sha512 {
    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u128;
        while !data.is_empty() {
            let n = (128 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
            if self.buf_len == 128 {
                compress512(&mut self.h, &self.buf);
                self.buf_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total * 8;
        self.update(&[0x80]);
        while self.buf_len != 112 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

/// HMAC-SHA512 keyed state, reusable for many messages (PBKDF2 rounds).
#[derive(Clone)]
pub struct HmacSha512 {
    inner: Sha512,
    outer: Sha512,
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 128];
        if key.len() > 128 {
            let mut h = Sha512::default();
            h.update(key);
            k[..64].copy_from_slice(&h.finalize());
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha512::default();
        let mut outer = Sha512::default();
        let mut pad = [0u8; 128];
        for (p, b) in pad.iter_mut().zip(k.iter()) {
            *p = b ^ 0x36;
        }
        inner.update(&pad);
        for (p, b) in pad.iter_mut().zip(k.iter()) {
            *p = b ^ 0x5c;
        }
        outer.update(&pad);
        HmacSha512 { inner, outer }
    }

    pub fn mac(&self, parts: &[&[u8]]) -> [u8; 64] {
        let mut inner = self.inner.clone();
        for p in parts {
            inner.update(p);
        }
        let mut outer = self.outer.clone();
        outer.update(&inner.finalize());
        outer.finalize()
    }
}

/// PBKDF2-HMAC-SHA512 with a single 64-byte output block, as BIP 39 uses it.
/// `progress` is called after each round so the device can animate.
pub fn pbkdf2_sha512(
    password: &[u8],
    salt: &[&[u8]],
    rounds: u32,
    mut progress: impl FnMut(u32),
) -> [u8; 64] {
    let prf = HmacSha512::new(password);
    let mut first: [&[u8]; 4] = [&[], &[], &[], &[0, 0, 0, 1]];
    for (slot, part) in first.iter_mut().zip(salt.iter()) {
        *slot = part;
    }
    let mut u = prf.mac(&first);
    let mut out = u;
    for r in 1..rounds {
        u = prf.mac(&[&u]);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
        progress(r);
    }
    out
}
