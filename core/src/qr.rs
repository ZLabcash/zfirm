//! A minimal QR encoder for receiving addresses and viewing keys: byte mode, error
//! correction level L, versions 1 to 9 (up to 230 bytes, 53 modules: one pixel each
//! still fits the Flipper's 64-pixel screen), mask 0. Small on purpose (a general QR library costs ~7 KiB
//! of a Flipper app's RAM). Matches `qrcodegen` with the same version and mask
//! (see tests/qr.rs).

use alloc::vec::Vec;

/// (data codewords per block, EC codewords per block, blocks) for level L, v1..=9.
const BLOCKS: [(usize, usize, usize); 9] = [
    (19, 7, 1),
    (34, 10, 1),
    (55, 15, 1),
    (80, 20, 1),
    (108, 26, 1),
    (68, 18, 2),
    (78, 20, 2),
    (97, 24, 2),
    (116, 30, 2),
];
/// The middle alignment pattern row/column of versions 7..=9 (the others are 6 and size - 7).
const ALIGN_MID: [usize; 3] = [22, 24, 26];
/// Format information for level L with mask 0, bits 14..0.
const FORMAT_L_MASK0: u16 = 0b111011111000100;

pub struct Qr {
    pub size: usize,
    /// Row-major modules, one bit each, set = dark (bits, not bools: the Flipper
    /// has a few KiB of heap to spare).
    modules: Bits1,
}

struct Bits1(Vec<u8>);

impl Bits1 {
    fn new(n: usize) -> Self {
        Bits1(alloc::vec![0; n.div_ceil(8)])
    }
    fn get(&self, i: usize) -> bool {
        self.0[i / 8] >> (i % 8) & 1 == 1
    }
    fn put(&mut self, i: usize, v: bool) {
        if v {
            self.0[i / 8] |= 1 << (i % 8);
        } else {
            self.0[i / 8] &= !(1 << (i % 8));
        }
    }
}

impl Qr {
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.modules.get(y * self.size + x)
    }

    /// Encodes `data`; `None` if it needs more than version 9 (230 bytes).
    pub fn encode(data: &[u8]) -> Option<Qr> {
        let version = (1..=9).find(|&v| {
            let (d, _, b) = BLOCKS[v - 1];
            4 + 8 + data.len() * 8 <= d * b * 8
        })?;
        let (dpb, ecb, blocks) = BLOCKS[version - 1];
        let capacity = dpb * blocks;

        // Bit stream: mode 0100, 8-bit length, bytes, terminator, padding.
        let mut bits = Bits::default();
        bits.push(0b0100, 4);
        bits.push(data.len() as u32, 8);
        for &b in data {
            bits.push(b as u32, 8);
        }
        let room = capacity * 8 - bits.len;
        bits.push(0, room.min(4));
        while bits.len % 8 != 0 {
            bits.push(0, 1);
        }
        let mut codewords = bits.bytes;
        let mut pad = 0xEC;
        while codewords.len() < capacity {
            codewords.push(pad);
            pad ^= 0xEC ^ 0x11;
        }

        // Error correction per block, then interleave.
        let poly = generator(ecb);
        let data_blocks: Vec<&[u8]> = codewords.chunks(dpb).collect();
        let ec_blocks: Vec<Vec<u8>> = data_blocks.iter().map(|b| remainder(b, &poly)).collect();
        let mut stream = Vec::with_capacity(capacity + ecb * blocks);
        for i in 0..dpb {
            for b in &data_blocks {
                stream.push(b[i]);
            }
        }
        for i in 0..ecb {
            for b in &ec_blocks {
                stream.push(b[i]);
            }
        }

        let size = version * 4 + 17;
        let mut qr = Qr { size, modules: Bits1::new(size * size) };
        let mut function = Bits1::new(size * size);
        qr.draw_function_patterns(version, &mut function);
        qr.place(&stream, &function);
        Some(qr)
    }

    fn set(&mut self, function: &mut Bits1, x: usize, y: usize, dark: bool) {
        self.modules.put(y * self.size + x, dark);
        function.put(y * self.size + x, true);
    }

    fn draw_function_patterns(&mut self, version: usize, function: &mut Bits1) {
        let size = self.size;
        // Timing patterns.
        for i in 0..size {
            self.set(function, 6, i, i % 2 == 0);
            self.set(function, i, 6, i % 2 == 0);
        }
        // Finders with their separators.
        for (cx, cy) in [(3, 3), (size - 4, 3), (3, size - 4)] {
            for dy in -4i32..=4 {
                for dx in -4i32..=4 {
                    let (x, y) = (cx as i32 + dx, cy as i32 + dy);
                    if x < 0 || y < 0 || x >= size as i32 || y >= size as i32 {
                        continue;
                    }
                    let d = dx.abs().max(dy.abs());
                    self.set(function, x as usize, y as usize, d != 2 && d != 4);
                }
            }
        }
        // Alignment patterns: one bottom right for versions 2..=6; a 3×3 grid (less the
        // three corners the finders take) for 7..=9.
        let centers: &[usize] = match version {
            1 => &[],
            2..=6 => &[size - 7],
            _ => &[6, ALIGN_MID[version - 7], size - 7],
        };
        let last = size - 7;
        for &cy in centers {
            for &cx in centers {
                if (cx == 6 && cy == 6) || (cx == 6 && cy == last) || (cx == last && cy == 6) {
                    continue;
                }
                for dy in -2i32..=2 {
                    for dx in -2i32..=2 {
                        let d = dx.abs().max(dy.abs());
                        self.set(function, (cx as i32 + dx) as usize, (cy as i32 + dy) as usize, d != 1);
                    }
                }
            }
        }
        // Version information (7 and up): 6 bits and a BCH(18, 6) remainder, twice.
        if version >= 7 {
            let mut rem = version as u32;
            for _ in 0..12 {
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
            }
            let info = (version as u32) << 12 | rem;
            for i in 0..18 {
                let dark = (info >> i) & 1 == 1;
                let (a, b) = (size - 11 + i % 3, i / 3);
                self.set(function, a, b, dark);
                self.set(function, b, a, dark);
            }
        }
        // Format information (both copies) and the dark module.
        let bit = |i: usize| (FORMAT_L_MASK0 >> i) & 1 == 1;
        for i in 0..=5 {
            self.set(function, 8, i, bit(i));
        }
        self.set(function, 8, 7, bit(6));
        self.set(function, 8, 8, bit(7));
        self.set(function, 7, 8, bit(8));
        for i in 9..15 {
            self.set(function, 14 - i, 8, bit(i));
        }
        for i in 0..8 {
            self.set(function, size - 1 - i, 8, bit(i));
        }
        for i in 8..15 {
            self.set(function, 8, size - 15 + i, bit(i));
        }
        self.set(function, 8, size - 8, true);
    }

    /// Zigzag placement of the codeword bits, with mask 0 ((x + y) even flips).
    fn place(&mut self, stream: &[u8], function: &Bits1) {
        let size = self.size;
        let total_bits = stream.len() * 8;
        let mut i = 0;
        let mut right = size as i32 - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size {
                for j in 0..2 {
                    let x = (right - j) as usize;
                    let upward = ((right + 1) & 2) == 0;
                    let y = if upward { size - 1 - vert } else { vert };
                    if function.get(y * size + x) {
                        continue;
                    }
                    let mut dark = false;
                    if i < total_bits {
                        dark = (stream[i >> 3] >> (7 - (i & 7))) & 1 == 1;
                        i += 1;
                    }
                    if (x + y) % 2 == 0 {
                        dark = !dark;
                    }
                    self.modules.put(y * size + x, dark);
                }
            }
            right -= 2;
        }
    }
}

#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn push(&mut self, value: u32, n: usize) {
        for i in (0..n).rev() {
            if self.len % 8 == 0 {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                *self.bytes.last_mut().unwrap_or(&mut 0) |= 1 << (7 - self.len % 8);
            }
            self.len += 1;
        }
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    out
}

/// Reed-Solomon generator polynomial of `degree` (coefficients, highest first,
/// leading 1 omitted).
fn generator(degree: usize) -> Vec<u8> {
    let mut g = alloc::vec![0u8; degree];
    g[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            g[j] = gf_mul(g[j], root);
            if j + 1 < degree {
                g[j] ^= g[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    g
}

fn remainder(data: &[u8], poly: &[u8]) -> Vec<u8> {
    let mut r = alloc::vec![0u8; poly.len()];
    for &b in data {
        let factor = b ^ r[0];
        r.remove(0);
        r.push(0);
        for (x, &g) in r.iter_mut().zip(poly) {
            *x ^= gf_mul(g, factor);
        }
    }
    r
}
