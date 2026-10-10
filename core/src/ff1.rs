//! FF1-AES256 (NIST SP 800-38G) specialised to Orchard diversifiers: radix 2, 88-bit
//! numeral strings, empty tweak. The generic `fpe` crate pulls in a bignum library
//! that alone weighs more than the rest of the device crypto; 44-bit halves fit in a
//! `u64`, so none is needed here. Tested against `fpe` and Orchard's `address_at`.

use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};

const N: u32 = 88;
const HALF: u32 = N / 2;
const MASK: u64 = (1 << HALF) - 1;

/// The numeral string of `bytes` read as `BinaryNumeralString::from_bytes_le` does:
/// numeral `8k + j` is bit `j` of byte `k`. NUM_2 reads the first numeral as the most
/// significant digit.
fn num(bytes: &[u8; 11], start: u32) -> u64 {
    (start..start + HALF).fold(0, |acc, i| {
        (acc << 1) | ((bytes[(i / 8) as usize] >> (i % 8)) & 1) as u64
    })
}

fn put(out: &mut [u8; 11], start: u32, value: u64) {
    for k in 0..HALF {
        let i = start + k;
        let bit = ((value >> (HALF - 1 - k)) & 1) as u8;
        out[(i / 8) as usize] |= bit << (i % 8);
    }
}

/// Encrypts the 88-bit diversifier index `j` (little-endian bytes) under `dk`.
pub fn encrypt(dk: &[u8; 32], j: &[u8; 11]) -> [u8; 11] {
    let aes = Aes256::new(GenericArray::from_slice(dk));
    let ciph = |block: &mut [u8; 16]| aes.encrypt_block(GenericArray::from_mut_slice(block));

    // P = [1] [2] [1] [radix]^3 [10] [u mod 256] [n]^4 [t]^4
    let mut p = [1, 2, 1, 0, 0, 2, 10, HALF as u8, 0, 0, 0, N as u8, 0, 0, 0, 0];
    ciph(&mut p);

    let (mut a, mut b) = (num(j, 0), num(j, HALF));
    for i in 0..10u8 {
        // Q = 0^9 [i] [NUM(B)]^6 ; R = CBC-MAC(P || Q) ; y = NUM(R[..12]).
        let mut r = p;
        r[9] ^= i;
        for (k, byte) in b.to_be_bytes()[2..].iter().enumerate() {
            r[10 + k] ^= byte;
        }
        ciph(&mut r);
        let y = r[..12].iter().fold(0u128, |acc, &x| (acc << 8) | x as u128);
        let c = ((a as u128 + y) & MASK as u128) as u64;
        a = b;
        b = c;
    }

    let mut out = [0u8; 11];
    put(&mut out, 0, a);
    put(&mut out, HALF, b);
    out
}
