//! Unified Address / UFVK encoding (ZIP 316) for the Orchard-only case.
//!
//! `zcash_address` handles every receiver type, but its generic parsing pulls in
//! I/O error types and `Debug` formatting worth ~10 KiB of a Flipper app's RAM.
//! This is the small subset ZFlip needs: Bech32m, F4Jumble and the TLV items.
//! Tested against `zcash_address` (see tests/account.rs).

use alloc::{string::String, vec::Vec};

use crate::Network;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const PADDING_LEN: usize = 16;

/// Typecode of an Orchard receiver in a UA, and of an Orchard FVK in a UFVK.
pub const ORCHARD: u32 = 0x03;

pub fn address_hrp(network: Network) -> &'static str {
    match network {
        Network::Main => "u",
        Network::Test => "utest",
    }
}

pub fn ufvk_hrp(network: Network) -> &'static str {
    match network {
        Network::Main => "uview",
        Network::Test => "uviewtest",
    }
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|c| c >> 5)
        .chain(core::iter::once(0))
        .chain(hrp.bytes().map(|c| c & 31))
}

fn to_5bit(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

fn from_5bit(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &v in data {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover padding must be shorter than 5 bits and zero.
    (bits < 5 && (acc & ((1 << bits) - 1)) == 0).then_some(out)
}

/// Bech32m with no length limit (unified encodings exceed 90 characters).
fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let values = to_5bit(data);
    let chk = polymod(hrp_expand(hrp).chain(values.iter().copied()).chain([0u8; 6])) ^ BECH32M_CONST;
    let mut s = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for v in values {
        s.push(CHARSET[v as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((chk >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

fn bech32m_decode(text: &str) -> Option<(&str, Vec<u8>)> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let sep = text.rfind('1')?;
    // Checked split: a slicing panic path would drag in `Debug` and Unicode tables.
    let (hrp, rest) = text.split_at_checked(sep)?;
    let rest = rest.as_bytes().get(1..)?;
    if hrp.is_empty() || rest.len() < 6 {
        return None;
    }
    let values = rest
        .iter()
        .map(|&c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<Vec<u8>>>()?;
    if polymod(hrp_expand(hrp).chain(values.iter().copied())) != BECH32M_CONST {
        return None;
    }
    Some((hrp, from_5bit(values.get(..values.len() - 6)?)?))
}

fn write_compact(out: &mut Vec<u8>, n: u32) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn read_compact(data: &[u8]) -> Option<(u32, &[u8])> {
    match *data.first()? {
        n @ 0..=0xfc => Some((n as u32, &data[1..])),
        0xfd => {
            let n = u16::from_le_bytes([*data.get(1)?, *data.get(2)?]) as u32;
            (n >= 0xfd).then_some((n, &data[3..]))
        }
        0xfe => {
            let n = u32::from_le_bytes(crate::arr(data.get(1..5)?));
            (n > 0xffff).then_some((n, &data[5..]))
        }
        _ => None,
    }
}

/// Encodes one item (`typecode`, `data`) as a unified encoding under `hrp`.
pub fn encode(hrp: &str, typecode: u32, data: &[u8]) -> String {
    let mut raw = Vec::with_capacity(data.len() + 4 + PADDING_LEN);
    write_compact(&mut raw, typecode);
    write_compact(&mut raw, data.len() as u32);
    raw.extend_from_slice(data);
    let mut padding = [0u8; PADDING_LEN];
    padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
    raw.extend_from_slice(&padding);
    // Lengths here are always within F4Jumble's bounds (48 bytes .. 4 MiB).
    let _ = f4jumble::f4jumble_mut(&mut raw);
    bech32m_encode(hrp, &raw)
}

/// Decodes a unified encoding: its HRP and its (typecode, data) items.
pub fn decode(text: &str) -> Option<(String, Vec<(u32, Vec<u8>)>)> {
    let (hrp, mut raw) = bech32m_decode(text)?;
    if hrp.len() > PADDING_LEN || raw.len() < PADDING_LEN {
        return None;
    }
    f4jumble::f4jumble_inv_mut(&mut raw).ok()?;
    let (body, padding) = raw.split_at(raw.len() - PADDING_LEN);
    let mut expected = [0u8; PADDING_LEN];
    expected[..hrp.len()].copy_from_slice(hrp.as_bytes());
    if padding != expected {
        return None;
    }
    let mut items = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (typecode, r) = read_compact(rest)?;
        let (len, r) = read_compact(r)?;
        let len = len as usize;
        if r.len() < len {
            return None;
        }
        items.push((typecode, r[..len].to_vec()));
        rest = &r[len..];
    }
    Some((String::from(hrp), items))
}

/// An Orchard-only unified address.
pub fn encode_orchard_address(network: Network, raw: &[u8; 43]) -> String {
    encode(address_hrp(network), ORCHARD, raw)
}

/// The Orchard receiver of a unified address on `network`, if it has one.
pub fn orchard_receiver(network: Network, text: &str) -> Option<[u8; 43]> {
    let (hrp, items) = decode(text)?;
    if hrp != address_hrp(network) {
        return None;
    }
    items
        .into_iter()
        .find(|(t, d)| *t == ORCHARD && d.len() == 43)
        .map(|(_, d)| crate::arr(&d))
}
