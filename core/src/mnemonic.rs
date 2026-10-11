//! BIP 39 mnemonics, English only.
//!
//! The word list is not compiled into the device app: the Flipper keeps
//! `english.txt` on the SD card and loads it only while showing or typing words.
//! Anything implementing [`WordList`] works; [`Packed`] reads that file's format
//! (one word per line, in order).

use alloc::{string::String, vec::Vec};

use crate::hash::{pbkdf2_sha512, sha256};

pub const PBKDF2_ROUNDS: u32 = 2048;

/// The BIP 39 English list, one word per line.
#[cfg(feature = "english")]
pub const ENGLISH: &str = include_str!("english.txt");

pub trait WordList {
    fn word(&self, index: u16) -> Option<&str>;
    fn find(&self, word: &str) -> Option<u16>;
}

/// A newline-separated word list held in memory (e.g. read from the SD card).
/// Lookups scan the text: no index is built, to spare the device's RAM.
pub struct Packed<'a> {
    text: &'a str,
}

impl<'a> Packed<'a> {
    /// `None` unless the text holds exactly 2048 sorted lowercase words.
    pub fn new(text: &'a str) -> Option<Self> {
        let list = Packed { text };
        let mut count = 0usize;
        let mut prev = "";
        for w in list.words() {
            if w <= prev || !w.bytes().all(|b| b.is_ascii_lowercase()) {
                return None;
            }
            prev = w;
            count += 1;
        }
        (count == 2048).then_some(list)
    }

    pub fn words(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.text.lines().map(str::trim_ascii).filter(|w| !w.is_empty())
    }

    /// Words starting with `prefix`, in order, for autocomplete.
    pub fn by_prefix<'p>(&self, prefix: &'p str) -> impl Iterator<Item = &'a str> + 'p
    where
        'a: 'p,
    {
        self.words()
            .skip_while(move |w| *w < prefix)
            .take_while(move |w| w.starts_with(prefix))
    }
}

impl WordList for Packed<'_> {
    fn word(&self, index: u16) -> Option<&str> {
        self.words().nth(index as usize)
    }

    fn find(&self, word: &str) -> Option<u16> {
        self.words().position(|w| w == word).map(|i| i as u16)
    }
}

/// The 24 word indices for 32 bytes of entropy (256 bits + 8-bit checksum).
pub fn indices_from_entropy(entropy: &[u8; 32]) -> [u16; 24] {
    let check = sha256(entropy)[0];
    let bit = |i: usize| -> u16 {
        let byte = if i < 256 { entropy[i / 8] } else { check };
        ((byte >> (7 - i % 8)) & 1) as u16
    };
    core::array::from_fn(|w| (0..11).fold(0, |acc, k| (acc << 1) | bit(w * 11 + k)))
}

/// The word indices for 16, 20, 24, 28 or 32 bytes of entropy (12 to 24 words).
pub fn indices_for(entropy: &[u8]) -> Option<Vec<u16>> {
    let n = entropy.len();
    if !(16..=32).contains(&n) || n % 4 != 0 {
        return None;
    }
    let check = sha256(entropy)[0];
    let bit = |i: usize| -> u16 {
        let b = if i < n * 8 { entropy[i / 8] >> (7 - i % 8) } else { check >> (7 - (i - n * 8)) };
        (b & 1) as u16
    };
    let words = n * 3 / 4;
    Some((0..words).map(|w| (0..11).fold(0, |acc, k| (acc << 1) | bit(w * 11 + k))).collect())
}

/// The entropy behind 12 to 24 word indices, once their checksum is checked.
pub fn entropy_of(indices: &[u16]) -> Result<Vec<u8>, Error> {
    validate(indices)?;
    let entropy_bits = indices.len() * 11 * 32 / 33;
    let bit = |i: usize| (indices[i / 11] >> (10 - i % 11)) & 1;
    let mut entropy = alloc::vec![0u8; entropy_bits / 8];
    for i in 0..entropy_bits {
        entropy[i / 8] |= (bit(i) as u8) << (7 - i % 8);
    }
    Ok(entropy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not 12, 15, 18, 21 or 24 words.
    WordCount,
    /// A word is not in the list.
    UnknownWord,
    /// The last word does not match the checksum.
    Checksum,
}

/// Checks the checksum of a 12–24 word mnemonic given as indices.
pub fn validate(indices: &[u16]) -> Result<(), Error> {
    let n = indices.len();
    if !(12..=24).contains(&n) || n % 3 != 0 {
        return Err(Error::WordCount);
    }
    let total_bits = n * 11;
    let check_bits = total_bits / 33;
    let entropy_bits = total_bits - check_bits;
    let bit = |i: usize| (indices[i / 11] >> (10 - i % 11)) & 1;

    let mut entropy = [0u8; 32];
    for i in 0..entropy_bits {
        entropy[i / 8] |= (bit(i) as u8) << (7 - i % 8);
    }
    let hash = sha256(&entropy[..entropy_bits / 8]);
    let ok = (0..check_bits).all(|k| bit(entropy_bits + k) as u8 == (hash[0] >> (7 - k)) & 1);
    if ok { Ok(()) } else { Err(Error::Checksum) }
}

/// Parses space-separated words into indices and checks the checksum.
pub fn parse(words: &str, list: &impl WordList) -> Result<Vec<u16>, Error> {
    let indices = words
        .split_ascii_whitespace()
        .map(|w| list.find(w).ok_or(Error::UnknownWord))
        .collect::<Result<Vec<_>, _>>()?;
    validate(&indices)?;
    Ok(indices)
}

/// The mnemonic sentence: words joined by single spaces.
pub fn sentence(indices: &[u16], list: &impl WordList) -> Option<String> {
    let mut s = String::new();
    for (i, &w) in indices.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(list.word(w)?);
    }
    Some(s)
}

/// The BIP 39 seed. Both strings must already be NFKD, which plain ASCII is; the
/// device keyboard only types ASCII. `progress(round)` runs during the 2048 rounds.
pub fn to_seed(sentence: &str, passphrase: &str, progress: impl FnMut(u32)) -> [u8; 64] {
    pbkdf2_sha512(
        sentence.as_bytes(),
        &[b"mnemonic", passphrase.as_bytes()],
        PBKDF2_ROUNDS,
        progress,
    )
}
