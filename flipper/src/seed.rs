// Only the wallet app uses this: the signing app never touches the seed.

//! The BIP 39 word list on the SD card, and the wallet's account from its seed.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::Ordering;

use flipperzero::{io::Read, storage::OpenOptions};
use zflip_core::{Account, Network, hash, mnemonic};

use crate::{ui::PROGRESS, vault::trace};

pub const WORDS_PATH: &core::ffi::CStr = c"/ext/apps_data/zflip/english.txt";

/// Calls `f(index, word)` for each word of `english.txt` on the SD card, in order,
/// until it returns false. The list is never held in RAM whole: 13 KiB in one
/// block is more than a Flipper app can count on. Returns false if unreadable.
pub fn scan_words(mut f: impl FnMut(u16, &str) -> bool) -> bool {
    let Ok(mut file) = OpenOptions::new().read(true).open_existing(true).open(WORDS_PATH) else {
        return false;
    };
    let mut chunk = [0u8; 256];
    let mut word = [0u8; 16];
    let (mut len, mut index) = (0usize, 0u16);
    loop {
        let n = match file.read(&mut chunk) {
            Ok(n) => n,
            Err(_) => return false,
        };
        for &b in chunk[..n].iter().chain(if n == 0 { &b"\n"[..] } else { &[][..] }) {
            if b == b'\n' || b == b'\r' {
                if len > 0 {
                    let w = core::str::from_utf8(&word[..len]).unwrap_or("");
                    if !f(index, w) {
                        return true;
                    }
                    index += 1;
                    len = 0;
                }
            } else if len < word.len() {
                word[len] = b;
                len += 1;
            }
        }
        if n == 0 {
            return true;
        }
    }
}

/// True if the SD card holds the 2048-word list.
pub fn words_present() -> bool {
    let mut count = 0u32;
    scan_words(|_, _| {
        count += 1;
        true
    }) && count == 2048
}

/// The words at `indices`, in that order.
pub fn words_at(indices: &[u16]) -> Option<Vec<String>> {
    let mut out: Vec<Option<String>> = alloc::vec![None; indices.len()];
    scan_words(|i, w| {
        for (slot, &want) in out.iter_mut().zip(indices) {
            if want == i {
                *slot = Some(String::from(w));
            }
        }
        true
    });
    out.into_iter().collect()
}

/// The index of `word` in the list.
pub fn find_word(word: &str) -> Option<u16> {
    let mut found = None;
    scan_words(|i, w| {
        if w == word {
            found = Some(i);
        }
        found.is_none() && w <= word
    });
    found
}

/// How many words start with `prefix`, and `take` of them from position `skip`.
pub fn by_prefix(prefix: &str, skip: usize, take: usize) -> (usize, Vec<String>) {
    let (mut count, mut out) = (0usize, Vec::new());
    scan_words(|_, w| {
        if w.starts_with(prefix) {
            if count >= skip && out.len() < take {
                out.push(String::from(w));
            }
            count += 1;
            true
        } else {
            // Sorted list: stop once past the prefix.
            count == 0
        }
    });
    (count, out)
}

/// Entropy bytes from validated word indices (12–24 words).
pub fn entropy_of(indices: &[u16]) -> Vec<u8> {
    let bits = indices.len() * 11 * 32 / 33;
    let mut out = alloc::vec![0u8; bits / 8];
    for i in 0..bits {
        let bit = (indices[i / 11] >> (10 - i % 11)) & 1;
        out[i / 8] |= (bit as u8) << (7 - i % 8);
    }
    out
}

/// Word indices (entropy + checksum) for stored entropy.
pub fn indices_of(entropy: &[u8]) -> Vec<u16> {
    let ent_bits = entropy.len() * 8;
    let total = ent_bits * 33 / 32;
    let check = hash::sha256(entropy)[0];
    let mut out = alloc::vec![0u16; total / 11];
    for i in 0..total {
        let bit = if i < ent_bits {
            (entropy[i / 8] >> (7 - i % 8)) & 1
        } else {
            (check >> (7 - (i - ent_bits))) & 1
        };
        out[i / 11] = (out[i / 11] << 1) | bit as u16;
    }
    out
}

/// The BIP 39 seed and account 0 from entropy. Slow (~20 s): run on a worker.
pub fn open_account(entropy: &[u8], network: Network) -> Option<Account> {
    trace(c"words");
    let sentence = words_at(&indices_of(entropy))?.join(" ");
    trace(c"seed");
    let seed = mnemonic::to_seed(&sentence, "", |r| {
        PROGRESS.store(r * 60 / mnemonic::PBKDF2_ROUNDS, Ordering::Relaxed)
    });
    trace(c"keys");
    let account = crate::stable::with(|| Account::from_seed(&seed, network, 0).ok());
    trace(c"account ready");
    PROGRESS.store(100, Ordering::Relaxed);
    account
}
