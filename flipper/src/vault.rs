// Shared by both apps; each uses a subset.
#![allow(dead_code)]

//! The sealed wallet file on the SD card (`wallet.zfv`).
//!
//! The secret part holds the BIP 39 entropy (so the wallet app can re-derive for
//! another network) and what the signing app needs without re-deriving: the Orchard
//! spending key and the seed fingerprint. It is encrypted with AES-256-CTR (the
//! Flipper's AES engine) and authenticated with a keyed BLAKE2b tag.
//!
//! The keys come from the PIN through an iterated keyed BLAKE2b (PBKDF2's
//! structure), and the encryption key is then passed through the Flipper's
//! secure-enclave unique key, which never leaves the radio co-processor: a copy of
//! the SD card is useless without this exact Flipper.
//!
//! Limits, stated plainly: the failed-attempt counter lives on the card, so someone
//! holding the Flipper can restore an old copy of the file and keep guessing on the
//! device itself; a long PIN is what makes that slow. And any app running on this
//! Flipper can use the enclave key too.

use core::ffi::CStr;

use flipperzero::{
    furi::rng::HwRng,
    io::{Read, Write},
    storage::OpenOptions,
};
use flipperzero_sys as sys;
use rand_core::RngCore;
use zflip_core::{Network, arr};

pub const DIR: &CStr = c"/ext/apps_data/zflip";
pub const PATH: &CStr = c"/ext/apps_data/zflip/wallet.zfv";

const MAGIC: &[u8; 4] = b"ZFLP";
const VERSION: u8 = 5;
/// Version 4 also sealed 50 precomputed addresses and a QR file hash; it is still
/// read, and rewritten as version 5 on the first unlock.
const LEGACY: u8 = 4;
const LEGACY_SECRET: usize = SECRET + 50 * 43 + 32;
const KDF_ROUNDS: u32 = 20_000;
pub const MAX_ATTEMPTS: u8 = 10;
/// FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT: a key unique to each Flipper.
const UNIQUE_KEY_SLOT: u8 = 11;

// Layout. Byte 7 (failed attempts) is the only one outside the tag.
const NETWORK: usize = 5;
const WORDS: usize = 6;
const FAILED: usize = 7;
const CREATED: usize = 8;
const SALT: usize = 12;
const IV: usize = 28;
const CHANGE: usize = 44;
const SECRET: usize = 87;
const SECRET_LEN: usize = 96;
const TAG: usize = SECRET + SECRET_LEN;
const LEN: usize = TAG + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Missing,
    Corrupt,
    WrongPin { attempts_left: u8 },
    Wiped,
    Enclave,
    Io,
}

/// Public fields, readable without the PIN (but covered by the tag).
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub network: Network,
    pub word_count: u8,
    pub created_at: u32,
    pub failed: u8,
    /// The change address at internal index 0, for the signing app to recognise.
    pub change: [u8; 43],
}

/// The sealed secrets. Zeroed when dropped.
pub struct Secret {
    pub entropy: [u8; 32],
    pub entropy_len: usize,
    pub sk: [u8; 32],
    pub seed_fp: [u8; 32],
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.entropy.iter_mut().chain(self.sk.iter_mut()).chain(self.seed_fp.iter_mut()) {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

impl Secret {
    pub fn entropy(&self) -> &[u8] {
        &self.entropy[..self.entropy_len]
    }
}

fn with_storage<R>(f: impl FnOnce(*mut sys::Storage) -> R) -> R {
    let storage = unsafe { sys::furi_record_open(c"storage".as_ptr()) } as *mut sys::Storage;
    let r = f(storage);
    unsafe { sys::furi_record_close(c"storage".as_ptr()) };
    r
}

pub fn exists() -> bool {
    with_storage(|s| unsafe { sys::storage_file_exists(s, PATH.as_ptr()) })
}

/// The file's bytes and where its secret starts (version 5, or legacy 4).
fn read_file() -> Result<(alloc::vec::Vec<u8>, usize), Error> {
    let mut f = OpenOptions::new()
        .read(true)
        .open_existing(true)
        .open(PATH)
        .map_err(|_| Error::Missing)?;
    // On the heap: a legacy file is about 2.4 KiB, a lot for the app's 4 KiB stack.
    let mut buf = alloc::vec![0u8; LEGACY_SECRET + SECRET_LEN + 32];
    let mut got = 0;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return Err(Error::Corrupt),
        }
    }
    buf.truncate(got);
    let secret = match buf.get(4) {
        Some(&VERSION) => SECRET,
        Some(&LEGACY) => LEGACY_SECRET,
        _ => return Err(Error::Corrupt),
    };
    if &buf[..4] != MAGIC || got != secret + SECRET_LEN + 32 {
        return Err(Error::Corrupt);
    }
    Ok((buf, secret))
}

fn write_file(buf: &[u8]) -> Result<(), Error> {
    with_storage(|s| unsafe { sys::storage_simply_mkdir(s, DIR.as_ptr()) });
    let mut f = OpenOptions::new()
        .write(true)
        .create_always(true)
        .open(PATH)
        .map_err(|_| Error::Io)?;
    f.write(buf).map_err(|_| Error::Io)?;
    Ok(())
}

fn parse_meta(buf: &[u8]) -> Result<Meta, Error> {
    Ok(Meta {
        network: Network::from_byte(buf[NETWORK]).ok_or(Error::Corrupt)?,
        word_count: buf[WORDS],
        failed: buf[FAILED],
        created_at: u32::from_le_bytes(arr(&buf[CREATED..])),
        change: arr(&buf[CHANGE..]),
    })
}

pub fn meta() -> Result<Meta, Error> {
    parse_meta(&read_file()?.0)
}

/// Erases the wallet (overwrite, then delete).
pub fn wipe() {
    let _ = write_file(&[0u8; LEN]);
    with_storage(|s| unsafe { sys::storage_simply_remove(s, PATH.as_ptr()) });
    reset_addresses();
}

struct Keys {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        for b in self.enc.iter_mut().chain(self.mac.iter_mut()) {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

fn blake2b(key: &[u8], personal: &[u8; 16]) -> blake2b_simd::Params {
    let mut p = blake2b_simd::Params::new();
    p.hash_length(64).key(key).personal(personal);
    p
}

fn derive_keys(pin: &[u8], salt: &[u8; 16], progress: &mut dyn FnMut(u32)) -> Result<Keys, Error> {
    // PBKDF2's structure with keyed BLAKE2b-512 as the PRF.
    let prf = blake2b(pin, b"ZFlipVaultKDF_v2");
    let mut first = [0u8; 20];
    first[..16].copy_from_slice(salt);
    first[19] = 1;
    let mut u: [u8; 64] = arr(prf.hash(&first).as_bytes());
    let mut k = u;
    for r in 1..KDF_ROUNDS {
        u = arr(prf.hash(&u).as_bytes());
        for (a, b) in k.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
        if r % 256 == 0 {
            progress(r * 100 / KDF_ROUNDS);
        }
    }
    let mut enc = [0u8; 32];
    // Bind to this Flipper: run the PIN key through the enclave's unique key.
    unsafe {
        if !sys::furi_hal_crypto_enclave_ensure_key(UNIQUE_KEY_SLOT)
            || !sys::furi_hal_crypto_enclave_load_key(UNIQUE_KEY_SLOT, salt.as_ptr())
        {
            return Err(Error::Enclave);
        }
        let ok = sys::furi_hal_crypto_encrypt(k.as_ptr(), enc.as_mut_ptr(), 32);
        sys::furi_hal_crypto_enclave_unload_key(UNIQUE_KEY_SLOT);
        if !ok {
            return Err(Error::Enclave);
        }
    }
    let keys = Keys { enc, mac: arr(&k[32..]) };
    k.iter_mut().for_each(|b| *b = 0);
    Ok(keys)
}

/// AES-256-CTR on the Flipper's AES engine (its own inverse).
fn ctr(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8; SECRET_LEN]) -> Result<(), Error> {
    let input = *data;
    let ok = unsafe {
        sys::furi_hal_crypto_ctr(key.as_ptr(), iv.as_ptr(), input.as_ptr(), data.as_mut_ptr(), SECRET_LEN)
    };
    if ok { Ok(()) } else { Err(Error::Enclave) }
}

/// Covers everything but the failed-attempt counter, up to the tag (the last 32 bytes).
fn tag(mac_key: &[u8; 32], buf: &[u8]) -> [u8; 32] {
    let mut state = blake2b(mac_key, b"ZFlipVaultTag_v2").hash_length(32).to_state();
    state.update(&buf[..FAILED]);
    state.update(&buf[FAILED + 1..buf.len() - 32]);
    arr(state.finalize().as_bytes())
}

/// Creates the wallet file.
pub fn seal(
    secret: &Secret,
    network: Network,
    created_at: u32,
    change: &[u8; 43],
    pin: &[u8],
    progress: &mut dyn FnMut(u32),
) -> Result<(), Error> {
    let mut buf = alloc::boxed::Box::new([0u8; LEN]);
    buf[..4].copy_from_slice(MAGIC);
    buf[4] = VERSION;
    buf[NETWORK] = network.to_byte();
    buf[WORDS] = (secret.entropy_len * 3 / 4) as u8; // 16 → 12 words ... 32 → 24
    buf[CREATED..CREATED + 4].copy_from_slice(&created_at.to_le_bytes());
    HwRng.fill_bytes(&mut buf[SALT..CHANGE]); // salt + iv
    buf[CHANGE..SECRET].copy_from_slice(change);
    let keys = derive_keys(pin, &arr(&buf[SALT..]), progress)?;
    let mut plain = [0u8; SECRET_LEN];
    plain[..32].copy_from_slice(&secret.entropy);
    plain[32..64].copy_from_slice(&secret.sk);
    plain[64..].copy_from_slice(&secret.seed_fp);
    ctr(&keys.enc, &arr(&buf[IV..]), &mut plain)?;
    buf[SECRET..TAG].copy_from_slice(&plain);
    let t = tag(&keys.mac, &*buf);
    buf[TAG..].copy_from_slice(&t);
    write_file(&*buf)
}

/// Opens the wallet with `pin`. Wrong PINs are counted; the tenth wipes it.
pub fn unseal(pin: &[u8], progress: &mut dyn FnMut(u32)) -> Result<(Meta, Secret), Error> {
    let (mut buf, at) = read_file()?;
    let meta = parse_meta(&buf)?;
    if meta.failed >= MAX_ATTEMPTS {
        wipe();
        return Err(Error::Wiped);
    }
    // Count the attempt before checking it, so pulling the battery doesn't help.
    buf[FAILED] = meta.failed + 1;
    write_file(&buf)?;

    let keys = derive_keys(pin, &arr(&buf[SALT..]), progress)?;
    let expected = tag(&keys.mac, &buf);
    let diff = expected.iter().zip(buf[at + SECRET_LEN..].iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        if buf[FAILED] >= MAX_ATTEMPTS {
            wipe();
            return Err(Error::Wiped);
        }
        return Err(Error::WrongPin { attempts_left: MAX_ATTEMPTS - buf[FAILED] });
    }
    buf[FAILED] = 0;
    if at != SECRET {
        // Legacy: drop the precomputed addresses, keep the same encrypted secret.
        buf.drain(SECRET..at);
        buf[4] = VERSION;
        let t = tag(&keys.mac, &buf);
        buf[TAG..].copy_from_slice(&t);
    }
    write_file(&buf)?;

    let mut plain: [u8; SECRET_LEN] = arr(&buf[SECRET..]);
    ctr(&keys.enc, &arr(&buf[IV..]), &mut plain)?;
    let entropy_len = meta.word_count as usize * 4 / 3;
    if !(16..=32).contains(&entropy_len) {
        return Err(Error::Corrupt);
    }
    let secret = Secret { entropy: arr(&plain), entropy_len, sk: arr(&plain[32..]), seed_fp: arr(&plain[64..]) };
    plain.iter_mut().for_each(|b| *b = 0);
    Ok((Meta { failed: 0, ..meta }, secret))
}

/// The last receiving address index handed out (the app moves on from it).
pub const INDEX_PATH: &CStr = c"/ext/apps_data/zflip/address_index";
/// Left behind by version 4, which precomputed QR codes.
const QR_PATH: &CStr = c"/ext/apps_data/zflip/qr.bin";

/// For a new wallet: addresses start again at #0.
pub fn reset_addresses() {
    with_storage(|s| unsafe {
        sys::storage_simply_remove(s, INDEX_PATH.as_ptr());
        sys::storage_simply_remove(s, QR_PATH.as_ptr());
    });
}

/// Logs a step and the time since boot, visible with `log` on the Flipper CLI.
pub fn trace(step: &CStr) {
    unsafe {
        sys::furi_log_print_format(
            sys::FuriLogLevelInfo,
            c"ZFlip".as_ptr(),
            c"%s at %lu ms, heap %u".as_ptr(),
            step.as_ptr(),
            sys::furi_get_tick(),
            sys::memmgr_get_free_heap() as u32,
        )
    };
}
