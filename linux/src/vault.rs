//! The wallet file: the seed's entropy sealed with the PIN.
//!
//! Argon2id (32 MiB, 3 passes) then AES-256-GCM.
//! File: "ZFV1" || failed (1) || network (1) || salt (16) || nonce (12) || ciphertext + tag,
//! with everything but the failed-attempt counter as associated data.
//!
//! Plainly: a Pi Zero or a Kindle has no secure element, so the PIN is the only thing
//! between a copy of this file and the seed. Argon2id makes each guess cost real
//! memory and time; a long PIN is what makes guessing hopeless. The attempt counter
//! is in the file, so it only slows guessing on the device itself.

use std::{fs, io, path::Path};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;
use zfirm_core::Network;

const MAGIC: &[u8; 4] = b"ZFV1";
const FAILED: usize = 4;
const NETWORK: usize = 5;
const SALT: usize = 6;
const NONCE: usize = 22;
const HEADER: usize = 34;
pub const MAX_ATTEMPTS: u8 = 10;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Missing,
    Corrupt,
    WrongPin { attempts_left: u8 },
    Wiped,
    Io,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound { Error::Missing } else { Error::Io }
    }
}

fn key(pin: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(32 * 1024, 3, 1, Some(32)).expect("valid params");
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, &mut *out)
        .expect("valid lengths");
    out
}

fn aad(file: &[u8]) -> Vec<u8> {
    [&file[..FAILED], &file[FAILED + 1..HEADER]].concat()
}

/// Seals `entropy` (16 to 32 bytes) for `network` under `pin` at `path`.
pub fn seal(path: &Path, entropy: &[u8], network: Network, pin: &str) -> Result<(), Error> {
    let mut file = vec![0u8; HEADER];
    file[..4].copy_from_slice(MAGIC);
    file[NETWORK] = network.to_byte();
    getrandom::getrandom(&mut file[SALT..HEADER]).map_err(|_| Error::Io)?;
    let k = key(pin, &file[SALT..NONCE]);
    let cipher = Aes256Gcm::new_from_slice(&*k).expect("32-byte key");
    let ct = cipher
        .encrypt(file[NONCE..HEADER].into(), Payload { msg: entropy, aad: &aad(&file) })
        .map_err(|_| Error::Io)?;
    file.extend_from_slice(&ct);
    write(path, &file)
}

/// Opens the wallet with `pin`: its network and entropy. Wrong PINs are counted
/// before they are checked; the tenth wipes the wallet.
pub fn open(path: &Path, pin: &str) -> Result<(Network, Zeroizing<Vec<u8>>), Error> {
    let mut file = fs::read(path)?;
    if file.len() < HEADER + 16 + 16 || &file[..4] != MAGIC {
        return Err(Error::Corrupt);
    }
    let network = Network::from_byte(file[NETWORK]).ok_or(Error::Corrupt)?;
    if file[FAILED] >= MAX_ATTEMPTS {
        wipe(path);
        return Err(Error::Wiped);
    }
    file[FAILED] += 1;
    write(path, &file)?;

    let k = key(pin, &file[SALT..NONCE]);
    let cipher = Aes256Gcm::new_from_slice(&*k).expect("32-byte key");
    let opened = cipher.decrypt(file[NONCE..HEADER].into(), Payload { msg: &file[HEADER..], aad: &aad(&file) });
    match opened {
        Ok(entropy) => {
            file[FAILED] = 0;
            write(path, &file)?;
            Ok((network, Zeroizing::new(entropy)))
        }
        Err(_) if file[FAILED] >= MAX_ATTEMPTS => {
            wipe(path);
            Err(Error::Wiped)
        }
        Err(_) => Err(Error::WrongPin { attempts_left: MAX_ATTEMPTS - file[FAILED] }),
    }
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}

/// Erases the wallet: overwrite, flush, then delete.
pub fn wipe(path: &Path) {
    if let Ok(len) = fs::metadata(path).map(|m| m.len()) {
        let _ = write(path, &vec![0u8; len as usize]);
    }
    let _ = fs::remove_file(path);
}

/// Writes through a temporary file and a rename, so a power cut leaves either the
/// old file or the new one.
fn write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let tmp = path.with_extension("tmp");
    // Readable by its owner only.
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_counts_and_wipes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.zfv");
        seal(&path, &[7u8; 32], Network::Test, "2468").unwrap();
        let (network, entropy) = open(&path, "2468").unwrap();
        assert_eq!((network, entropy.as_slice()), (Network::Test, &[7u8; 32][..]));

        assert_eq!(open(&path, "1111"), Err(Error::WrongPin { attempts_left: 9 }));
        // A right PIN resets the count.
        assert!(open(&path, "2468").is_ok());
        for left in (1..10).rev() {
            assert_eq!(open(&path, "0000"), Err(Error::WrongPin { attempts_left: left }));
        }
        assert_eq!(open(&path, "0000"), Err(Error::Wiped));
        assert!(!exists(&path));
    }

    #[test]
    fn the_header_is_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.zfv");
        seal(&path, &[7u8; 16], Network::Main, "2468").unwrap();
        let mut file = fs::read(&path).unwrap();
        file[NETWORK] = Network::Test.to_byte();
        fs::write(&path, &file).unwrap();
        assert_eq!(open(&path, "2468"), Err(Error::WrongPin { attempts_left: 9 }));
    }
}
