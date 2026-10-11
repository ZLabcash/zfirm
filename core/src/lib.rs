//! ZFirm: the Zcash shielded signer core shared by every ZFirm device (ZFlip on the
//! Flipper Zero, a Pi Zero, a jailbroken Kindle, any Linux board).
//!
//! Everything here is `no_std` + `alloc` and fits a Flipper app (Cortex-M4, ~100 KiB
//! of RAM for the whole app). The device holds the seed; a companion phone holds only
//! the viewing key, builds transactions, and sends the device a compact
//! [`request::SignRequest`] to check ([`sign::review`]), show and sign. The protocol
//! itself, from pairing to signatures, is [`session`]: a device only adds a screen,
//! buttons and a link.

#![no_std]

extern crate alloc;

pub mod account;
pub mod ff1;
pub mod hash;
pub mod mnemonic;
pub mod protocol;
pub mod qr;
pub mod request;
pub mod session;
pub mod sign;
pub mod ua;

pub use account::Account;

/// The Zcash network an account lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    /// ZIP 32 / SLIP 44 coin type.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Main => 133,
            Network::Test => 1,
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Network::Main => 0,
            Network::Test => 1,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Network::Main),
            1 => Some(Network::Test),
            _ => None,
        }
    }
}

/// The first `N` bytes of `s` as an array. Panics only on a short slice (bounds
/// check), without pulling in `Debug` formatting as `try_into().unwrap()` would.
pub fn arr<const N: usize>(s: &[u8]) -> [u8; N] {
    core::array::from_fn(|i| s[i])
}

/// One ZEC in zatoshis.
pub const COIN: u64 = 100_000_000;
