//! A ZIP 32 Orchard account derived from the seed. Ironwood (NU6.3) shares Orchard's
//! keys and receivers, so the same account receives and spends in both pools.

use alloc::string::String;

use orchard::keys::{
    Diversifier, FullViewingKey, IncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey,
};
use zip32::{AccountId, fingerprint::SeedFingerprint};

use crate::{Network, ff1, sign::Wallet, request::Owner, ua};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The seed is not 32..=252 bytes, or the account index is out of range.
    InvalidSeed,
}

pub struct Account {
    network: Network,
    index: u32,
    sk: SpendingKey,
    fvk: FullViewingKey,
    external: IncomingViewingKey,
    internal: IncomingViewingKey,
    seed_fp: [u8; 32],
}

impl Account {
    pub fn from_seed(seed: &[u8], network: Network, index: u32) -> Result<Self, Error> {
        let account = AccountId::try_from(index).map_err(|_| Error::InvalidSeed)?;
        let sk = SpendingKey::from_zip32_seed(seed, network.coin_type(), account)
            .map_err(|_| Error::InvalidSeed)?;
        let seed_fp = SeedFingerprint::from_seed(seed).ok_or(Error::InvalidSeed)?;
        let fvk = FullViewingKey::from(&sk);
        Ok(Account {
            network,
            index,
            sk,
            external: fvk.to_ivk(Scope::External),
            internal: fvk.to_ivk(Scope::Internal),
            fvk,
            seed_fp: seed_fp.to_bytes(),
        })
    }

    /// Rebuilds an account from its sealed spending key, skipping the BIP 39 and
    /// ZIP 32 derivation (which validates a key at every level: slow on a Flipper).
    pub fn from_sk(sk: [u8; 32], seed_fp: [u8; 32], network: Network, index: u32) -> Option<Self> {
        let sk = Option::from(SpendingKey::from_bytes(sk))?;
        let fvk = FullViewingKey::from(&sk);
        Some(Account {
            network,
            index,
            sk,
            external: fvk.to_ivk(Scope::External),
            internal: fvk.to_ivk(Scope::Internal),
            fvk,
            seed_fp,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// ZIP 32 account index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// ZIP 32 seed fingerprint: lets the wallet stamp spends with the derivation path
    /// so the device can tell they are its own.
    pub fn seed_fingerprint(&self) -> [u8; 32] {
        self.seed_fp
    }

    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// The spending key bytes, sealed in the vault for the signing app.
    pub fn sk_bytes(&self) -> [u8; 32] {
        *self.sk.to_bytes()
    }

    /// The diversified receiving address at index `j`. Every index pays the same
    /// account and none can be linked to another on chain.
    pub fn address(&self, j: u32) -> orchard::Address {
        self.address_in(Scope::External, j)
    }

    /// The address at diversifier index `j` of either scope (`Internal` is change).
    pub fn address_in(&self, scope: Scope, j: u32) -> orchard::Address {
        let ivk = match scope {
            Scope::External => &self.external,
            Scope::Internal => &self.internal,
        };
        address_at(ivk, j)
    }

    /// The unified address (`u1…`, or `utest1…` on testnet) at diversifier index `j`.
    pub fn encode_address(&self, j: u32) -> String {
        encode_orchard_address(self.network, &self.address(j))
    }

    /// The unified full viewing key (`uview1…`) to import as a watch-only account.
    pub fn ufvk(&self) -> String {
        ua::encode(ua::ufvk_hrp(self.network), ua::ORCHARD, &self.fvk.to_bytes())
    }
}

/// The address at diversifier index `j` for an incoming viewing key.
pub fn address_at(ivk: &IncomingViewingKey, j: u32) -> orchard::Address {
    let ivk_bytes = ivk.to_bytes();
    let dk: [u8; 32] = crate::arr(&ivk_bytes);
    let mut index = [0u8; 11];
    index[..4].copy_from_slice(&j.to_le_bytes());
    ivk.address(Diversifier::from_bytes(ff1::encrypt(&dk, &index)))
}

/// An Orchard-only unified address.
pub fn encode_orchard_address(network: Network, addr: &orchard::Address) -> String {
    ua::encode_orchard_address(network, &addr.to_raw_address_bytes())
}

impl Wallet for Account {
    fn network(&self) -> Network {
        self.network
    }

    fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    fn ask(&self) -> SpendAuthorizingKey {
        SpendAuthorizingKey::from(&self.sk)
    }

    fn owns(&self, owner: Owner, addr: &orchard::Address) -> Option<bool> {
        match owner {
            Owner::Other => Some(false),
            Owner::External(j) => Some(self.address_in(Scope::External, j) == *addr),
            Owner::Internal(j) => Some(self.address_in(Scope::Internal, j) == *addr),
        }
    }
}

/// What the signing app keeps: the spending key and the facts about the wallet it
/// cannot cheaply recompute (diversified addresses need FF1 and the IVKs).
pub struct SigningKey {
    network: Network,
    sk: SpendingKey,
    fvk: FullViewingKey,
    seed_fp: [u8; 32],
    /// The change address at internal index 0, as derived by the wallet app.
    change: [u8; 43],
}

impl SigningKey {
    pub fn from_parts(network: Network, sk: [u8; 32], seed_fp: [u8; 32], change: [u8; 43]) -> Option<Self> {
        let sk = Option::from(SpendingKey::from_bytes(sk))?;
        let fvk = FullViewingKey::from(&sk);
        Some(SigningKey { network, sk, fvk, seed_fp, change })
    }

    pub fn seed_fingerprint(&self) -> [u8; 32] {
        self.seed_fp
    }

    pub fn ufvk(&self) -> String {
        ua::encode(ua::ufvk_hrp(self.network), ua::ORCHARD, &self.fvk.to_bytes())
    }

    /// The external incoming viewing key (slow: a Sinsemilla commitment), for
    /// deriving receiving addresses with [`address_at`].
    pub fn external_ivk(&self) -> IncomingViewingKey {
        self.fvk.to_ivk(Scope::External)
    }
}

impl Wallet for SigningKey {
    fn network(&self) -> Network {
        self.network
    }

    fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    fn ask(&self) -> SpendAuthorizingKey {
        SpendAuthorizingKey::from(&self.sk)
    }

    /// Only the default change address can be checked; any other output the phone
    /// calls ours is shown as a payment instead.
    fn owns(&self, owner: Owner, addr: &orchard::Address) -> Option<bool> {
        match owner {
            Owner::Other => Some(false),
            Owner::Internal(0) => Some(addr.to_raw_address_bytes() == self.change),
            _ => None,
        }
    }
}
