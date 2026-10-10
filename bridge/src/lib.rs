//! Phone-side glue for ZFlip, linked into the iOS app as a static library.
//!
//! The Zcash SDK builds a PCZT; [`sign_request`] turns it into the compact request
//! the Flipper checks and signs, and [`apply_signatures`] puts the device's spend
//! authorization signatures back into the PCZT for the SDK to finish. Nothing here
//! is trusted by the device: it re-checks everything it is told.

use orchard::{
    keys::{FullViewingKey, Scope},
    primitives::redpallas::{self, SpendAuth},
};
use pasta_curves::group::ff::PrimeField;
use pczt::{
    Pczt,
    roles::{
        signer::Signer,
        verifier::{OrchardError, Verifier},
    },
};
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::PoolType;
use zflip_core::request::{self, Owner, SignRequest, SpendSignature};

pub mod ffi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Pczt(String),
    Ufvk,
    /// ZFlip only signs shielded Orchard/Ironwood transactions.
    Unsupported(&'static str),
    Signature(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Pczt(e) => write!(f, "invalid PCZT: {e}"),
            Error::Ufvk => write!(f, "invalid viewing key"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
            Error::Signature(e) => write!(f, "signature rejected: {e}"),
        }
    }
}

/// The Orchard full viewing key inside a UFVK string.
pub fn orchard_fvk(ufvk: &str) -> Result<FullViewingKey, Error> {
    let (_, ufvk) = unified::Ufvk::decode(ufvk).map_err(|_| Error::Ufvk)?;
    ufvk.items()
        .into_iter()
        .find_map(|item| match item {
            unified::Fvk::Orchard(bytes) => FullViewingKey::from_bytes(&bytes),
            _ => None,
        })
        .ok_or(Error::Ufvk)
}

/// The Orchard-only unified address at diversifier index `index` of a UFVK: the
/// same "Address #index" the Flipper shows.
pub fn address(ufvk: &str, index: u32) -> Result<String, Error> {
    let (network, _) = unified::Ufvk::decode(ufvk).map_err(|_| Error::Ufvk)?;
    let network = match network {
        zcash_protocol::consensus::NetworkType::Main => zflip_core::Network::Main,
        zcash_protocol::consensus::NetworkType::Test => zflip_core::Network::Test,
        _ => return Err(Error::Unsupported("regtest")),
    };
    let fvk = orchard_fvk(ufvk)?;
    let addr = fvk.address_at(index, Scope::External);
    Ok(zflip_core::ua::encode_orchard_address(network, &addr.to_raw_address_bytes()))
}

/// Builds the device request for `pczt_bytes` (before or after proving). `ufvk` is
/// the wallet's viewing key, used to tell the device which outputs are its own.
pub fn sign_request(pczt_bytes: &[u8], ufvk: &str) -> Result<SignRequest, Error> {
    let fvk = orchard_fvk(ufvk)?;
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| Error::Pczt(format!("{e:?}")))?;
    if pczt.has_data_in_pool(PoolType::TRANSPARENT) {
        return Err(Error::Unsupported("transparent inputs or outputs"));
    }
    if pczt.has_data_in_pool(PoolType::SAPLING) {
        return Err(Error::Unsupported("Sapling"));
    }
    let global = pczt.global().clone();
    let lock_time = pczt::common::determine_lock_time(&global, pczt.transparent().inputs())
        .ok_or(Error::Pczt("incompatible lock times".into()))?;

    let mut bundles = Vec::new();
    let mut failure = None;
    let mut collect = |b: &orchard::pczt::Bundle| match convert_bundle(b, &fvk) {
        Ok(Some(bundle)) => bundles.push(bundle),
        Ok(None) => {}
        Err(e) => failure = Some(e),
    };
    Verifier::new(pczt)
        .with_orchard::<(), _>(|b| {
            collect(b);
            Ok(())
        })
        .map_err(verify_error)?
        .with_ironwood::<(), _>(|b| {
            collect(b);
            Ok(())
        })
        .map_err(verify_error)?;
    if let Some(e) = failure {
        return Err(e);
    }

    Ok(SignRequest {
        tx_version: *global.tx_version(),
        version_group_id: *global.version_group_id(),
        branch_id: *global.consensus_branch_id(),
        lock_time,
        expiry_height: *global.expiry_height(),
        bundles,
    })
}

fn verify_error(e: OrchardError<()>) -> Error {
    Error::Pczt(format!("{e:?}"))
}

fn convert_bundle(
    b: &orchard::pczt::Bundle,
    fvk: &FullViewingKey,
) -> Result<Option<request::Bundle>, Error> {
    // The effecting data exactly as the transaction (and the sighash) commits to it.
    let Some(effects) = b
        .extract_effects::<i64>()
        .map_err(|e| Error::Pczt(format!("{e:?}")))?
    else {
        return Ok(None);
    };
    let version = request::bundle_version_id(effects.bundle_version())
        .ok_or(Error::Unsupported("Orchard bundle version"))?;

    let mut actions = Vec::with_capacity(b.actions().len());
    for (action, effect) in b.actions().iter().zip(effects.actions().iter()) {
        let spend = action.spend();
        let output = action.output();
        let missing = |what: &str| Error::Pczt(format!("missing {what}"));
        let recipient = output.recipient().ok_or_else(|| missing("output recipient"))?;
        let note = effect.encrypted_note();
        actions.push(request::Action {
            cv_net: effect.cv_net().to_bytes(),
            nullifier: effect.nullifier().to_bytes(),
            rk: effect.rk().into(),
            cmx: effect.cmx().to_bytes(),
            epk: note.epk_bytes,
            enc_ciphertext: note.enc_ciphertext.to_vec(),
            out_ciphertext: note.out_ciphertext,
            rcv: action.rcv().clone().ok_or_else(|| missing("rcv"))?.to_bytes(),
            spend_value: spend.value().ok_or_else(|| missing("spend value"))?.inner(),
            alpha: spend.alpha().ok_or_else(|| missing("alpha"))?.to_repr(),
            output_recipient: recipient.to_raw_address_bytes(),
            output_value: output.value().ok_or_else(|| missing("output value"))?.inner(),
            output_rseed: *output.rseed().ok_or_else(|| missing("output rseed"))?.as_bytes(),
            owner: owner_of(fvk, &recipient),
            user_address: output.user_address().clone().unwrap_or_default(),
        });
    }

    Ok(Some(request::Bundle {
        version,
        flags: effects
            .flags()
            .to_byte(effects.bundle_version())
            .ok_or(Error::Unsupported("Orchard flags"))?,
        value_balance: *effects.value_balance(),
        anchor: effects.anchor().to_bytes(),
        actions,
    }))
}

/// Whether an output pays this wallet, and at which diversifier index.
fn owner_of(fvk: &FullViewingKey, addr: &orchard::Address) -> Owner {
    let Some(scope) = fvk.scope_for_address(addr) else {
        return Owner::Other;
    };
    let Some(index) = fvk.to_ivk(scope).diversifier_index(addr) else {
        return Owner::Other;
    };
    let Ok(j) = u32::try_from(index) else {
        return Owner::Other;
    };
    match scope {
        Scope::External => Owner::External(j),
        Scope::Internal => Owner::Internal(j),
    }
}

/// Applies the device's signatures to the PCZT (each is checked against the spend's
/// randomized key and the PCZT's own sighash) and returns the signed PCZT.
pub fn apply_signatures(pczt_bytes: &[u8], sigs: &[SpendSignature]) -> Result<Vec<u8>, Error> {
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| Error::Pczt(format!("{e:?}")))?;
    let mut signer = Signer::new(pczt).map_err(|e| Error::Pczt(format!("{e:?}")))?;
    for s in sigs {
        let sig = redpallas::Signature::<SpendAuth>::from(s.signature);
        let index = s.action_index as usize;
        let result = if s.ironwood {
            signer.apply_ironwood_signature(index, sig)
        } else {
            signer.apply_orchard_signature(index, sig)
        };
        result.map_err(|e| Error::Signature(format!("{e:?}")))?;
    }
    signer
        .finish()
        .serialize()
        .map_err(|e| Error::Pczt(format!("{e:?}")))
}
