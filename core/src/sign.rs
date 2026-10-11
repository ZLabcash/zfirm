//! Reviewing and signing on the device.
//!
//! The phone is untrusted. Before anything is shown, [`review`] checks every value
//! it displays against the commitments that the transaction (and so the sighash)
//! commits to:
//!
//! - each action's value commitment opens to its declared spend and output values,
//! - each output's note commitment opens to its declared recipient and value,
//! - each bundle's value balance is the sum of its actions' values,
//! - an output the phone calls change (or a self-payment) re-derives to this
//!   wallet's own address, and an address typed by the user contains the receiver
//!   actually paid,
//! - every non-zero spend is authorized by this wallet's key,
//! - each non-zero output's encrypted note decrypts, with the key its recipient will
//!   use, to exactly that note (so a phone cannot send a payment, or our own change,
//!   that its recipient can never find), and its memo is the one shown.
//!
//! A phone that lies about a spent note's value cannot make the device sign it: the
//! output values are fixed by their note commitments and the value commitment fixes
//! the difference, so the spend value is fixed too (and the proof binds it to the
//! real note). [`sign`] then computes the ZIP 244 shielded sighash itself — the txid
//! digest, since there are no transparent inputs — and signs this wallet's spends.
//! Transparent and Sapling parts are never hashed as anything but empty, so a
//! request hiding them yields signatures that the network rejects.

use alloc::{string::String, vec::Vec};

use blake2b_simd::{Hash as Blake2bHash, Params};
use nonempty::NonEmpty;
use orchard::{
    Action as OrchardAction, Address, Anchor, Note, ValuePool,
    bundle::{EffectsOnly, Flags, TxVersion, commitments::hash_bundle_txid_empty},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendValidatingKey},
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext},
    note_encryption::OrchardDomain,
    primitives::redpallas::{self, SpendAuth},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use pasta_curves::{group::ff::PrimeField, pallas};
use rand_core::{CryptoRng, RngCore};
use zcash_note_encryption::Domain;
use crate::{
    Network,
    request::{self, Owner, SignRequest, SpendSignature},
    ua,
};

/// What signing needs from a wallet: implemented by the full [`crate::Account`] and
/// by the signing app's [`crate::account::SigningKey`].
pub trait Wallet {
    fn network(&self) -> Network;
    fn fvk(&self) -> &FullViewingKey;
    fn ask(&self) -> SpendAuthorizingKey;
    /// Whether `addr` is this wallet's address at the position `owner` claims:
    /// `Some(true)` yes, `Some(false)` no, `None` if the wallet cannot tell.
    fn owns(&self, owner: Owner, addr: &Address) -> Option<bool>;
}

const V5_TX_VERSION: u32 = 5;
const V6_TX_VERSION: u32 = 6;
const OVERWINTERED_FLAG: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Malformed request.
    Parse,
    /// Only v5 and v6 transactions carry Orchard or Ironwood bundles.
    UnsupportedTxVersion,
    /// A commitment does not open to the data that would be shown.
    Verification,
    /// A non-zero spend is not authorized by this wallet.
    NotMine,
    /// The typed recipient address does not contain the receiver paid.
    AddressMismatch,
    /// Amounts overflow or outputs exceed spends.
    ValueOverflow,
    /// Nothing for this wallet to sign.
    NothingToSign,
}

impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Error::Parse => "Unreadable transaction",
            Error::UnsupportedTxVersion => "Unsupported tx version",
            Error::Verification => "Transaction does not verify",
            Error::NotMine => "Spends another wallet's funds",
            Error::AddressMismatch => "Recipient address mismatch",
            Error::ValueOverflow => "Invalid amounts",
            Error::NothingToSign => "Nothing to sign",
        }
    }
}

/// A recipient outside this wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    pub address: String,
    pub value: u64,
    pub ironwood: bool,
    /// The memo's text, `None` when the memo is empty.
    pub memo: Option<String>,
}

/// Everything the user confirms before signing. Amounts are in zatoshis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Review {
    pub payments: Vec<Payment>,
    /// Paid to one of this wallet's own receiving addresses.
    pub to_self: u64,
    /// Change returning to this wallet.
    pub change: u64,
    /// Total of this wallet's notes being spent.
    pub spent: u64,
    pub fee: u64,
    pub expiry_height: u32,
    /// Number of spend authorizations the device will produce.
    pub spends: usize,
}

impl Review {
    /// Total leaving the wallet: payments plus fee.
    pub fn total_out(&self) -> u64 {
        self.payments.iter().map(|p| p.value).sum::<u64>() + self.fee
    }

    /// Pages to show: each payment, then its memo if it has one, then the confirmation.
    pub fn pages(&self) -> u8 {
        let pages: usize = self.payments.iter().map(|p| 1 + p.memo.is_some() as usize).sum();
        (pages + 1).min(u8::MAX as usize) as u8
    }

    /// The payment on `page` and whether it is its memo page; `None` for the confirmation.
    pub fn page(&self, page: u8) -> Option<(usize, bool)> {
        let mut n = 0;
        for (i, p) in self.payments.iter().enumerate() {
            if n == page {
                return Some((i, false));
            }
            n += 1;
            if p.memo.is_some() {
                if n == page {
                    return Some((i, true));
                }
                n += 1;
            }
        }
        None
    }
}

/// Checks `req` and returns what the user must confirm.
pub fn review(req: &SignRequest, account: &impl Wallet) -> Result<Review, Error> {
    tx_version(req)?;
    let ak = SpendValidatingKey::from(account.fvk().clone());
    let mut review = Review {
        expiry_height: req.expiry_height,
        ..Review::default()
    };
    let mut fee: i128 = 0;

    // Spend authorizations first, so a request for another wallet is always reported
    // as such, whatever the (shuffled) order of its actions.
    for action in req.bundles.iter().flat_map(|b| &b.actions) {
        if action.spend_value > 0 {
            let alpha = scalar(&action.alpha)?;
            let rk: [u8; 32] = (&ak.randomize(&alpha)).into();
            if rk != action.rk {
                return Err(Error::NotMine);
            }
            review.spent = review.spent.checked_add(action.spend_value).ok_or(Error::ValueOverflow)?;
            review.spends += 1;
        }
    }

    for bundle in &req.bundles {
        let bundle_version = request::bundle_version(bundle.version).ok_or(Error::Parse)?;
        let note_version = bundle_version.note_version();
        let mut balance: i128 = 0;

        for action in &bundle.actions {
            // Value commitment.
            let rcv = Option::from(ValueCommitTrapdoor::from_bytes(action.rcv)).ok_or(Error::Parse)?;
            let net = NoteValue::from_raw(action.spend_value) - NoteValue::from_raw(action.output_value);
            if ValueCommitment::derive(net, rcv).to_bytes() != action.cv_net {
                return Err(Error::Verification);
            }
            balance += action.spend_value as i128 - action.output_value as i128;

            // Note commitment.
            let recipient = Option::from(Address::from_raw_address_bytes(&action.output_recipient))
                .ok_or(Error::Parse)?;
            // ρ of an output note is the nullifier of the action's spent note.
            let rho = Option::from(Rho::from_bytes(&action.nullifier)).ok_or(Error::Parse)?;
            let rseed = Option::from(RandomSeed::from_bytes(action.output_rseed, &rho)).ok_or(Error::Parse)?;
            let note: Note = Option::from(Note::from_parts(
                recipient,
                NoteValue::from_raw(action.output_value),
                rho,
                rseed,
                note_version,
            ))
            .ok_or(Error::Parse)?;
            if ExtractedNoteCommitment::from(note.commitment()).to_bytes() != action.cmx {
                return Err(Error::Verification);
            }
            // Dummy outputs carry nothing; every other one must reach its recipient.
            let memo = if action.output_value > 0 {
                memo_text(&check_ciphertext(action, &note)?)
            } else {
                None
            };

            // Whose output is it?
            let value = action.output_value;
            let slot = match (action.owner, account.owns(action.owner, &recipient)) {
                (Owner::External(_), Some(true)) => &mut review.to_self,
                (Owner::Internal(_), Some(true)) => &mut review.change,
                (Owner::External(_) | Owner::Internal(_), Some(false)) => return Err(Error::Verification),
                (Owner::Other, _) if value == 0 => continue,
                _ => {
                    review.payments.push(Payment {
                        address: display_address(account, &action.user_address, &recipient)?,
                        value,
                        ironwood: bundle.is_ironwood(),
                        memo,
                    });
                    continue;
                }
            };
            *slot = slot.checked_add(value).ok_or(Error::ValueOverflow)?;
        }

        if balance != bundle.value_balance as i128 {
            return Err(Error::Verification);
        }
        fee += balance;
    }

    review.fee = u64::try_from(fee).map_err(|_| Error::ValueOverflow)?;
    let paid = review
        .payments
        .iter()
        .try_fold(review.to_self + review.change, |acc, p| acc.checked_add(p.value))
        .ok_or(Error::ValueOverflow)?;
    if paid.checked_add(review.fee) != Some(review.spent) {
        return Err(Error::ValueOverflow);
    }
    if review.spends == 0 {
        return Err(Error::NothingToSign);
    }
    Ok(review)
}

/// Reviews then signs (host tools and tests). On the device, call [`review`],
/// show the result, and call [`sign_reviewed`] once the user confirmed.
pub fn sign<R: RngCore + CryptoRng>(
    req: &SignRequest,
    account: &impl Wallet,
    rng: R,
) -> Result<Vec<SpendSignature>, Error> {
    review(req, account)?;
    sign_reviewed(req, account, rng)
}

/// Signs this wallet's spends in a request that [`review`] accepted and the user
/// confirmed. Skips the review's commitment checks, which are the slow part.
pub fn sign_reviewed<R: RngCore + CryptoRng>(
    req: &SignRequest,
    account: &impl Wallet,
    mut rng: R,
) -> Result<Vec<SpendSignature>, Error> {
    let sighash = shielded_sighash(req)?;
    let ask = account.ask();
    let mut sigs = Vec::new();
    for bundle in &req.bundles {
        for (i, action) in bundle.actions.iter().enumerate() {
            if action.spend_value == 0 {
                continue;
            }
            let rsk = ask.randomize(&scalar(&action.alpha)?);
            let sig: redpallas::Signature<SpendAuth> = rsk.sign(&mut rng, &sighash);
            sigs.push(SpendSignature {
                ironwood: bundle.is_ironwood(),
                action_index: i as u16,
                signature: (&sig).into(),
            });
        }
    }
    if sigs.is_empty() {
        return Err(Error::NothingToSign);
    }
    Ok(sigs)
}

/// Decrypts the action's output with the key its recipient derives (from the note's
/// own `esk`, as the sender) and checks it holds exactly `note`: the ephemeral key
/// and the plaintext. Returns the memo.
///
/// The same check as `try_output_recovery_with_pkd_esk`, minus the note commitment
/// it recomputes (the review already did) and with one code path for both note
/// versions (only the plaintext's lead byte differs, and `note` carries it): the
/// generic route cost the Flipper app ~2 KiB of RAM, which it does not have.
fn check_ciphertext(action: &request::Action, note: &Note) -> Result<[u8; 512], Error> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
    use zcash_note_encryption::{EphemeralKeyBytes, NOTE_PLAINTEXT_SIZE};

    let esk = OrchardDomain::derive_esk(note).ok_or(Error::Verification)?;
    let epk = OrchardDomain::epk_bytes(&OrchardDomain::ka_derive_public(note, &esk));
    if epk.0 != action.epk {
        return Err(Error::Verification);
    }
    let secret = OrchardDomain::ka_agree_enc(&esk, &OrchardDomain::get_pk_d(note));
    let key = OrchardDomain::kdf(secret, &EphemeralKeyBytes(action.epk));

    let enc = action.enc_ciphertext.as_slice();
    if enc.len() != NOTE_PLAINTEXT_SIZE + 16 {
        return Err(Error::Parse);
    }
    let mut plaintext = [0u8; NOTE_PLAINTEXT_SIZE];
    plaintext.copy_from_slice(&enc[..NOTE_PLAINTEXT_SIZE]);
    ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt_in_place_detached(&[0u8; 12].into(), &[], &mut plaintext, enc[NOTE_PLAINTEXT_SIZE..].into())
        .map_err(|_| Error::Verification)?;
    // Lead byte, diversifier, value and rseed: the note's own (the memo is not ours to know).
    let expected = OrchardDomain::note_plaintext_bytes(note, &[0u8; 512]);
    if plaintext[..52] != expected.0[..52] {
        return Err(Error::Verification);
    }
    let mut memo = [0u8; 512];
    memo.copy_from_slice(&plaintext[52..]);
    Ok(memo)
}

/// A memo as text (ZIP 302): `None` if empty, a marker if it is not text.
fn memo_text(memo: &[u8; 512]) -> Option<String> {
    match memo[0] {
        0xF6 if memo[1..].iter().all(|&b| b == 0) => None,
        0..=0xF4 => {
            let end = memo.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            Some(match core::str::from_utf8(&memo[..end]) {
                Ok(text) => String::from(text),
                Err(_) => String::from("[unreadable memo]"),
            })
        }
        _ => Some(String::from("[binary memo]")),
    }
}

fn scalar(bytes: &[u8; 32]) -> Result<pallas::Scalar, Error> {
    Option::from(pallas::Scalar::from_repr(*bytes)).ok_or(Error::Parse)
}

fn tx_version(req: &SignRequest) -> Result<TxVersion, Error> {
    let v = match req.tx_version {
        V5_TX_VERSION => TxVersion::V5,
        V6_TX_VERSION => TxVersion::V6,
        _ => return Err(Error::UnsupportedTxVersion),
    };
    let orchard = req.bundles.iter().filter(|b| !b.is_ironwood()).count();
    let ironwood = req.bundles.iter().filter(|b| b.is_ironwood()).count();
    if orchard > 1 || ironwood > 1 || (ironwood > 0 && v == TxVersion::V5) {
        return Err(Error::Parse);
    }
    Ok(v)
}

/// The address to show for an external recipient: the text the sender typed, if it
/// decodes to a unified address on our network whose Orchard receiver is the one
/// paid; otherwise the Orchard-only encoding of the receiver.
fn display_address(account: &impl Wallet, typed: &str, recipient: &Address) -> Result<String, Error> {
    let raw = recipient.to_raw_address_bytes();
    if typed.is_empty() {
        return Ok(ua::encode_orchard_address(account.network(), &raw));
    }
    if ua::orchard_receiver(account.network(), typed) == Some(raw) {
        Ok(String::from(typed))
    } else {
        Err(Error::AddressMismatch)
    }
}

/// The transaction's id, as explorers show it. A request has no transparent part, so
/// its signature digest is the txid digest (ZIP 244), shown byte-reversed.
pub fn txid(req: &SignRequest) -> Result<[u8; 32], Error> {
    let mut id = shielded_sighash(req)?;
    id.reverse();
    Ok(id)
}

/// The ZIP 244 signature digest for shielded spends. Without transparent inputs it
/// equals the txid digest, with empty transparent and Sapling digests.
pub fn shielded_sighash(req: &SignRequest) -> Result<[u8; 32], Error> {
    let tx_version = tx_version(req)?;
    let pool_digest = |pool: ValuePool| -> Result<Blake2bHash, Error> {
        match req
            .bundles
            .iter()
            .find(|b| b.is_ironwood() == (pool == ValuePool::Ironwood))
        {
            Some(b) => bundle_digest(b, tx_version),
            None => hash_bundle_txid_empty(pool, tx_version).map_err(|_| Error::UnsupportedTxVersion),
        }
    };

    let mut header = hasher(b"ZTxIdHeadersHash");
    header.update(&(req.tx_version | OVERWINTERED_FLAG).to_le_bytes());
    header.update(&req.version_group_id.to_le_bytes());
    header.update(&req.branch_id.to_le_bytes());
    header.update(&req.lock_time.to_le_bytes());
    header.update(&req.expiry_height.to_le_bytes());

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..].copy_from_slice(&req.branch_id.to_le_bytes());
    let mut h = hasher(&personal);
    h.update(header.finalize().as_bytes());
    h.update(hasher(b"ZTxIdTranspaHash").finalize().as_bytes());
    h.update(hasher(b"ZTxIdSaplingHash").finalize().as_bytes());
    h.update(pool_digest(ValuePool::Orchard)?.as_bytes());
    if tx_version == TxVersion::V6 {
        h.update(pool_digest(ValuePool::Ironwood)?.as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Ok(out)
}

/// Rebuilds the bundle's effecting data and lets Orchard compute its txid digest.
fn bundle_digest(b: &request::Bundle, tx_version: TxVersion) -> Result<Blake2bHash, Error> {
    let bundle_version = request::bundle_version(b.version).ok_or(Error::Parse)?;
    let mut actions = Vec::with_capacity(b.actions.len());
    for a in &b.actions {
        let enc_ciphertext: [u8; request::ENC_CIPHERTEXT_SIZE] =
            a.enc_ciphertext.as_slice().try_into().map_err(|_| Error::Parse)?;
        actions.push(
            OrchardAction::from_parts(
                Option::from(Nullifier::from_bytes(&a.nullifier)).ok_or(Error::Parse)?,
                redpallas::VerificationKey::try_from(a.rk).map_err(|_| Error::Parse)?,
                Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or(Error::Parse)?,
                TransmittedNoteCiphertext {
                    epk_bytes: a.epk,
                    enc_ciphertext,
                    out_ciphertext: a.out_ciphertext,
                },
                Option::from(ValueCommitment::from_bytes(&a.cv_net)).ok_or(Error::Parse)?,
                (),
            )
            .map_err(|_| Error::Parse)?,
        );
    }
    let actions = NonEmpty::from_vec(actions).ok_or(Error::Parse)?;
    let bundle = orchard::Bundle::<EffectsOnly, i64>::from_parts(
        actions,
        Flags::from_byte(b.flags, bundle_version).ok_or(Error::Parse)?,
        b.value_balance,
        Option::from(Anchor::from_bytes(b.anchor)).ok_or(Error::Parse)?,
        EffectsOnly,
        bundle_version,
    )
    .map_err(|_| Error::Parse)?;
    bundle
        .commitment(tx_version)
        .map(|c| c.0)
        .map_err(|_| Error::UnsupportedTxVersion)
}

fn hasher(personal: &[u8; 16]) -> blake2b_simd::State {
    Params::new().hash_length(32).personal(personal).to_state()
}
