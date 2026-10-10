//! End to end: a real PCZT from librustzcash goes through the phone bridge, is
//! checked and signed by the device code, and the signatures are put back and
//! extracted into a fully authorized transaction.

use std::sync::OnceLock;

use incrementalmerkletree::Retention;
use orchard::{
    keys::{FullViewingKey, Scope},
    tree::{MerklePath, MerkleHashOrchard},
    value::NoteValue,
};
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover, redactor::Redactor,
        signer::Signer, tx_extractor::TransactionExtractor, updater::Updater,
    },
};
use rand_core::OsRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::BlockHeight,
    local_consensus::LocalNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zflip_bridge::{apply_signatures, sign_request};
use zflip_core::{
    Account, Network,
    request::{self, Owner, SignRequest},
    sign::{self, Error},
};

#[derive(Clone, Copy, PartialEq)]
enum Pool {
    /// Orchard in a v5 transaction, before NU6.3.
    Orchard,
    /// Ironwood in a v6 transaction, after NU6.3.
    Ironwood,
}

fn network(pool: Pool) -> LocalNetwork {
    let h = |n| Some(BlockHeight::from_u32(n));
    LocalNetwork {
        overwinter: h(1),
        sapling: h(2),
        blossom: h(3),
        heartwood: h(4),
        canopy: h(5),
        nu5: h(6),
        nu6: h(7),
        nu6_1: h(8),
        nu6_2: h(9),
        nu6_3: (pool == Pool::Ironwood).then(|| BlockHeight::from_u32(10)),
    }
}

fn account(seed_byte: u8) -> Account {
    Account::from_seed(&[seed_byte; 32], Network::Test, 0).unwrap()
}

/// A note of `value` received by `fvk`, alone in a fresh tree.
fn received_note(
    fvk: &FullViewingKey,
    pool: Pool,
    value: u64,
) -> (orchard::Note, orchard::Anchor, MerklePath) {
    let version = match pool {
        Pool::Orchard => orchard::bundle::BundleVersion::orchard_v2(),
        Pool::Ironwood => orchard::bundle::BundleVersion::ironwood_v3(),
    };
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(value),
            Memo::Empty.encode().into_bytes(),
        )
        .unwrap();
    let (bundle, meta) = builder.build::<i64>(&mut OsRng).unwrap().unwrap();
    let action = bundle
        .actions()
        .get(meta.output_action_index(0).unwrap())
        .unwrap();
    let ivk = fvk.to_ivk(Scope::External).prepare();
    let note = match pool {
        Pool::Orchard => {
            let domain = orchard::note_encryption::OrchardDomain::for_action(action);
            try_note_decryption(&domain, &ivk, action).unwrap().0
        }
        Pool::Ironwood => {
            let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
            try_note_decryption(&domain, &ivk, action).unwrap().0
        }
    };

    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    tree.append(leaf, Retention::Marked).unwrap();
    tree.checkpoint(9_999_999).unwrap();
    let path = tree
        .witness_at_checkpoint_depth(0.into(), 0)
        .unwrap()
        .unwrap();
    let anchor = path.root(leaf);
    (note, anchor.into(), path.into())
}

/// `from` spends a 1 ZEC note, pays `amount` to `to` and keeps the change.
fn payment_pczt(from: &Account, to: orchard::Address, amount: u64, pool: Pool) -> Pczt {
    let fvk = from.fvk().clone();
    let (note, anchor, path) = received_note(&fvk, pool, 100_000_000);
    let (orchard_anchor, ironwood_anchor) = match pool {
        Pool::Orchard => (Some(anchor), None),
        Pool::Ironwood => (None, Some(anchor)),
    };
    let mut builder = Builder::new(
        network(pool),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor,
            ironwood_anchor,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    let ovk = Some(fvk.to_ovk(Scope::External));
    let change_ovk = Some(fvk.to_ovk(Scope::Internal));
    let change_addr = fvk.address_at(0u32, Scope::Internal);
    let fee = 10_000;
    let change = Zatoshis::const_from_u64(100_000_000 - amount - fee);
    let amount = Zatoshis::const_from_u64(amount);
    match pool {
        Pool::Orchard => {
            builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, path).unwrap();
            builder
                .add_orchard_output::<zip317::FeeRule>(ovk, to, amount, MemoBytes::empty())
                .unwrap();
            builder
                .add_orchard_output::<zip317::FeeRule>(change_ovk, change_addr, change, MemoBytes::empty())
                .unwrap();
        }
        Pool::Ironwood => {
            builder.add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, path).unwrap();
            builder
                .add_ironwood_output::<zip317::FeeRule>(ovk, to, amount, MemoBytes::empty())
                .unwrap();
            builder
                .add_ironwood_output::<zip317::FeeRule>(change_ovk, change_addr, change, MemoBytes::empty())
                .unwrap();
        }
    }
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap()
}


/// What the iOS SDK's `redactPCZTForSigner` leaves: no proof, witnesses or wire FVKs.
fn redact_for_signer(pczt: Pczt) -> Pczt {
    let redact = |mut r: pczt::roles::redactor::orchard::OrchardRedactor<'_>| {
        r.clear_zkproof();
        r.redact_actions(|mut a| {
            a.clear_spend_fvk();
            a.clear_spend_witness();
        });
    };
    Redactor::new(pczt)
        .redact_orchard_with(redact)
        .redact_ironwood_with(redact)
        .finish()
}

fn bytes(pczt: &Pczt) -> Vec<u8> {
    pczt.clone().serialize().unwrap()
}

/// What the phone sends the device for this PCZT (through the wire encoding).
fn request_for(pczt: &Pczt, wallet: &Account) -> SignRequest {
    let req = sign_request(&bytes(&redact_for_signer(pczt.clone())), &wallet.ufvk()).unwrap();
    let decoded = SignRequest::decode(&req.encode()).unwrap();
    assert_eq!(decoded, req);
    decoded
}

fn proving_key(pool: Pool) -> &'static orchard::circuit::ProvingKey {
    static PRE: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
    static POST: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
    match pool {
        Pool::Orchard => PRE.get_or_init(|| {
            orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2)
        }),
        Pool::Ironwood => POST.get_or_init(|| {
            orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
        }),
    }
}

const POOLS: [Pool; 2] = [Pool::Orchard, Pool::Ironwood];

#[test]
fn device_sighash_matches_librustzcash() {
    for pool in POOLS {
        let alice = account(1);
        let pczt = payment_pczt(&alice, account(2).address(0), 25_000_000, pool);
        let expected = Signer::new(pczt.clone()).unwrap().shielded_sighash();
        assert_eq!(sign::shielded_sighash(&request_for(&pczt, &alice)).unwrap(), expected);
    }
}

#[test]
fn review_shows_payment_change_and_fee() {
    for pool in POOLS {
        let alice = account(1);
        let bob = account(2);
        let pczt = payment_pczt(&alice, bob.address(3), 25_000_000, pool);
        let review = sign::review(&request_for(&pczt, &alice), &alice).unwrap();
        assert_eq!(review.payments.len(), 1);
        assert_eq!(review.payments[0].value, 25_000_000);
        assert_eq!(review.payments[0].address, bob.encode_address(3));
        assert_eq!(review.payments[0].ironwood, pool == Pool::Ironwood);
        assert_eq!(review.spent, 100_000_000);
        assert_eq!(review.change, 100_000_000 - 25_000_000 - 10_000);
        assert_eq!(review.to_self, 0);
        assert_eq!(review.fee, 10_000);
        assert_eq!(review.spends, 1);
        assert_eq!(review.total_out(), 25_010_000);
    }
}

#[test]
fn signed_pczt_extracts_to_a_valid_transaction() {
    for pool in POOLS {
        let alice = account(1);
        let pczt = payment_pczt(&alice, account(2).address(0), 25_000_000, pool);
        let req = request_for(&pczt, &alice);
        let sigs = sign::sign(&req, &alice, OsRng).unwrap();
        assert_eq!(sigs.len(), 1);
        let sigs = request::decode_signatures(&request::encode_signatures(&sigs)).unwrap();

        // The phone applies the signatures to its unredacted PCZT, proves, extracts.
        let signed = apply_signatures(&bytes(&pczt), &sigs).unwrap();
        let signed = Pczt::parse(&signed).unwrap();
        let proven = match pool {
            Pool::Orchard => Prover::new(signed).create_orchard_proof(proving_key(pool)).unwrap(),
            Pool::Ironwood => Prover::new(signed).create_ironwood_proof(proving_key(pool)).unwrap(),
        }
        .finish();
        let tx = TransactionExtractor::new(proven).extract().unwrap();
        assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
    }
}

#[test]
fn foreign_spends_are_refused() {
    let alice = account(1);
    let mallory = account(9);
    let pczt = payment_pczt(&alice, mallory.address(0), 25_000_000, Pool::Ironwood);
    let req = request_for(&pczt, &alice);
    assert_eq!(sign::review(&req, &mallory), Err(Error::NotMine));
    assert_eq!(sign::sign(&req, &mallory, OsRng).unwrap_err(), Error::NotMine);
}

fn payment_action(req: &mut SignRequest) -> &mut request::Action {
    req.bundles[0]
        .actions
        .iter_mut()
        .find(|a| a.owner == Owner::Other && a.output_value > 0)
        .unwrap()
}

#[test]
fn a_lying_phone_is_caught() {
    let alice = account(1);
    let bob = account(2);
    let mallory = account(3);
    let pczt = payment_pczt(&alice, bob.address(0), 25_000_000, Pool::Ironwood);
    let honest = request_for(&pczt, &alice);
    assert!(sign::review(&honest, &alice).is_ok());

    // Shows a smaller amount than is really paid.
    let mut req = honest.clone();
    payment_action(&mut req).output_value = 1_000_000;
    assert_eq!(sign::review(&req, &alice), Err(Error::Verification));

    // Shows a different recipient than the one really paid.
    let mut req = honest.clone();
    payment_action(&mut req).output_recipient = mallory.address(0).to_raw_address_bytes();
    assert_eq!(sign::review(&req, &alice), Err(Error::Verification));

    // Calls the payment "change" to hide it.
    let mut req = honest.clone();
    payment_action(&mut req).owner = Owner::Internal(0);
    assert_eq!(sign::review(&req, &alice), Err(Error::Verification));

    // Shifts value between the spend and the output of an action (the payment's
    // spend is a dummy, so it is now also an unauthorized spend).
    let mut req = honest.clone();
    let a = payment_action(&mut req);
    a.spend_value += 5;
    a.output_value += 5;
    assert!(sign::review(&req, &alice).is_err());
    let mut req = honest.clone();
    let change = req.bundles[0]
        .actions
        .iter_mut()
        .find(|a| matches!(a.owner, Owner::Internal(_)))
        .unwrap();
    change.spend_value += 5;
    change.output_value += 5;
    assert!(sign::review(&req, &alice).is_err());

    // Lies about the fee through the value balance.
    let mut req = honest.clone();
    req.bundles[0].value_balance += 1;
    assert_eq!(sign::review(&req, &alice), Err(Error::Verification));

    // Changes effecting data that only the sighash covers: the signature then fails.
    let mut req = honest.clone();
    req.expiry_height += 1;
    let sigs = sign::sign(&req, &alice, OsRng).unwrap();
    assert!(apply_signatures(&bytes(&pczt), &sigs).is_err());
}

#[test]
fn typed_address_must_contain_the_paid_receiver() {
    let alice = account(1);
    let bob = account(2);
    let pczt = payment_pczt(&alice, bob.address(0), 25_000_000, Pool::Ironwood);
    let bob_index = (0..pczt.ironwood().actions().len())
        .find(|&i| pczt.ironwood().actions()[i].output().value().unwrap_or(0) == 25_000_000)
        .unwrap();
    let with_text = |text: String| {
        let p = Updater::new(pczt.clone())
            .update_ironwood_with(|mut u| {
                u.update_action_with(bob_index, |mut a| {
                    a.set_output_user_address(text);
                    Ok(())
                })
            })
            .unwrap()
            .finish();
        request_for(&p, &alice)
    };
    let ok = sign::review(&with_text(bob.encode_address(0)), &alice).unwrap();
    assert_eq!(ok.payments[0].address, bob.encode_address(0));
    let lie = with_text(account(3).encode_address(0));
    assert_eq!(sign::review(&lie, &alice), Err(Error::AddressMismatch));
}

#[test]
fn paying_yourself_is_not_a_payment() {
    let alice = account(1);
    let pczt = payment_pczt(&alice, alice.address(7), 25_000_000, Pool::Ironwood);
    let review = sign::review(&request_for(&pczt, &alice), &alice).unwrap();
    assert!(review.payments.is_empty());
    assert_eq!(review.to_self, 25_000_000);
    assert_eq!(review.fee, 10_000);
}

#[test]
fn signing_key_reviews_like_the_full_account() {
    use zflip_core::{account::SigningKey, sign::Wallet};
    let alice = account(1);
    let change = alice.address_in(orchard::keys::Scope::Internal, 0).to_raw_address_bytes();
    let key = SigningKey::from_parts(Network::Test, alice.sk_bytes(), alice.seed_fingerprint(), change).unwrap();
    assert_eq!(key.ufvk(), alice.ufvk());
    assert_eq!(key.fvk().to_bytes(), alice.fvk().to_bytes());

    let pczt = payment_pczt(&alice, account(2).address(0), 25_000_000, Pool::Ironwood);
    let req = request_for(&pczt, &alice);
    assert_eq!(sign::review(&req, &key).unwrap(), sign::review(&req, &alice).unwrap());
    let sigs = sign::sign(&req, &key, OsRng).unwrap();
    assert!(apply_signatures(&bytes(&pczt), &sigs).is_ok());

    // A self-payment it cannot verify is shown as a payment, not hidden.
    let pczt = payment_pczt(&alice, alice.address(7), 25_000_000, Pool::Ironwood);
    let review = sign::review(&request_for(&pczt, &alice), &key).unwrap();
    assert_eq!(review.payments.len(), 1);
    assert_eq!(review.payments[0].address, alice.encode_address(7));
}

#[test]
fn bridge_addresses_match_the_device() {
    let alice = account(1);
    for j in [0u32, 1, 9] {
        assert_eq!(zflip_bridge::address(&alice.ufvk(), j).unwrap(), alice.encode_address(j));
    }
}
