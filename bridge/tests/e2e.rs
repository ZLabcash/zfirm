//! End to end: a real PCZT from librustzcash goes through the phone bridge, is
//! checked and signed by the device code, and the signatures are put back and
//! extracted into a fully authorized transaction.

use std::{str::FromStr, sync::OnceLock};

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
use zfirm_core::{
    protocol::{self, Decoder, Info, msg},
    session::{self, Session, Show},
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
    payment_pczt_with_memo(from, to, amount, pool, MemoBytes::empty())
}

fn payment_pczt_with_memo(from: &Account, to: orchard::Address, amount: u64, pool: Pool, memo: MemoBytes) -> Pczt {
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
                .add_orchard_output::<zip317::FeeRule>(ovk, to, amount, memo.clone())
                .unwrap();
            builder
                .add_orchard_output::<zip317::FeeRule>(change_ovk, change_addr, change, MemoBytes::empty())
                .unwrap();
        }
        Pool::Ironwood => {
            builder.add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, path).unwrap();
            builder
                .add_ironwood_output::<zip317::FeeRule>(ovk, to, amount, memo)
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


/// `from` spends a 1 ZEC note and pays each of `to` in one transaction (a multisend), keeping
/// the change. ZIP 317: one logical action per output here, at least two.
fn multi_payment_pczt(from: &Account, to: &[(orchard::Address, u64)], pool: Pool) -> (Pczt, u64) {
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
    let fee = 5_000 * (to.len() as u64 + 1).max(2);
    let paid: u64 = to.iter().map(|(_, v)| v).sum();
    let change = Zatoshis::const_from_u64(100_000_000 - paid - fee);
    match pool {
        Pool::Orchard => {
            builder.add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, path).unwrap();
            for (addr, v) in to {
                builder.add_orchard_output::<zip317::FeeRule>(ovk.clone(), *addr, Zatoshis::const_from_u64(*v), MemoBytes::empty()).unwrap();
            }
            builder.add_orchard_output::<zip317::FeeRule>(change_ovk, change_addr, change, MemoBytes::empty()).unwrap();
        }
        Pool::Ironwood => {
            builder.add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, path).unwrap();
            for (addr, v) in to {
                builder.add_ironwood_output::<zip317::FeeRule>(ovk.clone(), *addr, Zatoshis::const_from_u64(*v), MemoBytes::empty()).unwrap();
            }
            builder.add_ironwood_output::<zip317::FeeRule>(change_ovk, change_addr, change, MemoBytes::empty()).unwrap();
        }
    }
    let PcztResult { pczt_parts, .. } = builder.build_for_pczt(OsRng, &zip317::FeeRule::standard()).unwrap();
    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap()).finalize_io().unwrap();
    (pczt, fee)
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
fn a_payment_its_recipient_cannot_find_is_caught() {
    let alice = account(1);
    let bob = account(2);
    for pool in [Pool::Orchard, Pool::Ironwood] {
        let pczt = payment_pczt(&alice, bob.address(0), 25_000_000, pool);
        let honest = request_for(&pczt, &alice);
        assert!(sign::review(&honest, &alice).is_ok());

        // The payment's encrypted note is garbled: Bob would never see it.
        let mut req = honest.clone();
        payment_action(&mut req).enc_ciphertext[100] ^= 1;
        assert_eq!(sign::review(&req, &alice), Err(Error::Verification));

        // Same for our own change, which this wallet could then never find again.
        let mut req = honest.clone();
        let change = req.bundles[0]
            .actions
            .iter_mut()
            .find(|a| matches!(a.owner, Owner::Internal(_)))
            .unwrap();
        change.enc_ciphertext[0] ^= 1;
        assert_eq!(sign::review(&req, &alice), Err(Error::Verification));

        // An ephemeral key that is not the note's own.
        let mut req = honest.clone();
        let other = payment_action(&mut req.clone()).epk;
        let change_epk = req.bundles[0]
            .actions
            .iter()
            .find(|a| matches!(a.owner, Owner::Internal(_)))
            .unwrap()
            .epk;
        assert_ne!(other, change_epk);
        payment_action(&mut req).epk = change_epk;
        assert_eq!(sign::review(&req, &alice), Err(Error::Verification));
    }
}

#[test]
fn the_memo_is_shown() {
    let alice = account(1);
    let bob = account(2);
    let memo = MemoBytes::from(Memo::from_str("Merci pour le cafe").unwrap());
    let pczt = payment_pczt_with_memo(&alice, bob.address(0), 25_000_000, Pool::Ironwood, memo);
    let review = sign::review(&request_for(&pczt, &alice), &alice).unwrap();
    assert_eq!(review.payments[0].memo.as_deref(), Some("Merci pour le cafe"));

    let pczt = payment_pczt(&alice, bob.address(0), 25_000_000, Pool::Ironwood);
    let review = sign::review(&request_for(&pczt, &alice), &alice).unwrap();
    assert_eq!(review.payments[0].memo, None);
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
    use zfirm_core::{account::SigningKey, sign::Wallet};
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

#[test]
fn multisend_reviews_every_payment_and_signs_once() {
    let alice = account(1);
    for n in [1usize, 2, 5, 10] {
        let to: Vec<(orchard::Address, u64)> = (0..n).map(|i| (account(20 + i as u8).address(i as u32), 1_000_000 * (i as u64 + 1))).collect();
        let (pczt, fee) = multi_payment_pczt(&alice, &to, Pool::Ironwood);
        let req = request_for(&pczt, &alice);
        let wire = protocol::encode(protocol::msg::SIGN, &req.encode()).len();
        let actions: usize = req.bundles.iter().map(|b| b.actions.len()).sum();
        println!("multisend {n:>2} recipients: {actions:>2} actions, sign request {wire:>6} bytes on the wire");

        let review = sign::review(&req, &alice).unwrap();
        assert_eq!(review.payments.len(), n);
        // The builder shuffles outputs (on purpose): compare as sets.
        let mut got: Vec<(u64, String)> = review.payments.iter().map(|p| (p.value, p.address.clone())).collect();
        let mut want: Vec<(u64, String)> =
            to.iter().map(|(a, v)| (*v, zfirm_core::account::encode_orchard_address(alice.network(), a))).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(review.fee, fee);

        // One spent note: one signature, however many recipients.
        let sigs = sign::sign(&req, &alice, OsRng).unwrap();
        assert_eq!(sigs.len(), 1);
        let signed = Pczt::parse(&apply_signatures(&bytes(&pczt), &sigs).unwrap()).unwrap();
        let proven = Prover::new(signed).create_ironwood_proof(proving_key(Pool::Ironwood)).unwrap().finish();
        TransactionExtractor::new(proven).extract().unwrap();
    }
}

#[test]
fn recovery_phrases_match_bip39_and_zip32() {
    // BIP 39 reference vector, then a fresh phrase round trip.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = zflip_bridge::mnemonic_seed(phrase).unwrap();
    assert_eq!(hex::encode(seed), "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
    assert!(zflip_bridge::mnemonic_seed(&phrase.replace("about", "abandon")).is_err());
    assert!(zflip_bridge::mnemonic_seed("  Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon About ").is_ok());
    let fresh = zflip_bridge::mnemonic_new(&[42u8; 32]);
    assert_eq!(fresh.split(' ').count(), 24);
    let seed = zflip_bridge::mnemonic_seed(&fresh).unwrap();
    let fp = zflip_bridge::seed_fingerprint(&seed).unwrap();
    assert_eq!(fp, zip32::fingerprint::SeedFingerprint::from_seed(&seed).unwrap().to_bytes());
}

/// The phone's side of a [`Session`], with a wallet that is unlocked and shows address #0.
struct Host<'a>(&'a Account);

impl session::Host for Host<'_> {
    fn info(&self) -> Option<Info> {
        Some(Info {
            network: self.0.network().to_byte(),
            account: 0,
            seed_fingerprint: self.0.seed_fingerprint(),
            ufvk: self.0.ufvk(),
            created_at: 0,
            device_name: "test".into(),
            address_index: 0,
        })
    }
    fn address(&self) -> Option<(u32, String)> {
        Some((0, self.0.encode_address(0)))
    }
}

/// Runs the step's work inline and returns every frame sent and everything shown.
fn drive(session: &mut Session, step: session::Step, alice: &Account) -> (Vec<protocol::Frame>, Vec<Show>) {
    let (mut frames, mut shown) = (Vec::new(), Vec::new());
    session::run_inline(session, step, alice, &mut OsRng, |step| {
        for bytes in &step.send {
            frames.push(Decoder::new().push(bytes).unwrap().unwrap());
        }
        shown.extend(step.show.clone());
    });
    (frames, shown)
}

fn frame(kind: u8, payload: &[u8]) -> protocol::Frame {
    Decoder::new().push(&protocol::encode(kind, payload)).unwrap().unwrap()
}

#[test]
fn a_session_pairs_reviews_and_signs() {
    let alice = account(1);
    let host = Host(&alice);
    let mut s = Session::new();

    // Nothing before pairing, and pairing needs the user.
    let (f, _) = send(&mut s, &host, msg::SIGN, &[], &alice);
    assert_eq!(protocol::decode_error(&f[0].payload).unwrap().0, protocol::error::NOT_PAIRED);
    let (f, shown) = send(&mut s, &host, msg::HELLO, &[], &alice);
    assert_eq!((f[0].kind, shown), (msg::STATUS, vec![Show::PairPrompt]));
    let step = s.answer(true, &host);
    let (f, _) = drive(&mut s, step, &alice);
    let info = Info::decode(&f[0].payload).unwrap();
    assert_eq!(info.ufvk, alice.ufvk());
    assert_eq!(protocol::decode_address(&f[1].payload).unwrap().1, alice.encode_address(0));

    // A transaction is checked, shown, and signed only once approved.
    let pczt = payment_pczt(&alice, account(2).address(0), 25_000_000, Pool::Ironwood);
    let req = request_for(&pczt, &alice);
    let (f, shown) = send(&mut s, &host, msg::SIGN, &req.encode(), &alice);
    assert!(f.iter().all(|f| f.kind == msg::STATUS));
    let Some(Show::Review(review)) = shown.last() else { panic!("no review: {shown:?}") };
    assert_eq!(review.payments[0].value, 25_000_000);
    // A second request while one is on screen is turned away.
    let (f, _) = send(&mut s, &host, msg::SIGN, &req.encode(), &alice);
    assert_eq!(protocol::decode_error(&f[0].payload).unwrap().0, protocol::error::BUSY);
    let step = s.answer(true, &host);
    let (f, shown) = drive(&mut s, step, &alice);
    assert_eq!(shown.last(), Some(&Show::Done { ok: true, note: "Signed: phone sends it" }));
    let signed = f.iter().find(|f| f.kind == msg::SIGNED).unwrap();
    let sigs = request::decode_signatures(&signed.payload).unwrap();
    assert!(apply_signatures(&bytes(&pczt), &sigs).is_ok());

    // Refusing sends nothing signed; a dropped link must pair again.
    let (_, _) = send(&mut s, &host, msg::SIGN, &req.encode(), &alice);
    let step = s.answer(false, &host);
    let (f, _) = drive(&mut s, step, &alice);
    assert_eq!(protocol::decode_error(&f[0].payload).unwrap().0, protocol::error::REJECTED);
    s.disconnected();
    assert!(!s.paired());
}

fn send(s: &mut Session, host: &Host, kind: u8, payload: &[u8], alice: &Account) -> (Vec<protocol::Frame>, Vec<Show>) {
    let step = s.frame(frame(kind, payload), host);
    drive(s, step, alice)
}

/// ZFirm on Linux, driven by its keys and frames as the board and phone would:
/// restore a wallet from its words, set a PIN, pair, review a payment, sign it.
#[test]
fn zfirm_linux_restores_pairs_and_signs() {
    use zfirm_linux::app::{App, Key};
    use zfirm_core::mnemonic;

    let dir = tempfile::tempdir().unwrap();
    let entropy = [42u8; 16];
    let list = mnemonic::Packed::new(mnemonic::ENGLISH).unwrap();
    let sentence = mnemonic::sentence(&mnemonic::indices_for(&entropy).unwrap(), &list).unwrap();
    let alice = Account::from_seed(&mnemonic::to_seed(&sentence, "", |_| {}), Network::Test, 0).unwrap();

    zfirm_linux::use_sinsemilla_table();
    let mut app = App::new(dir.path().into(), Network::Test, "board".into());
    // ZFIRM_PREVIEW=dir: each screen as the Pi Zero's LCD draws it.
    let preview = std::env::var_os("ZFIRM_PREVIEW").map(std::path::PathBuf::from);
    let mut shot = 0;
    let mut snap = |app: &App| {
        if let Some(dir) = &preview {
            let mut c = zfirm_linux::canvas::Canvas::new(240, 240);
            c.page(&app.page());
            shot += 1;
            std::fs::write(dir.join(format!("{shot:02}.ppm")), c.ppm()).unwrap();
        }
    };
    snap(&app);
    let type_text = |app: &mut App, text: &str| text.chars().for_each(|c| app.key(Key::Char(c)));
    // Restore: 12 words, typed in full then picked.
    app.key(Key::Down);
    app.key(Key::Ok);
    app.key(Key::Up);
    app.key(Key::Up);
    app.key(Key::Ok);
    assert_eq!(app.page().title, "Word 1/12");
    app.key(Key::Char('a'));
    snap(&app);
    app.key(Key::Char('\x7f'));
    for word in sentence.split(' ') {
        type_text(&mut app, word);
        let page = app.page();
        // Line 0 is what was typed; the candidates follow.
        let pick = page.lines[1..].iter().position(|l| l.trim_start_matches(['>', ' ']) == word).unwrap();
        for _ in 0..pick {
            app.key(Key::Down);
        }
        app.key(Key::Ok);
    }
    assert_eq!(app.page().title, "Choose a PIN");
    app.key(Key::Char('2'));
    snap(&app);
    app.key(Key::Char('\x7f'));
    for _ in 0..2 {
        type_text(&mut app, "2468");
        app.key(Key::Ok);
    }
    assert_eq!(app.page().title, "Receive #0");
    assert_eq!(app.page().qr, Some(alice.encode_address(0)));
    snap(&app);

    // The phone pairs, with the user's yes.
    let talk = |app: &mut App, kind: u8, payload: &[u8]| -> Vec<protocol::Frame> {
        app.frame(frame(kind, payload));
        while app.has_work() {
            app.run_work();
        }
        app.take_output().iter().map(|b| Decoder::new().push(b).unwrap().unwrap()).collect()
    };
    talk(&mut app, msg::HELLO, &[]);
    assert_eq!(app.page().title, "Phone wants in");
    snap(&app);
    app.key(Key::Ok);
    let out: Vec<_> = app.take_output().iter().map(|b| Decoder::new().push(b).unwrap().unwrap()).collect();
    assert_eq!(Info::decode(&out[0].payload).unwrap().ufvk, alice.ufvk());

    // A payment with a memo: amount, recipient and memo pages, then a held OK signs.
    let memo = MemoBytes::from(Memo::from_str("rent").unwrap());
    let pczt = payment_pczt_with_memo(&alice, account(2).address(0), 25_000_000, Pool::Ironwood, memo);
    talk(&mut app, msg::SIGN, &request_for(&pczt, &alice).encode());
    assert_eq!(app.page().big.as_deref(), Some("0.25 ZEC"));
    snap(&app);
    app.key(Key::Ok);
    assert_eq!(app.page().lines, vec!["rent".to_string()]);
    snap(&app);
    app.key(Key::Ok);
    assert_eq!(app.page().title, "Confirm");
    snap(&app);
    app.key(Key::Ok); // a plain OK does not sign
    assert_eq!(app.page().title, "Confirm");
    app.key(Key::Hold);
    while app.has_work() {
        app.run_work();
    }
    snap(&app);
    let out: Vec<_> = app.take_output().iter().map(|b| Decoder::new().push(b).unwrap().unwrap()).collect();
    let signed = out.iter().find(|f| f.kind == msg::SIGNED).unwrap();
    let sigs = request::decode_signatures(&signed.payload).unwrap();
    assert!(apply_signatures(&bytes(&pczt), &sigs).is_ok());

    // Locked again, it answers nothing but "locked".
    app.key(Key::Ok);
    app.key(Key::Back);
    assert_eq!(app.page().title, "PIN");
    let out = talk(&mut app, msg::HELLO, &[]);
    assert_eq!(protocol::decode_error(&out[0].payload).unwrap().0, protocol::error::LOCKED);
}
