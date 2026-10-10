//! Checks the device's hand-rolled primitives and key derivation against reference
//! crates (sha2, pbkdf2, bip39, fpe, orchard, zcash_keys).

use aes::Aes256;
use fpe::ff1::{BinaryNumeralString, FF1};
use orchard::keys::{FullViewingKey, Scope};
use rand_core::{OsRng, RngCore};
use sha2::Digest;
use zcash_keys::{
    address::Address,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};
use zflip_core::{
    Account, Network, ff1, hash,
    mnemonic::{self, ENGLISH, Packed, WordList},
    protocol::{self, Decoder, Info},
};

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

#[test]
fn sha_and_pbkdf2_match_reference() {
    for len in [0usize, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 300] {
        let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        assert_eq!(hash::sha256(&msg), <[u8; 32]>::from(sha2::Sha256::digest(&msg)), "len {len}");
        let mut h = hash::Sha512::default();
        for chunk in msg.chunks(17) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), <[u8; 64]>::from(sha2::Sha512::digest(&msg)), "len {len}");
    }
    let mut expected = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(b"password", b"mnemonicTREZOR", 2048, &mut expected);
    let mut rounds = 0;
    let got = hash::pbkdf2_sha512(b"password", &[b"mnemonic", b"TREZOR"], 2048, |_| rounds += 1);
    assert_eq!(got, expected);
    assert_eq!(rounds, 2047);
    // A key longer than the block size is hashed first.
    let long_key = [9u8; 200];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&long_key, b"salt", 3, &mut expected);
    assert_eq!(hash::pbkdf2_sha512(&long_key, &[b"salt"], 3, |_| ()), expected);
}

#[test]
fn bip39_matches_reference() {
    let list = Packed::new(ENGLISH).unwrap();
    for _ in 0..20 {
        let entropy = random::<32>();
        let indices = mnemonic::indices_from_entropy(&entropy);
        let words = mnemonic::sentence(&indices, &list).unwrap();
        let reference = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(words, reference.to_string());
        assert_eq!(mnemonic::parse(&words, &list).unwrap(), indices);
        assert_eq!(mnemonic::to_seed(&words, "pass", |_| ()), reference.to_seed("pass"));
    }
    // 12-word phrases from other wallets restore too.
    let twelve = bip39::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_string();
    assert!(mnemonic::parse(&twelve, &list).is_ok());

    let zero = "abandon ".repeat(23) + "art";
    assert_eq!(
        hex::encode(mnemonic::to_seed(&zero, "TREZOR", |_| ())),
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
    );
    let bad = "abandon ".repeat(24);
    assert_eq!(mnemonic::parse(bad.trim(), &list), Err(mnemonic::Error::Checksum));
    assert_eq!(mnemonic::parse("abandon zcash", &list), Err(mnemonic::Error::UnknownWord));
    assert_eq!(list.by_prefix("zo").collect::<Vec<_>>(), ["zone", "zoo"]);
    assert_eq!(list.by_prefix("").count(), 2048);
    assert_eq!(list.word(2047), Some("zoo"));
    assert!(Packed::new("abandon\nability").is_none());
}

#[test]
fn ff1_matches_fpe() {
    for _ in 0..200 {
        let dk = random::<32>();
        let j = random::<11>();
        let expected = FF1::<Aes256>::new(&dk, 2)
            .unwrap()
            .encrypt(&[], &BinaryNumeralString::from_bytes_le(&j))
            .unwrap()
            .to_bytes_le();
        assert_eq!(ff1::encrypt(&dk, &j).to_vec(), expected);
    }
}

#[test]
fn addresses_match_orchard() {
    let account = Account::from_seed(&random::<32>(), Network::Main, 0).unwrap();
    let fvk: &FullViewingKey = account.fvk();
    for j in [0u32, 1, 2, 77, 1000, u32::MAX] {
        for scope in [Scope::External, Scope::Internal] {
            assert_eq!(account.address_in(scope, j), fvk.address_at(j, scope), "{scope:?} {j}");
        }
    }
}

#[test]
fn keys_match_zcash_keys() {
    let seed = random::<64>();
    for (network, main) in [(Network::Main, true), (Network::Test, false)] {
        for index in [0u32, 1, 7] {
            let account = Account::from_seed(&seed, network, index).unwrap();
            let id = zip32::AccountId::try_from(index).unwrap();
            let usk = if main {
                UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, id)
            } else {
                UnifiedSpendingKey::from_seed(&TEST_NETWORK, &seed, id)
            }
            .unwrap();
            let fvk = FullViewingKey::from(usk.orchard());
            assert_eq!(account.fvk().to_bytes(), fvk.to_bytes());

            let ufvk = if main {
                UnifiedFullViewingKey::decode(&MAIN_NETWORK, &account.ufvk())
            } else {
                UnifiedFullViewingKey::decode(&TEST_NETWORK, &account.ufvk())
            }
            .unwrap();
            assert_eq!(ufvk.orchard().unwrap().to_bytes(), fvk.to_bytes());

            for j in [0u32, 1, 1000] {
                let text = account.encode_address(j);
                assert!(text.starts_with(if main { "u1" } else { "utest1" }));
                let decoded = if main {
                    Address::decode(&MAIN_NETWORK, &text)
                } else {
                    Address::decode(&TEST_NETWORK, &text)
                };
                let Some(Address::Unified(ua)) = decoded else {
                    panic!("not a unified address: {text}")
                };
                assert_eq!(ua.orchard(), Some(&fvk.address_at(j, Scope::External)));
            }
        }
    }
}

#[test]
fn seed_fingerprint_matches_zip32() {
    let seed = [9u8; 32];
    let account = Account::from_seed(&seed, Network::Main, 0).unwrap();
    let fp = zip32::fingerprint::SeedFingerprint::from_seed(&seed).unwrap();
    assert_eq!(account.seed_fingerprint(), fp.to_bytes());
}

#[test]
fn frames_survive_any_packet_split() {
    let info = Info {
        network: 1,
        account: 0,
        seed_fingerprint: [3; 32],
        ufvk: "uviewtest1abc".into(),
        created_at: 1_760_000_000,
        device_name: "Flipper Zec".into(),
        address_index: 7,
    };
    let mut wire = protocol::encode(protocol::msg::INFO, &info.encode());
    wire.extend(protocol::encode(protocol::msg::PONG, &[]));
    for chunk in [1usize, 5, 20, 244] {
        let mut d = Decoder::new();
        let mut frames = vec![];
        for part in wire.chunks(chunk) {
            if let Some(f) = d.push(part).unwrap() {
                frames.push(f);
            }
            while let Some(f) = d.next().unwrap() {
                frames.push(f);
            }
        }
        assert_eq!(frames.len(), 2, "chunk {chunk}");
        assert_eq!(Info::decode(&frames[0].payload).unwrap(), info);
        assert_eq!(frames[1].kind, protocol::msg::PONG);
    }
    assert!(Decoder::new().push(&[0x00]).is_err());
}

#[test]
fn ua_codec_matches_zcash_address() {
    use zcash_address::unified::{self, Container, Encoding};
    use zcash_protocol::consensus::NetworkType;
    use zflip_core::ua;
    for (network, nt) in [(Network::Main, NetworkType::Main), (Network::Test, NetworkType::Test)] {
        for _ in 0..20 {
            let account = Account::from_seed(&random::<32>(), network, 0).unwrap();
            let raw = account.address(3).to_raw_address_bytes();
            let ours = ua::encode_orchard_address(network, &raw);
            let theirs = unified::Address::try_from_items(vec![unified::Receiver::Orchard(raw)])
                .unwrap()
                .encode(&nt);
            assert_eq!(ours, theirs);
            assert_eq!(ua::orchard_receiver(network, &theirs), Some(raw));

            // A wallet-style UA with Sapling + Orchard receivers still yields Orchard.
            let multi = unified::Address::try_from_items(vec![
                unified::Receiver::Sapling([9; 43]),
                unified::Receiver::Orchard(raw),
            ])
            .unwrap()
            .encode(&nt);
            assert_eq!(ua::orchard_receiver(network, &multi), Some(raw));
            let (_, items) = ua::decode(&multi).unwrap();
            assert_eq!(items.len(), 2);
            let (_, parsed) = unified::Address::decode(&multi).unwrap();
            assert_eq!(parsed.items().len(), 2);
        }
        // Wrong network, corrupted checksum, uppercase mix: rejected.
        let a = ua::encode_orchard_address(network, &[1; 43]);
        let other = if network == Network::Main { Network::Test } else { Network::Main };
        assert_eq!(ua::orchard_receiver(other, &a), None);
        let mut bad = a.clone().into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'q' { b'p' } else { b'q' };
        assert_eq!(ua::orchard_receiver(network, &String::from_utf8(bad).unwrap()), None);
    }
}

#[test]
fn account_rebuilds_from_its_spending_key() {
    let a = Account::from_seed(&random::<64>(), Network::Main, 0).unwrap();
    let b = Account::from_sk(a.sk_bytes(), a.seed_fingerprint(), Network::Main, 0).unwrap();
    assert_eq!(a.ufvk(), b.ufvk());
    assert_eq!(a.encode_address(4), b.encode_address(4));
    assert_eq!(a.address_in(Scope::Internal, 0), b.address_in(Scope::Internal, 0));
}

#[test]
fn signing_key_derives_the_same_addresses() {
    let a = Account::from_seed(&random::<64>(), Network::Main, 0).unwrap();
    let change = a.address_in(Scope::Internal, 0).to_raw_address_bytes();
    let key = zflip_core::account::SigningKey::from_parts(Network::Main, a.sk_bytes(), a.seed_fingerprint(), change).unwrap();
    let ivk = key.external_ivk();
    for j in [0u32, 19, 20, 12345] {
        assert_eq!(zflip_core::account::address_at(&ivk, j), a.address(j));
    }
}
