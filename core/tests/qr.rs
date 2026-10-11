//! The compact QR encoder must produce exactly what qrcodegen does for the same
//! version, level L and mask 0.
use qrcodegen::{Mask, QrCode, QrCodeEcc, QrSegment, Version};
use zfirm_core::{Account, Network, qr::Qr};

fn reference(data: &[u8], version: u8) -> QrCode {
    let segs = [QrSegment::make_bytes(data)];
    QrCode::encode_segments_advanced(&segs, QrCodeEcc::Low, Version::new(version), Version::new(version), Some(Mask::new(0)), false).unwrap()
}

#[test]
fn matches_qrcodegen() {
    let mut inputs: Vec<Vec<u8>> =
        vec![b"zcash".to_vec(), vec![0x42; 60], vec![7; 100], vec![9; 150], vec![3; 190], vec![1; 230]];
    for (net, seed) in [(Network::Main, 1u8), (Network::Test, 2)] {
        let a = Account::from_seed(&[seed; 32], net, 0).unwrap();
        for j in [0u32, 1, 77, 123456] {
            inputs.push(a.encode_address(j).into_bytes());
        }
        // Viewing keys (195 characters): version 9.
        inputs.push(a.ufvk().into_bytes());
    }
    for data in inputs {
        let ours = Qr::encode(&data).expect("fits");
        let version = ((ours.size - 17) / 4) as u8;
        let theirs = reference(&data, version);
        assert_eq!(theirs.size() as usize, ours.size, "len {}", data.len());
        for y in 0..ours.size {
            for x in 0..ours.size {
                assert_eq!(ours.get(x, y), theirs.get_module(x as i32, y as i32), "len {} at {x},{y}", data.len());
            }
        }
    }
    assert!(Qr::encode(&[0; 231]).is_none());
}
