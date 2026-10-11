// Shared by both apps; each uses a subset.
#![allow(dead_code)]

//! The Sinsemilla generator table on the SD card.
//!
//! Every Orchard key derivation and note commitment hashes ~51 message chunks, each
//! needing a point S(j). Computing one costs ~136 ms on the Flipper; reading its 64
//! bytes from `sinsemilla_s.bin` costs about one. The whole file is checked against
//! a digest pinned in the app before use, so a tampered card cannot slip in points
//! that would make a forged note commitment check out.

use core::{ffi::c_void, ptr};

use flipperzero_sys as sys;
use pasta_curves::{arithmetic::CurveAffine, group::ff::PrimeField, pallas};

const PATH: &core::ffi::CStr = c"/ext/apps_data/zflip/sinsemilla_s.bin";
const LEN: usize = 64 * 1024;
/// BLAKE2b-256 (personalisation "ZFlipSinsemillaS") of the table: the 1024 points
/// of `sinsemilla::SINSEMILLA_S`, x || y in little-endian (tools/gen-sinsemilla).
const DIGEST: [u8; 32] = [
    0x12, 0x61, 0x99, 0x9d, 0xc3, 0x8c, 0x01, 0x15, 0xc2, 0x73, 0x2d, 0x56, 0x42, 0x0c, 0x26, 0x9d,
    0x20, 0x4c, 0x38, 0x6a, 0xa3, 0xc9, 0x3d, 0x07, 0xb5, 0x27, 0xb2, 0xe1, 0xb5, 0x60, 0xef, 0xe1,
];

/// The open, verified table (only touched by the one worker thread at a time).
static mut FILE: *mut sys::File = ptr::null_mut();

fn provider(j: u32) -> Option<pallas::Affine> {
    let file = unsafe { FILE };
    if file.is_null() || j >= 1024 {
        return None;
    }
    let mut buf = [0u8; 64];
    unsafe {
        if !sys::storage_file_seek(file, j * 64, true)
            || sys::storage_file_read(file, buf.as_mut_ptr() as *mut c_void, 64) != 64
        {
            return None;
        }
    }
    let x = Option::from(pallas::Base::from_repr(zfirm_core::arr(&buf)))?;
    let y = Option::from(pallas::Base::from_repr(zfirm_core::arr(&buf[32..])))?;
    Option::from(pallas::Affine::from_xy(x, y))
}

/// Runs `f` with the SD table installed, if the card holds the right one;
/// otherwise `f` still runs, computing the points (slowly).
pub fn with<R>(f: impl FnOnce() -> R) -> R {
    let opened = open();
    let out = f();
    if opened {
        close();
    }
    out
}

fn open() -> bool {
    unsafe {
        let storage = sys::furi_record_open(c"storage".as_ptr()) as *mut sys::Storage;
        let file = sys::storage_file_alloc(storage);
        if !sys::storage_file_open(file, PATH.as_ptr(), sys::FSAM_READ, sys::FSOM_OPEN_EXISTING) {
            sys::storage_file_free(file);
            sys::furi_record_close(c"storage".as_ptr());
            return false;
        }
        let mut state = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZFlipSinsemillaS")
            .to_state();
        let mut buf = [0u8; 256];
        let mut total = 0;
        loop {
            let n = sys::storage_file_read(file, buf.as_mut_ptr() as *mut c_void, buf.len());
            if n == 0 {
                break;
            }
            state.update(&buf[..n]);
            total += n;
        }
        if total != LEN || state.finalize().as_bytes() != DIGEST {
            sys::storage_file_close(file);
            sys::storage_file_free(file);
            sys::furi_record_close(c"storage".as_ptr());
            return false;
        }
        FILE = file;
        sinsemilla::set_s_provider(Some(provider));
        true
    }
}

fn close() {
    sinsemilla::set_s_provider(None);
    unsafe {
        sys::storage_file_close(FILE);
        sys::storage_file_free(FILE);
        FILE = ptr::null_mut();
        sys::furi_record_close(c"storage".as_ptr());
    }
}
