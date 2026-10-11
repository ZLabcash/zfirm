//! C ABI for the iOS app. Buffers returned by this module are owned by Rust and
//! must be released with [`zflip_free`]. Every call returns 0 on success; on error
//! it returns a negative code and fills `out` with a UTF-8 message instead.

use std::ffi::{CStr, c_char};

use zflip_core::request;

/// A byte buffer handed to the caller.
#[repr(C)]
pub struct ZflipBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl ZflipBuffer {
    fn from_vec(v: Vec<u8>) -> Self {
        let mut b = v.into_boxed_slice();
        let out = ZflipBuffer {
            ptr: b.as_mut_ptr(),
            len: b.len(),
        };
        std::mem::forget(b);
        out
    }
}

fn finish(result: Result<Vec<u8>, crate::Error>, out: *mut ZflipBuffer) -> i32 {
    let (code, bytes) = match result {
        Ok(bytes) => (0, bytes),
        Err(e) => (-1, e.to_string().into_bytes()),
    };
    if !out.is_null() {
        unsafe { *out = ZflipBuffer::from_vec(bytes) };
    }
    code
}

unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

/// PCZT + UFVK → encoded device sign request.
///
/// # Safety
/// `pczt` must point to `pczt_len` readable bytes, `ufvk` to a NUL-terminated
/// string, and `out` to writable memory for one `ZflipBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_sign_request(
    pczt: *const u8,
    pczt_len: usize,
    ufvk: *const c_char,
    out: *mut ZflipBuffer,
) -> i32 {
    let pczt = unsafe { slice(pczt, pczt_len) };
    let result = unsafe { CStr::from_ptr(ufvk) }
        .to_str()
        .map_err(|_| crate::Error::Ufvk)
        .and_then(|ufvk| crate::sign_request(pczt, ufvk))
        .map(|req| req.encode());
    finish(result, out)
}

/// PCZT + encoded device signatures → signed PCZT.
///
/// # Safety
/// Same contract as [`zflip_sign_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_apply_signatures(
    pczt: *const u8,
    pczt_len: usize,
    sigs: *const u8,
    sigs_len: usize,
    out: *mut ZflipBuffer,
) -> i32 {
    let pczt = unsafe { slice(pczt, pczt_len) };
    let sigs = unsafe { slice(sigs, sigs_len) };
    let result = request::decode_signatures(sigs)
        .ok_or(crate::Error::Signature("malformed signature list".into()))
        .and_then(|sigs| crate::apply_signatures(pczt, &sigs));
    finish(result, out)
}

/// UFVK + diversifier index → UTF-8 unified address.
///
/// # Safety
/// `ufvk` must be a NUL-terminated string and `out` writable for one `ZflipBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_address(ufvk: *const c_char, index: u32, out: *mut ZflipBuffer) -> i32 {
    let result = unsafe { CStr::from_ptr(ufvk) }
        .to_str()
        .map_err(|_| crate::Error::Ufvk)
        .and_then(|ufvk| crate::address(ufvk, index))
        .map(String::into_bytes);
    finish(result, out)
}

/// 32 bytes of entropy → 24 words (UTF-8, single spaces).
///
/// # Safety
/// `entropy` must point to 32 readable bytes and `out` be writable for one `ZflipBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_mnemonic_new(entropy: *const u8, out: *mut ZflipBuffer) -> i32 {
    let bytes = unsafe { slice(entropy, 32) };
    let result = <[u8; 32]>::try_from(bytes)
        .map_err(|_| crate::Error::Mnemonic)
        .map(|e| crate::mnemonic_new(&e).into_bytes());
    finish(result, out)
}

/// Words → 64-byte BIP 39 seed (errors if a word or the checksum is wrong).
///
/// # Safety
/// `phrase` must be a NUL-terminated string and `out` writable for one `ZflipBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_mnemonic_seed(phrase: *const c_char, out: *mut ZflipBuffer) -> i32 {
    let result = unsafe { CStr::from_ptr(phrase) }
        .to_str()
        .map_err(|_| crate::Error::Mnemonic)
        .and_then(crate::mnemonic_seed)
        .map(|s| s.to_vec());
    finish(result, out)
}

/// Seed → its 32-byte ZIP 32 fingerprint.
///
/// # Safety
/// `seed` must point to `seed_len` readable bytes and `out` be writable for one `ZflipBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_seed_fingerprint(seed: *const u8, seed_len: usize, out: *mut ZflipBuffer) -> i32 {
    let seed = unsafe { slice(seed, seed_len) };
    finish(crate::seed_fingerprint(seed).map(|f| f.to_vec()), out)
}

/// Releases a buffer returned by this library.
///
/// # Safety
/// `buf` must come from this library and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zflip_free(buf: ZflipBuffer) {
    if !buf.ptr.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }
}
