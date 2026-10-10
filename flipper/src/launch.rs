// Shared by both apps.
#![allow(dead_code)]

//! Hand-over between the ZFlip app and its setup module.
//!
//! A Flipper app is loaded whole into RAM, and ZFlip (wallet + Bluetooth signer)
//! plus seed creation/restore would not fit. So the rarely used setup lives in a
//! second program kept out of the Apps menu, at `SETUP`; each one asks the loader
//! to start the other as it exits, and the user only ever sees "ZFlip".

use core::ffi::CStr;

use flipperzero_sys as sys;

pub const MAIN: &CStr = c"/ext/apps/Tools/zflip.fap";
pub const SETUP: &CStr = c"/ext/apps_data/zflip/zflip_setup.fap";

/// Starts `path` with `args` once the current app has exited.
pub fn after_exit(path: &CStr, args: &CStr) {
    unsafe {
        let loader = sys::furi_record_open(c"loader".as_ptr()) as *mut sys::Loader;
        sys::loader_enqueue_launch(loader, path.as_ptr(), args.as_ptr(), sys::LoaderDeferredLaunchFlagGui);
        sys::furi_record_close(c"loader".as_ptr());
    }
}
