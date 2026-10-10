//! Development only: times the crypto building blocks on the Flipper and logs
//! the results (read them with `log info` on the CLI).

#![no_main]
#![no_std]

#[path = "../stable.rs"]
mod stable;

extern crate alloc;
extern crate flipperzero_alloc;
extern crate flipperzero_rt;

use core::{ffi::CStr, hint::black_box};

use flipperzero_rt::{entry, manifest};
use flipperzero_sys as sys;
use pasta_curves::{
    arithmetic::CurveExt,
    group::{Group, ff::Field},
    pallas,
};
use zflip_core::{Account, Network};

manifest!(name = "ZFlip Bench", app_version = 1, has_icon = false, stack_size = 16384);
entry!(main);

/// Appends a line to /ext/apps_data/zflip/bench.txt (survives a crash).
fn log(what: &CStr, start: u32, count: u32) {
    use flipperzero::{io::Write, storage::OpenOptions};
    let ms = unsafe { sys::furi_get_tick() }.wrapping_sub(start);
    let line = alloc::format!("{}: {} ms for {}\n", what.to_str().unwrap_or("?"), ms, count);
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .open_append(true)
        .open(c"/ext/apps_data/zflip/bench.txt")
    {
        let _ = f.write(line.as_bytes());
    }
}

fn log_text(text: &str) {
    use flipperzero::{io::Write, storage::OpenOptions};
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .open_append(true)
        .open(c"/ext/apps_data/zflip/bench.txt")
    {
        let _ = f.write(text.as_bytes());
        let _ = f.write(b"\n");
    }
}

fn orchard_scope_internal() -> orchard::keys::Scope {
    orchard::keys::Scope::Internal
}

fn now() -> u32 {
    unsafe { sys::furi_get_tick() }
}

fn main(_args: Option<&CStr>) -> i32 {
    log(c"start", now(), 0);
    let mut a = pallas::Base::from(7u64);
    let b = pallas::Base::from(11u64);
    let t = now();
    for _ in 0..1000 {
        a = black_box(a * b);
    }
    log(c"Fp mul", t, 1000);

    let t = now();
    for _ in 0..10 {
        a = black_box(a.invert().unwrap_or(a));
    }
    log(c"Fp invert", t, 10);

    let t = now();
    for _ in 0..5 {
        a = black_box(a.square().sqrt().unwrap_or(a));
    }
    log(c"Fp sqrt", t, 5);

    let h = pallas::Point::hash_to_curve("z.cash:SinsemillaS");
    let t = now();
    for j in 0..5u32 {
        black_box(h(&j.to_le_bytes()));
    }
    log(c"hash_to_curve", t, 5);

    let g = pallas::Point::generator();
    let s = pallas::Scalar::from(0x1234_5678_9abc_def0u64) * pallas::Scalar::from(0xfedc_ba98_7654_3210u64);
    let t = now();
    black_box(g * s);
    log(c"scalar mult", t, 1);

    let t = now();
    let account = stable::with(|| Account::from_seed(&[7u8; 64], Network::Main, 0).ok());
    log(c"account with SD table", t, 1);

    if let Some(account) = account {
        let t = now();
        let text = stable::with(|| account.encode_address(5));
        log(c"address", t, 1);
        log_text(&text);
        log_text(&account.ufvk());
        let t = now();
        let internal = stable::with(|| account.address_in(orchard_scope_internal(), 3));
        log(c"internal address", t, 1);
        log_text(&zflip_core::account::encode_orchard_address(Network::Main, &internal));
    }
    let free = unsafe { sys::furi_thread_get_stack_space(sys::furi_thread_get_current_id()) };
    log(c"stack never used (bytes, of 16384)", now(), free as u32);
    log(c"done", now(), 0);
    0
}
