//! zkSNARKs — the 10,000 zkSNARKs NFTs on the Flipper Zero, one at a time.
//!
//! A viewer of its own, apart from the ZFlip wallet: the wallet keeps its RAM for
//! signing. ◀ ▶ previous / next, hold OK +100, OK pause, ▲ ▼ speed, Back quits.

#![no_main]
#![no_std]

extern crate alloc;
extern crate flipperzero_alloc;
extern crate flipperzero_rt;

#[path = "../gfx.rs"]
mod gfx;
#[path = "../sync.rs"]
mod sync;
#[path = "../ui.rs"]
mod ui;

use core::ffi::CStr;

use flipperzero::{io::Read, storage::OpenOptions};
use flipperzero_rt::{entry, manifest};
use flipperzero_sys as sys;

use crate::{
    gfx::{Font, Gfx},
    ui::{Key, Shell},
};

manifest!(name = "zkSNARKs", app_version = 1, has_icon = true, icon = "../zflip.icon", stack_size = 2048);
entry!(main);

/// The whole collection: 10,000 × 169 bytes (26×26 portraits, 2 bits per pixel: off /
/// dithered / ink), built by dolphin/pack_all.py.
const PATH: &CStr = c"/ext/apps_data/zksnarks/snarks.bin";
const RECORD: usize = 169;
const COUNT: u16 = 10_000;

struct State {
    id: u16,
    pixels: Option<[u8; RECORD]>,
    playing: bool,
    fast: bool,
    last_step: u32,
}

fn main(_args: Option<&CStr>) -> i32 {
    let shell = Shell::new(State { id: 1, pixels: None, playing: true, fast: false, last_step: 0 }, draw);
    show(&mut shell.state.lock(), 1);
    loop {
        let key = shell.next_key();
        {
            let mut s = shell.state.lock();
            let now = unsafe { sys::furi_get_tick() };
            if s.playing && now.wrapping_sub(s.last_step) >= if s.fast { 250 } else { 1200 } {
                let next = if s.id >= COUNT { 1 } else { s.id + 1 };
                show(&mut s, next);
            }
        }
        let Some(k) = key else { continue };
        let mut s = shell.state.lock();
        let id = s.id;
        match k {
            Key::Ok => s.playing = !s.playing,
            Key::Right => show(&mut s, if id >= COUNT { 1 } else { id + 1 }),
            Key::Left => show(&mut s, if id <= 1 { COUNT } else { id - 1 }),
            Key::LongOk => show(&mut s, if id > COUNT - 100 { 1 } else { id + 100 }),
            Key::Up => s.fast = true,
            Key::Down => s.fast = false,
            Key::Back | Key::LongBack => break,
        }
    }
    0
}

/// Loads zkSNARK `id` (1..=10,000) from the SD card.
fn show(s: &mut State, id: u16) {
    s.id = id;
    s.last_step = unsafe { sys::furi_get_tick() };
    s.pixels = None;
    let Ok(mut f) = OpenOptions::new().read(true).open_existing(true).open(PATH) else { return };
    let offset = (id as u64 - 1) * RECORD as u64;
    if unsafe { sys::storage_file_seek(f.as_ptr(), offset as u32, true) } {
        let mut buf = [0u8; RECORD];
        if f.read(&mut buf).ok() == Some(RECORD) {
            s.pixels = Some(buf);
        }
    }
}

fn draw(g: &Gfx, s: &State) {
    let Some(px) = &s.pixels else {
        ui::draw_message(g, "Copy snarks.bin to\napps_data/zksnarks");
        return;
    };
    for y in 0..26 {
        for x in 0..26 {
            let k = y * 26 + x;
            let level = (px[k / 4] >> (2 * (k % 4))) & 3;
            for dy in 0..2 {
                for dx in 0..2 {
                    if level == 2 || (level == 1 && (dx + dy) % 2 == 0) {
                        g.dot(4 + x as i32 * 2 + dx, 8 + y as i32 * 2 + dy);
                    }
                }
            }
        }
    }
    g.font(Font::Big);
    g.text(62, 14, "zkSNARKs");
    g.font(Font::Numbers);
    g.text(62, 38, &gfx::num(s.id as u64));
    g.font(Font::Small);
    g.text(62, 50, if s.playing { if s.fast { ">> fast" } else { "> playing" } } else { "|| paused" });
    g.text(62, 61, "of 10000");
}
