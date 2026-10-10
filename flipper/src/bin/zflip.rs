//! ZFlip — a Zcash shielded wallet for the Flipper Zero.
//!
//! Unlocks the sealed wallet, shows a fresh shielded receiving address each time
//! it opens and on each press of ▶ (as a QR code and text), and keeps a Bluetooth link to the ZFlip iPhone app for as long as it is
//! open: the phone gets the viewing key once the user agrees, follows the address
//! shown here, and sends transactions that ZFlip checks against their commitments
//! (see `zflip_core::sign`), shows, and signs only on a long press of OK.
//!
//! Creating or restoring a wallet, showing its words and switching networks live
//! in a setup module launched on demand (see `launch.rs`): together they would not
//! fit in the RAM a Flipper app gets.

#![no_main]
#![no_std]

extern crate alloc;
extern crate flipperzero_alloc;
extern crate flipperzero_rt;

#[path = "../ble.rs"]
mod ble;
#[path = "../gfx.rs"]
mod gfx;
#[path = "../launch.rs"]
mod launch;
#[path = "../stable.rs"]
mod stable;
#[path = "../sync.rs"]
mod sync;
#[path = "../ui.rs"]
mod ui;
#[path = "../vault.rs"]
mod vault;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{ffi::CStr, sync::atomic::Ordering};

use flipperzero::{
    furi::rng::HwRng,
    io::{Read, Write},
    storage::OpenOptions,
};
use flipperzero_rt::{entry, manifest};
use flipperzero_sys as sys;
use zflip_core::{
    Network,
    account::SigningKey,
    protocol::{self, Decoder, Info, error, msg, status},
    request::{self, SignRequest},
    sign::{self, Review},
};

use crate::{
    gfx::{Font, Gfx, Qr, zec},
    ui::{Key, PROGRESS, Pin, PinPad, Shell, Worker},
};

manifest!(name = "ZFlip", app_version = 2, has_icon = true, icon = "../zflip.icon", stack_size = 4096);
entry!(main);

/// The whole zkSNARKs collection: 10,000 × 169 bytes (26×26 portraits, 2 bits per
/// pixel: off / dithered / ink), built by dolphin/pack_all.py.
const SNARKS_PATH: &CStr = c"/ext/apps_data/zflip/snarks.bin";
const SNARK_RECORD: usize = 169;
const SNARKS: u16 = 10_000;
const HOME: [&str; 3] = ["Receive", "Collections", "Settings"];
/// NFT collections viewable on the Flipper (one so far).
const COLLECTIONS: [&str; 1] = ["zkSNARKs"];
const SETTINGS: [&str; 6] = ["Recovery words", "Viewing key", "Change PIN", "Network", "Lock", "Wipe wallet"];
/// Settings rows that fit under the title bar.
const SETTINGS_ROWS: u8 = 5;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Pin,
    Busy(&'static str),
    Home(u8),
    Receive { text: bool },
    Collections(u8),
    Gallery,
    Settings(u8),
    Wipe,
    PairPrompt,
    Review(u8),
    Done { ok: bool },
    Message(&'static str),
}

struct State {
    screen: Screen,
    /// Where to go back to after a pairing prompt or a signature.
    resume: Screen,
    frame: u32,
    meta: Option<vault::Meta>,
    account: Option<Arc<SigningKey>>,
    pin: PinPad,
    note: &'static str,
    connected: bool,
    paired: bool,
    review: Option<Review>,
    index: u32,
    address: Option<(u32, String, Option<Qr>)>,
    /// Derives receiving addresses; set at unlock.
    ivk: Option<Arc<orchard::keys::IncomingViewingKey>>,
    /// Gallery: the zkSNARK shown, its portrait, autoplay and speed.
    snark: u16,
    snark_pixels: Option<[u8; SNARK_RECORD]>,
    playing: bool,
    fast: bool,
    last_step: u32,
}

enum Job {
    Opened(Result<(vault::Meta, Arc<SigningKey>, Arc<orchard::keys::IncomingViewingKey>), vault::Error>),
    Address(u32, String, Option<Qr>),
    Reviewed(Result<Review, sign::Error>),
    Signed(Result<Vec<u8>, sign::Error>),
}

struct Session {
    link: Option<ble::Link>,
    decoder: Decoder,
    request: Option<Arc<SignRequest>>,
}

fn main(_args: Option<&CStr>) -> i32 {
    if !vault::exists() {
        // First run: hand over to the setup module, which comes back here.
        launch::after_exit(launch::SETUP, c"create");
        return 0;
    }
    // First, while the heap is still in one piece: the worker's stack.
    let mut worker = Worker::new(10 * 1024);
    let shell = Shell::new(
        State {
            screen: Screen::Pin,
            resume: Screen::Home(0),
            frame: 0,
            meta: None,
            account: None,
            pin: PinPad::new(),
            note: "",
            connected: false,
            paired: false,
            review: None,
            index: 0,
            address: None,
            ivk: None,
            snark: 1,
            snark_pixels: None,
            playing: true,
            fast: false,
            last_step: 0,
        },
        draw,
    );
    let mut session = Session { link: None, decoder: Decoder::new(), request: None };
    loop {
        let key = shell.next_key();
        if let Some(job) = worker.poll() {
            finish(&shell, &mut worker, &mut session, job);
        }
        poll_link(&shell, &mut worker, &mut session);
        {
            let mut s = shell.state.lock();
            s.frame += 1;
            if s.screen == Screen::Gallery && s.playing {
                let now = unsafe { sys::furi_get_tick() };
                if now.wrapping_sub(s.last_step) >= if s.fast { 250 } else { 1200 } {
                    let next = if s.snark >= SNARKS { 1 } else { s.snark + 1 };
                    show_snark(&mut s, next);
                }
            }
        }
        let Some(k) = key else { continue };
        if worker.busy() {
            continue;
        }
        if !input(&shell, &mut worker, &mut session, k) {
            break;
        }
    }
    worker.wait();
    session.link = None;
    0
}

/// The index after the last one handed out: #0 for a new wallet.
fn next_index() -> u32 {
    let mut buf = [0u8; 4];
    let Ok(mut f) = OpenOptions::new().read(true).open_existing(true).open(vault::INDEX_PATH) else { return 0 };
    if f.read(&mut buf).ok() == Some(4) { u32::from_le_bytes(buf).saturating_add(1) } else { 0 }
}

fn save_index(index: u32) {
    if let Ok(mut f) = OpenOptions::new().write(true).create_always(true).open(vault::INDEX_PATH) {
        let _ = f.write(&index.to_le_bytes());
    }
}

/// Loads zkSNARK `id` (1..=10,000) from the SD card.
fn show_snark(s: &mut State, id: u16) {
    s.snark = id;
    s.last_step = unsafe { sys::furi_get_tick() };
    s.snark_pixels = None;
    let Ok(mut f) = OpenOptions::new().read(true).open_existing(true).open(SNARKS_PATH) else { return };
    let offset = (id as u64 - 1) * SNARK_RECORD as u64;
    if unsafe { sys::storage_file_seek(f.as_ptr(), offset as u32, true) } {
        let mut buf = [0u8; SNARK_RECORD];
        if f.read(&mut buf).ok() == Some(SNARK_RECORD) {
            s.snark_pixels = Some(buf);
        }
    }
}

fn reply(session: &Session, kind: u8, payload: &[u8]) {
    if let Some(link) = &session.link {
        link.send(&protocol::encode(kind, payload));
    }
}

fn reply_error(session: &Session, code: u8, message: &str) {
    reply(session, msg::ERROR, &protocol::encode_error(code, message));
}

/// Moves on to a fresh address (the next index) and derives it, QR included, on
/// the worker; the paired iPhone follows. Old ones still receive, but are never
/// shown again.
fn new_address(s: &mut State, worker: &mut Worker<Job>, show: bool) {
    let (Some(meta), Some(ivk)) = (s.meta, s.ivk.clone()) else { return };
    let j = if s.address.is_some() { s.index.saturating_add(1) } else { s.index };
    s.index = j;
    save_index(j);
    if show {
        s.screen = Screen::Busy("Forging address");
    }
    worker.spawn(move || {
        let raw = stable::with(|| zflip_core::account::address_at(&ivk, j)).to_raw_address_bytes();
        let text = zflip_core::ua::encode_orchard_address(meta.network, &raw);
        let qr = Qr::address(&text);
        Job::Address(j, text, qr)
    });
}

fn finish(shell: &Shell<State>, worker: &mut Worker<Job>, session: &mut Session, job: Job) {
    match job {
        Job::Opened(Ok((meta, account, ivk))) => {
            {
                let mut s = shell.state.lock();
                s.meta = Some(meta);
                s.account = Some(account);
                s.ivk = Some(ivk);
                s.screen = Screen::Home(0);
                // Each opening hands out a fresh address, prepared in the background.
                s.address = None;
                s.index = next_index();
                new_address(&mut s, worker, false);
            }
            // Bluetooth stays on while the app is open.
            session.link = ble::Link::start();
            if session.link.is_none() {
                shell.state.lock().screen = Screen::Message("Bluetooth is off:\nturn it on in Settings");
            }
            shell.success();
        }
        Job::Opened(Err(e)) => {
            let mut s = shell.state.lock();
            s.screen = match e {
                vault::Error::WrongPin { attempts_left } => {
                    s.note = if attempts_left <= 3 { "Wrong PIN: few tries left" } else { "Wrong PIN" };
                    Screen::Pin
                }
                vault::Error::Wiped => Screen::Message("Too many tries:\nwallet wiped"),
                vault::Error::Enclave => Screen::Message("Secure enclave error"),
                _ => Screen::Message("Wallet file error"),
            };
            drop(s);
            shell.error();
        }
        Job::Address(j, text, qr) => {
            let mut s = shell.state.lock();
            let showing = s.screen == Screen::Busy("Forging address");
            let paired = s.paired;
            s.address = Some((j, text.clone(), qr));
            if showing {
                s.screen = Screen::Receive { text: false };
            }
            drop(s);
            if paired {
                reply(session, msg::ADDRESS, &protocol::encode_address(j, &text));
            }
        }
        Job::Reviewed(Ok(review)) => {
            {
                let mut s = shell.state.lock();
                s.review = Some(review);
                s.screen = Screen::Review(0);
            }
            reply(session, msg::STATUS, &[status::AWAITING_USER]);
            shell.attention();
        }
        Job::Reviewed(Err(e)) | Job::Signed(Err(e)) => {
            session.request = None;
            reply_error(session, error::INVALID_TX, e.message());
            let mut s = shell.state.lock();
            s.review = None;
            s.note = e.message();
            s.screen = Screen::Done { ok: false };
            drop(s);
            shell.error();
        }
        Job::Signed(Ok(sigs)) => {
            session.request = None;
            reply(session, msg::SIGNED, &sigs);
            let mut s = shell.state.lock();
            s.review = None;
            s.note = "Signed: phone sends it";
            s.screen = Screen::Done { ok: true };
            drop(s);
            shell.success();
        }
    }
}

/// Returns false to quit.
fn input(shell: &Shell<State>, worker: &mut Worker<Job>, session: &mut Session, k: Key) -> bool {
    let mut s = shell.state.lock();
    match s.screen {
        Screen::Pin => match s.pin.key(k) {
            Pin::Editing => {}
            Pin::Cancel => return false,
            Pin::Entered(pin) => {
                s.note = "";
                s.screen = Screen::Busy("Unlocking");
                worker.spawn(move || {
                    Job::Opened(vault::unseal(&pin, &mut |p| PROGRESS.store(p * 2 / 3, Ordering::Relaxed)).and_then(
                        |(meta, secret)| {
                            let key = stable::with(|| {
                                SigningKey::from_parts(meta.network, secret.sk, secret.seed_fp, meta.change)
                            })
                            .ok_or(vault::Error::Corrupt)?;
                            let ivk = stable::with(|| key.external_ivk());
                            PROGRESS.store(100, Ordering::Relaxed);
                            Ok((meta, Arc::new(key), Arc::new(ivk)))
                        },
                    ))
                });
            }
        },
        Screen::Busy(_) => {}
        Screen::Home(sel) => match k {
            Key::Up => s.screen = Screen::Home((sel + 2) % 3),
            Key::Down => s.screen = Screen::Home((sel + 1) % 3),
            Key::Ok if sel == 0 => {
                if s.address.is_some() {
                    s.screen = Screen::Receive { text: false };
                } else {
                    s.screen = Screen::Busy("Forging address");
                }
            }
            Key::Ok if sel == 1 => s.screen = Screen::Collections(0),
            Key::Ok => s.screen = Screen::Settings(0),
            Key::Back => return false,
            _ => {}
        },
        Screen::Collections(_) => match k {
            Key::Ok => {
                let id = s.snark;
                show_snark(&mut s, id);
                s.playing = true;
                s.screen = if s.snark_pixels.is_some() {
                    Screen::Gallery
                } else {
                    Screen::Message("Copy snarks.bin to\napps_data/zflip")
                };
            }
            Key::Back => s.screen = Screen::Home(1),
            _ => {}
        },
        Screen::Gallery => {
            let id = s.snark;
            match k {
                Key::Ok => s.playing = !s.playing,
                Key::Right => show_snark(&mut s, if id >= SNARKS { 1 } else { id + 1 }),
                Key::Left => show_snark(&mut s, if id <= 1 { SNARKS } else { id - 1 }),
                Key::LongOk => show_snark(&mut s, if id > SNARKS - 100 { 1 } else { id + 100 }),
                Key::Up => s.fast = true,
                Key::Down => s.fast = false,
                Key::Back => s.screen = Screen::Collections(0),
                _ => {}
            }
        }
        Screen::Receive { text } => match k {
            Key::Right => new_address(&mut s, worker, true),
            Key::Ok => s.screen = Screen::Receive { text: !text },
            Key::Back => s.screen = Screen::Home(0),
            _ => {}
        },
        Screen::Settings(sel) => {
            let n = SETTINGS.len() as u8;
            match k {
                Key::Up => s.screen = Screen::Settings((sel + n - 1) % n),
                Key::Down => s.screen = Screen::Settings((sel + 1) % n),
                // The setup module asks for the PIN itself, then comes back here.
                Key::Ok if sel == 0 => {
                    launch::after_exit(launch::SETUP, c"reveal");
                    return false;
                }
                Key::Ok if sel == 1 => {
                    launch::after_exit(launch::SETUP, c"viewkey");
                    return false;
                }
                Key::Ok if sel == 2 => {
                    launch::after_exit(launch::SETUP, c"pin");
                    return false;
                }
                Key::Ok if sel == 3 => {
                    launch::after_exit(launch::SETUP, c"network");
                    return false;
                }
                Key::Ok if sel == 4 => {
                    session.link = None;
                    s.account = None;
                    s.address = None;
                    s.ivk = None;
                    s.paired = false;
                    s.connected = false;
                    s.pin.clear();
                    s.screen = Screen::Pin;
                }
                Key::Ok => s.screen = Screen::Wipe,
                Key::Back => s.screen = Screen::Home(2),
                _ => {}
            }
        }
        Screen::Wipe => match k {
            Key::LongOk => {
                session.link = None;
                vault::wipe();
                drop(s);
                shell.error();
                launch::after_exit(launch::SETUP, c"create");
                return false;
            }
            Key::Back => s.screen = Screen::Settings(5),
            _ => {}
        },
        Screen::PairPrompt => match k {
            Key::Ok => {
                s.paired = true;
                s.screen = s.resume;
                let info = info(&s);
                let address = s.address.as_ref().map(|(j, a, _)| protocol::encode_address(*j, a));
                drop(s);
                if let Some(info) = info {
                    reply(session, msg::INFO, &info.encode());
                }
                if let Some(address) = address {
                    reply(session, msg::ADDRESS, &address);
                }
                shell.success();
            }
            Key::Back => {
                s.screen = s.resume;
                drop(s);
                reply_error(session, error::REJECTED, "Refused on the Flipper");
            }
            _ => {}
        },
        Screen::Review(page) => {
            let pages = s.review.as_ref().map_or(1, |r| r.payments.len() as u8 + 1);
            match k {
                Key::Right | Key::Ok if page + 1 < pages => s.screen = Screen::Review(page + 1),
                Key::Left if page > 0 => s.screen = Screen::Review(page - 1),
                Key::LongOk if page + 1 == pages => {
                    let (Some(req), Some(account)) = (session.request.clone(), s.account.clone()) else {
                        return true;
                    };
                    s.screen = Screen::Busy("Signing");
                    drop(s);
                    reply(session, msg::STATUS, &[status::WORKING]);
                    worker.spawn(move || {
                        Job::Signed(
                            stable::with(|| sign::sign_reviewed(&req, &*account, HwRng))
                                .map(|sigs| request::encode_signatures(&sigs)),
                        )
                    });
                }
                Key::Back | Key::LongBack => {
                    session.request = None;
                    s.review = None;
                    s.note = "Refused";
                    s.screen = Screen::Done { ok: false };
                    drop(s);
                    reply_error(session, error::REJECTED, "Refused on the Flipper");
                }
                _ => {}
            }
        }
        Screen::Done { .. } => {
            if matches!(k, Key::Ok | Key::Back) {
                s.screen = s.resume;
            }
        }
        Screen::Message(_) => {
            if matches!(k, Key::Ok | Key::Back) {
                if s.account.is_some() {
                    s.screen = Screen::Home(0);
                } else {
                    return false;
                }
            }
        }
    }
    true
}

fn info(s: &State) -> Option<Info> {
    let (account, meta) = (s.account.as_ref()?, s.meta.as_ref()?);
    let mut device_name = String::new();
    let mut p = unsafe { sys::furi_hal_version_get_name_ptr() } as *const u8;
    while !p.is_null() && unsafe { *p } != 0 && device_name.len() < 16 {
        device_name.push(unsafe { *p } as char);
        p = unsafe { p.add(1) };
    }
    Some(Info {
        network: meta.network.to_byte(),
        account: 0,
        seed_fingerprint: account.seed_fingerprint(),
        ufvk: account.ufvk(),
        created_at: meta.created_at,
        device_name,
        address_index: s.index,
    })
}

/// Interrupts whatever is on screen (a prompt or a review), remembering it.
fn interrupt(s: &mut State, next: Screen) {
    if !matches!(s.screen, Screen::PairPrompt | Screen::Review(_) | Screen::Done { .. } | Screen::Busy(_)) {
        s.resume = s.screen;
    }
    s.screen = next;
}

fn poll_link(shell: &Shell<State>, worker: &mut Worker<Job>, session: &mut Session) {
    let Some(connected) = session.link.as_ref().map(|l| l.connected()) else { return };
    {
        let mut s = shell.state.lock();
        if s.connected && !connected {
            // A new connection must be approved again.
            s.paired = false;
            if s.screen == Screen::PairPrompt {
                s.screen = s.resume;
            }
        }
        s.connected = connected;
    }
    let mut buf = [0u8; 256];
    loop {
        let n = session.link.as_ref().map_or(0, |l| l.recv(&mut buf));
        if n == 0 {
            break;
        }
        let mut next = session.decoder.push(&buf[..n]);
        while let Ok(Some(frame)) = next {
            handle(shell, worker, session, frame);
            next = session.decoder.next();
        }
        if next.is_err() {
            reply_error(session, error::BAD_REQUEST, "Bad frame");
        }
    }
}

fn handle(shell: &Shell<State>, worker: &mut Worker<Job>, session: &mut Session, f: protocol::Frame) {
    let (paired, account) = {
        let s = shell.state.lock();
        (s.paired, s.account.clone())
    };
    match f.kind {
        msg::PING => reply(session, msg::PONG, &[]),
        msg::HELLO if paired => {
            let info = info(&shell.state.lock());
            if let Some(info) = info {
                reply(session, msg::INFO, &info.encode());
            }
        }
        msg::HELLO => {
            if worker.busy() || session.request.is_some() {
                return reply_error(session, error::BUSY, "Busy");
            }
            interrupt(&mut shell.state.lock(), Screen::PairPrompt);
            reply(session, msg::STATUS, &[status::AWAITING_USER]);
            shell.attention();
        }
        _ if !paired => reply_error(session, error::NOT_PAIRED, "Say hello first"),
        msg::SIGN if worker.busy() || session.request.is_some() => reply_error(session, error::BUSY, "Busy"),
        msg::SIGN => {
            let (Some(req), Some(account)) = (SignRequest::decode(&f.payload), account) else {
                return reply_error(session, error::BAD_REQUEST, "Bad request");
            };
            let req = Arc::new(req);
            session.request = Some(req.clone());
            interrupt(&mut shell.state.lock(), Screen::Busy("Checking transaction"));
            reply(session, msg::STATUS, &[status::WORKING]);
            worker.spawn(move || Job::Reviewed(stable::with(|| sign::review(&req, &*account))));
        }
        _ => reply_error(session, error::BAD_REQUEST, "Unknown message"),
    }
}

fn menu(g: &Gfx, items: &[&str], sel: u8, x: i32, y0: i32, step: i32) {
    g.font(Font::Small);
    for (i, label) in items.iter().enumerate() {
        let y = y0 + i as i32 * step;
        if i as u8 == sel {
            g.fill(x - 4, y - 9, 128 - x + 4, 12);
            g.white();
        }
        g.text(x, y, label);
        g.black();
    }
}

/// The iPhone link, as a small badge in the title bar's right corner.
fn link_badge(g: &Gfx, s: &State) {
    g.white();
    let x = 112;
    if s.paired {
        // A filled dot with a ring: paired and ready to sign.
        g.disc(x + 6, 5, 3);
        g.frame(x, 0, 13, 11);
    } else if s.connected {
        g.disc(x + 6, 5, 2);
    } else if (s.frame / 15) % 2 == 0 {
        g.dot(x + 6, 5);
    }
    g.black();
}

fn draw(g: &Gfx, s: &State) {
    match s.screen {
        Screen::Pin => s.pin.draw(g, "ZFlip: PIN", s.note),
        Screen::Busy(label) => ui::draw_busy(g, label, s.frame),
        Screen::Home(sel) => {
            g.title(if s.meta.map(|m| m.network) == Some(Network::Test) { "ZFlip testnet" } else { "ZFlip" });
            link_badge(g, s);
            g.shield(18, 37, 1000, 0);
            menu(g, &HOME, sel, 40, 23, 12);
            g.font(Font::Small);
            g.text(
                38,
                61,
                match (s.connected, s.paired) {
                    (_, true) => "Phone ready",
                    (true, false) => "Phone connecting",
                    (false, _) => "Open on your phone",
                },
            );
        }
        Screen::Receive { text } => {
            let Some((_, addr, qr)) = &s.address else { return };
            if text {
                g.title("Address:");
                link_badge(g, s);
                g.wrapped(1, 19, addr, 21, 0, 6);
            } else {
                match qr {
                    Some(qr) => g.qr(qr, 0),
                    None => {
                        g.font(Font::Small);
                        g.text(6, 36, "OK: text");
                    }
                }
                g.font(Font::Big);
                g.text(68, 12, "Shielded");
                g.font(Font::Small);
                g.text(68, 24, "Address:");
                // `get`, not slicing: a slicing panic path drags in Unicode tables.
                g.text(68, 34, addr.get(..10).unwrap_or(""));
                g.text(68, 46, "> new one");
                g.text(68, 58, "OK: text");
            }
        }
        Screen::Gallery => {
            if let Some(px) = &s.snark_pixels {
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
            }
            g.font(Font::Big);
            g.text(62, 14, "zkSNARKs");
            g.font(Font::Numbers);
            g.text(62, 38, &gfx::num(s.snark as u64));
            g.font(Font::Small);
            g.text(62, 50, if s.playing { if s.fast { ">> fast" } else { "> playing" } } else { "|| paused" });
            g.text(62, 61, "of 10000");
        }
        Screen::Collections(sel) => {
            g.title("Collections");
            menu(g, &COLLECTIONS, sel, 4, 24, 12);
            g.font(Font::Small);
            g.text(4, 61, "10,000 zkSNARKs NFTs");
        }
        Screen::Settings(sel) => {
            g.title("Settings");
            let net = if s.meta.map(|m| m.network) == Some(Network::Test) { "Network: testnet" } else { "Network: mainnet" };
            let items = [SETTINGS[0], SETTINGS[1], SETTINGS[2], net, SETTINGS[4], SETTINGS[5]];
            // Scrolls: the selected row stays in the five that fit.
            let first = sel.saturating_sub(SETTINGS_ROWS - 1);
            let end = (first + SETTINGS_ROWS) as usize;
            menu(g, &items[first as usize..end.min(items.len())], sel - first, 4, 21, 10);
        }
        Screen::Wipe => {
            g.title("Wipe wallet?");
            g.font(Font::Small);
            g.center(28, "Erases the seed from");
            g.center(38, "this Flipper. Only your");
            g.center(48, "written words restore it.");
            g.hints("Back", "Hold OK: wipe");
        }
        Screen::PairPrompt => {
            g.title("Phone wants in");
            g.font(Font::Small);
            g.center(28, "Share this wallet's");
            g.center(38, "viewing key with it?");
            g.center(48, "(it cannot spend)");
            g.hints("Back: no", "OK: yes");
        }
        Screen::Review(page) => {
            let Some(r) = &s.review else { return };
            if let Some(p) = r.payments.get(page as usize) {
                g.title(&["Send ", &gfx::num(page as u64 + 1), "/", &gfx::num(r.payments.len() as u64)].concat());
                g.font(Font::Big);
                g.center(24, &zec(p.value));
                g.wrapped(1, 33, &p.address, 21, 0, 3);
                g.hints("< >", "OK: next");
            } else {
                g.title("Confirm");
                g.font(Font::Small);
                g.text(2, 22, "Fee");
                g.right(126, 22, &zec(r.fee));
                g.text(2, 33, "Total out");
                g.right(126, 33, &zec(r.total_out()));
                g.text(2, 44, "Back to you");
                g.right(126, 44, &zec(r.change + r.to_self));
                g.hints("Back: refuse", "Hold OK: sign");
            }
        }
        Screen::Done { ok } => {
            if ok {
                g.shield(64, 24, 1000, 0);
            } else {
                g.font(Font::Big);
                g.center(30, "X");
            }
            g.font(Font::Small);
            g.center(54, s.note);
            g.hints("", "OK");
        }
        Screen::Message(text) => ui::draw_message(g, text),
    }
}
