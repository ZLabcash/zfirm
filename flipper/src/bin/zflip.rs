//! ZFlip — a Zcash shielded wallet for the Flipper Zero.
//!
//! Unlocks the sealed wallet, shows a fresh shielded receiving address each time
//! it opens and on each press of ▶ (as a QR code and text), and keeps a Bluetooth link to the ZFlip iPhone app for as long as it is
//! open: the phone gets the viewing key once the user agrees, follows the address
//! shown here, and sends transactions that ZFlip checks against their commitments
//! (see `zfirm_core::sign`), shows, and signs only on a long press of OK.
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
#[path = "../wifi.rs"]
mod wifi;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{ffi::CStr, sync::atomic::Ordering};

use flipperzero::{
    furi::rng::HwRng,
    io::{Read, Write},
    storage::OpenOptions,
};
use flipperzero_rt::{entry, manifest};
use flipperzero_sys as sys;
use zfirm_core::{
    Network,
    account::SigningKey,
    protocol::{self, Decoder, Info, error, msg},
    request::SpendSignature,
    session::{self, Show, Work},
    sign::{self, Review},
};

use crate::{
    gfx::{Font, Gfx, Qr, num, zec},
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
/// With a Wi-Fi board answering, the network gets its own entry.
const HOME_WIFI: [&str; 4] = ["Receive", "Network", "Collections", "Settings"];
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
    /// Where the last signed transaction stands (with the Wi-Fi board).
    Track,
    /// The network and the ZEC price (with the Wi-Fi board).
    Network,
}

/// The last signed transaction, followed through the Wi-Fi board.
struct Track {
    txid: [u8; 32],
    tx: wifi::Tx,
    /// Tick of the last question to the board.
    asked: u32,
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
    /// The Wi-Fi board's network, `None` when no board answers.
    wifi: Option<wifi::Net>,
    track: Option<Track>,
    price: Option<wifi::Price>,
    network: Option<wifi::NetInfo>,
}

enum Job {
    Opened(Result<(vault::Meta, Arc<SigningKey>, Arc<orchard::keys::IncomingViewingKey>), vault::Error>),
    Address(u32, String, Option<Qr>),
    Reviewed(Result<Review, sign::Error>),
    Signed(Result<Vec<SpendSignature>, sign::Error>, Option<[u8; 32]>),
}

struct Session {
    link: Option<ble::Link>,
    decoder: Decoder,
    /// The protocol itself, shared with every ZFirm device.
    core: session::Session,
    board: Option<wifi::Board>,
    /// Ticks: until when to wait for a board's first answer, and its last answer.
    board_probe_until: u32,
    board_heard: u32,
    board_hello: u32,
    /// Tick of the last price and network questions.
    board_market: u32,
}

/// What the shared session needs to know about this Flipper's wallet.
struct Host<'a>(&'a State);

impl session::Host for Host<'_> {
    fn info(&self) -> Option<Info> {
        info(self.0)
    }

    fn address(&self) -> Option<(u32, String)> {
        self.0.address.as_ref().map(|(j, text, _)| (*j, text.clone()))
    }
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
            wifi: None,
            track: None,
            price: None,
            network: None,
        },
        draw,
    );
    let mut session = Session {
        link: None,
        decoder: Decoder::new(),
        core: session::Session::new(),
        board: None,
        board_probe_until: 0,
        board_heard: 0,
        board_hello: 0,
        board_market: 0,
    };
    loop {
        let key = shell.next_key();
        if let Some(job) = worker.poll() {
            finish(&shell, &mut worker, &mut session, job);
        }
        poll_link(&shell, &mut worker, &mut session);
        poll_board(&shell, &mut session);
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
    session.board = None;
    0
}

/// How long a Wi-Fi board gets to answer after power-up (it boots in about a second).
const BOARD_PROBE_MS: u32 = 4000;
/// A board silent this long is gone.
const BOARD_LOST_MS: u32 = 15_000;
/// How often to ask where a transaction stands.
const TRACK_EVERY_MS: u32 = 4000;
/// Confirmations after which a transaction is settled (and no longer followed).
const SETTLED: u32 = 10;
/// How often to refresh the price and the network's state (every block or so).
const MARKET_EVERY_MS: u32 = 60_000;

/// Powers the GPIO header and looks for a Wi-Fi board for a few seconds; without
/// one, ZFlip carries on exactly as before.
fn probe_board(session: &mut Session) {
    if session.board.is_none() {
        session.board = wifi::Board::open();
        session.board_probe_until = unsafe { sys::furi_get_tick() }.wrapping_add(BOARD_PROBE_MS);
        session.board_hello = 0;
    }
}

fn poll_board(shell: &Shell<State>, session: &mut Session) {
    let Some(board) = session.board.as_mut() else { return };
    let now = unsafe { sys::furi_get_tick() };
    let mut s = shell.state.lock();
    while let Some(reply) = board.poll() {
        session.board_heard = now;
        match reply {
            wifi::Reply::Hello(net) => {
                // A board without a network gets the one saved on the SD card.
                if net == wifi::Net::NoWifi && s.wifi.is_none() {
                    board.send_wifi();
                }
                s.wifi = Some(net);
            }
            wifi::Reply::Tx(tx) => {
                if let Some(t) = s.track.as_mut() {
                    t.tx = tx;
                }
            }
            wifi::Reply::WifiSaved => s.wifi = Some(wifi::Net::Connecting),
            wifi::Reply::Price(p) => s.price = Some(p),
            wifi::Reply::Net(n) => s.network = Some(n),
        }
    }
    let present = s.wifi.is_some();
    // Still probing: hello twice a second. Found: every five seconds, to follow its Wi-Fi.
    let every = if present { 5000 } else { 500 };
    if now.wrapping_sub(session.board_hello) >= every {
        session.board_hello = now;
        board.hello();
    }
    let online = s.wifi == Some(wifi::Net::Online);
    let stale = s.price.is_none() || now.wrapping_sub(session.board_market) >= MARKET_EVERY_MS;
    // Fresh on the Network screen; otherwise once a minute (the price shows in reviews).
    let wanted = stale || (s.screen == Screen::Network && now.wrapping_sub(session.board_market) >= TRACK_EVERY_MS * 3);
    if online && wanted && now.wrapping_sub(session.board_market) >= 2000 {
        session.board_market = now;
        board.ask_price();
        board.ask_network();
    }
    if let Some(t) = s.track.as_mut() {
        if present && !settled(t) && now.wrapping_sub(t.asked) >= TRACK_EVERY_MS {
            t.asked = now;
            board.ask(&t.txid);
        }
    }
    let gone = if present {
        now.wrapping_sub(session.board_heard) >= BOARD_LOST_MS
    } else {
        (now.wrapping_sub(session.board_probe_until) as i32) >= 0
    };
    if gone {
        // No board (or it was unplugged): power the header off again.
        if s.wifi.is_some() && matches!(s.screen, Screen::Track | Screen::Network) {
            s.screen = Screen::Home(0);
        }
        s.wifi = None;
        drop(s);
        session.board = None;
    }
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

/// Carries out a step of the shared session: frames out, screen, work on the worker.
fn apply(shell: &Shell<State>, worker: &mut Worker<Job>, session: &mut Session, step: session::Step) {
    if let Some(link) = &session.link {
        for frame in &step.send {
            link.send(frame);
        }
    }
    let mut s = shell.state.lock();
    s.paired = session.core.paired();
    let account = s.account.clone();
    match step.show {
        Some(Show::PairPrompt) => {
            interrupt(&mut s, Screen::PairPrompt);
            drop(s);
            shell.attention();
        }
        Some(Show::Busy(label)) => interrupt(&mut s, Screen::Busy(label)),
        Some(Show::Review(review)) => {
            s.review = Some(review);
            s.screen = Screen::Review(0);
            drop(s);
            shell.attention();
        }
        Some(Show::Done { ok, note }) => {
            s.review = None;
            s.note = note;
            s.screen = Screen::Done { ok };
            drop(s);
            if ok { shell.success() } else { shell.error() }
        }
        Some(Show::Resume) => s.screen = s.resume,
        None => {}
    }
    let Some(account) = account else { return };
    match step.work {
        Some(Work::Review(req)) => worker.spawn(move || Job::Reviewed(stable::with(|| sign::review(&req, &*account)))),
        Some(Work::Sign(req)) => {
            worker.spawn(move || {
                let sigs = stable::with(|| sign::sign_reviewed(&req, &*account, HwRng));
                Job::Signed(sigs, sign::txid(&req).ok())
            })
        }
        None => {}
    }
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
        let raw = stable::with(|| zfirm_core::account::address_at(&ivk, j)).to_raw_address_bytes();
        let text = zfirm_core::ua::encode_orchard_address(meta.network, &raw);
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
            probe_board(session);
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
            s.address = Some((j, text.clone(), qr));
            if showing {
                s.screen = Screen::Receive { text: false };
            }
            drop(s);
            let step = session.core.address_changed(j, &text);
            apply(shell, worker, session, step);
        }
        Job::Reviewed(result) => {
            let step = session.core.reviewed(result);
            apply(shell, worker, session, step);
        }
        Job::Signed(result, txid) => {
            let signed = result.is_ok();
            let step = session.core.signed(result);
            apply(shell, worker, session, step);
            let mut s = shell.state.lock();
            if let (true, Some(txid)) = (signed, txid) {
                // Followed through the Wi-Fi board, if one is here now or later.
                s.track = Some(Track { txid, tx: wifi::Tx::Asking, asked: 0 });
                if s.wifi.is_some() {
                    s.screen = Screen::Track;
                }
            }
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
        Screen::Home(sel) => {
            let items = home_items(&s);
            let n = items.len() as u8;
            let sel = sel.min(n - 1);
            match k {
                Key::Up => s.screen = Screen::Home((sel + n - 1) % n),
                Key::Down => s.screen = Screen::Home((sel + 1) % n),
                Key::Ok => match items[sel as usize] {
                    "Receive" if s.address.is_some() => s.screen = Screen::Receive { text: false },
                    "Receive" => s.screen = Screen::Busy("Forging address"),
                    // The last transaction first while it is still being followed.
                    "Network" if s.track.as_ref().is_some_and(|t| !settled(t)) => s.screen = Screen::Track,
                    "Network" => s.screen = Screen::Network,
                    "Collections" => s.screen = Screen::Collections(0),
                    _ => s.screen = Screen::Settings(0),
                },
                Key::Back => return false,
                _ => {}
            }
        }
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
            Key::Back => s.screen = home_at(&s, "Collections"),
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
                Key::Back => s.screen = home_at(&s, "Settings"),
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
            Key::Ok | Key::Back => {
                let step = session.core.answer(k == Key::Ok, &Host(&s));
                drop(s);
                apply(shell, worker, session, step);
                if k == Key::Ok {
                    shell.success();
                }
            }
            _ => {}
        },
        Screen::Review(page) => {
            let pages = s.review.as_ref().map_or(1, Review::pages);
            match k {
                Key::Right | Key::Ok if page + 1 < pages => s.screen = Screen::Review(page + 1),
                Key::Left if page > 0 => s.screen = Screen::Review(page - 1),
                Key::LongOk | Key::Back | Key::LongBack if k != Key::LongOk || page + 1 == pages => {
                    let step = session.core.answer(k == Key::LongOk, &Host(&s));
                    drop(s);
                    apply(shell, worker, session, step);
                }
                _ => {}
            }
        }
        Screen::Done { .. } => {
            if matches!(k, Key::Ok | Key::Back) {
                s.screen = s.resume;
            }
        }
        Screen::Track => match k {
            Key::Back => s.screen = home_at(&s, "Network"),
            Key::Right => s.screen = Screen::Network,
            // Ask again now.
            Key::Ok => {
                if let Some(t) = s.track.as_mut() {
                    t.asked = 0;
                }
            }
            _ => {}
        },
        Screen::Network => match k {
            Key::Back => s.screen = home_at(&s, "Network"),
            Key::Left if s.track.is_some() => s.screen = Screen::Track,
            _ => {}
        },
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
        let dropped = s.connected && !connected;
        s.connected = connected;
        drop(s);
        if dropped {
            // A new connection must be approved again.
            session.decoder.reset();
            let step = session.core.disconnected();
            apply(shell, worker, session, step);
        }
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
            let step = session.core.bad_frame();
            apply(shell, worker, session, step);
        }
    }
}

fn handle(shell: &Shell<State>, worker: &mut Worker<Job>, session: &mut Session, f: protocol::Frame) {
    // The worker may be busy with an address: anything that needs it waits.
    let needs_worker = f.kind == msg::SIGN || (f.kind == msg::HELLO && !session.core.paired());
    if needs_worker && worker.busy() {
        return reply_error(session, error::BUSY, "Busy");
    }
    let step = session.core.frame(f, &Host(&shell.state.lock()));
    apply(shell, worker, session, step);
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
            let items = home_items(s);
            let sel = sel.min(items.len() as u8 - 1);
            // Four entries (with the Wi-Fi board) sit closer together.
            if items.len() > 3 { menu(g, items, sel, 40, 21, 10) } else { menu(g, items, sel, 40, 23, 12) }
            g.font(Font::Small);
            wifi_badge(g, s);
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
            if let Some((i, memo)) = r.page(page) {
                let p = &r.payments[i];
                let of = ["/", &gfx::num(r.payments.len() as u64)].concat();
                if memo {
                    // The memo was decrypted from the transaction itself, so it is what Bob reads.
                    g.title(&["Memo ", &gfx::num(i as u64 + 1), &of].concat());
                    let text = p.memo.as_deref().map(printable).unwrap_or_default();
                    g.wrapped(1, 20, &text, 21, 0, 5);
                } else {
                    g.title(&["Send ", &gfx::num(i as u64 + 1), &of].concat());
                    g.font(Font::Big);
                    g.center(24, &zec(p.value));
                    g.wrapped(1, 33, &p.address, 21, 0, 3);
                }
                g.hints("< >", "OK: next");
            } else {
                // What leaves the wallet, plainly. The change coming back was checked in the
                // review (it must be ours) and needs no line of its own.
                g.title("Confirm");
                g.font(Font::Small);
                // Several recipients: their sum, each one having had its own page.
                let n = r.payments.len();
                let label = if n > 1 { ["Payments (", &gfx::num(n as u64), ")"].concat() } else { "Payment".into() };
                g.text(2, 22, &label);
                g.right(126, 22, &zec(r.total_out() - r.fee));
                g.text(2, 33, "Fee");
                g.right(126, 33, &zec(r.fee));
                g.line(2, 37, 126, 37);
                g.text(2, 47, "Total");
                g.right(126, 47, &zec(r.total_out()));
                // In dollars, from the Wi-Fi board's price: a guide, never part of what is signed.
                if let Some(p) = s.price {
                    g.right(126, 56, &["~ ", &usd(r.total_out() as u128 * p.usd_cents as u128 / zfirm_core::COIN as u128)].concat());
                }
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
        Screen::Track => draw_track(g, s),
        Screen::Network => draw_network(g, s),
    }
}

/// "$1270.99" from cents.
fn usd(cents: u128) -> String {
    let c = num((cents % 100) as u64);
    [ "$", &num((cents / 100) as u64), ".", if c.len() < 2 { "0" } else { "" }, &c ].concat()
}

/// "+3.77%" from basis points.
fn percent(bp: i32) -> String {
    let (sign, n) = if bp < 0 { ("-", (-bp) as u64) } else { ("+", bp as u64) };
    let c = num(n % 100);
    [sign, &num(n / 100), ".", if c.len() < 2 { "0" } else { "" }, &c, "%"].concat()
}

/// The network and the ZEC price, as ZScan sees them.
fn draw_network(g: &Gfx, s: &State) {
    g.title("Zcash network");
    wifi_badge(g, s);
    g.font(Font::Small);
    let Some(n) = s.network else {
        g.center(36, if s.wifi == Some(wifi::Net::Online) { "Asking ZScan..." } else { "Wi-Fi board offline" });
        g.hints("Back", "");
        return;
    };
    g.text(2, 22, "Block");
    g.right(126, 22, &num(n.height as u64));
    if let Some(p) = s.price {
        g.text(2, 32, "ZEC");
        g.right(126, 32, &[usd(p.usd_cents as u128).as_str(), "  ", &percent(p.change)].concat());
    }
    g.text(2, 42, "Transactions 24 h");
    g.right(126, 42, &num(n.txs_24h as u64));
    g.text(2, 52, "Shielded");
    g.right(126, 52, &[num(n.shielded as u64 / 10).as_str(), ".", &num(n.shielded as u64 % 10), "%"].concat());
    g.hints("Back", if s.track.is_some() { "< Transaction" } else { "" });
}

fn home_items(s: &State) -> &'static [&'static str] {
    if s.wifi.is_some() { &HOME_WIFI } else { &HOME }
}

/// The home screen with `label` selected (where Back from that entry lands).
fn home_at(s: &State, label: &str) -> Screen {
    Screen::Home(home_items(s).iter().position(|l| *l == label).unwrap_or(0) as u8)
}

fn settled(t: &Track) -> bool {
    matches!(t.tx, wifi::Tx::Mined { confirmations, .. } if confirmations >= SETTLED)
}

/// The Wi-Fi board, as bars left of the phone badge: filled when online.
fn wifi_badge(g: &Gfx, s: &State) {
    let Some(net) = s.wifi else { return };
    g.white();
    for i in 0..3 {
        let (x, h) = (100 + i * 3, 3 + i * 2);
        if net == wifi::Net::Online {
            g.fill(x, 9 - h, 2, h);
        } else {
            g.dot(x, 8);
        }
    }
    g.black();
}

/// Where the last signed transaction stands: an hourglass while it waits, a block
/// once mined, and its confirmations.
fn draw_track(g: &Gfx, s: &State) {
    g.title("Transaction");
    wifi_badge(g, s);
    let Some(t) = &s.track else { return };
    let (lines, mined): ([&str; 2], Option<(u32, u32)>) = match (s.wifi, t.tx) {
        (Some(net), _) if net != wifi::Net::Online => (
            [
                "Wi-Fi board",
                match net {
                    wifi::Net::NoWifi => "needs wifi.txt",
                    wifi::Net::Failed => "cannot join Wi-Fi",
                    _ => "joining Wi-Fi...",
                },
            ],
            None,
        ),
        (_, wifi::Tx::Asking) => (["Asking ZScan", ""], None),
        (_, wifi::Tx::Unknown) => (["Not sent yet:", "phone sends it"], None),
        (_, wifi::Tx::Mempool) => (["In the mempool", "waiting for a block"], None),
        (_, wifi::Tx::Mined { height, confirmations }) => (["In block", ""], Some((height, confirmations))),
        (_, wifi::Tx::Offline) => (["Wi-Fi board", "offline"], None),
        (_, wifi::Tx::Error) => (["ZScan did not", "answer: retrying"], None),
    };
    g.font(Font::Small);
    g.text(36, 22, lines[0]);
    match mined {
        Some((height, confirmations)) => {
            block_icon(g, 6, 20, confirmations >= SETTLED);
            g.font(Font::Big);
            g.text(36, 35, &gfx::num(height as u64));
            g.font(Font::Small);
            let shown = confirmations.min(SETTLED);
            let label = [&gfx::num(shown as u64), "/", &gfx::num(SETTLED as u64), " confirmations"].concat();
            g.text(36, 46, &label);
            g.frame(36, 49, 88, 5);
            g.fill(37, 50, (86 * shown / SETTLED) as i32, 3);
        }
        None => {
            hourglass(g, 8, 17, s.frame);
            g.text(36, 33, lines[1]);
        }
    }
    // The txid's start, to match it in an explorer.
    let mut short = String::from("tx ");
    for b in &t.txid[..4] {
        short.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
        short.push(char::from(b"0123456789abcdef"[(b & 15) as usize]));
    }
    g.hints("Back", &short);
}

/// An hourglass whose sand runs down, then turns over.
fn hourglass(g: &Gfx, x: i32, y: i32, frame: u32) {
    const H: i32 = 16; // each bulb's height
    const W: i32 = 9; // half the width at the rim
    let cx = x + W;
    let phase = (frame % 64) as i32; // ~2.5 s per run
    let fallen = phase * H / 64;
    g.line(x, y, x + 2 * W, y);
    g.line(x, y + 2 * H, x + 2 * W, y + 2 * H);
    g.line(x + 1, y + 1, cx, y + H);
    g.line(x + 2 * W - 1, y + 1, cx, y + H);
    g.line(cx, y + H, x + 1, y + 2 * H - 1);
    g.line(cx, y + H, x + 2 * W - 1, y + 2 * H - 1);
    for r in 0..H - 1 {
        // Top bulb: sand below its sinking surface.
        if r >= fallen + 1 {
            let w = (H - r) * W / H - 1;
            if w > 0 {
                g.line(cx - w, y + r + 1, cx + w, y + r + 1);
            }
        }
        // Bottom bulb: the pile grows from the floor.
        if r >= H - 1 - fallen {
            let w = r * W / H - 1;
            if w > 0 {
                g.line(cx - w, y + H + r, cx + w, y + H + r);
            }
        }
    }
    // The falling grains.
    if fallen < H - 1 {
        for d in (((frame % 2) as i32)..(2 * H - 2 - fallen - H)).step_by(2) {
            g.dot(cx, y + H + 1 + d);
        }
    }
}

/// A block, with a check once the transaction is settled.
fn block_icon(g: &Gfx, x: i32, y: i32, settled: bool) {
    g.frame(x, y + 6, 18, 18);
    g.line(x, y + 6, x + 6, y);
    g.line(x + 18, y + 6, x + 23, y);
    g.line(x + 17, y + 23, x + 23, y + 17);
    g.line(x + 6, y, x + 23, y);
    g.line(x + 23, y, x + 23, y + 17);
    if settled {
        g.line(x + 4, y + 15, x + 7, y + 18);
        g.line(x + 7, y + 18, x + 13, y + 10);
    }
}


/// The Flipper's fonts are ASCII: anything else shows as `?`, line breaks as spaces.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            ' '..='~' => c,
            '\n' | '\r' | '\t' => ' ',
            _ => '?',
        })
        .collect()
}
