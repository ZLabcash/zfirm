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

const HOME: [&str; 2] = ["Receive", "Settings"];
/// With a Wi-Fi board answering, the network gets its own entry.
const HOME_WIFI: [&str; 3] = ["Receive", "Blockchain", "Settings"];
const SETTINGS: [&str; 6] = ["Recovery words", "Viewing key", "Change PIN", "Wi-Fi network", "Lock", "Wipe wallet"];
/// Settings rows that fit under the title bar.
const SETTINGS_ROWS: u8 = 5;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Pin,
    Busy(&'static str),
    Home(u8),
    Receive { text: bool },
    Settings(u8),
    Wipe,
    PairPrompt,
    Review(u8),
    Done { ok: bool },
    Message(&'static str),
    /// With the Wi-Fi board: Activity or Stats.
    Chain(u8),
    /// The last signed transactions and where each stands.
    Activity(u8),
    /// One of them in detail (`State::shown`).
    Track,
    /// The network and the ZEC price.
    Network,
    /// "A Wi-Fi board is plugged in: let it go online?"
    WifiPrompt,
    /// The viewing key, as a QR code or as text (scrolled by `line`).
    ViewKey { text: bool, line: u8 },
}

/// A signed transaction, followed through the Wi-Fi board and kept on the SD card
/// (so a restart does not lose it).
struct Track {
    txid: [u8; 32],
    /// What left the wallet: payments and fee, in zatoshis.
    amount: u64,
    /// When it was signed (the Flipper's clock, local time, seconds).
    signed_at: u32,
    tx: wifi::Tx,
    /// Tick of the last question to the board.
    asked: u32,
}

/// Today's signed transactions: id, amount, time and last known state. Plain on the
/// card (like the wallet's receiving index): a reader learns which transactions are
/// yours, so only today's are kept, and at most `ACTIVITY_MAX`.
const ACTIVITY_PATH: &CStr = c"/ext/apps_data/zflip/activity.bin";
const ACTIVITY_MAX: usize = 10;
const ACTIVITY_RECORD: usize = 32 + 8 + 4 + 1 + 4 + 4;
const CHAIN: [&str; 2] = ["Activity", "Stats"];

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
    /// The Wi-Fi board's network, `None` when no board answers.
    wifi: Option<wifi::Net>,
    /// Today's, newest first, at most `ACTIVITY_MAX`.
    activity: Vec<Track>,
    /// The one on the Track screen.
    shown: usize,
    price: Option<wifi::Price>,
    network: Option<wifi::NetInfo>,
    /// The viewing key and its QR code, while shown.
    ufvk: Option<(String, Option<Qr>)>,
}

enum Job {
    Opened(Result<(vault::Meta, Arc<SigningKey>, Arc<orchard::keys::IncomingViewingKey>), vault::Error>),
    Address(u32, String, Option<Qr>),
    Reviewed(Result<Review, sign::Error>),
    Signed(Result<Vec<SpendSignature>, sign::Error>, Option<[u8; 32]>),
    ViewKey(String, Option<Qr>),
}

struct Session {
    link: Option<ble::Link>,
    decoder: Decoder,
    /// The protocol itself, shared with every ZFirm device.
    core: session::Session,
    board: Option<wifi::Board>,
    /// Ticks: until when to wait for a board's first answer, and its last answer.
    board_heard: u32,
    board_hello: u32,
    /// Tick of the last price and network questions.
    board_market: u32,
    /// A board answered since it was powered.
    board_seen: bool,
    /// The user's answer to the Wi-Fi prompt, for this run of the app.
    board_allowed: Option<bool>,
    /// The saved network was handed over and not yet acknowledged.
    board_wifi_sent: bool,
    /// The transaction the board was last asked about (its answer names none), and when.
    board_asking: Option<usize>,
    board_asked_at: u32,
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
    let shell = Shell::new(new_state(), draw);
    let mut session = Session {
        link: None,
        decoder: Decoder::new(),
        core: session::Session::new(),
        board: None,
        board_heard: 0,
        board_hello: 0,
        board_market: 0,
        board_seen: false,
        board_allowed: None,
        board_wifi_sent: false,
        board_asking: None,
        board_asked_at: 0,
    };
    loop {
        let key = shell.next_key();
        if let Some(job) = worker.poll() {
            finish(&shell, &mut worker, &mut session, job);
        }
        poll_link(&shell, &mut worker, &mut session);
        poll_board(&shell, &mut session);
        shell.state.lock().frame += 1;
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
    shell.clear(new_state());
    0
}

fn new_state() -> State {
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
        wifi: None,
        activity: Vec::new(),
        shown: 0,
        price: None,
        network: None,
        ufvk: None,
    }
}

/// A board silent this long is gone.
const BOARD_LOST_MS: u32 = 15_000;
/// How often to ask where a transaction stands.
const TRACK_EVERY_MS: u32 = 4000;
/// Confirmations after which a transaction is settled (and no longer followed).
const SETTLED: u32 = 10;
/// How often to refresh the price and the network's state (every block or so).
const MARKET_EVERY_MS: u32 = 60_000;

/// Powers the GPIO header and listens for a Wi-Fi board while ZFlip is open; without
/// one, ZFlip carries on exactly as before.
fn probe_board(session: &mut Session) {
    // Refused once: not again until ZFlip is opened again.
    if session.board.is_none() && session.board_allowed != Some(false) {
        session.board_seen = false;
        session.board = wifi::Board::open();
        session.board_hello = 0;
    }
}

fn poll_board(shell: &Shell<State>, session: &mut Session) {
    let Some(board) = session.board.as_mut() else { return };
    let now = unsafe { sys::furi_get_tick() };
    let mut s = shell.state.lock();
    let allowed = session.board_allowed == Some(true);
    while let Some(reply) = board.poll() {
        session.board_heard = now;
        session.board_seen = true;
        if !allowed {
            // Nothing goes to the board, and nothing it says is used, until the user agrees.
            continue;
        }
        match reply {
            wifi::Reply::Hello(net) => {
                // The saved network goes to a board that has none, or a newer one.
                if (net == wifi::Net::NoWifi || wifi::network_pending()) && !session.board_wifi_sent {
                    session.board_wifi_sent = board.send_wifi();
                }
                s.wifi = Some(net);
            }
            wifi::Reply::Tx(tx) => {
                if let Some(t) = session.board_asking.take().and_then(|i| s.activity.get_mut(i)) {
                    let changed = t.tx != tx && !matches!(tx, wifi::Tx::Offline | wifi::Tx::Error);
                    t.tx = tx;
                    if changed {
                        save_activity(&s.activity);
                    }
                }
            }
            wifi::Reply::WifiSaved => {
                wifi::network_delivered();
                s.wifi = Some(wifi::Net::Connecting);
            }
            wifi::Reply::Price(p) => s.price = Some(p),
            wifi::Reply::Net(n) => s.network = Some(n),
        }
    }
    let present = session.board_seen;
    // Ask once a board answers, when nothing else is on screen.
    let idle = matches!(
        s.screen,
        Screen::Home(_) | Screen::Receive { .. } | Screen::Settings(_)
    );
    if present && session.board_allowed.is_none() && idle {
        interrupt(&mut s, Screen::WifiPrompt);
        drop(s);
        shell.attention();
        s = shell.state.lock();
    }
    // Still probing: hello twice a second. Found: every five seconds, to follow its Wi-Fi.
    let every = if present { 5000 } else { 1000 };
    if now.wrapping_sub(session.board_hello) >= every {
        session.board_hello = now;
        board.hello();
    }
    if allowed {
        let online = s.wifi == Some(wifi::Net::Online);
        let stale = s.price.is_none() || now.wrapping_sub(session.board_market) >= MARKET_EVERY_MS;
        // Fresh on the Blockchain screen; otherwise once a minute (the price shows in reviews).
        let wanted =
            stale || (s.screen == Screen::Network && now.wrapping_sub(session.board_market) >= TRACK_EVERY_MS * 3);
        if online && wanted && now.wrapping_sub(session.board_market) >= 2000 {
            session.board_market = now;
            board.ask_price();
            board.ask_network();
        }
        // One question at a time (the answer does not say which transaction it is about).
        let waiting = session.board_asking.is_some() && now.wrapping_sub(session.board_asked_at) < 12_000;
        if online && !waiting {
            let next = s.activity.iter().position(|t| !settled(t) && now.wrapping_sub(t.asked) >= TRACK_EVERY_MS);
            if let Some(i) = next {
                s.activity[i].asked = now;
                session.board_asking = Some(i);
                session.board_asked_at = now;
                board.ask(&s.activity[i].txid);
            }
        }
    }
    // Silent for a while (unplugged): forget it, but keep listening (and powering the
    // header) for as long as ZFlip is open, so a board plugged in later is found too.
    if present && now.wrapping_sub(session.board_heard) >= BOARD_LOST_MS {
        if matches!(s.screen, Screen::Chain(_) | Screen::Activity(_) | Screen::Track | Screen::Network) {
            s.screen = Screen::Home(0);
        } else if s.screen == Screen::WifiPrompt {
            s.screen = s.resume;
        }
        s.wifi = None;
        session.board_seen = false;
        session.board_wifi_sent = false;
        // A board plugged in again asks again.
        if session.board_allowed == Some(true) {
            session.board_allowed = None;
        }
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
                s.activity = load_activity();
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
        Job::ViewKey(text, qr) => {
            let mut s = shell.state.lock();
            s.ufvk = Some((text, qr));
            if s.screen == Screen::Busy("Viewing key") {
                s.screen = Screen::ViewKey { text: false, line: 0 };
            }
        }
        Job::Reviewed(result) => {
            let step = session.core.reviewed(result);
            apply(shell, worker, session, step);
        }
        Job::Signed(result, txid) => {
            let signed = result.is_ok();
            let amount = shell.state.lock().review.as_ref().map_or(0, Review::total_out);
            let step = session.core.signed(result);
            apply(shell, worker, session, step);
            let mut s = shell.state.lock();
            if let (true, Some(txid)) = (signed, txid) {
                // Followed through the Wi-Fi board, if one is here now or later.
                let signed_at = now_secs();
                s.activity.retain(|t| same_day(t.signed_at, signed_at));
                s.activity.insert(0, Track { txid, amount, signed_at, tx: wifi::Tx::Asking, asked: 0 });
                s.activity.truncate(ACTIVITY_MAX);
                save_activity(&s.activity);
                // The board's pending answer was about a transaction now one row down.
                session.board_asking = None;
                s.shown = 0;
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
                    "Blockchain" => s.screen = Screen::Chain(0),
                    _ => s.screen = Screen::Settings(0),
                },
                Key::Back => return false,
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
                // Already derived at unlock (the phone gets it too): no PIN, no setup module.
                Key::Ok if sel == 1 => {
                    if let Some(account) = s.account.clone() {
                        s.screen = Screen::Busy("Viewing key");
                        worker.spawn(move || {
                            let text = account.ufvk();
                            let qr = Qr::address(&text);
                            Job::ViewKey(text, qr)
                        });
                    }
                }
                Key::Ok if sel == 2 => {
                    launch::after_exit(launch::SETUP, c"pin");
                    return false;
                }
                Key::Ok if sel == 3 => {
                    drop(s);
                    let note = ask_network(shell);
                    // A newer network goes to the board at its next hello.
                    session.board_wifi_sent = false;
                    shell.state.lock().screen = Screen::Message(note);
                    return true;
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
        Screen::Chain(sel) => match k {
            Key::Up | Key::Down => s.screen = Screen::Chain(1 - sel),
            Key::Ok if sel == 0 => s.screen = Screen::Activity(0),
            Key::Ok => s.screen = Screen::Network,
            Key::Back => s.screen = home_at(&s, "Blockchain"),
            _ => {}
        },
        Screen::Activity(sel) => {
            let n = s.activity.len() as u8;
            match k {
                Key::Up if n > 0 => s.screen = Screen::Activity((sel + n - 1) % n),
                Key::Down if n > 0 => s.screen = Screen::Activity((sel + 1) % n),
                Key::Ok if sel < n => {
                    s.shown = sel as usize;
                    s.screen = Screen::Track;
                }
                Key::Back => s.screen = Screen::Chain(0),
                _ => {}
            }
        }
        Screen::Track => match k {
            Key::Back => s.screen = Screen::Activity(s.shown as u8),
            // Ask again now.
            Key::Ok => {
                let i = s.shown;
                if let Some(t) = s.activity.get_mut(i) {
                    t.asked = 0;
                }
            }
            _ => {}
        },
        Screen::ViewKey { text, line } => match k {
            Key::Ok => s.screen = Screen::ViewKey { text: !text, line: 0 },
            Key::Down if text => s.screen = Screen::ViewKey { text, line: (line + 1).min(5) },
            Key::Up if text => s.screen = Screen::ViewKey { text, line: line.saturating_sub(1) },
            Key::Back => {
                s.ufvk = None;
                s.screen = Screen::Settings(1);
            }
            _ => {}
        },
        Screen::WifiPrompt => match k {
            Key::Ok => {
                session.board_allowed = Some(true);
                s.screen = s.resume;
                drop(s);
                shell.success();
            }
            Key::Back => {
                // Refused: power it off and leave it alone until ZFlip opens again.
                session.board_allowed = Some(false);
                session.board = None;
                s.wifi = None;
                s.screen = s.resume;
            }
            _ => {}
        },
        Screen::Network => {
            if k == Key::Back {
                s.screen = Screen::Chain(1);
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

/// The phone link, as a Bluetooth rune left of the Wi-Fi fan: steady once
/// paired, blinking while the phone connects, absent otherwise.
fn link_badge(g: &Gfx, s: &State) {
    if !s.paired && !(s.connected && (s.frame / 12) % 2 == 0) {
        return;
    }
    g.white();
    let (x, y) = (110, 1);
    g.line(x, y, x, y + 8);
    g.line(x, y, x + 2, y + 2);
    g.line(x + 2, y + 2, x - 2, y + 6);
    g.line(x, y + 8, x + 2, y + 6);
    g.line(x + 2, y + 6, x - 2, y + 2);
    g.black();
}

fn draw(g: &Gfx, s: &State) {
    match s.screen {
        Screen::Pin => s.pin.draw(g, "ZFlip: PIN", s.note),
        Screen::Busy(label) => ui::draw_busy(g, label, s.frame),
        Screen::Home(sel) => {
            g.title("ZFlip");
            link_badge(g, s);
            g.shield(18, 37, 1000, 0);
            let items = home_items(s);
            let sel = sel.min(items.len() as u8 - 1);
            menu(g, items, sel, 40, 23, 12);
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
        Screen::Settings(sel) => {
            g.title("Settings");
            let items = SETTINGS;
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
        Screen::ViewKey { text, line } => {
            let Some((key, qr)) = &s.ufvk else { return };
            if text {
                g.title("Viewing key");
                g.wrapped(1, 19, key, 21, line as usize, 5);
            } else {
                if let Some(qr) = qr {
                    g.qr(qr, 0);
                }
                g.font(Font::Big);
                g.text(68, 12, "Viewing");
                g.text(68, 24, "key");
                g.font(Font::Small);
                g.text(68, 36, "Sees, never");
                g.text(68, 45, "spends");
                g.text(68, 60, "OK: text");
            }
        }
        Screen::WifiPrompt => {
            g.title("Wi-Fi board");
            g.font(Font::Small);
            g.center(26, "Let it go online for");
            g.center(36, "prices and transactions?");
            g.center(46, "(it never gets your keys)");
            g.hints("Back: no", "OK: yes");
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
                    // To the nearest 1000 zatoshis, in u64 (u128 maths costs ~1.5 KiB of code).
                    let cents = (r.total_out() / 1000).saturating_mul(p.usd_cents) / (zfirm_core::COIN / 1000);
                    g.right(126, 56, &["~ ", &usd(cents)].concat());
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
        Screen::Chain(sel) => {
            g.title("Blockchain");
            wifi_badge(g, s);
            menu(g, &CHAIN, sel, 6, 26, 14);
            g.font(Font::Small);
            g.text(4, 61, "From ZScan, over Wi-Fi");
        }
        Screen::Activity(sel) => draw_activity(g, s, sel),
        Screen::Track => draw_track(g, s),
        Screen::Network => draw_network(g, s),
    }
}

/// "$1270.99" from cents.
fn usd(cents: u64) -> String {
    let c = num(cents % 100);
    ["$", &num(cents / 100), ".", if c.len() < 2 { "0" } else { "" }, &c].concat()
}

/// "+3.77%" from basis points.
fn percent(bp: i32) -> String {
    let (sign, n) = if bp < 0 { ("-", (-bp) as u64) } else { ("+", bp as u64) };
    let c = num(n % 100);
    [sign, &num(n / 100), ".", if c.len() < 2 { "0" } else { "" }, &c, "%"].concat()
}

/// The network and the ZEC price, as ZScan sees them.
fn draw_network(g: &Gfx, s: &State) {
    g.title("Stats");
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
        g.right(126, 32, &[usd(p.usd_cents).as_str(), "  ", &percent(p.change)].concat());
    }
    g.text(2, 42, "Transactions 24 h");
    g.right(126, 42, &num(n.txs_24h as u64));
    g.text(2, 52, "Shielded");
    g.right(126, 52, &[num(n.shielded as u64 / 10).as_str(), ".", &num(n.shielded as u64 % 10), "%"].concat());
    g.hints("Back", "");
}

/// The Wi-Fi network for the Wi-Fi board: its name, then its password, with the
/// Flipper's keyboard. Returns what to tell the user.
fn ask_network(shell: &Shell<State>) -> &'static str {
    let saved = wifi::saved_network();
    let current = saved.as_ref().map_or("", |(ssid, _)| ssid.as_str());
    let Some(ssid) = shell.ask_text(c"Wi-Fi network name", current, 32, 1) else { return "Wi-Fi unchanged" };
    // Never shown again once saved. Empty keeps it for the same network; for a new
    // one, empty means an open network.
    let same = saved.as_ref().is_some_and(|(s, _)| *s == ssid);
    let header = if same { c"Password (empty: keep)" } else { c"Password (empty: open)" };
    let Some(mut pass) = shell.ask_text(header, "", 64, 0) else { return "Wi-Fi unchanged" };
    if pass.is_empty() && same {
        pass = saved.map(|(_, p)| p).unwrap_or_default();
    }
    // WPA needs 8 characters or more.
    if !pass.is_empty() && pass.len() < 8 {
        return "Password too short:\nWi-Fi unchanged";
    }
    if wifi::save_network(&ssid, &pass) { "Saved: the Wi-Fi\nboard joins it" } else { "Could not save\nthe Wi-Fi network" }
}

fn home_items(s: &State) -> &'static [&'static str] {
    if s.wifi.is_some() { &HOME_WIFI } else { &HOME }
}

/// The home screen with `label` selected (where Back from that entry lands).
fn home_at(s: &State, label: &str) -> Screen {
    Screen::Home(home_items(s).iter().position(|l| *l == label).unwrap_or(0) as u8)
}

/// The last signed transactions, newest first: what left the wallet and where it stands.
fn draw_activity(g: &Gfx, s: &State, sel: u8) {
    g.title("Activity");
    wifi_badge(g, s);
    g.font(Font::Small);
    if s.activity.is_empty() {
        g.center(30, "No transaction today:");
        g.center(41, "they show here once signed");
        g.hints("Back", "");
        return;
    }
    // Four rows fit; the selected one stays in view.
    let first = sel.saturating_sub(3) as usize;
    for (row, t) in s.activity.iter().enumerate().skip(first).take(4) {
        let y = 22 + (row - first) as i32 * 11;
        if row == sel as usize {
            g.fill(0, y - 9, 128, 11);
            g.white();
        }
        g.text(2, y, &["-", &zec(t.amount)].concat());
        g.right(126, y, &status(t.tx));
        g.black();
    }
}

/// A transaction's state in a few characters.
fn status(tx: wifi::Tx) -> String {
    match tx {
        wifi::Tx::Mined { confirmations, .. } if confirmations >= SETTLED => "done".into(),
        wifi::Tx::Mined { confirmations, .. } => [num(confirmations as u64).as_str(), "/", &num(SETTLED as u64)].concat(),
        wifi::Tx::Mempool => "mempool".into(),
        wifi::Tx::Unknown => "not sent".into(),
        _ => "...".into(),
    }
}

fn load_activity() -> Vec<Track> {
    let mut out = Vec::new();
    let today = now_secs();
    let Ok(mut f) = OpenOptions::new().read(true).open_existing(true).open(ACTIVITY_PATH) else { return out };
    let mut r = [0u8; ACTIVITY_RECORD];
    while out.len() < ACTIVITY_MAX && f.read(&mut r).ok() == Some(ACTIVITY_RECORD) {
        let word = |i: usize| u32::from_le_bytes([r[i], r[i + 1], r[i + 2], r[i + 3]]);
        let signed_at = word(40);
        if !same_day(signed_at, today) {
            continue;
        }
        let tx = match r[44] {
            1 => wifi::Tx::Unknown,
            2 => wifi::Tx::Mempool,
            3 => wifi::Tx::Mined { height: word(45), confirmations: word(49) },
            _ => wifi::Tx::Asking,
        };
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&r[..32]);
        let mut amount = [0u8; 8];
        amount.copy_from_slice(&r[32..40]);
        out.push(Track { txid, amount: u64::from_le_bytes(amount), signed_at, tx, asked: 0 });
    }
    drop(f);
    // Older days go from the card too.
    save_activity(&out);
    out
}

fn now_secs() -> u32 {
    unsafe { sys::furi_hal_rtc_get_timestamp() }
}

/// Whether two of the Flipper's (local) timestamps fall on the same day.
fn same_day(a: u32, b: u32) -> bool {
    a / 86_400 == b / 86_400
}

fn save_activity(list: &[Track]) {
    let Ok(mut f) = OpenOptions::new().write(true).create_always(true).open(ACTIVITY_PATH) else { return };
    for t in list {
        let mut r = [0u8; ACTIVITY_RECORD];
        r[..32].copy_from_slice(&t.txid);
        r[32..40].copy_from_slice(&t.amount.to_le_bytes());
        r[40..44].copy_from_slice(&t.signed_at.to_le_bytes());
        let (kind, height, confirmations) = match t.tx {
            wifi::Tx::Unknown => (1, 0, 0),
            wifi::Tx::Mempool => (2, 0, 0),
            wifi::Tx::Mined { height, confirmations } => (3, height, confirmations),
            _ => (0, 0, 0),
        };
        r[44] = kind;
        r[45..49].copy_from_slice(&height.to_le_bytes());
        r[49..53].copy_from_slice(&confirmations.to_le_bytes());
        let _ = f.write(&r);
    }
}

fn settled(t: &Track) -> bool {
    matches!(t.tx, wifi::Tx::Mined { confirmations, .. } if confirmations >= SETTLED)
}

/// The Wi-Fi board, as the Wi-Fi fan in the title bar's right corner: whole once online,
/// its inner arc blinking while it joins, the dot alone without a network.
fn wifi_badge(g: &Gfx, s: &State) {
    let Some(net) = s.wifi else { return };
    g.white();
    let (cx, y) = (120, 9);
    g.dot(cx, y);
    let arcs = match net {
        wifi::Net::Online => 3,
        wifi::Net::Connecting if (s.frame / 12) % 2 == 0 => 1,
        _ => 0,
    };
    // Each arc as three strokes, wider and higher outwards.
    for r in 1..=arcs {
        let (w, h) = (2 * r, 2 * r);
        g.line(cx - w, y - h / 2, cx - w / 2, y - h);
        g.line(cx - w / 2, y - h, cx + w / 2, y - h);
        g.line(cx + w / 2, y - h, cx + w, y - h / 2);
    }
    g.black();
}

/// Where the last signed transaction stands: an hourglass while it waits, a block
/// once mined, and its confirmations.
fn draw_track(g: &Gfx, s: &State) {
    g.title("Transaction");
    wifi_badge(g, s);
    let Some(t) = s.activity.get(s.shown) else { return };
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
