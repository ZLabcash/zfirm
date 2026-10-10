//! ZFlip's setup module: create or restore the wallet, show its recovery words,
//! switch network. Kept out of the Apps menu (see `launch.rs`): ZFlip starts it with
//! an argument ("create", "reveal" or "network") and it starts ZFlip again when done.

#![no_main]
#![no_std]

extern crate alloc;
extern crate flipperzero_alloc;
extern crate flipperzero_rt;

#[path = "../gfx.rs"]
mod gfx;
#[path = "../launch.rs"]
mod launch;
#[path = "../seed.rs"]
mod seed;
#[path = "../stable.rs"]
mod stable;
#[path = "../sync.rs"]
mod sync;
#[path = "../ui.rs"]
mod ui;
#[path = "../vault.rs"]
mod vault;

use alloc::{string::String, vec::Vec};
use core::{ffi::CStr, sync::atomic::Ordering};

use flipperzero::furi::rng::HwRng;
use flipperzero_rt::{entry, manifest};
use rand_core::RngCore;
use zflip_core::{Network, mnemonic};

use crate::{
    gfx::{Font, Gfx},
    ui::{Key, PROGRESS, Pin, PinPad, Shell, Worker},
};

manifest!(name = "ZFlip setup", app_version = 2, has_icon = false, stack_size = 4096);
entry!(main);

#[derive(Clone, Copy, PartialEq, Eq)]
enum PinFor {
    New,
    Confirm,
    Reveal,
    Network,
    ViewKey,
    /// The current PIN, before choosing a new one.
    Current,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome(u8),
    ShowWords(u8),
    RestoreCount(u8),
    RestoreWord,
    Pin(PinFor),
    Busy(&'static str),
    Message(&'static str),
    ViewingKey { text: bool, line: u8 },
}

struct WordEntry {
    prefix: String,
    letter: u8,
    pick: usize,
}

impl WordEntry {
    const fn new() -> Self {
        WordEntry { prefix: String::new(), letter: 0, pick: 0 }
    }
}

struct State {
    screen: Screen,
    frame: u32,
    indices: Vec<u16>,
    page_words: Vec<String>,
    matches: usize,
    shown: Vec<String>,
    restored: bool,
    restore_count: usize,
    entry: WordEntry,
    pin: PinFor,
    pad: PinPad,
    new_pin: Vec<u8>,
    note: &'static str,
    /// Showing an existing wallet's words (not a new seed to write down).
    revealing: bool,
    /// Set when the job is done: hand back to ZFlip.
    done: bool,
    ufvk: Option<(String, Option<gfx::Qr>)>,
    /// Changing the PIN: the wallet opened with the current one, to seal again.
    changing: Option<(vault::Meta, vault::Secret)>,
}

impl State {
    fn load_page(&mut self, page: u8) {
        let start = (page as usize * 4).min(self.indices.len());
        let end = (start + 4).min(self.indices.len());
        self.page_words = seed::words_at(&self.indices[start..end]).unwrap_or_default();
        self.screen = Screen::ShowWords(page);
    }

    fn load_matches(&mut self) {
        let start = self.entry.pick.saturating_sub(1);
        let (count, shown) = seed::by_prefix(&self.entry.prefix, start, 3);
        self.matches = count;
        self.shown = shown;
    }

    fn ask_pin(&mut self, purpose: PinFor) {
        self.pad.clear();
        self.pin = purpose;
        self.screen = Screen::Pin(purpose);
    }
}

enum Job {
    Created(Result<(), vault::Error>),
    Revealed(Result<Vec<u16>, vault::Error>),
    ViewKey(Result<(String, Option<gfx::Qr>), vault::Error>),
    Opened(Result<(vault::Meta, vault::Secret), vault::Error>),
}

fn main(args: Option<&CStr>) -> i32 {
    let arg = args.and_then(|a| a.to_str().ok()).unwrap_or("create");
    let exists = vault::exists();
    let start = match arg {
        "reveal" if exists => Screen::Pin(PinFor::Reveal),
        "network" if exists => Screen::Pin(PinFor::Network),
        "viewkey" if exists => Screen::Pin(PinFor::ViewKey),
        "pin" if exists => Screen::Pin(PinFor::Current),
        _ if exists => {
            // Nothing to set up: back to ZFlip.
            launch::after_exit(launch::MAIN, c"");
            return 0;
        }
        _ => Screen::Welcome(0),
    };
    let pin = match start {
        Screen::Pin(p) => p,
        _ => PinFor::New,
    };
    let mut worker = Worker::new(10 * 1024);
    let shell = Shell::new(
        State {
            screen: start,
            frame: 0,
            indices: Vec::new(),
            page_words: Vec::new(),
            matches: 0,
            shown: Vec::new(),
            restored: false,
            restore_count: 24,
            entry: WordEntry::new(),
            pin,
            pad: PinPad::new(),
            new_pin: Vec::new(),
            note: "",
            revealing: false,
            done: false,
            ufvk: None,
            changing: None,
        },
        draw,
    );
    loop {
        let key = shell.next_key();
        if let Some(job) = worker.poll() {
            finish(&shell, job);
        }
        shell.state.lock().frame += 1;
        if shell.state.lock().done {
            break;
        }
        let Some(k) = key else { continue };
        if worker.busy() {
            continue;
        }
        if !input(&shell, &mut worker, k) {
            break;
        }
    }
    worker.wait();
    // Back to ZFlip, unless there is still no wallet (the user gave up on setup).
    if vault::exists() {
        launch::after_exit(launch::MAIN, c"");
    }
    0
}

fn finish(shell: &Shell<State>, job: Job) {
    let mut s = shell.state.lock();
    match job {
        Job::Created(Ok(())) => {
            s.done = true;
            drop(s);
            shell.success();
        }
        Job::ViewKey(Ok(key)) => {
            s.ufvk = Some(key);
            s.screen = Screen::ViewingKey { text: false, line: 0 };
        }
        Job::Revealed(Ok(indices)) => {
            s.indices = indices;
            s.revealing = true;
            s.load_page(0);
        }
        Job::Opened(Ok(opened)) => {
            s.changing = Some(opened);
            s.ask_pin(PinFor::New);
        }
        Job::Created(Err(e)) | Job::Revealed(Err(e)) | Job::ViewKey(Err(e)) | Job::Opened(Err(e)) => {
            s.screen = match e {
                vault::Error::WrongPin { .. } => {
                    s.note = "Wrong PIN";
                    let again = s.pin;
                    Screen::Pin(again)
                }
                vault::Error::Wiped => Screen::Message("Too many tries:\nwallet wiped"),
                vault::Error::Enclave => Screen::Message("Secure enclave error"),
                vault::Error::Missing => Screen::Message("Copy english.txt to\napps_data/zflip"),
                _ => Screen::Message("Wallet file error"),
            };
            drop(s);
            shell.error();
        }
    }
}

/// Returns false to quit (ZFlip is started again on the way out).
fn input(shell: &Shell<State>, worker: &mut Worker<Job>, k: Key) -> bool {
    let mut s = shell.state.lock();
    match s.screen {
        Screen::Welcome(sel) => match k {
            Key::Up | Key::Down => s.screen = Screen::Welcome(sel ^ 1),
            Key::Ok if !seed::words_present() => s.screen = Screen::Message("Copy english.txt to\napps_data/zflip"),
            Key::Ok if sel == 0 => {
                let mut entropy = [0u8; 32];
                HwRng.fill_bytes(&mut entropy);
                s.indices = mnemonic::indices_from_entropy(&entropy).to_vec();
                entropy.iter_mut().for_each(|b| *b = 0);
                s.restored = false;
                s.load_page(0);
            }
            Key::Ok => s.screen = Screen::RestoreCount(1),
            Key::Back => return false,
            _ => {}
        },
        Screen::ShowWords(page) => {
            let pages = (s.indices.len() / 4) as u8;
            match k {
                Key::Right | Key::Ok if page + 1 < pages => s.load_page(page + 1),
                Key::Left if page > 0 => s.load_page(page - 1),
                Key::LongOk | Key::Back | Key::LongBack if s.revealing => return false,
                Key::LongOk if page + 1 == pages => s.ask_pin(PinFor::New),
                Key::LongBack => {
                    s.indices.clear();
                    s.screen = Screen::Welcome(0);
                }
                _ => {}
            }
        }
        Screen::RestoreCount(sel) => match k {
            Key::Up | Key::Down => s.screen = Screen::RestoreCount(sel ^ 1),
            Key::Ok => {
                s.restore_count = if sel == 0 { 12 } else { 24 };
                s.indices.clear();
                s.entry = WordEntry::new();
                s.restored = true;
                s.load_matches();
                s.screen = Screen::RestoreWord;
            }
            Key::Back => s.screen = Screen::Welcome(1),
            _ => {}
        },
        Screen::RestoreWord => restore_key(&mut s, k),
        Screen::Pin(purpose) => match s.pad.key(k) {
            Pin::Editing => {}
            Pin::Cancel => match purpose {
                PinFor::Reveal | PinFor::Network | PinFor::ViewKey | PinFor::Current => return false,
                PinFor::New | PinFor::Confirm if s.changing.is_some() => return false,
                PinFor::New | PinFor::Confirm => s.screen = Screen::Welcome(0),
            },
            Pin::Entered(pin) => {
                s.note = "";
                pin_entered(&mut s, worker, purpose, pin);
            }
        },
        Screen::Busy(_) => {}
        Screen::Message(_) => {
            if matches!(k, Key::Ok | Key::Back) {
                return false;
            }
        }
        Screen::ViewingKey { text, line } => match k {
            Key::Ok => s.screen = Screen::ViewingKey { text: !text, line: 0 },
            Key::Down if text => s.screen = Screen::ViewingKey { text, line: (line + 1).min(8) },
            Key::Up if text => s.screen = Screen::ViewingKey { text, line: line.saturating_sub(1) },
            Key::Back | Key::LongBack => return false,
            _ => {}
        },
    }
    true
}

fn restore_key(s: &mut State, k: Key) {
    let matches = s.matches;
    let e = &mut s.entry;
    match k {
        Key::Left => e.letter = (e.letter + 25) % 26,
        Key::Right => e.letter = (e.letter + 1) % 26,
        Key::Up if matches > 0 => e.pick = (e.pick + matches - 1) % matches,
        Key::Down if matches > 0 => e.pick = (e.pick + 1) % matches,
        Key::Ok => {
            e.prefix.push((b'a' + e.letter) as char);
            if seed::by_prefix(&e.prefix, 0, 0).0 == 0 {
                e.prefix.pop();
            }
            e.pick = 0;
        }
        Key::LongOk if matches > 0 => {
            let word = seed::by_prefix(&e.prefix, e.pick, 1).1.pop().unwrap_or_default();
            if let Some(i) = seed::find_word(&word) {
                s.indices.push(i);
            }
            s.entry = WordEntry::new();
            if s.indices.len() == s.restore_count {
                if mnemonic::validate(&s.indices).is_ok() {
                    s.ask_pin(PinFor::New);
                } else {
                    s.indices.clear();
                    s.screen = Screen::Message("Checksum wrong:\ncheck your words");
                }
            }
        }
        Key::Back => {
            if e.prefix.pop().is_none() {
                s.indices.pop();
            }
            s.entry.pick = 0;
        }
        Key::LongBack => {
            s.indices.clear();
            s.screen = Screen::Welcome(1);
        }
        _ => {}
    }
    if s.screen == Screen::RestoreWord {
        s.load_matches();
    }
}

fn pin_entered(s: &mut State, worker: &mut Worker<Job>, purpose: PinFor, pin: Vec<u8>) {
    match purpose {
        PinFor::New => {
            s.new_pin = pin;
            s.ask_pin(PinFor::Confirm);
        }
        PinFor::Confirm if s.new_pin != pin => {
            s.new_pin.clear();
            s.note = "PINs differ, again";
            s.ask_pin(PinFor::New);
        }
        PinFor::Confirm if s.changing.is_some() => {
            let Some((meta, secret)) = s.changing.take() else { return };
            s.new_pin.clear();
            s.screen = Screen::Busy("Sealing");
            worker.spawn(move || {
                Job::Created(vault::seal(&secret, meta.network, meta.created_at, &meta.change, &pin, &mut |p| {
                    PROGRESS.store(p, Ordering::Relaxed)
                }))
            });
        }
        PinFor::Current => {
            s.screen = Screen::Busy("Unlocking");
            worker.spawn(move || Job::Opened(vault::unseal(&pin, &mut |p| PROGRESS.store(p, Ordering::Relaxed))));
        }
        PinFor::Confirm => {
            let entropy = seed::entropy_of(&core::mem::take(&mut s.indices));
            // A new seed's birthday is now; a restored one is unknown.
            let created_at = if s.restored { 0 } else { unsafe { flipperzero_sys::furi_hal_rtc_get_timestamp() } };
            s.page_words.clear();
            s.new_pin.clear();
            s.screen = Screen::Busy("Forging wallet");
            worker.spawn(move || Job::Created(create(&entropy, Network::Main, created_at, &pin)));
        }
        PinFor::Reveal => {
            s.screen = Screen::Busy("Unlocking");
            worker.spawn(move || {
                Job::Revealed(
                    vault::unseal(&pin, &mut |p| PROGRESS.store(p, Ordering::Relaxed))
                        .map(|(_, secret)| seed::indices_of(secret.entropy())),
                )
            });
        }
        PinFor::ViewKey => {
            s.screen = Screen::Busy("Unlocking");
            worker.spawn(move || {
                Job::ViewKey(vault::unseal(&pin, &mut |p| PROGRESS.store(p, Ordering::Relaxed)).and_then(
                    |(meta, secret)| {
                        let key = stable::with(|| {
                            zflip_core::account::SigningKey::from_parts(meta.network, secret.sk, secret.seed_fp, meta.change)
                        })
                        .ok_or(vault::Error::Corrupt)?;
                        let text = key.ufvk();
                        let qr = gfx::Qr::encode(&text);
                        Ok((text, qr))
                    },
                ))
            });
        }
        PinFor::Network => {
            s.screen = Screen::Busy("Switching network");
            worker.spawn(move || {
                Job::Created(vault::unseal(&pin, &mut half).and_then(|(meta, secret)| {
                    let next = if meta.network == Network::Main { Network::Test } else { Network::Main };
                    create(secret.entropy(), next, meta.created_at, &pin)
                }))
            });
        }
    }
}

/// Derives the account (seed, ZIP 32, viewing keys) and seals it with `pin`.
fn create(entropy: &[u8], network: Network, created_at: u32, pin: &[u8]) -> Result<(), vault::Error> {
    let account = seed::open_account(entropy, network).ok_or(vault::Error::Missing)?;
    let change = stable::with(|| account.address_in(orchard::keys::Scope::Internal, 0)).to_raw_address_bytes();
    vault::reset_addresses();
    let mut secret = vault::Secret {
        entropy: [0; 32],
        entropy_len: entropy.len(),
        sk: account.sk_bytes(),
        seed_fp: account.seed_fingerprint(),
    };
    secret.entropy[..entropy.len()].copy_from_slice(entropy);
    // The seed derivation reported 0–100; the vault KDF now refills the bar.
    vault::seal(&secret, network, created_at, &change, pin, &mut |p| PROGRESS.store(p, Ordering::Relaxed))
}

/// The vault KDF reports the first half of the progress bar.
fn half(p: u32) {
    PROGRESS.store(p / 2, Ordering::Relaxed);
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

fn draw(g: &Gfx, s: &State) {
    match s.screen {
        Screen::Welcome(sel) => {
            g.title("ZFlip");
            g.shield(22, 38, 1000, 0);
            menu(g, &["Create wallet", "Restore wallet"], sel, 46, 30, 15);
            g.hints("", "Zcash shielded");
        }
        Screen::ShowWords(page) => {
            let pages = s.indices.len() / 4;
            let title = if s.revealing { "Your words" } else { "Write down" };
            g.title(&alloc::format!("{title} {}/{}", page + 1, pages));
            g.font(Font::Small);
            for (k, w) in s.page_words.iter().enumerate() {
                let i = page as usize * 4 + k;
                let (x, y) = (4 + (k as i32 % 2) * 64, 27 + (k as i32 / 2) * 14);
                g.text(x, y, &alloc::format!("{}. {}", i + 1, w));
            }
            g.hints(
                "< >",
                if s.revealing {
                    "Hold OK: close"
                } else if page as usize + 1 == pages {
                    "Hold OK: done"
                } else {
                    "OK: next"
                },
            );
        }
        Screen::RestoreCount(sel) => {
            g.title("Restore");
            menu(g, &["12 words", "24 words"], sel, 44, 30, 15);
        }
        Screen::RestoreWord => {
            g.title(&alloc::format!("Word {}/{}", s.indices.len() + 1, s.restore_count));
            g.font(Font::Big);
            g.text(4, 26, &alloc::format!("{}[{}]", s.entry.prefix, (b'a' + s.entry.letter) as char));
            g.font(Font::Small);
            let start = s.entry.pick.saturating_sub(1);
            for (row, w) in s.shown.iter().enumerate() {
                let y = 37 + row as i32 * 9;
                if start + row == s.entry.pick {
                    g.text(70, y, ">");
                }
                g.text(76, y, w);
            }
            g.text(4, 46, &alloc::format!("{} match", s.matches));
            g.hints("<>letter OK add", "Hold OK: pick");
        }
        Screen::Pin(purpose) => s.pad.draw(
            g,
            match purpose {
                PinFor::New => "New PIN (6-10)",
                PinFor::Confirm => "Confirm PIN",
                PinFor::Reveal => "PIN to show words",
                PinFor::Network => "PIN to switch net",
                PinFor::ViewKey => "PIN: viewing key",
                PinFor::Current => "Current PIN",
            },
            s.note,
        ),
        Screen::Busy(label) => ui::draw_busy(g, label, s.frame),
        Screen::Message(text) => ui::draw_message(g, text),
        Screen::ViewingKey { text, line } => {
            let Some((key, qr)) = &s.ufvk else { return };
            if text {
                g.title("Viewing key");
                g.wrapped(1, 19, key, 21, line as usize, 6);
            } else {
                match qr {
                    Some(qr) => g.qr(qr, 0),
                    None => g.text(4, 32, "QR too large"),
                }
                g.font(Font::Big);
                g.text(68, 12, "Viewing");
                g.text(68, 24, "key");
                g.font(Font::Small);
                g.text(68, 36, "Sees, can't");
                g.text(68, 45, "spend");
                g.text(68, 60, "OK: text");
            }
        }
    }
}
