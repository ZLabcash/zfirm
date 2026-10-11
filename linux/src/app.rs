//! What the device shows and how it answers keys and frames, whatever the screen
//! and buttons: a [`Page`] to draw, [`Key`]s in, frames out.

use std::{os::unix::fs::DirBuilderExt, path::PathBuf};

use zeroize::Zeroizing;
use zfirm_core::{
    Account, Network, mnemonic,
    protocol::{Frame, Info},
    session::{self, Session, Show, Work},
    sign::{self, Review},
};

use crate::vault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Ok,
    /// OK held down: the deliberate gesture that signs or confirms a seed.
    Hold,
    Back,
    /// Typed on a keyboard (terminal), for PINs and words.
    Char(char),
}

/// One screen, in terms any display can draw.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Page {
    pub title: String,
    /// One prominent line (an amount).
    pub big: Option<String>,
    pub lines: Vec<String>,
    /// Label and amount pairs, amounts aligned right.
    pub rows: Vec<(String, String)>,
    /// Data to show as a QR code.
    pub qr: Option<String>,
    pub hints: (String, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Screen {
    Welcome(u8),
    /// Choosing how many words to restore.
    RestoreCount(u8),
    Restore,
    Words(u8),
    NewPin,
    ConfirmPin,
    Pin,
    Home,
    PairPrompt,
    Review(u8),
    Done { ok: bool, note: String },
    Busy(String),
    Message(String),
}

const WORD_COUNTS: [usize; 3] = [12, 18, 24];
const WORDS_PER_PAGE: usize = 4;
const MIN_PIN: usize = 4;

/// The unlocked wallet, as the session sees it.
struct Wallet {
    account: Option<Account>,
    index: u32,
    name: String,
}

impl session::Host for Wallet {
    fn info(&self) -> Option<Info> {
        let account = self.account.as_ref()?;
        Some(Info {
            network: account.network().to_byte(),
            account: 0,
            seed_fingerprint: account.seed_fingerprint(),
            ufvk: account.ufvk(),
            created_at: 0,
            device_name: self.name.clone(),
            address_index: self.index,
        })
    }

    fn address(&self) -> Option<(u32, String)> {
        Some((self.index, self.account.as_ref()?.encode_address(self.index)))
    }
}

pub struct App {
    dir: PathBuf,
    network: Network,
    screen: Screen,
    /// Where to go back after the phone interrupted.
    resume: Screen,
    wallet: Wallet,
    session: Session,
    review: Option<Review>,
    work: Option<Work>,
    out: Vec<Vec<u8>>,
    /// A new or restored seed's entropy, until it is sealed.
    entropy: Option<Zeroizing<Vec<u8>>>,
    /// Word entry while restoring.
    words: Vec<u16>,
    word_count: usize,
    prefix: String,
    letter: u8,
    pick: usize,
    pin: Zeroizing<String>,
    first_pin: Zeroizing<String>,
    note: String,
}

impl App {
    pub fn new(dir: PathBuf, network: Network, name: String) -> App {
        let screen = if vault::exists(&dir.join("wallet.zfv")) { Screen::Pin } else { Screen::Welcome(0) };
        App {
            dir,
            network,
            resume: Screen::Home,
            screen,
            wallet: Wallet { account: None, index: 0, name },
            session: Session::new(),
            review: None,
            work: None,
            out: Vec::new(),
            entropy: None,
            words: Vec::new(),
            word_count: 24,
            prefix: String::new(),
            letter: 0,
            pick: 0,
            pin: Zeroizing::new(String::new()),
            first_pin: Zeroizing::new(String::new()),
            note: String::new(),
        }
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("wallet.zfv")
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("address_index")
    }

    /// Frames to send to the phone.
    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    pub fn unlocked(&self) -> bool {
        self.wallet.account.is_some()
    }

    /// Slow work waiting to run (after the current page has been drawn).
    pub fn has_work(&self) -> bool {
        self.work.is_some()
    }

    /// Runs the pending work: reviewing or signing.
    pub fn run_work(&mut self) {
        let Some(work) = self.work.take() else { return };
        let Some(account) = self.wallet.account.as_ref() else { return };
        let step = match work {
            Work::Review(req) => self.session.reviewed(sign::review(&req, account)),
            Work::Sign(req) => {
                let mut rng = rand_core::OsRng;
                self.session.signed(sign::sign_reviewed(&req, account, &mut rng))
            }
        };
        self.apply(step);
    }

    pub fn frame(&mut self, f: Frame) {
        if !self.unlocked() {
            self.out.push(zfirm_core::protocol::encode(
                zfirm_core::protocol::msg::ERROR,
                &zfirm_core::protocol::encode_error(zfirm_core::protocol::error::LOCKED, "Locked"),
            ));
            return;
        }
        let step = self.session.frame(f, &self.wallet);
        self.apply(step);
    }

    pub fn bad_frame(&mut self) {
        let step = self.session.bad_frame();
        self.apply(step);
    }

    pub fn disconnected(&mut self) {
        let step = self.session.disconnected();
        self.apply(step);
    }

    fn apply(&mut self, step: session::Step) {
        self.out.extend(step.send);
        if let Some(work) = step.work {
            self.work = Some(work);
        }
        match step.show {
            Some(Show::PairPrompt) => self.interrupt(Screen::PairPrompt),
            Some(Show::Busy(label)) => self.interrupt(Screen::Busy(label.into())),
            Some(Show::Review(review)) => {
                self.review = Some(review);
                self.screen = Screen::Review(0);
            }
            Some(Show::Done { ok, note }) => {
                self.review = None;
                self.screen = Screen::Done { ok, note: note.into() };
            }
            Some(Show::Resume) => self.screen = self.resume.clone(),
            None => {}
        }
    }

    fn interrupt(&mut self, next: Screen) {
        if !matches!(
            self.screen,
            Screen::PairPrompt | Screen::Review(_) | Screen::Done { .. } | Screen::Busy(_)
        ) {
            self.resume = self.screen.clone();
        }
        self.screen = next;
    }

    pub fn key(&mut self, k: Key) {
        match self.screen.clone() {
            Screen::Welcome(sel) => match k {
                Key::Up | Key::Down => self.screen = Screen::Welcome(1 - sel),
                Key::Ok | Key::Right if sel == 0 => self.create(),
                Key::Ok | Key::Right => self.screen = Screen::RestoreCount(2),
                _ => {}
            },
            Screen::RestoreCount(sel) => match k {
                Key::Up => self.screen = Screen::RestoreCount(sel.saturating_sub(1)),
                Key::Down => self.screen = Screen::RestoreCount((sel + 1).min(2)),
                Key::Ok | Key::Right => {
                    self.word_count = WORD_COUNTS[sel as usize];
                    self.words.clear();
                    self.reset_word();
                    self.screen = Screen::Restore;
                }
                Key::Back => self.screen = Screen::Welcome(1),
                _ => {}
            },
            Screen::Restore => self.restore_key(k),
            Screen::Words(page) => {
                let pages = self.word_pages();
                match k {
                    Key::Right | Key::Ok if page + 1 < pages => self.screen = Screen::Words(page + 1),
                    Key::Left if page > 0 => self.screen = Screen::Words(page - 1),
                    Key::Hold if page + 1 == pages => {
                        self.pin.clear();
                        self.screen = Screen::NewPin;
                    }
                    Key::Back => {
                        self.entropy = None;
                        self.screen = Screen::Welcome(0);
                    }
                    _ => {}
                }
            }
            Screen::NewPin | Screen::ConfirmPin | Screen::Pin => self.pin_key(k),
            Screen::Home => match k {
                Key::Right => {
                    self.wallet.index += 1;
                    let _ = std::fs::write(self.index_path(), self.wallet.index.to_string());
                    if let Some(text) = self.wallet.account.as_ref().map(|a| a.encode_address(self.wallet.index)) {
                        let step = self.session.address_changed(self.wallet.index, &text);
                        self.apply(step);
                    }
                }
                Key::Back | Key::Hold => self.lock(),
                _ => {}
            },
            Screen::PairPrompt => match k {
                Key::Ok => self.answer(true),
                Key::Back => self.answer(false),
                _ => {}
            },
            Screen::Review(page) => {
                let pages = self.review.as_ref().map_or(1, Review::pages);
                match k {
                    Key::Right | Key::Ok if page + 1 < pages => self.screen = Screen::Review(page + 1),
                    Key::Left if page > 0 => self.screen = Screen::Review(page - 1),
                    Key::Hold if page + 1 == pages => self.answer(true),
                    Key::Back => self.answer(false),
                    _ => {}
                }
            }
            Screen::Done { .. } | Screen::Message(_) => {
                if matches!(k, Key::Ok | Key::Back) {
                    self.screen = if self.unlocked() {
                        Screen::Home
                    } else if vault::exists(&self.vault_path()) {
                        Screen::Pin
                    } else {
                        Screen::Welcome(0)
                    };
                }
            }
            Screen::Busy(_) => {}
        }
    }

    fn answer(&mut self, yes: bool) {
        let step = self.session.answer(yes, &self.wallet);
        self.apply(step);
    }

    fn lock(&mut self) {
        self.wallet.account = None;
        self.session = Session::new();
        self.screen = Screen::Pin;
    }

    fn create(&mut self) {
        let mut entropy = Zeroizing::new(vec![0u8; 32]);
        if getrandom::getrandom(&mut entropy).is_err() {
            self.screen = Screen::Message("No system randomness".into());
            return;
        }
        self.entropy = Some(entropy);
        self.screen = Screen::Words(0);
    }

    fn word_pages(&self) -> u8 {
        let words = self.entropy.as_ref().map_or(24, |e| e.len() * 3 / 4);
        words.div_ceil(WORDS_PER_PAGE) as u8
    }

    fn reset_word(&mut self) {
        self.prefix.clear();
        self.letter = 0;
        self.pick = 0;
    }

    fn candidates(&self) -> Vec<&'static str> {
        if self.prefix.is_empty() {
            return Vec::new();
        }
        english().by_prefix(&self.prefix).take(6).collect()
    }

    fn restore_key(&mut self, k: Key) {
        let candidates = self.candidates();
        // Few enough matches: pick one from the list.
        let picking = !candidates.is_empty() && candidates.len() <= 5;
        match k {
            Key::Char(c) if c.is_ascii_lowercase() => {
                self.prefix.push(c);
                self.pick = 0;
            }
            Key::Char(' ') | Key::Char('\n') if picking => self.accept_word(candidates[self.pick.min(candidates.len() - 1)]),
            Key::Up if picking => self.pick = self.pick.saturating_sub(1),
            Key::Down if picking => self.pick = (self.pick + 1).min(candidates.len() - 1),
            Key::Ok if picking => self.accept_word(candidates[self.pick.min(candidates.len() - 1)]),
            Key::Up => self.letter = (self.letter + 25) % 26,
            Key::Down => self.letter = (self.letter + 1) % 26,
            Key::Right | Key::Ok => {
                self.prefix.push((b'a' + self.letter) as char);
                self.pick = 0;
            }
            Key::Left | Key::Char('\x7f') => {
                if self.prefix.pop().is_none() {
                    self.words.pop();
                }
                self.pick = 0;
            }
            Key::Back => self.screen = Screen::RestoreCount(2),
            _ => {}
        }
    }

    fn accept_word(&mut self, word: &str) {
        let Some(index) = english().words().position(|w| w == word) else { return };
        self.words.push(index as u16);
        self.reset_word();
        if self.words.len() < self.word_count {
            return;
        }
        match mnemonic::entropy_of(&self.words) {
            Ok(entropy) => {
                self.entropy = Some(Zeroizing::new(entropy));
                self.words.clear();
                self.pin.clear();
                self.screen = Screen::NewPin;
            }
            Err(_) => {
                self.words.clear();
                self.screen = Screen::Message("These words do not check out: start again".into());
            }
        }
    }

    fn pin_key(&mut self, k: Key) {
        match k {
            Key::Char(c) if c.is_ascii_digit() => self.pin.push(c),
            Key::Up => self.pin_digit(1),
            Key::Down => self.pin_digit(9),
            Key::Right => self.pin.push('0'),
            Key::Left | Key::Char('\x7f') => {
                self.pin.pop();
            }
            Key::Ok | Key::Char('\n') if self.pin.len() >= MIN_PIN => self.pin_done(),
            Key::Back if self.screen != Screen::Pin => {
                self.entropy = None;
                self.screen = Screen::Welcome(0);
            }
            _ => {}
        }
    }

    /// Up and Down change the last digit (buttons only: there is no keyboard).
    fn pin_digit(&mut self, step: u8) {
        let last = self.pin.pop().and_then(|c| c.to_digit(10)).unwrap_or(0) as u8;
        self.pin.push((b'0' + (last + step) % 10) as char);
    }

    fn pin_done(&mut self) {
        let pin = std::mem::replace(&mut self.pin, Zeroizing::new(String::new()));
        match self.screen {
            Screen::NewPin => {
                self.first_pin = pin;
                self.screen = Screen::ConfirmPin;
            }
            Screen::ConfirmPin if *pin != *self.first_pin => {
                self.note = "PINs differ: again".into();
                self.screen = Screen::NewPin;
            }
            Screen::ConfirmPin => {
                let Some(entropy) = self.entropy.take() else { return };
                let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&self.dir);
                if vault::seal(&self.vault_path(), &entropy, self.network, &pin).is_err() {
                    self.screen = Screen::Message("Could not save the wallet".into());
                    return;
                }
                let _ = std::fs::remove_file(self.index_path());
                self.note.clear();
                self.screen = Screen::Busy("Opening".into());
                self.unlock_with(self.network, &entropy);
            }
            Screen::Pin => match vault::open(&self.vault_path(), &pin) {
                Ok((network, entropy)) => {
                    self.note.clear();
                    self.unlock_with(network, &entropy);
                }
                Err(vault::Error::WrongPin { attempts_left }) => {
                    self.note = format!("Wrong PIN: {attempts_left} tries left");
                }
                Err(vault::Error::Wiped) => self.screen = Screen::Message("Too many tries: wallet wiped".into()),
                Err(_) => self.screen = Screen::Message("Wallet file error".into()),
            },
            _ => {}
        }
    }

    fn unlock_with(&mut self, network: Network, entropy: &[u8]) {
        let account = mnemonic::indices_for(entropy)
            .and_then(|indices| mnemonic::sentence(&indices, &english()))
            .map(Zeroizing::new)
            .map(|sentence| Zeroizing::new(mnemonic::to_seed(&sentence, "", |_| {})))
            .and_then(|seed| Account::from_seed(&*seed, network, 0).ok());
        let Some(account) = account else {
            self.screen = Screen::Message("Wallet file error".into());
            return;
        };
        // A fresh address each time the wallet opens.
        let last = std::fs::read_to_string(self.index_path()).ok().and_then(|s| s.trim().parse::<u32>().ok());
        self.wallet.index = last.map_or(0, |j| j + 1);
        let _ = std::fs::write(self.index_path(), self.wallet.index.to_string());
        self.wallet.account = Some(account);
        self.screen = Screen::Home;
    }

    pub fn page(&self) -> Page {
        let hints = |l: &str, r: &str| (l.to_string(), r.to_string());
        match &self.screen {
            Screen::Welcome(sel) => Page {
                title: "ZFirm".into(),
                lines: vec![
                    "No wallet yet".into(),
                    format!("{}Create", if *sel == 0 { "> " } else { "  " }),
                    format!("{}Restore", if *sel == 1 { "> " } else { "  " }),
                ],
                hints: hints("", "OK"),
                ..Page::default()
            },
            Screen::RestoreCount(sel) => Page {
                title: "Restore".into(),
                lines: WORD_COUNTS
                    .iter()
                    .enumerate()
                    .map(|(i, n)| format!("{} {n} words", if i == *sel as usize { ">" } else { " " }))
                    .collect(),
                hints: hints("Back", "OK"),
                ..Page::default()
            },
            Screen::Restore => {
                let candidates = self.candidates();
                let picking = !candidates.is_empty() && candidates.len() <= 5;
                let mut lines = vec![format!(
                    "{}{}",
                    self.prefix,
                    if picking { String::new() } else { format!("[{}]", (b'a' + self.letter) as char) }
                )];
                if picking {
                    lines.extend(candidates.iter().enumerate().map(|(i, w)| {
                        format!("{} {w}", if i == self.pick { ">" } else { " " })
                    }));
                } else if self.prefix.len() >= 2 && candidates.is_empty() {
                    lines.push("no such word".into());
                }
                Page {
                    title: format!("Word {}/{}", self.words.len() + 1, self.word_count),
                    lines,
                    hints: hints("< delete", if picking { "OK: pick" } else { "> add" }),
                    ..Page::default()
                }
            }
            Screen::Words(page) => {
                let indices = self.entropy.as_ref().and_then(|e| mnemonic::indices_for(e)).unwrap_or_default();
                let first = *page as usize * WORDS_PER_PAGE;
                let list = english();
                let lines = indices
                    .iter()
                    .enumerate()
                    .skip(first)
                    .take(WORDS_PER_PAGE)
                    .map(|(i, &w)| format!("{:>2}. {}", i + 1, list.words().nth(w as usize).unwrap_or("?")))
                    .collect();
                let last = *page + 1 == self.word_pages();
                Page {
                    title: format!("Write down {}/{}", page + 1, self.word_pages()),
                    lines,
                    hints: hints("< >", if last { "Hold OK: done" } else { "OK: next" }),
                    ..Page::default()
                }
            }
            Screen::NewPin | Screen::ConfirmPin | Screen::Pin => {
                let title = match self.screen {
                    Screen::NewPin => "Choose a PIN",
                    Screen::ConfirmPin => "PIN again",
                    _ => "PIN",
                };
                let shown: String = match self.pin.len() {
                    0 => "_".into(),
                    n => "*".repeat(n - 1) + &self.pin[n - 1..],
                };
                Page {
                    title: title.into(),
                    big: Some(shown),
                    lines: vec![self.note.clone()],
                    hints: hints("^v digit  > next", "OK"),
                    ..Page::default()
                }
            }
            Screen::Home => {
                let address = self.wallet.account.as_ref().map(|a| a.encode_address(self.wallet.index));
                let link = if self.session.paired() { "phone paired" } else { "no phone" };
                Page {
                    title: format!("Receive #{}", self.wallet.index),
                    lines: vec![address.clone().unwrap_or_default(), link.into()],
                    qr: address,
                    hints: hints("Back: lock", "> new"),
                    ..Page::default()
                }
            }
            Screen::PairPrompt => Page {
                title: "Phone wants in".into(),
                lines: vec!["Share this wallet's".into(), "viewing key with it?".into(), "(it cannot spend)".into()],
                hints: hints("Back: no", "OK: yes"),
                ..Page::default()
            },
            Screen::Review(page) => self.review_page(*page),
            Screen::Done { ok, note } => Page {
                title: if *ok { "Done".into() } else { "Not signed".into() },
                lines: vec![note.clone()],
                hints: hints("", "OK"),
                ..Page::default()
            },
            Screen::Busy(label) => Page { title: format!("{label}..."), ..Page::default() },
            Screen::Message(text) => Page {
                title: "ZFirm".into(),
                lines: vec![text.clone()],
                hints: hints("", "OK"),
                ..Page::default()
            },
        }
    }

    fn review_page(&self, page: u8) -> Page {
        let Some(r) = &self.review else { return Page::default() };
        let of = r.payments.len();
        match r.page(page) {
            Some((i, false)) => Page {
                title: format!("Send {}/{of}", i + 1),
                big: Some(zec(r.payments[i].value)),
                lines: vec![r.payments[i].address.clone()],
                hints: ("< >".into(), "OK: next".into()),
                ..Page::default()
            },
            Some((i, true)) => Page {
                title: format!("Memo {}/{of}", i + 1),
                lines: vec![r.payments[i].memo.clone().unwrap_or_default()],
                hints: ("< >".into(), "OK: next".into()),
                ..Page::default()
            },
            None => Page {
                title: "Confirm".into(),
                rows: vec![
                    (if of > 1 { format!("Payments ({of})") } else { "Payment".into() }, zec(r.total_out() - r.fee)),
                    ("Fee".into(), zec(r.fee)),
                    ("Total".into(), zec(r.total_out())),
                ],
                hints: ("Back: refuse".into(), "Hold OK: sign".into()),
                ..Page::default()
            },
        }
    }
}

fn english() -> mnemonic::Packed<'static> {
    mnemonic::Packed::new(mnemonic::ENGLISH).expect("embedded list")
}


/// Zatoshis as ZEC, without trailing zeros.
pub fn zec(zats: u64) -> String {
    let whole = zats / 100_000_000;
    let frac = zats % 100_000_000;
    if frac == 0 {
        return format!("{whole} ZEC");
    }
    let frac = format!("{frac:08}");
    format!("{whole}.{} ZEC", frac.trim_end_matches('0'))
}
