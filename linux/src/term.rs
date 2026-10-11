//! A terminal as the device's screen and buttons: for a computer, an SSH session or
//! any board without a display of its own.
//!
//! Keys: arrows, Enter = OK, Tab = hold OK, Esc = Back, letters and digits type.

use std::io::{Read, Write};

use zfirm_core::qr::Qr;

use crate::app::{Key, Page};

pub struct Terminal {
    saved: Option<libc::termios>,
    pending: Vec<u8>,
    last: Option<Page>,
}

impl Terminal {
    pub fn new() -> Terminal {
        let saved = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            (libc::tcgetattr(0, &mut t) == 0).then(|| {
                let saved = t;
                t.c_lflag &= !(libc::ICANON | libc::ECHO);
                t.c_cc[libc::VMIN] = 0;
                t.c_cc[libc::VTIME] = 0;
                libc::tcsetattr(0, libc::TCSANOW, &t);
                saved
            })
        };
        // Never wait for a key, even when stdin is a pipe rather than a terminal.
        unsafe {
            let flags = libc::fcntl(0, libc::F_GETFL);
            libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Terminal { saved, pending: Vec::new(), last: None }
    }

    /// The next key pressed, if any (never blocks).
    pub fn key(&mut self) -> Option<Key> {
        let mut buf = [0u8; 64];
        if let Ok(n) = std::io::stdin().read(&mut buf) {
            self.pending.extend_from_slice(&buf[..n]);
        }
        let (key, used) = parse(&self.pending)?;
        self.pending.drain(..used);
        key.or_else(|| self.key())
    }

    pub fn draw(&mut self, page: &Page) {
        if self.last.as_ref() == Some(page) {
            return;
        }
        let mut out = String::from("\x1b[2J\x1b[H");
        out.push_str(&format!("\x1b[1m{}\x1b[0m\n\n", page.title));
        if let Some(qr) = page.qr.as_deref().and_then(|d| Qr::encode(d.as_bytes())) {
            out.push_str(&qr_blocks(&qr));
        }
        if let Some(big) = &page.big {
            out.push_str(&format!("  \x1b[1m{big}\x1b[0m\n"));
        }
        for line in &page.lines {
            out.push_str(&format!("  {line}\n"));
        }
        for (label, value) in &page.rows {
            out.push_str(&format!("  {label:<16}{value:>16}\n"));
        }
        out.push_str(&format!("\n\x1b[2m{}    {}\x1b[0m\n", page.hints.0, page.hints.1));
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(out.as_bytes());
        let _ = stdout.flush();
        self.last = Some(page.clone());
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if let Some(t) = self.saved {
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
        }
    }
}

/// One key from the start of `bytes`: the key (or `None` for an ignored sequence)
/// and the bytes it used; `None` if more bytes are needed.
fn parse(bytes: &[u8]) -> Option<(Option<Key>, usize)> {
    let first = *bytes.first()?;
    Some(match first {
        0x1b => match bytes.get(1) {
            None => (Some(Key::Back), 1),
            Some(b'[') => match bytes.get(2)? {
                b'A' => (Some(Key::Up), 3),
                b'B' => (Some(Key::Down), 3),
                b'C' => (Some(Key::Right), 3),
                b'D' => (Some(Key::Left), 3),
                _ => (None, 3),
            },
            Some(_) => (Some(Key::Back), 1),
        },
        b'\r' | b'\n' => (Some(Key::Ok), 1),
        b'\t' => (Some(Key::Hold), 1),
        0x7f | 0x08 => (Some(Key::Char('\x7f')), 1),
        b' ' => (Some(Key::Char(' ')), 1),
        c if c.is_ascii_alphanumeric() => (Some(Key::Char(c.to_ascii_lowercase() as char)), 1),
        _ => (None, 1),
    })
}

/// A QR code in half blocks: two modules per character cell, with a quiet zone.
fn qr_blocks(qr: &Qr) -> String {
    let n = qr.size as i32;
    let dark = |x: i32, y: i32| x >= 0 && y >= 0 && x < n && y < n && qr.get(x as usize, y as usize);
    let mut out = String::new();
    for y in (-2..n + 2).step_by(2) {
        out.push_str("  \x1b[97;40m");
        for x in -2..n + 2 {
            // Light modules are drawn: dark terminals show the code the right way round.
            out.push(match (!dark(x, y), !dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keys() {
        assert_eq!(parse(b"\x1b[A"), Some((Some(Key::Up), 3)));
        assert_eq!(parse(b"\x1b["), None);
        assert_eq!(parse(b"\x1b"), Some((Some(Key::Back), 1)));
        assert_eq!(parse(b"\r"), Some((Some(Key::Ok), 1)));
        assert_eq!(parse(b"\t"), Some((Some(Key::Hold), 1)));
        assert_eq!(parse(b"K"), Some((Some(Key::Char('k')), 1)));
    }
}
