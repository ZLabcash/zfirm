//! ZFirm on Linux: the Zcash shielded signer for a Pi Zero, a jailbroken Kindle or
//! any Linux board. The seed stays here; the phone (ZApp) holds only the viewing key,
//! builds and proves transactions, and sends them here to be checked, shown and signed.
//!
//! ```text
//! zfirm [--link /dev/ttyGS0 | --link tcp:0.0.0.0:7700] [--dir DIR] [--testnet] [--lcd]
//! ```

use std::{path::PathBuf, time::Duration};

#[cfg(feature = "lcd")]
use zfirm_linux::lcd;
use zfirm_linux::{
    app::{App, Key, Page},
    link::{Event, Link},
    term,
};
use zfirm_core::{Network, protocol::Decoder};

/// The screen and buttons.
enum Panel {
    Terminal(term::Terminal),
    #[cfg(feature = "lcd")]
    Lcd(lcd::Lcd),
}

impl Panel {
    fn key(&mut self) -> Option<Key> {
        match self {
            Panel::Terminal(t) => t.key(),
            #[cfg(feature = "lcd")]
            Panel::Lcd(l) => l.key(),
        }
    }

    fn draw(&mut self, page: &Page) {
        match self {
            Panel::Terminal(t) => t.draw(page),
            #[cfg(feature = "lcd")]
            Panel::Lcd(l) => l.draw(page),
        }
    }
}

struct Args {
    link: String,
    dir: PathBuf,
    network: Network,
    lcd: bool,
}

fn args() -> Result<Args, String> {
    let mut a = Args {
        link: "/dev/ttyGS0".into(),
        dir: std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(".zfirm"),
        network: Network::Main,
        lcd: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--link" => a.link = it.next().ok_or("--link needs a value")?,
            "--dir" => a.dir = it.next().ok_or("--dir needs a value")?.into(),
            "--testnet" => a.network = Network::Test,
            "--lcd" => a.lcd = true,
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    Ok(a)
}

fn main() {
    let a = match args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zfirm: {e}\nusage: zfirm [--link /dev/ttyGS0 | --link tcp:0.0.0.0:7700] [--dir DIR] [--testnet] [--lcd]");
            std::process::exit(2);
        }
    };
    let mut link = match Link::open(&a.link) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("zfirm: cannot open {}: {e}", a.link);
            std::process::exit(1);
        }
    };
    let mut panel = if a.lcd {
        #[cfg(feature = "lcd")]
        match lcd::Lcd::open() {
            Ok(l) => Panel::Lcd(l),
            Err(e) => {
                eprintln!("zfirm: LCD: {e}");
                std::process::exit(1);
            }
        }
        #[cfg(not(feature = "lcd"))]
        {
            eprintln!("zfirm: built without the lcd feature");
            std::process::exit(2);
        }
    } else {
        Panel::Terminal(term::Terminal::new())
    };

    zfirm_linux::use_sinsemilla_table();
    let name = hostname();
    let mut app = App::new(a.dir, a.network, name);
    let mut decoder = Decoder::new();
    let mut buf = [0u8; 4096];
    loop {
        loop {
            match link.poll(&mut buf) {
                Event::Bytes(n) => {
                    let mut next = decoder.push(&buf[..n]);
                    while let Ok(Some(frame)) = next {
                        app.frame(frame);
                        next = decoder.next();
                    }
                    if next.is_err() {
                        app.bad_frame();
                    }
                }
                Event::Disconnected => {
                    decoder.reset();
                    app.disconnected();
                }
                Event::Connected => {}
                Event::Nothing => break,
            }
        }
        while let Some(k) = panel.key() {
            app.key(k);
        }
        for frame in app.take_output() {
            link.send(&frame);
        }
        panel.draw(&app.page());
        if app.has_work() {
            // The page says what is running; now run it.
            app.run_work();
            continue;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 64];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(0);
    match std::str::from_utf8(&buf[..end]) {
        Ok(name) if ok && !name.is_empty() => name.chars().take(16).collect(),
        _ => "ZFirm".into(),
    }
}
