//! The Waveshare 1.3" LCD HAT on a Pi Zero (the SeedSigner screen): an ST7789
//! 240×240 panel on SPI0, a five-way joystick and three keys on GPIO.
//!
//! Pins (BCM): DC 25, RST 27, backlight 24; joystick up 6, down 19, left 5, right 26,
//! press 13; KEY1 21, KEY2 20, KEY3 16. The inputs are active low and need pull-ups:
//! `gpio=6,19,5,26,13,21,20,16=pu` in `/boot/config.txt`, with `dtparam=spi=on`.
//!
//! Keys: joystick = arrows, press or KEY1 = OK, held one second = hold OK, KEY3 = Back.

use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

use gpio_cdev::{Chip, LineHandle, LineRequestFlags};
use spidev::{SpiModeFlags, Spidev, SpidevOptions};

use crate::{
    app::{Key, Page},
    canvas::Canvas,
};

const SIZE: usize = 240;
const DC: u32 = 25;
const RST: u32 = 27;
const BL: u32 = 24;
/// Pins and the key each one gives.
const KEYS: [(u32, Key); 8] = [
    (6, Key::Up),
    (19, Key::Down),
    (5, Key::Left),
    (26, Key::Right),
    (13, Key::Ok),
    (21, Key::Ok),
    (20, Key::Ok),
    (16, Key::Back),
];
const HOLD: Duration = Duration::from_secs(1);

struct Button {
    line: LineHandle,
    key: Key,
    down_since: Option<Instant>,
    held: bool,
}

pub struct Lcd {
    spi: Spidev,
    dc: LineHandle,
    buttons: Vec<Button>,
    canvas: Canvas,
    last: Option<Page>,
}

impl Lcd {
    pub fn open() -> io::Result<Lcd> {
        let err = |e: gpio_cdev::Error| io::Error::other(e.to_string());
        let mut chip = Chip::new("/dev/gpiochip0").map_err(err)?;
        let out = |chip: &mut Chip, pin: u32, v: u8| {
            chip.get_line(pin).and_then(|l| l.request(LineRequestFlags::OUTPUT, v, "zfirm")).map_err(err)
        };
        let dc = out(&mut chip, DC, 0)?;
        let rst = out(&mut chip, RST, 1)?;
        let bl = out(&mut chip, BL, 1)?;
        let mut buttons = Vec::new();
        for (pin, key) in KEYS {
            let line = chip.get_line(pin).and_then(|l| l.request(LineRequestFlags::INPUT, 0, "zfirm")).map_err(err)?;
            buttons.push(Button { line, key, down_since: None, held: false });
        }

        let mut spi = Spidev::open("/dev/spidev0.0")?;
        spi.configure(&SpidevOptions::new().bits_per_word(8).max_speed_hz(40_000_000).mode(SpiModeFlags::SPI_MODE_0).build())?;

        // Hardware reset.
        for (v, ms) in [(1, 10), (0, 10), (1, 120)] {
            rst.set_value(v).map_err(err)?;
            std::thread::sleep(Duration::from_millis(ms));
        }
        std::mem::forget(rst);
        std::mem::forget(bl); // the backlight stays on while the app runs
        let mut lcd = Lcd { spi, dc, buttons, canvas: Canvas::new(SIZE, SIZE), last: None };
        lcd.command(0x01, &[])?; // software reset
        std::thread::sleep(Duration::from_millis(150));
        lcd.command(0x11, &[])?; // sleep out
        std::thread::sleep(Duration::from_millis(120));
        lcd.command(0x3A, &[0x05])?; // 16 bits per pixel
        lcd.command(0x36, &[0x00])?; // memory order
        lcd.command(0x21, &[])?; // this IPS panel shows inverted colours unless told
        lcd.command(0x13, &[])?; // normal mode
        lcd.command(0x29, &[])?; // display on
        Ok(lcd)
    }

    fn command(&mut self, cmd: u8, data: &[u8]) -> io::Result<()> {
        let err = |e: gpio_cdev::Error| io::Error::other(e.to_string());
        self.dc.set_value(0).map_err(err)?;
        self.spi.write_all(&[cmd])?;
        if !data.is_empty() {
            self.dc.set_value(1).map_err(err)?;
            // spidev takes at most 4 KiB per transfer by default.
            for chunk in data.chunks(4096) {
                self.spi.write_all(chunk)?;
            }
        }
        Ok(())
    }

    pub fn draw(&mut self, page: &Page) {
        if self.last.as_ref() == Some(page) {
            return;
        }
        self.canvas.page(page);
        let bytes: Vec<u8> = self.canvas.px.iter().flat_map(|p| p.to_be_bytes()).collect();
        let end = (SIZE as u16 - 1).to_be_bytes();
        let _ = self.command(0x2A, &[0, 0, end[0], end[1]]);
        let _ = self.command(0x2B, &[0, 0, end[0], end[1]]);
        let _ = self.command(0x2C, &bytes);
        self.last = Some(page.clone());
    }

    /// The next key: a press on release, or a hold after one second down.
    pub fn key(&mut self) -> Option<Key> {
        let now = Instant::now();
        for b in &mut self.buttons {
            let down = b.line.get_value().map(|v| v == 0).unwrap_or(false);
            match (down, b.down_since) {
                (true, None) => {
                    b.down_since = Some(now);
                    b.held = false;
                }
                (true, Some(t)) if !b.held && b.key == Key::Ok && now - t >= HOLD => {
                    b.held = true;
                    return Some(Key::Hold);
                }
                (false, Some(_)) => {
                    b.down_since = None;
                    if !b.held {
                        return Some(b.key);
                    }
                }
                _ => {}
            }
        }
        None
    }
}
