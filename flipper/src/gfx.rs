// Shared by both apps; each uses a subset.
#![allow(dead_code)]

//! Drawing helpers: text, wrapped addresses, QR codes and the shield animation.

use flipperzero_sys as sys;
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};

pub use sys::Canvas;

pub const W: i32 = 128;
pub const H: i32 = 64;

pub struct Gfx(pub *mut Canvas);

/// Copies `s` into a NUL-terminated stack buffer (truncating at 63 bytes).
fn with_c<R>(s: &str, f: impl FnOnce(*const core::ffi::c_char) -> R) -> R {
    let mut buf = [0u8; 64];
    let n = s.len().min(63);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    f(buf.as_ptr() as *const core::ffi::c_char)
}

#[derive(Clone, Copy)]
pub enum Font {
    Big,
    Small,
    Mono,
    Numbers,
}

impl Gfx {
    pub fn clear(&self) {
        unsafe { sys::canvas_clear(self.0) };
    }

    pub fn font(&self, f: Font) {
        let font = match f {
            Font::Big => sys::FontPrimary,
            Font::Small => sys::FontSecondary,
            Font::Mono => sys::FontKeyboard,
            Font::Numbers => sys::FontBigNumbers,
        };
        unsafe { sys::canvas_set_font(self.0, font) };
    }

    pub fn black(&self) {
        unsafe { sys::canvas_set_color(self.0, sys::ColorBlack) };
    }

    pub fn white(&self) {
        unsafe { sys::canvas_set_color(self.0, sys::ColorWhite) };
    }

    pub fn text(&self, x: i32, y: i32, s: &str) {
        with_c(s, |p| unsafe { sys::canvas_draw_str(self.0, x, y, p) });
    }

    pub fn center(&self, y: i32, s: &str) {
        with_c(s, |p| unsafe {
            sys::canvas_draw_str_aligned(self.0, W / 2, y, sys::AlignCenter, sys::AlignBottom, p)
        });
    }

    pub fn right(&self, x: i32, y: i32, s: &str) {
        with_c(s, |p| unsafe {
            sys::canvas_draw_str_aligned(self.0, x, y, sys::AlignRight, sys::AlignBottom, p)
        });
    }

    pub fn line(&self, x1: i32, y1: i32, x2: i32, y2: i32) {
        unsafe { sys::canvas_draw_line(self.0, x1, y1, x2, y2) };
    }

    pub fn dot(&self, x: i32, y: i32) {
        unsafe { sys::canvas_draw_dot(self.0, x, y) };
    }

    pub fn fill(&self, x: i32, y: i32, w: i32, h: i32) {
        unsafe { sys::canvas_draw_box(self.0, x, y, w.max(0) as usize, h.max(0) as usize) };
    }

    pub fn frame(&self, x: i32, y: i32, w: i32, h: i32) {
        unsafe { sys::canvas_draw_rframe(self.0, x, y, w as usize, h as usize, 2) };
    }

    pub fn disc(&self, x: i32, y: i32, r: i32) {
        unsafe { sys::canvas_draw_disc(self.0, x, y, r as usize) };
    }

    /// A title bar with inverted text.
    pub fn title(&self, s: &str) {
        self.black();
        self.fill(0, 0, W, 11);
        self.white();
        self.font(Font::Big);
        self.center(10, s);
        self.black();
    }

    /// Bottom hints, e.g. ("Back", "OK").
    pub fn hints(&self, left: &str, right: &str) {
        self.font(Font::Small);
        if !left.is_empty() {
            self.text(1, 63, left);
        }
        if !right.is_empty() {
            self.right(127, 63, right);
        }
    }

    /// Monospace text wrapped to `cols` characters, starting at line `first`.
    pub fn wrapped(&self, x: i32, y: i32, text: &str, cols: usize, first: usize, lines: usize) {
        self.font(Font::Mono);
        let bytes = text.as_bytes();
        for (i, chunk) in bytes.chunks(cols).skip(first).take(lines).enumerate() {
            if let Ok(s) = core::str::from_utf8(chunk) {
                self.text(x, y + i as i32 * 8, s);
            }
        }
    }

    /// Draws a QR code computed with [`Qr::encode`], centred in the left square.
    pub fn qr(&self, qr: &Qr, left: i32) {
        let size = qr.size;
        let scale = (H / (size + 2)).max(1);
        let px = size * scale;
        let x0 = left + (H - px) / 2;
        let y0 = (H - px) / 2;
        self.white();
        self.fill(x0 - scale, y0 - scale, px + 2 * scale, px + 2 * scale);
        self.black();
        for y in 0..size {
            for x in 0..size {
                if qr.get(x, y) {
                    self.fill(x0 + x * scale, y0 + y * scale, scale, scale);
                }
            }
        }
    }

    /// The ZScan mark (as on zscan.cash and the iPhone app): a rounded shield, a Z
    /// and a dashed scan line, about 30 px tall, forging itself: the outline draws
    /// in, sparks converge, the Z and the scan line appear. `t` goes 0..=1000.
    pub fn shield(&self, cx: i32, cy: i32, t: i32, frame: u32) {
        // The logo's 32-unit path (scan/public/brand/zscan-logo.svg), sampled.
        const OUTLINE: [(i32, i32); 13] = [
            (16, 2), (27, 7), (27, 15), (26, 20), (23, 25), (19, 28), (16, 29),
            (13, 28), (9, 25), (6, 20), (5, 15), (5, 7), (16, 2),
        ];
        let p = |(x, y): (i32, i32)| (cx + (x - 16) * 15 / 16, cy + (y - 16) * 15 / 16);
        let outline = (t * 5 / 3).min(1000);
        let segs = OUTLINE.len() as i32 - 1;
        for i in 0..segs {
            let start = i * 1000 / segs;
            if outline <= start {
                break;
            }
            let f = ((outline - start) * segs).min(1000);
            let (x1, y1) = p(OUTLINE[i as usize]);
            let (x2, y2) = p(OUTLINE[i as usize + 1]);
            let (xe, ye) = (x1 + (x2 - x1) * f / 1000, y1 + (y2 - y1) * f / 1000);
            // Two pixels thick, like the logo's stroke.
            self.line(x1, y1, xe, ye);
            self.line(x1 + if x1 < cx { 1 } else if x1 > cx { -1 } else { 0 }, y1 + 1, xe, ye + 1);
        }

        if t < 900 {
            let radius = 30 - t * 26 / 900;
            for k in 0..10u32 {
                let a = (k * 36 + frame * 13) % 360;
                let (s, c) = sin_cos(a as i32);
                self.dot(cx + c * radius / 1000, cy + s * radius / 1000);
            }
        }

        if t > 600 {
            let z = ((t - 600) * 1000 / 300).min(1000);
            let (l, r, top, bot) = (p((11, 11)).0, p((21, 11)).0, p((11, 11)).1, p((11, 21)).1);
            let seg = |f: i32| f.clamp(0, 1000);
            let a = seg(z * 3);
            self.line(l, top, l + (r - l) * a / 1000, top);
            self.line(l, top + 1, l + (r - l) * a / 1000, top + 1);
            let b = seg(z * 3 - 1000);
            if b > 0 {
                self.line(r, top, r - (r - l) * b / 1000, top + (bot - top) * b / 1000);
                self.line(r - 1, top + 1, r - 1 - (r - l) * b / 1000, top + 1 + (bot - top) * b / 1000);
            }
            let c = seg(z * 3 - 2000);
            if c > 0 {
                self.line(l, bot, l + (r - l) * c / 1000, bot);
                self.line(l, bot - 1, l + (r - l) * c / 1000, bot - 1);
            }
        }
        if t > 900 {
            // The scan line: dashes across the shield.
            let (x0, x1, y) = (p((7, 16)).0, p((25, 16)).0, cy);
            let mut x = x0;
            while x < x1 {
                self.line(x, y, (x + 1).min(x1), y);
                x += 4;
            }
        }
    }

    pub fn progress(&self, y: i32, percent: u32) {
        self.frame(14, y, 100, 6);
        self.fill(15, y + 1, (percent.min(100) as i32 * 98) / 100, 4);
    }
}

/// A QR code as a bitmap. Encoded off the GUI thread (whose stack is small).
pub struct Qr {
    size: i32,
    bits: alloc::vec::Vec<u8>,
}

impl Qr {
    fn from_modules(size: i32, dark: impl Fn(i32, i32) -> bool) -> Qr {
        let mut bits = alloc::vec![0u8; ((size * size + 7) / 8) as usize];
        for y in 0..size {
            for x in 0..size {
                if dark(x, y) {
                    let i = (y * size + x) as usize;
                    bits[i / 8] |= 1 << (i % 8);
                }
            }
        }
        Qr { size, bits }
    }

    /// Addresses: the compact encoder (versions 1 to 6), cheap in code size.
    pub fn address(text: &str) -> Option<Qr> {
        let qr = zfirm_core::qr::Qr::encode(text.as_bytes())?;
        Some(Qr::from_modules(qr.size as i32, |x, y| qr.get(x as usize, y as usize)))
    }

    /// Longer texts (the viewing key): byte mode, low ECC, up to version 10.
    pub fn encode(text: &str) -> Option<Qr> {
        let mut temp = [0u8; Version::new(10).buffer_len()];
        let mut out = [0u8; Version::new(10).buffer_len()];
        let qr = QrCode::encode_text(text, &mut temp, &mut out, QrCodeEcc::Low, Version::MIN, Version::new(10), None, true)
            .ok()?;
        Some(Qr::from_modules(qr.size(), |x, y| qr.get_module(x, y)))
    }

    fn get(&self, x: i32, y: i32) -> bool {
        let i = (y * self.size + x) as usize;
        self.bits[i / 8] & (1 << (i % 8)) != 0
    }
}

/// sin and cos of `deg` degrees, scaled by 1000 (coarse table, fine for sparks).
fn sin_cos(deg: i32) -> (i32, i32) {
    const S: [i32; 10] = [0, 174, 342, 500, 643, 766, 866, 940, 985, 1000];
    let sin = |d: i32| -> i32 {
        let d = d.rem_euclid(360);
        let (q, r) = (d / 90, d % 90);
        let v = |x: i32| S[(x / 10).min(9) as usize];
        match q {
            0 => v(r),
            1 => v(90 - r),
            2 => -v(r),
            _ => -v(90 - r),
        }
    };
    (sin(deg), sin(deg + 90))
}

/// Decimal digits of `n`, without `core::fmt` (which costs the app ~3 KiB).
pub fn num(n: u64) -> alloc::string::String {
    let mut digits = [0u8; 20];
    let (mut n, mut i) = (n, digits.len());
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    digits[i..].iter().map(|&d| d as char).collect()
}

/// "1.2345 ZEC" from zatoshis, trimming trailing zeros (at least 2 decimals).
pub fn zec(zats: u64) -> alloc::string::String {
    let whole = zats / zfirm_core::COIN;
    let mut frac = zats % zfirm_core::COIN;
    let mut digits = 8;
    while digits > 2 && frac % 10 == 0 {
        frac /= 10;
        digits -= 1;
    }
    let f = num(frac);
    let mut out = num(whole);
    out.push('.');
    for _ in f.len()..digits {
        out.push('0');
    }
    out.push_str(&f);
    out.push_str(" ZEC");
    out
}
