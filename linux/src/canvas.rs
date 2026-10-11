//! A page drawn into pixels, for small screens (240×240 on the Pi Zero's LCD HAT).
//! Black on white, Zcash yellow for the title bar.

use font8x8::UnicodeFonts;
use zfirm_core::qr::Qr;

use crate::app::Page;

pub const WHITE: u16 = 0xFFFF;
pub const BLACK: u16 = 0x0000;
/// #F4B728 in RGB565.
pub const YELLOW: u16 = 0xF5A5;

pub struct Canvas {
    pub w: usize,
    pub h: usize,
    /// RGB565 pixels, row by row.
    pub px: Vec<u16>,
}

impl Canvas {
    pub fn new(w: usize, h: usize) -> Canvas {
        Canvas { w, h, px: vec![WHITE; w * h] }
    }

    pub fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, color: u16) {
        for yy in y..(y + h).min(self.h) {
            for xx in x..(x + w).min(self.w) {
                self.px[yy * self.w + xx] = color;
            }
        }
    }

    /// 8×8 glyphs scaled by `scale`.
    pub fn text(&mut self, x: usize, y: usize, s: &str, scale: usize, color: u16) {
        for (n, c) in s.chars().enumerate() {
            let glyph = font8x8::BASIC_FONTS.get(c).or_else(|| font8x8::BASIC_FONTS.get('?')).unwrap_or([0; 8]);
            for (row, bits) in glyph.iter().enumerate() {
                for col in 0..8 {
                    if bits >> col & 1 == 1 {
                        self.fill(x + (n * 8 + col) * scale, y + row * scale, scale, scale, color);
                    }
                }
            }
        }
    }

    pub fn centered(&mut self, y: usize, s: &str, scale: usize, color: u16) {
        let w = s.chars().count() * 8 * scale;
        self.text(self.w.saturating_sub(w) / 2, y, s, scale, color);
    }

    /// Draws `page`.
    pub fn page(&mut self, page: &Page) {
        self.fill(0, 0, self.w, self.h, WHITE);
        // Title bar.
        self.fill(0, 0, self.w, 26, YELLOW);
        self.centered(5, &fit(&page.title, self.w / 16), 2, BLACK);
        let mut y = 34;
        let bottom = self.h - 14;

        if let Some(qr) = page.qr.as_deref().and_then(|d| Qr::encode(d.as_bytes())) {
            let modules = qr.size + 4;
            let m = ((bottom - y - 34) / modules).max(1);
            let x0 = (self.w - modules * m) / 2;
            for qy in 0..qr.size {
                for qx in 0..qr.size {
                    if qr.get(qx, qy) {
                        self.fill(x0 + (qx + 2) * m, y + (qy + 2) * m, m, m, BLACK);
                    }
                }
            }
            y += modules * m + 2;
        }
        if let Some(big) = &page.big {
            let scale = if big.chars().count() * 24 <= self.w { 3 } else { 2 };
            self.centered(y, big, scale, BLACK);
            y += 8 * scale + 8;
        }
        for line in &page.lines {
            // Prose in large type; long unbroken text (addresses, keys) small.
            let small = line.len() > 60 || page.qr.is_some();
            let (scale, cols) = if small { (1, self.w / 8) } else { (2, self.w / 16) };
            for row in wrap(line, cols) {
                if y + 8 * scale > bottom {
                    break;
                }
                self.text(2, y, &row, scale, BLACK);
                y += 8 * scale + 2;
            }
        }
        for (label, value) in &page.rows {
            if y + 30 > bottom {
                break;
            }
            self.text(2, y, label, 1, BLACK);
            let w = value.chars().count() * 16;
            self.text(self.w.saturating_sub(w + 2), y + 10, value, 2, BLACK);
            y += 32;
        }
        // Hints.
        self.fill(0, bottom, self.w, 14, BLACK);
        self.text(2, bottom + 3, &page.hints.0, 1, WHITE);
        let right = &page.hints.1;
        self.text(self.w.saturating_sub(right.chars().count() * 8 + 2), bottom + 3, right, 1, WHITE);
    }
}

impl Canvas {
    /// The pixels as a binary PPM image (for previews on a computer).
    pub fn ppm(&self) -> Vec<u8> {
        let mut out = format!("P6\n{} {}\n255\n", self.w, self.h).into_bytes();
        for &p in &self.px {
            let (r, g, b) = ((p >> 11) & 0x1F, (p >> 5) & 0x3F, p & 0x1F);
            out.extend([(r << 3 | r >> 2) as u8, (g << 2 | g >> 4) as u8, (b << 3 | b >> 2) as u8]);
        }
        out
    }
}

fn fit(s: &str, cols: usize) -> String {
    s.chars().take(cols).collect()
}

/// Lines of at most `cols` characters, broken at spaces when there are any.
fn wrap(s: &str, cols: usize) -> Vec<String> {
    let cols = cols.max(1);
    if s.chars().count() <= cols {
        return vec![s.to_string()];
    }
    if !s.contains(' ') {
        let chars: Vec<char> = s.chars().collect();
        return chars.chunks(cols).map(|c| c.iter().collect()).collect();
    }
    let mut lines = vec![String::new()];
    for word in s.split(' ') {
        let last = lines.last_mut().expect("one line");
        if !last.is_empty() && last.len() + 1 + word.len() > cols {
            lines.push(String::new());
        }
        let last = lines.last_mut().expect("one line");
        if !last.is_empty() {
            last.push(' ');
        }
        last.push_str(word);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_words_and_codes() {
        assert_eq!(wrap("share this key", 10), vec!["share this", "key"]);
        assert_eq!(wrap("u1abcdefgh", 4), vec!["u1ab", "cdef", "gh"]);
    }
}
