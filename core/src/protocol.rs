//! The wire protocol between the phone and the device, carried over the Flipper's
//! BLE serial service. See `PROTOCOL.md` at the repository root.
//!
//! A frame is `0x5A 0x01 type len:u32le payload`. Strings are UTF-8 prefixed with a
//! `u16le` length.

use alloc::{string::String, vec::Vec};

pub const MAGIC: u8 = 0x5A;
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 7;
/// Largest payload the device accepts (it must fit in the Flipper's RAM).
pub const MAX_PAYLOAD: usize = 16 * 1024;

pub mod msg {
    // Phone -> device.
    pub const HELLO: u8 = 0x01;
    pub const GET_ADDRESS: u8 = 0x03;
    pub const SIGN: u8 = 0x04;
    pub const PING: u8 = 0x05;
    // Device -> phone.
    pub const INFO: u8 = 0x81;
    /// The receiving address now shown on the Flipper (also sent unprompted).
    pub const ADDRESS: u8 = 0x83;
    pub const SIGNED: u8 = 0x84;
    pub const PONG: u8 = 0x85;
    pub const STATUS: u8 = 0x86;
    pub const ERROR: u8 = 0xE0;
}

/// `STATUS` payload values.
pub mod status {
    /// The device is showing a prompt and waits for the user.
    pub const AWAITING_USER: u8 = 1;
    /// The user accepted; the device is working (e.g. signing).
    pub const WORKING: u8 = 2;
}

/// `ERROR` codes.
pub mod error {
    pub const REJECTED: u8 = 1;
    pub const BAD_REQUEST: u8 = 2;
    pub const TOO_LARGE: u8 = 3;
    pub const LOCKED: u8 = 4;
    pub const NOT_PAIRED: u8 = 5;
    pub const INVALID_TX: u8 = 6;
    pub const BUSY: u8 = 7;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub payload: Vec<u8>,
}

pub fn encode(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    BadMagic,
    BadVersion,
    TooLarge,
}

/// Reassembles frames from BLE packets of any size.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// A decoder with room reserved for frames up to `bytes` long.
    pub fn with_capacity(bytes: usize) -> Self {
        Decoder { buf: Vec::with_capacity(bytes) }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.buf.shrink_to_fit();
    }

    /// Appends received bytes. Returns a complete frame once one is buffered. On error
    /// the buffer is cleared so the stream can resynchronize on the next frame.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Frame>, DecodeError> {
        self.buf.extend_from_slice(bytes);
        self.next()
    }

    /// Takes the next complete frame already buffered, if any.
    pub fn next(&mut self) -> Result<Option<Frame>, DecodeError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        if self.buf[0] != MAGIC {
            self.reset();
            return Err(DecodeError::BadMagic);
        }
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        if self.buf[1] != VERSION {
            self.reset();
            return Err(DecodeError::BadVersion);
        }
        let len = u32::from_le_bytes([self.buf[3], self.buf[4], self.buf[5], self.buf[6]]) as usize;
        if len > MAX_PAYLOAD {
            self.reset();
            return Err(DecodeError::TooLarge);
        }
        if self.buf.len() < HEADER_LEN + len {
            // Room for exactly this frame, once: letting the Vec double would briefly need
            // twice a sign request's size, more than a Flipper app has to spare.
            self.buf.reserve_exact(HEADER_LEN + len - self.buf.len());
            return Ok(None);
        }
        let kind = self.buf[2];
        if self.buf.len() == HEADER_LEN + len {
            // The usual case: the buffer holds just this frame. Hand it over without a copy.
            let mut payload = core::mem::take(&mut self.buf);
            payload.drain(..HEADER_LEN);
            return Ok(Some(Frame { kind, payload }));
        }
        let payload = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
        self.buf.drain(..HEADER_LEN + len);
        Ok(Some(Frame { kind, payload }))
    }
}

/// `INFO`: what the phone needs to create the watch-only account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub network: u8,
    pub account: u32,
    pub seed_fingerprint: [u8; 32],
    pub ufvk: String,
    /// Unix time the seed was generated on the device, or 0 if it was restored.
    pub created_at: u32,
    pub device_name: String,
    /// Diversifier index of the receiving address the Flipper is showing.
    pub address_index: u32,
}

impl Info {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(self.network);
        w.u32(self.account);
        w.bytes(&self.seed_fingerprint);
        w.str(&self.ufvk);
        w.u32(self.created_at);
        w.str(&self.device_name);
        w.u32(self.address_index);
        w.0
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader(b);
        let info = Info {
            network: r.u8()?,
            account: r.u32()?,
            seed_fingerprint: r.array()?,
            ufvk: r.str()?,
            created_at: r.u32()?,
            device_name: r.str()?,
            address_index: r.u32()?,
        };
        r.0.is_empty().then_some(info)
    }
}

/// `ADDRESS`: diversifier index + encoded unified address.
pub fn encode_address(index: u32, address: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(index);
    w.str(address);
    w.0
}

pub fn decode_address(b: &[u8]) -> Option<(u32, String)> {
    let mut r = Reader(b);
    let out = (r.u32()?, r.str()?);
    r.0.is_empty().then_some(out)
}

/// `ERROR`: code + human-readable message.
pub fn encode_error(code: u8, message: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.u8(code);
    w.str(message);
    w.0
}

pub fn decode_error(b: &[u8]) -> Option<(u8, String)> {
    let mut r = Reader(b);
    let out = (r.u8()?, r.str()?);
    r.0.is_empty().then_some(out)
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn str(&mut self, s: &str) {
        self.0.extend_from_slice(&(s.len() as u16).to_le_bytes());
        self.0.extend_from_slice(s.as_bytes());
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(crate::arr)
    }
    fn str(&mut self) -> Option<String> {
        let len = self.u16()? as usize;
        let b = self.take(len)?;
        core::str::from_utf8(b).ok().map(String::from)
    }
}
