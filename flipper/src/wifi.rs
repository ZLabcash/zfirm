// Shared by both apps: the setup module only uses the saved network.
#![allow(dead_code)]

//! The Wi-Fi devboard on the GPIO header, running the ZFirm Wi-Fi board firmware (wifi-board/):
//! it tells where a signed transaction stands (mempool, block, confirmations).
//! It only ever learns transaction ids and the Wi-Fi network to join: no keys.
//!
//! One line per message over USART (pins 13/14) at 115200 baud; see the
//! firmware's README for the messages.

use alloc::{string::String, vec::Vec};
use core::{ffi::c_void, ptr};

use flipperzero::furi::stream_buffer::{self, StreamBuffer};
use flipperzero_sys as sys;

const BAUD: u32 = 115_200;
/// Wi-Fi network for the board: the SSID on the first line, the password on the second.
const WIFI_FILE: &core::ffi::CStr = c"/ext/apps_data/zflip/wifi.txt";
/// Present while the saved network has not reached the board yet.
const WIFI_NEW: &core::ffi::CStr = c"/ext/apps_data/zflip/wifi.new";

static mut RX: Option<stream_buffer::Sender> = None;

unsafe extern "C" fn on_rx(handle: *mut sys::FuriHalSerialHandle, event: sys::FuriHalSerialRxEvent, _: *mut c_void) {
    if event.0 & sys::FuriHalSerialRxEventData.0 != 0 {
        unsafe {
            while sys::furi_hal_serial_async_rx_available(handle) {
                let b = sys::furi_hal_serial_async_rx(handle);
                if let Some(tx) = (*ptr::addr_of!(RX)).as_ref() {
                    tx.send(&[b]);
                }
            }
        }
    }
}

/// Where the board's Wi-Fi stands, as it last said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    NoWifi,
    Connecting,
    Online,
    Failed,
}

/// A transaction's state, as ZScan sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    /// Not asked yet.
    Asking,
    /// Not on the network yet: the phone has not sent it.
    Unknown,
    Mempool,
    Mined { height: u32, confirmations: u32 },
    Offline,
    Error,
}

/// The network's state, from ZScan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetInfo {
    pub height: u32,
    pub txs_24h: u32,
    /// Share of shielded transactions over 24 h, in ‰.
    pub shielded: u16,
}

/// The ZEC price, from ZScan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    pub usd_cents: u64,
    /// Change over 24 h, in basis points.
    pub change: i32,
}

pub enum Reply {
    Hello(Net),
    Tx(Tx),
    WifiSaved,
    Price(Price),
    Net(NetInfo),
}

pub struct Board {
    serial: *mut sys::FuriHalSerialHandle,
    rx: stream_buffer::Receiver,
    line: Vec<u8>,
    expansion: *mut sys::Expansion,
    /// We switched the header's 5 V on (and switch it off when done).
    otg: bool,
}

impl Board {
    /// Powers the header and opens the serial port. Whether a board answers is for
    /// [`Board::hello`] to find out.
    pub fn open() -> Option<Board> {
        unsafe {
            // The firmware listens for expansion modules on this port: pause that.
            let expansion = sys::furi_record_open(c"expansion".as_ptr()) as *mut sys::Expansion;
            sys::expansion_disable(expansion);
            let serial = sys::furi_hal_serial_control_acquire(sys::FuriHalSerialIdUsart);
            if serial.is_null() {
                sys::expansion_enable(expansion);
                sys::furi_record_close(c"expansion".as_ptr());
                return None;
            }
            // 5 V on the header, through the power service (the HAL call alone is
            // refused while the power service owns OTG).
            let power = sys::furi_record_open(c"power".as_ptr()) as *mut sys::Power;
            let otg = !sys::power_is_otg_enabled(power);
            if otg {
                sys::power_enable_otg(power, true);
            }
            sys::furi_record_close(c"power".as_ptr());
            let (tx, rx) = StreamBuffer::new(core::num::NonZeroUsize::new(256).unwrap(), 1).into_stream();
            RX = Some(tx);
            sys::furi_hal_serial_init(serial, BAUD);
            sys::furi_hal_serial_async_rx_start(serial, Some(on_rx), ptr::null_mut(), false);
            Some(Board { serial, rx, line: Vec::new(), expansion, otg })
        }
    }

    fn send(&self, parts: &[&[u8]]) {
        for p in parts {
            unsafe { sys::furi_hal_serial_tx(self.serial, p.as_ptr(), p.len()) };
        }
        unsafe { sys::furi_hal_serial_tx(self.serial, b"\n".as_ptr(), 1) };
    }

    pub fn hello(&self) {
        self.send(&[b"ZF?"]);
    }

    pub fn ask_price(&self) {
        self.send(&[b"PRICE"]);
    }

    pub fn ask_network(&self) {
        self.send(&[b"NET"]);
    }

    /// Asks where the transaction stands. `txid` in the usual order (as explorers show it).
    pub fn ask(&self, txid: &[u8; 32]) {
        let mut hex = [0u8; 64];
        for (i, b) in txid.iter().enumerate() {
            hex[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
            hex[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
        }
        self.send(&[b"TX ", &hex]);
    }

    /// Hands the board the Wi-Fi network saved on the SD card, if there is one.
    pub fn send_wifi(&self) -> bool {
        let Some((ssid, pass)) = saved_network() else { return false };
        self.send(&[b"WIFI ", ssid.as_bytes(), b"\t", pass.as_bytes()]);
        true
    }

    /// The next reply, if a whole line has arrived (never blocks).
    pub fn poll(&mut self) -> Option<Reply> {
        let mut buf = [0u8; 64];
        loop {
            let n = self.rx.recv(&mut buf);
            if n == 0 {
                return None;
            }
            for &b in &buf[..n] {
                if b == b'\n' || b == b'\r' {
                    let reply = parse(&self.line);
                    self.line.clear();
                    if reply.is_some() {
                        return reply;
                    }
                } else if self.line.len() < 80 {
                    self.line.push(b);
                } else {
                    self.line.clear();
                }
            }
        }
    }
}

impl Drop for Board {
    fn drop(&mut self) {
        unsafe {
            sys::furi_hal_serial_async_rx_stop(self.serial);
            sys::furi_hal_serial_deinit(self.serial);
            sys::furi_hal_serial_control_release(self.serial);
            RX = None;
            if self.otg {
                let power = sys::furi_record_open(c"power".as_ptr()) as *mut sys::Power;
                sys::power_enable_otg(power, false);
                sys::furi_record_close(c"power".as_ptr());
            }
            sys::expansion_enable(self.expansion);
            sys::furi_record_close(c"expansion".as_ptr());
        }
    }
}

fn parse(line: &[u8]) -> Option<Reply> {
    let line = core::str::from_utf8(line).ok()?;
    let mut words = line.split(' ');
    match (words.next()?, words.next()) {
        ("ZF", Some(_version)) => Some(Reply::Hello(match words.next()? {
            "online" => Net::Online,
            "connecting" => Net::Connecting,
            "failed" => Net::Failed,
            _ => Net::NoWifi,
        })),
        ("WIFI", Some("saved")) => Some(Reply::WifiSaved),
        ("TX", Some(state)) => Some(Reply::Tx(match state {
            "mempool" => Tx::Mempool,
            "mined" => Tx::Mined {
                height: words.next()?.parse().ok()?,
                confirmations: words.next()?.parse().ok()?,
            },
            "unknown" => Tx::Unknown,
            "offline" => Tx::Offline,
            _ => Tx::Error,
        })),
        ("PRICE", Some(cents)) => Some(Reply::Price(Price {
            usd_cents: cents.parse().ok()?,
            change: words.next()?.parse().ok()?,
        })),
        ("NET", Some(height)) => Some(Reply::Net(NetInfo {
            height: height.parse().ok()?,
            txs_24h: words.next()?.parse().ok()?,
            shielded: words.next()?.parse().ok()?,
        })),
        _ => None,
    }
}

/// The saved network: its name and password.
pub fn saved_network() -> Option<(String, String)> {
    let text = read_wifi_file()?;
    let mut lines = text.lines();
    let ssid = String::from(lines.next()?.trim_end());
    let pass = String::from(lines.next().unwrap_or("").trim_end());
    (!ssid.is_empty()).then_some((ssid, pass))
}

/// Saves the network for the board, to hand over next time ZFlip sees it.
pub fn save_network(ssid: &str, pass: &str) -> bool {
    use flipperzero::{io::Write, storage::OpenOptions};
    let Ok(mut f) = OpenOptions::new().write(true).create_always(true).open(WIFI_FILE) else { return false };
    let ok = [ssid.as_bytes(), b"\n", pass.as_bytes(), b"\n"].iter().all(|p| f.write(p).is_ok());
    drop(f);
    ok && OpenOptions::new().write(true).create_always(true).open(WIFI_NEW).is_ok()
}

/// Whether the saved network is newer than what the board was last given.
pub fn network_pending() -> bool {
    use flipperzero::storage::OpenOptions;
    OpenOptions::new().read(true).open_existing(true).open(WIFI_NEW).is_ok()
}

pub fn network_delivered() {
    unsafe {
        let storage = sys::furi_record_open(c"storage".as_ptr()) as *mut sys::Storage;
        sys::storage_simply_remove(storage, WIFI_NEW.as_ptr());
        sys::furi_record_close(c"storage".as_ptr());
    }
}

fn read_wifi_file() -> Option<String> {
    use flipperzero::{io::Read, storage::OpenOptions};
    let mut f = OpenOptions::new().read(true).open(WIFI_FILE).ok()?;
    let mut buf = [0u8; 128];
    let n = f.read(&mut buf).ok()?;
    core::str::from_utf8(&buf[..n]).ok().map(String::from)
}
