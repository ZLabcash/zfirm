//! The link to the phone, carrying the frames of `zfirm_core::protocol`.
//!
//! - USB serial: a Pi Zero in USB gadget mode (`/dev/ttyGS0`), or any serial port.
//!   No radio at all: the cable is the only way in.
//! - TCP on the local network: a Kindle over its Wi-Fi, or a computer for testing.

use std::{
    fs::{File, OpenOptions},
    io::{self, ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
};

pub enum Link {
    Serial(File),
    Tcp { listener: TcpListener, client: Option<TcpStream> },
}

/// What happened on the link since the last poll.
pub enum Event {
    Bytes(usize),
    Connected,
    Disconnected,
    Nothing,
}

impl Link {
    /// `tcp:HOST:PORT` or the path of a serial device.
    pub fn open(spec: &str) -> io::Result<Link> {
        if let Some(addr) = spec.strip_prefix("tcp:") {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            return Ok(Link::Tcp { listener, client: None });
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(spec)?;
        raw_mode(file.as_raw_fd());
        Ok(Link::Serial(file))
    }

    /// Reads what is available into `buf`, without blocking.
    pub fn poll(&mut self, buf: &mut [u8]) -> Event {
        match self {
            Link::Serial(f) => match f.read(buf) {
                Ok(n) if n > 0 => Event::Bytes(n),
                _ => Event::Nothing,
            },
            Link::Tcp { listener, client } => {
                if client.is_none() {
                    // One phone at a time.
                    return match listener.accept() {
                        Ok((stream, _)) if stream.set_nonblocking(true).is_ok() => {
                            let _ = stream.set_nodelay(true);
                            *client = Some(stream);
                            Event::Connected
                        }
                        _ => Event::Nothing,
                    };
                }
                match client.as_mut().map(|c| c.read(buf)) {
                    Some(Ok(0)) => {
                        *client = None;
                        Event::Disconnected
                    }
                    Some(Ok(n)) => Event::Bytes(n),
                    Some(Err(e)) if e.kind() == ErrorKind::WouldBlock => Event::Nothing,
                    _ => {
                        *client = None;
                        Event::Disconnected
                    }
                }
            }
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        let ok = match self {
            Link::Serial(f) => write_all(f, bytes),
            Link::Tcp { client: Some(c), .. } => write_all(c, bytes),
            Link::Tcp { client: None, .. } => true,
        };
        if !ok && let Link::Tcp { client, .. } = self {
            *client = None;
        }
    }
}

/// Writes all of `bytes` to a non-blocking stream, waiting while it is full.
fn write_all(w: &mut impl Write, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        match w.write(bytes) {
            Ok(0) => return false,
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                std::thread::sleep(std::time::Duration::from_millis(2))
            }
            Err(_) => return false,
        }
    }
    w.flush().is_ok()
}

/// Bytes in, bytes out: no echo, no line editing, no translation.
fn raw_mode(fd: i32) {
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) == 0 {
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(fd, libc::TCSANOW, &t);
        }
    }
}
