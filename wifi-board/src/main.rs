//! ZFirm Wi-Fi board: firmware for the Flipper Zero Wi-Fi devboard (ESP32-S2).
//!
//! The board joins a Wi-Fi network and asks the ZScan API where a transaction
//! signed by ZFlip stands: in the mempool, or mined and how deep. It never holds a
//! key: all it gets from the Flipper is a transaction id (public once broadcast)
//! and the Wi-Fi network to join.
//!
//! The Flipper talks to it over UART0 (GPIO 43/44, the header's pins 13/14) at
//! 115200 baud, one line per message, `\n`-terminated:
//!
//! | Flipper sends          | Board answers                                        |
//! |------------------------|------------------------------------------------------|
//! | `ZF?`                  | `ZF 1 <nowifi\|connecting\|online\|failed>`          |
//! | `WIFI <ssid>\t<pass>`  | `WIFI saved` (then it joins that network)            |
//! | `TX <txid>`            | `TX mempool`, `TX mined <height> <confirmations>`,   |
//! |                        | `TX unknown`, `TX offline` or `TX error`             |
//! | `PRICE`                | `PRICE <usd cents> <24 h change, basis points>`      |
//! | `NET`                  | `NET <height> <txs in 24 h> <shielded share, ‰>`     |
//!
//! `PRICE` and `NET` answer `<WORD> offline` or `<WORD> error` when they cannot.
//!
//! Anything else on the line (the ROM's boot messages, for one) is ignored by the
//! Flipper, which only reads lines starting with these words.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::Result;
use embedded_svc::http::client::Client;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::{gpio::AnyIOPin, peripherals::Peripherals, uart, units::Hertz},
    http::client::{Configuration as HttpConfig, EspHttpConnection},
    nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault},
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi},
};
use log::{info, warn};

const API: &str = "https://api.zscan.cash/v1";
const VERSION: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Net {
    NoWifi,
    Connecting,
    Online,
    Failed,
}

impl Net {
    fn word(self) -> &'static str {
        match self {
            Net::NoWifi => "nowifi",
            Net::Connecting => "connecting",
            Net::Online => "online",
            Net::Failed => "failed",
        }
    }
}

struct Shared {
    net: Mutex<Net>,
    /// Bumped when new credentials are saved, so the Wi-Fi thread joins again.
    creds: AtomicU32,
    nvs: Mutex<EspNvs<NvsDefault>>,
}

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let p = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let partition = EspDefaultNvsPartition::take()?;
    let nvs = EspNvs::new(partition.clone(), "zflip", true)?;

    let config = uart::config::Config::default().baudrate(Hertz(115_200));
    let link = uart::UartDriver::new(
        p.uart0,
        p.pins.gpio43,
        p.pins.gpio44,
        Option::<AnyIOPin>::None,
        Option::<AnyIOPin>::None,
        &config,
    )?;

    let shared = Arc::new(Shared {
        net: Mutex::new(Net::NoWifi),
        creds: AtomicU32::new(0),
        nvs: Mutex::new(nvs),
    });
    let wifi = BlockingWifi::wrap(EspWifi::new(p.modem, sysloop.clone(), Some(partition))?, sysloop)?;
    {
        let shared = shared.clone();
        thread::Builder::new().stack_size(8192).spawn(move || wifi_thread(wifi, &shared))?;
    }

    info!("ZFirm Wi-Fi board {VERSION} ready");
    let mut line = Vec::with_capacity(128);
    let mut buf = [0u8; 64];
    loop {
        let n = link.read(&mut buf, 10)?;
        for &b in &buf[..n] {
            match b {
                b'\n' | b'\r' => {
                    if !line.is_empty() {
                        let reply = handle(&String::from_utf8_lossy(&line), &shared);
                        if let Some(reply) = reply {
                            link.write(reply.as_bytes())?;
                            link.write(b"\n")?;
                        }
                        line.clear();
                    }
                }
                // A line longer than any message is noise: drop it.
                _ if line.len() >= 160 => line.clear(),
                _ => line.push(b),
            }
        }
    }
}

fn handle(line: &str, shared: &Shared) -> Option<String> {
    let net = *shared.net.lock().unwrap();
    if line == "ZF?" {
        return Some(format!("ZF {VERSION} {}", net.word()));
    }
    if let Some(rest) = line.strip_prefix("WIFI ") {
        let (ssid, pass) = rest.split_once('\t').unwrap_or((rest, ""));
        if ssid.is_empty() || ssid.len() > 32 || pass.len() > 64 {
            return Some("WIFI bad".into());
        }
        let nvs = shared.nvs.lock().unwrap();
        if nvs.set_str("ssid", ssid).is_err() || nvs.set_str("pass", pass).is_err() {
            return Some("WIFI bad".into());
        }
        shared.creds.fetch_add(1, Ordering::Release);
        return Some("WIFI saved".into());
    }
    if line == "PRICE" || line == "NET" {
        if net != Net::Online {
            return Some(format!("{line} offline"));
        }
        let answer = if line == "PRICE" { price() } else { network() };
        return Some(answer.unwrap_or_else(|e| {
            warn!("{line}: {e}");
            format!("{line} error")
        }));
    }
    if let Some(txid) = line.strip_prefix("TX ") {
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some("TX error".into());
        }
        if net != Net::Online {
            return Some("TX offline".into());
        }
        return Some(match tx_status(txid) {
            Ok(status) => status,
            Err(e) => {
                warn!("tx {txid}: {e}");
                "TX error".into()
            }
        });
    }
    None
}

#[derive(serde::Deserialize)]
struct Tx {
    status: String,
    height: Option<u64>,
    confirmations: Option<u64>,
}

/// GETs `path` from the ZScan API: `None` for a 404, the parsed JSON otherwise.
fn get<T: serde::de::DeserializeOwned>(path: &str) -> Result<Option<T>> {
    let conn = EspHttpConnection::new(&HttpConfig {
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    })?;
    let mut client = Client::wrap(conn);
    let url = format!("{API}{path}");
    let mut resp = client.request(embedded_svc::http::Method::Get, &url, &[("accept", "application/json")])?.submit()?;
    match resp.status() {
        200 => {}
        404 => return Ok(None),
        s => anyhow::bail!("HTTP {s}"),
    }
    // These answers are a few KiB; read them whole.
    let mut body = Vec::with_capacity(4096);
    let mut buf = [0u8; 512];
    loop {
        let n = resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
        anyhow::ensure!(body.len() <= 64 * 1024, "response too large");
    }
    Ok(Some(serde_json::from_slice(&body)?))
}

#[derive(serde::Deserialize)]
struct Price {
    usd: f64,
    usd_24h_change: Option<f64>,
}

fn price() -> Result<String> {
    let p: Price = get("/price")?.ok_or_else(|| anyhow::anyhow!("no price"))?;
    let change = p.usd_24h_change.unwrap_or(0.0);
    Ok(format!("PRICE {} {}", (p.usd * 100.0).round() as u64, (change * 100.0).round() as i64))
}

#[derive(serde::Deserialize)]
struct Network {
    height: u64,
    txs_24h: Option<u64>,
    shielded_tx_ratio_24h: Option<f64>,
}

fn network() -> Result<String> {
    let n: Network = get("/network")?.ok_or_else(|| anyhow::anyhow!("no network"))?;
    let shielded = (n.shielded_tx_ratio_24h.unwrap_or(0.0) * 1000.0).round() as u64;
    Ok(format!("NET {} {} {shielded}", n.height, n.txs_24h.unwrap_or(0)))
}

/// Asks ZScan where `txid` stands.
fn tx_status(txid: &str) -> Result<String> {
    let Some(tx) = get::<Tx>(&format!("/tx/{}", txid.to_ascii_lowercase()))? else {
        return Ok("TX unknown".into());
    };
    Ok(match (tx.status.as_str(), tx.height, tx.confirmations) {
        ("mined", Some(h), Some(c)) => format!("TX mined {h} {c}"),
        ("mempool", ..) => "TX mempool".into(),
        _ => "TX unknown".into(),
    })
}

/// Joins the saved network and stays on it, joining again after a drop or when
/// new credentials arrive.
fn wifi_thread(mut wifi: BlockingWifi<EspWifi<'static>>, shared: &Shared) {
    let set = |n| *shared.net.lock().unwrap() = n;
    let mut joined = u32::MAX;
    loop {
        let wanted = shared.creds.load(Ordering::Acquire);
        let online = wifi.is_connected().unwrap_or(false);
        if online && wanted == joined {
            set(Net::Online);
            thread::sleep(Duration::from_secs(2));
            continue;
        }
        let creds = {
            let nvs = shared.nvs.lock().unwrap();
            let (mut s, mut p) = ([0u8; 33], [0u8; 65]);
            let ssid = nvs.get_str("ssid", &mut s).ok().flatten().map(str::to_owned);
            let pass = nvs.get_str("pass", &mut p).ok().flatten().map(str::to_owned).unwrap_or_default();
            ssid.map(|ssid| (ssid, pass))
        };
        let Some((ssid, pass)) = creds else {
            set(Net::NoWifi);
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        set(Net::Connecting);
        let _ = wifi.disconnect();
        let _ = wifi.stop();
        match join(&mut wifi, &ssid, &pass) {
            Ok(()) => {
                info!("joined {ssid}");
                joined = wanted;
                set(Net::Online);
            }
            Err(e) => {
                warn!("joining {ssid}: {e}");
                set(Net::Failed);
                thread::sleep(Duration::from_secs(10));
            }
        }
    }
}

fn join(wifi: &mut BlockingWifi<EspWifi<'static>>, ssid: &str, pass: &str) -> Result<()> {
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: ssid.try_into().map_err(|_| anyhow::anyhow!("SSID too long"))?,
        password: pass.try_into().map_err(|_| anyhow::anyhow!("password too long"))?,
        auth_method: if pass.is_empty() { AuthMethod::None } else { AuthMethod::WPA2Personal },
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.connect()?;
    wifi.wait_netif_up()?;
    Ok(())
}
