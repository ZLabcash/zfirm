# ZFirm Wi-Fi board

Firmware for the **Flipper Zero Wi-Fi devboard** (ESP32-S2), or any ESP32 with Wi-Fi.
Plugged into the Flipper's GPIO header, it gives ZFlip a view of the network, with no
phone needed:

- where each transaction it signs stands: in the mempool, mined in block N, its
  confirmations;
- the ZEC price, so the Confirm screen also shows the total in dollars;
- the network's state: block height, transactions in 24 h, shielded share.

The board never holds a key. All it learns from the Flipper is the Wi-Fi network to join
and the id of a transaction ZFlip just signed (public as soon as the phone broadcasts
it). It asks the [ZScan](https://zscan.cash) API (`api.zscan.cash`) over HTTPS, checking
the server's certificate; ZScan sees the transaction id and the board's IP address.

ZFlip asks before using a board it finds ("Let it go online?", like a phone asking over
Bluetooth). Then a Wi-Fi icon shows next to the Bluetooth one, and the home screen gets a
**Blockchain** entry: **Activity** (today's signed transactions and where each stands,
kept on the SD card across restarts) and **Stats**. Without a board, ZFlip works exactly
as before.

## What about the balance?

A shielded balance is not written anywhere on the chain: finding it means trying to
decrypt every shielded output since the wallet was created, with its viewing key. No API
can do that without being given the viewing key (and with it, every transaction of the
wallet). Scanning on the board itself, with the viewing key only, is planned once its
speed has been measured. Until then the balance stays in the phone app.

## Wi-Fi network

On the Flipper: ZFlip → Settings → Wi-Fi network (the Flipper's keyboard; the password
is never shown again). ZFlip keeps it in `apps_data/zflip/wifi.txt` and hands it to the
board, which keeps it in its own flash.

## Power

ZFlip switches the Flipper's 5 V pin on while it is open and listens for a board, so one
plugged in at any time is found within seconds. The Flipper only gives that 5 V on its
battery: while it is plugged into USB, power the board through its own USB port.

## Chips

The Flipper's own Wi-Fi devboard is an ESP32-S2. Any ESP32 with Wi-Fi works too, wired
to the Flipper's header: 3V3 or 5V and GND, its TX to pin 14 and its RX to pin 13.

| Chip | Build | Flipper link (TX / RX, UART0) | Log |
|---|---|---|---|
| ESP32-S2 (Flipper devboard) | `./build.sh esp32s2` | GPIO 43 / 44 | its USB port |
| ESP32-S3 | `./build.sh esp32s3` | GPIO 43 / 44 | its USB port |
| ESP32-C3 | `./build.sh esp32c3` | GPIO 21 / 20 | its USB port |
| ESP32-C6 | `./build.sh esp32c6` | GPIO 16 / 17 | its USB port |
| ESP32 | `./build.sh esp32` | GPIO 1 / 3 | none (no USB of its own) |

A board wired to other pins: `ZFIRM_UART_TX=17 ZFIRM_UART_RX=18 ./build.sh esp32s3`.

## Building

You need the Rust toolchain for ESP32 ([espup](https://github.com/esp-rs/espup)),
`espflash`, `ldproxy`, and a Python 3.12 that can create virtual environments (the
ESP-IDF build makes its own; `uv python install 3.12` gives one).

```sh
cargo install espup espflash ldproxy
espup install --targets all --std
. ~/export-esp.sh
./build.sh esp32s2
```

This makes `zfirm-wifi-board-esp32s2.bin`: ESP-IDF's own bootloader, the partition
table (the app needs more than the default 1 MB partition) and the app, as one image
written at offset 0.

## Flashing

With the board's USB port plugged into the computer, and the firmware already on it,
one command resets it into download mode and flashes it (`--before default-reset`). On
a new board (or a stuck one): unplug it, hold **BOOT**, plug it in, release **BOOT**.

```sh
uvx --python 3.12 esptool --chip esp32s2 -p /dev/cu.usbmodem01 \
  --before default-reset --after no-reset write-flash --flash-size 4MB 0 zfirm-wifi-board-esp32s2.bin
```

Then unplug and plug it back in: the firmware starts. Its log goes to that USB port
(115200 baud; open it with DTR and RTS low, or the board restarts into download mode).

This replaces the devboard's stock Black Magic debugger firmware: back it up first with
`esptool read-flash 0 0x400000 backup.bin` (in download mode) to be able to put it back.

## Protocol

One line per message, `\n`-terminated, over UART0 (GPIO 43/44, the header's pins 13/14)
at 115200 baud:

| Flipper sends          | Board answers                                                     |
|------------------------|-------------------------------------------------------------------|
| `ZF?`                  | `ZF 1 nowifi`, `ZF 1 connecting`, `ZF 1 online` or `ZF 1 failed` (also sent unasked every 2 s) |
| `WIFI <ssid>\t<pass>`  | `WIFI saved` (then it joins that network)                         |
| `TX <txid>`            | `TX mempool`, `TX mined <height> <confirmations>`, `TX unknown`, `TX offline` or `TX error` |
| `PRICE`                | `PRICE <usd cents> <24 h change in basis points>`                 |
| `NET`                  | `NET <height> <transactions in 24 h> <shielded share in ‰>`       |

`PRICE` and `NET` answer `<WORD> offline` or `<WORD> error` when they cannot. The Flipper
ignores any other line (the chip's boot messages, for one).
