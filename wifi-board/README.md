# ZFirm Wi-Fi board

Firmware for the **Flipper Zero Wi-Fi devboard** (ESP32-S2). Plugged into the Flipper's
GPIO header, it gives ZFlip a view of the network, with no phone needed:

- where each transaction it signs stands: in the mempool, mined in block N, its
  confirmations;
- the ZEC price, so the Confirm screen also shows the total in dollars;
- the network's state: block height, transactions in 24 h, shielded share.

The board never holds a key. All it learns from the Flipper is the Wi-Fi network to join
and the id of a transaction ZFlip just signed (public as soon as the phone broadcasts
it). It asks the [ZScan](https://zscan.cash) API (`api.zscan.cash`) over HTTPS, checking
the server's certificate; ZScan sees the transaction id and the board's IP address.

Without the board, ZFlip works exactly as before: the Wi-Fi badge and the Network entry
only appear while a board answers.

## What about the balance?

A shielded balance is not written anywhere on the chain: finding it means trying to
decrypt every shielded output since the wallet was created, with its viewing key. No API
can do that without being given the viewing key (and with it, every transaction of the
wallet). Scanning on the board itself, with the viewing key only, is planned once its
speed has been measured. Until then the balance stays in the phone app.

## Wi-Fi network

Put a file `wifi.txt` in `apps_data/zflip/` on the Flipper's SD card (with qFlipper):
the network's name on the first line, its password on the second. ZFlip hands it to the
board, which keeps it in its own flash; you may delete the file afterwards.

## Power

The Flipper powers the board from its 5 V pin, which it only switches on when running on
its battery: while the Flipper is plugged into USB, power the board through its own USB-C
port instead.

## Building

You need the Rust toolchain for Xtensa ([espup](https://github.com/esp-rs/espup)),
`espflash`, `ldproxy`, and a Python 3.12 that can create virtual environments (the
ESP-IDF build makes its own; `uv python install 3.12` gives one).

```sh
cargo install espup espflash ldproxy
espup install --targets esp32s2 --std
. ~/export-esp.sh
cargo build --release
```

Then one image with ESP-IDF's own bootloader and the partition table (the app needs more
than the default 1 MB partition):

```sh
B=$(ls -t $(find target/xtensa-esp32s2-espidf/release/build -name bootloader.bin) | head -1)
espflash save-image --chip esp32s2 --merge --flash-size 4mb --bootloader "$B" \
  --partition-table partitions.csv target/xtensa-esp32s2-espidf/release/zfirm-wifi-board zfirm-wifi-board.bin
```

## Flashing

1. Unplug the board's USB-C cable, hold **BOOT**, plug the cable into the computer,
   release **BOOT**: the board is in download mode (no LED).
2. Flash it, without any other command first (opening the port can restart the board):

   ```sh
   uvx --python 3.12 esptool --chip esp32s2 -p /dev/cu.usbmodem01 \
     --before no-reset --after no-reset write-flash --flash-size 4MB 0 zfirm-wifi-board.bin
   ```

3. Unplug and plug the cable back in: the firmware starts. Its log goes to that USB port,
   never to the Flipper.

This replaces the board's stock Black Magic debugger firmware: back it up first with
`esptool read-flash 0 0x400000 backup.bin` (same download mode) to be able to put it back.

## Protocol

One line per message, `\n`-terminated, over UART0 (GPIO 43/44, the header's pins 13/14)
at 115200 baud:

| Flipper sends          | Board answers                                                     |
|------------------------|-------------------------------------------------------------------|
| `ZF?`                  | `ZF 1 nowifi`, `ZF 1 connecting`, `ZF 1 online` or `ZF 1 failed`  |
| `WIFI <ssid>\t<pass>`  | `WIFI saved` (then it joins that network)                         |
| `TX <txid>`            | `TX mempool`, `TX mined <height> <confirmations>`, `TX unknown`, `TX offline` or `TX error` |
| `PRICE`                | `PRICE <usd cents> <24 h change in basis points>`                 |
| `NET`                  | `NET <height> <transactions in 24 h> <shielded share in ‰>`       |

`PRICE` and `NET` answer `<WORD> offline` or `<WORD> error` when they cannot. The Flipper
ignores any other line (the chip's boot messages, for one).
