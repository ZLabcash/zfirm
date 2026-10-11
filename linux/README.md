# ZFirm on Linux

`zfirm` is the ZFirm signer for a Pi Zero, a jailbroken Kindle, any Linux board or a
computer. Same core, same checks and same protocol as ZFlip on the Flipper.

```
zfirm [--link tcp:HOST:PORT | --link /dev/ttyX] [--dir DIR] [--testnet] [--lcd]
```

- `--link tcp:10.55.0.1:7700`: waits for the phone on that address (USB network or Wi-Fi).
- `--link /dev/ttyACM0`: a serial port (a computer).
- `--lcd`: the Waveshare 1.3" LCD HAT; without it, the terminal is the screen
  (arrows, Enter = OK, Tab = hold OK, Esc = Back, letters and digits type).
- `--dir`: where the sealed wallet lives (default `~/.zfirm`).

## Build

```sh
cargo build --release -p zfirm-linux                     # this computer
cargo zigbuild --release -p zfirm-linux --features lcd \
  --target arm-unknown-linux-musleabihf                  # Pi Zero 1.3 (ARMv6)
cargo zigbuild --release -p zfirm-linux \
  --target armv7-unknown-linux-musleabihf                # Kindle, Pi 2+ (ARMv7)
```

The binaries are static: copy `target/<target>/release/zfirm` to the device.

## Pi Zero 1.3 with the LCD HAT

About €30 of parts: a Pi Zero 1.3 (the model without Wi-Fi or Bluetooth), a microSD card
and the Waveshare 1.3" LCD HAT (240×240, joystick, three keys), the screen SeedSigner uses.

1. Flash Raspberry Pi OS Lite (32-bit) and add to `config.txt`:
   ```
   dtoverlay=dwc2
   dtparam=spi=on
   gpio=6,19,5,26,13,21,20,16=pu
   ```
   and `modules-load=dwc2,g_ether` after `rootwait` in `cmdline.txt`.
2. Give `usb0` the address `10.55.0.1/24` and hand out `10.55.0.2` over DHCP on it (e.g.
   with dnsmasq), so the phone gets an address when plugged in.
3. Run `zfirm --lcd --link tcp:10.55.0.1:7700` at boot (a systemd service).

Plugged into the phone's USB port, the Pi powers up and shows up as a wired network: the
cable is the only way in. Keys: joystick = arrows, press or KEY1/KEY2 = OK (held one second =
hold OK, to sign), KEY3 = Back.

Not yet tested on the hardware: the LCD driver and the USB network link to the iPhone.
