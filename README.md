# ZFirm

> [!WARNING]
> **Experimental software. Not audited.** ZFirm is a research prototype. It has not been
> reviewed by any third party, parts of its cryptography were rewritten to fit the Flipper's
> RAM, and none of the devices it runs on has a secure element like a Ledger. Use it only
> with small amounts you can afford to lose, keep your words on paper, and never use a seed
> whose words have been seen by anyone else. No warranty of any kind (see the licenses).

One Zcash shielded signer for any small device you own. The device holds the seed and
signs; the phone app ([ZApp](https://github.com/ZLabcash/zapp)) holds only the viewing key:
it syncs, builds transactions and their proofs, and broadcasts.

| Device | App | Screen and buttons | Link to the phone |
|---|---|---|---|
| Flipper Zero | **ZFlip** (`flipper/`) | its own | Bluetooth |
| Pi Zero 1.3 (no radio) | `zfirm` (`linux/`) | Waveshare 1.3" LCD HAT (the SeedSigner screen) | USB cable, as a network link |
| Jailbroken Kindle, any Linux board, a computer | `zfirm` (`linux/`) | terminal | local network (TCP) or serial |

Add-on: the **Flipper Wi-Fi devboard** (`wifi-board/`). Plugged into the Flipper, it lets ZFlip
follow each transaction it signs (mempool, block, confirmations), show the total in dollars
before signing, and show the network's state. It holds no key. See
[wifi-board/README.md](wifi-board/README.md).

Every device runs the same core (`core/`): the checks, the signing and the protocol
([`session`](core/src/session.rs)); a device only adds a screen, buttons and a link.

## How a payment works

1. The phone, which can see but never spend, builds the transaction (a PCZT) and proves it.
2. It sends a compact sign request to the device.
3. The device checks it against the transaction's commitments itself: who gets what, the fee,
   that the change comes back to this wallet, and that each encrypted note decrypts to exactly
   that note (so neither the recipient nor this wallet can be sent a payment it cannot find).
4. It shows the payment, the recipient, the memo and the fee on its own screen. Hold OK to
   sign, Back to refuse.
5. It returns the signatures; the phone finishes and broadcasts the transaction.

A compromised phone cannot spend without the user seeing the real amount, recipient and memo
on the device.

## Security model, and its limits

On the Flipper:

- The 24-word seed is made on the Flipper from its hardware random number generator.
- It is sealed on the SD card with the PIN (an iterated keyed BLAKE2b) and the Flipper's unique
  secure-enclave key, so a copy of the card alone is useless. Ten wrong PINs wipe the vault.
- Bluetooth pairing uses a 6-digit code shown on the Flipper, and each connection is approved
  on the Flipper.
- Limits: the failed-PIN counter lives on the card (restoring an old copy allows more tries on
  the device itself, so use a long PIN); once unlocked, the spending key is in ordinary RAM; the
  compact SHA-2, PBKDF2, FF1, BIP 39 and BLAKE2b implementations are tested against reference
  implementations but not audited.

On Linux (`linux/`): the seed's entropy is sealed with the PIN (Argon2id, 32 MiB, then
AES-256-GCM) in a file readable by its owner only; ten wrong PINs wipe it. There is no secure
element: a copy of the file can be attacked offline, so use a long PIN. On a Pi Zero 1.3 there
is no radio at all; on a Kindle the link is Wi-Fi, so keep it on a network you trust.

## Layout

- `core/` (`zfirm-core`): no_std signer core (ZIP 32, Orchard/Ironwood, unified addresses,
  BIP 39, compact QR, review and signing of a compact sign request, the device session).
  `cargo test --release --features english`.
- `linux/` (`zfirm-linux`): the `zfirm` app for Linux devices. See [linux/README.md](linux/README.md).
- `bridge/`: PCZT ↔ sign request glue for the iPhone app (Rust, C FFI).
- `flipper/`: the Flipper app, ZFlip (`zflip.fap`, mainnet, and `zflip_setup.fap`, a module it
  launches for creating, restoring, revealing the words and changing the PIN; the Flipper restarts
  after it, so ZFlip always gets a whole heap back), and `zksnarks.fap`, the viewer of the 10,000
  zkSNARKs NFTs (Apps → Media, `snarks.bin` in `apps_data/zksnarks/`). `./build.sh` → `dist/` (Rust nightly: the standard
  library is rebuilt without panic messages to fit the Flipper's RAM).
- `wifi-board/`: firmware for the Flipper Wi-Fi devboard (ESP32-S2, Rust on ESP-IDF).
- `dolphin/`: zkSNARKs desktop animations and `snarks.bin`, the pack for `zksnarks.fap`.
- `vendor/`: `pasta_curves`, `sinsemilla` and a compact `blake2b_simd`, trimmed for a Flipper
  app's ~100 KiB of RAM.

Addresses are Orchard-only unified addresses (`u1…`), received in the Ironwood pool since NU6.3.

## License

MIT or Apache-2.0, at your option. Vendored crates keep their own licenses.
