# ZFlip

> [!WARNING]
> **Experimental software. Not audited.** ZFlip is a research prototype. It has not been
> reviewed by any third party, parts of its cryptography were rewritten to fit the Flipper's
> RAM, and the Flipper Zero has no secure element like a Ledger. Use it only with small
> amounts you can afford to lose, keep your 24 words on paper, and never use a seed whose
> words have been seen by anyone else. No warranty of any kind (see the licenses).

A Zcash shielded wallet for the Flipper Zero. The Flipper holds the seed and signs; the
iPhone app ([ZApp](https://github.com/ZLabcash/zapp)) holds only the viewing key: it syncs,
builds transactions and their proofs, and broadcasts. They talk over Bluetooth.

## How a payment works

1. The iPhone, which can see but never spend, builds the transaction (a PCZT) and proves it.
2. It sends a compact sign request to the Flipper over Bluetooth.
3. The Flipper checks it against the transaction's commitments itself: who gets what, the fee,
   and that the change comes back to this wallet.
4. It shows the payment, the recipient and the fee on its own screen. Hold OK to sign, Back to
   refuse.
5. It returns the signatures; the iPhone finishes and broadcasts the transaction.

A compromised phone cannot spend without the user seeing the real amount and recipient on the
Flipper.

## Security model, and its limits

- The 24-word seed is made on the Flipper from its hardware random number generator.
- It is sealed on the SD card with the PIN (an iterated keyed BLAKE2b) and the Flipper's unique
  secure-enclave key, so a copy of the card alone is useless. Ten wrong PINs wipe the vault.
- Bluetooth pairing uses a 6-digit code shown on the Flipper, and each connection is approved
  on the Flipper.
- Limits: the failed-PIN counter lives on the card (restoring an old copy allows more tries on
  the device itself, so use a long PIN); once unlocked, the spending key is in ordinary RAM; the
  compact SHA-2, PBKDF2, FF1, BIP 39 and BLAKE2b implementations are tested against reference
  implementations but not audited.

## Layout

- `core/`: no_std signer core (ZIP 32, Orchard/Ironwood, unified addresses, BIP 39, compact QR,
  review and signing of a compact sign request). `cargo test --release --features english`.
- `bridge/`: PCZT ↔ sign request glue for the iPhone app (Rust, C FFI).
- `flipper/`: the Flipper apps (`zflip.fap`, and `zflip_setup.fap` for creating, restoring and
  revealing). `./build.sh` → `dist/`.
- `dolphin/`: zkSNARKs desktop animations and the NFT gallery pack.
- `vendor/`: `pasta_curves`, `sinsemilla` and a compact `blake2b_simd`, trimmed for a Flipper
  app's ~100 KiB of RAM.

Addresses are Orchard-only unified addresses (`u1…`), received in the Ironwood pool since NU6.3.

## License

MIT or Apache-2.0, at your option. Vendored crates keep their own licenses.
