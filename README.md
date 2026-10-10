# ZFlip

A Zcash shielded wallet for the Flipper Zero. The Flipper holds the seed and signs;
the phone app ([zapp](https://github.com/adamzkdev/zapp)) holds the viewing key,
syncs, builds transactions and proofs, and broadcasts. They talk over Bluetooth.

- `core/`: no_std signer core (ZIP 32, Orchard/Ironwood, unified addresses, BIP 39,
  compact QR, review and signing of a compact sign request).
- `bridge/`: PCZT ↔ sign request glue for the phone (Rust, FFI).
- `flipper/`: the Flipper apps (`zflip.fap`, `zflip_setup.fap`), `./build.sh`.
- `dolphin/`: zkSNARKs desktop animations and gallery pack.
- `vendor/`: pasta_curves and sinsemilla trimmed for a Flipper app's RAM.

See PLAN.md.
