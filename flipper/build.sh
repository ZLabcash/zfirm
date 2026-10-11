#!/bin/sh
# Builds dist/zflip.fap (the app), dist/zflip_setup.fap (its setup module,
# installed to apps_data/zflip/ so it stays out of the Apps menu) and dist/zksnarks.fap
# (the zkSNARKs NFT viewer, an app of its own). Source paths in panic messages are shortened, since the
# whole app (strings included) is loaded into the Flipper's RAM.
#
# Nightly, to rebuild core/alloc without panic messages, panic locations or Debug
# formatting (-Cpanic=immediate-abort, -Zlocation-detail=none, -Zfmt-debug=none):
# ~18 KiB less RAM for zflip.fap, which needs every byte of it to sign. A panic
# still stops the app; it just carries no message. Tested with nightly 2026-04-17;
# set ZFLIP_TOOLCHAIN to pin another.
set -e
TOOLCHAIN=${ZFLIP_TOOLCHAIN:-nightly}
cd "$(dirname "$0")"
SYSROOT=$(rustc +"$TOOLCHAIN" --print sysroot)
REGISTRY=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/ | head -1)
ROOT=$(cd .. && pwd)
SEP=$(printf '\037')
FLAGS="-Ctarget-cpu=cortex-m4${SEP}-Zunstable-options${SEP}-Cpanic=immediate-abort${SEP}-Zlocation-detail=none${SEP}-Zfmt-debug=none${SEP}-Cdebuginfo=0${SEP}-Copt-level=z${SEP}-Cembed-bitcode=yes${SEP}-Clto=yes"
FLAGS="${FLAGS}${SEP}--remap-path-prefix=${REGISTRY%/}=${SEP}--remap-path-prefix=${SYSROOT}/lib/rustlib/src/rust/library=${SEP}--remap-path-prefix=${ROOT}="
FLAGS="${FLAGS}${SEP}-Clink-args=--script=flipperzero-rt.ld --Bstatic --relocatable --discard-all --strip-all --lto-O3 --lto-whole-program-visibility"
CARGO_ENCODED_RUSTFLAGS="$FLAGS" cargo +"$TOOLCHAIN" build --release -Zbuild-std=core,alloc --bin zflip --bin zflip_setup --bin zksnarks
mkdir -p dist
cp target/thumbv7em-none-eabihf/release/zflip dist/zflip.fap
cp target/thumbv7em-none-eabihf/release/zflip_setup dist/zflip_setup.fap
cp target/thumbv7em-none-eabihf/release/zksnarks dist/zksnarks.fap
cp ../core/src/english.txt dist/english.txt
ls -l dist/*.fap
