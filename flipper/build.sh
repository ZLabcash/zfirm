#!/bin/sh
# Builds dist/zflip.fap (the app) and dist/zflip_setup.fap (its setup module,
# installed to apps_data/zflip/ so it stays out of the Apps menu). Source paths in panic messages are shortened, since the
# whole app (strings included) is loaded into the Flipper's RAM.
set -e
cd "$(dirname "$0")"
SYSROOT=$(rustc --print sysroot)
REGISTRY=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/ | head -1)
ROOT=$(cd .. && pwd)
SEP=$(printf '\037')
FLAGS="-Ctarget-cpu=cortex-m4${SEP}-Cpanic=abort${SEP}-Cdebuginfo=0${SEP}-Copt-level=z${SEP}-Cembed-bitcode=yes${SEP}-Clto=yes"
FLAGS="${FLAGS}${SEP}--remap-path-prefix=${REGISTRY%/}=${SEP}--remap-path-prefix=${SYSROOT}/lib/rustlib/src/rust/library=${SEP}--remap-path-prefix=${ROOT}="
FLAGS="${FLAGS}${SEP}-Clink-args=--script=flipperzero-rt.ld --Bstatic --relocatable --discard-all --strip-all --lto-O3 --lto-whole-program-visibility"
CARGO_ENCODED_RUSTFLAGS="$FLAGS" cargo build --release
mkdir -p dist
cp target/thumbv7em-none-eabihf/release/zflip dist/zflip.fap
cp target/thumbv7em-none-eabihf/release/zflip_setup dist/zflip_setup.fap
cp ../core/src/english.txt dist/english.txt
ls -l dist/*.fap
