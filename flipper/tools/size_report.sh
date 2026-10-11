#!/bin/sh
# Per-crate code size of one app, from an unstripped build: tools/size_report.sh zflip_sign
set -e
cd "$(dirname "$0")/.."
BIN=${1:-zflip_sign}
OUT=target/size-report
SYSROOT=$(rustc --print sysroot)
SEP=$(printf '\037')
FLAGS="-Ctarget-cpu=cortex-m4${SEP}-Cpanic=abort${SEP}-Copt-level=z${SEP}-Cembed-bitcode=yes${SEP}-Clto=yes"
FLAGS="${FLAGS}${SEP}-Clink-args=--script=flipperzero-rt.ld --Bstatic --relocatable --lto-O3 --lto-whole-program-visibility"
CARGO_TARGET_DIR=$OUT CARGO_ENCODED_RUSTFLAGS="$FLAGS" cargo build --release --bin "$BIN" 2>&1 | grep -E "^error" || true
NM=$(find "$SYSROOT" -name llvm-nm | head -1)
"$NM" --size-sort -S -C --radix=d "$OUT/thumbv7em-none-eabihf/release/$BIN" | python3 -c '
import re, sys, collections
c = collections.Counter(); rows = []
for line in sys.stdin:
    p = line.split(None, 3)
    if len(p) < 4: continue
    size, kind, name = int(p[1]), p[2], p[3].strip()
    rows.append((size, name))
    m = re.findall(r"(zfirm_core::sign|zfirm_core::request|zfirm_core::account|zfirm_core|zflip_sign|zflip::|qrcodegen|orchard|pasta_curves|blake2b|sinsemilla|zcash_address|f4jumble|bech32|aes|fpe|reddsa|core::fmt|alloc::|compiler_builtins|flipperzero|core::)", name)
    c[m[0] if m else "other"] += size
for k, v in c.most_common(): print(f"{k:28}{v:>7}")
print("--- largest")
for s, n in sorted(rows)[-25:]: print(f"{s:>6} {n[:110]}")
'
