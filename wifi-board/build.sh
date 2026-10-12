#!/bin/sh
# ./build.sh [esp32s2|esp32s3|esp32c3|esp32c6|esp32]   (default: esp32s2, the Flipper devboard)
# → zfirm-wifi-board-<chip>.bin, one image to write at offset 0.
# ZFIRM_UART_TX / ZFIRM_UART_RX override the Flipper link's pins (default: UART0's own).
set -e
cd "$(dirname "$0")"
CHIP=${1:-esp32s2}
case "$CHIP" in
    esp32) TARGET=xtensa-esp32-espidf ;;
    esp32s2) TARGET=xtensa-esp32s2-espidf ;;
    esp32s3) TARGET=xtensa-esp32s3-espidf ;;
    esp32c3) TARGET=riscv32imc-esp-espidf ;;
    esp32c6) TARGET=riscv32imac-esp-espidf ;;
    *) echo "usage: $0 [esp32s2|esp32s3|esp32c3|esp32c6|esp32]" >&2; exit 1 ;;
esac
MCU=$CHIP cargo build --release --target "$TARGET"
BOOTLOADER=$(ls -t $(find "target/$TARGET/release/build" -name bootloader.bin) | head -1)
espflash save-image --chip "$CHIP" --merge --flash-size 4mb --bootloader "$BOOTLOADER" \
    --partition-table partitions.csv "target/$TARGET/release/zfirm-wifi-board" "zfirm-wifi-board-$CHIP.bin"
echo "zfirm-wifi-board-$CHIP.bin"
