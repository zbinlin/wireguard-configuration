#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUILD_BIN="$SCRIPT_DIR/build/router_ctl"
TARGET_BIN="$SCRIPT_DIR/target/router_ctl"

BIN=""
if [ -f "$BUILD_BIN" ]; then
    BIN="$BUILD_BIN"
elif [ -f "$TARGET_BIN" ]; then
    BIN="$TARGET_BIN"
else
    echo "[*] router_ctl binary not found, compiling..."
    make -s -C "$SCRIPT_DIR"
    BIN="$BUILD_BIN"
fi

exec "$BIN" "$@"
