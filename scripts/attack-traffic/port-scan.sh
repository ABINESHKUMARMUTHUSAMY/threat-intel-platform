#!/bin/bash
# Port scan attack — simulates reconnaissance phase.
# Maps to CICIDS2017 "PortScan" label.

set -e

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip> [scan-type]"
    echo "  scan-type: syn (default) | fin | xmas | null"
    exit 1
fi

SCAN_TYPE="${2:-syn}"

case "$SCAN_TYPE" in
    syn)   FLAGS="-sS" ;;
    fin)   FLAGS="-sF" ;;
    xmas)  FLAGS="-sX" ;;
    null)  FLAGS="-sN" ;;
    *)     echo "Unknown scan type: $SCAN_TYPE"; exit 1 ;;
esac

echo "[*] Starting $SCAN_TYPE scan against $TARGET"
echo "[*] Scanning common ports (top 1000)"
sudo nmap $FLAGS -T4 --top-ports 1000 "$TARGET"
echo "[+] Scan complete"
