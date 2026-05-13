#!/bin/bash
# Master script: runs every attack type in sequence with pauses between.
# Used for end-to-end pipeline validation and ML evaluation.

set -e

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================"
echo "Running full attack suite against $TARGET"
echo "Expected duration: ~5 minutes"
echo "================================================"

echo ""
echo "[Phase 1/5] Benign baseline (30s)"
"$SCRIPT_DIR/benign-traffic.sh" "$TARGET" 30
sleep 5

echo ""
echo "[Phase 2/5] Port scan"
"$SCRIPT_DIR/port-scan.sh" "$TARGET" syn
sleep 10

echo ""
echo "[Phase 3/5] SSH brute force"
"$SCRIPT_DIR/ssh-bruteforce.sh" "$TARGET"
sleep 10

echo ""
echo "[Phase 4/5] SYN flood (30s)"
"$SCRIPT_DIR/syn-flood.sh" "$TARGET" 80 30
sleep 10

echo ""
echo "[Phase 5/5] Slow HTTP (30s)"
"$SCRIPT_DIR/slow-http.sh" "$TARGET" 8000 30

echo ""
echo "================================================"
echo "Attack suite complete"
echo "================================================"
