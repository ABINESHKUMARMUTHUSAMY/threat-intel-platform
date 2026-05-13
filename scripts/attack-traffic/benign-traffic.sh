#!/bin/bash
# Generate benign traffic — used as negative labels for ML training validation.

set -e

TARGET="${1:-}"
DURATION="${2:-60}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip> [duration-seconds]"
    exit 1
fi

echo "[*] Generating benign traffic for ${DURATION}s"

END_TIME=$(($(date +%s) + DURATION))

while [ $(date +%s) -lt $END_TIME ]; do
    # Mix of healthcheck and short HTTP requests at variable intervals
    curl -s "http://$TARGET:8000/health" > /dev/null &
    curl -s "http://$TARGET:8000/" > /dev/null &
    curl -s "http://$TARGET:8000/flows?limit=10" > /dev/null &

    # Random sleep 0.5 - 3 seconds (mimics human-paced clicks)
    sleep "$(awk -v min=0.5 -v max=3 'BEGIN{srand(); print min+rand()*(max-min)}')"
done

wait
echo "[+] Benign traffic complete"
