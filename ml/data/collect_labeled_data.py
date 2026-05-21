"""
Orchestrate attack traffic generation against the sensor, recording exact
start/end timestamps so we can label flows from Postgres by window membership.

Run on the SENSOR. SSH-executes attack scripts on the attacker EC2.

Output: ml/data/attack_windows.json with start/end timestamps per phase.
"""

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

# ===== CONFIG — EDIT THESE =====
ATTACKER_PRIVATE_IP = "10.20.7.205"
SENSOR_PRIVATE_IP = "10.20.9.39"
SSH_KEY = "/home/ubuntu/.ssh/attacker_key"
SCRIPTS_DIR = "/home/ubuntu/attack-scripts"
OUTPUT_FILE = Path("/home/ubuntu/threat-intel-platform/ml/data/attack_windows.json")
# ================================

ATTACKER_HOST = f"ubuntu@{ATTACKER_PRIVATE_IP}"

# Each phase: (label, command, duration_seconds, cooldown_seconds)
# Cooldown lets flows finish (TCP timeouts) before the next phase, so labels are clean.
PHASES = [
    ("BENIGN",     f"{SCRIPTS_DIR}/benign-traffic.sh {SENSOR_PRIVATE_IP} 120",     120, 90),
    ("PortScan",   f"{SCRIPTS_DIR}/port-scan.sh {SENSOR_PRIVATE_IP} syn",          30, 90),
    ("BENIGN",     f"{SCRIPTS_DIR}/benign-traffic.sh {SENSOR_PRIVATE_IP} 90",      90, 90),
    ("Bruteforce", f"{SCRIPTS_DIR}/ssh-bruteforce.sh {SENSOR_PRIVATE_IP}",         30, 90),
    ("BENIGN",     f"{SCRIPTS_DIR}/benign-traffic.sh {SENSOR_PRIVATE_IP} 90",      90, 90),
    ("DoS",        f"{SCRIPTS_DIR}/syn-flood.sh {SENSOR_PRIVATE_IP} 80 60",        60, 90),
    ("BENIGN",     f"{SCRIPTS_DIR}/benign-traffic.sh {SENSOR_PRIVATE_IP} 90",      90, 90),
]


def ssh_run(cmd: str):
    """Execute a command on the attacker via SSH."""
    ssh_cmd = [
        "ssh", "-i", SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        ATTACKER_HOST, cmd,
    ]
    return subprocess.Popen(ssh_cmd, stdout=subprocess.DEVNULL)

def main():
    if "<" in ATTACKER_PRIVATE_IP or "<" in SENSOR_PRIVATE_IP:
        print("ERROR: edit the IP constants at the top of this file before running.")
        return

    windows = []
    total = len(PHASES)
    total_time = sum(d + c for _, _, d, c in PHASES)
    print(f"Starting data collection: {total} phases, ~{total_time/60:.0f} min total\n")

    for i, (label, cmd, duration, cooldown) in enumerate(PHASES, 1):
        print(f"[{i}/{total}] {label}: running ({duration}s)")
        start = datetime.now(timezone.utc)
        proc = ssh_run(cmd)

        time.sleep(duration + 5)

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        end = datetime.now(timezone.utc)
        label_end = end.timestamp() + cooldown
        windows.append({
            "label": label,
            "start_ts": start.isoformat(),
            "end_ts": end.isoformat(),
            "label_until_ts": datetime.fromtimestamp(label_end, tz=timezone.utc).isoformat(),
            "command": cmd,
        })
        print(f"          actual={int((end-start).total_seconds())}s — cooldown {cooldown}s")
        time.sleep(cooldown)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "windows": windows,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "attacker_ip": ATTACKER_PRIVATE_IP,
            "sensor_ip": SENSOR_PRIVATE_IP,
        }, f, indent=2)

    print(f"\nDone. Saved {len(windows)} windows to {OUTPUT_FILE}")
    from collections import Counter
    counts = Counter(w["label"] for w in windows)
    print("Distribution by label:")
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count} windows")


if __name__ == "__main__":
    main()
