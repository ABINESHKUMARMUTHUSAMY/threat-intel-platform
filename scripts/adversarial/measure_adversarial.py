"""
Adversarial robustness measurement.

For each (tool, expected_attack_type) pair, run the attack N times and
measure whether an alert of the expected type fires within a detection
window. Report detection rate.

Output: CSV with one row per trial + summary stats per condition.
"""
import argparse
import csv
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import psycopg2


PG_DSN = "host=localhost port=5432 user=threat password=Personalproject2026-threatintel dbname=threat_intel"
ATTACKER_HOST = "10.20.7.205"
SENSOR_PRIVATE_IP = "10.20.9.39"
SSH_KEY = "/home/ubuntu/.ssh/attacker_key"

# Conditions: (label, attack_script, expected_attack_type, expected_min_confidence)
CONDITIONS = [
    # Training-tool baselines for comparison
    ("baseline_portscan_nmap",      "~/attack-scripts/port-scan.sh {target} syn",         "PortScan",    0.5),
    ("baseline_dos_hping3_slow",    "sudo timeout 30 hping3 -S -p 80 -i u10000 -c 300 {target}", "DoS", 0.5),
    ("baseline_bruteforce_hydra",   "~/attack-scripts/ssh-bruteforce.sh {target}",        "Bruteforce",  0.5),

    # Adversarial conditions
    ("adversarial_portscan_masscan",   "~/attack-scripts/adv-port-scan.sh {target}",      "PortScan",    0.5),
    ("adversarial_dos_hping3_fast",    "~/attack-scripts/adv-dos.sh {target}",            "DoS",         0.5),
    ("adversarial_bruteforce_wfuzz",   "~/attack-scripts/adv-bruteforce.sh {target}",     "Bruteforce",  0.5),
]

DETECTION_WAIT_S = 120  # max wait for alert to appear
INTER_RUN_DELAY_S = 90  # avoid dedupe window (1 min)
RUNS_PER_CONDITION = 5


def now_utc():
    return datetime.now(timezone.utc)


def reset_state():
    """Clear blocklist and iptables between runs so containment doesn't interfere."""
    conn = psycopg2.connect(PG_DSN)
    with conn.cursor() as cur:
        cur.execute("UPDATE blocklist SET active = false WHERE active = true")
    conn.commit()
    conn.close()
    subprocess.run(
        ["bash", "-c",
         "sudo iptables-save | grep -v 'comment.*tip:' | sudo iptables-restore"],
        check=False,
    )


def fire_attack(cmd_template: str) -> datetime:
    cmd = cmd_template.format(target=SENSOR_PRIVATE_IP)
    issued = now_utc()
    subprocess.run(
        ["ssh", "-i", SSH_KEY,
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR",
         f"ubuntu@{ATTACKER_HOST}", cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=180,
    )
    return issued


def poll_for_alert(expected_type: str, since: datetime, min_conf: float):
    """Wait for an alert of expected_type with confidence >= min_conf to appear."""
    conn = psycopg2.connect(PG_DSN)
    deadline = time.monotonic() + DETECTION_WAIT_S
    found = None
    while time.monotonic() < deadline:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text, timestamp, attack_type, severity, confidence::float
                FROM alerts
                WHERE timestamp >= %s
                  AND attack_type = %s
                  AND confidence >= %s
                  AND description NOT LIKE 'SYNTHETIC:%%'
                ORDER BY timestamp ASC
                LIMIT 1
                """,
                (since, expected_type, min_conf),
            )
            row = cur.fetchone()
            if row:
                found = {
                    "alert_id": row[0],
                    "timestamp": row[1],
                    "attack_type": row[2],
                    "severity": row[3],
                    "confidence": row[4],
                }
                break
        conn.commit()
        time.sleep(2)
    conn.close()
    return found


def run_trial(condition: dict, trial: int) -> dict:
    label, cmd_template, expected_type, min_conf = condition
    print(f"\n[{label}] trial {trial}/{RUNS_PER_CONDITION}")
    reset_state()

    issued = fire_attack(cmd_template)
    print(f"  attack issued at {issued.strftime('%H:%M:%S')}, waiting for alert (timeout={DETECTION_WAIT_S}s)...")
    alert = poll_for_alert(expected_type, issued - timedelta(seconds=5), min_conf)

    if alert is None:
        print(f"  ✗ NO ALERT — model failed to detect")
        return {
            "condition": label,
            "trial": trial,
            "expected_type": expected_type,
            "detected": False,
            "alert_id": "",
            "confidence": "",
            "detected_type": "",
        }
    else:
        print(f"  ✓ detected: type={alert['attack_type']} conf={alert['confidence']:.3f}")
        return {
            "condition": label,
            "trial": trial,
            "expected_type": expected_type,
            "detected": True,
            "alert_id": alert["alert_id"],
            "confidence": round(alert["confidence"], 4),
            "detected_type": alert["attack_type"],
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="adversarial_results.csv")
    ap.add_argument("--conditions", default="all",
                    help="Comma-separated condition labels, or 'all'")
    args = ap.parse_args()

    if args.conditions == "all":
        conditions = CONDITIONS
    else:
        wanted = set(args.conditions.split(","))
        conditions = [c for c in CONDITIONS if c[0] in wanted]

    output_path = Path(args.output)
    results = []

    print(f"Running {len(conditions)} conditions × {RUNS_PER_CONDITION} trials each.")
    print(f"Estimated time: ~{len(conditions) * RUNS_PER_CONDITION * (INTER_RUN_DELAY_S + 60) / 60:.0f} minutes\n")

    for ci, condition in enumerate(conditions):
        for trial in range(1, RUNS_PER_CONDITION + 1):
            result = run_trial(condition, trial)
            results.append(result)

            write_header = not output_path.exists()
            with output_path.open("a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "condition", "trial", "expected_type",
                    "detected", "detected_type", "confidence", "alert_id",
                ])
                if write_header:
                    writer.writeheader()
                writer.writerow(result)

            is_last = (ci == len(conditions) - 1) and (trial == RUNS_PER_CONDITION)
            if not is_last:
                print(f"  inter-run delay: {INTER_RUN_DELAY_S}s")
                time.sleep(INTER_RUN_DELAY_S)

    # Summary
    print("\n" + "=" * 60)
    print("DETECTION RATE BY CONDITION")
    print("=" * 60)
    from collections import defaultdict
    by_condition = defaultdict(list)
    for r in results:
        by_condition[r["condition"]].append(r["detected"])
    for cond_label, dets in by_condition.items():
        n = len(dets)
        d = sum(dets)
        rate = d / n * 100 if n else 0
        kind = "ADVERSARIAL" if cond_label.startswith("adversarial") else "BASELINE   "
        print(f"  {kind} {cond_label}: {d}/{n} detected ({rate:.0f}%)")


if __name__ == "__main__":
    main()
