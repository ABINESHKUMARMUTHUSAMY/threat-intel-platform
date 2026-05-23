"""
MTTC measurement script.

Runs N attacks, polls Postgres for the resulting high-severity alert,
records timestamps for analysis.

Modes:
  manual: pauses after alert visibility, waits for human to confirm containment
  automated: polls playbook_runs for blocklist completion

Output: CSV with one row per run.

Usage:
  python3 measure_mttc.py --mode manual --runs 5 --output manual.csv
  python3 measure_mttc.py --mode automated --runs 5 --output automated.csv
"""
import argparse
import csv
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import psycopg2


import os

PG_PASSWORD = os.getenv("POSTGRES_PASSWORD")
if not PG_PASSWORD:
    print("ERROR: POSTGRES_PASSWORD env var not set")
    print("Run: export POSTGRES_PASSWORD=$(grep POSTGRES_PASSWORD ~/threat-intel-platform/infra/.env | cut -d= -f2)")
    sys.exit(1)

PG_DSN = f"host=localhost port=5432 user=threat password={PG_PASSWORD} dbname=threat_intel"
ATTACKER_HOST = "10.20.7.205"
SENSOR_PRIVATE_IP = "10.20.9.39"
SSH_KEY = "/home/ubuntu/.ssh/attacker_key"

# Inter-run delay so the dedupe window (5 min in detection.py) doesn't suppress alerts
INTER_RUN_DELAY_S = 90  # 6 minutes


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def fire_attack(attack_type: str) -> datetime:
    """SSH to attacker and fire a DoS attack. Returns local timestamp of issuance."""
    if attack_type == "DoS":
        cmd = (
            f"sudo hping3 -S -p 80 -i u10000 -c 100 {SENSOR_PRIVATE_IP}"
        )
    elif attack_type == "Bruteforce":
        cmd = f"~/attack-scripts/ssh-bruteforce.sh {SENSOR_PRIVATE_IP}"
    else:
        raise ValueError(f"unknown attack type: {attack_type}")

    issued = now_utc()
    subprocess.run(
        ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
         f"ubuntu@{ATTACKER_HOST}", cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=180,
    )
    return issued


def poll_for_alert(conn, attack_type: str, since: datetime, timeout_s: int = 180) -> dict | None:
    """Poll alerts table until a high-severity alert of the given type appears."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text, timestamp, attack_type, severity,
                       src_ip::text, dst_ip::text, confidence::float
                FROM alerts
                WHERE timestamp >= %s
                  AND attack_type = %s
                  AND severity = 'high'
                  AND description NOT LIKE 'SYNTHETIC:%%'
                ORDER BY timestamp ASC
                LIMIT 1
                """,
                (since, attack_type),
            )
            row = cur.fetchone()
            if row:
                return {
                    "alert_id": row[0],
                    "timestamp": row[1],
                    "attack_type": row[2],
                    "severity": row[3],
                    "src_ip": row[4].split("/")[0] if row[4] else "",
                    "dst_ip": row[5].split("/")[0] if row[5] else "",
                    "confidence": row[6],
                }
        conn.commit()
        time.sleep(2)
    return None


def poll_for_playbook(conn, alert_id: str, playbook_name: str, timeout_s: int = 120) -> datetime | None:
    """Poll playbook_runs until the named playbook completes for this alert."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT completed_at FROM playbook_runs
                WHERE alert_id = %s::uuid
                  AND playbook_name = %s
                  AND status = 'success'
                  AND completed_at IS NOT NULL
                """,
                (alert_id, playbook_name),
            )
            row = cur.fetchone()
            if row:
                return row[0]
        conn.commit()
        time.sleep(0.5)
    return None


def reset_state(conn):
    """Clear blocklist and iptables between runs so each measurement starts clean."""
    with conn.cursor() as cur:
        cur.execute("UPDATE blocklist SET active = false WHERE active = true")
    conn.commit()
    # Remove all tip: iptables rules — broad sweep so manual-mode runs don't leave residue
    subprocess.run(
        ["bash", "-c",
         "sudo iptables-save | grep -v 'comment.*tip:' | sudo iptables-restore"],
        check=False,
    )


def run_manual(conn, run_num: int, attack_type: str) -> dict:
    print(f"\n=== Manual Run {run_num}: {attack_type} ===")
    reset_state(conn)

    print(f"[{now_utc().strftime('%H:%M:%S')}] firing attack...")
    issued_at = fire_attack(attack_type)
    print(f"[{now_utc().strftime('%H:%M:%S')}] attack issued, polling for alert...")

    alert = poll_for_alert(conn, attack_type, issued_at - timedelta(seconds=10))
    if alert is None:
        print("TIMEOUT — no alert appeared within 180s")
        return {"run": run_num, "mode": "manual", "attack_type": attack_type, "status": "timeout"}

    # Use canonical alert.timestamp (same reference as automated mode)
    alert_visible_at = alert["timestamp"]
    if alert_visible_at.tzinfo is None:
        alert_visible_at = alert_visible_at.replace(tzinfo=timezone.utc)
    src_ip = alert["src_ip"]
    print(f"[{alert_visible_at.strftime('%H:%M:%S')}] ALERT VISIBLE — id={alert['alert_id'][:8]} src={src_ip}")
    print()
    print("=" * 60)
    print(f"MANUAL ACTION REQUIRED")
    print(f"  1. Open new terminal: ssh -i ~/.ssh/threat-intel-key.pem ubuntu@<SENSOR_PUBLIC_IP>")
    print(f"  2. Run: sudo iptables -I INPUT -s {src_ip} -m comment --comment 'tip:manual{run_num}' -j DROP")
    print(f"  3. Verify: sudo iptables -L INPUT -n | grep {src_ip}")
    print(f"  4. Press ENTER when block is verified in place")
    print("=" * 60)

    input(">>> Press ENTER when block is verified: ")
    containment_at = now_utc()

    mttc_seconds = (containment_at - alert_visible_at).total_seconds()
    print(f"[{containment_at.strftime('%H:%M:%S')}] containment verified — MTTC = {mttc_seconds:.2f}s")

    return {
        "run": run_num,
        "mode": "manual",
        "attack_type": attack_type,
        "alert_id": alert["alert_id"],
        "src_ip": src_ip,
        "alert_visible_at": alert_visible_at.isoformat(),
        "containment_at": containment_at.isoformat(),
        "mttc_seconds": round(mttc_seconds, 3),
        "status": "ok",
    }


def run_automated(conn, run_num: int, attack_type: str) -> dict:
    print(f"\n=== Automated Run {run_num}: {attack_type} ===")
    reset_state(conn)

    print(f"[{now_utc().strftime('%H:%M:%S')}] firing attack...")
    issued_at = fire_attack(attack_type)
    print(f"[{now_utc().strftime('%H:%M:%S')}] attack issued, polling for alert...")

    alert = poll_for_alert(conn, attack_type, issued_at - timedelta(seconds=10))
    if alert is None:
        print("TIMEOUT — no alert appeared within 180s")
        return {"run": run_num, "mode": "automated", "attack_type": attack_type, "status": "timeout"}

    alert_visible_at = alert["timestamp"]
    # Ensure timezone awareness for comparison with completed_at
    if alert_visible_at.tzinfo is None:
        alert_visible_at = alert_visible_at.replace(tzinfo=timezone.utc)
    print(f"[{alert_visible_at.strftime('%H:%M:%S')}] ALERT VISIBLE — id={alert['alert_id'][:8]} src={alert['src_ip']}")
    print(f"[{now_utc().strftime('%H:%M:%S')}] polling for blocklist playbook completion...")

    completed_at = poll_for_playbook(conn, alert["alert_id"], "blocklist")
    if completed_at is None:
        print("TIMEOUT — playbook did not complete within 120s")
        return {"run": run_num, "mode": "automated", "attack_type": attack_type, "status": "playbook_timeout"}

    # completed_at from DB is timezone-aware
    mttc_seconds = (completed_at - alert_visible_at).total_seconds()
    print(f"[{completed_at.strftime('%H:%M:%S')}] containment verified — MTTC = {mttc_seconds:.2f}s")

    return {
        "run": run_num,
        "mode": "automated",
        "attack_type": attack_type,
        "alert_id": alert["alert_id"],
        "src_ip": alert["src_ip"],
        "alert_visible_at": alert_visible_at.isoformat(),
        "containment_at": completed_at.isoformat(),
        "mttc_seconds": round(mttc_seconds, 3),
        "status": "ok",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["manual", "automated"], required=True)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--output", required=True)
    ap.add_argument("--attack-types", default="DoS",
                    help="Comma-separated attack types to cycle through")
    args = ap.parse_args()

    attack_types = [a.strip() for a in args.attack_types.split(",")]
    output_path = Path(args.output)
    conn = psycopg2.connect(PG_DSN)

    results = []
    runner = run_manual if args.mode == "manual" else run_automated

    for i in range(1, args.runs + 1):
        attack = attack_types[(i - 1) % len(attack_types)]
        result = runner(conn, i, attack)
        results.append(result)

        # Append to CSV incrementally so we don't lose data on crash
        write_header = not output_path.exists()
        with output_path.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "run", "mode", "attack_type", "alert_id", "src_ip",
                "alert_visible_at", "containment_at", "mttc_seconds", "status",
            ])
            if write_header:
                writer.writeheader()
            writer.writerow({k: result.get(k, "") for k in writer.fieldnames})

        if i < args.runs:
            print(f"\n--- inter-run cooldown: {INTER_RUN_DELAY_S}s (dedupe window) ---")
            time.sleep(INTER_RUN_DELAY_S)

    conn.close()

    # Summary
    ok = [r for r in results if r.get("status") == "ok"]
    if ok:
        times = [r["mttc_seconds"] for r in ok]
        times.sort()
        n = len(times)
        mean = sum(times) / n
        median = times[n // 2] if n % 2 else (times[n // 2 - 1] + times[n // 2]) / 2
        print(f"\n=== {args.mode} summary (n={n}/{args.runs}) ===")
        print(f"  mean:   {mean:.2f}s")
        print(f"  median: {median:.2f}s")
        print(f"  min:    {min(times):.2f}s")
        print(f"  max:    {max(times):.2f}s")
    else:
        print(f"\n=== {args.mode} summary: NO SUCCESSFUL RUNS ===")


if __name__ == "__main__":
    main()
