"""
TTL Expiration Worker — periodically removes expired blocklist entries.

Lifecycle per cycle:
  1. SELECT * FROM blocklist WHERE active=true AND expires_at < NOW()
  2. For each: try iptables -D INPUT -s <ip> ... -j DROP (idempotent via comment)
  3. UPDATE blocklist SET active=false
  4. Log per-IP outcome
"""
import asyncio
import logging
import os
import subprocess

log = logging.getLogger("expiry-worker")

DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
EXPIRY_CHECK_INTERVAL_S = int(os.getenv("EXPIRY_CHECK_INTERVAL_S", "60"))


async def _remove_iptables_rule(ip: str, alert_id_short: str) -> tuple[bool, str]:
    """Delete the iptables rule for this IP. Returns (success, message)."""
    comment = f"tip:{alert_id_short}"
    cmd = [
        "iptables", "-D", "INPUT",
        "-s", ip,
        "-m", "comment", "--comment", comment,
        "-j", "DROP",
    ]
    if DRY_RUN:
        log.info(f"DRY_RUN — would execute: {' '.join(cmd)}")
        return True, "dry-run"
    try:
        proc = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            return True, "removed"
        # iptables returns nonzero if the rule doesn't exist — treat as ok
        if "does a matching rule exist" in (proc.stderr or "").lower():
            return True, "rule not present (already gone)"
        return False, proc.stderr.strip()
    except Exception as e:
        return False, str(e)


async def expiry_loop(pool, shutdown_event):
    log.info(
        f"expiry worker started: interval={EXPIRY_CHECK_INTERVAL_S}s, "
        f"dry_run={DRY_RUN}"
    )
    while not shutdown_event.is_set():
        try:
            async with pool.acquire() as conn:
                expired = await conn.fetch(
                    """
                    SELECT ip_address::text AS ip, alert_id::text AS alert_id
                    FROM blocklist
                    WHERE active = true
                      AND expires_at IS NOT NULL
                      AND expires_at < NOW()
                    """
                )

            for row in expired:
                ip = row["ip"].split("/")[0]
                alert_short = (row["alert_id"] or "00000000")[:8]
                ok, msg = await _remove_iptables_rule(ip, alert_short)
                if ok:
                    async with pool.acquire() as conn:
                        await conn.execute(
                            """
                            UPDATE blocklist
                            SET active = false
                            WHERE ip_address = $1::inet AND active = true
                            """,
                            ip,
                        )
                    log.info(f"expired block lifted: ip={ip} ({msg})")
                else:
                    log.error(f"failed to lift block on {ip}: {msg}")

        except asyncio.CancelledError:
            break
        except Exception:
            log.exception("expiry loop error")

        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=EXPIRY_CHECK_INTERVAL_S)
        except asyncio.TimeoutError:
            pass
