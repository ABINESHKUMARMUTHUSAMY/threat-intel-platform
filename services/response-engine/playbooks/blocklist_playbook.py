"""
BlocklistPlaybook — blocks the attacker IP via iptables on the sensor.

Lifecycle:
  - applies_to: any high/critical alert with src_ip set
  - should_run: refuses if IP already actively blocked OR if IP is on operator allowlist
                (engine-level guard catches the second case earlier; this is defense in depth)
  - execute:
      1. INSERT into blocklist (idempotent via ON CONFLICT)
      2. iptables -I INPUT -s <ip> -j DROP -m comment --comment "tip:<short_alert_id>"
      3. log both actions to actions_taken
"""
import asyncio
import json
import logging
import os
import subprocess
from datetime import datetime, timedelta, timezone

import asyncpg

from .base import Playbook, PlaybookContext, PlaybookResult

log = logging.getLogger("playbook.blocklist")

DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
BLOCK_TTL_MINUTES = int(os.getenv("BLOCK_TTL_MINUTES", "60"))
OPERATOR_ALLOWLIST = set(
    ip.strip() for ip in os.getenv("OPERATOR_ALLOWLIST", "").split(",") if ip.strip()
)


class BlocklistPlaybook(Playbook):
    name = "blocklist"

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    def applies_to(self, ctx: PlaybookContext) -> bool:
        # Only fire for alerts where we have a clear external source to block
        if not ctx.src_ip:
            return False
        # Don't block our own infra (the sensor itself, the bait service, etc.)
        # The sensor is what's being attacked TO; we wouldn't block it FROM itself.
        if ctx.src_ip.startswith("10.20.9."):  # sensor's subnet
            return False
        return True

    async def should_run(self, ctx: PlaybookContext) -> tuple[bool, str]:
        # Defense in depth — engine already checked, but check again here
        if ctx.src_ip in OPERATOR_ALLOWLIST:
            return False, f"src_ip {ctx.src_ip} is on operator allowlist"

        # Idempotency — is this IP already actively blocked and not expired?
        async with self.pool.acquire() as conn:
            existing = await conn.fetchrow(
                """
                SELECT id, expires_at FROM blocklist
                WHERE ip_address = $1::inet AND active = true
                  AND (expires_at IS NULL OR expires_at > NOW())
                """,
                ctx.src_ip,
            )
        if existing:
            return False, f"ip {ctx.src_ip} already blocked until {existing['expires_at']}"

        return True, "ok"

    async def execute(self, ctx: PlaybookContext) -> PlaybookResult:
        actions = []
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=BLOCK_TTL_MINUTES)
        reason = (
            f"{ctx.attack_type} (sev={ctx.severity}, "
            f"xgb_conf={ctx.confidence:.3f}, alert={ctx.alert_id[:8]})"
        )

        # --- Action 1: Insert into blocklist table ---
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO blocklist (ip_address, reason, alert_id, expires_at, active)
                    VALUES ($1::inet, $2, $3::uuid, $4, true)
                    ON CONFLICT (ip_address) DO UPDATE
                    SET reason = EXCLUDED.reason,
                        alert_id = EXCLUDED.alert_id,
                        expires_at = EXCLUDED.expires_at,
                        active = true,
                        blocked_at = NOW()
                    """,
                    ctx.src_ip, reason, ctx.alert_id, expires_at,
                )
            actions.append({
                "type": "blocklist_db",
                "ip": ctx.src_ip,
                "ttl_minutes": BLOCK_TTL_MINUTES,
                "expires_at": expires_at.isoformat(),
            })
            log.info(f"blocklist db: {ctx.src_ip} expires {expires_at.isoformat()}")
        except Exception as e:
            log.exception("blocklist db insert failed")
            return PlaybookResult(success=False, actions=actions, error=f"db insert failed: {e}")

        # --- Action 2: Apply iptables DROP rule ---
        comment = f"tip:{ctx.alert_id[:8]}"
        iptables_cmd = [
            "iptables", "-I", "INPUT",
            "-s", ctx.src_ip,
            "-m", "comment", "--comment", comment,
            "-j", "DROP",
        ]

        if DRY_RUN:
            log.info(f"DRY_RUN — would execute: {' '.join(iptables_cmd)}")
            actions.append({
                "type": "iptables",
                "ip": ctx.src_ip,
                "rule": " ".join(iptables_cmd),
                "dry_run": True,
            })
        else:
            try:
                # Run blocking subprocess in default executor so we don't stall asyncio loop
                proc = await asyncio.to_thread(
                    subprocess.run, iptables_cmd,
                    capture_output=True, text=True, timeout=10,
                )
                if proc.returncode != 0:
                    raise RuntimeError(
                        f"iptables returned {proc.returncode}: {proc.stderr.strip()}"
                    )
                actions.append({
                    "type": "iptables",
                    "ip": ctx.src_ip,
                    "rule": " ".join(iptables_cmd),
                    "stdout": proc.stdout.strip(),
                })
                log.info(f"iptables DROP added for {ctx.src_ip} (comment={comment})")
            except Exception as e:
                log.exception("iptables apply failed")
                # Try to rollback the blocklist row
                try:
                    async with self.pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE blocklist SET active = false WHERE ip_address = $1::inet",
                            ctx.src_ip,
                        )
                    actions.append({"type": "rollback_blocklist_db", "ip": ctx.src_ip})
                except Exception:
                    log.exception("blocklist rollback also failed")
                return PlaybookResult(
                    success=False, actions=actions,
                    error=f"iptables failed: {e}",
                )

        return PlaybookResult(success=True, actions=actions)
