"""
Response engine — consumes alerts:new Redis stream, runs playbooks idempotently.

Architecture:
- Long-running asyncio loop reads from Redis stream with XREAD blocking
- For each alert, evaluates safeguards then dispatches to applicable playbooks
- Each playbook is independent; failures in one don't block others
- All actions audit-logged to playbook_runs table
"""
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as aioredis

from playbooks.base import PlaybookContext, PlaybookResult
from playbooks.logger_playbook import LoggerPlaybook
from playbooks.noop_playbook import NoopPlaybook
from playbooks.blocklist_playbook import BlocklistPlaybook   # ← NEW
from expiry_worker import expiry_loop  

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("response-engine")

# === Config ===
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
STREAM_NAME = os.getenv("STREAM_NAME", "alerts:new")
CONSUMER_GROUP = os.getenv("CONSUMER_GROUP", "response-engine")
CONSUMER_NAME = os.getenv("CONSUMER_NAME", "engine-1")

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_USER = os.getenv("POSTGRES_USER", "threat")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "changeme")
PG_DB = os.getenv("POSTGRES_DB", "threat_intel")

# Severity threshold — only these and above trigger playbooks
TRIGGER_SEVERITIES = set(os.getenv("TRIGGER_SEVERITIES", "high,critical").split(","))

# Operator allowlist — IPs that must never be blocked or have actions taken against them
OPERATOR_ALLOWLIST = set(
    ip.strip() for ip in os.getenv("OPERATOR_ALLOWLIST", "").split(",") if ip.strip()
)

# Stats counters
stats = {
    "alerts_received": 0,
    "alerts_skipped_severity": 0,
    "alerts_skipped_allowlist": 0,
    "playbooks_run": 0,
    "playbooks_succeeded": 0,
    "playbooks_failed": 0,
    "errors": 0,
}


# === Registry of available playbooks ===
# Built inside main() because some playbooks need the DB pool
PLAYBOOK_REGISTRY: list = []


async def setup_postgres():
    pool = await asyncpg.create_pool(
        host=PG_HOST, port=PG_PORT,
        user=PG_USER, password=PG_PASSWORD, database=PG_DB,
        min_size=2, max_size=8,
    )
    log.info(f"connected to postgres at {PG_HOST}:{PG_PORT}")
    return pool


async def setup_redis():
    client = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    await client.ping()
    log.info(f"connected to redis at {REDIS_HOST}:{REDIS_PORT}")

    # Idempotently create the consumer group (XGROUP CREATE errors if group exists)
    try:
        await client.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
        log.info(f"created consumer group {CONSUMER_GROUP} on stream {STREAM_NAME}")
    except aioredis.ResponseError as e:
        if "BUSYGROUP" in str(e):
            log.info(f"consumer group {CONSUMER_GROUP} already exists")
        else:
            raise
    return client


def parse_alert_message(fields: dict) -> dict | None:
    """Stream fields come as {b'alert_id': b'...', b'attack_type': b'...', ...} or already-decoded dicts."""
    try:
        # decode_responses=True means we already get strings
        alert = dict(fields)
        if isinstance(alert.get("raw_features"), str):
            alert["raw_features"] = json.loads(alert["raw_features"])
        return alert
    except Exception as e:
        log.error(f"failed to parse alert message: {e}")
        return None


async def evaluate_safeguards(alert: dict) -> tuple[bool, str]:
    """Returns (should_proceed, reason). Safeguards run before any playbook."""
    severity = alert.get("severity", "low")
    if severity not in TRIGGER_SEVERITIES:
        return False, f"severity={severity} below trigger threshold"

    src_ip = alert.get("src_ip", "")
    dst_ip = alert.get("dst_ip", "")
    if src_ip in OPERATOR_ALLOWLIST or dst_ip in OPERATOR_ALLOWLIST:
        return False, f"operator-allowlisted IP involved: src={src_ip} dst={dst_ip}"

    return True, "ok"


async def run_playbook(pool, playbook, ctx: PlaybookContext) -> PlaybookResult:
    """Execute one playbook with full audit logging."""
    name = playbook.name
    started_at = datetime.now(timezone.utc)

    # Idempotency check — if this (alert_id, playbook_name) already ran, skip
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            """
            SELECT id, status FROM playbook_runs
            WHERE alert_id = $1 AND playbook_name = $2
            """,
            ctx.alert_id, name,
        )
        if existing:
            log.info(f"[{name}] already ran for alert {ctx.alert_id[:8]} — skipping (status={existing['status']})")
            return PlaybookResult(skipped=True, reason="already-ran")

    # Pre-check
    should_run, reason = await playbook.should_run(ctx)
    if not should_run:
        log.info(f"[{name}] should_run=false for alert {ctx.alert_id[:8]}: {reason}")
        return PlaybookResult(skipped=True, reason=reason)

    # Insert run record as 'running' so concurrent attempts hit unique constraint
    async with pool.acquire() as conn:
        try:
            run_id = await conn.fetchval(
                """
                INSERT INTO playbook_runs (alert_id, playbook_name, started_at, status)
                VALUES ($1, $2, $3, 'running')
                RETURNING id
                """,
                ctx.alert_id, name, started_at,
            )
        except asyncpg.UniqueViolationError:
            log.info(f"[{name}] concurrent run detected for alert {ctx.alert_id[:8]}, skipping")
            return PlaybookResult(skipped=True, reason="concurrent-run")

    # Actually run the playbook
    log.info(f"[{name}] executing for alert {ctx.alert_id[:8]} (attack={ctx.attack_type}, src={ctx.src_ip})")
    try:
        result = await playbook.execute(ctx)
        status = "success" if result.success else "failed"
        completed_at = datetime.now(timezone.utc)
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE playbook_runs
                SET status = $1, actions_taken = $2, completed_at = $3,
                    duration_ms = $4, error_message = $5
                WHERE id = $6
                """,
                status,
                json.dumps(result.actions or []),
                completed_at,
                duration_ms,
                result.error,
                run_id,
            )

        if result.success:
            stats["playbooks_succeeded"] += 1
            log.info(f"[{name}] succeeded in {duration_ms}ms — actions: {result.actions}")
        else:
            stats["playbooks_failed"] += 1
            log.error(f"[{name}] failed in {duration_ms}ms: {result.error}")
        return result

    except Exception as e:
        stats["playbooks_failed"] += 1
        completed_at = datetime.now(timezone.utc)
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)
        log.exception(f"[{name}] exception during execution")

        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE playbook_runs
                SET status = 'failed', completed_at = $1, duration_ms = $2, error_message = $3
                WHERE id = $4
                """,
                completed_at, duration_ms, str(e), run_id,
            )
        return PlaybookResult(success=False, error=str(e))


async def fetch_full_alert(pool, alert_id: str) -> dict | None:
    """Fetch the canonical alert record from Postgres, with IPs cleaned."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                id::text AS alert_id,
                attack_type, severity,
                src_ip::text AS src_ip,
                dst_ip::text AS dst_ip,
                confidence::float AS confidence,
                raw_features, status
            FROM alerts
            WHERE id = $1::uuid
            """,
            alert_id,
        )
    if row is None:
        return None
    d = dict(row)
    # Strip CIDR notation from inet columns
    if d.get("src_ip"):
        d["src_ip"] = d["src_ip"].split("/")[0]
    if d.get("dst_ip"):
        d["dst_ip"] = d["dst_ip"].split("/")[0]
    # raw_features is JSONB; asyncpg returns it as a string
    if isinstance(d.get("raw_features"), str):
        d["raw_features"] = json.loads(d["raw_features"])
    return d

async def handle_alert(pool, alert: dict):
    """Run all applicable playbooks for one alert.

    `alert` is the stub from the Redis stream — only has alert_id and a
    few summary fields. We fetch the canonical record from Postgres.
    """
    stats["alerts_received"] += 1

    alert_id = alert.get("alert_id")
    if not alert_id:
        log.error(f"stream message has no alert_id: {alert}")
        return

    # Fetch canonical alert from Postgres (single source of truth)
    full_alert = await fetch_full_alert(pool, alert_id)
    if full_alert is None:
        log.warning(f"alert {alert_id[:8]} not found in postgres — was it deleted?")
        return

    should_proceed, reason = await evaluate_safeguards(full_alert)
    if not should_proceed:
        if "severity" in reason:
            stats["alerts_skipped_severity"] += 1
        else:
            stats["alerts_skipped_allowlist"] += 1
        log.info(f"alert {alert_id[:8]} skipped: {reason}")
        return

    ctx = PlaybookContext(
        alert_id=full_alert["alert_id"],
        attack_type=full_alert.get("attack_type", "Unknown"),
        severity=full_alert.get("severity", "low"),
        src_ip=full_alert.get("src_ip", ""),
        dst_ip=full_alert.get("dst_ip", ""),
        confidence=float(full_alert.get("confidence", 0.0)),
        raw_features=full_alert.get("raw_features", {}),
    )

    for playbook in PLAYBOOK_REGISTRY:
        if playbook.applies_to(ctx):
            stats["playbooks_run"] += 1
            await run_playbook(pool, playbook, ctx)


async def stream_consumer_loop(pool, redis_client, shutdown_event):
    """Long-running loop: XREADGROUP with block, dispatch to handlers."""
    log.info(f"consumer loop started: stream={STREAM_NAME}, group={CONSUMER_GROUP}")

    while not shutdown_event.is_set():
        try:
            messages = await redis_client.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=CONSUMER_NAME,
                streams={STREAM_NAME: ">"},
                count=10,
                block=5000,
            )
            if not messages:
                continue

            for stream_key, entries in messages:
                for msg_id, fields in entries:
                    alert = parse_alert_message(fields)
                    if alert is None:
                        await redis_client.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)
                        continue
                    try:
                        await handle_alert(pool, alert)
                    except Exception:
                        stats["errors"] += 1
                        log.exception(f"unhandled error processing alert {msg_id}")
                    finally:
                        await redis_client.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)

        except asyncio.CancelledError:
            break
        except Exception:
            stats["errors"] += 1
            log.exception("consumer loop error")
            await asyncio.sleep(2)


async def stats_loop(shutdown_event):
    while not shutdown_event.is_set():
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=10)
        except asyncio.TimeoutError:
            log.info(
                f"stats: received={stats['alerts_received']} "
                f"skipped_sev={stats['alerts_skipped_severity']} "
                f"skipped_allow={stats['alerts_skipped_allowlist']} "
                f"runs={stats['playbooks_run']} "
                f"ok={stats['playbooks_succeeded']} "
                f"fail={stats['playbooks_failed']} "
                f"errors={stats['errors']}"
            )


async def main():
    log.info("starting response engine")
    log.info(f"trigger severities: {TRIGGER_SEVERITIES}")
    log.info(f"operator allowlist: {OPERATOR_ALLOWLIST or '(empty)'}")
    log.info(f"registered playbooks: {[p.name for p in PLAYBOOK_REGISTRY]}")

    pool = await setup_postgres()
    redis_client = await setup_redis()
    PLAYBOOK_REGISTRY.extend([
        LoggerPlaybook(),
        BlocklistPlaybook(pool=pool),
        NoopPlaybook(),
    ])
    log.info(f"playbooks loaded: {[p.name for p in PLAYBOOK_REGISTRY]}")

    shutdown_event = asyncio.Event()

    def _shutdown(*_):
        log.info("shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    await asyncio.gather(
        stream_consumer_loop(pool, redis_client, shutdown_event),
        stats_loop(shutdown_event),
        expiry_loop(pool, shutdown_event),   # ← NEW
    )

    await redis_client.aclose()
    await pool.close()
    log.info("clean shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
