"""
Suricata eve.json reader service.

Tails /var/log/suricata/eve.json, parses alert events, normalizes to the
alerts schema, inserts to Postgres, publishes to Redis stream alerts:new.

State: tracks the last-read file position in Redis so we don't reprocess
events on restart. Handles log rotation (eve.json rotated to .1) by
detecting inode changes.
"""
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
import redis.asyncio as aioredis

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("suricata-reader")

# === Config ===
EVE_PATH = Path(os.getenv("EVE_PATH", "/var/log/suricata/eve.json"))
POSITION_KEY = os.getenv("POSITION_KEY", "suricata-reader:position")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
STREAM_NAME = os.getenv("STREAM_NAME", "alerts:new")
STREAM_MAXLEN = int(os.getenv("STREAM_MAXLEN", "100000"))

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_USER = os.getenv("POSTGRES_USER", "threat")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "changeme")
PG_DB = os.getenv("POSTGRES_DB", "threat_intel")

POLL_INTERVAL_S = float(os.getenv("POLL_INTERVAL_S", "1.0"))

# === Suricata signature_id → our attack_type taxonomy ===
SID_MAP = {
    9000001: ("PortScan",   "medium"),
    9000002: ("PortScan",   "medium"),
    9000010: ("DoS",        "high"),
    9000011: ("DoS",        "high"),
    9000020: ("Bruteforce", "high"),
    9000021: ("Bruteforce", "high"),
    9000030: ("Bruteforce", "high"),
    9000040: ("DoS",        "high"),
}

stats = {
    "events_read": 0,
    "alerts_seen": 0,
    "alerts_inserted": 0,
    "alerts_published": 0,
    "alerts_unknown_sid": 0,
    "errors": 0,
}


async def setup_postgres():
    pool = await asyncpg.create_pool(
        host=PG_HOST, port=PG_PORT,
        user=PG_USER, password=PG_PASSWORD, database=PG_DB,
        min_size=2, max_size=4,
    )
    log.info(f"connected to postgres at {PG_HOST}:{PG_PORT}")
    return pool


async def setup_redis():
    client = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    await client.ping()
    log.info(f"connected to redis at {REDIS_HOST}:{REDIS_PORT}")
    return client


async def get_starting_position(redis_client) -> int:
    """Load last-read position from Redis. 0 means start from beginning."""
    val = await redis_client.get(POSITION_KEY)
    if val is None:
        # First start ever — skip existing content, start at end-of-file
        if EVE_PATH.exists():
            return EVE_PATH.stat().st_size
        return 0
    try:
        return int(val)
    except ValueError:
        return 0


async def save_position(redis_client, position: int):
    await redis_client.set(POSITION_KEY, str(position))


async def normalize_alert(event: dict) -> dict | None:
    """Convert a Suricata eve.json alert event to our alerts schema fields."""
    alert = event.get("alert", {})
    sid = alert.get("signature_id")

    if sid not in SID_MAP:
        stats["alerts_unknown_sid"] += 1
        return None  # not one of our custom rules; ignore

    attack_type, severity = SID_MAP[sid]
    src_ip = event.get("src_ip")
    dst_ip = event.get("dest_ip")
    if not src_ip or not dst_ip:
        return None

    raw_features = {
        "suricata_sid": sid,
        "suricata_signature": alert.get("signature", ""),
        "suricata_category": alert.get("category", ""),
        "suricata_severity": alert.get("severity"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dest_port"),
        "protocol": event.get("proto"),
        "flow_id": event.get("flow_id"),
        "in_iface": event.get("in_iface"),
    }
    if "http" in event:
        raw_features["http"] = {
            "hostname": event["http"].get("hostname"),
            "url": event["http"].get("url"),
            "http_method": event["http"].get("http_method"),
            "http_user_agent": event["http"].get("http_user_agent"),
            "status": event["http"].get("status"),
        }

    raw_ts = event.get("timestamp")
    parsed_ts = datetime.fromisoformat(raw_ts) if raw_ts else datetime.now(timezone.utc)

    return {
        "timestamp": parsed_ts,
        "attack_type": attack_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        # Suricata doesn't give us a probability; use 1.0 since rule matched explicitly
        "confidence": 1.0,
        "description": f"Suricata signature {sid}: {alert.get('signature', '')}",
        "raw_features": raw_features,
        "detection_source": "suricata",
    }


async def insert_alert(pool, alert: dict) -> str | None:
    """Insert into alerts table, return the new alert_id."""
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO alerts (
                    timestamp, severity, attack_type, confidence,
                    src_ip, dst_ip, description, status,
                    raw_features, detection_source
                )
                VALUES ($1::timestamptz, $2, $3, $4,
                        $5::inet, $6::inet, $7, 'new',
                        $8::jsonb, $9)
                RETURNING id::text
                """,
                alert["timestamp"],
                alert["severity"],
                alert["attack_type"],
                alert["confidence"],
                alert["src_ip"],
                alert["dst_ip"],
                alert["description"],
                json.dumps(alert["raw_features"]),
                alert["detection_source"],
            )
            return row["id"]
        except Exception as e:
            log.exception(f"insert failed for alert: {e}")
            stats["errors"] += 1
            return None


async def publish_to_stream(redis_client, alert_id: str, alert: dict):
    """Publish the alert stub to alerts:new so the response engine picks it up."""
    try:
        await redis_client.xadd(
            STREAM_NAME,
            {
                "alert_id": alert_id,
                "attack_type": alert["attack_type"],
                "severity": alert["severity"],
                "src_ip": alert["src_ip"],
                "detection_source": "suricata",
            },
            maxlen=STREAM_MAXLEN,
            approximate=True,
        )
        stats["alerts_published"] += 1
    except Exception:
        log.exception("redis xadd failed")
        stats["errors"] += 1


async def deduplicate_check(pool, alert: dict, window_seconds: int = 60) -> bool:
    """
    Check if we already have a Suricata alert for the same (src_ip, attack_type)
    in the recent window. Returns True if duplicate (skip), False if new.
    """
    from datetime import timedelta
    async with pool.acquire() as conn:
        existing = await conn.fetchval(
            """
            SELECT id FROM alerts
            WHERE detection_source = 'suricata'
              AND src_ip = $1::inet
              AND attack_type = $2
              AND timestamp > NOW() - $3::interval
            LIMIT 1
            """,
            alert["src_ip"], alert["attack_type"], timedelta(seconds=window_seconds),
        )
    return existing is not None


async def process_event(pool, redis_client, raw_line: str):
    stats["events_read"] += 1
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        return

    if event.get("event_type") != "alert":
        return

    stats["alerts_seen"] += 1
    alert = await normalize_alert(event)
    if alert is None:
        return

    if await deduplicate_check(pool, alert, window_seconds=60):
        return  # dedupe within 60s window — same as detection service

    alert_id = await insert_alert(pool, alert)
    if alert_id is None:
        return
    stats["alerts_inserted"] += 1
    await publish_to_stream(redis_client, alert_id, alert)
    log.info(
        f"alert: sid={alert['raw_features']['suricata_sid']} "
        f"type={alert['attack_type']} src={alert['src_ip']} id={alert_id[:8]}"
    )


async def tail_loop(pool, redis_client, shutdown_event):
    """Tail eve.json, processing new lines as they arrive."""
    if not EVE_PATH.exists():
        log.error(f"eve.json not found at {EVE_PATH}; waiting...")

    position = await get_starting_position(redis_client)
    current_inode = EVE_PATH.stat().st_ino if EVE_PATH.exists() else None
    log.info(f"starting tail at position={position}, inode={current_inode}")

    buffer = ""
    while not shutdown_event.is_set():
        try:
            if not EVE_PATH.exists():
                await asyncio.sleep(POLL_INTERVAL_S)
                continue

            stat = EVE_PATH.stat()

            # Log rotation detection: inode changed, file shrank
            if current_inode != stat.st_ino or position > stat.st_size:
                log.info(f"log rotated (inode {current_inode} -> {stat.st_ino}); restarting from 0")
                position = 0
                current_inode = stat.st_ino
                buffer = ""

            if stat.st_size > position:
                with EVE_PATH.open("rb") as f:
                    f.seek(position)
                    chunk = f.read(stat.st_size - position).decode("utf-8", errors="replace")
                    position = stat.st_size

                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        await process_event(pool, redis_client, line)

                await save_position(redis_client, position)

            await asyncio.sleep(POLL_INTERVAL_S)

        except asyncio.CancelledError:
            break
        except Exception:
            log.exception("tail loop error")
            stats["errors"] += 1
            await asyncio.sleep(2)


async def stats_loop(shutdown_event):
    while not shutdown_event.is_set():
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=15)
        except asyncio.TimeoutError:
            log.info(
                f"stats: events={stats['events_read']} "
                f"alerts_seen={stats['alerts_seen']} "
                f"inserted={stats['alerts_inserted']} "
                f"published={stats['alerts_published']} "
                f"unknown_sid={stats['alerts_unknown_sid']} "
                f"errors={stats['errors']}"
            )


async def main():
    log.info("starting suricata-reader")
    log.info(f"watching: {EVE_PATH}")
    log.info(f"known signature IDs: {sorted(SID_MAP.keys())}")

    pool = await setup_postgres()
    redis_client = await setup_redis()

    shutdown_event = asyncio.Event()

    def _shutdown(*_):
        log.info("shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    await asyncio.gather(
        tail_loop(pool, redis_client, shutdown_event),
        stats_loop(shutdown_event),
    )

    await redis_client.aclose()
    await pool.close()
    log.info("clean shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
