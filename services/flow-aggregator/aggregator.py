"""
Flow aggregator service.

Consumes per-packet records from Redis Stream `packets:raw`, groups them
into 5-tuple flows, computes CICFlowMeter-aligned features on flow
termination, and writes complete flows to Postgres.

Flow termination conditions (any one triggers flush):
  - TCP FIN or RST seen in either direction
  - 60 seconds of inactivity (idle timeout)
  - 120 seconds since flow start (hard cap)
"""

import asyncio
import json
import logging
import os
import signal
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as redis

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
STREAM_NAME = os.getenv("STREAM_NAME", "packets:raw")
CONSUMER_GROUP = os.getenv("CONSUMER_GROUP", "flow-aggregator")
CONSUMER_NAME = os.getenv("CONSUMER_NAME", "agg-1")

POSTGRES_DSN = (
    f"postgresql://{os.getenv('POSTGRES_USER', 'threat')}:"
    f"{os.getenv('POSTGRES_PASSWORD', 'changeme')}@"
    f"{os.getenv('POSTGRES_HOST', 'postgres')}:"
    f"{os.getenv('POSTGRES_PORT', '5432')}/"
    f"{os.getenv('POSTGRES_DB', 'threat_intel')}"
)

IDLE_TIMEOUT_S = int(os.getenv("IDLE_TIMEOUT_S", "60"))
FLOW_HARD_CAP_S = int(os.getenv("FLOW_HARD_CAP_S", "120"))
FLUSH_INTERVAL_S = int(os.getenv("FLUSH_INTERVAL_S", "5"))
STATS_INTERVAL_S = int(os.getenv("STATS_INTERVAL_S", "10"))

# TCP flag bits
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("aggregator")


# ----------------------------------------------------------------------
# Flow data structure
# ----------------------------------------------------------------------
class Flow:
    """A single network flow, accumulating packet stats over its lifetime."""

    __slots__ = (
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "start_ts", "last_ts",
        "fwd_packet_count", "bwd_packet_count",
        "fwd_bytes", "bwd_bytes",
        "fwd_packet_lengths", "bwd_packet_lengths",
        "packet_timestamps",
        "syn_count", "ack_count", "fin_count", "rst_count",
        "psh_count", "urg_count",
        "terminated",
    )

    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, first_pkt_ts):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_ts = first_pkt_ts
        self.last_ts = first_pkt_ts
        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.packet_timestamps = []
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0
        self.terminated = False

    def add_packet(self, pkt: dict, forward: bool):
        """Update flow with a new packet."""
        ts = pkt["ts_epoch"]
        self.last_ts = ts
        self.packet_timestamps.append(ts)
        pkt_len = pkt["pkt_len"]

        if forward:
            self.fwd_packet_count += 1
            self.fwd_bytes += pkt_len
            self.fwd_packet_lengths.append(pkt_len)
        else:
            self.bwd_packet_count += 1
            self.bwd_bytes += pkt_len
            self.bwd_packet_lengths.append(pkt_len)

        flags = pkt.get("tcp_flags", 0)
        if flags & TCP_SYN:
            self.syn_count += 1
        if flags & TCP_ACK:
            self.ack_count += 1
        if flags & TCP_FIN:
            self.fin_count += 1
            self.terminated = True
        if flags & TCP_RST:
            self.rst_count += 1
            self.terminated = True
        if flags & TCP_PSH:
            self.psh_count += 1
        if flags & TCP_URG:
            self.urg_count += 1

    def is_idle(self, now: float) -> bool:
        return (now - self.last_ts) >= IDLE_TIMEOUT_S

    def is_too_old(self, now: float) -> bool:
        return (now - self.start_ts) >= FLOW_HARD_CAP_S

    def should_flush(self, now: float) -> bool:
        return self.terminated or self.is_idle(now) or self.is_too_old(now)

    def to_db_row(self) -> dict:
        """Compute aggregate features and return a dict for DB insertion."""
        all_lengths = self.fwd_packet_lengths + self.bwd_packet_lengths
        duration_ms = int((self.last_ts - self.start_ts) * 1000)

        # Inter-arrival times (sorted by capture order — packet_timestamps is append-order)
        iats = []
        sorted_ts = sorted(self.packet_timestamps)
        for i in range(1, len(sorted_ts)):
            iats.append((sorted_ts[i] - sorted_ts[i - 1]) * 1000)

        def safe_stat(fn, data, default=0):
            try:
                return fn(data) if data else default
            except statistics.StatisticsError:
                return default

        return {
            "timestamp": datetime.fromtimestamp(self.start_ts, tz=timezone.utc),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self._proto_name(),
            "duration_ms": duration_ms,
            "fwd_packet_count": self.fwd_packet_count,
            "bwd_packet_count": self.bwd_packet_count,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "urg_count": self.urg_count,
            "iat_mean_ms": safe_stat(statistics.mean, iats),
            "iat_std_ms": safe_stat(statistics.stdev, iats) if len(iats) > 1 else 0,
            "iat_min_ms": min(iats) if iats else 0,
            "iat_max_ms": max(iats) if iats else 0,
            "pkt_len_mean": safe_stat(statistics.mean, all_lengths),
            "pkt_len_std": safe_stat(statistics.stdev, all_lengths) if len(all_lengths) > 1 else 0,
            "pkt_len_min": min(all_lengths) if all_lengths else 0,
            "pkt_len_max": max(all_lengths) if all_lengths else 0,
        }

    def _proto_name(self) -> str:
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(self.protocol, f"OTHER({self.protocol})")


# ----------------------------------------------------------------------
# Flow key & direction
# ----------------------------------------------------------------------
def flow_key_and_direction(pkt: dict):
    """
    Return ((canonical 5-tuple), is_forward).
    Forward = pkt direction matches the canonical ordering.
    """
    a = (pkt["src_ip"], pkt["src_port"])
    b = (pkt["dst_ip"], pkt["dst_port"])
    proto = pkt["protocol"]
    if a <= b:
        key = (a[0], a[1], b[0], b[1], proto)
        forward = True
    else:
        key = (b[0], b[1], a[0], a[1], proto)
        forward = False
    return key, forward


# ----------------------------------------------------------------------
# Stats
# ----------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.packets_processed = 0
        self.flows_created = 0
        self.flows_flushed = 0
        self.db_errors = 0
        self.last_report = time.time()

    def report_if_due(self, active_flows: int):
        now = time.time()
        if now - self.last_report >= STATS_INTERVAL_S:
            log.info(
                f"stats: packets={self.packets_processed} "
                f"flows_created={self.flows_created} "
                f"flows_flushed={self.flows_flushed} "
                f"active={active_flows} "
                f"db_errors={self.db_errors}"
            )
            self.packets_processed = 0
            self.flows_created = 0
            self.flows_flushed = 0
            self.db_errors = 0
            self.last_report = now


stats = Stats()

# ----------------------------------------------------------------------
# Main async loops
# ----------------------------------------------------------------------
flows: dict = {}
shutdown_event = asyncio.Event()


async def ensure_consumer_group(r: redis.Redis):
    """Create the consumer group if it doesn't exist."""
    try:
        await r.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
        log.info(f"created consumer group {CONSUMER_GROUP}")
    except redis.ResponseError as e:
        if "BUSYGROUP" in str(e):
            log.info(f"consumer group {CONSUMER_GROUP} already exists")
        else:
            raise


async def consume_loop(r: redis.Redis):
    """Read packets from Redis stream and update flow table."""
    log.info("consumer loop started")
    while not shutdown_event.is_set():
        try:
            resp = await r.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME,
                streams={STREAM_NAME: ">"},
                count=500,
                block=1000,
            )
        except redis.RedisError as e:
            log.error(f"redis read error: {e}")
            await asyncio.sleep(1)
            continue

        if not resp:
            continue

        # resp = [(stream_name, [(msg_id, fields), ...])]
        ack_ids = []
        for _stream, messages in resp:
            for msg_id, fields in messages:
                ack_ids.append(msg_id)
                try:
                    raw = fields[b"data"]
                    pkt = json.loads(raw)
                    # Add epoch timestamp for convenience
                    pkt["ts_epoch"] = datetime.fromisoformat(pkt["ts"]).timestamp()
                    process_packet(pkt)
                    stats.packets_processed += 1
                except Exception as e:
                    log.warning(f"failed to process packet {msg_id}: {e}")

        if ack_ids:
            try:
                await r.xack(STREAM_NAME, CONSUMER_GROUP, *ack_ids)
            except redis.RedisError as e:
                log.error(f"redis ack error: {e}")


def process_packet(pkt: dict):
    """Route a packet to its flow, creating one if needed."""
    key, forward = flow_key_and_direction(pkt)
    flow = flows.get(key)
    if flow is None:
        flow = Flow(
            src_ip=key[0], src_port=key[1],
            dst_ip=key[2], dst_port=key[3],
            protocol=key[4],
            first_pkt_ts=pkt["ts_epoch"],
        )
        flows[key] = flow
        stats.flows_created += 1
    flow.add_packet(pkt, forward)


async def flush_loop(pg: asyncpg.Pool):
    """Periodically check for flows ready to flush, write them to Postgres."""
    log.info("flusher loop started")
    while not shutdown_event.is_set():
        await asyncio.sleep(FLUSH_INTERVAL_S)
        now = time.time()
        to_flush = [k for k, f in flows.items() if f.should_flush(now)]

        for key in to_flush:
            flow = flows.pop(key)
            try:
                await insert_flow(pg, flow.to_db_row())
                stats.flows_flushed += 1
            except Exception as e:
                stats.db_errors += 1
                log.error(f"db insert error: {e}")

        stats.report_if_due(len(flows))


INSERT_SQL = """
INSERT INTO flows (
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol, duration_ms,
    fwd_packet_count, bwd_packet_count, fwd_bytes, bwd_bytes,
    syn_count, ack_count, fin_count, rst_count, psh_count, urg_count,
    iat_mean_ms, iat_std_ms, iat_min_ms, iat_max_ms,
    pkt_len_mean, pkt_len_std, pkt_len_min, pkt_len_max
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11,
    $12, $13, $14, $15, $16, $17,
    $18, $19, $20, $21,
    $22, $23, $24, $25
)
"""


async def insert_flow(pg: asyncpg.Pool, row: dict):
    async with pg.acquire() as conn:
        await conn.execute(
            INSERT_SQL,
            row["timestamp"], row["src_ip"], row["dst_ip"],
            row["src_port"], row["dst_port"], row["protocol"], row["duration_ms"],
            row["fwd_packet_count"], row["bwd_packet_count"],
            row["fwd_bytes"], row["bwd_bytes"],
            row["syn_count"], row["ack_count"], row["fin_count"],
            row["rst_count"], row["psh_count"], row["urg_count"],
            row["iat_mean_ms"], row["iat_std_ms"], row["iat_min_ms"], row["iat_max_ms"],
            row["pkt_len_mean"], row["pkt_len_std"], row["pkt_len_min"], row["pkt_len_max"],
        )


async def main():
    log.info("starting flow aggregator")

    # Connect Redis with retries
    r = None
    for attempt in range(10):
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
            await r.ping()
            log.info(f"connected to redis at {REDIS_HOST}:{REDIS_PORT}")
            break
        except Exception as e:
            log.warning(f"redis connect attempt {attempt+1}: {e}")
            await asyncio.sleep(2)
    if r is None:
        raise RuntimeError("could not connect to redis")

    # Connect Postgres with retries
    pg = None
    for attempt in range(10):
        try:
            pg = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=5)
            async with pg.acquire() as conn:
                await conn.fetchval("SELECT 1")
            log.info("connected to postgres")
            break
        except Exception as e:
            log.warning(f"postgres connect attempt {attempt+1}: {e}")
            await asyncio.sleep(2)
    if pg is None:
        raise RuntimeError("could not connect to postgres")

    await ensure_consumer_group(r)

    # Signal handling
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_event.set)

    try:
        await asyncio.gather(
            consume_loop(r),
            flush_loop(pg),
        )
    finally:
        log.info("shutting down — flushing remaining flows")
        now = time.time()
        for key in list(flows.keys()):
            flow = flows.pop(key)
            try:
                await insert_flow(pg, flow.to_db_row())
            except Exception as e:
                log.error(f"final flush error: {e}")
        await pg.close()
        await r.aclose()
        log.info("done")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
