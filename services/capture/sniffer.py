"""
Scapy-based packet capture service.

Sniffs the host's primary network interface, parses L3/L4 headers,
and pushes structured packet metadata to a Redis Stream for downstream
flow aggregation and ML detection.
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import redis
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

# ----------------------------------------------------------------------
# Configuration (from env vars, with sane defaults)
# ----------------------------------------------------------------------
INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
STREAM_NAME = os.getenv("STREAM_NAME", "packets:raw")
STREAM_MAXLEN = int(os.getenv("STREAM_MAXLEN", "100000"))
STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "10"))

# BPF filter — capture all IP traffic EXCEPT our management ports.
# Without this, every Redis write we make generates packets we'd capture
# and re-publish, creating a feedback loop.
BPF_FILTER = (
    "ip and not (tcp port 22 or tcp port 5432 or tcp port 6379 "
    "or tcp port 8000 or tcp port 5173)"
)

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("capture")

# ----------------------------------------------------------------------
# Stats counters (in-memory, reset on restart)
# ----------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.packets_captured = 0
        self.packets_published = 0
        self.publish_errors = 0
        self.last_report = time.time()

    def report_if_due(self):
        now = time.time()
        if now - self.last_report >= STATS_INTERVAL:
            elapsed = now - self.last_report
            rate = self.packets_captured / elapsed if elapsed > 0 else 0
            log.info(
                f"stats: captured={self.packets_captured} "
                f"published={self.packets_published} "
                f"errors={self.publish_errors} "
                f"rate={rate:.1f}pps"
            )
            self.packets_captured = 0
            self.packets_published = 0
            self.publish_errors = 0
            self.last_report = now


stats = Stats()

# ----------------------------------------------------------------------
# Redis connection
# ----------------------------------------------------------------------
def connect_redis() -> redis.Redis:
    """Connect to Redis with retries."""
    for attempt in range(10):
        try:
            r = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=False,
                socket_keepalive=True,
            )
            r.ping()
            log.info(f"connected to redis at {REDIS_HOST}:{REDIS_PORT}")
            return r
        except redis.ConnectionError as e:
            log.warning(f"redis connection attempt {attempt+1} failed: {e}")
            time.sleep(2)
    raise RuntimeError("Could not connect to Redis after 10 attempts")


r_client = connect_redis()

# ----------------------------------------------------------------------
# Packet parsing
# ----------------------------------------------------------------------
def packet_to_dict(pkt) -> dict | None:
    """
    Extract L3/L4 features from a packet into a dict.
    Returns None if the packet doesn't have an IP layer (we skip ARP, etc).
    """
    if IP not in pkt:
        return None

    ip_layer = pkt[IP]
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": ip_layer.proto,  # 6=TCP, 17=UDP, 1=ICMP
        "pkt_len": len(pkt),
        "ttl": ip_layer.ttl,
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        record.update({
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "tcp_flags": int(tcp.flags),
            "tcp_window": int(tcp.window),
            "proto_name": "TCP",
        })
    elif UDP in pkt:
        udp = pkt[UDP]
        record.update({
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport),
            "proto_name": "UDP",
        })
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        record.update({
            "src_port": 0,
            "dst_port": 0,
            "icmp_type": int(icmp.type),
            "icmp_code": int(icmp.code),
            "proto_name": "ICMP",
        })
    else:
        record.update({
            "src_port": 0,
            "dst_port": 0,
            "proto_name": f"OTHER({ip_layer.proto})",
        })

    return record


# ----------------------------------------------------------------------
# Packet handler — called for every captured packet
# ----------------------------------------------------------------------
def handle_packet(pkt):
    stats.packets_captured += 1
    record = packet_to_dict(pkt)
    if record is None:
        return
    try:
        # XADD with MAXLEN ~N trims old entries automatically.
        # Using approximate trimming (~) is much cheaper than exact (=).
        r_client.xadd(
            STREAM_NAME,
            {"data": json.dumps(record)},
            maxlen=STREAM_MAXLEN,
            approximate=True,
        )
        stats.packets_published += 1
    except redis.RedisError as e:
        stats.publish_errors += 1
        if stats.publish_errors % 100 == 1:
            log.error(f"redis publish error: {e}")
    stats.report_if_due()


# ----------------------------------------------------------------------
# Graceful shutdown
# ----------------------------------------------------------------------
sniffer = None


def shutdown(signum, frame):
    log.info(f"received signal {signum}, stopping sniffer...")
    if sniffer is not None:
        sniffer.stop()
    sys.exit(0)


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    global sniffer
    log.info(f"starting capture on interface={INTERFACE}")
    log.info(f"bpf filter: {BPF_FILTER}")
    log.info(f"publishing to redis stream: {STREAM_NAME} (maxlen ~{STREAM_MAXLEN})")

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter=BPF_FILTER,
        prn=handle_packet,
        store=False,  # critical: don't keep packets in memory
    )
    sniffer.start()
    log.info("sniffer started — capture is live")

    # Block forever; signal handlers will exit
    while True:
        time.sleep(60)
        # Forcibly report stats even if no packets (so we know we're alive)
        stats.report_if_due()


if __name__ == "__main__":
    main()
