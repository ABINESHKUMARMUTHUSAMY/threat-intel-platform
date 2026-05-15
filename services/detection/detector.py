"""
Detection service.

Polls the flows table every N seconds for new flows, scores them with
XGBoost + Isolation Forest, and writes alerts to the alerts table.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import asyncpg
import joblib
import numpy as np
import redis.asyncio as redis

from feature_mapping import flow_to_features

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
MODELS_DIR = Path(os.getenv('MODELS_DIR', '/app/models'))
POLL_INTERVAL_S = int(os.getenv('POLL_INTERVAL_S', '2'))
BATCH_SIZE = int(os.getenv('BATCH_SIZE', '500'))
DETECTION_THRESHOLD = float(os.getenv('DETECTION_THRESHOLD', '0.7'))
DEDUPE_WINDOW_MIN = int(os.getenv('DEDUPE_WINDOW_MIN', '5'))
STATS_INTERVAL_S = int(os.getenv('STATS_INTERVAL_S', '10'))

POSTGRES_DSN = (
    f"postgresql://{os.getenv('POSTGRES_USER', 'threat')}:"
    f"{os.getenv('POSTGRES_PASSWORD', 'changeme')}@"
    f"{os.getenv('POSTGRES_HOST', 'postgres')}:"
    f"{os.getenv('POSTGRES_PORT', '5432')}/"
    f"{os.getenv('POSTGRES_DB', 'threat_intel')}"
)

REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
ALERTS_STREAM = 'alerts:new'

# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("detector")

# ----------------------------------------------------------------------
# Load model artifacts
# ----------------------------------------------------------------------
log.info(f"Loading model artifacts from {MODELS_DIR}")
xgb_model = joblib.load(MODELS_DIR / 'xgboost_classifier.pkl')
iso_forest = joblib.load(MODELS_DIR / 'isolation_forest.pkl')
scaler = joblib.load(MODELS_DIR / 'feature_scaler.pkl')
label_encoder = joblib.load(MODELS_DIR / 'label_encoder.pkl')

with open(MODELS_DIR / 'model_metadata.json') as f:
    metadata = json.load(f)
FEATURE_ORDER = metadata['feature_order']
CLASS_NAMES = metadata['class_names']

log.info(f"Loaded: XGBoost ({len(CLASS_NAMES)} classes), Isolation Forest, scaler")
log.info(f"Expecting {len(FEATURE_ORDER)} features per flow")

# ----------------------------------------------------------------------
# Severity mapping
# ----------------------------------------------------------------------
SEVERITY_MAP = {
    'BENIGN': 'low',
    'PortScan': 'medium',
    'Bruteforce': 'high',
    'WebAttack': 'high',
    'DoS': 'high',
    'Botnet': 'critical',
    'Infiltration': 'critical',
}


# ----------------------------------------------------------------------
# Stats
# ----------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.flows_scored = 0
        self.alerts_emitted = 0
        self.alerts_deduped = 0
        self.xgb_attacks = 0
        self.iso_anomalies = 0
        self.errors = 0
        self.last_report = time.time()

    def report_if_due(self, watermark_id):
        now = time.time()
        if now - self.last_report >= STATS_INTERVAL_S:
            log.info(
                f"stats: scored={self.flows_scored} "
                f"alerts={self.alerts_emitted} (xgb_attacks={self.xgb_attacks}, "
                f"iso_anomalies={self.iso_anomalies}, deduped={self.alerts_deduped}) "
                f"errors={self.errors} watermark={watermark_id}"
            )
            self.flows_scored = 0
            self.alerts_emitted = 0
            self.alerts_deduped = 0
            self.xgb_attacks = 0
            self.iso_anomalies = 0
            self.errors = 0
            self.last_report = now


stats = Stats()
shutdown_event = asyncio.Event()


# ----------------------------------------------------------------------
# Detection logic
# ----------------------------------------------------------------------
def score_flows(flows: list[dict]) -> list[dict]:
    """
    Score a batch of flows. Returns enriched dicts with prediction data.
    """
    if not flows:
        return []

    # Build feature matrix
    X = np.array([flow_to_features(f, FEATURE_ORDER) for f in flows], dtype=np.float32)
    X_scaled = scaler.transform(X)

    # XGBoost predictions
    xgb_proba = xgb_model.predict_proba(X_scaled)
    xgb_preds = np.argmax(xgb_proba, axis=1)
    xgb_max_proba = xgb_proba.max(axis=1)

    # Isolation Forest scores
    # -1 = anomaly, 1 = normal
    iso_preds = iso_forest.predict(X_scaled)
    iso_scores = iso_forest.score_samples(X_scaled)

    results = []
    for i, flow in enumerate(flows):
        results.append({
            'flow': flow,
            'xgb_class': CLASS_NAMES[xgb_preds[i]],
            'xgb_confidence': float(xgb_max_proba[i]),
            'xgb_all_proba': {CLASS_NAMES[j]: float(xgb_proba[i][j]) for j in range(len(CLASS_NAMES))},
            'iso_anomaly': bool(iso_preds[i] == -1),
            'iso_score': float(iso_scores[i]),
        })
    return results


def should_alert(result: dict) -> tuple[bool, str, str]:
    """
    Decide if an alert should fire and what attack_type to assign.
    Returns (should_alert, attack_type, severity).
    """
    xgb_class = result['xgb_class']
    xgb_confidence = result['xgb_confidence']
    iso_anomaly = result['iso_anomaly']

    # XGBoost says it's a known attack with confidence above threshold
    if xgb_class != 'BENIGN' and xgb_confidence >= DETECTION_THRESHOLD:
        stats.xgb_attacks += 1
        return True, xgb_class, SEVERITY_MAP.get(xgb_class, 'medium')

    # Isolation Forest flags an anomaly but XGBoost called it benign —
    # potentially novel. Lower severity since it's unconfirmed.
    if iso_anomaly and xgb_class == 'BENIGN':
        stats.iso_anomalies += 1
        return True, 'AnomalyUnknown', 'medium'

    return False, '', ''


# ----------------------------------------------------------------------
# Database access
# ----------------------------------------------------------------------
async def fetch_new_flows(pg, watermark_ts, watermark_id, limit):
    """Fetch flows newer than the watermark."""
    rows = await pg.fetch(
        """
        SELECT id, timestamp, src_ip::text, dst_ip::text,
               src_port, dst_port, protocol, duration_ms,
               fwd_packet_count, bwd_packet_count,
               fwd_bytes, bwd_bytes,
               syn_count, ack_count, fin_count, rst_count,
               psh_count, urg_count,
               iat_mean_ms, iat_std_ms, iat_min_ms, iat_max_ms,
               pkt_len_mean, pkt_len_std, pkt_len_min, pkt_len_max
        FROM flows
        WHERE (timestamp, id) > ($1, $2)
        ORDER BY timestamp ASC, id ASC
        LIMIT $3
        """,
        watermark_ts, watermark_id, limit,
    )
    return [dict(r) for r in rows]


async def check_dedupe(pg, src_ip, attack_type) -> bool:
    """Returns True if an alert for this (src_ip, attack_type) was recently emitted."""
    window_ago = datetime.now(timezone.utc) - timedelta(minutes=DEDUPE_WINDOW_MIN)
    row = await pg.fetchval(
        """
        SELECT 1 FROM alerts
        WHERE src_ip = $1::inet
          AND attack_type = $2
          AND timestamp > $3
        LIMIT 1
        """,
        src_ip, attack_type, window_ago,
    )
    return row is not None


async def insert_alert(pg, flow, result, attack_type, severity):
    flow_features = {
        'duration_ms': flow.get('duration_ms'),
        'fwd_bytes': flow.get('fwd_bytes'),
        'bwd_bytes': flow.get('bwd_bytes'),
        'syn_count': flow.get('syn_count'),
        'rst_count': flow.get('rst_count'),
        'pkt_len_mean': float(flow.get('pkt_len_mean') or 0),
    }
    raw = {
        'xgb_prediction': result['xgb_class'],
        'xgb_confidence': result['xgb_confidence'],
        'xgb_all_proba': result['xgb_all_proba'],
        'iso_anomaly': result['iso_anomaly'],
        'iso_score': result['iso_score'],
        'flow_features': flow_features,
        'src_port': flow.get('src_port'),
        'dst_port': flow.get('dst_port'),
        'protocol': flow.get('protocol'),
    }
    description = (
        f"{attack_type} detected from {flow['src_ip']} "
        f"(xgb_conf={result['xgb_confidence']:.2f}, "
        f"iso_anomaly={result['iso_anomaly']})"
    )
    alert_id = await pg.fetchval(
        """
        INSERT INTO alerts (
            flow_id, severity, attack_type, confidence,
            src_ip, dst_ip, description, raw_features
        ) VALUES ($1, $2, $3, $4, $5::inet, $6::inet, $7, $8)
        RETURNING id
        """,
        flow['id'], severity, attack_type,
        result['xgb_confidence'],
        flow['src_ip'], flow['dst_ip'],
        description, json.dumps(raw),
    )
    return alert_id


# ----------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------
async def main():
    log.info("starting detection service")

    # Connect Postgres
    pg = None
    for attempt in range(10):
        try:
            pg = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=5)
            async with pg.acquire() as conn:
                await conn.fetchval("SELECT 1")
            log.info("connected to postgres")
            break
        except Exception as e:
            log.warning(f"postgres attempt {attempt+1}: {e}")
            await asyncio.sleep(2)
    if pg is None:
        raise RuntimeError("could not connect to postgres")

    # Connect Redis (for publishing alerts to stream — Day 4 will consume)
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    await r.ping()
    log.info("connected to redis")

    # Determine starting watermark — resume from last-known alert flow, or now
    row = await pg.fetchrow(
        "SELECT timestamp, id FROM flows ORDER BY timestamp DESC, id DESC LIMIT 1"
    )
    if row is None:
        # No flows yet — start at beginning of time
        watermark_ts = datetime(1970, 1, 1, tzinfo=timezone.utc)
        watermark_id = '00000000-0000-0000-0000-000000000000'
    else:
        # Start from now — don't re-score historical flows on first run
        watermark_ts = row['timestamp']
        watermark_id = str(row['id'])
    log.info(f"starting watermark: ts={watermark_ts}, id={watermark_id}")

    # Signal handling
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_event.set)

    # Main loop
    while not shutdown_event.is_set():
        try:
            flows = await fetch_new_flows(pg, watermark_ts, watermark_id, BATCH_SIZE)
            if flows:
                results = score_flows(flows)
                stats.flows_scored += len(flows)

                for r_result in results:
                    flow = r_result['flow']
                    fire, attack_type, severity = should_alert(r_result)
                    if not fire:
                        continue

                    # Dedupe check
                    if await check_dedupe(pg, flow['src_ip'], attack_type):
                        stats.alerts_deduped += 1
                        continue

                    try:
                        alert_id = await insert_alert(pg, flow, r_result, attack_type, severity)
                        stats.alerts_emitted += 1

                        # Publish to stream for Day 4's response engine
                        await r.xadd(
                            ALERTS_STREAM,
                            {'alert_id': str(alert_id), 'attack_type': attack_type,
                             'severity': severity, 'src_ip': flow['src_ip']},
                            maxlen=10000, approximate=True,
                        )
                    except Exception as e:
                        stats.errors += 1
                        log.error(f"alert insert error: {e}")

                # Advance watermark to last flow processed
                watermark_ts = flows[-1]['timestamp']
                watermark_id = str(flows[-1]['id'])

            stats.report_if_due(watermark_id[:8])

            if len(flows) < BATCH_SIZE:
                # Caught up — wait for new flows
                await asyncio.sleep(POLL_INTERVAL_S)
        except Exception as e:
            stats.errors += 1
            log.error(f"main loop error: {e}", exc_info=True)
            await asyncio.sleep(POLL_INTERVAL_S)

    log.info("shutting down")
    await pg.close()
    await r.aclose()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
