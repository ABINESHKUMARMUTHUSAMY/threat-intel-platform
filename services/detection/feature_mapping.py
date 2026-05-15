"""
Map live flow records (from Postgres `flows` table) to the feature vector
expected by the trained XGBoost model.

CRITICAL: the order and names must exactly match model_metadata.json's
feature_order. Misalignment produces silently-wrong predictions.

Live flows have ~24 columns; training expects 65. We derive what we can
and zero-fill what we genuinely can't (and document which).
"""

from typing import Any


def flow_to_features(flow: dict, expected_features: list[str]) -> list[float]:
    """
    Given a flow dict from our DB and the expected feature names,
    return a feature vector in the right order.
    """
    # Build a feature dict from what we have, then read it in the expected order.
    f: dict[str, float] = {}

    fwd_pkts = flow.get('fwd_packet_count') or 0
    bwd_pkts = flow.get('bwd_packet_count') or 0
    fwd_bytes = flow.get('fwd_bytes') or 0
    bwd_bytes = flow.get('bwd_bytes') or 0
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    duration_us = (flow.get('duration_ms') or 0) * 1000  # CICFlowMeter uses microseconds
    duration_s = duration_us / 1_000_000 if duration_us > 0 else 1e-6

    pkt_len_mean = float(flow.get('pkt_len_mean') or 0)
    pkt_len_std = float(flow.get('pkt_len_std') or 0)
    pkt_len_min = float(flow.get('pkt_len_min') or 0)
    pkt_len_max = float(flow.get('pkt_len_max') or 0)
    iat_mean_ms = float(flow.get('iat_mean_ms') or 0)
    iat_std_ms = float(flow.get('iat_std_ms') or 0)
    iat_min_ms = float(flow.get('iat_min_ms') or 0)
    iat_max_ms = float(flow.get('iat_max_ms') or 0)

    # Flow-level features
    f['Flow Duration'] = duration_us
    f['Total Fwd Packets'] = fwd_pkts
    f['Total Backward Packets'] = bwd_pkts
    f['Total Length of Fwd Packets'] = fwd_bytes
    f['Total Length of Bwd Packets'] = bwd_bytes
    f['Flow Bytes/s'] = total_bytes / duration_s if duration_s > 0 else 0
    f['Flow Packets/s'] = total_pkts / duration_s if duration_s > 0 else 0

    # Packet length features — we have aggregate, not per-direction.
    # We use the aggregate for all length stats. Imperfect but defensible.
    f['Fwd Packet Length Max'] = pkt_len_max
    f['Fwd Packet Length Min'] = pkt_len_min
    f['Fwd Packet Length Mean'] = pkt_len_mean
    f['Fwd Packet Length Std'] = pkt_len_std
    f['Bwd Packet Length Max'] = pkt_len_max
    f['Bwd Packet Length Min'] = pkt_len_min
    f['Bwd Packet Length Mean'] = pkt_len_mean
    f['Bwd Packet Length Std'] = pkt_len_std
    f['Min Packet Length'] = pkt_len_min
    f['Max Packet Length'] = pkt_len_max
    f['Packet Length Mean'] = pkt_len_mean
    f['Packet Length Std'] = pkt_len_std
    f['Packet Length Variance'] = pkt_len_std ** 2
    f['Average Packet Size'] = pkt_len_mean
    f['Avg Fwd Segment Size'] = pkt_len_mean
    f['Avg Bwd Segment Size'] = pkt_len_mean

    # Inter-arrival time features — we have one set, share across directions
    iat_mean_us = iat_mean_ms * 1000
    iat_std_us = iat_std_ms * 1000
    iat_min_us = iat_min_ms * 1000
    iat_max_us = iat_max_ms * 1000
    iat_total_us = duration_us  # approximation
    f['Flow IAT Mean'] = iat_mean_us
    f['Flow IAT Std'] = iat_std_us
    f['Flow IAT Max'] = iat_max_us
    f['Flow IAT Min'] = iat_min_us
    f['Fwd IAT Total'] = iat_total_us
    f['Fwd IAT Mean'] = iat_mean_us
    f['Fwd IAT Std'] = iat_std_us
    f['Fwd IAT Max'] = iat_max_us
    f['Fwd IAT Min'] = iat_min_us
    f['Bwd IAT Total'] = iat_total_us
    f['Bwd IAT Mean'] = iat_mean_us
    f['Bwd IAT Std'] = iat_std_us
    f['Bwd IAT Max'] = iat_max_us
    f['Bwd IAT Min'] = iat_min_us

    # TCP flag counts
    f['Fwd PSH Flags'] = flow.get('psh_count') or 0
    f['Bwd PSH Flags'] = 0  # we don't split flags by direction
    f['Fwd URG Flags'] = flow.get('urg_count') or 0
    f['Bwd URG Flags'] = 0
    f['FIN Flag Count'] = flow.get('fin_count') or 0
    f['SYN Flag Count'] = flow.get('syn_count') or 0
    f['RST Flag Count'] = flow.get('rst_count') or 0
    f['PSH Flag Count'] = flow.get('psh_count') or 0
    f['ACK Flag Count'] = flow.get('ack_count') or 0
    f['URG Flag Count'] = flow.get('urg_count') or 0
    f['CWE Flag Count'] = 0
    f['ECE Flag Count'] = 0

    # Header lengths (approximation — we don't capture these directly)
    f['Fwd Header Length'] = fwd_pkts * 20  # rough TCP header avg
    f['Bwd Header Length'] = bwd_pkts * 20
    f['Fwd Header Length.1'] = fwd_pkts * 20  # CICFlowMeter has duplicate
    f['Fwd Packets/s'] = fwd_pkts / duration_s if duration_s > 0 else 0
    f['Bwd Packets/s'] = bwd_pkts / duration_s if duration_s > 0 else 0

    # Down/Up ratio
    f['Down/Up Ratio'] = bwd_pkts / fwd_pkts if fwd_pkts > 0 else 0

    # Active/Idle stats — would require packet-level timing we don't track
    # These are typically 0 for short flows anyway
    for col in ['Active Mean', 'Active Std', 'Active Max', 'Active Min',
                'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']:
        f[col] = 0

    # Subflow features — for non-bidirectional flows these mirror totals
    f['Subflow Fwd Packets'] = fwd_pkts
    f['Subflow Fwd Bytes'] = fwd_bytes
    f['Subflow Bwd Packets'] = bwd_pkts
    f['Subflow Bwd Bytes'] = bwd_bytes

    # Init window sizes (we don't capture)
    f['Init_Win_bytes_forward'] = 0
    f['Init_Win_bytes_backward'] = 0
    f['act_data_pkt_fwd'] = fwd_pkts
    f['min_seg_size_forward'] = pkt_len_min

    # Bulk transfer features (we don't capture)
    for col in ['Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
                'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']:
        f[col] = 0

    # Read out in the model's expected order, with 0 for any missing
    return [float(f.get(name, 0)) for name in expected_features]
