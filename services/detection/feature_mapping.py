"""
Map live flow records (from Postgres flows table) to the feature vector
expected by the live-trained XGBoost model.

The live model was trained on flow aggregator's native feature names,
so this mapping is direct — no CICFlowMeter translation needed.
"""


def flow_to_features(flow: dict, expected_features: list[str]) -> list[float]:
    """
    Direct mapping: read the requested features from the flow dict.
    Any missing feature is filled with 0.
    """
    return [float(flow.get(name) or 0) for name in expected_features]
