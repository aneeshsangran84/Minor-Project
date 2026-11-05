import json

import pytest

from authsense.behavior import FEATURES, feature_vector, get_model, train_profile, validate_window
from conftest import features


def training_rows():
    return [{"session_id": f"round-{i // 10}", "features": features(i)} for i in range(30)]


def test_model_training_and_extreme_change():
    payload, stats = train_profile(training_rows())
    model = get_model(payload)
    assert stats["fit_windows"] == 20
    assert stats["calibration_windows"] == 10
    assert not model.assess(feature_vector(features(100)))["anomalous"]
    assert model.assess(feature_vector(features(100, alien=True)))["anomalous"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 2001, True, "90", 10**1000])
def test_invalid_feature_rejected(value):
    data = features()
    data[FEATURES[0]] = value
    with pytest.raises(ValueError):
        feature_vector(data)


def test_insufficient_rounds_cannot_train():
    rows = training_rows()
    for row in rows:
        row["session_id"] = "same-round"
    with pytest.raises(ValueError, match="separate"):
        train_profile(rows)


def test_version_mismatch_rejected():
    payload, _ = train_profile(training_rows())
    doc = json.loads(payload)
    doc["sklearn"] = "0.0.0"
    with pytest.raises(ValueError, match="version changed"):
        get_model(json.dumps(doc))


def test_invalid_counts_and_boolean_versions_rejected():
    data = {"v": 1, "nonce": "example", "seq": 1, "count": 23, "interval_count": 25,
            "duration_ms": 6000, "features": features()}
    with pytest.raises(ValueError):
        validate_window(data)
    data["count"] = 30
    data["v"] = True
    with pytest.raises(ValueError):
        validate_window(data)
