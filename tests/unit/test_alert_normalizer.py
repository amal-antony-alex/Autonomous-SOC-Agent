
from backend.app.services.alert_normalizer import AlertNormalizer


def test_normalizer_preserves_valid_timestamp():
    timestamp = "2026-10-25T10:00:00+00:00"

    result = AlertNormalizer.normalize({
        "timestamp": timestamp,
        "rule": {"id": "5710"},
    })

    assert result["timestamp"] == timestamp


def test_normalizer_preserves_missing_timestamp_as_none():
    result = AlertNormalizer.normalize({
        "rule": {"id": "5710"},
    })

    assert result["timestamp"] is None


def test_normalizer_preserves_malformed_timestamp_for_validation():
    timestamp = "not-a-valid-timestamp"

    result = AlertNormalizer.normalize({
        "timestamp": timestamp,
        "rule": {"id": "5710"},
    })

    assert result["timestamp"] == timestamp

def test_normalizer_preserves_full_log_evidence():
    full_log = (
        "Failed password for admin from 192.168.1.200 port 22 ssh2"
    )

    result = AlertNormalizer.normalize({
        "id": "alert-123",
        "timestamp": "2026-10-28T10:00:00Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "Failed SSH authentication",
        },
        "data": {
            "srcip": "192.168.1.200",
            "srcuser": "admin",
        },
        "full_log": full_log,
    })

    assert result["full_log"] == full_log
    assert result["source_ip"] == "192.168.1.200"
    assert result["source_user"] == "admin"
    assert result["rule_id"] == "5710"


def test_normalizer_preserves_original_alert():
    raw_alert = {
        "id": "alert-456",
        "timestamp": "2026-10-28T10:00:00Z",
        "rule": {"id": "5710"},
        "full_log": "Failed password for admin",
    }

    result = AlertNormalizer.normalize(raw_alert)

    assert result["raw_alert"] is raw_alert
    assert result["raw_alert"]["full_log"] == "Failed password for admin"
