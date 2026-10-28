
from datetime import datetime, timezone

from backend.app.services.alert_correlator import AlertCorrelator


def make_alert(alert_id, rule_id, description, timestamp, source_ip="198.51.100.10"):
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "rule_description": description,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_user": "test-user",
    }


def test_correlator_groups_alerts_by_source_ip():
    correlator = AlertCorrelator(window_minutes=10)
    timestamp = "2026-10-25T10:00:00+00:00"

    correlator.correlate(
        make_alert("1", "5710", "Failed password", timestamp)
    )
    result = correlator.correlate(
        make_alert("2", "5710", "Failed password", "2026-10-25T10:01:00+00:00")
    )

    assert result["alert_count"] == 2
    assert result["correlated"] is True


def test_correlator_keeps_different_source_ips_separate():
    correlator = AlertCorrelator(window_minutes=10)
    timestamp = "2026-10-25T10:00:00+00:00"

    correlator.correlate(
        make_alert("1", "5710", "Failed password", timestamp)
    )
    result = correlator.correlate(
        make_alert("2", "5710", "Failed password", "2026-10-25T10:01:00+00:00", "203.0.113.20")
    )

    assert result["alert_count"] == 1
    assert result["correlated"] is False


def test_correlator_returns_no_source_ip_without_source():
    correlator = AlertCorrelator()

    result = correlator.correlate({
        "alert_id": "1",
        "rule_id": "5710",
        "rule_description": "Failed password",
        "timestamp": "2026-10-25T10:00:00+00:00",
    })

    assert result["correlated"] is False
    assert result["alert_count"] == 0



def test_correlator_does_not_count_duplicate_alert_ids():
    correlator = AlertCorrelator(window_minutes=10)
    timestamp = "2026-10-25T10:00:00+00:00"
    alert = make_alert(
        "duplicate-1",
        "5710",
        "Failed password",
        timestamp,
    )

    correlator.correlate(alert)
    result = correlator.correlate(alert)

    assert result["alert_count"] == 1
    assert result["correlated"] is False


def test_correlator_rejects_missing_timestamp():
    correlator = AlertCorrelator()

    result = correlator.correlate({
        "alert_id": "missing-time",
        "rule_id": "5710",
        "rule_description": "Failed password",
        "source_ip": "198.51.100.10",
    })

    assert result["correlated"] is False
    assert result["alert_count"] == 0
    assert result["reason"] == "Missing or invalid alert timestamp"


def test_correlator_rejects_malformed_timestamp():
    correlator = AlertCorrelator()

    result = correlator.correlate(
        make_alert(
            "invalid-time",
            "5710",
            "Failed password",
            "not-a-valid-timestamp",
        )
    )

    assert result["correlated"] is False
    assert result["alert_count"] == 0
    assert result["reason"] == "Missing or invalid alert timestamp"
