from datetime import datetime, timezone

from app.services.alert_correlator import AlertCorrelator


def make_alert(
    alert_id,
    timestamp="2026-10-28T10:00:00Z",
    source_ip="192.168.1.200",
    rule_id="5710",
    description="Failed SSH authentication",
    full_log="Failed password for admin",
):
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "rule_id": rule_id,
        "rule_description": description,
        "source_user": "admin",
        "full_log": full_log,
    }


def test_first_alert_is_not_correlated():
    correlator = AlertCorrelator()

    result = correlator.correlate(make_alert("alert-1"))

    assert result["correlated"] is False
    assert result["alert_count"] == 1


def test_two_alerts_from_same_ip_are_correlated():
    correlator = AlertCorrelator()

    correlator.correlate(make_alert("alert-1"))
    result = correlator.correlate(
        make_alert("alert-2", timestamp="2026-10-28T10:05:00Z")
    )

    assert result["correlated"] is True
    assert result["alert_count"] == 2


def test_duplicate_alert_id_is_not_counted_twice():
    correlator = AlertCorrelator()

    correlator.correlate(make_alert("alert-1"))
    result = correlator.correlate(
        make_alert("alert-1", timestamp="2026-10-28T10:01:00Z")
    )

    assert result["alert_count"] == 1
    assert result["correlated"] is False


def test_alert_outside_time_window_is_removed():
    correlator = AlertCorrelator(window_minutes=10)

    correlator.correlate(make_alert("alert-1", timestamp="2026-10-28T10:00:00Z"))
    result = correlator.correlate(
        make_alert("alert-2", timestamp="2026-10-28T10:11:00Z")
    )

    assert result["alert_count"] == 1
    assert result["correlated"] is False


def test_missing_source_ip_does_not_correlate():
    correlator = AlertCorrelator()

    result = correlator.correlate(make_alert("alert-1", source_ip=None))

    assert result["correlated"] is False
    assert result["alert_count"] == 0
    assert result["related_alerts"] == []


def test_invalid_timestamp_does_not_correlate():
    correlator = AlertCorrelator()

    result = correlator.correlate(
        make_alert("alert-1", timestamp="not-a-valid-timestamp")
    )

    assert result["correlated"] is False
    assert result["alert_count"] == 0
    assert result["related_alerts"] == []


def test_naive_datetime_is_normalized_to_utc():
    parsed = AlertCorrelator._parse_timestamp(
        datetime(2026, 10, 28, 10, 0, 0)
    )

    assert parsed is not None
    assert parsed.tzinfo == timezone.utc


def test_correlated_alert_retains_full_log_evidence():
    correlator = AlertCorrelator()

    correlator.correlate(make_alert("alert-1"))
    result = correlator.correlate(
        make_alert("alert-2", timestamp="2026-10-28T10:01:00Z")
    )

    assert all("full_log" in alert for alert in result["related_alerts"])
