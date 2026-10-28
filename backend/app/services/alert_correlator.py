
from collections import defaultdict
from datetime import datetime, timedelta, timezone


class AlertCorrelator:
    def __init__(self, window_minutes=10):
        self.window_minutes = window_minutes
        self.alerts_by_source = defaultdict(list)

    @staticmethod
    def _parse_timestamp(value):
        """Parse timestamps and normalize valid values to UTC."""
        if isinstance(value, datetime):
            timestamp = value
        elif isinstance(value, str) and value.strip():
            try:
                timestamp = datetime.fromisoformat(
                    value.strip().replace("Z", "+00:00")
                )
            except ValueError:
                return None
        else:
            return None

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    def correlate(self, alert):
        source_ip = alert.get("source_ip")
        timestamp = self._parse_timestamp(alert.get("timestamp"))

        # Missing source IP: correlation cannot be established.
        if not source_ip:
            return {
                "correlated": False,
                "source_ip": None,
                "window_minutes": self.window_minutes,
                "alert_count": 0,
                "related_alerts": [],
                "reason": "No source IP available",
            }

        # Invalid or missing timestamps must not be silently replaced
        # with the current time or used as correlation evidence.
        if timestamp is None:
            return {
                "correlated": False,
                "source_ip": source_ip,
                "window_minutes": self.window_minutes,
                "alert_count": 0,
                "related_alerts": [],
                "reason": "Missing or invalid alert timestamp",
            }

        source_alerts = self.alerts_by_source[source_ip]

        # Remove entries outside the current alert's time window.
        cutoff = timestamp - timedelta(minutes=self.window_minutes)
        recent_alerts = [
            item
            for item in source_alerts
            if cutoff <= item["timestamp"] <= timestamp
        ]

        self.alerts_by_source[source_ip] = recent_alerts
        source_alerts = self.alerts_by_source[source_ip]

        alert_id = alert.get("alert_id")

        # Avoid counting the same identifiable alert more than once.
        duplicate = (
            alert_id is not None
            and any(
                item.get("alert_id") == alert_id
                for item in source_alerts
            )
        )

        if not duplicate:
            source_alerts.append({
                "alert_id": alert_id,
                "rule_id": alert.get("rule_id"),
                "rule_description": alert.get("rule_description"),
                "full_log": alert.get("full_log"),
                "source_user": alert.get("source_user"),
                "timestamp": timestamp,
            })

        alert_count = len(source_alerts)

        return {
            "correlated": alert_count > 1,
            "source_ip": source_ip,
            "window_minutes": self.window_minutes,
            "alert_count": alert_count,
            "related_alerts": source_alerts.copy(),
        }


alert_correlator = AlertCorrelator()
