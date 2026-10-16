
from collections import defaultdict
from datetime import datetime, timedelta, timezone


class AlertCorrelator:
    def __init__(self, window_minutes=10):
        self.window_minutes = window_minutes
        self.alerts_by_source = defaultdict(list)

    @staticmethod
    def _parse_timestamp(value):
        if isinstance(value, datetime):
            timestamp = value
        elif isinstance(value, str) and value.strip():
            try:
                timestamp = datetime.fromisoformat(
                    value.strip().replace("Z", "+00:00")
                )
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        # Normalize all timestamps to UTC-aware datetimes.
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    def correlate(self, alert):
        source_ip = alert.get("source_ip")
        timestamp = self._parse_timestamp(
            alert.get("timestamp")
        )

        # Return the same fields for alerts without a source IP.
        if not source_ip:
            return {
                "correlated": False,
                "source_ip": None,
                "window_minutes": self.window_minutes,
                "alert_count": 0,
                "related_alerts": [],
                "reason": "No source IP available",
            }

        self.alerts_by_source[source_ip].append({
            "alert_id": alert.get("alert_id"),
            "rule_id": alert.get("rule_id"),
            "rule_description": alert.get("rule_description"),
            "timestamp": timestamp,
            "source_user": alert.get("source_user"),
        })

        cutoff = timestamp - timedelta(
            minutes=self.window_minutes
        )

        recent_alerts = [
            item
            for item in self.alerts_by_source[source_ip]
            if cutoff <= item["timestamp"] <= timestamp
        ]

        self.alerts_by_source[source_ip] = recent_alerts

        return {
            "correlated": len(recent_alerts) > 1,
            "source_ip": source_ip,
            "window_minutes": self.window_minutes,
            "alert_count": len(recent_alerts),
            "related_alerts": recent_alerts,
        }


alert_correlator = AlertCorrelator()
