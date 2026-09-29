from collections import defaultdict
from datetime import datetime, timedelta


class AlertCorrelator:

    def __init__(self, window_minutes=10):
        self.window_minutes = window_minutes
        self.alerts_by_source = defaultdict(list)

    def correlate(self, alert):
        source_ip = alert.get("source_ip")

        if not source_ip:
            return {
                "correlated": False,
                "reason": "No source IP available",
                "related_alerts": []
            }

        timestamp = alert.get("timestamp")

        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                timestamp = datetime.utcnow()

        if timestamp is None:
            timestamp = datetime.utcnow()

        self.alerts_by_source[source_ip].append({
            "alert_id": alert.get("alert_id"),
            "rule_id": alert.get("rule_id"),
            "rule_description": alert.get("rule_description"),
            "timestamp": timestamp,
            "source_user": alert.get("source_user")
        })

        cutoff = timestamp - timedelta(
            minutes=self.window_minutes
        )

        recent_alerts = [
            item
            for item in self.alerts_by_source[source_ip]
            if item["timestamp"] >= cutoff
        ]

        self.alerts_by_source[source_ip] = recent_alerts

        return {
            "correlated": len(recent_alerts) > 1,
            "source_ip": source_ip,
            "window_minutes": self.window_minutes,
            "alert_count": len(recent_alerts),
            "related_alerts": recent_alerts
        }


alert_correlator = AlertCorrelator()
