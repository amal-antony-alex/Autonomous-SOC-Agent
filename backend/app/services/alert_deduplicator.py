import hashlib
import json


class AlertDeduplicator:

    @staticmethod
    def generate_fingerprint(alert: dict) -> str:
        fingerprint_data = {
            "source": alert.get("source"),
            "rule_id": alert.get("rule_id"),
            "agent_id": alert.get("agent_id"),
            "source_ip": alert.get("source_ip"),
            "source_user": alert.get("source_user"),
            "destination_ip": alert.get("destination_ip"),
            "destination_port": alert.get("destination_port"),
            "full_log": alert.get("full_log"),
        }

        serialized = json.dumps(
            fingerprint_data,
            sort_keys=True
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def is_duplicate(
        alert: dict,
        seen_fingerprints: set
    ) -> bool:
        fingerprint = AlertDeduplicator.generate_fingerprint(alert)

        if fingerprint in seen_fingerprints:
            return True

        seen_fingerprints.add(fingerprint)
        return False


alert_deduplicator = AlertDeduplicator()
