from datetime import datetime, timezone


class AlertNormalizer:

    @staticmethod
    def normalize(alert: dict) -> dict:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})

        normalized = {
            "timestamp": alert.get(
                "timestamp",
                datetime.now(timezone.utc).isoformat()
            ),

            "source": "wazuh",

            "alert_id": alert.get("id"),

            "rule_id": rule.get("id"),

            "rule_level": rule.get("level"),

            "rule_description": rule.get("description"),

            "agent_id": agent.get("id"),

            "agent_name": agent.get("name"),

            "source_ip": data.get("srcip"),

            "source_user": data.get("srcuser"),

            "destination_ip": data.get("dstip"),

            "destination_port": data.get("dstport"),

            "full_log": alert.get("full_log"),

            "location": alert.get("location"),

            "mitre": rule.get("mitre", {}),

            "raw_alert": alert,
        }

        return normalized


alert_normalizer = AlertNormalizer()
