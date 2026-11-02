import re
from datetime import datetime, timezone


class AlertNormalizer:

    @staticmethod
    def normalize(alert: dict) -> dict:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})
        full_log = alert.get("full_log")

        process_match = (
            re.search(r"\bsshd\[(\d+)\]", full_log)
            if isinstance(full_log, str)
            else None
        )

        normalized = {
            "timestamp": alert.get("timestamp"),

            "source": "wazuh",

            "alert_id": alert.get("id"),

            "rule_id": rule.get("id"),

            "rule_level": rule.get("level"),

            "rule_description": rule.get("description"),

            "agent_id": agent.get("id"),

            "agent_name": agent.get("name"),

            "source_ip": data.get("srcip"),

            "source_port": data.get("srcport"),

            "process_id": (
                process_match.group(1)
                if process_match
                else None
            ),

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
