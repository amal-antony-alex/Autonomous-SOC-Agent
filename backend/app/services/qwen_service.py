import requests


class QwenService:

    def __init__(
        self,
        base_url="http://host.docker.internal:11434",
        model="qwen3:0.6b",
    ):
        self.base_url = base_url
        self.model = model

    def verify(
        self,
        alert: dict,
        security_context: str,
        tiny_llm_analysis: str,
        correlation_result=None,
    ):

        if correlation_result is None:
            correlation_result = {
                "correlated": False,
                "alert_count": 1,
                "related_alerts": [],
            }

        correlation_text = (
            f"Correlation window: "
            f"{correlation_result.get('window_minutes', 10)} minutes\n"
            f"Correlated alert count: "
            f"{correlation_result.get('alert_count', 0)}\n"
        )

        related_alerts = correlation_result.get(
            "related_alerts",
            []
        )

        if related_alerts:
            correlation_text += "\nRelated alerts:\n"

            for related in related_alerts:
                correlation_text += (
                    f"- Alert ID: {related.get('alert_id')}, "
                    f"Rule ID: {related.get('rule_id')}, "
                    f"Timestamp: {related.get('timestamp')}, "
                    f"User: {related.get('source_user')}\n"
                )

        prompt = f"""
You are a cybersecurity SOC analyst performing second-level verification.

Review the Wazuh alert, security knowledge, preliminary Tiny CyberLLM
analysis, and alert correlation evidence below.

=== WAZUH ALERT ===
Rule ID: {alert.get("rule_id")}
Rule Level: {alert.get("rule_level")}
Rule Description: {alert.get("rule_description")}
Source IP: {alert.get("source_ip")}
Username: {alert.get("source_user")}
Full Log: {alert.get("full_log")}

=== ALERT CORRELATION ===
{correlation_text}

=== SECURITY CONTEXT ===
{security_context}

=== PRELIMINARY TINY CYBERLLM ANALYSIS ===
{tiny_llm_analysis}

Perform cross-verification.

Determine:

1. Likely security event
2. Evidence supporting the event
3. Whether the preliminary analysis is supported by the evidence
4. Important inconsistencies or missing information
5. Whether multiple/repeated attempts are actually supported by
   the correlated alerts
6. Recommended severity: Critical, High, Medium, or Low

Rules:

- Do not invent evidence.
- Do not claim repeated or multiple attempts unless the correlation
  evidence contains multiple related alerts.
- Distinguish the current alert from correlated alerts.
- Do not assume that a non-existent username means the attacker
  successfully accessed the system.
"""

        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=120,
        )

        response.raise_for_status()

        return response.json()["response"]


qwen_service = QwenService()
