
import requests


class QwenService:
    MAX_RELATED_ALERTS = 5
    REQUEST_TIMEOUT_SECONDS = 120
    MAX_GENERATED_TOKENS = 160

    def __init__(
        self,
        base_url="http://host.docker.internal:11434",
        model="qwen3:0.6b",
    ):
        self.base_url = base_url.rstrip("/")
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

        related_alerts = (
            correlation_result.get("related_alerts", []) or []
        )

        if related_alerts:
            correlation_text += (
                f"\nRelated alerts "
                f"(up to {self.MAX_RELATED_ALERTS} shown):\n"
            )

            for related in related_alerts[:self.MAX_RELATED_ALERTS]:
                correlation_text += (
                    f"- Alert ID: {related.get('alert_id')}, "
                    f"Rule ID: {related.get('rule_id')}, "
                    f"Timestamp: {related.get('timestamp')}, "
                    f"User: {related.get('source_user')}\n"
                )

            omitted_count = (
                len(related_alerts) - self.MAX_RELATED_ALERTS
            )

            if omitted_count > 0:
                correlation_text += (
                    f"- {omitted_count} additional related alerts "
                    "omitted from this prompt.\n"
                )

        prompt = f"""
/no_think
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

Perform concise cross-verification.

Return these six items:
1. Likely security event
2. Specific evidence supporting the event
3. Whether the preliminary analysis is supported
4. Important inconsistencies or missing information
5. Whether repeated attempts are supported by the supplied correlation evidence
6. Recommended severity: Critical, High, Medium, or Low

Rules:
- Do not invent evidence or indicators.
- Do not claim scanning based only on source/destination IPs or a port.
- Do not claim repeated attempts unless multiple relevant alerts support that claim.
- Distinguish the current alert from correlated alerts.
- Do not treat the preliminary Tiny CyberLLM analysis as ground truth.
- Do not assume a missing username means successful authentication.
- If evidence is insufficient, explicitly state that uncertainty.
- Keep the response concise and evidence-based.
""".strip()

        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {
                    "temperature": 0,
                    "num_predict": self.MAX_GENERATED_TOKENS,
                },
            },
            timeout=self.REQUEST_TIMEOUT_SECONDS,
        )

        response.raise_for_status()
        data = response.json()

        if "response" not in data:
            raise ValueError(
                "Qwen response did not contain the expected 'response' field."
            )

        return data["response"]


qwen_service = QwenService()
