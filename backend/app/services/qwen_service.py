import requests


class QwenService:
    def __init__(
        self,
        base_url="http://localhost:11434",
        model="qwen3:0.6b",
    ):
        self.base_url = base_url
        self.model = model

    def verify(
        self,
        alert: dict,
        security_context: str,
        tiny_llm_analysis: str,
    ) -> str:

        prompt = f"""
You are a cybersecurity SOC analyst performing second-level verification.

Review the Wazuh alert, security knowledge, and preliminary Tiny CyberLLM
analysis below.

=== WAZUH ALERT ===
Rule ID: {alert.get("rule_id")}
Rule Level: {alert.get("rule_level")}
Rule Description: {alert.get("rule_description")}
Source IP: {alert.get("source_ip")}
Username: {alert.get("source_user")}
Full Log: {alert.get("full_log")}

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
5. Recommended severity: Critical, High, Medium, or Low

Do not invent evidence that is not present in the alert or security context.
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
