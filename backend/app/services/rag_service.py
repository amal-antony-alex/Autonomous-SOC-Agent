from rag.retriever.rag_pipeline import RAGPipeline

from app.services.tiny_llm_service import tiny_llm_service
from app.services.qwen_service import qwen_service
from app.services.evidence_validator import evidence_validator


class RAGService:

    def __init__(self):
        self.pipeline = RAGPipeline()

    @staticmethod
    def build_query(alert, correlation_result=None):

        parts = [
            alert.get("rule_description"),
            alert.get("full_log"),
            alert.get("source_ip"),
            alert.get("source_user"),
            alert.get("destination_ip"),
            alert.get("destination_port"),
        ]

        if correlation_result:
            parts.append(
                f"Correlated alerts: "
                f"{correlation_result.get('alert_count', 0)}"
            )

        return " ".join(
            str(value)
            for value in parts
            if value is not None
        )

    @staticmethod
    def build_llm_prompt(
        alert,
        context,
        correlation_result=None
    ):

        correlation_text = "No correlated alerts."

        if correlation_result:

            related_alerts = (
                correlation_result.get(
                    "related_alerts",
                    []
                )
            )

            correlation_text = (
                f"Correlation window: "
                f"{correlation_result.get('window_minutes')} minutes\n"
                f"Correlated alert count: "
                f"{correlation_result.get('alert_count', 0)}\n"
            )

            if related_alerts:

                correlation_text += (
                    "\nRelated alerts:\n"
                )

                for related in related_alerts:

                    correlation_text += (
                        f"- Alert ID: "
                        f"{related.get('alert_id')}, "
                        f"Rule ID: "
                        f"{related.get('rule_id')}, "
                        f"Timestamp: "
                        f"{related.get('timestamp')}, "
                        f"User: "
                        f"{related.get('source_user')}\n"
                    )

        return f"""
You are a cybersecurity SOC analyst.

Analyze the following Wazuh alert using the supplied security
knowledge and alert correlation evidence.

=== SECURITY KNOWLEDGE ===
{context}

=== CURRENT WAZUH ALERT ===
Rule ID: {alert.get("rule_id")}
Rule Description: {alert.get("rule_description")}
Rule Level: {alert.get("rule_level")}
Source IP: {alert.get("source_ip")}
Username: {alert.get("source_user")}
Full Log: {alert.get("full_log")}

=== ALERT CORRELATION ===
{correlation_text}

Important:
- Only claim repeated or multiple attempts when the correlation
  evidence actually shows multiple related alerts.
- Do not invent evidence.
- Distinguish the current alert from related alerts.

Provide a preliminary SOC analysis.
Identify the likely security event and the relevant evidence.
"""

    def investigate(
        self,
        alert,
        rulebook_matches=None,
        correlation_result=None
    ):

        if rulebook_matches is None:
            rulebook_matches = []

        if correlation_result is None:
            correlation_result = {
                "correlated": False,
                "alert_count": 1,
                "related_alerts": []
            }

        query = self.build_query(
            alert,
            correlation_result=correlation_result
        )

        result = self.pipeline.build_context(
            query=query,
            alert=alert,
            top_k=3
        )

        llm_prompt = self.build_llm_prompt(
            alert,
            result["context"],
            correlation_result=correlation_result
        )

        # --------------------------------------------------
        # Tiny CyberLLM
        # --------------------------------------------------

        preliminary_analysis = (
            tiny_llm_service.generate(
                llm_prompt,
                max_new_tokens=30
            )
        )

        result["tiny_cyberllm"] = {
            "prompt": llm_prompt,
            "analysis": preliminary_analysis
        }

        # --------------------------------------------------
        # Qwen Verification
        # --------------------------------------------------

        qwen_analysis = qwen_service.verify(
            alert=alert,
            security_context=result["context"],
            tiny_llm_analysis=preliminary_analysis,
            correlation_result=correlation_result
        )

        result["qwen_verification"] = {
            "model": qwen_service.model,
            "analysis": qwen_analysis
        }

        # --------------------------------------------------
        # Evidence Validation
        # --------------------------------------------------

        validation = evidence_validator.validate(
            alert=alert,
            rulebook_matches=rulebook_matches,
            qwen_analysis=qwen_analysis,
            correlation_result=correlation_result
        )

        result["evidence_validation"] = validation

        # Keep correlation available in the final result
        result["alert_correlation"] = correlation_result

        return result


rag_service = RAGService()
