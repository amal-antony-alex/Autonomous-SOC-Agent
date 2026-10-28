
import time

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
        correlation_result=None,
    ):
        correlation_result = correlation_result or {}

        related_alerts = correlation_result.get(
            "related_alerts", []
        )

        correlation_lines = [
            f"Correlated alert count: "
            f"{correlation_result.get('alert_count', 1)}",
            f"Correlation window: "
            f"{correlation_result.get('window_minutes', 'unknown')} minutes",
        ]

        for related in related_alerts[:5]:
            correlation_lines.append(
                "- "
                f"Alert ID: {related.get('alert_id')}; "
                f"Rule ID: {related.get('rule_id')}; "
                f"Timestamp: {related.get('timestamp')}; "
                f"User: {related.get('source_user')}"
            )

        if len(related_alerts) > 5:
            correlation_lines.append(
                f"- {len(related_alerts) - 5} additional related alerts "
                "omitted from this prompt."
            )

        input_text = f"""
CURRENT WAZUH ALERT
Rule ID: {alert.get('rule_id')}
Rule Description: {alert.get('rule_description')}
Rule Level: {alert.get('rule_level')}
Source IP: {alert.get('source_ip')}
Destination IP: {alert.get('destination_ip')}
Destination Port: {alert.get('destination_port')}
Username: {alert.get('source_user')}
Full Log: {alert.get('full_log')}

CORRELATION EVIDENCE
{chr(10).join(correlation_lines)}

RETRIEVED SECURITY KNOWLEDGE
{context}
""".strip()

        return (
            "Instruction:\n"
            "Analyze this SOC alert using only the supplied evidence. "
            "Identify the likely security event, cite relevant evidence, "
            "and state what remains uncertain. Do not invent indicators "
            "or claim malicious activity without sufficient evidence.\n\n"
            "Input:\n"
            f"{input_text}\n\n"
            "Response:\n"
        )

    def investigate(
        self,
        alert,
        rulebook_matches=None,
        correlation_result=None,
    ):
        if rulebook_matches is None:
            rulebook_matches = []

        if correlation_result is None:
            correlation_result = {
                "correlated": False,
                "alert_count": 1,
                "related_alerts": [],
            }

        # Build the retrieval query.
        query = self.build_query(
            alert,
            correlation_result=correlation_result,
        )

        # Stage 1: RAG context retrieval.
        stage_started = time.perf_counter()

        result = self.pipeline.build_context(
            query=query,
            alert=alert,
            top_k=3,
        )

        print(
            f"PERF context_retrieval="
            f"{time.perf_counter() - stage_started:.3f}s",
            flush=True,
        )

        llm_prompt = self.build_llm_prompt(
            alert,
            result["context"],
            correlation_result=correlation_result,
        )

        # Stage 2: Tiny CyberLLM preliminary analysis.
        stage_started = time.perf_counter()

        preliminary_analysis = tiny_llm_service.generate(
            llm_prompt,
            max_new_tokens=80,
        )

        print(
            f"PERF tiny_cyberllm="
            f"{time.perf_counter() - stage_started:.3f}s",
            flush=True,
        )

        result["tiny_cyberllm"] = {
            "prompt": llm_prompt,
            "analysis": preliminary_analysis,
        }

        # Stage 3: Qwen cross-verification.
        stage_started = time.perf_counter()

        qwen_analysis = qwen_service.verify(
            alert=alert,
            security_context=result["context"],
            tiny_llm_analysis=preliminary_analysis,
            correlation_result=correlation_result,
        )

        print(
            f"PERF qwen_verification="
            f"{time.perf_counter() - stage_started:.3f}s",
            flush=True,
        )

        result["qwen_verification"] = {
            "model": qwen_service.model,
            "analysis": qwen_analysis,
        }

        # Stage 4: Evidence validation.
        stage_started = time.perf_counter()

        validation_result = evidence_validator.validate(
            alert=alert,
            rulebook_matches=rulebook_matches,
            qwen_analysis=qwen_analysis,
            correlation_result=correlation_result,
        )

        print(
            f"PERF evidence_validation="
            f"{time.perf_counter() - stage_started:.3f}s",
            flush=True,
        )

        result["evidence_validation"] = validation_result

        return result


rag_service = RAGService()
