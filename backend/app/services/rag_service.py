from rag.retriever.rag_pipeline import RAGPipeline
from app.services.tiny_llm_service import tiny_llm_service
from app.services.qwen_service import qwen_service


class RAGService:

    def __init__(self):
        self.pipeline = RAGPipeline()

    @staticmethod
    def build_query(alert):
        parts = [
            alert.get("rule_description"),
            alert.get("full_log"),
            alert.get("source_ip"),
            alert.get("source_user"),
            alert.get("destination_ip"),
            alert.get("destination_port"),
        ]

        return " ".join(
            str(value)
            for value in parts
            if value is not None
        )

    @staticmethod
    def build_llm_prompt(alert, context):
        return f"""
You are a cybersecurity SOC analyst.

Analyze the following Wazuh alert using the supplied security knowledge.

=== SECURITY KNOWLEDGE ===
{context}

=== WAZUH ALERT ===
Rule ID: {alert.get("rule_id")}
Rule Description: {alert.get("rule_description")}
Rule Level: {alert.get("rule_level")}
Source IP: {alert.get("source_ip")}
Username: {alert.get("source_user")}
Full Log: {alert.get("full_log")}

Provide a preliminary SOC analysis.
Identify the likely security event and relevant evidence.
"""

    def investigate(self, alert):

        # ---------------------------------------------------------
        # 1. Build RAG query
        # ---------------------------------------------------------
        query = self.build_query(alert)

        # ---------------------------------------------------------
        # 2. Retrieve cybersecurity knowledge
        # ---------------------------------------------------------
        result = self.pipeline.build_context(
            query=query,
            alert=alert,
            top_k=3
        )

        # ---------------------------------------------------------
        # 3. Tiny CyberLLM preliminary analysis
        # ---------------------------------------------------------
        llm_prompt = self.build_llm_prompt(
            alert,
            result["context"]
        )

        preliminary_analysis = tiny_llm_service.generate(
            llm_prompt,
            max_new_tokens=30
        )

        result["tiny_cyberllm"] = {
            "prompt": llm_prompt,
            "analysis": preliminary_analysis
        }

        # ---------------------------------------------------------
        # 4. Qwen second-level verification
        # ---------------------------------------------------------
        qwen_analysis = qwen_service.verify(
            alert=alert,
            security_context=result["context"],
            tiny_llm_analysis=preliminary_analysis
        )

        result["qwen_verification"] = {
            "model": qwen_service.model,
            "analysis": qwen_analysis
        }

        return result


rag_service = RAGService()

