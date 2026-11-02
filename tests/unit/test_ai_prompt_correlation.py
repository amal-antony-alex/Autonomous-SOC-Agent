import sys
import types

# Prevent unrelated model and pipeline initialization during unit tests.
tiny_llm_stub = types.ModuleType("app.services.tiny_llm_service")
tiny_llm_stub.tiny_llm_service = None
sys.modules["app.services.tiny_llm_service"] = tiny_llm_stub

rag_pipeline_stub = types.ModuleType("rag.retriever.rag_pipeline")


class FakeRAGPipeline:
    pass


rag_pipeline_stub.RAGPipeline = FakeRAGPipeline
sys.modules["rag.retriever.rag_pipeline"] = rag_pipeline_stub

evidence_validator_stub = types.ModuleType(
    "app.services.evidence_validator"
)
evidence_validator_stub.evidence_validator = None
sys.modules["app.services.evidence_validator"] = evidence_validator_stub

from app.services.rag_service import RAGService
from app.services.qwen_service import QwenService


def make_related_alerts(count=3):
    return [
        {
            "alert_id": f"alert-{i}",
            "rule_id": "5710",
            "timestamp": f"2026-10-31T06:5{i}:00Z",
            "source_user": "nonexistentuser",
            "process_id": "8958",
            "source_port": "39522",
        }
        for i in range(count)
    ]


def test_rag_prompt_includes_process_id_and_source_port():
    alert = {
        "rule_id": "5710",
        "rule_description": "SSH authentication failure",
        "rule_level": 5,
        "source_ip": "127.0.0.1",
        "source_user": "nonexistentuser",
        "full_log": "Failed password for invalid user",
    }

    correlation = {
        "alert_count": 1,
        "window_minutes": 10,
        "related_alerts": make_related_alerts(1),
    }

    prompt = RAGService.build_llm_prompt(
        alert, "SSH security context", correlation
    )

    assert "Process ID: 8958" in prompt
    assert "Source Port: 39522" in prompt
    assert "User: nonexistentuser; Process ID:" in prompt


def test_rag_prompt_limits_related_alerts_to_five():
    alert = {"rule_id": "5710"}

    correlation = {
        "alert_count": 7,
        "window_minutes": 10,
        "related_alerts": make_related_alerts(7),
    }

    prompt = RAGService.build_llm_prompt(
        alert, "Security context", correlation
    )

    assert "alert-4" in prompt
    assert "alert-5" not in prompt
    assert "2 additional related alerts omitted" in prompt


def test_qwen_prompt_includes_process_id_and_source_port(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "Verification completed."}

    def fake_post(url, json, timeout):
        captured["prompt"] = json["prompt"]
        return FakeResponse()

    monkeypatch.setattr(
        "backend.app.services.qwen_service.requests.post",
        fake_post,
    )

    service = QwenService(
        base_url="http://example.test",
        model="test-model",
    )

    service.verify(
        alert={
            "rule_id": "5710",
            "rule_level": 5,
            "rule_description": "SSH authentication failure",
            "source_ip": "127.0.0.1",
            "source_user": "nonexistentuser",
            "full_log": "Failed password",
        },
        security_context="SSH security context",
        tiny_llm_analysis="Possible brute-force activity.",
        correlation_result={
            "alert_count": 1,
            "window_minutes": 10,
            "related_alerts": make_related_alerts(1),
        },
    )

    prompt = captured["prompt"]

    assert "Process ID: 8958" in prompt
    assert "Source Port: 39522" in prompt


def test_qwen_prompt_limits_related_alerts_to_five(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "Verification completed."}

    def fake_post(url, json, timeout):
        captured["prompt"] = json["prompt"]
        return FakeResponse()

    monkeypatch.setattr(
        "backend.app.services.qwen_service.requests.post",
        fake_post,
    )

    service = QwenService()

    service.verify(
        alert={"rule_id": "5710"},
        security_context="Security context",
        tiny_llm_analysis="Preliminary analysis",
        correlation_result={
            "alert_count": 7,
            "window_minutes": 10,
            "related_alerts": make_related_alerts(7),
        },
    )

    prompt = captured["prompt"]

    assert "alert-4" in prompt
    assert "alert-5" not in prompt
    assert "2 additional related alerts omitted" in prompt
