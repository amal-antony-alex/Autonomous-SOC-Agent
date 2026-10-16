import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(1, str(PROJECT_ROOT))

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.models import Alert, Incident, Investigation

# Stub heavy AI services so importing ai_worker does not load models.
rag_module = ModuleType("app.services.rag_service")
rag_module.rag_service = MagicMock()
sys.modules["app.services.rag_service"] = rag_module

tiny_module = ModuleType("app.services.tiny_llm_service")
tiny_module.tiny_llm_service = MagicMock()
sys.modules["app.services.tiny_llm_service"] = tiny_module

qwen_module = ModuleType("app.services.qwen_service")
qwen_module.qwen_service = MagicMock()
sys.modules["app.services.qwen_service"] = qwen_module

from backend.app import ai_worker


@pytest.fixture
def test_db(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(ai_worker, "SessionLocal", TestSessionLocal)

    with TestSessionLocal() as db:
        db.add(
            Alert(
                id=101,
                wazuh_alert_id="test-wazuh-alert-101",
                rule_id="5710",
                rule_level=5,
                rule_description="Test SSH authentication alert",
                source_ip="198.51.100.10",
                username="test-user",
                full_log="Synthetic test alert",
            )
        )
        db.commit()

    yield TestSessionLocal

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def base_inputs():
    return {
        "db_alert_id": 101,
        "normalized_alert": {
            "alert_id": "test-wazuh-alert-101",
            "rule_description": "Test SSH authentication alert",
        },
        "rulebook_matches": [
            {"rule_id": "BRUTE_FORCE", "severity": "High"}
        ],
        "correlation_result": {"alert_count": 1},
    }


def test_uncertain_creates_investigation_without_incident(
    test_db, base_inputs
):
    result = {
        "evidence_validation": {
            "decision": "Uncertain",
            "severity": "High",
        }
    }

    ai_worker.persist_investigation(**base_inputs, result=result)

    with test_db() as db:
        assert db.query(Incident).count() == 0
        investigation = db.query(Investigation).one()
        findings = json.loads(investigation.findings)

        assert investigation.incident_id is None
        assert findings["human_review_required"] is True
        assert findings["response_actions_executed"] is False


def test_validated_true_positive_creates_linked_incident(
    test_db, base_inputs
):
    result = {
        "evidence_validation": {
            "decision": "True Positive",
            "severity": "High",
        }
    }

    ai_worker.persist_investigation(**base_inputs, result=result)

    with test_db() as db:
        incident = db.query(Incident).one()
        investigation = db.query(Investigation).one()

        assert incident.incident_number == "SOC-101"
        assert incident.severity == "High"
        assert incident.status == "Open"
        assert investigation.incident_id == incident.id

        findings = json.loads(investigation.findings)
        assert findings["response_actions_executed"] is False


def test_failed_investigation_does_not_create_incident(
    test_db, base_inputs
):
    result = {
        "evidence_validation": {
            "decision": "True Positive",
            "severity": "Critical",
        }
    }

    ai_worker.persist_investigation(
        **base_inputs,
        result=result,
        error="Synthetic test failure",
    )

    with test_db() as db:
        # This assertion should expose the current bug.
        assert db.query(Incident).count() == 0

        investigation = db.query(Investigation).one()
        findings = json.loads(investigation.findings)

        assert investigation.incident_id is None
        assert findings["investigation_status"] == "Failed"
        assert findings["response_actions_executed"] is False


def test_reprocessing_does_not_duplicate_incident(
    test_db, base_inputs
):
    result = {
        "evidence_validation": {
            "decision": "True Positive",
            "severity": "High",
        }
    }

    ai_worker.persist_investigation(**base_inputs, result=result)
    ai_worker.persist_investigation(**base_inputs, result=result)

    with test_db() as db:
        assert db.query(Incident).count() == 1
        assert db.query(Investigation).count() == 2
