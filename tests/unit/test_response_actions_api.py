
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(1, str(PROJECT_ROOT))

from app.db import get_db
from app.db.database import Base
from app.models import Alert, Incident, Investigation
from app.main import app


TEST_TOKEN = "test-reviewer-token-not-for-production"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )
    Base.metadata.create_all(bind=engine)

    monkeypatch.setenv("SOC_REVIEWER_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("SOC_REVIEWER_ID", "test-reviewer")

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.test_session = TestingSession

    with TestingSession() as db:
        incident = Incident(
            id=1,
            incident_number="SOC-TEST-1",
            title="Synthetic test incident",
            description="Test-only incident",
            severity="High",
            status="Open",
        )
        db.add(incident)

        alert = Alert(
            id=1,
            wazuh_alert_id="TEST-ALERT-1",
            rule_id="BRUTE_FORCE",
            rule_level=10,
            rule_description="Synthetic repeated failed authentication",
            source_ip="198.51.100.25",
            username="synthetic-user",
            agent_id="TEST-AGENT-1",
            agent_name="synthetic-endpoint",
            full_log="Synthetic test evidence",
            raw_json={},
            mitre_attack={},
        )
        db.add(alert)

        findings = {
            "alert_database_id": 1,
            "wazuh_alert_id": "TEST-ALERT-1",
            "normalized_alert": {
                "alert_id": "TEST-ALERT-1",
                "source_ip": "198.51.100.25",
                "source_user": "synthetic-user",
                "agent_id": "TEST-AGENT-1",
                "agent_name": "synthetic-endpoint",
            },
            "investigation_status": "Completed",
            "error": None,
            "evidence_validation": {
                "decision": "True Positive",
                "severity": "High",
                "evidence": [
                    "Synthetic repeated failed authentication",
                    "Source IP: 198.51.100.25",
                ],
                "evidence_grounded": True,
                "unsupported_claims": [],
                "correlation_supported": True,
            },
            "response_actions_executed": False,
        }

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        db.add(
            Investigation(
                id=1,
                incident_id=1,
                investigation_type="Synthetic Test Investigation",
                findings=json.dumps(findings),
                confidence="High",
                started_at=now,
                completed_at=now,
            )
        )
        db.commit()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def propose(
    client,
    action_type="block_ip",
    target="198.51.100.25",
    headers=AUTH_HEADERS,
):
    return client.post(
        "/api/v1/response-actions",
        headers=headers,
        json={
            "incident_id": 1,
            "action_type": action_type,
            "target": target,
        },
    )


def test_proposal_starts_pending_without_execution(client):
    response = propose(client)

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "Pending"
    assert body["approved_by"] is None
    assert body["approved_at"] is None
    assert body["executed_at"] is None
    assert "No response executed" in body["result"]


def test_proposal_requires_authentication(client):
    response = propose(client, headers={})
    assert response.status_code == 401


def test_proposal_requires_existing_incident(client):
    response = client.post(
        "/api/v1/response-actions",
        headers=AUTH_HEADERS,
        json={
            "incident_id": 999,
            "action_type": "block_ip",
            "target": "198.51.100.25",
        },
    )
    assert response.status_code == 404


def test_invalid_action_type_is_rejected(client):
    response = propose(client, action_type="run_arbitrary_command")
    assert response.status_code == 422


def test_invalid_ip_is_rejected(client):
    response = propose(client, target="not-an-ip")
    assert response.status_code == 422


def test_mismatched_ip_is_rejected(client):
    response = propose(client, target="198.51.100.26")
    assert response.status_code == 409


def test_uncertain_investigation_cannot_propose(client):
    with client.app.state.test_session() as db:
        investigation = db.query(Investigation).filter_by(id=1).first()
        findings = json.loads(investigation.findings)
        findings["evidence_validation"]["decision"] = "Uncertain"
        investigation.findings = json.dumps(findings)
        db.commit()

    response = propose(client)
    assert response.status_code == 409


def test_unsupported_claims_block_proposal(client):
    with client.app.state.test_session() as db:
        investigation = db.query(Investigation).filter_by(id=1).first()
        findings = json.loads(investigation.findings)
        findings["evidence_validation"]["unsupported_claims"] = [
            "Unsupported claim"
        ]
        investigation.findings = json.dumps(findings)
        db.commit()

    response = propose(client)
    assert response.status_code == 409


def test_approval_requires_authentication(client):
    action = propose(client).json()

    response = client.post(
        f"/api/v1/response-actions/{action['id']}/approve"
    )
    assert response.status_code == 401


def test_unapproved_action_cannot_execute(client):
    action = propose(client).json()

    response = client.post(
        f"/api/v1/response-actions/{action['id']}/execute",
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 409


def test_rejection_audit_is_separate_from_approval(client):
    action = propose(client).json()
    action_id = action["id"]

    rejected = client.post(
        f"/api/v1/response-actions/{action_id}/reject",
        headers=AUTH_HEADERS,
        json={"reason": "Insufficient evidence"},
    )

    assert rejected.status_code == 200
    body = rejected.json()
    assert body["status"] == "Rejected"
    assert body["rejected_by"] == "test-reviewer"
    assert body["rejected_at"] is not None
    assert body["rejection_reason"] == "Insufficient evidence"
    assert body["approved_by"] is None
    assert body["approved_at"] is None

    execution = client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers=AUTH_HEADERS,
    )
    assert execution.status_code == 409


def test_approved_action_executes_in_simulation_only(client):
    action = propose(client).json()
    action_id = action["id"]

    approved = client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        headers=AUTH_HEADERS,
    )

    assert approved.status_code == 200
    assert approved.json()["status"] == "Approved"
    assert approved.json()["approved_by"] == "test-reviewer"
    assert approved.json()["approved_at"] is not None
    assert approved.json()["executed_at"] is None

    executed = client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers=AUTH_HEADERS,
    )

    assert executed.status_code == 200
    body = executed.json()
    assert body["status"] == "Executed"
    assert body["executed_at"] is not None
    assert "SIMULATED ONLY" in body["result"]
    assert "No real system changes" in body["result"]


def test_action_cannot_be_approved_twice(client):
    action = propose(client).json()
    endpoint = f"/api/v1/response-actions/{action['id']}/approve"

    first = client.post(endpoint, headers=AUTH_HEADERS)
    second = client.post(endpoint, headers=AUTH_HEADERS)

    assert first.status_code == 200
    assert second.status_code == 409


def test_action_cannot_be_executed_twice(client):
    action = propose(client).json()
    action_id = action["id"]

    client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        headers=AUTH_HEADERS,
    )

    endpoint = f"/api/v1/response-actions/{action_id}/execute"
    first = client.post(endpoint, headers=AUTH_HEADERS)
    second = client.post(endpoint, headers=AUTH_HEADERS)

    assert first.status_code == 200
    assert second.status_code == 409


def test_invalid_reviewer_token_is_rejected(client):
    response = propose(
        client,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401
def test_closed_incident_rejects_new_proposal(client):
    with client.app.state.test_session() as db:
        incident = db.query(Incident).filter(Incident.id == 1).first()
        incident.status = "Closed"
        db.commit()

    response = propose(client)

    assert response.status_code == 409


def test_resolved_incident_rejects_new_proposal(client):
    with client.app.state.test_session() as db:
        incident = db.query(Incident).filter(Incident.id == 1).first()
        incident.status = "Resolved"
        db.commit()

    response = propose(client)

    assert response.status_code == 409


def test_disable_account_rejects_mismatched_target(client):
    response = propose(
        client,
        action_type="disable_account",
        target="different-user",
    )

    assert response.status_code == 409


def test_isolate_endpoint_rejects_mismatched_target(client):
    response = propose(
        client,
        action_type="isolate_endpoint",
        target="different-endpoint",
    )

    assert response.status_code == 409


def test_proposal_rejects_incomplete_investigation(client):
    with client.app.state.test_session() as db:
        investigation = (
            db.query(Investigation)
            .filter(Investigation.id == 1)
            .first()
        )
        investigation.completed_at = None
        db.commit()

    response = propose(client)

    assert response.status_code == 409


def test_proposal_rejects_invalid_findings_json(client):
    with client.app.state.test_session() as db:
        investigation = (
            db.query(Investigation)
            .filter(Investigation.id == 1)
            .first()
        )
        investigation.findings = "{invalid-json"
        db.commit()

    response = propose(client)

    assert response.status_code == 409


def test_rejected_action_cannot_be_approved(client):
    action = propose(client).json()
    action_id = action["id"]

    rejected = client.post(
        f"/api/v1/response-actions/{action_id}/reject",
        headers=AUTH_HEADERS,
        json={"reason": "Evidence is insufficient"},
    )
    approved = client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        headers=AUTH_HEADERS,
    )

    assert rejected.status_code == 200
    assert rejected.json()["status"] == "Rejected"
    assert approved.status_code == 409


def test_missing_reviewer_configuration_fails_closed(client, monkeypatch):
    monkeypatch.delenv("SOC_REVIEWER_TOKEN", raising=False)

    response = propose(client)

    assert response.status_code == 503


def test_execution_retry_preserves_original_audit_record(client):
    action = propose(client).json()
    action_id = action["id"]

    approved = client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        headers=AUTH_HEADERS,
    )
    assert approved.status_code == 200

    first_execution = client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers=AUTH_HEADERS,
    )
    assert first_execution.status_code == 200

    original = first_execution.json()
    assert original["status"] == "Executed"
    assert original["executed_at"] is not None

    retry = client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers=AUTH_HEADERS,
    )
    assert retry.status_code == 409

    listing = client.get(
        "/api/v1/response-actions",
        headers=AUTH_HEADERS,
    )
    assert listing.status_code == 200

    persisted = next(
        item for item in listing.json()["actions"]
        if item["id"] == action_id
    )

    assert persisted["status"] == "Executed"
    assert persisted["executed_at"] == original["executed_at"]
    assert persisted["result"] == original["result"]


def test_ungrounded_investigation_cannot_propose_action(client):
    with client.app.state.test_session() as db:
        investigation = db.query(Investigation).filter_by(id=1).first()
        findings = json.loads(investigation.findings)
        findings["evidence_validation"]["evidence_grounded"] = False
        investigation.findings = json.dumps(findings)
        db.commit()

    response = propose(client)

    assert response.status_code == 409


def test_investigation_with_error_cannot_propose_action(client):
    with client.app.state.test_session() as db:
        investigation = db.query(Investigation).filter_by(id=1).first()
        findings = json.loads(investigation.findings)
        findings["error"] = "Synthetic investigation failure"
        investigation.findings = json.dumps(findings)
        db.commit()

    response = propose(client)

    assert response.status_code == 409
