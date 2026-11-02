
import sys
from pathlib import Path
from unittest.mock import MagicMock
from sqlalchemy.exc import IntegrityError

import pytest
from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(1, str(PROJECT_ROOT))

from app.db import get_db
from app import main


@pytest.fixture
def client(monkeypatch):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    db_alert = MagicMock()
    db_alert.id = 501

    monkeypatch.setattr(main, "rulebook_engine", MagicMock())
    monkeypatch.setattr(main, "redis_queue", MagicMock())
    monkeypatch.setattr(main, "Alert", MagicMock(return_value=db_alert))
    monkeypatch.setattr(main, "seen_fingerprints", set())

    main.app.dependency_overrides[get_db] = lambda: db

    with TestClient(main.app) as test_client:
        yield test_client, db

    main.app.dependency_overrides.clear()


def valid_alert():
    return {
        "id": "wazuh-test-501",
        "timestamp": "2026-10-25T10:00:00Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "Failed password for invalid user",
        },
        "agent": {"id": "001", "name": "test-agent"},
        "data": {
            "srcip": "198.51.100.25",
            "srcuser": "test-user",
        },
        "full_log": "Failed password for invalid user test-user",
    }


@pytest.mark.parametrize(
    "timestamp",
    [None, "", "not-a-valid-timestamp"],
)
def test_invalid_timestamp_returns_422_without_side_effects(
    client, timestamp
):
    test_client, db = client
    alert = valid_alert()
    alert["timestamp"] = timestamp

    response = test_client.post("/api/v1/wazuh/alert", json=alert)

    assert response.status_code == 422
    db.add.assert_not_called()
    db.commit.assert_not_called()
    main.redis_queue.enqueue.assert_not_called()


def test_valid_timestamp_is_normalized_and_accepted(client):
    test_client, db = client

    response = test_client.post(
        "/api/v1/wazuh/alert",
        json=valid_alert(),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert response.json()["alert"]["timestamp"] == (
        "2026-10-25T10:00:00+00:00"
    )

    db.add.assert_called_once()
    db.commit.assert_called_once()
    main.redis_queue.enqueue.assert_called_once()

def test_existing_wazuh_alert_id_returns_duplicate_without_side_effects(client):
    test_client, db = client

    existing_alert = MagicMock()
    existing_alert.id = 171
    db.query.return_value.filter.return_value.first.return_value = existing_alert

    response = test_client.post(
        "/api/v1/wazuh/alert",
        json=valid_alert(),
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "duplicate",
        "source": "wazuh",
        "duplicate": True,
        "database_id": 171,
    }

    db.add.assert_not_called()
    db.commit.assert_not_called()
    main.redis_queue.enqueue.assert_not_called()


def test_concurrent_duplicate_insert_returns_existing_record(client):
    test_client, db = client

    existing_alert = MagicMock()
    existing_alert.id = 171

    query_result = db.query.return_value.filter.return_value.first
    query_result.side_effect = [None, existing_alert]

    db.commit.side_effect = IntegrityError(
        "INSERT INTO alerts",
        {},
        Exception("duplicate key"),
    )

    response = test_client.post(
        "/api/v1/wazuh/alert",
        json=valid_alert(),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "duplicate"
    assert response.json()["database_id"] == 171

    db.add.assert_called_once()
    db.rollback.assert_called_once()
    main.redis_queue.enqueue.assert_not_called()
