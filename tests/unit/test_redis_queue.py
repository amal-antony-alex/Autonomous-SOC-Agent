
import json
from unittest.mock import MagicMock

import pytest
import redis

from backend.app.services.redis_queue import RedisInvestigationQueue


@pytest.fixture
def queue():
    instance = RedisInvestigationQueue()
    instance.client = MagicMock()
    return instance


def test_reserve_moves_task_from_pending_to_processing(queue):
    task = {
        "db_alert_id": 101,
        "normalized_alert": {"alert_id": "wazuh-101"},
        "rulebook_matches": [],
    }
    queue.client.blmove.return_value = json.dumps(task)

    result = queue.reserve(timeout=5)

    assert result == task
    queue.client.blmove.assert_called_once_with(
        queue.queue_name,
        queue.processing_queue_name,
        5,
        src="LEFT",
        dest="RIGHT",
    )


def test_reserve_returns_none_when_queue_is_empty(queue):
    queue.client.blmove.return_value = None

    assert queue.reserve(timeout=1) is None


def test_reserve_handles_redis_timeout(queue):
    queue.client.blmove.side_effect = redis.exceptions.TimeoutError()

    assert queue.reserve(timeout=1) is None


def test_acknowledge_removes_exact_processing_task(queue):
    task = {"db_alert_id": 101}
    queue.client.lrem.return_value = 1

    assert queue.acknowledge(task) is True

    queue.client.lrem.assert_called_once_with(
        queue.processing_queue_name,
        1,
        json.dumps(task),
    )


def test_acknowledge_reports_missing_task(queue):
    queue.client.lrem.return_value = 0

    assert queue.acknowledge({"db_alert_id": 101}) is False


def test_release_moves_task_back_to_pending(queue):
    task = {"db_alert_id": 101}
    queue.client.eval.return_value = 1

    assert queue.release(task) is True

    args = queue.client.eval.call_args.args
    assert args[1] == 2
    assert args[2] == queue.processing_queue_name
    assert args[3] == queue.queue_name
    assert args[4] == json.dumps(task)


def test_recovery_runs_atomic_redis_script(queue):
    queue.client.eval.return_value = 2

    recovered = queue.recover_processing()

    assert recovered == 2
    args = queue.client.eval.call_args.args
    assert args[1] == 2
    assert args[2] == queue.processing_queue_name
    assert args[3] == queue.queue_name


def test_pending_queue_size(queue):
    queue.client.llen.return_value = 3

    assert queue.size() == 3
    queue.client.llen.assert_called_once_with(queue.queue_name)
