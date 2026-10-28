import json
import traceback
from datetime import datetime, timezone

from app.db import SessionLocal
from app.models import Alert, Incident, Investigation
from app.services.redis_queue import redis_queue
from app.services.rag_service import rag_service
from app.services.alert_correlator import alert_correlator


def persist_investigation(
    db_alert_id,
    normalized_alert,
    rulebook_matches,
    correlation_result,
    result=None,
    error=None,
    started_at=None,
):
    """Persist investigation findings and create incidents only for validated TPs."""
    db = SessionLocal()

    try:
        alert_record = db.query(Alert).filter(
            Alert.id == db_alert_id
        ).first()

        if alert_record is None:
            raise ValueError(
                f"Alert database record {db_alert_id} was not found"
            )

        validation = (
            result.get("evidence_validation", {})
            if result else {}
        )
        decision = validation.get("decision", "Uncertain")
        severity = validation.get("severity", "Low")

        incident = None

        if not error and decision == "True Positive":
            incident_number = f"SOC-{db_alert_id}"

            incident = db.query(Incident).filter(
                Incident.incident_number == incident_number
            ).first()

            if incident is None:
                incident = Incident(
                    incident_number=incident_number,
                    title=(
                        normalized_alert.get("rule_description")
                        or "Validated security detection"
                    )[:255],
                    description=(
                        "Incident created from a validated SOC investigation. "
                        f"Wazuh alert ID: "
                        f"{normalized_alert.get('alert_id')}"
                    ),
                    severity=severity,
                    status="Open",
                )
                db.add(incident)
                db.flush()

        findings = {
            "alert_database_id": db_alert_id,
            "wazuh_alert_id": normalized_alert.get("alert_id"),
            "normalized_alert": normalized_alert,
            "rulebook_matches": rulebook_matches,
            "correlation": correlation_result,
            "tiny_cyberllm": (
                result.get("tiny_cyberllm") if result else None
            ),
            "qwen_verification": (
                result.get("qwen_verification") if result else None
            ),
            "evidence_validation": validation,
            "investigation_status": (
                "Failed" if error else "Completed"
            ),
            "error": error,
            "human_review_required": (
                not error and decision == "Uncertain"
            ),
            "response_actions_executed": False,
        }

        started_at = started_at or datetime.now(
            timezone.utc
        ).replace(tzinfo=None)
        completed_at = max(
            datetime.now(timezone.utc).replace(tzinfo=None),
            started_at,
        )

        investigation = Investigation(
            incident_id=incident.id if incident else None,
            started_at=started_at,
            completed_at=completed_at,
            investigation_type="AI Alert Investigation",
            findings=json.dumps(findings, default=str),
            confidence={
                "True Positive": "High",
                "False Positive": "Medium",
                "Uncertain": "Low",
            }.get(decision, "Low"),
        )

        db.add(investigation)
        db.commit()
        db.refresh(investigation)

        print(
            "Investigation persisted: "
            f"id={investigation.id}, "
            f"alert_id={db_alert_id}, "
            f"decision={decision}, "
            f"incident_id={incident.id if incident else None}",
            flush=True,
        )

        return investigation.id

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()



def process_alert(task):
    normalized_alert = task["normalized_alert"]
    rulebook_matches = task["rulebook_matches"]
    db_alert_id = task["db_alert_id"]
    investigation_started_at = datetime.now(
        timezone.utc
    ).replace(tzinfo=None)

    result = None
    correlation_result = None

    try:
        print("Starting alert correlation...", flush=True)

        correlation_result = alert_correlator.correlate(
            normalized_alert
        )

        print(
            "Alert correlation completed: "
            f"count={correlation_result.get('alert_count')}, "
            f"source_ip={correlation_result.get('source_ip')}",
            flush=True,
        )

        print(
            f"AI investigation started for database alert {db_alert_id}",
            flush=True,
        )

        result = rag_service.investigate(
            normalized_alert,
            rulebook_matches=rulebook_matches,
            correlation_result=correlation_result,
        )

        print("\n----- Tiny CyberLLM -----", flush=True)
        print(
            result.get("tiny_cyberllm", {}).get("analysis", ""),
            flush=True,
        )

        print("\n----- Qwen Verification -----", flush=True)
        print(
            result.get("qwen_verification", {}).get("analysis", ""),
            flush=True,
        )

        print("\n----- Evidence Validation -----", flush=True)
        print(
            result.get("evidence_validation", {}),
            flush=True,
        )

        investigation_id = persist_investigation(
            db_alert_id=db_alert_id,
            normalized_alert=normalized_alert,
            rulebook_matches=rulebook_matches,
            correlation_result=correlation_result,
            result=result,
            started_at=investigation_started_at,
        )

        print(
            f"AI investigation completed and saved: {investigation_id}",
            flush=True,
        )
        return True

    except Exception as error:
        print(
            f"AI investigation failed for alert {db_alert_id}: "
            f"{type(error).__name__}: {error}",
            flush=True,
        )
        traceback.print_exc()

        try:
            investigation_id = persist_investigation(
                db_alert_id=db_alert_id,
                normalized_alert=normalized_alert,
                rulebook_matches=rulebook_matches,
                correlation_result=correlation_result or {},
                result=result,
                error=f"{type(error).__name__}: {error}",
                started_at=investigation_started_at,
            )
            print(
                f"Failure record saved: {investigation_id}",
                flush=True,
            )
            # The failure is durably recorded, so this task is handled.
            return True

        except Exception:
            print(
                "Could not persist investigation failure record. "
                "Task must remain recoverable.",
                flush=True,
            )
            traceback.print_exc()
            return False

def main():
    import time

    print(
        "Redis AI investigation worker started.",
        flush=True,
    )
    print(
        f"Redis queue: {redis_queue.queue_name}",
        flush=True,
    )

    recovered = redis_queue.recover_processing()
    print(
        f"Recovered {recovered} unacknowledged task(s).",
        flush=True,
    )

    while True:
        task = redis_queue.reserve(timeout=5)

        if task is None:
            continue

        print("Task reserved from Redis.", flush=True)
        print(
            f"Remaining pending queue size: {redis_queue.size()}",
            flush=True,
        )

        try:
            handled = process_alert(task)

            if handled:
                acknowledged = redis_queue.acknowledge(task)

                if not acknowledged:
                    print(
                        "Warning: task outcome was recorded, but its "
                        "processing entry was not acknowledged.",
                        flush=True,
                    )
            else:
                released = redis_queue.release(task)

                if released:
                    print(
                        "Task returned to pending queue after "
                        "unsuccessful persistence.",
                        flush=True,
                    )
                else:
                    print(
                        "Warning: task could not be released. "
                        "It remains eligible for startup recovery.",
                        flush=True,
                    )
                    time.sleep(5)

                time.sleep(5)

        except Exception as error:
            print(
                "Queue handling error: "
                f"{type(error).__name__}: {error}",
                flush=True,
            )
            traceback.print_exc()

            # If the task is still in processing, try to return it
            # to pending. If Redis is unavailable, startup recovery
            # can recover it after a worker restart.
            try:
                redis_queue.release(task)
            except Exception:
                traceback.print_exc()
                time.sleep(5)


if __name__ == "__main__":
    main()
