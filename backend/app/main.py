
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert

from app.services.alert_normalizer import alert_normalizer
from app.services.alert_deduplicator import alert_deduplicator
from app.services.rulebook_engine import rulebook_engine
from app.services.redis_queue import redis_queue

from app.api.response_actions import router as response_actions_router
from app.api.dashboard import router as dashboard_router

app = FastAPI(
    title="Autonomous SOC Analyst Agent",
    description="Human-Gated Autonomous SOC Analyst Agent API",
    version="0.1.0",
)
app.include_router(response_actions_router)
app.include_router(dashboard_router)
# In-memory deduplication state. This does not persist across restarts
# and is not shared between multiple backend processes.
seen_fingerprints = set()


@app.get("/")
def root():
    return {
        "project": "Autonomous SOC Analyst Agent",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.post("/api/v1/wazuh/alert")
def receive_wazuh_alert(
    alert: dict,
    db: Session = Depends(get_db),
):
    # --------------------------------------------------
    # 1. Normalize the incoming Wazuh alert
    # --------------------------------------------------
    normalized_alert = alert_normalizer.normalize(alert)

    # --------------------------------------------------
    # 2. Validate the event timestamp before deduplication
    #    or database writes
    # --------------------------------------------------
    timestamp_value = normalized_alert.get("timestamp")

    if not isinstance(timestamp_value, str) or not timestamp_value.strip():
        raise HTTPException(
            status_code=422,
            detail="Missing or invalid Wazuh alert timestamp",
        )

    try:
        parsed_timestamp = datetime.fromisoformat(
            timestamp_value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Missing or invalid Wazuh alert timestamp",
        )

    # Normalize the event time to UTC.
    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(
            tzinfo=timezone.utc
        )

    parsed_timestamp = parsed_timestamp.astimezone(timezone.utc)

    # Keep the normalized event JSON-serializable for Redis.
    normalized_alert["timestamp"] = parsed_timestamp.isoformat()

    # The SQLAlchemy column is DateTime without timezone support.
    database_timestamp = parsed_timestamp.replace(tzinfo=None)

    # --------------------------------------------------
    # 3. Check for duplicates
    # --------------------------------------------------
    fingerprint = alert_deduplicator.generate_fingerprint(
        normalized_alert
    )

    if fingerprint in seen_fingerprints:
        return {
            "status": "duplicate",
            "source": "wazuh",
        }

    # Preserve the existing deduplicator contract: record the
    # fingerprint before processing, then release it if processing
    # fails so a retry is not immediately rejected as a duplicate.
    seen_fingerprints.add(fingerprint)

    try:
        # --------------------------------------------------
        # 4. Evaluate the rulebook
        # --------------------------------------------------
        rulebook_matches = rulebook_engine.evaluate(alert)

        # --------------------------------------------------
        # 5. Persist the alert in PostgreSQL
        # --------------------------------------------------
        db_alert = Alert(
            wazuh_alert_id=normalized_alert.get("alert_id"),
            timestamp=database_timestamp,
            rule_id=normalized_alert.get("rule_id"),
            rule_level=normalized_alert.get("rule_level"),
            rule_description=normalized_alert.get("rule_description"),
            agent_id=normalized_alert.get("agent_id"),
            agent_name=normalized_alert.get("agent_name"),
            source_ip=normalized_alert.get("source_ip"),
            destination_ip=normalized_alert.get("destination_ip"),
            username=normalized_alert.get("source_user"),
            full_log=normalized_alert.get("full_log"),
            decoder=normalized_alert.get("decoder"),
            mitre_attack=normalized_alert.get("mitre"),
            raw_json=normalized_alert.get("raw_alert"),
        )

        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        # --------------------------------------------------
        # 6. Enqueue the investigation task in Redis
        # --------------------------------------------------
        task = {
            "normalized_alert": normalized_alert,
            "rulebook_matches": rulebook_matches,
            "db_alert_id": db_alert.id,
        }

        redis_queue.enqueue(task)
        queue_size = redis_queue.size()

    except Exception as exc:
        db.rollback()
        seen_fingerprints.discard(fingerprint)

        print(
            "Wazuh alert ingestion failed: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

        raise HTTPException(
            status_code=500,
            detail="Alert ingestion failed",
        ) from exc

    # --------------------------------------------------
    # 7. Log successful ingestion
    # --------------------------------------------------
    print("\nNew Wazuh alert accepted:", flush=True)
    print(normalized_alert, flush=True)

    print("\nRulebook matches:", flush=True)
    print(rulebook_matches, flush=True)

    print("\nAlert added to Redis investigation queue.", flush=True)
    print(f"Queue size: {queue_size}", flush=True)

    # --------------------------------------------------
    # 8. Return the API response
    # --------------------------------------------------
    return {
        "status": "accepted",
        "source": "wazuh",
        "duplicate": False,
        "database_id": db_alert.id,
        "rulebook_matches": rulebook_matches,
        "queue_size": queue_size,
        "alert": normalized_alert,
    }
