from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert
from app.services.alert_normalizer import alert_normalizer
from app.services.alert_deduplicator import alert_deduplicator
from app.services.rulebook_engine import rulebook_engine
from app.services.rag_service import rag_service


app = FastAPI(
    title="Autonomous SOC Analyst Agent",
    description="Human-Gated Autonomous SOC Analyst Agent API",
    version="0.1.0"
)


seen_fingerprints = set()


@app.get("/")
def root():
    return {
        "project": "Autonomous SOC Analyst Agent",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/api/v1/wazuh/alert")
def receive_wazuh_alert(
    alert: dict,
    db: Session = Depends(get_db)
):
    # -----------------------------------
    # 1. Normalize Wazuh alert
    # -----------------------------------

    normalized_alert = alert_normalizer.normalize(
        alert
    )

    # -----------------------------------
    # 2. Deduplicate alert
    # -----------------------------------

    is_duplicate = alert_deduplicator.is_duplicate(
        normalized_alert,
        seen_fingerprints
    )

    if is_duplicate:
        return {
            "status": "duplicate",
            "source": "wazuh"
        }

    # -----------------------------------
    # 3. Evaluate SOC Rulebook
    # -----------------------------------

    rulebook_matches = rulebook_engine.evaluate(
        alert
    )

    # -----------------------------------
    # 4. Store alert in PostgreSQL
    # -----------------------------------

    db_alert = Alert(
        wazuh_alert_id=normalized_alert.get(
            "alert_id"
        ),
        timestamp=normalized_alert.get(
            "timestamp"
        ),
        rule_id=normalized_alert.get(
            "rule_id"
        ),
        rule_level=normalized_alert.get(
            "rule_level"
        ),
        rule_description=normalized_alert.get(
            "rule_description"
        ),
        agent_id=normalized_alert.get(
            "agent_id"
        ),
        agent_name=normalized_alert.get(
            "agent_name"
        ),
        source_ip=normalized_alert.get(
            "source_ip"
        ),
        destination_ip=normalized_alert.get(
            "destination_ip"
        ),
        username=normalized_alert.get(
            "source_user"
        ),
        full_log=normalized_alert.get(
            "full_log"
        ),
        decoder=normalized_alert.get(
            "decoder"
        ),
        mitre_attack=normalized_alert.get(
            "mitre"
        ),
        raw_json=normalized_alert.get(
            "raw_alert"
        )
    )

    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    # -----------------------------------
    # 5. RAG investigation
    # -----------------------------------

    rag_result = rag_service.investigate(
        normalized_alert
    )

    # -----------------------------------
    # 6. Logging
    # -----------------------------------

    print(
        "New Wazuh alert stored in PostgreSQL:"
    )
    print(normalized_alert)

    print(
        "Rulebook matches:"
    )
    print(rulebook_matches)

    print(
        "RAG investigation context:"
    )
    print(rag_result["context"])

    # -----------------------------------
    # 7. API response
    # -----------------------------------

    return {
        "status": "accepted",
        "source": "wazuh",
        "duplicate": False,
        "database_id": db_alert.id,

        "rulebook_matches": rulebook_matches,

        "rag": {
            "query": rag_result["query"],
            "retrieved_chunks": (
                rag_result["retrieved_chunks"]
            ),
            "context": rag_result["context"]
        },

        "alert": normalized_alert
    }
