from fastapi import FastAPI

from app.services.alert_normalizer import alert_normalizer
from app.services.alert_deduplicator import alert_deduplicator


app = FastAPI(
    title="Autonomous SOC Analyst Agent",
    description="Human-Gated Autonomous SOC Analyst Agent API",
    version="0.1.0"
)


# Temporary in-memory fingerprint store.
# PostgreSQL persistence will be added on Friday.
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
def receive_wazuh_alert(alert: dict):

    # Step 1: Normalize raw Wazuh alert
    normalized_alert = alert_normalizer.normalize(alert)

    # Step 2: Check for duplicate
    is_duplicate = alert_deduplicator.is_duplicate(
        normalized_alert,
        seen_fingerprints
    )

    if is_duplicate:
        return {
            "status": "duplicate",
            "source": "wazuh"
        }

    # New alert
    print("New normalized Wazuh alert:")
    print(normalized_alert)

    return {
        "status": "accepted",
        "source": "wazuh",
        "duplicate": False,
        "alert": normalized_alert
    }
