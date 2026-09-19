from fastapi import FastAPI

app = FastAPI(
    title="Autonomous SOC Analyst Agent",
    description="Human-Gated Autonomous SOC Analyst Agent API",
    version="0.1.0"
)


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
    print("Received Wazuh alert:")
    print(alert)

    return {
        "status": "received",
        "source": "wazuh"
    }
