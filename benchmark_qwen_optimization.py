
import time
import uuid
import requests
from statistics import mean

URL = "http://localhost:8000/api/v1/wazuh/alert"
PREFIX = f"QWENOPT5-{uuid.uuid4().hex[:8]}"
session = requests.Session()
results = []

print("Benchmark:", PREFIX)

for i in range(5):
    alert_id = f"{PREFIX}-{i:03d}"
    payload = {
        "id": alert_id,
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()
        ),
        "rule": {
            "id": "100001",
            "level": 3,
            "description": "Synthetic benign performance test event",
        },
        "agent": {
            "id": "999",
            "name": "soc-performance-test-host",
        },
        "data": {
            "srcip": "192.0.2.10",
            "dstip": "198.51.100.20",
            "dstport": "443",
        },
        "full_log": (
            f"Synthetic benign performance test event {i}; "
            "no malicious activity is asserted."
        ),
    }

    start = time.perf_counter()
    try:
        response = session.post(URL, json=payload, timeout=30)
        elapsed = (time.perf_counter() - start) * 1000
        results.append({
            "id": alert_id,
            "status": response.status_code,
            "latency_ms": elapsed,
        })
        print(
            f"{alert_id}: HTTP {response.status_code}, "
            f"{elapsed:.2f} ms, response={response.text[:200]}"
        )
    except requests.RequestException as exc:
        print(f"{alert_id}: REQUEST FAILED: {exc}")

    time.sleep(0.2)

successful = [r for r in results if r["status"] in (200, 201, 202)]

print("\n--- Ingestion Summary ---")
print("Submitted:", 5)
print("Responses received:", len(results))
print("Successful HTTP responses:", len(successful))
if results:
    latencies = [r["latency_ms"] for r in results]
    print(f"Mean latency: {mean(latencies):.2f} ms")
    print(f"Maximum latency: {max(latencies):.2f} ms")
print("Benchmark prefix:", PREFIX)
