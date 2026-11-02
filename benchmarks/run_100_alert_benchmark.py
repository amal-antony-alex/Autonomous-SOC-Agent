import csv
import json
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE_URL = "http://localhost:18000"
ENDPOINT = f"{BASE_URL}/api/v1/wazuh/alert"
HEALTH_ENDPOINT = f"{BASE_URL}/health"

TOTAL_ALERTS = 100
REQUEST_TIMEOUT = 30

RESULT_DIR = Path("benchmarks/results")
RESULT_DIR.mkdir(parents=True, exist_ok=True)

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
CSV_PATH = RESULT_DIR / f"benchmark_100_{RUN_ID}.csv"
JSON_PATH = RESULT_DIR / f"benchmark_100_{RUN_ID}.json"


def generate_alert(index):
    unique_id = f"BENCH-{RUN_ID}-{index:04d}"
    source_ip = f"192.0.2.{(index % 254) + 1}"

    return {
        "id": unique_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "mitre": {}
        },
        "agent": {
            "id": "999",
            "name": "benchmark-endpoint"
        },
        "data": {
            "srcip": source_ip,
            "srcport": str(40000 + index),
            "srcuser": f"benchmark_user_{index:04d}",
            "dstport": "22"
        },
        "full_log": (
            f"Failed password for invalid user benchmark_user_{index:04d} "
            f"from {source_ip} port {40000 + index} ssh2"
        ),
        "location": "benchmark"
    }


def percentile(values, percentile_value):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile_value
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def main():
    health = requests.get(HEALTH_ENDPOINT, timeout=10)
    health.raise_for_status()

    rows = []
    latencies = []

    start_time = time.perf_counter()

    for index in range(1, TOTAL_ALERTS + 1):
        alert = generate_alert(index)
        request_start = time.perf_counter()

        try:
            response = requests.post(
                ENDPOINT,
                json=alert,
                timeout=REQUEST_TIMEOUT
            )
            latency = time.perf_counter() - request_start
            latencies.append(latency)

            try:
                body = response.json()
            except ValueError:
                body = {"response_text": response.text[:500]}

            rows.append({
                "index": index,
                "wazuh_alert_id": alert["id"],
                "http_status": response.status_code,
                "api_status": body.get("status"),
                "duplicate": body.get("duplicate"),
                "database_id": body.get("database_id"),
                "ingestion_latency_seconds": round(latency, 4),
                "error": body.get("detail") if response.status_code >= 400 else None
            })

            print(
                f"[{index:03d}/{TOTAL_ALERTS}] "
                f"HTTP {response.status_code} | "
                f"{latency:.3f}s | "
                f"{body.get('status', 'unknown')}"
            )

        except requests.RequestException as exc:
            latency = time.perf_counter() - request_start
            rows.append({
                "index": index,
                "wazuh_alert_id": alert["id"],
                "http_status": None,
                "api_status": "request_error",
                "duplicate": None,
                "database_id": None,
                "ingestion_latency_seconds": round(latency, 4),
                "error": str(exc)
            })
            print(f"[{index:03d}/{TOTAL_ALERTS}] REQUEST ERROR: {exc}")

    ingestion_duration = time.perf_counter() - start_time

    accepted = sum(row["api_status"] == "accepted" for row in rows)
    duplicates = sum(row["api_status"] == "duplicate" for row in rows)
    failures = TOTAL_ALERTS - accepted - duplicates

    summary = {
        "run_id": RUN_ID,
        "target_alerts": TOTAL_ALERTS,
        "accepted": accepted,
        "duplicates": duplicates,
        "failures": failures,
        "ingestion_duration_seconds": round(ingestion_duration, 3),
        "ingestion_throughput_alerts_per_second": round(
            accepted / ingestion_duration, 3
        ),
        "latency_seconds": {
            "mean": round(statistics.mean(latencies), 4) if latencies else None,
            "median": round(statistics.median(latencies), 4) if latencies else None,
            "p95": round(percentile(latencies, 0.95), 4) if latencies else None,
            "max": round(max(latencies), 4) if latencies else None
        }
    }

    with CSV_PATH.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    JSON_PATH.write_text(json.dumps(summary, indent=2))

    print("\n========== INGESTION BENCHMARK SUMMARY ==========")
    print(json.dumps(summary, indent=2))
    print(f"\nCSV results: {CSV_PATH}")
    print(f"JSON summary: {JSON_PATH}")


if __name__ == "__main__":
    main()
