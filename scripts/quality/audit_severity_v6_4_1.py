
import json
from collections import Counter
from pathlib import Path

DATASET = Path(
    "data/raw/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1.jsonl"
)

TARGET_CATEGORY = "severity_classification"

def main():
    records = []

    with DATASET.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"Invalid JSON on line {line_number}: {exc}"
                )
            if record.get("category") == TARGET_CATEGORY:
                records.append((line_number, record))

    print(f"Dataset: {DATASET}")
    print(f"Severity records: {len(records)}")

    if len(records) != 500:
        raise SystemExit(
            "Expected 500 severity records; investigate before continuing."
        )

    print("\nAvailable fields:")
    if records:
        print(json.dumps(
            sorted(records[0][1].keys()), indent=2
        ))

    print("\nSample records (first 5):")
    for line_number, record in records[:5]:
        print(f"\n--- Dataset line {line_number} ---")
        print(json.dumps(record, indent=2, ensure_ascii=False))

    output = Path(
        "data/raw/soc_curated_v3/"
        "v6_4_1_severity_review_samples.jsonl"
    )
    with output.open("w", encoding="utf-8") as f:
        for line_number, record in records:
            f.write(json.dumps({
                "dataset_line": line_number,
                "record": record,
                "review_status": "PENDING_HUMAN_REVIEW",
                "review_notes": ""
            }, ensure_ascii=False) + "\n")

    print(f"\nReview sample saved to: {output}")
    print("No dataset records were modified.")

if __name__ == "__main__":
    main()
