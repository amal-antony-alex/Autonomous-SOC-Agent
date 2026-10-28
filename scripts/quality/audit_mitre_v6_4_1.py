
import json
from pathlib import Path

DATASET = Path(
    "data/raw/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1.jsonl"
)
OUT = Path(
    "data/raw/soc_curated_v3/"
    "v6_4_1_mitre_review_samples.jsonl"
)

def main():
    rows = []
    with DATASET.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("category") == "mitre_mapping":
                rows.append((line_no, record))

    if len(rows) != 500:
        raise SystemExit(
            f"Expected 500 MITRE records; found {len(rows)}"
        )

    print("MITRE records:", len(rows))
    print("\nAvailable fields:")
    print(json.dumps(sorted(rows[0][1].keys()), indent=2))

    print("\nFirst 10 records:")
    for line_no, record in rows[:10]:
        print(f"\n--- Dataset line {line_no} ---")
        print(json.dumps(record, indent=2, ensure_ascii=False))

    with OUT.open("w", encoding="utf-8") as f:
        for line_no, record in rows:
            f.write(json.dumps({
                "dataset_line": line_no,
                "record": record,
                "behavior_supported": None,
                "review_status": "PENDING_HUMAN_REVIEW",
                "review_notes": ""
            }, ensure_ascii=False) + "\n")

    print("\nReview file saved to:", OUT)
    print("No dataset records were modified.")

if __name__ == "__main__":
    main()
