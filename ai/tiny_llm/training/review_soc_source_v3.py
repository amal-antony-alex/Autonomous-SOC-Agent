
import json
from collections import Counter
from pathlib import Path

SOURCE = Path("data/raw/soc_curated_v3/soc_source_labeled_v1.jsonl")
OUTPUT = Path("data/raw/soc_curated_v3/soc_source_reviewed_candidate_v1.jsonl")
REPORT = Path("data/raw/soc_curated_v3/soc_source_reviewed_candidate_v1_report.json")

CORRECTIONS = {
    "SOC-SRC-005": ("alert_correlation", "Explicit correlation task"),
    "SOC-SRC-017": ("ioc_analysis", "Extracts observable security indicators"),
    "SOC-SRC-029": ("alert_analysis", "Assesses a suspicious outbound connection"),
    "SOC-SRC-031": ("ioc_analysis", "Extracts network indicators"),
    "SOC-SRC-048": ("ioc_analysis", "Extracts observable security indicators"),
    "SOC-SRC-095": ("incident_summary", "Requests a malware-event summary"),
    "SOC-SRC-097": ("incident_summary", "Requests a privilege-event summary"),
    "SOC-SRC-099": ("incident_summary", "Explicitly requests a summary"),
    "SOC-SRC-101": ("incident_summary", "Requests an evidence-grounded event summary"),
    "SOC-SRC-105": ("incident_summary", "Requests a sequence summary"),
    "SOC-SRC-107": ("incident_summary", "Requests a summary of IOC enrichment findings"),
}

def main():
    if not SOURCE.exists():
        raise FileNotFoundError(f"Missing input: {SOURCE}")

    with SOURCE.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    seen_ids = set()
    counts = Counter()
    applied = []

    for row in rows:
        record_id = row.get("source_record_id")

        if not record_id or record_id in seen_ids:
            raise ValueError(f"Missing or duplicate record ID: {record_id}")
        seen_ids.add(record_id)

        if record_id in CORRECTIONS:
            new_category, reason = CORRECTIONS[record_id]
            old_category = row["category"]

            row["category"] = new_category
            row["review_status"] = "PROVISIONAL_HUMAN_REVIEWED_LABEL"
            row["label_review_note"] = reason

            applied.append({
                "record_id": record_id,
                "old_category": old_category,
                "new_category": new_category,
                "reason": reason,
            })
        else:
            row["review_status"] = "REQUIRES_MANUAL_REVIEW"

        counts[row["category"]] += 1

    with OUTPUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    report = {
        "input_records": len(rows),
        "output_records": len(rows),
        "corrections_applied": len(applied),
        "category_counts": dict(sorted(counts.items())),
        "corrections": applied,
        "status": "REVIEWED_CANDIDATE_NOT_TRAINING_APPROVED",
        "notes": [
            "Original source and provisional labeled copy were not modified.",
            "Applied labels are task-label proposals, not verified answer correctness.",
            "Unchanged records remain pending review.",
            "Scenario families and answer quality still require review.",
            "No model training was performed.",
        ],
    }

    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nReviewed candidate: {OUTPUT}")
    print(f"Report: {REPORT}")

if __name__ == "__main__":
    main()
