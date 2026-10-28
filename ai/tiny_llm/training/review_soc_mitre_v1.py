
import json
from pathlib import Path

SOURCE = Path(
    "data/raw/soc_curated_v3/soc_source_reviewed_candidate_v1.jsonl"
)
OUTPUT = Path(
    "data/raw/soc_curated_v3/soc_source_mitre_reviewed_v1.jsonl"
)
REPORT = Path(
    "data/raw/soc_curated_v3/soc_source_mitre_reviewed_v1_report.json"
)

def main():
    with SOURCE.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    updated = 0
    statuses = {}

    for row in rows:
        if row.get("category") != "mitre_mapping":
            continue

        record_id = row.get("source_record_id")
        output = row.get("output", "")

        if record_id == "SOC-SRC-081":
            output = output.replace(
                "T1046 Network Service Scanning",
                "T1046 Network Service Discovery",
            )
            row["output"] = output
            row["mitre_review_status"] = "NAME_CORRECTED_BEHAVIOR_REVIEW_PENDING"
            updated += 1

        elif record_id in {"SOC-SRC-082", "SOC-SRC-089", "SOC-SRC-090"}:
            row["mitre_review_status"] = "INSUFFICIENT_EVIDENCE_RESPONSE_RETAINED"

        else:
            row["mitre_review_status"] = "ID_NAME_MATCH_BEHAVIOR_REVIEW_PENDING"

        statuses[row["mitre_review_status"]] = (
            statuses.get(row["mitre_review_status"], 0) + 1
        )

    with OUTPUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    report = {
        "input_records": len(rows),
        "output_records": len(rows),
        "mitre_name_corrections": updated,
        "mitre_review_status_counts": statuses,
        "status": "MITRE_CANDIDATE_NOT_FULLY_VERIFIED",
        "notes": [
            "Original candidate was not modified.",
            "Only the T1046 technique name was corrected.",
            "Behavioral validity of the other mappings remains unverified.",
            "No model training was performed.",
        ],
    }

    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nOutput: {OUTPUT}")

if __name__ == "__main__":
    main()
