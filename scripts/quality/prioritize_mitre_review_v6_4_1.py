
import json
from collections import defaultdict
from pathlib import Path

DATASET = Path(
    "data/raw/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1.jsonl"
)
OUTPUT = Path(
    "data/raw/soc_curated_v3/"
    "v6_4_1_mitre_review_queue.jsonl"
)

PRIORITY = {
    "T1021.002": 1,
    "T1055": 2,
    "T1003.001": 3,
    "T1021.004": 4,
    "T1059.003": 4,
}

def main():
    groups = defaultdict(list)

    with DATASET.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("category") != "mitre_mapping":
                continue

            meta = row.get("metadata", {})
            tid = meta.get("candidate_technique_id", "MISSING")

            groups[tid].append({
                "dataset_line": line_no,
                "scenario_id": row.get("scenario_id"),
                "technique_id": tid,
                "technique_name": meta.get(
                    "candidate_technique_name", "MISSING"
                ),
                "input": row.get("input", ""),
                "output": row.get("output", ""),
                "review_priority": PRIORITY.get(tid, 5),
                "review_status": "PENDING_HUMAN_REVIEW",
                "behavior_supported": None,
                "review_notes": "",
            })

    total = sum(len(rows) for rows in groups.values())
    if total != 500:
        raise SystemExit(f"Expected 500 records, found {total}")

    with OUTPUT.open("w", encoding="utf-8") as f:
        for tid in sorted(
            groups,
            key=lambda x: (PRIORITY.get(x, 5), x)
        ):
            for item in groups[tid]:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print("Records queued:", total)
    print("Technique families:", len(groups))
    print("Review queue:", OUTPUT)
    print("Priority 1 = highest review priority.")
    print("No source dataset records were modified.")

if __name__ == "__main__":
    main()
