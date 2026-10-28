import json
from pathlib import Path
from collections import Counter

SOURCE = Path("data/raw/soc_curated_v3/soc_training_candidates_4000.jsonl")
OUTPUT = Path("data/raw/soc_curated_v3/soc_training_candidates_4000_v2.jsonl")
REPORT = Path("data/raw/soc_curated_v3/soc_training_candidates_4000_v2_audit.json")

REQUIRED = {
    "instruction", "input", "output", "category",
    "source", "scenario_family", "scenario_id",
    "verification_status", "metadata",
}
CATEGORIES = {
    "alert_analysis", "alert_correlation", "false_positive_assessment",
    "incident_summary", "ioc_analysis", "log_analysis",
    "mitre_mapping", "severity_classification", "uncertainty_analysis",
}

def main():
    if not SOURCE.exists():
        raise FileNotFoundError(SOURCE)

    rows = []
    with SOURCE.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not REQUIRED.issubset(row):
                raise ValueError(f"Line {line_no}: missing schema fields")
            if row["category"] not in CATEGORIES:
                raise ValueError(f"Line {line_no}: unknown category")
            rows.append(row)

    if len(rows) != 4000:
        raise ValueError(f"Expected 4000 records, found {len(rows)}")

    # Preserve original records and make no unverified factual corrections.
    # Instead, identify defects for targeted regeneration and human review.
    bad_context = []
    for i, row in enumerate(rows, 1):
        text = row["input"].lower()
        if any(x in text for x in (
            "context= .", "context=t.", "context= .;", "context=;"
        )):
            bad_context.append(i)

    per_category = {}
    for category in sorted(CATEGORIES):
        subset = [r for r in rows if r["category"] == category]
        output_counts = Counter(r["output"] for r in subset)
        per_category[category] = {
            "records": len(subset),
            "unique_outputs": len(output_counts),
            "most_common_output_count": (
                output_counts.most_common(1)[0][1] if output_counts else 0
            ),
        }

    triples = [(r["instruction"], r["input"], r["output"]) for r in rows]
    report = {
        "record_count": len(rows),
        "schema_compatible": True,
        "malformed_context_record_numbers": bad_context,
        "malformed_context_count": len(bad_context),
        "categories": per_category,
        "exact_duplicate_triples": len(triples) - len(set(triples)),
        "verification_status": "NOT_FACTUALLY_VERIFIED",
        "note": (
            "This audit copy preserves the original records. It does not repair "
            "their content or claim improved diversity. Records with malformed "
            "contexts and repetitive outputs require regeneration and human review."
        ),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("Created audit copy:", OUTPUT)
    print("Created report:", REPORT)
    print("Records:", len(rows))
    print("Malformed context candidates:", len(bad_context))
    print("Exact duplicate triples:", report["exact_duplicate_triples"])
    print("Factual verification: NOT VERIFIED")
    print("No source records were modified.")

if __name__ == "__main__":
    main()
