import csv
import json
from pathlib import Path

ROOT = Path.cwd()
BASE = ROOT / "data/raw/soc_curated_v3"
REPORT = BASE / "v6_4_1_review_inventory_audit.json"

expected = []

# Six remaining categories
categories = [
    "alert_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "incident_summary",
    "uncertainty_analysis",
]

for category in categories:
    expected.extend([
        (f"v6_4_1_{category}_human_review.csv", 500, "worksheet"),
        (f"v6_4_1_{category}_review_suggestions.csv", 500, "suggestions"),
    ])

# Severity
expected.extend([
    ("v6_4_1_severity_human_review.csv", 500, "worksheet"),
    ("v6_4_1_severity_review_suggestions.csv", 500, "suggestions"),
])

# MITRE priority review files
mitre_counts = {
    1: 41,
    2: 41,
    3: 41,
    4: 84,
    5: 293,
}

for priority, count in mitre_counts.items():
    expected.extend([
        (
            f"v6_4_1_mitre_priority{priority}_human_review.csv",
            count,
            "worksheet",
        ),
        (
            f"v6_4_1_mitre_priority{priority}_review_suggestions.csv",
            count,
            "suggestions",
        ),
    ])

results = []
missing = []
mismatches = []

for filename, expected_rows, kind in expected:
    path = BASE / filename
    result = {
        "file": filename,
        "kind": kind,
        "expected_rows": expected_rows,
        "exists": path.is_file(),
        "actual_rows": None,
        "status": "MISSING",
    }

    if path.is_file():
        try:
            with path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as f:
                rows = sum(1 for _ in csv.DictReader(f))

            result["actual_rows"] = rows
            result["status"] = (
                "ROW_COUNT_OK" if rows == expected_rows
                else "ROW_COUNT_MISMATCH"
            )

            if rows != expected_rows:
                mismatches.append(filename)

        except Exception as exc:
            result["status"] = "READ_ERROR"
            result["error"] = str(exc)
            mismatches.append(filename)
    else:
        missing.append(filename)

    results.append(result)

# Validate the immutable source candidate's basic record count/categories.
source_path = BASE / "soc_training_v4_revision_v6_4_1.jsonl"
source_summary = {
    "file": source_path.name,
    "exists": source_path.is_file(),
    "rows": None,
    "category_counts": {},
    "status": "MISSING",
}

if source_path.is_file():
    counts = {}
    total = 0

    with source_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            total += 1
            category = record.get("category", "MISSING_CATEGORY")
            counts[category] = counts.get(category, 0) + 1

    source_summary["rows"] = total
    source_summary["category_counts"] = counts
    source_summary["status"] = (
        "SOURCE_COUNTS_OK"
        if total == 4000 and all(
            counts.get(category, 0) == 500
            for category in [
                "alert_analysis",
                "ioc_analysis",
                "alert_correlation",
                "false_positive_assessment",
                "severity_classification",
                "mitre_mapping",
                "incident_summary",
                "uncertainty_analysis",
            ]
        )
        else "SOURCE_COUNTS_MISMATCH"
    )

report = {
    "audit_type": "REVIEW_ARTIFACT_INVENTORY_ONLY",
    "human_review_completed": False,
    "expected_review_files": len(expected),
    "files_with_correct_row_counts": sum(
        item["status"] == "ROW_COUNT_OK" for item in results
    ),
    "missing_files": missing,
    "row_count_or_read_errors": mismatches,
    "source_dataset": source_summary,
    "files": results,
    "warning": (
        "File presence and row counts do not establish semantic correctness "
        "or completion of human review."
    ),
}

BASE.mkdir(parents=True, exist_ok=True)
REPORT.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)

print(f"Expected review files: {len(expected)}")
print(f"Correct row counts: {report['files_with_correct_row_counts']}")
print(f"Missing files: {len(missing)}")
print(f"Row-count/read errors: {len(mismatches)}")
print(f"Source dataset status: {source_summary['status']}")
print(f"Audit report: {REPORT}")

if missing:
    print("\nMISSING FILES:")
    for filename in missing:
        print(" -", filename)

if mismatches:
    print("\nFILES NEEDING ATTENTION:")
    for filename in mismatches:
        print(" -", filename)

print("\nHuman review remains pending.")
