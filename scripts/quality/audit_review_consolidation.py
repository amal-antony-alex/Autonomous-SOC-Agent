import csv
import json
from pathlib import Path
from collections import Counter

ROOT = Path.cwd()
SOURCE = ROOT / "data/raw/soc_curated_v3/soc_training_v4_revision_v6_4_1.jsonl"
CSV_DIR = ROOT / "data/reviewed_v6_4_1/reviewed_csvs"
REPORT_DIR = ROOT / "data/reviewed_v6_4_1/reports"

FILES = {
    "combined_decisions": CSV_DIR / "v6_4_1_all_record_ai_review_decisions.csv",
    "corrections": CSV_DIR / "v6_4_1_corrections_required.csv",
    "remaining_pending": CSV_DIR / "v6_4_1_records_remaining_pending.csv",
    "severity_assessed": CSV_DIR / "v6_4_1_severity_ai_assessed.csv",
    "severity_pending": CSV_DIR / "v6_4_1_severity_pending_followup.csv",
}

def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader), reader.fieldnames or []

def get_value(row, names):
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""

def get_ids(rows):
    return [
        get_value(row, ["scenario_id", "id", "record_id", "sample_id"])
        for row in rows
    ]

print("=== READ-ONLY CONSOLIDATION AUDIT ===")
print("Project root:", ROOT)

missing = [str(p) for p in [SOURCE, *FILES.values()] if not p.is_file()]
if missing:
    print("\nSTOP — required files missing:")
    for path in missing:
        print("  ", path)
    print("\nNo files were modified. Check that you are in the project root.")
    raise SystemExit(1)

# Load and validate the original dataset.
source_rows = []
errors = []

with SOURCE.open(encoding="utf-8") as f:
    for line_no, line in enumerate(f, 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                errors.append((line_no, "Not a JSON object"))
            else:
                source_rows.append(obj)
        except json.JSONDecodeError as exc:
            errors.append((line_no, str(exc)))

source_ids = get_ids(source_rows)
source_counts = Counter(source_ids)
source_set = {x for x in source_ids if x}

print("\n[1] ORIGINAL DATASET")
print("Records:", len(source_rows))
print("Unique nonblank IDs:", len(source_set))
print("Blank IDs:", sum(not x for x in source_ids))
print("Duplicate IDs:", sum(n - 1 for k, n in source_counts.items() if k and n > 1))
print("JSONL errors:", len(errors))
if errors:
    print("First errors:", errors[:5])

source_categories = Counter(
    get_value(row, ["category", "task_category"]) for row in source_rows
)
source_categories.pop("", None)
print("Category counts:", dict(source_categories))

loaded = {}

print("\n[2] REVIEW FILES")
for label, path in FILES.items():
    rows, columns = read_csv(path)
    loaded[label] = rows
    row_ids = get_ids(rows)
    nonblank = [x for x in row_ids if x]
    counts = Counter(nonblank)

    print(f"\n{label}: {len(rows)} rows")
    print("Columns:", columns)
    print("IDs populated:", len(nonblank), "/", len(rows))
    print("Unique IDs:", len(set(nonblank)))
    print("Duplicate IDs:", sum(n - 1 for n in counts.values() if n > 1))

    if source_set:
        review_set = set(nonblank)
        print("IDs matching source:", len(review_set & source_set))
        print("IDs absent from source:", len(review_set - source_set))
        print("Source IDs not in this file:", len(source_set - review_set))

    decision_col = next(
        (c for c in ["reviewer_decision", "decision", "ai_decision", "review_decision"]
         if c in columns),
        None,
    )
    if decision_col:
        print("Decision counts:", dict(Counter(
            (row.get(decision_col) or "").strip() or "(blank)"
            for row in rows
        )))

    category_col = next(
        (c for c in ["category", "task_category"] if c in columns), None
    )
    if category_col:
        print("Category counts:", dict(Counter(
            (row.get(category_col) or "").strip() or "(blank)"
            for row in rows
        )))

print("\n[3] CROSS-FILE CHECKS")
combined_ids = set(get_ids(loaded["combined_decisions"])) - {""}
severity_ids = set(get_ids(loaded["severity_assessed"])) - {""}
pending_ids = set(get_ids(loaded["severity_pending"])) - {""}

print("Combined decision rows:", len(loaded["combined_decisions"]))
print("Combined unique IDs:", len(combined_ids))
print("Severity assessed unique IDs:", len(severity_ids))
print("Severity pending unique IDs:", len(pending_ids))
print("Pending IDs all in severity assessment:", pending_ids <= severity_ids)
print("Severity IDs found in combined decisions:",
      len(severity_ids & combined_ids), "/", len(severity_ids))
print("Severity IDs missing from combined decisions:",
      len(severity_ids - combined_ids))

summary = REPORT_DIR / "v6_4_1_ai_review_summary.json"
if summary.is_file():
    try:
        with summary.open(encoding="utf-8") as f:
            report = json.load(f)
        print("\nExisting overall summary JSON: valid")
        print("Summary keys:", list(report.keys()))
    except Exception as exc:
        print("\nExisting overall summary JSON: INVALID:", exc)
else:
    print("\nExisting overall summary JSON: missing")

print("\n[4] SOURCE FILE METADATA")
print("Original JSONL size:", SOURCE.stat().st_size, "bytes")
print("Original JSONL modification time:", SOURCE.stat().st_mtime)

print("\nAUDIT COMPLETE — READ ONLY. No files were changed.")
