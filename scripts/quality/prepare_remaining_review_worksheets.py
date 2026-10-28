import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1.jsonl"
)

OUTPUT_DIR = ROOT / "data/raw/soc_curated_v3"

CATEGORIES = [
    "alert_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "incident_summary",
    "uncertainty_analysis",
]

FIELDS = [
    "scenario_id",
    "category",
    "scenario_family",
    "instruction",
    "input",
    "output",
    "source",
    "generator_version",
    "verification_status",
    "behavior_supported",
    "review_notes",
    "reviewer_decision",
    "reviewer_notes",
]

def cell(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)

if not SOURCE.is_file():
    raise FileNotFoundError(
        f"Dataset not found: {SOURCE}\n"
        "Check the project directory and filename."
    )

records = []

with SOURCE.open("r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON on line {line_number}: {exc}"
            ) from exc

        if not isinstance(record, dict):
            raise ValueError(
                f"Line {line_number} is not a JSON object."
            )

        records.append(record)

counts = Counter(record.get("category") for record in records)

print(f"Source records loaded: {len(records)}")
print("\nCategory counts in source:")

for category in CATEGORIES:
    print(f"  {category}: {counts.get(category, 0)}")

if len(records) != 4000:
    raise ValueError(
        f"Expected 4000 source records, found {len(records)}. "
        "Stopping without generating worksheets."
    )

for category in CATEGORIES:
    category_records = [
        record for record in records
        if record.get("category") == category
    ]

    if len(category_records) != 500:
        raise ValueError(
            f"{category}: expected 500 records, "
            f"found {len(category_records)}. "
            "Stopping before generating worksheets."
        )

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

created = []

for category in CATEGORIES:
    category_records = [
        record for record in records
        if record.get("category") == category
    ]

    destination = OUTPUT_DIR / (
        f"v6_4_1_{category}_human_review.csv"
    )

    with destination.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()

        for record in category_records:
            row = {
                field: cell(record.get(field))
                for field in FIELDS
            }

            # These are reviewer fields, not AI-validated labels.
            row["behavior_supported"] = ""
            row["review_notes"] = ""
            row["reviewer_decision"] = ""
            row["reviewer_notes"] = ""

            writer.writerow(row)

    # Reopen each CSV to verify the exported row count.
    with destination.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        exported_count = sum(1 for _ in csv.DictReader(file))

    if exported_count != 500:
        raise RuntimeError(
            f"Verification failed for {destination.name}: "
            f"found {exported_count} rows."
        )

    created.append(destination)
    print(f"VERIFIED: {destination.name} — {exported_count} rows")

print(f"\nSUCCESS: {len(created)} worksheets generated.")
print("Total review rows:", sum(500 for _ in created))
print("Original JSONL dataset was not modified.")
