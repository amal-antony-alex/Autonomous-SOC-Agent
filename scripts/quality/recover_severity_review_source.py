import csv
import json
from pathlib import Path

root = Path.cwd()
source = root / (
    "data/raw/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1.jsonl"
)
destination = root / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_severity_human_review_recovered.csv"
)

if not source.is_file():
    raise FileNotFoundError(source)

if destination.exists():
    raise FileExistsError(
        f"Recovery file already exists; not overwriting: {destination}"
    )

records = []
with source.open("r", encoding="utf-8") as f:
    for line_no, line in enumerate(f, 1):
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("category") == "severity_classification":
            records.append(record)

if len(records) != 500:
    raise ValueError(f"Expected 500 severity records; found {len(records)}")

fields = [
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

def serialize(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)

with destination.open("w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        row = {field: serialize(record.get(field)) for field in fields}
        row["behavior_supported"] = ""
        row["review_notes"] = ""
        row["reviewer_decision"] = "PENDING"
        row["reviewer_notes"] = ""
        writer.writerow(row)

with destination.open("r", encoding="utf-8-sig", newline="") as f:
    recovered = list(csv.DictReader(f))

for field in ["scenario_id", "category", "input", "output"]:
    populated = sum(bool(row.get(field, "").strip()) for row in recovered)
    print(f"{field}: {populated}/{len(recovered)} populated")

if len(recovered) != 500:
    raise RuntimeError("Recovered row count verification failed")

print(f"\nRecovered worksheet: {destination}")
print("Original JSONL dataset was not modified.")
print("All recovered records remain pending review.")
