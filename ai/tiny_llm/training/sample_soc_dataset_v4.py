import json
import random
from collections import defaultdict
from pathlib import Path

DATASET = Path(
    "data/raw/soc_curated_v3/soc_training_v4_revision_v4.jsonl"
)
OUTPUT = Path(
    "data/raw/soc_curated_v3/soc_training_v4_revision_v4_manual_sample.json"
)

SAMPLES_PER_CATEGORY = 4
SEED = 20261022

if not DATASET.exists():
    raise FileNotFoundError(f"Dataset not found: {DATASET}")

categories = defaultdict(list)

with DATASET.open("r", encoding="utf-8") as f:
    for line_number, line in enumerate(f, start=1):
        if not line.strip():
            continue

        record = json.loads(line)
        record["_source_line"] = line_number
        categories[record.get("category", "UNKNOWN")].append(record)

expected_categories = {
    "alert_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "severity_classification",
    "mitre_mapping",
    "incident_summary",
    "uncertainty_analysis",
}

if set(categories) != expected_categories:
    raise ValueError(
        f"Unexpected categories: {sorted(categories)}"
    )

rng = random.Random(SEED)
sample = []

for category in sorted(categories):
    records = categories[category]

    if len(records) < SAMPLES_PER_CATEGORY:
        raise ValueError(
            f"{category} has only {len(records)} records"
        )

    chosen = rng.sample(records, SAMPLES_PER_CATEGORY)
    sample.extend(chosen)

OUTPUT.write_text(
    json.dumps(sample, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)

print(f"Dataset records loaded: {sum(map(len, categories.values()))}")
print(f"Categories sampled: {len(categories)}")
print(f"Samples per category: {SAMPLES_PER_CATEGORY}")
print(f"Total sample records: {len(sample)}")
print(f"Saved to: {OUTPUT}")
print("\nSample counts:")
for category in sorted(categories):
    print(
        f"  {category}: "
        f"{sum(r['category'] == category for r in sample)}"
    )
