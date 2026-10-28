import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("data/raw/soc_curated_v3")
INPUT = ROOT / "soc_pilot_400.jsonl"
REPORT = ROOT / "soc_pilot_400_quality_audit.json"

rows = [json.loads(line) for line in INPUT.read_text(encoding="utf-8").splitlines()
        if line.strip()]

categories = Counter()
families = defaultdict(Counter)
answers = defaultdict(Counter)
normalized_inputs = Counter()
normalized_pairs = Counter()

for row in rows:
    category = row.get("category", "UNKNOWN")
    family = row.get("scenario_family", "UNKNOWN")
    output = " ".join(row.get("output", "").lower().split())
    input_text = " ".join(row.get("input", "").lower().split())

    categories[category] += 1
    families[category][family] += 1
    answers[category][output] += 1
    normalized_inputs[(category, input_text)] += 1
    normalized_pairs[(category, family, output)] += 1

report = {
    "total_rows": len(rows),
    "category_counts": dict(categories),
    "unique_families_by_category": {
        category: len(counts) for category, counts in families.items()
    },
    "unique_answers_by_category": {
        category: len(counts) for category, counts in answers.items()
    },
    "most_repeated_answers_by_category": {
        category: [
            {"count": count, "answer": answer[:220]}
            for answer, count in counts.most_common(5)
        ]
        for category, counts in answers.items()
    },
    "repeated_normalized_inputs": sum(
        count > 1 for count in normalized_inputs.values()
    ),
    "repeated_family_answer_pairs": sum(
        count > 1 for count in normalized_pairs.values()
    ),
    "status": "AUDIT_ONLY_NOT_A_FACTUAL_QUALITY_CERTIFICATION",
}

REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
print(f"\nReport saved to: {REPORT}")
