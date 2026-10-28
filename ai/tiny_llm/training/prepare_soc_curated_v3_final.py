
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path

ROOT = Path("data")
OUT = ROOT / "processed" / "soc_curated_v3" / "final"

MITRE_SOURCE = ROOT / "processed/mitre_attack/mitre_instruction_dataset_v2.jsonl"
SOC_PILOT = ROOT / "raw/soc_curated_v3/soc_pilot_400.jsonl"
SOC_TEST = ROOT / "raw/soc_curated_v3/soc_source_mitre_reviewed_v1.jsonl"
TECHNIQUES = ROOT / "processed/mitre_attack/mitre_techniques.jsonl"

SEED = 20261017
VALID_CATEGORIES = {
    "alert_analysis",
    "log_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "severity_classification",
    "mitre_mapping",
    "incident_summary",
    "uncertainty_analysis",
    "mitre_lookup",
    "mitre_platform",
    "mitre_tactic",
    "mitre_explanation",
}

def read_jsonl(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

def fingerprint(row):
    parts = [
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]
    normalized = "\n".join(
        re.sub(r"\s+", " ", part).strip().casefold()
        for part in parts
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

def input_fingerprint(row):
    normalized = "\n".join(
        re.sub(r"\s+", " ", row.get(field, "")).strip().casefold()
        for field in ("instruction", "input")
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

def valid_example(row):
    return all(
        isinstance(row.get(field), str) and row[field].strip()
        for field in ("instruction", "input", "output")
    )

def technique_group(row):
    # Keep examples for the same MITRE technique in the same split.
    tid = row.get("technique_id")
    if tid:
        return str(tid).upper()

    text = " ".join(
        str(row.get(field, ""))
        for field in ("instruction", "input", "output")
    ).upper()
    match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", text)
    if match:
        return match.group(0)

    # Avoid dropping a record solely because its technique metadata is absent.
    return "UNASSIGNED-" + fingerprint(row)

def split_groups(rows, seed=SEED):
    grouped = {}
    for row in rows:
        grouped.setdefault(technique_group(row), []).append(row)

    groups = list(grouped.items())
    random.Random(seed).shuffle(groups)

    total = len(rows)
    train_target = int(total * 0.80)
    val_target = int(total * 0.90)

    train, val, test = [], [], []
    for _, group_rows in groups:
        if len(train) < train_target:
            train.extend(group_rows)
        elif len(val) < val_target - train_target:
            val.extend(group_rows)
        else:
            test.extend(group_rows)

    return train, val, test, {
        "total_groups": len(groups),
        "train_groups": len({technique_group(r) for r in train}),
        "validation_groups": len({technique_group(r) for r in val}),
        "test_groups": len({technique_group(r) for r in test}),
    }

def main():
    OUT.mkdir(parents=True, exist_ok=True)

    mitre_raw = read_jsonl(MITRE_SOURCE)
    pilot_raw = read_jsonl(SOC_PILOT)
    soc_test_raw = read_jsonl(SOC_TEST)

    # Load the local MITRE catalogue for ID/name validation.
    technique_names = {
        row["technique_id"].upper(): row["name"]
        for row in read_jsonl(TECHNIQUES)
        if row.get("technique_id") and row.get("name")
    }

    # Prepare and deduplicate the MITRE instruction dataset.
    mitre_rows, seen = [], set()
    rejected = Counter()
    mitre_issues = []

    for original in mitre_raw:
        row = dict(original)
        row.setdefault("source", "mitre_instruction_dataset_v2")

        if not valid_example(row):
            rejected["mitre_incomplete"] += 1
            continue

        category = row.get("category", "")
        if category not in VALID_CATEGORIES:
            rejected["mitre_invalid_category"] += 1
            continue

        key = fingerprint(row)
        if key in seen:
            rejected["mitre_duplicate"] += 1
            continue
        seen.add(key)

        tid = row.get("technique_id")
        if tid and tid.upper() in technique_names:
            row["technique_name"] = technique_names[tid.upper()]
        elif tid:
            mitre_issues.append({
                "technique_id": tid,
                "input": row.get("input", "")[:160],
                "issue": "ID not found in local technique catalogue",
            })

        row["source"] = "mitre_instruction_dataset_v2"
        row["split_group"] = technique_group(row)
        mitre_rows.append(row)

    train_mitre, val_mitre, test_mitre, split_report = split_groups(mitre_rows)

    # Keep one SOC pilot example per category and scenario family.
    # The pilot has repeated answers, so all 400 are not independent examples.
    pilot_selected = []
    pilot_seen_families = set()
    pilot_seen_fingerprints = set()
    pilot_test_inputs = {
        input_fingerprint(row)
        for row in soc_test_raw
        if valid_example(row)
    }

    for original in pilot_raw:
        row = dict(original)
        category = row.get("category")
        family = row.get("scenario_family")

        if not valid_example(row):
            rejected["pilot_incomplete"] += 1
            continue

        if category not in VALID_CATEGORIES:
            rejected["pilot_invalid_category"] += 1
            continue

        if not family:
            rejected["pilot_missing_family"] += 1
            continue

        # Never train on an exact prompt that is in the SOC evaluation set.
        if input_fingerprint(row) in pilot_test_inputs:
            rejected["pilot_test_prompt_overlap"] += 1
            continue

        family_key = (category, family)
        if family_key in pilot_seen_families:
            rejected["pilot_repeated_family"] += 1
            continue

        key = fingerprint(row)
        if key in pilot_seen_fingerprints:
            rejected["pilot_duplicate"] += 1
            continue

        pilot_seen_families.add(family_key)
        pilot_seen_fingerprints.add(key)
        row["source"] = "curated_soc_v3_pilot"
        row["split_group"] = f"SOC:{category}:{family}"
        row["review_status"] = "SYNTHETIC_CANDIDATE_NOT_FACTUALLY_CERTIFIED"
        pilot_selected.append(row)

    # SOC evaluation set: keep separate from training.
    # Labels/answers are still provisional and require future quality review.
    soc_test, soc_test_seen = [], set()
    for original in soc_test_raw:
        row = dict(original)

        if not valid_example(row):
            rejected["soc_test_incomplete"] += 1
            continue

        key = fingerprint(row)
        if key in soc_test_seen:
            rejected["soc_test_duplicate"] += 1
            continue

        soc_test_seen.add(key)
        row["source"] = "existing_soc_source"
        row["review_status"] = "PROVISIONAL_SOC_EVALUATION"
        soc_test.append(row)

    # Remove exact duplicate triples across training sources.
    train = []
    train_seen = set()
    for row in train_mitre + pilot_selected:
        key = fingerprint(row)
        if key in train_seen:
            rejected["cross_source_train_duplicate"] += 1
            continue
        train_seen.add(key)
        train.append(row)

    # Ensure SOC test has no exact input overlap with training.
    train_inputs = {input_fingerprint(row) for row in train}
    soc_test_filtered = []
    for row in soc_test:
        if input_fingerprint(row) in train_inputs:
            rejected["soc_test_train_prompt_overlap"] += 1
            continue
        soc_test_filtered.append(row)

    write_jsonl(OUT / "train.jsonl", train)
    write_jsonl(OUT / "val_mitre.jsonl", val_mitre)
    write_jsonl(OUT / "test_mitre.jsonl", test_mitre)
    write_jsonl(OUT / "test_soc.jsonl", soc_test_filtered)

    def category_counts(rows):
        return dict(sorted(Counter(
            row.get("category", "unknown") for row in rows
        ).items()))

    report = {
        "status": "PREPARED_REQUIRES_QUALITY_REVIEW_BEFORE_TRAINING",
        "seed": SEED,
        "input_counts": {
            "mitre_instruction_dataset_v2": len(mitre_raw),
            "soc_pilot": len(pilot_raw),
            "soc_source_evaluation_candidates": len(soc_test_raw),
        },
        "output_counts": {
            "train": len(train),
            "validation_mitre": len(val_mitre),
            "test_mitre": len(test_mitre),
            "test_soc": len(soc_test_filtered),
        },
        "category_counts": {
            "train": category_counts(train),
            "validation_mitre": category_counts(val_mitre),
            "test_mitre": category_counts(test_mitre),
            "test_soc": category_counts(soc_test_filtered),
        },
        "mitre_group_split": split_report,
        "rejected_or_filtered": dict(rejected),
        "mitre_ids_needing_review": mitre_issues,
        "warnings": [
            "MITRE train/validation/test groups are separated by technique ID.",
            "SOC pilot contributes at most one example per category/family.",
            "SOC evaluation answers are provisional, not fully verified ground truth.",
            "Exact prompt matching does not detect semantic or near-duplicate leakage.",
            "Review generated SOC examples before treating them as trusted labels.",
            "The existing v2.2 checkpoint and source datasets were not modified.",
        ],
    }

    (OUT / "preparation_report.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print(f"\nOutput directory: {OUT}")

if __name__ == "__main__":
    main()
