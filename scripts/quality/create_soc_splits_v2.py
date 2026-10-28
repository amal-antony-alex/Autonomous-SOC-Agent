import hashlib
import itertools
import json
import random
from collections import Counter, defaultdict
from pathlib import Path


SOURCE = Path(
    "data/processed/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1_training_candidate.jsonl"
)

OUTPUT_DIR = Path(
    "data/processed/soc_curated_v3/sft_splits_v2"
)

SEED = 20261024
RATIOS = {"train": 0.80, "validation": 0.10, "test": 0.10}
SPLITS = ("train", "validation", "test")

REQUIRED_FIELDS = {
    "scenario_id",
    "scenario_family",
    "category",
    "instruction",
    "input",
    "output",
}

OUTPUT_FILES = {
    "train": OUTPUT_DIR / "train.jsonl",
    "validation": OUTPUT_DIR / "validation.jsonl",
    "test": OUTPUT_DIR / "test.jsonl",
}
AUDIT_FILE = OUTPUT_DIR / "sft_split_audit.json"


def load_jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc}"
                ) from exc
            rows.append(row)
    return rows


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def partition_category(family_groups, rng):
    """
    Assign complete families to three partitions.

    Randomized greedy search minimizes the deviation from per-category
    row-count targets while guaranteeing at least one family per split.
    Returns family -> split.
    """
    if len(family_groups) < 3:
        raise ValueError(
            "Cannot put every category in all three splits while "
            f"keeping families intact: only {len(family_groups)} families."
        )

    families = list(family_groups)
    sizes = {family: len(rows) for family, rows in family_groups.items()}
    total = sum(sizes.values())
    targets = {s: total * RATIOS[s] for s in SPLITS}

    best_assignment = None
    best_score = float("inf")

    # Each trial starts with three distinct families assigned one per split.
    # The rest are assigned greedily according to target-count deviation.
    for _ in range(2500):
        order = families[:]
        rng.shuffle(order)
        order.sort(key=lambda family: sizes[family], reverse=True)

        # Randomize tie-breaking by giving each family a tiny random key.
        # Sorting remains primarily by descending family size.
        tie = {family: rng.random() for family in order}
        order.sort(key=lambda family: (-sizes[family], tie[family]))

        assignment = {}
        counts = Counter()

        seed_splits = list(SPLITS)
        rng.shuffle(seed_splits)

        for family, split in zip(order[:3], seed_splits):
            assignment[family] = split
            counts[split] += sizes[family]

        for index, family in enumerate(order[3:], start=3):
            remaining = len(order) - index

            choices = []
            for split in SPLITS:
                proposed = counts.copy()
                proposed[split] += sizes[family]

                score = sum(
                    ((proposed[s] - targets[s]) / max(targets[s], 1)) ** 2
                    for s in SPLITS
                )
                score += rng.random() * 1e-9
                choices.append((score, split))

            _, chosen = min(choices)
            assignment[family] = chosen
            counts[chosen] += sizes[family]

        score = sum(
            ((counts[s] - targets[s]) / max(targets[s], 1)) ** 2
            for s in SPLITS
        )

        if score < best_score:
            best_score = score
            best_assignment = assignment.copy()

    if set(best_assignment.values()) != set(SPLITS):
        raise RuntimeError("Internal error: a split is missing.")

    return best_assignment


def main():
    if not SOURCE.is_file():
        raise FileNotFoundError(f"Source file not found: {SOURCE}")

    # Never overwrite a prior run.
    existing = [str(p) for p in [*OUTPUT_FILES.values(), AUDIT_FILE] if p.exists()]
    if existing:
        raise FileExistsError(
            "Output files already exist; refusing to overwrite:\n"
            + "\n".join(existing)
            + "\nChoose a new output directory or archive the old run first."
        )

    source_hash_before = sha256_file(SOURCE)
    rows = load_jsonl(SOURCE)

    if not rows:
        raise ValueError("Source dataset is empty.")

    seen_ids = set()
    for i, row in enumerate(rows, 1):
        missing = REQUIRED_FIELDS - row.keys()
        if missing:
            raise ValueError(
                f"Record {i} missing required fields: {sorted(missing)}"
            )

        for field in ("scenario_id", "scenario_family", "category",
                      "instruction", "input", "output"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(
                    f"Record {i} has an empty/invalid {field!r}."
                )

        sid = row["scenario_id"]
        if sid in seen_ids:
            raise ValueError(f"Duplicate scenario_id in source: {sid}")
        seen_ids.add(sid)

    # Category -> family -> records. A family must belong to one category.
    grouped = defaultdict(lambda: defaultdict(list))
    family_category = {}

    for row in rows:
        category = row["category"]
        family = row["scenario_family"]

        if family in family_category and family_category[family] != category:
            raise ValueError(
                f"Family {family!r} appears in multiple categories: "
                f"{family_category[family]!r}, {category!r}"
            )

        family_category[family] = category
        grouped[category][family].append(row)

    rng = random.Random(SEED)
    partitions = {s: [] for s in SPLITS}
    family_assignment = {}

    for category in sorted(grouped):
        groups = grouped[category]

        if len(groups) < 3:
            raise ValueError(
                f"{category}: only {len(groups)} families; cannot ensure "
                "category coverage in all three splits without leakage."
            )

        assignment = partition_category(groups, rng)

        for family, split in assignment.items():
            family_assignment[family] = split
            partitions[split].extend(groups[family])

    # Deterministic record order within each output.
    for split in SPLITS:
        partitions[split].sort(
            key=lambda r: (r["category"], r["scenario_family"], r["scenario_id"])
        )

    # Validate ID and family isolation.
    id_sets = {
        split: {r["scenario_id"] for r in partitions[split]}
        for split in SPLITS
    }
    family_sets = {
        split: {r["scenario_family"] for r in partitions[split]}
        for split in SPLITS
    }

    id_overlaps = {}
    family_overlaps = {}
    for a, b in itertools.combinations(SPLITS, 2):
        id_overlaps[f"{a}__{b}"] = sorted(id_sets[a] & id_sets[b])
        family_overlaps[f"{a}__{b}"] = sorted(
            family_sets[a] & family_sets[b]
        )

    if any(id_overlaps.values()):
        raise RuntimeError(f"Scenario ID leakage detected: {id_overlaps}")
    if any(family_overlaps.values()):
        raise RuntimeError(f"Scenario family leakage detected: {family_overlaps}")

    categories = sorted(grouped)
    category_counts = {}
    category_family_counts = {}

    for split in SPLITS:
        category_counts[split] = dict(
            sorted(Counter(r["category"] for r in partitions[split]).items())
        )
        category_family_counts[split] = dict(
            sorted(Counter(
                r["category"]
                for r in partitions[split]
            ).items())
        )

    # Every category must be represented in every split.
    for split in SPLITS:
        missing_categories = set(categories) - set(category_counts[split])
        if missing_categories:
            raise RuntimeError(
                f"{split} missing categories: {sorted(missing_categories)}"
            )

    # Explicitly project records onto the model-facing SFT schema.
    # Review decisions, suggested corrections, and metadata must not
    # be copied into model training records.
    allowed_fields = (
        "scenario_id", "scenario_family", "category",
        "instruction", "input", "output",
    )

    for split in SPLITS:
        partitions[split] = [
            {field: row[field] for field in allowed_fields}
            for row in partitions[split]
        ]

    # Verify projection removed all non-SFT fields.
    unexpected = [
        (split, row.get("scenario_id"), sorted(set(row) - set(allowed_fields)))
        for split in SPLITS
        for row in partitions[split]
        if set(row) != set(allowed_fields)
    ]
    if unexpected:
        raise ValueError(
            f"SFT schema projection failed: {unexpected[:5]}"
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=False)

    for split in SPLITS:
        with OUTPUT_FILES[split].open("w", encoding="utf-8") as f:
            for row in partitions[split]:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    audit = {
        "source": str(SOURCE),
        "source_sha256_before": source_hash_before,
        "source_sha256_after": sha256_file(SOURCE),
        "seed": SEED,
        "strategy": (
            "Per-category whole-family assignment; randomized greedy "
            "optimization toward 80/10/10; at least one family per split"
        ),
        "target_ratios": RATIOS,
        "records_total": len(rows),
        "split_counts": {s: len(partitions[s]) for s in SPLITS},
        "split_ratios_actual": {
            s: round(len(partitions[s]) / len(rows), 6) for s in SPLITS
        },
        "category_counts": category_counts,
        "category_family_counts": category_family_counts,
        "family_groups_total": len(family_category),
        "families_crossing_splits": sum(
            len(v) for v in family_overlaps.values()
        ),
        "scenario_id_overlap_between_splits": sum(
            len(v) for v in id_overlaps.values()
        ),
        "family_overlap_details": family_overlaps,
        "scenario_id_overlap_details": id_overlaps,
        "all_categories_in_all_splits": True,
        "review_metadata_in_sft_records": False,
        "source_modified": source_hash_before != sha256_file(SOURCE),
        "human_validation_claimed": False,
        "note": (
            "Synthetic data. Family isolation does not establish factual "
            "validity or eliminate all semantic leakage. Whole-family "
            "constraints can make exact 80/10/10 ratios impossible."
        ),
    }

    if audit["source_modified"]:
        raise RuntimeError("Source hash changed unexpectedly.")

    AUDIT_FILE.write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("=== SPLIT V2 CREATED ===")
    print("Source:", SOURCE)
    print("Output:", OUTPUT_DIR)
    print("Seed:", SEED)
    print("Total records:", len(rows))

    for split in SPLITS:
        count = len(partitions[split])
        ratio = count / len(rows)
        print(f"\n{split}: {count} records ({ratio:.2%})")
        for category, n in category_counts[split].items():
            print(f"  {category}: {n}")

    print("\nFamily groups:", len(family_category))
    print("Family overlap:", audit["families_crossing_splits"])
    print("Scenario ID overlap:", audit["scenario_id_overlap_between_splits"])
    print("All categories in all splits:", audit["all_categories_in_all_splits"])
    print("Source unchanged:", not audit["source_modified"])
    print("Audit:", AUDIT_FILE)


if __name__ == "__main__":
    main()
