import json
import random
from pathlib import Path
from collections import Counter, defaultdict


INPUT_FILE = Path(
    "data/processed/cyberllm_v2_instruction_dataset.jsonl"
)

OUTPUT_DIR = Path(
    "data/processed/cyberllm_v2"
)

TRAIN_FILE = OUTPUT_DIR / "train.jsonl"
VAL_FILE = OUTPUT_DIR / "val.jsonl"

SEED = 42
VALIDATION_RATIO = 0.10


def load_jsonl(path):
    examples = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                examples.append(json.loads(line))

    return examples


def write_jsonl(path, examples):
    with path.open("w", encoding="utf-8") as f:

        for example in examples:

            f.write(
                json.dumps(
                    example,
                    ensure_ascii=False
                )
                + "\n"
            )


def get_group_key(example):
    """
    Stratify by source + category.

    This prevents the large MITRE dataset from completely
    dominating the validation split and ensures the curated
    SOC categories are represented.
    """

    return (
        example.get("source", "unknown"),
        example.get("category", "unknown"),
    )


def main():

    print("===== SPLIT CYBERLLM V2 DATASET =====")
    print()

    examples = load_jsonl(INPUT_FILE)

    print(
        f"Total examples: {len(examples)}"
    )

    print(
        f"Validation ratio: "
        f"{VALIDATION_RATIO:.0%}"
    )

    print(
        f"Random seed: {SEED}"
    )

    print()

    # --------------------------------------------------
    # Group examples by source + category
    # --------------------------------------------------

    groups = defaultdict(list)

    for example in examples:

        groups[
            get_group_key(example)
        ].append(example)

    # --------------------------------------------------
    # Stratified split
    # --------------------------------------------------

    rng = random.Random(SEED)

    train_examples = []
    val_examples = []

    for group_key, group_examples in sorted(
        groups.items()
    ):

        group_examples = list(group_examples)

        rng.shuffle(group_examples)

        group_size = len(group_examples)

        # At least one validation example for every group.
        val_count = max(
            1,
            round(
                group_size
                * VALIDATION_RATIO
            )
        )

        # Never move the entire group into validation.
        if val_count >= group_size:
            val_count = group_size - 1

        group_val = group_examples[
            :val_count
        ]

        group_train = group_examples[
            val_count:
        ]

        val_examples.extend(
            group_val
        )

        train_examples.extend(
            group_train
        )

    # --------------------------------------------------
    # Shuffle final datasets
    # --------------------------------------------------

    rng.shuffle(train_examples)
    rng.shuffle(val_examples)

    # --------------------------------------------------
    # Write datasets
    # --------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    write_jsonl(
        TRAIN_FILE,
        train_examples
    )

    write_jsonl(
        VAL_FILE,
        val_examples
    )

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    print("===== SPLIT STATISTICS =====")
    print()

    print(
        f"Training examples: "
        f"{len(train_examples)}"
    )

    print(
        f"Validation examples: "
        f"{len(val_examples)}"
    )

    print()

    print("Training Distribution:")

    train_sources = Counter(
        example.get(
            "source",
            "unknown"
        )
        for example in train_examples
    )

    train_categories = Counter(
        example.get(
            "category",
            "unknown"
        )
        for example in train_examples
    )

    for source, count in sorted(
        train_sources.items()
    ):

        print(
            f"  {source}: {count}"
        )

    print()

    for category, count in sorted(
        train_categories.items()
    ):

        print(
            f"  {category}: {count}"
        )

    print()

    print("Validation Distribution:")

    val_sources = Counter(
        example.get(
            "source",
            "unknown"
        )
        for example in val_examples
    )

    val_categories = Counter(
        example.get(
            "category",
            "unknown"
        )
        for example in val_examples
    )

    for source, count in sorted(
        val_sources.items()
    ):

        print(
            f"  {source}: {count}"
        )

    print()

    for category, count in sorted(
        val_categories.items()
    ):

        print(
            f"  {category}: {count}"
        )

    print()

    # --------------------------------------------------
    # Integrity checks
    # --------------------------------------------------

    train_keys = {
        (
            example["instruction"],
            example["input"],
            example["output"],
        )
        for example in train_examples
    }

    val_keys = {
        (
            example["instruction"],
            example["input"],
            example["output"],
        )
        for example in val_examples
    }

    overlap = train_keys & val_keys

    print("===== INTEGRITY CHECK =====")
    print()

    print(
        f"Train/validation exact overlap: "
        f"{len(overlap)}"
    )

    print(
        f"Total after split: "
        f"{len(train_examples) + len(val_examples)}"
    )

    print()

    print(
        f"Training output: {TRAIN_FILE}"
    )

    print(
        f"Validation output: {VAL_FILE}"
    )

    print()
    print(
        "===== SPLIT COMPLETE ====="
    )


if __name__ == "__main__":
    main()
