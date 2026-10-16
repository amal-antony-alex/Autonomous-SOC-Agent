
import json
from pathlib import Path
from collections import Counter


MITRE_FILE = Path(
    "data/processed/mitre_attack/mitre_instruction_dataset_v2.jsonl"
)

SOC_FILE = Path(
    "data/raw/cybersecurity_instruction_dataset.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/cyberllm_v2_instruction_dataset.jsonl"
)


def load_jsonl(path):
    examples = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                examples.append(json.loads(line))

    return examples


def infer_soc_category(example):
    """
    Recover the category of the original 110 curated SOC examples.

    The original dataset does not contain a category field, so the
    category is inferred from the instruction wording.
    """

    instruction = example.get(
        "instruction",
        ""
    ).lower()

    if "ioc" in instruction:
        return "ioc_analysis"

    if "mitre" in instruction or "technique" in instruction:
        return "mitre_mapping"

    if "log" in instruction:
        return "log_analysis"

    if "incident" in instruction:
        return "incident_summary"

    return "alert_analysis"


def normalize_example(example, source):
    """
    Convert datasets into a common format.
    """

    category = example.get("category")

    # The original 110-example SOC dataset does not contain
    # category metadata, so recover it here.
    if not category and source == "curated_soc":
        category = infer_soc_category(example)

    if not category:
        category = "unknown"

    normalized = {
        "instruction": example.get(
            "instruction",
            ""
        ).strip(),

        "input": example.get(
            "input",
            ""
        ).strip(),

        "output": example.get(
            "output",
            ""
        ).strip(),

        "category": category,

        "source": source,
    }

    # Preserve MITRE metadata when available.
    if example.get("technique_id"):
        normalized["technique_id"] = (
            example["technique_id"]
        )

    if example.get("technique_name"):
        normalized["technique_name"] = (
            example["technique_name"]
        )

    return normalized


def main():

    print("===== BUILD CYBERLLM V2 DATASET =====")
    print()

    # --------------------------------------------------
    # Load datasets
    # --------------------------------------------------

    mitre_examples = load_jsonl(
        MITRE_FILE
    )

    soc_examples = load_jsonl(
        SOC_FILE
    )

    print(
        f"MITRE examples loaded: "
        f"{len(mitre_examples)}"
    )

    print(
        f"SOC examples loaded: "
        f"{len(soc_examples)}"
    )

    print()

    # --------------------------------------------------
    # Normalize datasets
    # --------------------------------------------------

    combined = []

    for example in mitre_examples:

        combined.append(
            normalize_example(
                example,
                "mitre_attack"
            )
        )

    for example in soc_examples:

        combined.append(
            normalize_example(
                example,
                "curated_soc"
            )
        )

    # --------------------------------------------------
    # Exact deduplication
    # --------------------------------------------------

    unique_examples = []
    seen = set()

    for example in combined:

        key = (
            example["instruction"],
            example["input"],
            example["output"],
        )

        if key in seen:
            continue

        seen.add(key)
        unique_examples.append(
            example
        )

    # --------------------------------------------------
    # Write dataset
    # --------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as f:

        for example in unique_examples:

            f.write(
                json.dumps(
                    example,
                    ensure_ascii=False
                )
                + "\n"
            )

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    source_counts = Counter(
        example["source"]
        for example in unique_examples
    )

    category_counts = Counter(
        example["category"]
        for example in unique_examples
    )

    print("===== DATASET STATISTICS =====")
    print()

    print(
        f"Combined examples: "
        f"{len(combined)}"
    )

    print(
        f"Unique examples: "
        f"{len(unique_examples)}"
    )

    print(
        f"Removed exact duplicates: "
        f"{len(combined) - len(unique_examples)}"
    )

    print()

    print("Source Distribution:")

    for source, count in sorted(
        source_counts.items()
    ):
        print(
            f"  {source}: {count}"
        )

    print()

    print("Category Distribution:")

    for category, count in sorted(
        category_counts.items()
    ):
        print(
            f"  {category}: {count}"
        )

    print()

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print()
    print(
        "===== CYBERLLM V2 DATASET COMPLETE ====="
    )


if __name__ == "__main__":
    main()
