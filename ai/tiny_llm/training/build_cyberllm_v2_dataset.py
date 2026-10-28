
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

ALLOWED_SOC_CATEGORIES = {
    "alert_analysis",
    "log_analysis",
    "ioc_analysis",
    "incident_summary",
    "mitre_mapping",
}


def load_jsonl(path):
    """Load JSONL examples and report malformed records clearly."""
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    examples = []

    with path.open("r", encoding="utf-8") as file:
        for line_no, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                example = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path}, line {line_no}: {exc}"
                ) from exc

            if not isinstance(example, dict):
                raise ValueError(
                    f"Expected a JSON object in {path}, "
                    f"line {line_no}"
                )

            examples.append(example)

    return examples


def infer_soc_category(example):
    """
    Infer a category from the actual task requested.

    Priority:
    1. IOC extraction and enrichment
    2. Explicit MITRE ATT&CK mapping
    3. Incident summaries and reporting
    4. Log interpretation and correlation
    5. General alert analysis

    This is a heuristic and should be reviewed against the dataset.
    """

    instruction = example.get("instruction", "").strip().lower()

    if not instruction:
        raise ValueError(
            "Cannot infer a category: instruction is empty."
        )

    # IOC extraction, reputation, and threat-intelligence enrichment.
    if any(term in instruction for term in [
        "indicator of compromise",
        "indicators of compromise",
        "extract the ioc",
        "extract all observable security indicators",
        "extract the indicators",
        "extract the network-related",
        "extract the file-related",
        "extract identity-related",
        "extract process-related",
        "ioc",
        "threat intelligence",
        "threat-intelligence",
        "reputation",
    ]):
        return "ioc_analysis"

    # Explicit ATT&CK mapping and technique identification.
    if any(term in instruction for term in [
        "map the observed",
        "map the command",
        "map the behavior",
        "mitre attack",
        "mitre mapping",
        "technique associated",
        "technique corresponds",
        "technique mapping",
        "mitre technique",
    ]):
        return "mitre_mapping"

    # Incident summaries, reporting, and concise SOC summaries.
    if any(term in instruction for term in [
        "incident summary",
        "soc incident summary",
        "soc summary",
        "summarize the security event",
        "summarize the event",
        "summarize the incident",
        "summarize the alert",
        "summarize the possible",
        "summarize the authentication",
        "summarize the privilege",
        "summarize the web security",
        "summarize an uncertain",
        "create a concise summary",
        "create an incident summary",
    ]):
        return "incident_summary"

    # Log analysis, event interpretation, and correlation.
    if any(term in instruction for term in [
        "log",
        "logs",
        "event id",
        "event sequence",
        "log sequence",
        "correlate the process",
        "security logs",
        "windows security",
        "firewall",
        "web server",
        "system log",
    ]):
        return "log_analysis"

    # Remaining SOC triage and investigation tasks.
    return "alert_analysis"


def normalize_example(example, source):
    """Normalize records while preserving available metadata."""

    normalized = {
        "instruction": example.get("instruction", "").strip(),
        "input": example.get("input", "").strip(),
        "output": example.get("output", "").strip(),
        "source": source,
    }

    if source == "curated_soc":
        # Infer categories for the original curated SOC dataset.
        # If category metadata already exists, preserve valid values.
        category = example.get("category")

        if category not in ALLOWED_SOC_CATEGORIES:
            category = infer_soc_category(example)

        normalized["category"] = category

    else:
        # Preserve existing MITRE categories.
        normalized["category"] = (
            example.get("category") or "unknown"
        )

    # Preserve MITRE technique metadata where available.
    for field in ("technique_id", "technique_name"):
        if example.get(field):
            normalized[field] = example[field]

    return normalized


def validate_examples(examples):
    """Reject malformed examples and invalid curated SOC categories."""

    errors = []

    for index, example in enumerate(examples, start=1):
        for field in ("instruction", "input", "output"):
            if not isinstance(example.get(field), str):
                errors.append(
                    f"Example {index}: {field} must be a string."
                )
            elif not example[field].strip():
                errors.append(
                    f"Example {index}: {field} is empty."
                )

        if (
            example.get("source") == "curated_soc"
            and example.get("category") not in ALLOWED_SOC_CATEGORIES
        ):
            errors.append(
                f"Example {index}: invalid SOC category "
                f"{example.get('category')!r}."
            )

    if errors:
        preview = "\n".join(errors[:20])
        raise ValueError(
            f"Dataset validation failed with {len(errors)} issue(s):\n"
            f"{preview}"
        )


def main():
    print("===== BUILD CYBERLLM V2 DATASET =====\n")

    # Load both source datasets.
    mitre_examples = load_jsonl(MITRE_FILE)
    soc_examples = load_jsonl(SOC_FILE)

    print(f"MITRE examples loaded: {len(mitre_examples)}")
    print(f"SOC examples loaded:   {len(soc_examples)}")

    # Normalize records.
    combined = []

    for example in mitre_examples:
        combined.append(
            normalize_example(example, "mitre_attack")
        )

    for example in soc_examples:
        combined.append(
            normalize_example(example, "curated_soc")
        )

    # Validate before deduplication and writing.
    validate_examples(combined)

    # Exact deduplication based on instruction, input, and output.
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
        unique_examples.append(example)

    # Validate the final records too.
    validate_examples(unique_examples)

    # Write output.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for example in unique_examples:
            file.write(
                json.dumps(example, ensure_ascii=False) + "\n"
            )

    # Statistics.
    source_counts = Counter(
        example["source"] for example in unique_examples
    )

    category_counts = Counter(
        example["category"] for example in unique_examples
    )

    soc_category_counts = Counter(
        example["category"]
        for example in unique_examples
        if example["source"] == "curated_soc"
    )

    print("\n===== DATASET STATISTICS =====")
    print(f"Combined examples:          {len(combined)}")
    print(f"Unique examples:            {len(unique_examples)}")
    print(
        "Removed exact duplicates:  "
        f"{len(combined) - len(unique_examples)}"
    )

    print("\nSource distribution:")
    for source, count in sorted(source_counts.items()):
        print(f"  {source}: {count}")

    print("\nOverall category distribution:")
    for category, count in sorted(category_counts.items()):
        print(f"  {category}: {count}")

    print("\nCurated SOC category distribution:")
    for category in sorted(ALLOWED_SOC_CATEGORIES):
        print(f"  {category}: {soc_category_counts[category]}")

    print(f"\nOutput: {OUTPUT_FILE}")
    print("\n===== CYBERLLM V2 DATASET COMPLETE =====")


if __name__ == "__main__":
    main()
