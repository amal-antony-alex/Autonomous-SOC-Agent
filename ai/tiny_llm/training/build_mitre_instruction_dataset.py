import json
import re
from pathlib import Path


INPUT_FILE = Path(
    "data/processed/mitre_attack/mitre_techniques.jsonl"
)

OUTPUT_FILE = Path(
    "data/processed/mitre_attack/mitre_instruction_dataset_v2.jsonl"
)


def clean_text(text):
    """Clean MITRE text for concise instruction examples."""

    if not text:
        return ""

    text = re.sub(
        r"\(Citation:.*?\)",
        "",
        text,
        flags=re.DOTALL
    )

    text = re.sub(
        r"\[([^\]]+)\]\([^)]+\)",
        r"\1",
        text
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def first_sentence(text):
    """Return the first useful sentence."""

    text = clean_text(text)

    sentences = re.split(
        r"(?<=[.!?])\s+",
        text
    )

    if sentences:
        return sentences[0].strip()

    return text


def make_short_description(description):
    """
    Create a concise activity description from ATT&CK
    documentation without copying the entire description.
    """

    description = clean_text(description)

    sentences = re.split(
        r"(?<=[.!?])\s+",
        description
    )

    sentences = [
        sentence.strip()
        for sentence in sentences
        if sentence.strip()
    ]

    if not sentences:
        return ""

    # Keep only the first two sentences.
    short = " ".join(sentences[:2])

    # Prevent excessively long inputs.
    words = short.split()

    if len(words) > 80:
        short = " ".join(words[:80]).rstrip(" ,.;:") + "."

    return short


def build_examples(technique):
    technique_id = technique.get("technique_id", "").strip()
    name = technique.get("name", "").strip()
    description = technique.get("description", "").strip()

    tactics = technique.get("tactics", [])
    platforms = technique.get("platforms", [])

    if not technique_id or not name:
        return []

    short_description = make_short_description(description)

    examples = []

    # --------------------------------------------------
    # 1. Technique identification
    # --------------------------------------------------

    if short_description:

        examples.append({
            "instruction": (
                "Identify the MITRE ATT&CK technique represented "
                "by the following behavior."
            ),
            "input": short_description,
            "output": (
                f"{technique_id} - {name}"
            ),
            "category": "mitre_mapping",
            "technique_id": technique_id,
            "technique_name": name
        })

        examples.append({
            "instruction": (
                "Map the observed behavior to a MITRE ATT&CK "
                "technique."
            ),
            "input": short_description,
            "output": (
                f"MITRE ATT&CK mapping: "
                f"{technique_id} - {name}."
            ),
            "category": "mitre_mapping",
            "technique_id": technique_id,
            "technique_name": name
        })

    # --------------------------------------------------
    # 2. Technique explanation
    # --------------------------------------------------

    if short_description:

        explanation = (
            f"{name} ({technique_id}) involves "
            f"{short_description}"
        )

        examples.append({
            "instruction": (
                "Explain this MITRE ATT&CK technique in "
                "concise SOC analyst language."
            ),
            "input": (
                f"Technique ID: {technique_id}\n"
                f"Technique: {name}"
            ),
            "output": explanation,
            "category": "mitre_explanation",
            "technique_id": technique_id,
            "technique_name": name
        })

    # --------------------------------------------------
    # 3. Technique ID lookup
    # --------------------------------------------------

    examples.append({
        "instruction": (
            "What MITRE ATT&CK technique corresponds "
            "to the following technique ID?"
        ),
        "input": technique_id,
        "output": name,
        "category": "mitre_lookup",
        "technique_id": technique_id,
        "technique_name": name
    })

    # --------------------------------------------------
    # 4. Technique name lookup
    # --------------------------------------------------

    examples.append({
        "instruction": (
            "What is the MITRE ATT&CK ID for this technique?"
        ),
        "input": name,
        "output": technique_id,
        "category": "mitre_lookup",
        "technique_id": technique_id,
        "technique_name": name
    })

    # --------------------------------------------------
    # 5. Tactic mapping
    # --------------------------------------------------

    if tactics:

        tactic_text = ", ".join(tactics)

        examples.append({
            "instruction": (
                "Identify the MITRE ATT&CK tactic associated "
                "with this technique."
            ),
            "input": (
                f"Technique ID: {technique_id}\n"
                f"Technique: {name}"
            ),
            "output": tactic_text,
            "category": "mitre_tactic",
            "technique_id": technique_id,
            "technique_name": name
        })

    # --------------------------------------------------
    # 6. Platform mapping
    # --------------------------------------------------

    if platforms:

        platform_text = ", ".join(platforms)

        examples.append({
            "instruction": (
                "Identify the platforms associated with "
                "this MITRE ATT&CK technique."
            ),
            "input": (
                f"Technique ID: {technique_id}\n"
                f"Technique: {name}"
            ),
            "output": platform_text,
            "category": "mitre_platform",
            "technique_id": technique_id,
            "technique_name": name
        })

    return examples


def main():

    print("===== BUILDING MITRE INSTRUCTION DATASET V2 =====")
    print()

    techniques = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if line:
                techniques.append(
                    json.loads(line)
                )

    print(
        f"Techniques loaded: {len(techniques)}"
    )

    all_examples = []

    for technique in techniques:

        examples = build_examples(
            technique
        )

        all_examples.extend(
            examples
        )

    # --------------------------------------------------
    # Exact deduplication
    # --------------------------------------------------

    unique_examples = []
    seen = set()

    for example in all_examples:

        key = (
            example["instruction"],
            example["input"],
            example["output"]
        )

        if key not in seen:

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

    print(
        f"Instruction examples: "
        f"{len(unique_examples)}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print()
    print(
        "===== MITRE DATASET V2 COMPLETE ====="
    )


if __name__ == "__main__":
    main()
