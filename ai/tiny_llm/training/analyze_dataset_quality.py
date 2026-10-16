import json
from pathlib import Path
from collections import Counter
from difflib import SequenceMatcher


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATASET_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_instruction_dataset.jsonl"
)


def word_count(text):
    return len(text.split())


def infer_category(instruction):
    text = instruction.lower()

    if "mitre" in text or "technique" in text:
        return "mitre_mapping"

    if "ioc" in text or "indicator" in text:
        return "ioc_analysis"

    if "log" in text:
        return "log_analysis"

    if "incident" in text or "summary" in text:
        return "incident_summary"

    return "alert_analysis"


def main():

    with open(
        DATASET_FILE,
        "r",
        encoding="utf-8",
    ) as f:
        rows = [
            json.loads(line)
            for line in f
            if line.strip()
        ]

    print("===== CYBERSECURITY DATASET QUALITY =====")
    print(f"Total examples: {len(rows)}")
    print()

    categories = Counter()

    input_lengths = []
    output_lengths = []

    duplicate_instructions = []
    short_outputs = []

    for i, row in enumerate(rows):

        instruction = row.get("instruction", "").strip()
        input_text = row.get("input", "").strip()
        output = row.get("output", "").strip()

        category = infer_category(instruction)
        categories[category] += 1

        input_lengths.append(
            word_count(input_text)
        )

        output_lengths.append(
            word_count(output)
        )

        if word_count(output) < 10:
            short_outputs.append(
                {
                    "index": i + 1,
                    "words": word_count(output),
                    "output": output,
                }
            )

    # Exact duplicate instructions
    instruction_counts = Counter(
        row.get("instruction", "").strip().lower()
        for row in rows
    )

    for instruction, count in instruction_counts.items():
        if count > 1:
            duplicate_instructions.append(
                {
                    "instruction": instruction,
                    "count": count,
                }
            )

    # Near-duplicate instructions
    near_duplicates = []

    instructions = [
        row.get("instruction", "").strip()
        for row in rows
    ]

    for i in range(len(instructions)):
        for j in range(i + 1, len(instructions)):

            similarity = SequenceMatcher(
                None,
                instructions[i].lower(),
                instructions[j].lower(),
            ).ratio()

            if similarity >= 0.85:
                near_duplicates.append(
                    {
                        "example_a": i + 1,
                        "example_b": j + 1,
                        "similarity": round(
                            similarity,
                            3,
                        ),
                    }
                )

    print("----- Category Distribution -----")

    for category, count in sorted(
        categories.items()
    ):
        print(
            f"{category}: {count}"
        )

    print()

    print("----- Input Length -----")

    print(
        f"Average: "
        f"{sum(input_lengths) / len(input_lengths):.2f} words"
    )

    print(
        f"Minimum: {min(input_lengths)} words"
    )

    print(
        f"Maximum: {max(input_lengths)} words"
    )

    print()

    print("----- Expected Response Length -----")

    print(
        f"Average: "
        f"{sum(output_lengths) / len(output_lengths):.2f} words"
    )

    print(
        f"Minimum: {min(output_lengths)} words"
    )

    print(
        f"Maximum: {max(output_lengths)} words"
    )

    print()

    print("----- Short Expected Responses -----")

    print(
        f"Responses under 10 words: "
        f"{len(short_outputs)}"
    )

    for item in short_outputs[:10]:

        print(
            f"{item['index']}: "
            f"{item['words']} words -> "
            f"{item['output']}"
        )

    print()

    print("----- Duplicate Instructions -----")

    print(
        f"Exact duplicate instruction groups: "
        f"{len(duplicate_instructions)}"
    )

    for item in duplicate_instructions[:10]:

        print(
            f"{item['count']}x -> "
            f"{item['instruction']}"
        )

    print()

    print("----- Near-Duplicate Instructions -----")

    print(
        f"Near-duplicate pairs: "
        f"{len(near_duplicates)}"
    )

    for item in near_duplicates[:10]:

        print(
            f"{item['example_a']} <-> "
            f"{item['example_b']} "
            f"({item['similarity']})"
        )

    print()

    print("===== DATASET ANALYSIS COMPLETE =====")


if __name__ == "__main__":
    main()
