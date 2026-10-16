import json
from pathlib import Path
from collections import Counter
from difflib import SequenceMatcher

DATASET = Path(
    "data/processed/mitre_attack/mitre_instruction_dataset_v2.jsonl"
)

examples = []

with DATASET.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            examples.append(json.loads(line))

print("===== MITRE DATASET QUALITY =====")
print()

# --------------------------------------------------
# Basic statistics
# --------------------------------------------------

print(f"Total examples: {len(examples)}")
print()

# --------------------------------------------------
# Category distribution
# --------------------------------------------------

categories = Counter(
    example.get("category", "unknown")
    for example in examples
)

print("Category Distribution:")
for category, count in sorted(categories.items()):
    print(f"  {category}: {count}")
print()

# --------------------------------------------------
# Input / output lengths
# --------------------------------------------------

input_lengths = [
    len(example.get("input", "").split())
    for example in examples
]

output_lengths = [
    len(example.get("output", "").split())
    for example in examples
]

print("Input Length:")
print(f"  Average: {sum(input_lengths) / len(input_lengths):.2f}")
print(f"  Minimum: {min(input_lengths)}")
print(f"  Maximum: {max(input_lengths)}")
print()

print("Output Length:")
print(f"  Average: {sum(output_lengths) / len(output_lengths):.2f}")
print(f"  Minimum: {min(output_lengths)}")
print(f"  Maximum: {max(output_lengths)}")
print()

# --------------------------------------------------
# Empty fields
# --------------------------------------------------

empty_inputs = sum(
    not example.get("input", "").strip()
    for example in examples
)

empty_outputs = sum(
    not example.get("output", "").strip()
    for example in examples
)

empty_instructions = sum(
    not example.get("instruction", "").strip()
    for example in examples
)

print("Empty Fields:")
print(f"  Empty instructions: {empty_instructions}")
print(f"  Empty inputs: {empty_inputs}")
print(f"  Empty outputs: {empty_outputs}")
print()

# --------------------------------------------------
# Exact duplicates
# --------------------------------------------------

triples = [
    (
        example.get("instruction", ""),
        example.get("input", ""),
        example.get("output", ""),
    )
    for example in examples
]

unique_triples = set(triples)

print("Exact Duplicates:")
print(f"  Unique examples: {len(unique_triples)}")
print(f"  Duplicate examples: {len(examples) - len(unique_triples)}")
print()

# --------------------------------------------------
# Instruction repetition
# --------------------------------------------------

instruction_counts = Counter(
    example.get("instruction", "")
    for example in examples
)

repeated_instructions = {
    instruction: count
    for instruction, count in instruction_counts.items()
    if count > 1
}

print("Instruction Repetition:")
print(f"  Unique instructions: {len(instruction_counts)}")
print(f"  Repeated instruction patterns: {len(repeated_instructions)}")
print()

# --------------------------------------------------
# Very short examples
# --------------------------------------------------

short_examples = [
    example
    for example in examples
    if len(example.get("output", "").split()) < 5
]

print("Very Short Outputs:")
print(f"  Outputs under 5 words: {len(short_examples)}")
print()

# --------------------------------------------------
# Near duplicate detection
# --------------------------------------------------

print("Near-Duplicate Check:")

sample_size = min(len(examples), 1500)

near_duplicates = []

for i in range(sample_size):
    text_a = (
        examples[i].get("instruction", "")
        + " "
        + examples[i].get("input", "")
        + " "
        + examples[i].get("output", "")
    )

    for j in range(i + 1, sample_size):
        text_b = (
            examples[j].get("instruction", "")
            + " "
            + examples[j].get("input", "")
            + " "
            + examples[j].get("output", "")
        )

        similarity = SequenceMatcher(
            None,
            text_a,
            text_b
        ).ratio()

        if similarity >= 0.90:
            near_duplicates.append((i, j, similarity))

print(
    f"  Near-duplicate pairs found "
    f"(sample of {sample_size}): {len(near_duplicates)}"
)

if near_duplicates:
    print()
    print("  Examples:")

    for i, j, similarity in near_duplicates[:10]:
        print(
            f"    {i} <-> {j} "
            f"(similarity={similarity:.3f})"
        )

print()

# --------------------------------------------------
# Dataset structure
# --------------------------------------------------

required_fields = {
    "instruction",
    "input",
    "output",
    "category",
}

missing_fields = 0

for example in examples:
    if not required_fields.issubset(example.keys()):
        missing_fields += 1

print("Structure:")
print(f"  Examples missing required fields: {missing_fields}")
print()

print("===== ANALYSIS COMPLETE =====")
