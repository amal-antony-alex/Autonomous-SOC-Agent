import json
from pathlib import Path
from statistics import mean

from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


DATASET = Path(
    "data/processed/cyberllm_v2_instruction_dataset.jsonl"
)

TOKENIZER_PATH = Path(
    "ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json"
)

MAX_SEQ_LEN = 512


def main():
    print("===== MITRE BPE TOKEN ANALYSIS =====")
    print()

    # --------------------------------------------------
    # Load tokenizer
    # --------------------------------------------------

    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER_PATH)

    print(f"Tokenizer vocabulary: {tokenizer.vocab_size}")
    print()

    # --------------------------------------------------
    # Load dataset
    # --------------------------------------------------

    examples = []

    with DATASET.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                examples.append(json.loads(line))

    print(f"Total examples: {len(examples)}")
    print()

    # --------------------------------------------------
    # Token statistics
    # --------------------------------------------------

    total_lengths = []
    input_lengths = []
    output_lengths = []

    over_512 = []
    over_256 = []

    for index, example in enumerate(examples):

        instruction = example.get("instruction", "")
        input_text = example.get("input", "")
        output = example.get("output", "")

        # Full training sequence
        prompt = (
            f"Instruction:\n"
            f"{instruction}\n\n"
            f"Input:\n"
            f"{input_text}\n\n"
            f"Response:\n"
        )

        full_text = prompt + output

        # Tokenize separately
        input_tokens = tokenizer.encode(
            prompt,
            add_bos=True,
            add_eos=False
        )

        output_tokens = tokenizer.encode(
            output,
            add_bos=False,
            add_eos=True
        )

        full_tokens = tokenizer.encode(
            full_text,
            add_bos=True,
            add_eos=True
        )

        input_length = len(input_tokens)
        output_length = len(output_tokens)
        total_length = len(full_tokens)

        input_lengths.append(input_length)
        output_lengths.append(output_length)
        total_lengths.append(total_length)

        if total_length > MAX_SEQ_LEN:
            over_512.append(
                (index, total_length)
            )

        if total_length > 256:
            over_256.append(
                (index, total_length)
            )

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    print("===== FULL SEQUENCE LENGTH =====")

    print(
        f"Average: "
        f"{mean(total_lengths):.2f}"
    )

    print(
        f"Minimum: "
        f"{min(total_lengths)}"
    )

    print(
        f"Maximum: "
        f"{max(total_lengths)}"
    )

    print()

    print("===== INPUT / PROMPT TOKENS =====")

    print(
        f"Average: "
        f"{mean(input_lengths):.2f}"
    )

    print(
        f"Minimum: "
        f"{min(input_lengths)}"
    )

    print(
        f"Maximum: "
        f"{max(input_lengths)}"
    )

    print()

    print("===== OUTPUT TOKENS =====")

    print(
        f"Average: "
        f"{mean(output_lengths):.2f}"
    )

    print(
        f"Minimum: "
        f"{min(output_lengths)}"
    )

    print(
        f"Maximum: "
        f"{max(output_lengths)}"
    )

    print()

    # --------------------------------------------------
    # Sequence thresholds
    # --------------------------------------------------

    print("===== SEQUENCE THRESHOLDS =====")

    print(
        f"Examples > 256 tokens: "
        f"{len(over_256)}"
    )

    print(
        f"Examples > 512 tokens: "
        f"{len(over_512)}"
    )

    print()

    # --------------------------------------------------
    # Percentage
    # --------------------------------------------------

    total_examples = len(examples)

    if total_examples > 0:

        pct_256 = (
            len(over_256)
            / total_examples
            * 100
        )

        pct_512 = (
            len(over_512)
            / total_examples
            * 100
        )

        print("===== PERCENTAGES =====")

        print(
            f">256 tokens: "
            f"{pct_256:.2f}%"
        )

        print(
            f">512 tokens: "
            f"{pct_512:.2f}%"
        )

        print()

    # --------------------------------------------------
    # Longest examples
    # --------------------------------------------------

    print("===== 10 LONGEST EXAMPLES =====")

    longest = sorted(
        enumerate(total_lengths),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    for index, length in longest:

        category = examples[index].get(
            "category",
            "unknown"
        )

        technique_id = examples[index].get(
            "technique_id",
            "unknown"
        )

        print(
            f"Example {index}: "
            f"{length} tokens | "
            f"Category: {category} | "
            f"Technique: {technique_id}"
        )

    print()

    print("===== MITRE BPE ANALYSIS COMPLETE =====")


if __name__ == "__main__":
    main()
