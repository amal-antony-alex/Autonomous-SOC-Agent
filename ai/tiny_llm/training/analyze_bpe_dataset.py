from pathlib import Path
from collections import Counter

from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATASET_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_instruction_dataset.jsonl"
)

TOKENIZER_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "cyber_bpe"
    / "tokenizer.json"
)


def main():

    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    lengths = []
    prompt_lengths = []
    response_lengths = []

    with open(
        DATASET_FILE,
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            if not line.strip():
                continue

            import json

            row = json.loads(line)

            instruction = row["instruction"]
            input_text = row["input"]
            output = row["output"]

            prompt = (
                "Instruction:\n"
                + instruction
                + "\n\n"
                + "Input:\n"
                + input_text
                + "\n\n"
                + "Response:\n"
            )

            prompt_tokens = tokenizer.encode(
                prompt,
                add_bos=True,
                add_eos=False,
            )

            response_tokens = tokenizer.encode(
                output,
                add_bos=False,
                add_eos=True,
            )

            total_tokens = (
                len(prompt_tokens)
                + len(response_tokens)
            )

            lengths.append(total_tokens)
            prompt_lengths.append(
                len(prompt_tokens)
            )
            response_lengths.append(
                len(response_tokens)
            )

    print("===== BPE DATASET ANALYSIS =====")

    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    print(
        f"Examples: {len(lengths)}"
    )

    print()

    print("----- Total Sequence Length -----")

    print(
        f"Average: "
        f"{sum(lengths) / len(lengths):.2f}"
    )

    print(
        f"Minimum: {min(lengths)}"
    )

    print(
        f"Maximum: {max(lengths)}"
    )

    print()

    print("----- Prompt Length -----")

    print(
        f"Average: "
        f"{sum(prompt_lengths) / len(prompt_lengths):.2f}"
    )

    print(
        f"Minimum: {min(prompt_lengths)}"
    )

    print(
        f"Maximum: {max(prompt_lengths)}"
    )

    print()

    print("----- Response Length -----")

    print(
        f"Average: "
        f"{sum(response_lengths) / len(response_lengths):.2f}"
    )

    print(
        f"Minimum: {min(response_lengths)}"
    )

    print(
        f"Maximum: {max(response_lengths)}"
    )

    print()

    print("----- 512 Token Limit -----")

    truncated = [
        length
        for length in lengths
        if length > 512
    ]

    print(
        f"Sequences over 512 tokens: "
        f"{len(truncated)}"
    )

    if truncated:

        print(
            f"Longest truncated sequence: "
            f"{max(truncated)}"
        )

    print()

    print("----- Length Distribution -----")

    buckets = Counter()

    for length in lengths:

        if length <= 128:
            bucket = "0-128"
        elif length <= 256:
            bucket = "129-256"
        elif length <= 384:
            bucket = "257-384"
        elif length <= 512:
            bucket = "385-512"
        else:
            bucket = "513+"

        buckets[bucket] += 1

    for bucket in [
        "0-128",
        "129-256",
        "257-384",
        "385-512",
        "513+",
    ]:

        print(
            f"{bucket}: {buckets[bucket]}"
        )

    print()

    print("===== BPE ANALYSIS COMPLETE =====")


if __name__ == "__main__":
    main()
