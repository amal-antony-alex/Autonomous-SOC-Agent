import json
from pathlib import Path
from collections import Counter, defaultdict
from statistics import mean

from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


TRAIN_FILE = Path(
    "data/processed/cyberllm_v2/train.jsonl"
)

TOKENIZER_PATH = Path(
    "ai/tiny_llm/tokenizer/artifacts/"
    "cyber_bpe/tokenizer.json"
)


def load_jsonl(path):
    examples = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                examples.append(
                    json.loads(line)
                )

    return examples


def main():

    print(
        "===== CYBERLLM V2 RESPONSE ANALYSIS ====="
    )
    print()

    # --------------------------------------------------
    # Load tokenizer
    # --------------------------------------------------

    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER_PATH)

    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    # --------------------------------------------------
    # Load training dataset
    # --------------------------------------------------

    examples = load_jsonl(
        TRAIN_FILE
    )

    print(
        f"Training examples: "
        f"{len(examples)}"
    )

    print()

    # --------------------------------------------------
    # Calculate response token lengths
    # --------------------------------------------------

    all_lengths = []

    by_source = defaultdict(list)
    by_category = defaultdict(list)

    for example in examples:

        output = example.get(
            "output",
            ""
        ).strip()

        response_tokens = tokenizer.encode(
            output,
            add_bos=False,
            add_eos=True
        )

        length = len(response_tokens)

        all_lengths.append(length)

        source = example.get(
            "source",
            "unknown"
        )

        category = example.get(
            "category",
            "unknown"
        )

        by_source[source].append(
            length
        )

        by_category[category].append(
            length
        )

    # --------------------------------------------------
    # Overall statistics
    # --------------------------------------------------

    print("===== OVERALL RESPONSE TOKENS =====")

    print(
        f"Average: "
        f"{mean(all_lengths):.2f}"
    )

    print(
        f"Minimum: "
        f"{min(all_lengths)}"
    )

    print(
        f"Maximum: "
        f"{max(all_lengths)}"
    )

    print()

    # --------------------------------------------------
    # Buckets
    # --------------------------------------------------

    buckets = Counter()

    for length in all_lengths:

        if length <= 5:
            buckets["0-5"] += 1

        elif length <= 10:
            buckets["6-10"] += 1

        elif length <= 25:
            buckets["11-25"] += 1

        elif length <= 50:
            buckets["26-50"] += 1

        else:
            buckets["51+"] += 1

    print("===== RESPONSE LENGTH DISTRIBUTION =====")

    for bucket in [
        "0-5",
        "6-10",
        "11-25",
        "26-50",
        "51+",
    ]:

        count = buckets[bucket]

        percentage = (
            count
            / len(all_lengths)
            * 100
        )

        print(
            f"{bucket:>5} tokens: "
            f"{count:4d} "
            f"({percentage:6.2f}%)"
        )

    print()

    # --------------------------------------------------
    # Source distribution
    # --------------------------------------------------

    print("===== BY SOURCE =====")

    for source, lengths in sorted(
        by_source.items()
    ):

        print(
            f"{source}: "
            f"{len(lengths)} examples | "
            f"average {mean(lengths):.2f} | "
            f"min {min(lengths)} | "
            f"max {max(lengths)}"
        )

    print()

    # --------------------------------------------------
    # Category distribution
    # --------------------------------------------------

    print("===== BY CATEGORY =====")

    for category, lengths in sorted(
        by_category.items()
    ):

        print(
            f"{category}: "
            f"{len(lengths)} examples | "
            f"average {mean(lengths):.2f} | "
            f"min {min(lengths)} | "
            f"max {max(lengths)}"
        )

    print()

    # --------------------------------------------------
    # Very short response percentage
    # --------------------------------------------------

    short_count = sum(
        length <= 5
        for length in all_lengths
    )

    print("===== SHORT RESPONSE CHECK =====")

    print(
        f"Responses <=5 tokens: "
        f"{short_count}"
    )

    print(
        f"Percentage <=5 tokens: "
        f"{short_count / len(all_lengths) * 100:.2f}%"
    )

    print()

    # --------------------------------------------------
    # Response token contribution
    # --------------------------------------------------

    total_tokens = sum(
        all_lengths
    )

    source_token_totals = {
        source: sum(lengths)
        for source, lengths
        in by_source.items()
    }

    print(
        "===== RESPONSE TOKEN CONTRIBUTION ====="
    )

    print(
        f"Total trainable response tokens: "
        f"{total_tokens}"
    )

    for source, token_count in sorted(
        source_token_totals.items()
    ):

        percentage = (
            token_count
            / total_tokens
            * 100
        )

        print(
            f"{source}: "
            f"{token_count} tokens "
            f"({percentage:.2f}%)"
        )

    print()

    print(
        "===== RESPONSE ANALYSIS COMPLETE ====="
    )


if __name__ == "__main__":
    main()
