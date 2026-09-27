from pathlib import Path

from ai.tiny_llm.tokenizer.bpe_tokenizer import BPETokenizer


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TRAIN_FILE = PROJECT_ROOT / "data" / "processed" / "train.txt"
TOKENIZER_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "tokenizer.json"
)


def main():
    if not TRAIN_FILE.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {TRAIN_FILE}"
        )

    text = TRAIN_FILE.read_text(
        encoding="utf-8"
    )

    tokenizer = BPETokenizer(
        vocab_size=10000
    )

    tokenizer.build_vocabulary(
        [text]
    )

    tokenizer.save(
        TOKENIZER_FILE
    )

    print("Tokenizer built successfully.")
    print(f"Vocabulary size: {len(tokenizer.token_to_id)}")
    print(f"Tokenizer saved: {TOKENIZER_FILE}")

    sample = (
        "Multiple failed SSH authentication attempts "
        "from the same source IP may indicate brute force."
    )

    encoded = tokenizer.encode(sample)
    decoded = tokenizer.decode(encoded)

    print("\nSample text:")
    print(sample)

    print("\nEncoded:")
    print(encoded[:50])

    print("\nDecoded:")
    print(decoded)


if __name__ == "__main__":
    main()
