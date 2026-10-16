from pathlib import Path

from tokenizers import Tokenizer
from tokenizers import decoders
from tokenizers import models
from tokenizers import pre_tokenizers
from tokenizers import trainers


PROJECT_ROOT = Path(__file__).resolve().parents[3]


CORPUS_FILES = [
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_corpus.txt",

    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_instruction_dataset.jsonl",
]


OUTPUT_DIR = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "cyber_bpe"
)


OUTPUT_FILE = (
    OUTPUT_DIR
    / "tokenizer.json"
)


VOCAB_SIZE = 2000


def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("===== CYBERSECURITY BPE TOKENIZER =====")
    print()

    print("Corpus files:")

    for path in CORPUS_FILES:
        print(f"  - {path}")

        if not path.exists():
            raise FileNotFoundError(
                f"Corpus file not found: {path}"
            )

    tokenizer = Tokenizer(
        models.BPE(
            unk_token="<UNK>"
        )
    )

    tokenizer.pre_tokenizer = (
        pre_tokenizers.ByteLevel(
            add_prefix_space=False
        )
    )
    
    tokenizer.decoder = decoders.ByteLevel()

    trainer = trainers.BpeTrainer(
        vocab_size=VOCAB_SIZE,
        min_frequency=1,
        special_tokens=[
            "<PAD>",
            "<UNK>",
            "<BOS>",
            "<EOS>",
        ],
    )

    tokenizer.train(
        files=[
            str(path)
            for path in CORPUS_FILES
        ],
        trainer=trainer,
    )

    tokenizer.save(
        str(OUTPUT_FILE)
    )

    print()
    print("Tokenizer training complete.")
    print(
        f"Vocabulary size: "
        f"{tokenizer.get_vocab_size()}"
    )

    print(
        f"Saved to: {OUTPUT_FILE}"
    )

    # Test cybersecurity terminology.
    test_text = (
        "Multiple failed SSH authentication attempts "
        "from the same source IP may indicate brute force."
    )

    encoding = tokenizer.encode(
        test_text
    )

    print()
    print("===== TOKENIZATION TEST =====")
    print()
    print("Input:")
    print(test_text)

    print()
    print("Tokens:")
    print(encoding.tokens)

    print()
    print("Token IDs:")
    print(encoding.ids)

    print()
    print("Token count:")
    print(len(encoding.ids))

    print()
    print("Decoded:")
    print(
        tokenizer.decode(
            encoding.ids
        )
    )


if __name__ == "__main__":
    main()

