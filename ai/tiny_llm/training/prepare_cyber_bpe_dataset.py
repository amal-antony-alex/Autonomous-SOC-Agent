from pathlib import Path

from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import (
    CyberBPETokenizer,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

CORPUS_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_corpus.txt"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cyber_bpe"
)

TRAIN_FILE = OUTPUT_DIR / "train.txt"
VAL_FILE = OUTPUT_DIR / "val.txt"

TOKENIZER_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "cyber_bpe"
    / "tokenizer.json"
)


VALIDATION_RATIO = 0.1
SEED = 42


def main():

    if not CORPUS_FILE.exists():
        raise FileNotFoundError(
            f"Corpus not found: {CORPUS_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    text = CORPUS_FILE.read_text(
        encoding="utf-8"
    ).strip()

    if not text:
        raise ValueError(
            "Cybersecurity corpus is empty."
        )

    # Preserve the corpus as a continuous language-model
    # training stream. The tokenizer is used here for validation
    # and token statistics; the actual training files remain text.
    paragraphs = [
        paragraph.strip()
        for paragraph in text.split("\n")
        if paragraph.strip()
    ]

    split_index = max(
        1,
        int(
            len(paragraphs)
            * (1 - VALIDATION_RATIO)
        ),
    )

    train_paragraphs = paragraphs[:split_index]
    val_paragraphs = paragraphs[split_index:]

    TRAIN_FILE.write_text(
        "\n\n".join(train_paragraphs),
        encoding="utf-8",
    )

    VAL_FILE.write_text(
        "\n\n".join(val_paragraphs),
        encoding="utf-8",
    )

    train_tokens = len(
        tokenizer.encode(
            TRAIN_FILE.read_text(
                encoding="utf-8"
            ),
            add_bos=True,
            add_eos=True,
        )
    )

    val_tokens = len(
        tokenizer.encode(
            VAL_FILE.read_text(
                encoding="utf-8"
            ),
            add_bos=True,
            add_eos=True,
        )
    )

    print("===== CYBER BPE DATASET =====")
    print(f"Total paragraphs: {len(paragraphs)}")
    print(f"Training paragraphs: {len(train_paragraphs)}")
    print(f"Validation paragraphs: {len(val_paragraphs)}")
    print(f"Training tokens: {train_tokens}")
    print(f"Validation tokens: {val_tokens}")
    print(f"Training file: {TRAIN_FILE}")
    print(f"Validation file: {VAL_FILE}")
    print("Dataset preparation: OK")


if __name__ == "__main__":
    main()
