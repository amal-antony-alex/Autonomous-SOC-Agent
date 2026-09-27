from pathlib import Path
import random
import re


PROJECT_ROOT = Path(__file__).resolve().parents[3]

RAW_FILE = PROJECT_ROOT / "data" / "raw" / "cybersecurity_corpus.txt"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

TRAIN_FILE = PROCESSED_DIR / "train.txt"
VAL_FILE = PROCESSED_DIR / "val.txt"

VAL_RATIO = 0.10
RANDOM_SEED = 42


def clean_text(text):
    """Clean whitespace while preserving paragraph structure."""

    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    # Normalize spaces and tabs.
    text = re.sub(r"[ \t]+", " ", text)

    # Preserve paragraph boundaries.
    text = re.sub(r"\n\s*\n+", "\n\n", text)

    return text.strip()


def extract_paragraphs(text):
    """Extract non-empty paragraphs as training samples."""

    blocks = re.split(r"\n\s*\n", text)

    paragraphs = []

    for block in blocks:
        block = block.strip()

        if not block:
            continue

        block = re.sub(r"\s+", " ", block)

        if len(block.split()) < 3:
            continue

        paragraphs.append(block)

    return paragraphs


def split_dataset(paragraphs):
    """Create a reproducible 90/10 train/validation split."""

    random.seed(RANDOM_SEED)

    shuffled = paragraphs.copy()
    random.shuffle(shuffled)

    validation_size = max(
        1,
        int(len(shuffled) * VAL_RATIO)
    )

    val_samples = shuffled[:validation_size]
    train_samples = shuffled[validation_size:]

    return train_samples, val_samples


def write_dataset(path, samples):
    with open(path, "w", encoding="utf-8") as file:
        for sample in samples:
            file.write(sample)
            file.write("\n\n")


def main():
    if not RAW_FILE.exists():
        raise FileNotFoundError(
            f"Raw dataset not found: {RAW_FILE}"
        )

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    raw_text = RAW_FILE.read_text(
        encoding="utf-8"
    )

    cleaned_text = clean_text(raw_text)

    paragraphs = extract_paragraphs(
        cleaned_text
    )

    if len(paragraphs) < 10:
        raise ValueError(
            f"Dataset contains only {len(paragraphs)} "
            "usable samples. At least 10 are required."
        )

    train_samples, val_samples = split_dataset(
        paragraphs
    )

    write_dataset(
        TRAIN_FILE,
        train_samples
    )

    write_dataset(
        VAL_FILE,
        val_samples
    )

    print("Dataset preparation complete.")
    print(f"Total samples:      {len(paragraphs)}")
    print(f"Training samples:   {len(train_samples)}")
    print(f"Validation samples: {len(val_samples)}")
    print(f"Training file:      {TRAIN_FILE}")
    print(f"Validation file:    {VAL_FILE}")


if __name__ == "__main__":
    main()
