import torch
from ai.tiny_llm.tokenizer.bpe_tokenizer import BPETokenizer
from ai.tiny_llm.training.dataset import CybersecurityDataset


TOKENIZER_PATH = (
    "ai/tiny_llm/tokenizer/artifacts/tokenizer.json"
)

TRAIN_FILE = "data/processed/train.txt"
VAL_FILE = "data/processed/val.txt"


def main():

    tokenizer = BPETokenizer()

    tokenizer.load(
        TOKENIZER_PATH
    )

    train_dataset = CybersecurityDataset(
        TRAIN_FILE,
        tokenizer
    )

    val_dataset = CybersecurityDataset(
        VAL_FILE,
        tokenizer
    )

    print("===== DATASET TEST =====")
    print(
        f"Vocabulary size: {len(tokenizer.token_to_id)}"
    )
    print(
        f"Training examples: {len(train_dataset)}"
    )
    print(
        f"Validation examples: {len(val_dataset)}"
    )

    train_input, train_target = train_dataset[0]

    print("\n===== FIRST TRAINING EXAMPLE =====")
    print(
        f"Input shape:  {train_input.shape}"
    )
    print(
        f"Target shape: {train_target.shape}"
    )

    print("\nInput IDs:")
    print(train_input[:20])

    print("\nTarget IDs:")
    print(train_target[:20])

    print("\n===== SHIFT CHECK =====")

    if torch.equal(
        train_input[1:],
        train_target[:-1]
    ):
        print(
            "Input/target shift: PASSED"
        )
    else:
        print(
            "Input/target shift: FAILED"
        )


if __name__ == "__main__":
    main()

