from pathlib import Path
import math

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from ai.tiny_llm.model.tiny_llm import TinyLLM
from ai.tiny_llm.tokenizer.bpe_tokenizer import BPETokenizer
from ai.tiny_llm.training.dataset import CybersecurityDataset


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TOKENIZER_PATH = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "tokenizer.json"
)

TRAIN_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "train.txt"
)

VAL_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "val.txt"
)

CHECKPOINT_DIR = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
)

CHECKPOINT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


BATCH_SIZE = 1
EPOCHS = 20
LEARNING_RATE = 3e-4
MAX_SEQ_LEN = 512


def calculate_perplexity(loss):
    return math.exp(
        min(loss, 20)
    )


def evaluate(
    model,
    dataloader,
    criterion,
    device
):
    model.eval()

    total_loss = 0.0
    batches = 0

    with torch.no_grad():

        for input_ids, target_ids in dataloader:

            input_ids = input_ids.to(device)
            target_ids = target_ids.to(device)

            logits = model(input_ids)

            loss = criterion(
                logits.reshape(-1, logits.size(-1)),
                target_ids.reshape(-1)
            )

            total_loss += loss.item()
            batches += 1

    return total_loss / max(batches, 1)


def main():

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(
        f"Training device: {device}"
    )

    tokenizer = BPETokenizer()

    tokenizer.load(
        TOKENIZER_PATH
    )

    vocab_size = len(
        tokenizer.token_to_id
    )

    print(
        f"Vocabulary size: {vocab_size}"
    )

    train_dataset = CybersecurityDataset(
        TRAIN_FILE,
        tokenizer,
        MAX_SEQ_LEN
    )

    val_dataset = CybersecurityDataset(
        VAL_FILE,
        tokenizer,
        MAX_SEQ_LEN
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        shuffle=True
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False
    )

    model = TinyLLM(
        vocab_size=vocab_size
    ).to(device)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=LEARNING_RATE
    )

    criterion = nn.CrossEntropyLoss()

    best_val_loss = float("inf")

    print(
        f"Training examples: {len(train_dataset)}"
    )

    print(
        f"Validation examples: {len(val_dataset)}"
    )

    print(
        f"Epochs: {EPOCHS}"
    )

    print("\n===== TRAINING =====")

    for epoch in range(1, EPOCHS + 1):

        model.train()

        total_train_loss = 0.0
        train_batches = 0

        for input_ids, target_ids in train_loader:

            input_ids = input_ids.to(device)
            target_ids = target_ids.to(device)

            optimizer.zero_grad()

            logits = model(input_ids)

            loss = criterion(
                logits.reshape(
                    -1,
                    logits.size(-1)
                ),
                target_ids.reshape(-1)
            )

            loss.backward()

            optimizer.step()

            total_train_loss += loss.item()
            train_batches += 1

        train_loss = (
            total_train_loss
            / max(train_batches, 1)
        )

        val_loss = evaluate(
            model,
            val_loader,
            criterion,
            device
        )

        train_perplexity = calculate_perplexity(
            train_loss
        )

        val_perplexity = calculate_perplexity(
            val_loss
        )

        print(
            f"Epoch {epoch:02d}/{EPOCHS} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f} | "
            f"Train PPL: {train_perplexity:.2f} | "
            f"Val PPL: {val_perplexity:.2f}"
        )

        if val_loss < best_val_loss:

            best_val_loss = val_loss

            checkpoint_path = (
                CHECKPOINT_DIR
                / "tiny_llm_best.pt"
            )

            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "train_loss": train_loss,
                    "val_loss": val_loss,
                    "vocab_size": vocab_size,
                },
                checkpoint_path
            )

            print(
                f"  Saved best checkpoint: "
                f"{checkpoint_path}"
            )

    print("\n===== TRAINING COMPLETE =====")
    print(
        f"Best validation loss: "
        f"{best_val_loss:.4f}"
    )
    print(
        f"Best validation perplexity: "
        f"{calculate_perplexity(best_val_loss):.2f}"
    )


if __name__ == "__main__":
    main()
