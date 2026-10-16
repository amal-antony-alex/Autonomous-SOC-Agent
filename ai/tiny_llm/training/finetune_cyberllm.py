from pathlib import Path
import math

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split

from ai.tiny_llm.model.tiny_llm import TinyLLM
from ai.tiny_llm.tokenizer.bpe_tokenizer import BPETokenizer
from ai.tiny_llm.training.instruction_dataset import (
    CybersecurityInstructionDataset,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]


TOKENIZER_PATH = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "tokenizer.json"
)


DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_instruction_dataset.jsonl"
)


BASE_CHECKPOINT = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
    / "tiny_llm_best.pt"
)


# CyberLLM v1.1 is kept separate from the original v1 checkpoint.
OUTPUT_CHECKPOINT = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
    / "cyberllm_v1_1.pt"
)


MAX_SEQ_LEN = 512
BATCH_SIZE = 1
EPOCHS = 5
LEARNING_RATE = 5e-5
VALIDATION_SPLIT = 0.1
SEED = 42


def calculate_perplexity(loss):
    return math.exp(
        min(loss, 20)
    )


def evaluate(
    model,
    dataloader,
    criterion,
    device,
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
                logits.reshape(
                    -1,
                    logits.size(-1),
                ),
                target_ids.reshape(-1),
            )

            total_loss += loss.item()
            batches += 1

    return total_loss / max(batches, 1)


def main():

    torch.manual_seed(SEED)

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(
        f"Training device: {device}"
    )

    print(
        f"Loading tokenizer: {TOKENIZER_PATH}"
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

    print(
        f"Loading instruction dataset: {DATASET_PATH}"
    )

    full_dataset = CybersecurityInstructionDataset(
        DATASET_PATH,
        tokenizer,
        MAX_SEQ_LEN,
    )

    print(
        f"Total instruction examples: "
        f"{len(full_dataset)}"
    )

    validation_size = max(
        1,
        int(
            len(full_dataset)
            * VALIDATION_SPLIT
        ),
    )

    training_size = (
        len(full_dataset)
        - validation_size
    )

    train_dataset, val_dataset = random_split(
        full_dataset,
        [training_size, validation_size],
        generator=torch.Generator().manual_seed(SEED),
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        shuffle=True,
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
    )

    print(
        f"Training examples: {len(train_dataset)}"
    )

    print(
        f"Validation examples: {len(val_dataset)}"
    )

    print(
        f"Loading base TinyLLM checkpoint: "
        f"{BASE_CHECKPOINT}"
    )

    model = TinyLLM(
        vocab_size=vocab_size
    ).to(device)

    checkpoint = torch.load(
        BASE_CHECKPOINT,
        map_location=device,
    )

    if "model_state_dict" in checkpoint:

        model.load_state_dict(
            checkpoint["model_state_dict"]
        )

    else:

        model.load_state_dict(
            checkpoint
        )

    print(
        "Base TinyLLM checkpoint loaded."
    )

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
    )

    # Ignore prompt tokens marked as -100.
    # Only response tokens contribute to the loss.
    criterion = nn.CrossEntropyLoss(
        ignore_index=-100
    )

    best_val_loss = float("inf")

    print(
        "\n===== CYBERLLM V1.1 FINE-TUNING ====="
    )

    print(
        f"Epochs: {EPOCHS}"
    )

    print(
        f"Learning rate: {LEARNING_RATE}"
    )

    print(
        "Loss objective: response tokens only"
    )

    for epoch in range(
        1,
        EPOCHS + 1,
    ):

        model.train()

        total_train_loss = 0.0
        train_batches = 0

        for input_ids, target_ids in train_loader:

            input_ids = input_ids.to(device)
            target_ids = target_ids.to(device)

            optimizer.zero_grad()

            logits = model(
                input_ids
            )

            loss = criterion(
                logits.reshape(
                    -1,
                    logits.size(-1),
                ),
                target_ids.reshape(-1),
            )

            loss.backward()

            torch.nn.utils.clip_grad_norm_(
                model.parameters(),
                max_norm=1.0,
            )

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
            device,
        )

        train_ppl = calculate_perplexity(
            train_loss
        )

        val_ppl = calculate_perplexity(
            val_loss
        )

        print(
            f"Epoch {epoch:02d}/{EPOCHS} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f} | "
            f"Train PPL: {train_ppl:.2f} | "
            f"Val PPL: {val_ppl:.2f}"
        )

        if val_loss < best_val_loss:

            best_val_loss = val_loss

            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "vocab_size": vocab_size,
                    "max_seq_len": MAX_SEQ_LEN,
                    "epoch": epoch,
                    "val_loss": val_loss,
                    "learning_rate": LEARNING_RATE,
                    "base_checkpoint": str(
                        BASE_CHECKPOINT
                    ),
                    "model_type": "CyberLLM-v1.1",
                    "loss_objective": "response_only",
                },
                OUTPUT_CHECKPOINT,
            )

            print(
                f"Saved best CyberLLM v1.1 checkpoint: "
                f"{OUTPUT_CHECKPOINT}"
            )

    print(
        "\n===== FINE-TUNING COMPLETE ====="
    )

    print(
        f"Best validation loss: "
        f"{best_val_loss:.4f}"
    )

    print(
        f"CyberLLM v1.1 checkpoint: "
        f"{OUTPUT_CHECKPOINT}"
    )


if __name__ == "__main__":
    main()
