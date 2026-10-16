from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.cyber_bpe_instruction_dataset import (
    CyberBPEInstructionDataset,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TOKENIZER_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "cyber_bpe"
    / "tokenizer.json"
)

DATASET_FILE = (
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
    / "tiny_llm_cyber_bpe_small_best.pt"
)

CHECKPOINT_DIR = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
)

CHECKPOINT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


BATCH_SIZE = 1
EPOCHS = 10
LEARNING_RATE = 5e-5
MAX_SEQ_LEN = 512

TRAIN_RATIO = 0.9
SEED = 42


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

    if batches == 0:
        return float("inf")

    return total_loss / batches


def main():

    print(
        "===== CYBERLLM SMALL FINE-TUNING ====="
    )

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(f"Device: {device}")

    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    dataset = CyberBPEInstructionDataset(
        DATASET_FILE,
        tokenizer,
        max_seq_len=MAX_SEQ_LEN,
    )

    print(
        f"Total examples: {len(dataset)}"
    )

    train_size = int(
        len(dataset) * TRAIN_RATIO
    )

    val_size = len(dataset) - train_size

    generator = torch.Generator().manual_seed(
        SEED
    )

    train_dataset, val_dataset = random_split(
        dataset,
        [train_size, val_size],
        generator=generator,
    )

    print(
        f"Training examples: {len(train_dataset)}"
    )

    print(
        f"Validation examples: {len(val_dataset)}"
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

    base_checkpoint = torch.load(
        BASE_CHECKPOINT,
        map_location=device,
    )

    model = TinyLLMSmall(
        vocab_size=base_checkpoint["vocab_size"],
        max_seq_len=base_checkpoint["max_seq_len"],
        embed_dim=base_checkpoint["embed_dim"],
        num_heads=base_checkpoint["num_heads"],
        num_layers=base_checkpoint["num_layers"],
        ff_dim=base_checkpoint["ff_dim"],
    ).to(device)

    model.load_state_dict(
        base_checkpoint["model_state_dict"]
    )

    print(
        f"Loaded base checkpoint from epoch "
        f"{base_checkpoint['epoch']}"
    )

    print(
        f"Base validation loss: "
        f"{base_checkpoint['val_loss']:.4f}"
    )

    parameter_count = sum(
        parameter.numel()
        for parameter in model.parameters()
    )

    print(
        f"Model parameters: "
        f"{parameter_count:,}"
    )

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
    )

    criterion = nn.CrossEntropyLoss(
        ignore_index=-100
    )

    best_val_loss = float("inf")

    checkpoint_path = (
        CHECKPOINT_DIR
        / "cyberllm_small_v1_best.pt"
    )

    for epoch in range(
        1,
        EPOCHS + 1,
    ):

        model.train()

        total_loss = 0.0
        batches = 0

        for input_ids, target_ids in train_loader:

            input_ids = input_ids.to(device)
            target_ids = target_ids.to(device)

            optimizer.zero_grad()

            logits = model(input_ids)

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

            total_loss += loss.item()
            batches += 1

        train_loss = (
            total_loss / batches
            if batches
            else float("inf")
        )

        val_loss = evaluate(
            model,
            val_loader,
            criterion,
            device,
        )

        print(
            f"Epoch {epoch:02d}/{EPOCHS} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f}"
        )

        if val_loss < best_val_loss:

            best_val_loss = val_loss

            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "vocab_size": base_checkpoint[
                        "vocab_size"
                    ],
                    "max_seq_len": MAX_SEQ_LEN,
                    "embed_dim": base_checkpoint[
                        "embed_dim"
                    ],
                    "num_heads": base_checkpoint[
                        "num_heads"
                    ],
                    "num_layers": base_checkpoint[
                        "num_layers"
                    ],
                    "ff_dim": base_checkpoint[
                        "ff_dim"
                    ],
                    "epoch": epoch,
                    "val_loss": val_loss,
                    "model_type": "CyberLLM-Small-v1",
                    "tokenizer": "cyber_bpe",
                    "base_checkpoint": str(
                        BASE_CHECKPOINT
                    ),
                    "loss_objective": "response_only",
                },
                checkpoint_path,
            )

            print(
                f"  Saved best checkpoint: "
                f"{checkpoint_path}"
            )

    print()
    print(
        "===== FINE-TUNING COMPLETE ====="
    )
    print(
        f"Best validation loss: "
        f"{best_val_loss:.4f}"
    )
    print(
        f"Checkpoint: {checkpoint_path}"
    )


if __name__ == "__main__":
    main()
