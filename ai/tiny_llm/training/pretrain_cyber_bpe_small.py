from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.cyber_bpe_dataset import CyberBPEDataset


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

TRAIN_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cyber_bpe"
    / "train.txt"
)

VAL_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cyber_bpe"
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
    exist_ok=True,
)

BATCH_SIZE = 1
EPOCHS = 30
LEARNING_RATE = 3e-4
MAX_SEQ_LEN = 512


def evaluate(model, dataloader, criterion, device):

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
                target_ids.reshape(-1),
            )

            total_loss += loss.item()
            batches += 1

    if batches == 0:
        return float("inf")

    return total_loss / batches


def main():

    print("===== CYBER BPE TINYLLM SMALL PRETRAINING =====")

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(f"Device: {device}")

    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    vocab_size = tokenizer.vocab_size

    print(f"Vocabulary size: {vocab_size}")

    train_dataset = CyberBPEDataset(
        TRAIN_FILE,
        tokenizer,
        MAX_SEQ_LEN,
    )

    val_dataset = CyberBPEDataset(
        VAL_FILE,
        tokenizer,
        MAX_SEQ_LEN,
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

    model = TinyLLMSmall(
        vocab_size=vocab_size,
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=MAX_SEQ_LEN,
    ).to(device)

    parameter_count = sum(
        parameter.numel()
        for parameter in model.parameters()
    )

    print(
        f"Model parameters: {parameter_count:,}"
    )

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
    )

    criterion = nn.CrossEntropyLoss()

    best_val_loss = float("inf")

    checkpoint_path = (
        CHECKPOINT_DIR
        / "tiny_llm_cyber_bpe_small_best.pt"
    )

    for epoch in range(1, EPOCHS + 1):

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
                    "vocab_size": vocab_size,
                    "max_seq_len": MAX_SEQ_LEN,
                    "embed_dim": 128,
                    "num_heads": 4,
                    "num_layers": 2,
                    "ff_dim": 512,
                    "epoch": epoch,
                    "val_loss": val_loss,
                    "model_type": "TinyLLM-CyberBPE-Small",
                    "tokenizer": "cyber_bpe",
                },
                checkpoint_path,
            )

            print(
                f"  Saved best checkpoint: "
                f"{checkpoint_path}"
            )

    print()
    print("===== PRETRAINING COMPLETE =====")
    print(
        f"Best validation loss: "
        f"{best_val_loss:.4f}"
    )
    print(
        f"Checkpoint: {checkpoint_path}"
    )


if __name__ == "__main__":
    main()
