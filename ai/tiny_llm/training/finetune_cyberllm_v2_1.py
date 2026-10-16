
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.utils.data import DataLoader, WeightedRandomSampler

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.cyberllm_v2_dataset import CyberLLMv2Dataset


TRAIN_FILE = Path("data/processed/cyberllm_v2/train.jsonl")
VAL_FILE = Path("data/processed/cyberllm_v2/val.jsonl")
TOKENIZER_FILE = Path(
    "ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json"
)
BASE_CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/cyberllm_v2_shifted_best.pt"
)
OUTPUT_CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/cyberllm_v2_1_soc_balanced_best.pt"
)

MAX_SEQ_LEN = 512
BATCH_SIZE = 1
EPOCHS = 5
LEARNING_RATE = 1e-5
GRAD_CLIP = 1.0
SEED = 42

# Increase SOC exposure without discarding MITRE examples.
# These are sampling weights, not changes to the dataset.
SOC_WEIGHT = 10.0
MITRE_WEIGHT = 1.0


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def causal_loss(logits, labels, criterion):
    # Predict the next token, not the token at the same position.
    shift_logits = logits[:, :-1, :].contiguous()
    shift_labels = labels[:, 1:].contiguous()

    return criterion(
        shift_logits.view(-1, shift_logits.size(-1)),
        shift_labels.view(-1),
    )


def make_sampler(dataset):
    weights = []

    soc_count = 0
    mitre_count = 0

    for example in dataset.examples:
        source = example.get("source", "unknown")

        if source == "curated_soc":
            weights.append(SOC_WEIGHT)
            soc_count += 1
        elif source == "mitre_attack":
            weights.append(MITRE_WEIGHT)
            mitre_count += 1
        else:
            weights.append(1.0)

    print(f"SOC examples: {soc_count}")
    print(f"MITRE examples: {mitre_count}")
    print(f"SOC sampling weight: {SOC_WEIGHT}")
    print(f"MITRE sampling weight: {MITRE_WEIGHT}")

    sampler = WeightedRandomSampler(
        weights=weights,
        num_samples=len(dataset),
        replacement=True,
        generator=torch.Generator().manual_seed(SEED),
    )

    return sampler


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    batches = 0

    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)

            logits = model(input_ids)
            loss = causal_loss(logits, labels, criterion)

            total_loss += loss.item()
            batches += 1

    return total_loss / max(batches, 1)


def main():
    print("===== CYBERLLM V2.1 SOC-BALANCED FINE-TUNING =====")

    set_seed(SEED)

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )
    print(f"Device: {device}")

    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER_FILE)
    print(f"Tokenizer vocabulary: {tokenizer.vocab_size}")

    train_dataset = CyberLLMv2Dataset(
        TRAIN_FILE, tokenizer, max_seq_len=MAX_SEQ_LEN
    )
    val_dataset = CyberLLMv2Dataset(
        VAL_FILE, tokenizer, max_seq_len=MAX_SEQ_LEN
    )

    print(f"Training examples: {len(train_dataset)}")
    print(f"Validation examples: {len(val_dataset)}")

    sampler = make_sampler(train_dataset)

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        sampler=sampler,
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
    )

    base = torch.load(BASE_CHECKPOINT, map_location=device)

    model = TinyLLMSmall(
        vocab_size=base["vocab_size"],
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=base["max_seq_len"],
        dropout=0.1,
    )
    model.load_state_dict(base["model_state_dict"])
    model.to(device)

    optimizer = AdamW(model.parameters(), lr=LEARNING_RATE)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    best_val_loss = float("inf")
    best_epoch = 0

    print("\n===== TRAINING =====")

    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_train_loss = 0.0
        batches = 0

        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad()
            logits = model(input_ids)
            loss = causal_loss(logits, labels, criterion)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                model.parameters(), GRAD_CLIP
            )
            optimizer.step()

            total_train_loss += loss.item()
            batches += 1

        train_loss = total_train_loss / max(batches, 1)
        val_loss = evaluate(
            model, val_loader, criterion, device
        )

        print(
            f"Epoch {epoch:02d} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f}"
        )

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch

            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "vocab_size": tokenizer.vocab_size,
                    "max_seq_len": MAX_SEQ_LEN,
                    "epoch": epoch,
                    "val_loss": val_loss,
                    "learning_rate": LEARNING_RATE,
                    "base_checkpoint": str(BASE_CHECKPOINT),
                    "model_type": "CyberLLM-v2.1-SOC-balanced",
                    "loss_objective": "response_only_shifted_causal",
                    "train_examples": len(train_dataset),
                    "val_examples": len(val_dataset),
                    "seed": SEED,
                    "soc_weight": SOC_WEIGHT,
                    "mitre_weight": MITRE_WEIGHT,
                },
                OUTPUT_CHECKPOINT,
            )
            print("  -> Best checkpoint saved.")

    print("\n===== TRAINING COMPLETE =====")
    print(f"Best validation loss: {best_val_loss:.4f}")
    print(f"Best epoch: {best_epoch}")
    print(f"Checkpoint: {OUTPUT_CHECKPOINT}")


if __name__ == "__main__":
    main()
