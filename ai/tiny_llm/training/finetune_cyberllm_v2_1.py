
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

# Preserve the v2.1 checkpoint and save this experiment separately.
OUTPUT_CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt"
)

MAX_SEQ_LEN = 512
BATCH_SIZE = 1
EPOCHS = 5
LEARNING_RATE = 1e-5
GRAD_CLIP = 1.0
SEED = 42

SOC_WEIGHT = 10.0
MITRE_WEIGHT = 1.0


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def causal_loss(logits, labels, criterion):
    """Next-token loss with prompt positions ignored."""
    shift_logits = logits[:, :-1, :].contiguous()
    shift_labels = labels[:, 1:].contiguous()

    return criterion(
        shift_logits.reshape(-1, shift_logits.size(-1)),
        shift_labels.reshape(-1),
    )


def make_sampler(dataset):
    weights = []
    source_counts = {}

    for example in dataset.examples:
        source = example.get("source", "unknown")

        if source == "curated_soc":
            weights.append(SOC_WEIGHT)
        elif source == "mitre_attack":
            weights.append(MITRE_WEIGHT)
        else:
            weights.append(1.0)

        source_counts[source] = source_counts.get(source, 0) + 1

    print("\n===== SAMPLER CONFIGURATION =====")
    for source, count in sorted(source_counts.items()):
        print(f"{source}: {count}")

    print(f"SOC sampling weight: {SOC_WEIGHT}")
    print(f"MITRE sampling weight: {MITRE_WEIGHT}")

    return WeightedRandomSampler(
        weights=weights,
        num_samples=len(dataset),
        replacement=True,
        generator=torch.Generator().manual_seed(SEED),
    )


def evaluate_by_source(model, dataset, criterion, device):
    """
    Evaluate each source independently.

    Batches remain size 1 because examples have variable sequence lengths.
    Losses are averaged per example, matching the existing evaluation style.
    """
    model.eval()

    source_totals = {}
    source_counts = {}

    with torch.no_grad():
        for index in range(len(dataset)):
            batch = dataset[index]
            input_ids = batch["input_ids"].unsqueeze(0).to(device)
            labels = batch["labels"].unsqueeze(0).to(device)

            logits = model(input_ids)
            loss = causal_loss(logits, labels, criterion)

            source = dataset.examples[index].get("source", "unknown")
            source_totals[source] = (
                source_totals.get(source, 0.0) + loss.item()
            )
            source_counts[source] = source_counts.get(source, 0) + 1

    source_means = {
        source: source_totals[source] / source_counts[source]
        for source in source_totals
    }

    total_count = sum(source_counts.values())
    overall = (
        sum(source_totals.values()) / total_count
        if total_count
        else float("inf")
    )

    return overall, source_means, source_counts


def main():
    print("===== CYBERLLM V2.2 SOURCE-METRICS EXPERIMENT =====")

    set_seed(SEED)

    if not TRAIN_FILE.exists():
        raise FileNotFoundError(f"Training data missing: {TRAIN_FILE}")
    if not VAL_FILE.exists():
        raise FileNotFoundError(f"Validation data missing: {VAL_FILE}")
    if not TOKENIZER_FILE.exists():
        raise FileNotFoundError(f"Tokenizer missing: {TOKENIZER_FILE}")
    if not BASE_CHECKPOINT.exists():
        raise FileNotFoundError(f"Baseline checkpoint missing: {BASE_CHECKPOINT}")

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

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        sampler=make_sampler(train_dataset),
    )

    base = torch.load(
        BASE_CHECKPOINT,
        map_location=device,
        weights_only=False,
    )

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

    OUTPUT_CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)

    print("\n===== TRAINING =====")

    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_train_loss = 0.0
        batches = 0

        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad(set_to_none=True)

            logits = model(input_ids)
            loss = causal_loss(logits, labels, criterion)

            if not torch.isfinite(loss):
                raise RuntimeError(
                    f"Non-finite training loss at epoch {epoch}, "
                    f"batch {batches + 1}"
                )

            loss.backward()

            torch.nn.utils.clip_grad_norm_(
                model.parameters(), GRAD_CLIP
            )
            optimizer.step()

            total_train_loss += loss.item()
            batches += 1

        train_loss = total_train_loss / max(batches, 1)

        overall_val, source_losses, source_counts = evaluate_by_source(
            model, val_dataset, criterion, device
        )

        soc_loss = source_losses.get("curated_soc", float("nan"))
        mitre_loss = source_losses.get("mitre_attack", float("nan"))

        print(
            f"Epoch {epoch:02d} | "
            f"Train: {train_loss:.4f} | "
            f"Val overall: {overall_val:.4f} | "
            f"Val SOC: {soc_loss:.4f} "
            f"(n={source_counts.get('curated_soc', 0)}) | "
            f"Val MITRE: {mitre_loss:.4f} "
            f"(n={source_counts.get('mitre_attack', 0)})"
        )

        # Keep checkpoint selection based on overall validation loss
        # for comparability with the previous experiment. SOC loss is
        # reported separately rather than silently changing the criterion.
        if overall_val < best_val_loss:
            best_val_loss = overall_val
            best_epoch = epoch

            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "vocab_size": tokenizer.vocab_size,
                    "max_seq_len": MAX_SEQ_LEN,
                    "epoch": epoch,
                    "val_loss": overall_val,
                    "val_soc_loss": soc_loss,
                    "val_mitre_loss": mitre_loss,
                    "val_soc_examples": source_counts.get("curated_soc", 0),
                    "val_mitre_examples": source_counts.get("mitre_attack", 0),
                    "learning_rate": LEARNING_RATE,
                    "base_checkpoint": str(BASE_CHECKPOINT),
                    "model_type": "CyberLLM-v2.2-source-metrics",
                    "loss_objective": "response_only_shifted_causal",
                    "train_examples": len(train_dataset),
                    "val_examples": len(val_dataset),
                    "seed": SEED,
                    "soc_weight": SOC_WEIGHT,
                    "mitre_weight": MITRE_WEIGHT,
                },
                OUTPUT_CHECKPOINT,
            )
            print("  -> Best overall-validation checkpoint saved.")

    print("\n===== TRAINING COMPLETE =====")
    print(f"Best overall validation loss: {best_val_loss:.4f}")
    print(f"Best epoch: {best_epoch}")
    print(f"Checkpoint: {OUTPUT_CHECKPOINT}")


if __name__ == "__main__":
    main()
