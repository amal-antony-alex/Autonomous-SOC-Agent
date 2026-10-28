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

TRAIN = Path("data/processed/soc_curated_v3/final/train.jsonl")
VAL = Path("data/processed/soc_curated_v3/final/val_mitre.jsonl")
TOKENIZER = Path("ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json")
BASE = Path("ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt")
OUT = Path("ai/tiny_llm/checkpoints/soc_curated_v3_experiment.pt")

SEED = 42
EPOCHS = 5
BATCH_SIZE = 1
MAX_SEQ_LEN = 512
LR = 1e-5
SOC_WEIGHT = 10.0
MITRE_WEIGHT = 1.0


def seed_everything():
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)


def causal_loss(logits, labels, criterion):
    return criterion(
        logits[:, :-1, :].contiguous().reshape(-1, logits.size(-1)),
        labels[:, 1:].contiguous().reshape(-1),
    )


def evaluate(model, dataset, criterion, device):
    model.eval()
    totals, counts = {}, {}

    with torch.no_grad():
        for i in range(len(dataset)):
            item = dataset[i]
            ids = item["input_ids"].unsqueeze(0).to(device)
            labels = item["labels"].unsqueeze(0).to(device)
            loss = causal_loss(model(ids), labels, criterion).item()
            source = dataset.examples[i].get("source", "unknown")
            totals[source] = totals.get(source, 0.0) + loss
            counts[source] = counts.get(source, 0) + 1

    means = {s: totals[s] / counts[s] for s in totals}
    overall = sum(totals.values()) / max(sum(counts.values()), 1)
    return overall, means, counts


def main():
    seed_everything()

    for path in (TRAIN, VAL, TOKENIZER, BASE):
        if not path.exists():
            raise FileNotFoundError(f"Required file missing: {path}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device} (CUDA available: {torch.cuda.is_available()})")

    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER)

    train_ds = CyberLLMv2Dataset(TRAIN, tokenizer, max_seq_len=MAX_SEQ_LEN)
    val_ds = CyberLLMv2Dataset(VAL, tokenizer, max_seq_len=MAX_SEQ_LEN)

    weights = []
    source_counts = {}
    for ex in train_ds.examples:
        source = ex.get("source", "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        weights.append(
            SOC_WEIGHT if "soc" in source.lower()
            else MITRE_WEIGHT
        )

    print(f"Training examples: {len(train_ds)}")
    print(f"Validation examples: {len(val_ds)}")
    print(f"Training sources: {source_counts}")
    print("SOC examples are upweighted for sampling; this does not add new data.")

    sampler = WeightedRandomSampler(
        weights, num_samples=len(train_ds), replacement=True,
        generator=torch.Generator().manual_seed(SEED),
    )
    loader = DataLoader(train_ds, batch_size=BATCH_SIZE, sampler=sampler)

    base = torch.load(BASE, map_location=device, weights_only=False)
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

    optimizer = AdamW(model.parameters(), lr=LR)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    print("\nStarting training. Test sets are not used here.")
    for epoch in range(1, EPOCHS + 1):
        model.train()
        running, batches = 0.0, 0

        for batch in loader:
            ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)
            optimizer.zero_grad(set_to_none=True)
            loss = causal_loss(model(ids), labels, criterion)

            if not torch.isfinite(loss):
                raise RuntimeError(f"Non-finite loss at epoch {epoch}")

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            running += loss.item()
            batches += 1

        val_loss, source_losses, counts = evaluate(
            model, val_ds, criterion, device
        )
        print(
            f"Epoch {epoch}/{EPOCHS} | "
            f"Train loss={running / max(batches, 1):.4f} | "
            f"MITRE validation loss={val_loss:.4f} | "
            f"validation sources={counts}"
        )

        # Save each epoch separately for later comparison; never select
        # an epoch using the held-out SOC or MITRE test sets.
        checkpoint = {
            "model_state_dict": model.state_dict(),
            "vocab_size": tokenizer.vocab_size,
            "max_seq_len": base["max_seq_len"],
            "epoch": epoch,
            "val_loss": val_loss,
            "val_source_losses": source_losses,
            "val_source_counts": counts,
            "learning_rate": LR,
            "base_checkpoint": str(BASE),
            "model_type": "CyberLLM-SOC-curated-v3-experiment",
            "train_examples": len(train_ds),
            "val_examples": len(val_ds),
            "seed": SEED,
            "soc_weight": SOC_WEIGHT,
            "mitre_weight": MITRE_WEIGHT,
        }
        epoch_path = OUT.with_name(f"{OUT.stem}_epoch{epoch}{OUT.suffix}")
        torch.save(checkpoint, epoch_path)
        print(f"Saved: {epoch_path}")

    print("\nTraining complete.")
    print("No held-out test data was used for training or checkpoint selection.")
    print("Evaluate the saved epochs against the untouched test sets next.")


if __name__ == "__main__":
    main()
