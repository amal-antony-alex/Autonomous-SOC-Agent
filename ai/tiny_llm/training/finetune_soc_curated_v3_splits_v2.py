import json
import random
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.utils.data import DataLoader, Dataset

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


ROOT = Path.cwd()
SPLIT_DIR = ROOT / "data/processed/soc_curated_v3/sft_splits_v2"
TOKENIZER_PATH = ROOT / "ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json"
BASE_CHECKPOINT = ROOT / "ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt"
OUTPUT_DIR = ROOT / "ai/tiny_llm/checkpoints/soc_curated_v3_splits_v2"

SEED = 20261024
EPOCHS = 3
BATCH_SIZE = 1
MAX_SEQ_LEN = 512
LEARNING_RATE = 5e-6
WEIGHT_DECAY = 0.01
GRAD_CLIP = 1.0
PATIENCE = 2


def seed_everything():
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)


def load_jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path}, line {line_number}: {exc}"
                ) from exc
    return rows


class SOCInstructionDataset(Dataset):
    """
    Instruction-tuning dataset:
    - only response tokens contribute to loss
    - retains the full response when it fits within the context window
    - trims input context before trimming instruction or response
    """

    def __init__(self, path, tokenizer, max_seq_len):
        self.path = path
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len
        self.examples = load_jsonl(path)
        self.truncated_prompts = 0
        self.response_too_long = 0

        if not self.examples:
            raise ValueError(f"Empty dataset: {path}")

        required = {
            "scenario_id", "scenario_family", "category",
            "instruction", "input", "output",
        }
        for index, row in enumerate(self.examples):
            if set(row) != required:
                raise ValueError(
                    f"{path}: record {index} has unexpected schema fields."
                )
            if not all(isinstance(row[k], str) and row[k].strip()
                       for k in required):
                raise ValueError(
                    f"{path}: record {index} has empty/invalid fields."
                )

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, index):
        row = self.examples[index]

        instruction_prefix = (
            "Instruction:\n"
            + row["instruction"]
            + "\n\nInput:\n"
        )
        input_text = row["input"] + "\n\nResponse:\n"

        # BOS belongs at the beginning of the prompt.
        prefix_ids = self.tokenizer.encode(
            instruction_prefix, add_bos=True, add_eos=False
        )
        input_ids = self.tokenizer.encode(
            input_text, add_bos=False, add_eos=False
        )
        response_ids = self.tokenizer.encode(
            row["output"], add_bos=False, add_eos=True
        )

        if len(response_ids) >= self.max_seq_len:
            # Keep the final EOS token and the response tail only when the
            # response itself exceeds the full model context.
            response_ids = (
                response_ids[: self.max_seq_len - 1]
                + [response_ids[-1]]
            )
            self.response_too_long += 1

        prompt_budget = self.max_seq_len - len(response_ids)

        # Preserve instruction prefix when possible; trim input context first.
        if len(prefix_ids) + len(input_ids) > prompt_budget:
            self.truncated_prompts += 1
            input_budget = max(0, prompt_budget - len(prefix_ids))
            if len(prefix_ids) > prompt_budget:
                # Exceptional case: preserve BOS and the end of the
                # instruction prefix so the prompt still fits.
                if prompt_budget <= 1:
                    prefix_ids = prefix_ids[:prompt_budget]
                else:
                    prefix_ids = (
                        prefix_ids[:1]
                        + prefix_ids[-(prompt_budget - 1):]
                    )
                input_ids = []
            else:
                # Retain the latest input tokens when shortening context.
                input_ids = input_ids[-input_budget:] if input_budget else []

        prompt_ids = prefix_ids + input_ids
        available_response = self.max_seq_len - len(prompt_ids)
        if len(response_ids) > available_response:
            response_ids = response_ids[:available_response]
            if response_ids:
                response_ids[-1] = self.tokenizer.token_to_id.get(
                    "<EOS>", response_ids[-1]
                )

        ids = prompt_ids + response_ids
        labels = [-100] * len(prompt_ids) + response_ids

        if len(ids) != len(labels) or not ids:
            raise RuntimeError(f"Invalid encoded record: {row['scenario_id']}")

        return {
            "input_ids": torch.tensor(ids, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
            "category": row["category"],
        }


def causal_loss(logits, labels, criterion):
    return criterion(
        logits[:, :-1, :].contiguous().reshape(-1, logits.size(-1)),
        labels[:, 1:].contiguous().reshape(-1),
    )


def evaluate(model, dataset, criterion, device):
    model.eval()
    totals = defaultdict(float)
    counts = Counter()
    token_totals = defaultdict(int)
    overall_total = 0.0
    overall_count = 0

    with torch.no_grad():
        for item in dataset:
            ids = item["input_ids"].unsqueeze(0).to(device)
            labels = item["labels"].unsqueeze(0).to(device)
            category = item["category"]

            logits = model(ids)
            loss = causal_loss(logits, labels, criterion)

            valid_tokens = int((labels[:, 1:] != -100).sum().item())
            if valid_tokens == 0:
                continue

            # Per-example mean loss; aggregate equally by example.
            value = float(loss.item())
            totals[category] += value
            counts[category] += 1
            token_totals[category] += valid_tokens
            overall_total += value
            overall_count += 1

    if overall_count == 0:
        raise RuntimeError("Evaluation produced no valid response tokens.")

    return {
        "loss": overall_total / overall_count,
        "examples": overall_count,
        "category_losses": {
            category: totals[category] / counts[category]
            for category in sorted(totals)
        },
        "category_examples": dict(sorted(counts.items())),
        "category_response_tokens": dict(sorted(token_totals.items())),
    }


def save_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main():
    seed_everything()

    required_paths = [
        TOKENIZER_PATH,
        BASE_CHECKPOINT,
        SPLIT_DIR / "train.jsonl",
        SPLIT_DIR / "validation.jsonl",
        SPLIT_DIR / "test.jsonl",
    ]
    for path in required_paths:
        if not path.is_file():
            raise FileNotFoundError(f"Required file missing: {path}")

    if OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        raise FileExistsError(
            f"Output directory is not empty: {OUTPUT_DIR}\n"
            "Refusing to overwrite previous experiment results."
        )
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    tokenizer = CyberBPETokenizer(TOKENIZER_PATH)
    base = torch.load(
        BASE_CHECKPOINT, map_location="cpu", weights_only=True
    )

    if tokenizer.vocab_size != base["vocab_size"]:
        raise ValueError(
            f"Tokenizer vocab {tokenizer.vocab_size} != "
            f"checkpoint vocab {base['vocab_size']}"
        )

    train_ds = SOCInstructionDataset(
        SPLIT_DIR / "train.jsonl", tokenizer, MAX_SEQ_LEN
    )
    val_ds = SOCInstructionDataset(
        SPLIT_DIR / "validation.jsonl", tokenizer, MAX_SEQ_LEN
    )

    # The test split is intentionally not loaded or evaluated here.
    print(f"Training examples: {len(train_ds)}")
    print(f"Validation examples: {len(val_ds)}")
    print(f"Context length: {MAX_SEQ_LEN}")
    print(f"Learning rate: {LEARNING_RATE}")
    print(f"Epoch limit: {EPOCHS}")
    print("Held-out test set: untouched")

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

    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    baseline = evaluate(model, val_ds, criterion, device)
    print(f"\nBaseline validation loss: {baseline['loss']:.6f}")
    print("Baseline category losses:")
    for category, loss in baseline["category_losses"].items():
        print(f"  {category}: {loss:.6f}")

    save_json(OUTPUT_DIR / "baseline_validation.json", baseline)

    loader = DataLoader(
        train_ds,
        batch_size=BATCH_SIZE,
        shuffle=True,
        generator=torch.Generator().manual_seed(SEED),
    )

    optimizer = AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
        weight_decay=WEIGHT_DECAY,
    )

    best_loss = baseline["loss"]
    best_epoch = 0
    stale_epochs = 0
    history = []

    # Save an initial baseline checkpoint so the best result can never be
    # worse than the original model on this validation split.
    best_path = OUTPUT_DIR / "best_validation.pt"
    torch.save(
        {
            **base,
            "model_state_dict": model.state_dict(),
            "model_type": "CyberLLM-SOC-curated-v3-splits-v2",
            "epoch": 0,
            "val_loss": best_loss,
            "base_checkpoint": str(BASE_CHECKPOINT),
            "split_dir": str(SPLIT_DIR),
            "seed": SEED,
        },
        best_path,
    )

    for epoch in range(1, EPOCHS + 1):
        model.train()
        running_loss = 0.0
        batches = 0

        for batch in loader:
            ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad(set_to_none=True)
            logits = model(ids)
            loss = causal_loss(logits, labels, criterion)

            if not torch.isfinite(loss):
                raise RuntimeError(f"Non-finite loss in epoch {epoch}")

            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                model.parameters(), GRAD_CLIP
            )
            optimizer.step()

            running_loss += float(loss.item())
            batches += 1

        val_metrics = evaluate(model, val_ds, criterion, device)
        train_loss = running_loss / max(batches, 1)

        result = {
            "epoch": epoch,
            "train_loss": train_loss,
            "validation": val_metrics,
            "learning_rate": LEARNING_RATE,
        }
        history.append(result)

        print(
            f"\nEpoch {epoch}/{EPOCHS} | "
            f"train loss={train_loss:.6f} | "
            f"validation loss={val_metrics['loss']:.6f}"
        )
        for category, loss in val_metrics["category_losses"].items():
            print(f"  {category}: {loss:.6f}")

        checkpoint = {
            "model_state_dict": model.state_dict(),
            "vocab_size": tokenizer.vocab_size,
            "max_seq_len": base["max_seq_len"],
            "epoch": epoch,
            "train_loss": train_loss,
            "val_loss": val_metrics["loss"],
            "val_category_losses": val_metrics["category_losses"],
            "val_category_examples": val_metrics["category_examples"],
            "learning_rate": LEARNING_RATE,
            "base_checkpoint": str(BASE_CHECKPOINT),
            "model_type": "CyberLLM-SOC-curated-v3-splits-v2",
            "train_examples": len(train_ds),
            "val_examples": len(val_ds),
            "seed": SEED,
            "max_context_length": MAX_SEQ_LEN,
        }

        torch.save(checkpoint, OUTPUT_DIR / f"epoch_{epoch}.pt")
        save_json(OUTPUT_DIR / "metrics.json", {
            "baseline": baseline,
            "history": history,
            "best_epoch": best_epoch,
            "best_validation_loss": best_loss,
            "test_evaluated": False,
        })

        if val_metrics["loss"] < best_loss:
            best_loss = val_metrics["loss"]
            best_epoch = epoch
            stale_epochs = 0
            torch.save(checkpoint, best_path)
            print(f"  New best checkpoint saved: {best_path}")
        else:
            stale_epochs += 1
            print(f"  No validation improvement ({stale_epochs}/{PATIENCE})")

        if stale_epochs >= PATIENCE:
            print("Early stopping: validation loss did not improve.")
            break

    save_json(OUTPUT_DIR / "metrics.json", {
        "baseline": baseline,
        "history": history,
        "best_epoch": best_epoch,
        "best_validation_loss": best_loss,
        "best_checkpoint": str(best_path),
        "test_evaluated": False,
        "training_truncated_prompt_counts": {
            "train": train_ds.truncated_prompts,
            "validation": val_ds.truncated_prompts,
        },
        "responses_over_context_counts": {
            "train": train_ds.response_too_long,
            "validation": val_ds.response_too_long,
        },
    })

    print("\n=== TRAINING COMPLETE ===")
    print(f"Baseline validation loss: {baseline['loss']:.6f}")
    print(f"Best validation loss: {best_loss:.6f}")
    print(f"Best epoch: {best_epoch} (0 means base checkpoint)")
    print(f"Saved results: {OUTPUT_DIR}")
    print("Held-out test set was not used.")


if __name__ == "__main__":
    main()
