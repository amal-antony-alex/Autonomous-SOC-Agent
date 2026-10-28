import json
from collections import Counter, defaultdict
from pathlib import Path

import torch
import torch.nn as nn

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.finetune_soc_curated_v3_splits_v2 import (
    SOCInstructionDataset,
)

ROOT = Path.cwd()
TEST_FILE = ROOT / "data/processed/soc_curated_v3/sft_splits_v2/test.jsonl"
TOKENIZER_FILE = ROOT / "ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json"

BASE_CHECKPOINT = (
    ROOT / "ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt"
)
FINE_TUNED_CHECKPOINT = (
    ROOT / "ai/tiny_llm/checkpoints/soc_curated_v3_splits_v2/best_validation.pt"
)

OUTPUT_DIR = ROOT / "ai/tiny_llm/evaluations/soc_curated_v3_splits_v2"
OUTPUT_FILE = OUTPUT_DIR / "test_comparison.json"
MAX_SEQ_LEN = 512


def causal_loss(logits, labels, criterion):
    return criterion(
        logits[:, :-1, :].contiguous().reshape(-1, logits.size(-1)),
        labels[:, 1:].contiguous().reshape(-1),
    )


def evaluate_checkpoint(path, model, dataset, criterion, device):
    checkpoint = torch.load(path, map_location="cpu", weights_only=True)

    if checkpoint.get("vocab_size") != model.embedding.token_embedding.num_embeddings:
        raise ValueError(f"Vocabulary mismatch in {path}")

    if checkpoint.get("max_seq_len") != model.max_seq_len:
        raise ValueError(f"Context-length mismatch in {path}")

    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()

    totals = defaultdict(float)
    counts = Counter()
    all_losses = []

    with torch.no_grad():
        for i in range(len(dataset)):
            item = dataset[i]
            ids = item["input_ids"].unsqueeze(0).to(device)
            labels = item["labels"].unsqueeze(0).to(device)

            logits = model(ids)
            loss = causal_loss(logits, labels, criterion)

            if not torch.isfinite(loss):
                raise RuntimeError(
                    f"Non-finite loss: {path.name}, test index {i}"
                )

            value = float(loss.item())
            category = dataset.examples[i]["category"]
            totals[category] += value
            counts[category] += 1
            all_losses.append(value)

    if len(all_losses) != len(dataset):
        raise RuntimeError("Not all test examples were evaluated.")

    return {
        "checkpoint": str(path.relative_to(ROOT)),
        "examples_evaluated": len(all_losses),
        "overall_mean_example_loss": sum(all_losses) / len(all_losses),
        "category_mean_example_loss": {
            category: totals[category] / counts[category]
            for category in sorted(totals)
        },
        "category_example_counts": dict(sorted(counts.items())),
    }


def main():
    for path in (TEST_FILE, TOKENIZER_FILE, BASE_CHECKPOINT, FINE_TUNED_CHECKPOINT):
        if not path.is_file():
            raise FileNotFoundError(f"Missing required file: {path}")

    if OUTPUT_DIR.exists() or OUTPUT_FILE.exists():
        raise FileExistsError(
            f"Evaluation output already exists: {OUTPUT_DIR}. "
            "Choose a new output directory to preserve prior results."
        )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Device:", device)

    tokenizer = CyberBPETokenizer(TOKENIZER_FILE)
    test_dataset = SOCInstructionDataset(TEST_FILE, tokenizer, MAX_SEQ_LEN)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    # Confirm every expected category is present before evaluation.
    categories = Counter(row["category"] for row in test_dataset.examples)
    print("Test examples:", len(test_dataset))
    print("Category counts:", dict(sorted(categories.items())))
    print("Evaluating both checkpoints on the same held-out test set.")

    base_checkpoint = torch.load(
        BASE_CHECKPOINT, map_location="cpu", weights_only=True
    )
    model = TinyLLMSmall(
        vocab_size=base_checkpoint["vocab_size"],
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=base_checkpoint["max_seq_len"],
        dropout=0.1,
    )
    del base_checkpoint

    results = {}
    for name, checkpoint_path in (
        ("base_model", BASE_CHECKPOINT),
        ("fine_tuned_model", FINE_TUNED_CHECKPOINT),
    ):
        print(f"\nEvaluating {name}...")
        result = evaluate_checkpoint(
            checkpoint_path, model, test_dataset, criterion, device
        )
        results[name] = result
        print("Overall test loss:", f"{result['overall_mean_example_loss']:.6f}")
        for category, loss in result["category_mean_example_loss"].items():
            print(f"  {category}: {loss:.6f}")

    base_loss = results["base_model"]["overall_mean_example_loss"]
    tuned_loss = results["fine_tuned_model"]["overall_mean_example_loss"]
    results["comparison"] = {
        "base_loss": base_loss,
        "fine_tuned_loss": tuned_loss,
        "absolute_loss_change": tuned_loss - base_loss,
        "relative_loss_reduction_percent": (
            (base_loss - tuned_loss) / base_loss * 100
            if base_loss else None
        ),
        "test_examples": len(test_dataset),
        "test_used_for_training_or_checkpoint_selection": False,
        "interpretation_note": (
            "Lower test loss indicates better next-token prediction on this "
            "dataset; it does not by itself establish factual correctness."
        ),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=False)
    OUTPUT_FILE.write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\n=== FINAL COMPARISON ===")
    print("Base loss:", f"{base_loss:.6f}")
    print("Fine-tuned loss:", f"{tuned_loss:.6f}")
    print(
        "Relative loss reduction:",
        f"{results['comparison']['relative_loss_reduction_percent']:.2f}%"
    )
    print("Results saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
