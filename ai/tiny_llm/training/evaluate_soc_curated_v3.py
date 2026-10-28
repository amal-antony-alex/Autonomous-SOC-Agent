from pathlib import Path
import torch
import torch.nn as nn

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.cyberllm_v2_dataset import CyberLLMv2Dataset

TOKENIZER = Path("ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json")
BASE = Path("ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt")
DATASETS = {
    "SOC TEST": Path("data/processed/soc_curated_v3/final/test_soc.jsonl"),
    "MITRE TEST": Path("data/processed/soc_curated_v3/final/test_mitre.jsonl"),
}
CHECKPOINTS = [
    BASE,
    *[
        Path(f"ai/tiny_llm/checkpoints/soc_curated_v3_experiment_epoch{i}.pt")
        for i in range(1, 6)
    ],
]
MAX_SEQ_LEN = 512


def loss_for(logits, labels, criterion):
    return criterion(
        logits[:, :-1, :].contiguous().reshape(-1, logits.size(-1)),
        labels[:, 1:].contiguous().reshape(-1),
    )


def main():
    for p in [TOKENIZER, *DATASETS.values(), *CHECKPOINTS]:
        if not p.exists():
            raise FileNotFoundError(f"Missing required file: {p}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    datasets = {
        name: CyberLLMv2Dataset(path, tokenizer, max_seq_len=MAX_SEQ_LEN)
        for name, path in DATASETS.items()
    }

    print(f"Device: {device}")
    print("Evaluation only; no training or checkpoint selection.")

    for checkpoint_path in CHECKPOINTS:
        ckpt = torch.load(
            checkpoint_path, map_location=device, weights_only=False
        )
        model = TinyLLMSmall(
            vocab_size=ckpt["vocab_size"],
            embed_dim=128,
            num_layers=2,
            num_heads=4,
            ff_dim=512,
            max_seq_len=ckpt["max_seq_len"],
            dropout=0.1,
        )
        model.load_state_dict(ckpt["model_state_dict"])
        model.to(device)
        model.eval()

        print(f"\n{'=' * 72}\n{checkpoint_path.name}")
        print(f"Checkpoint epoch: {ckpt.get('epoch', 'baseline')}")

        with torch.no_grad():
            for dataset_name, dataset in datasets.items():
                totals, counts = {}, {}
                overall_sum = 0.0

                for i in range(len(dataset)):
                    item = dataset[i]
                    ids = item["input_ids"].unsqueeze(0).to(device)
                    labels = item["labels"].unsqueeze(0).to(device)
                    loss = loss_for(model(ids), labels, criterion).item()

                    category = dataset.examples[i].get("category", "unknown")
                    totals[category] = totals.get(category, 0.0) + loss
                    counts[category] = counts.get(category, 0) + 1
                    overall_sum += loss

                print(
                    f"\n{dataset_name}: "
                    f"mean per-example loss={overall_sum / len(dataset):.4f} "
                    f"(n={len(dataset)})"
                )
                for category in sorted(totals):
                    print(
                        f"  {category:30s} "
                        f"{totals[category] / counts[category]:.4f} "
                        f"(n={counts[category]})"
                    )

        del model
        if device.type == "cuda":
            torch.cuda.empty_cache()


if __name__ == "__main__":
    main()
