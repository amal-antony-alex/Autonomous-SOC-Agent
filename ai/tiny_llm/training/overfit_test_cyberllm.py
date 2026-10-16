import json
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Subset

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import (
    CyberBPETokenizer,
)
from ai.tiny_llm.training.cyber_bpe_instruction_dataset import (
    CyberBPEInstructionDataset,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATASET_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_instruction_dataset.jsonl"
)

TOKENIZER_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "cyber_bpe"
    / "tokenizer.json"
)

BASE_CHECKPOINT = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
    / "tiny_llm_cyber_bpe_small_best.pt"
)

OUTPUT_CHECKPOINT = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
    / "cyberllm_overfit_10.pt"
)

DEVICE = torch.device(
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)


def main():

    print(
        "===== CYBERLLM 10-EXAMPLE OVERFIT TEST ====="
    )

    # Load tokenizer
    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    # Load dataset
    dataset = CyberBPEInstructionDataset(
        jsonl_file=DATASET_FILE,
        tokenizer=tokenizer,
        max_seq_len=512,
    )

    print(
        f"Full dataset: {len(dataset)} examples"
    )

    # Use only first 10 examples
    subset = Subset(
        dataset,
        list(range(10)),
    )

    print(
        f"Training subset: {len(subset)} examples"
    )

    print(
        f"Device: {DEVICE}"
    )

    loader = DataLoader(
        subset,
        batch_size=1,
        shuffle=True,
    )

    # Create the same Small model
    model = TinyLLMSmall(
        vocab_size=2000,
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=512,
    )

    # Load pretrained Cyber BPE checkpoint
    checkpoint = torch.load(
        BASE_CHECKPOINT,
        map_location=DEVICE,
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.to(DEVICE)

    print(
        "Base checkpoint loaded."
    )

    # Aggressive learning rate intentionally used
    # for this diagnostic overfitting experiment.
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=1e-3,
        weight_decay=0.0,
    )

    criterion = nn.CrossEntropyLoss(
        ignore_index=-100
    )

    epochs = 100

    print()
    print(
        "Starting overfit training..."
    )
    print()

    for epoch in range(
        1,
        epochs + 1,
    ):

        model.train()

        total_loss = 0.0

        for batch in loader:

            input_ids, targets = batch
      
            input_ids = input_ids.to(DEVICE)
            targets = targets.to(DEVICE)

            optimizer.zero_grad()

            logits = model(
                input_ids
            )

            loss = criterion(
                logits.reshape(
                    -1,
                    logits.size(-1),
                ),
                targets.reshape(-1),
            )

            loss.backward()

            torch.nn.utils.clip_grad_norm_(
                model.parameters(),
                max_norm=1.0,
            )

            optimizer.step()

            total_loss += loss.item()

        avg_loss = (
            total_loss
            / len(loader)
        )

        if (
            epoch == 1
            or epoch % 10 == 0
            or epoch == epochs
        ):
            print(
                f"Epoch {epoch:03d} | "
                f"Loss {avg_loss:.4f}"
            )

    # Save checkpoint
    torch.save(
        {
            "model_state_dict":
                model.state_dict(),
            "model_type":
                "CyberLLM-Overfit-Test",
            "examples": 10,
            "epochs": epochs,
            "learning_rate": 1e-3,
            "base_checkpoint":
                str(BASE_CHECKPOINT),
        },
        OUTPUT_CHECKPOINT,
    )

    print()
    print(
        f"Checkpoint saved:\n"
        f"{OUTPUT_CHECKPOINT}"
    )

    print()
    print(
        "===== OVERFIT TEST COMPLETE ====="
    )


if __name__ == "__main__":
    main()
