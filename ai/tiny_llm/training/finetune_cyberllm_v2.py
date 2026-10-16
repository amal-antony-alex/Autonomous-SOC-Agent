import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.utils.data import DataLoader

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.cyberllm_v2_dataset import CyberLLMv2Dataset


# ============================================================
# Configuration
# ============================================================

TRAIN_FILE = Path(
    "data/processed/cyberllm_v2/train.jsonl"
)

VAL_FILE = Path(
    "data/processed/cyberllm_v2/val.jsonl"
)

BASE_CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/"
    "tiny_llm_cyber_bpe_small_best.pt"
)

OUTPUT_CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/"
    "cyberllm_v2_shifted_best.pt"
)

TOKENIZER_PATH = Path(
    "ai/tiny_llm/tokenizer/artifacts/"
    "cyber_bpe/tokenizer.json"
)

MAX_SEQ_LEN = 512
BATCH_SIZE = 1
EPOCHS = 10
LEARNING_RATE = 5e-5
GRAD_CLIP = 1.0
SEED = 42


# ============================================================
# Reproducibility
# ============================================================

def set_seed(seed):

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ============================================================
# Tokenizer
# ============================================================

def load_tokenizer():

    tokenizer = CyberBPETokenizer()

    tokenizer.load(
        TOKENIZER_PATH
    )

    return tokenizer


# ============================================================
# Model
# ============================================================

def load_model(
    device,
    vocab_size
):

    checkpoint = torch.load(
        BASE_CHECKPOINT,
        map_location=device
    )

    model = TinyLLMSmall(
        vocab_size=vocab_size,
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=MAX_SEQ_LEN,
        dropout=0.1,
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.to(device)

    return model


# ============================================================
# Causal LM loss
# ============================================================

def calculate_causal_loss(
    logits,
    labels,
    criterion
):
    """
    Correct causal language-model objective.

    Given:

        input:  A B C D
        target: A B C D

    the model must predict:

        B C D

    from:

        A B C

    Therefore logits and labels are shifted by one position.
    """

    shift_logits = logits[
        :, :-1, :
    ].contiguous()

    shift_labels = labels[
        :, 1:
    ].contiguous()

    loss = criterion(
        shift_logits.view(
            -1,
            shift_logits.size(-1)
        ),
        shift_labels.view(-1)
    )

    return loss


# ============================================================
# Training
# ============================================================

def train_one_epoch(
    model,
    loader,
    optimizer,
    criterion,
    device
):

    model.train()

    total_loss = 0.0
    batches = 0

    for batch in loader:

        input_ids = batch[
            "input_ids"
        ].to(device)

        labels = batch[
            "labels"
        ].to(device)

        optimizer.zero_grad()

        logits = model(
            input_ids
        )

        loss = calculate_causal_loss(
            logits,
            labels,
            criterion
        )

        loss.backward()

        torch.nn.utils.clip_grad_norm_(
            model.parameters(),
            GRAD_CLIP
        )

        optimizer.step()

        total_loss += loss.item()
        batches += 1

    return total_loss / batches


# ============================================================
# Validation
# ============================================================

def evaluate(
    model,
    loader,
    criterion,
    device
):

    model.eval()

    total_loss = 0.0
    batches = 0

    with torch.no_grad():

        for batch in loader:

            input_ids = batch[
                "input_ids"
            ].to(device)

            labels = batch[
                "labels"
            ].to(device)

            logits = model(
                input_ids
            )

            loss = calculate_causal_loss(
                logits,
                labels,
                criterion
            )

            total_loss += loss.item()
            batches += 1

    return total_loss / batches


# ============================================================
# Main
# ============================================================

def main():

    print(
        "===== CYBERLLM V2 CORRECTED FINE-TUNING ====="
    )

    set_seed(SEED)

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print()
    print(
        f"Device: {device}"
    )

    print(
        f"Seed: {SEED}"
    )

    print()
    print(
        "IMPORTANT:"
    )
    print(
        "Using shifted causal language-model loss."
    )

    # --------------------------------------------------------
    # Tokenizer
    # --------------------------------------------------------

    tokenizer = load_tokenizer()

    print()
    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    # --------------------------------------------------------
    # Datasets
    # --------------------------------------------------------

    train_dataset = CyberLLMv2Dataset(
        TRAIN_FILE,
        tokenizer,
        max_seq_len=MAX_SEQ_LEN,
    )

    val_dataset = CyberLLMv2Dataset(
        VAL_FILE,
        tokenizer,
        max_seq_len=MAX_SEQ_LEN,
    )

    print(
        f"Training examples: "
        f"{len(train_dataset)}"
    )

    print(
        f"Validation examples: "
        f"{len(val_dataset)}"
    )

    # --------------------------------------------------------
    # DataLoaders
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    model = load_model(
        device,
        tokenizer.vocab_size
    )

    print()
    print(
        "Base checkpoint loaded:"
    )

    print(
        f"  {BASE_CHECKPOINT}"
    )

    # --------------------------------------------------------
    # Optimizer / loss
    # --------------------------------------------------------

    optimizer = AdamW(
        model.parameters(),
        lr=LEARNING_RATE
    )

    criterion = nn.CrossEntropyLoss(
        ignore_index=-100
    )

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    best_val_loss = float("inf")
    best_epoch = 0

    print()
    print(
        "===== TRAINING ====="
    )

    for epoch in range(
        1,
        EPOCHS + 1
    ):

        train_loss = train_one_epoch(
            model,
            train_loader,
            optimizer,
            criterion,
            device
        )

        val_loss = evaluate(
            model,
            val_loader,
            criterion,
            device
        )

        print(
            f"Epoch {epoch:02d} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f}"
        )

        if val_loss < best_val_loss:

            best_val_loss = val_loss
            best_epoch = epoch

            checkpoint = {
                "model_state_dict":
                    model.state_dict(),

                "vocab_size":
                    tokenizer.vocab_size,

                "max_seq_len":
                    MAX_SEQ_LEN,

                "epoch":
                    epoch,

                "val_loss":
                    val_loss,

                "learning_rate":
                    LEARNING_RATE,

                "base_checkpoint":
                    str(BASE_CHECKPOINT),

                "model_type":
                    "CyberLLM-v2-shifted",

                "loss_objective":
                    "response_only_shifted_causal",

                "train_examples":
                    len(train_dataset),

                "val_examples":
                    len(val_dataset),

                "seed":
                    SEED,
            }

            torch.save(
                checkpoint,
                OUTPUT_CHECKPOINT
            )

            print(
                "  -> Best checkpoint saved."
            )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print()
    print(
        "===== TRAINING COMPLETE ====="
    )

    print(
        f"Best validation loss: "
        f"{best_val_loss:.4f}"
    )

    print(
        f"Best epoch: "
        f"{best_epoch}"
    )

    print(
        "Checkpoint:"
    )

    print(
        f"  {OUTPUT_CHECKPOINT}"
    )


if __name__ == "__main__":
    main()
