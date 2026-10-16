import torch
import torch.nn as nn
from pathlib import Path

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer
from ai.tiny_llm.training.cyberllm_v2_dataset import (
    CyberLLMv2Dataset,
)


CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/cyberllm_v2_shifted_best.pt"
)

TOKENIZER_PATH = Path(
    "ai/tiny_llm/tokenizer/artifacts/"
    "cyber_bpe/tokenizer.json"
)

TRAIN_FILE = Path(
    "data/processed/cyberllm_v2/train.jsonl"
)

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


def load_model():

    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER_PATH)

    checkpoint = torch.load(
        CHECKPOINT,
        map_location=DEVICE
    )

    model = TinyLLMSmall(
        vocab_size=checkpoint["vocab_size"],
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=checkpoint["max_seq_len"],
        dropout=0.1,
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.to(DEVICE)
    model.eval()

    return model, tokenizer


def get_token_text(
    tokenizer,
    token_id
):

    try:
        return tokenizer.decode(
            [token_id]
        )
    except Exception:
        return f"<ID:{token_id}>"


def inspect_next_token(
    model,
    tokenizer,
    prompt
):

    token_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False
    )

    input_ids = torch.tensor(
        [token_ids],
        dtype=torch.long,
        device=DEVICE
    )

    with torch.no_grad():

        logits = model(
            input_ids
        )

        next_logits = logits[
            0,
            -1
        ]

        probabilities = torch.softmax(
            next_logits,
            dim=-1
        )

        top_values, top_indices = torch.topk(
            probabilities,
            k=10
        )

    print()
    print(
        "===== NEXT TOKEN PREDICTIONS ====="
    )

    for rank, (
        probability,
        token_id
    ) in enumerate(
        zip(
            top_values.tolist(),
            top_indices.tolist()
        ),
        start=1
    ):

        token_text = get_token_text(
            tokenizer,
            token_id
        )

        print(
            f"{rank:02d}. "
            f"ID={token_id:<5} "
            f"Probability={probability:.6f} "
            f"Token={repr(token_text)}"
        )


def teacher_forced_test(
    model,
    tokenizer,
    dataset
):

    criterion = nn.CrossEntropyLoss(
        ignore_index=-100
    )

    total_loss = 0.0
    total_examples = 0

    print()
    print(
        "===== TEACHER-FORCED EVALUATION ====="
    )

    for index in range(
        min(20, len(dataset))
    ):

        sample = dataset[index]

        input_ids = sample[
            "input_ids"
        ].unsqueeze(0).to(DEVICE)

        labels = sample[
            "labels"
        ].unsqueeze(0).to(DEVICE)

        with torch.no_grad():

            logits = model(
                input_ids
            )

        # Standard next-token prediction:
        #
        # input:  token 1 2 3 4
        # target: token 2 3 4 5
        #
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

        total_loss += loss.item()
        total_examples += 1

        print(
            f"Example {index + 1:02d} | "
            f"Loss: {loss.item():.6f}"
        )

    average_loss = (
        total_loss / total_examples
    )

    print()
    print(
        f"Average teacher-forced loss: "
        f"{average_loss:.6f}"
    )

    return average_loss


def inspect_training_example(
    dataset,
    tokenizer,
    index=0
):

    example = dataset.examples[index]

    prompt = (
        "Instruction:\n"
        f"{example['instruction']}\n\n"
        "Input:\n"
        f"{example['input']}\n\n"
        "Response:\n"
    )

    expected = example["output"]

    print()
    print(
        "===== DATASET EXAMPLE ====="
    )

    print()
    print("Instruction:")
    print(
        example["instruction"]
    )

    print()
    print("Input:")
    print(
        example["input"]
    )

    print()
    print("Expected response:")
    print(expected)

    print()
    print("Prompt token IDs:")
    prompt_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False
    )

    print(prompt_ids)

    print()
    print("Expected response token IDs:")
    response_ids = tokenizer.encode(
        expected,
        add_bos=False,
        add_eos=True
    )

    print(response_ids)

    print()
    print(
        "Decoded response:"
    )

    print(
        tokenizer.decode(
            response_ids
        )
    )

    return prompt


def inspect_response_predictions(
    model,
    tokenizer,
    dataset,
    index=0,
    max_tokens=20
):

    example = dataset.examples[index]

    prompt = (
        "Instruction:\n"
        f"{example['instruction']}\n\n"
        "Input:\n"
        f"{example['input']}\n\n"
        "Response:\n"
    )

    prompt_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False
    )

    response_ids = tokenizer.encode(
        example["output"],
        add_bos=False,
        add_eos=True
    )

    input_ids = torch.tensor(
        [prompt_ids],
        dtype=torch.long,
        device=DEVICE
    )

    print()
    print(
        "===== RESPONSE TOKEN PREDICTIONS ====="
    )

    print()
    print(
        "Expected response:"
    )

    print(
        example["output"]
    )

    print()

    correct = 0
    total = min(
        len(response_ids),
        max_tokens
    )

    for position in range(total):

        with torch.no_grad():

            logits = model(
                input_ids
            )

        next_logits = logits[
            0,
            -1
        ]

        predicted_id = (
            torch.argmax(
                next_logits
            ).item()
        )

        expected_id = response_ids[
            position
        ]

        predicted_text = (
            get_token_text(
                tokenizer,
                predicted_id
            )
        )

        expected_text = (
            get_token_text(
                tokenizer,
                expected_id
            )
        )

        is_correct = (
            predicted_id == expected_id
        )

        if is_correct:
            correct += 1

        print(
            f"{position + 1:02d}. "
            f"Expected={repr(expected_text)} "
            f"Predicted={repr(predicted_text)} "
            f"{'✓' if is_correct else '✗'}"
        )

        next_id = expected_id

        next_tensor = torch.tensor(
            [[next_id]],
            dtype=torch.long,
            device=DEVICE
        )

        input_ids = torch.cat(
            [
                input_ids,
                next_tensor
            ],
            dim=1
        )

    accuracy = (
        correct / total
        if total > 0
        else 0
    )

    print()
    print(
        f"Teacher-forced next-token accuracy "
        f"for first {total} response tokens: "
        f"{accuracy:.4f}"
    )


def main():

    print(
        "===== CYBERLLM V2 ROOT-CAUSE DIAGNOSTIC ====="
    )

    print(
        f"Device: {DEVICE}"
    )

    model, tokenizer = load_model()

    print()
    print(
        "Checkpoint loaded:"
    )

    print(
        f"  {CHECKPOINT}"
    )

    print()
    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    dataset = CyberLLMv2Dataset(
        TRAIN_FILE,
        tokenizer,
        max_seq_len=512
    )

    print(
        f"Training examples: "
        f"{len(dataset)}"
    )

    # ----------------------------------------------
    # Dataset inspection
    # ----------------------------------------------

    prompt = inspect_training_example(
        dataset,
        tokenizer,
        index=0
    )

    # ----------------------------------------------
    # Next-token diagnostic
    # ----------------------------------------------

    inspect_next_token(
        model,
        tokenizer,
        prompt
    )

    # ----------------------------------------------
    # Teacher-forced loss
    # ----------------------------------------------

    teacher_forced_test(
        model,
        tokenizer,
        dataset
    )

    # ----------------------------------------------
    # Response prediction diagnostic
    # ----------------------------------------------

    inspect_response_predictions(
        model,
        tokenizer,
        dataset,
        index=0,
        max_tokens=20
    )

    print()
    print(
        "===== DIAGNOSTIC COMPLETE ====="
    )


if __name__ == "__main__":
    main()

