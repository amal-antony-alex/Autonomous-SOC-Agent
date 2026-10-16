import json
from pathlib import Path

import torch
from torch.utils.data import Dataset

from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


class CyberLLMv2Dataset(Dataset):
    """
    Dataset for CyberLLM v2 instruction fine-tuning.

    Training format:

        Instruction:
        <instruction>

        Input:
        <input>

        Response:
        <output>

    Loss is calculated only on response tokens.
    Instruction and input tokens are masked with -100.

    Metadata such as category, source, and MITRE technique
    information is retained internally but is not returned
    to the DataLoader because some examples do not have
    MITRE-specific metadata.
    """

    def __init__(
        self,
        jsonl_file,
        tokenizer,
        max_seq_len=512,
    ):
        self.jsonl_file = Path(jsonl_file)
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len

        self.examples = []

        self._load_dataset()

    def _load_dataset(self):

        with self.jsonl_file.open(
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                example = json.loads(line)

                instruction = example.get(
                    "instruction",
                    ""
                ).strip()

                input_text = example.get(
                    "input",
                    ""
                ).strip()

                output = example.get(
                    "output",
                    ""
                ).strip()

                # Skip incomplete examples.
                if not instruction:
                    continue

                if not input_text:
                    continue

                if not output:
                    continue

                self.examples.append({
                    "instruction": instruction,
                    "input": input_text,
                    "output": output,

                    # Metadata retained for future
                    # evaluation/reporting.
                    "category": example.get(
                        "category",
                        "unknown"
                    ),

                    "source": example.get(
                        "source",
                        "unknown"
                    ),

                    "technique_id": example.get(
                        "technique_id"
                    ),

                    "technique_name": example.get(
                        "technique_name"
                    ),
                })

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, index):

        example = self.examples[index]

        instruction = example["instruction"]
        input_text = example["input"]
        output = example["output"]

        # ----------------------------------------------
        # Build prompt
        # ----------------------------------------------

        prompt = (
            "Instruction:\n"
            f"{instruction}\n\n"
            "Input:\n"
            f"{input_text}\n\n"
            "Response:\n"
        )

        # ----------------------------------------------
        # Tokenize prompt
        # ----------------------------------------------

        prompt_ids = self.tokenizer.encode(
            prompt,
            add_bos=True,
            add_eos=False
        )

        # ----------------------------------------------
        # Tokenize response
        # ----------------------------------------------

        response_ids = self.tokenizer.encode(
            output,
            add_bos=False,
            add_eos=True
        )

        # ----------------------------------------------
        # Combine prompt + response
        # ----------------------------------------------

        input_ids = (
            prompt_ids
            + response_ids
        )

        # ----------------------------------------------
        # Response-only loss
        #
        # -100 means CrossEntropyLoss ignores
        # those positions.
        # ----------------------------------------------

        labels = (
            [-100] * len(prompt_ids)
            + response_ids
        )

        # ----------------------------------------------
        # Apply maximum sequence length
        # ----------------------------------------------

        input_ids = input_ids[
            :self.max_seq_len
        ]

        labels = labels[
            :self.max_seq_len
        ]

        # ----------------------------------------------
        # Safety check
        # ----------------------------------------------

        if len(input_ids) != len(labels):
            raise RuntimeError(
                "input_ids and labels have "
                "different lengths."
            )

        # ----------------------------------------------
        # Only tensors are returned.
        #
        # This prevents PyTorch DataLoader from
        # failing when metadata contains None.
        # ----------------------------------------------

        return {
            "input_ids": torch.tensor(
                input_ids,
                dtype=torch.long
            ),

            "labels": torch.tensor(
                labels,
                dtype=torch.long
            ),
        }


def load_cyberllm_v2_tokenizer():

    tokenizer_path = Path(
        "ai/tiny_llm/tokenizer/artifacts/"
        "cyber_bpe/tokenizer.json"
    )

    tokenizer = CyberBPETokenizer()

    tokenizer.load(
        tokenizer_path
    )

    return tokenizer


if __name__ == "__main__":

    print(
        "===== CYBERLLM V2 DATASET TEST ====="
    )

    tokenizer = (
        load_cyberllm_v2_tokenizer()
    )

    train_dataset = CyberLLMv2Dataset(
        "data/processed/cyberllm_v2/train.jsonl",
        tokenizer,
        max_seq_len=512,
    )

    val_dataset = CyberLLMv2Dataset(
        "data/processed/cyberllm_v2/val.jsonl",
        tokenizer,
        max_seq_len=512,
    )

    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    print(
        f"Training examples: "
        f"{len(train_dataset)}"
    )

    print(
        f"Validation examples: "
        f"{len(val_dataset)}"
    )

    # ----------------------------------------------
    # Inspect first training example
    # ----------------------------------------------

    sample = train_dataset[0]

    print()
    print(
        "===== FIRST TRAINING EXAMPLE ====="
    )

    print(
        f"Input shape: "
        f"{sample['input_ids'].shape}"
    )

    print(
        f"Label shape: "
        f"{sample['labels'].shape}"
    )

    trainable_tokens = (
        sample["labels"] != -100
    ).sum().item()

    ignored_tokens = (
        sample["labels"] == -100
    ).sum().item()

    print(
        f"Ignored prompt tokens: "
        f"{ignored_tokens}"
    )

    print(
        f"Trainable response tokens: "
        f"{trainable_tokens}"
    )

    print()
    print(
        "===== DATASET TEST COMPLETE ====="
    )
