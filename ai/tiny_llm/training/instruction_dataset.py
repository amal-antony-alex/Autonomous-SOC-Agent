import json

import torch
from torch.utils.data import Dataset


class CybersecurityInstructionDataset(Dataset):

    def __init__(
        self,
        jsonl_file,
        tokenizer,
        max_seq_len=512,
    ):
        self.examples = []

        with open(
            jsonl_file,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                example = json.loads(line)

                instruction = example["instruction"].strip()
                input_text = example["input"].strip()
                output = example["output"].strip()

                prompt = (
                    "Instruction:\n"
                    + instruction
                    + "\n\n"
                    + "Input:\n"
                    + input_text
                    + "\n\n"
                    + "Response:\n"
                )

                full_text = prompt + output

                prompt_ids = tokenizer.encode(
                    prompt,
                    add_bos=True,
                    add_eos=False,
                )

                full_ids = tokenizer.encode(
                    full_text,
                    add_bos=True,
                    add_eos=True,
                )

                if len(full_ids) > max_seq_len + 1:
                    full_ids = full_ids[
                        :max_seq_len + 1
                    ]

                if len(full_ids) < 2:
                    continue

                input_ids = full_ids[:-1]
                target_ids = full_ids[1:]

                # Ignore loss on the prompt.
                #
                # target_ids[i] corresponds to
                # input_ids[i] predicting the next token.
                #
                # The first response token is predicted from
                # the final prompt token.

                prompt_target_length = max(
                    len(prompt_ids) - 1,
                    0,
                )

                for index in range(
                    min(
                        prompt_target_length,
                        len(target_ids),
                    )
                ):
                    target_ids[index] = -100

                self.examples.append(
                    (
                        torch.tensor(
                            input_ids,
                            dtype=torch.long,
                        ),
                        torch.tensor(
                            target_ids,
                            dtype=torch.long,
                        ),
                    )
                )

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, index):
        return self.examples[index]

