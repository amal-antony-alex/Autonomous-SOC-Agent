import json

import torch
from torch.utils.data import Dataset


class CyberBPEInstructionDataset(Dataset):

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

                instruction = example.get(
                    "instruction",
                    "",
                ).strip()

                input_text = example.get(
                    "input",
                    "",
                ).strip()

                output = example.get(
                    "output",
                    "",
                ).strip()

                prompt = (
                    "Instruction:\n"
                    f"{instruction}\n\n"
                    "Input:\n"
                    f"{input_text}\n\n"
                    "Response:\n"
                )

                prompt_ids = tokenizer.encode(
                    prompt,
                    add_bos=True,
                    add_eos=False,
                )

                output_ids = tokenizer.encode(
                    output,
                    add_bos=False,
                    add_eos=True,
                )

                token_ids = (
                    prompt_ids + output_ids
                )

                if len(token_ids) > max_seq_len:
                    token_ids = token_ids[
                        :max_seq_len
                    ]

                if len(token_ids) < 2:
                    continue

                input_ids = token_ids[:-1]
                target_ids = token_ids[1:]

                # Ignore the prompt portion when
                # calculating the supervised loss.
                prompt_target_length = (
                    len(prompt_ids) - 1
                )

                target_ids = [
                    -100
                    if index < prompt_target_length
                    else token_id
                    for index, token_id
                    in enumerate(target_ids)
                ]

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
