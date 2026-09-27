import torch
from torch.utils.data import Dataset


class CybersecurityDataset(Dataset):

    def __init__(
        self,
        text_file,
        tokenizer,
        max_seq_len=512
    ):
        self.examples = []

        with open(
            text_file,
            "r",
            encoding="utf-8"
        ) as file:
            text = file.read()

        token_ids = tokenizer.encode(
            text,
            add_bos=True,
            add_eos=True
        )

        for start in range(
            0,
            len(token_ids) - 1,
            max_seq_len
        ):
            chunk = token_ids[
                start:start + max_seq_len + 1
            ]

            if len(chunk) < 2:
                continue

            input_ids = chunk[:-1]
            target_ids = chunk[1:]

            self.examples.append(
                (
                    torch.tensor(
                        input_ids,
                        dtype=torch.long
                    ),
                    torch.tensor(
                        target_ids,
                        dtype=torch.long
                    )
                )
            )

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, index):
        return self.examples[index]
