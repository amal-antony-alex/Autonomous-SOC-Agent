from pathlib import Path

from tokenizers import Tokenizer


class CyberBPETokenizer:

    SPECIAL_TOKENS = {
        "<PAD>": 0,
        "<UNK>": 1,
        "<BOS>": 2,
        "<EOS>": 3,
    }

    def __init__(self, tokenizer_path=None):

        self.tokenizer = None

        self.token_to_id = {}
        self.id_to_token = {}

        if tokenizer_path is not None:
            self.load(tokenizer_path)

    def load(self, path):

        path = Path(path)

        self.tokenizer = Tokenizer.from_file(
            str(path)
        )

        vocab = self.tokenizer.get_vocab()

        self.token_to_id = {
            token: token_id
            for token, token_id in vocab.items()
        }

        self.id_to_token = {
            token_id: token
            for token, token_id
            in self.token_to_id.items()
        }

        return self

    def encode(
        self,
        text,
        add_bos=True,
        add_eos=True,
    ):

        if self.tokenizer is None:
            raise RuntimeError(
                "Tokenizer has not been loaded."
            )

        encoding = self.tokenizer.encode(
            text
        )

        token_ids = list(
            encoding.ids
        )

        bos_id = self.token_to_id.get(
            "<BOS>"
        )

        eos_id = self.token_to_id.get(
            "<EOS>"
        )

        if add_bos and bos_id is not None:
            token_ids.insert(
                0,
                bos_id
            )

        if add_eos and eos_id is not None:
            token_ids.append(
                eos_id
            )

        return token_ids

    def decode(
        self,
        token_ids
    ):

        if self.tokenizer is None:
            raise RuntimeError(
                "Tokenizer has not been loaded."
            )

        special_ids = {
            self.token_to_id.get(
                "<PAD>"
            ),
            self.token_to_id.get(
                "<UNK>"
            ),
            self.token_to_id.get(
                "<BOS>"
            ),
            self.token_to_id.get(
                "<EOS>"
            ),
        }

        filtered_ids = [
            token_id
            for token_id in token_ids
            if token_id not in special_ids
        ]

        return self.tokenizer.decode(
            filtered_ids,
            skip_special_tokens=True,
        )

    @property
    def vocab_size(self):

        return len(
            self.token_to_id
        )
