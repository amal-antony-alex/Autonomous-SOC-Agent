import json
import re
from collections import Counter


class BPETokenizer:
    SPECIAL_TOKENS = {
        "<PAD>": 0,
        "<UNK>": 1,
        "<BOS>": 2,
        "<EOS>": 3,
    }

    def __init__(self, vocab_size=10000):
        self.vocab_size = vocab_size

        self.token_to_id = dict(self.SPECIAL_TOKENS)

        self.id_to_token = {
            idx: token
            for token, idx in self.token_to_id.items()
        }

        self.merges = []

    def _pre_tokenize(self, text):
        return re.findall(r"\w+|[^\w\s]", text.lower())

    def build_vocabulary(self, texts):
        word_counter = Counter()

        for text in texts:
            words = self._pre_tokenize(text)

            for word in words:
                word_counter[word] += 1

        # Add complete words first.
        for word in word_counter:
            if word not in self.token_to_id:
                token_id = len(self.token_to_id)

                if token_id >= self.vocab_size:
                    break

                self.token_to_id[word] = token_id
                self.id_to_token[token_id] = word

        # Add individual characters for unknown words.
        for word in word_counter:
            for character in word:
                if character not in self.token_to_id:
                    token_id = len(self.token_to_id)

                    if token_id >= self.vocab_size:
                        break

                    self.token_to_id[character] = token_id
                    self.id_to_token[token_id] = character

        return self

    def _encode_word(self, word):
        # Exact word match.
        if word in self.token_to_id:
            return [self.token_to_id[word]]

        # Character fallback.
        token_ids = []

        for character in word:
            token_ids.append(
                self.token_to_id.get(
                    character,
                    self.token_to_id["<UNK>"]
                )
            )

        return token_ids

    def encode(
        self,
        text,
        add_bos=True,
        add_eos=True
    ):
        tokens = []

        if add_bos:
            tokens.append(
                self.token_to_id["<BOS>"]
            )

        words = self._pre_tokenize(text)

        for word in words:
            tokens.extend(
                self._encode_word(word)
            )

        if add_eos:
            tokens.append(
                self.token_to_id["<EOS>"]
            )

        return tokens

    def decode(self, token_ids):
        tokens = []

        for token_id in token_ids:
            token = self.id_to_token.get(
                token_id,
                "<UNK>"
            )

            if token in self.SPECIAL_TOKENS:
                continue

            tokens.append(token)

        return " ".join(tokens)

    def save(self, path):
        data = {
            "vocab_size": self.vocab_size,
            "token_to_id": self.token_to_id,
            "merges": self.merges,
        }

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False
            )

    def load(self, path):
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        self.vocab_size = data["vocab_size"]

        self.token_to_id = {
            token: int(token_id)
            for token, token_id
            in data["token_to_id"].items()
        }

        self.id_to_token = {
            token_id: token
            for token, token_id
            in self.token_to_id.items()
        }

        self.merges = [
            tuple(pair)
            for pair in data["merges"]
        ]

        return self
