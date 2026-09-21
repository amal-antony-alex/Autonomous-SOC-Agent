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
        """
        Build a basic BPE vocabulary from training text.
        """

        word_counter = Counter()

        for text in texts:
            words = self._pre_tokenize(text)

            for word in words:
                word_counter[word] += 1

        # Start with characters.
        vocabulary = set()

        for word in word_counter:
            vocabulary.update(word)

        next_id = len(self.token_to_id)

        for token in sorted(vocabulary):
            if token not in self.token_to_id:
                self.token_to_id[token] = next_id
                self.id_to_token[next_id] = token
                next_id += 1

        # Perform simple BPE merges.
        while len(self.token_to_id) < self.vocab_size:
            pair_counts = Counter()

            for word, frequency in word_counter.items():
                symbols = list(word)

                for i in range(len(symbols) - 1):
                    pair = (symbols[i], symbols[i + 1])
                    pair_counts[pair] += frequency

            if not pair_counts:
                break

            best_pair, best_count = pair_counts.most_common(1)[0]

            if best_count < 2:
                break

            merged_token = "".join(best_pair)

            if merged_token in self.token_to_id:
                break

            self.merges.append(best_pair)

            self.token_to_id[merged_token] = next_id
            self.id_to_token[next_id] = merged_token
            next_id += 1

            if next_id >= self.vocab_size:
                break

            # Update words using the new merge.
            updated_counter = Counter()

            for word, frequency in word_counter.items():
                symbols = list(word)
                merged_symbols = []

                i = 0

                while i < len(symbols):
                    if (
                        i < len(symbols) - 1
                        and symbols[i] == best_pair[0]
                        and symbols[i + 1] == best_pair[1]
                    ):
                        merged_symbols.append(merged_token)
                        i += 2
                    else:
                        merged_symbols.append(symbols[i])
                        i += 1

                updated_counter[" ".join(merged_symbols)] += frequency

            word_counter = updated_counter

        return self

    def encode(
        self,
        text,
        add_bos=True,
        add_eos=True,
    ):
        tokens = []

        if add_bos:
            tokens.append(self.token_to_id["<BOS>"])

        words = self._pre_tokenize(text)

        for word in words:
            if word in self.token_to_id:
                tokens.append(self.token_to_id[word])
                continue

            # Character-level fallback.
            for character in word:
                tokens.append(
                    self.token_to_id.get(
                        character,
                        self.token_to_id["<UNK>"],
                    )
                )

        if add_eos:
            tokens.append(self.token_to_id["<EOS>"])

        return tokens

    def decode(self, token_ids):
        tokens = []

        for token_id in token_ids:
            token = self.id_to_token.get(
                token_id,
                "<UNK>",
            )

            if token not in self.SPECIAL_TOKENS:
                tokens.append(token)

        return " ".join(tokens)

    def save(self, path):
        data = {
            "vocab_size": self.vocab_size,
            "token_to_id": self.token_to_id,
            "merges": self.merges,
        }

        with open(path, "w", encoding="utf-8") as file:
            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False,
            )

    def load(self, path):
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        self.vocab_size = data["vocab_size"]
        self.token_to_id = data["token_to_id"]
        self.token_to_id = {
            token: int(token_id)
            for token, token_id in self.token_to_id.items()
        }

        self.id_to_token = {
            token_id: token
            for token, token_id in self.token_to_id.items()
        }

        self.merges = [
            tuple(pair)
            for pair in data["merges"]
        ]

        return self
