import os

import torch

from ai.tiny_llm.model.tiny_llm import TinyLLM
from ai.tiny_llm.tokenizer.bpe_tokenizer import BPETokenizer


class TinyLLMService:
    def __init__(self):
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../")
        )

        self.checkpoint_path = os.path.join(
            project_root,
            "ai",
            "tiny_llm",
            "checkpoints",
            "tiny_llm_best.pt",
        )

        self.tokenizer_path = os.path.join(
            project_root,
            "ai",
            "tiny_llm",
            "tokenizer",
            "artifacts",
            "tokenizer.json",
        )

        self.device = torch.device("cpu")

        # Load tokenizer
        self.tokenizer = BPETokenizer()
        self.tokenizer.load(self.tokenizer_path)

        # Load trained checkpoint
        checkpoint = torch.load(
            self.checkpoint_path,
            map_location=self.device,
        )

        # Build model using checkpoint vocabulary
        self.model = TinyLLM(
            vocab_size=checkpoint["vocab_size"]
        )

        self.model.load_state_dict(
            checkpoint["model_state_dict"]
        )

        self.model.to(self.device)
        self.model.eval()

        # Model information
        self.vocab_size = checkpoint["vocab_size"]
        self.best_epoch = checkpoint["epoch"]
        self.validation_loss = checkpoint["val_loss"]

        # Tiny LLM maximum context length
        self.max_context_length = 512

    def generate(
        self,
        prompt: str,
        max_new_tokens: int = 30,
        temperature: float = 0.8,
        top_k: int = 10,
    ) -> str:

        # Tokenize prompt
        token_ids = self.tokenizer.encode(
            prompt,
            add_bos=True,
            add_eos=False,
        )

        # Reserve space for generated tokens.
        max_input_tokens = (
            self.max_context_length - max_new_tokens
        )

        # Prevent the model from exceeding its
        # maximum context length.
        if len(token_ids) > max_input_tokens:
            token_ids = token_ids[-max_input_tokens:]

        input_ids = torch.tensor(
            [token_ids],
            dtype=torch.long,
            device=self.device,
        )

        generated = input_ids.clone()

        for _ in range(max_new_tokens):

            with torch.no_grad():
                logits = self.model(generated)

            # Only use predictions for the final token.
            logits = logits[:, -1, :]

            # Temperature controls randomness.
            logits = logits / temperature

            # Select the top-k candidate tokens.
            values, indices = torch.topk(
                logits,
                min(top_k, logits.shape[-1]),
            )

            # Convert candidate scores to probabilities.
            probabilities = torch.softmax(
                values,
                dim=-1,
            )

            # Sample one candidate.
            selected = torch.multinomial(
                probabilities,
                num_samples=1,
            )

            next_token = indices.gather(
                1,
                selected,
            )

            # Append generated token.
            generated = torch.cat(
                [generated, next_token],
                dim=1,
            )

            # Stop when EOS is generated.
            if (
                next_token.item()
                == self.tokenizer.token_to_id["<EOS>"]
            ):
                break

        return self.tokenizer.decode(
            generated[0].tolist()
        )


tiny_llm_service = TinyLLMService()
