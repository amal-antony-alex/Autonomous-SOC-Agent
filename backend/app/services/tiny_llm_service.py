
import os

import torch

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


class TinyLLMService:
    def __init__(self):
        # Resolve the repository root from this file:
        # backend/app/services/tiny_llm_service.py
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../..")
        )

        self.checkpoint_path = os.path.join(
            project_root,
            "ai",
            "tiny_llm",
            "checkpoints",
            "cyberllm_v2_2_soc_metrics_best.pt",
        )

        self.tokenizer_path = os.path.join(
            project_root,
            "ai",
            "tiny_llm",
            "tokenizer",
            "artifacts",
            "cyber_bpe",
            "tokenizer.json",
        )

        self.device = torch.device("cpu")

        self.tokenizer = CyberBPETokenizer()
        self.tokenizer.load(self.tokenizer_path)

        checkpoint = torch.load(
            self.checkpoint_path,
            map_location=self.device,
            weights_only=False,
        )

        self.model = TinyLLMSmall(
            vocab_size=checkpoint["vocab_size"],
            embed_dim=128,
            num_layers=2,
            num_heads=4,
            ff_dim=512,
            max_seq_len=checkpoint["max_seq_len"],
            dropout=0.1,
        )

        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.to(self.device)
        self.model.eval()

        self.vocab_size = checkpoint["vocab_size"]
        self.best_epoch = checkpoint["epoch"]
        self.validation_loss = checkpoint["val_loss"]
        self.max_context_length = self.model.max_seq_len

        print(
            "Tiny CyberLLM v2.2 loaded:",
            f"epoch={self.best_epoch},",
            f"val_loss={self.validation_loss:.4f},",
            f"vocab={self.vocab_size}",
        )

    def generate(
        self,
        prompt: str,
        max_new_tokens: int = 60,
        temperature: float = 1.0,
        top_k: int = 1,
    ) -> str:
        del temperature, top_k  # Greedy decoding is deterministic.

        token_ids = self.tokenizer.encode(
            prompt,
            add_bos=True,
            add_eos=False,
        )

        # Keep the prompt within the model's context window.
        token_ids = token_ids[-self.max_context_length:]

        input_ids = torch.tensor(
            [token_ids],
            dtype=torch.long,
            device=self.device,
        )

        prompt_length = input_ids.shape[1]
        generated = input_ids.clone()
        eos_id = self.tokenizer.token_to_id["<EOS>"]

        with torch.no_grad():
            for _ in range(max_new_tokens):
                # The model cannot accept more than max_context_length tokens.
                context = generated[:, -self.max_context_length:]
                logits = self.model(context)
                next_token = logits[:, -1, :].argmax(
                    dim=-1,
                    keepdim=True,
                )

                if next_token.item() == eos_id:
                    break

                generated = torch.cat(
                    [generated, next_token],
                    dim=1,
                )

        response_ids = generated[0, prompt_length:].tolist()
        return self.tokenizer.decode(response_ids)


tiny_llm_service = TinyLLMService()
