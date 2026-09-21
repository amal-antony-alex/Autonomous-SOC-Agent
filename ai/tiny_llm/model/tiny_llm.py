import torch
import torch.nn as nn

from .embeddings import TokenPositionalEmbedding
from .transformer_block import TransformerBlock


class TinyLLM(nn.Module):
    def __init__(
        self,
        vocab_size=10000,
        embed_dim=256,
        num_layers=4,
        num_heads=4,
        ff_dim=1024,
        max_seq_len=512,
        dropout=0.1,
    ):
        super().__init__()

        self.max_seq_len = max_seq_len

        self.embedding = TokenPositionalEmbedding(
            vocab_size=vocab_size,
            embed_dim=embed_dim,
            max_seq_len=max_seq_len,
        )

        self.transformer_blocks = nn.ModuleList(
            [
                TransformerBlock(
                    embed_dim=embed_dim,
                    num_heads=num_heads,
                    ff_dim=ff_dim,
                    dropout=dropout,
                )
                for _ in range(num_layers)
            ]
        )

        self.norm = nn.LayerNorm(embed_dim)

        self.lm_head = nn.Linear(
            embed_dim,
            vocab_size,
        )

    def forward(self, input_ids):
        _, seq_len = input_ids.shape

        if seq_len > self.max_seq_len:
            raise ValueError(
                f"Sequence length {seq_len} exceeds "
                f"maximum length {self.max_seq_len}"
            )

        x = self.embedding(input_ids)

        for block in self.transformer_blocks:
            x = block(x)

        x = self.norm(x)

        logits = self.lm_head(x)

        return logits
