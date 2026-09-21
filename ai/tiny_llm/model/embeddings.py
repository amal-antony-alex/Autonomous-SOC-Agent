import torch
import torch.nn as nn


class TokenPositionalEmbedding(nn.Module):
    def __init__(
        self,
        vocab_size=10000,
        embed_dim=256,
        max_seq_len=512,
    ):
        super().__init__()

        self.token_embedding = nn.Embedding(
            vocab_size,
            embed_dim,
        )

        self.position_embedding = nn.Embedding(
            max_seq_len,
            embed_dim,
        )

    def forward(self, input_ids):
        batch_size, seq_len = input_ids.shape

        if seq_len > self.position_embedding.num_embeddings:
            raise ValueError(
                f"Sequence length {seq_len} exceeds "
                f"maximum length "
                f"{self.position_embedding.num_embeddings}"
            )

        positions = torch.arange(
            seq_len,
            device=input_ids.device,
        ).unsqueeze(0)

        token_embeddings = self.token_embedding(input_ids)

        position_embeddings = self.position_embedding(
            positions
        )

        return token_embeddings + position_embeddings
