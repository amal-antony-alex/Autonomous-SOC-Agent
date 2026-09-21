import torch
import torch.nn as nn


class CausalSelfAttention(nn.Module):
    def __init__(
        self,
        embed_dim=256,
        num_heads=4,
        dropout=0.1,
    ):
        super().__init__()

        self.attention = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )

    def forward(self, x):
        batch_size, seq_len, _ = x.shape

        # Prevent the model from looking at future tokens.
        causal_mask = torch.triu(
            torch.ones(
                seq_len,
                seq_len,
                device=x.device,
                dtype=torch.bool,
            ),
            diagonal=1,
        )

        output, _ = self.attention(
            x,
            x,
            x,
            attn_mask=causal_mask,
            need_weights=False,
        )

        return output
