import torch
import torch.nn as nn


class TransformerBlock(nn.Module):
    def __init__(
        self,
        embed_dim=256,
        num_heads=4,
        ff_dim=1024,
        dropout=0.1,
    ):
        super().__init__()

        self.attention = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )

        self.norm1 = nn.LayerNorm(embed_dim)
        self.norm2 = nn.LayerNorm(embed_dim)

        self.feed_forward = nn.Sequential(
            nn.Linear(embed_dim, ff_dim),
            nn.GELU(),
            nn.Linear(ff_dim, embed_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x, causal_mask=None):
        attention_output, _ = self.attention(
            x,
            x,
            x,
            attn_mask=causal_mask,
            need_weights=False,
        )

        x = self.norm1(x + attention_output)

        ff_output = self.feed_forward(x)

        x = self.norm2(x + ff_output)

        return x
