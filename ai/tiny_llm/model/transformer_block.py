import torch.nn as nn

from .attention import CausalSelfAttention
from .feed_forward import FeedForward


class TransformerBlock(nn.Module):
    def __init__(
        self,
        embed_dim=256,
        num_heads=4,
        ff_dim=1024,
        dropout=0.1,
    ):
        super().__init__()

        self.attention = CausalSelfAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            dropout=dropout,
        )

        self.feed_forward = FeedForward(
            embed_dim=embed_dim,
            ff_dim=ff_dim,
            dropout=dropout,
        )

        self.norm1 = nn.LayerNorm(embed_dim)
        self.norm2 = nn.LayerNorm(embed_dim)

    def forward(self, x):
        # Self-attention + residual connection + normalization
        attention_output = self.attention(x)
        x = self.norm1(x + attention_output)

        # Feed-forward + residual connection + normalization
        ff_output = self.feed_forward(x)
        x = self.norm2(x + ff_output)

        return x
