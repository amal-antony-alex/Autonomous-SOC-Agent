import torch.nn as nn


class FeedForward(nn.Module):
    def __init__(
        self,
        embed_dim=256,
        ff_dim=1024,
        dropout=0.1,
    ):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(embed_dim, ff_dim),
            nn.GELU(),
            nn.Linear(ff_dim, embed_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x):
        return self.network(x)
