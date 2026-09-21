import torch.nn as nn


class LanguageModelHead(nn.Module):
    def __init__(
        self,
        embed_dim=256,
        vocab_size=10000,
    ):
        super().__init__()

        self.projection = nn.Linear(
            embed_dim,
            vocab_size,
        )

    def forward(self, x):
        return self.projection(x)
