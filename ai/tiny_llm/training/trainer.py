import torch
import torch.nn as nn


class TinyLLMTrainer:
    def __init__(
        self,
        model,
        learning_rate=3e-4,
        device=None,
    ):
        self.device = device or (
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        self.model = model.to(self.device)

        self.loss_function = nn.CrossEntropyLoss()

        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
        )

    def train_step(self, input_ids, target_ids):
        self.model.train()

        input_ids = input_ids.to(self.device)
        target_ids = target_ids.to(self.device)

        self.optimizer.zero_grad()

        logits = self.model(input_ids)

        batch_size, seq_len, vocab_size = logits.shape

        loss = self.loss_function(
            logits.reshape(
                batch_size * seq_len,
                vocab_size,
            ),
            target_ids.reshape(
                batch_size * seq_len
            ),
        )

        loss.backward()

        self.optimizer.step()

        return loss.item()
