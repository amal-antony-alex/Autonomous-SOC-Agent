import torch

from ai.tiny_llm.model.tiny_llm import TinyLLM


def main():
    vocab_size = 10000

    model = TinyLLM(
        vocab_size=vocab_size,
        embed_dim=256,
        num_layers=4,
        num_heads=4,
        ff_dim=1024,
        max_seq_len=512,
    )

    model.eval()

    # Simulated tokenized cybersecurity input
    input_ids = torch.tensor(
        [[101, 205, 412, 789, 1200, 450, 67, 901]]
    )

    with torch.no_grad():
        logits = model(input_ids)

    # Get the predicted next token
    next_token_logits = logits[:, -1, :]
    next_token = torch.argmax(
        next_token_logits,
        dim=-1,
    )

    print("Input token IDs:")
    print(input_ids)

    print("\nLogits shape:")
    print(logits.shape)

    print("\nNext predicted token ID:")
    print(next_token.item())

    print("\nTiny LLM smoke test: PASSED")


if __name__ == "__main__":
    main()
