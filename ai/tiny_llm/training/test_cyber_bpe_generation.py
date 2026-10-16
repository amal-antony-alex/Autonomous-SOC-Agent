from pathlib import Path

import torch

from ai.tiny_llm.model.tiny_llm import TinyLLM
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TOKENIZER_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "cyber_bpe"
    / "tokenizer.json"
)

CHECKPOINT_FILE = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
    / "tiny_llm_cyber_bpe_best.pt"
)


def main():

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

    print("===== CYBER BPE GENERATION TEST =====")
    print(f"Device: {device}")

    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    checkpoint = torch.load(
        CHECKPOINT_FILE,
        map_location=device,
    )

    model = TinyLLM(
        vocab_size=checkpoint["vocab_size"],
        max_seq_len=checkpoint["max_seq_len"],
        embed_dim=checkpoint["embed_dim"],
        num_heads=checkpoint["num_heads"],
        num_layers=checkpoint["num_layers"],
        ff_dim=checkpoint["ff_dim"],
    ).to(device)

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.eval()

    print(
        f"Loaded checkpoint from epoch "
        f"{checkpoint['epoch']}"
    )

    print(
        f"Validation loss: "
        f"{checkpoint['val_loss']:.4f}"
    )

    prompt = (
        "Multiple failed SSH authentication attempts "
        "from the same source IP may indicate"
    )

    print()
    print("Prompt:")
    print(prompt)

    input_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False,
    )

    generated_ids = list(input_ids)

    max_new_tokens = 60

    temperature = 0.8
    top_k = 20

    eos_id = tokenizer.token_to_id.get(
        "<EOS>"
    )

    with torch.no_grad():

        for _ in range(max_new_tokens):

            context = generated_ids[
                -checkpoint["max_seq_len"]:
            ]

            input_tensor = torch.tensor(
                [context],
                dtype=torch.long,
                device=device,
            )

            logits = model(input_tensor)

            next_token_logits = logits[
                0, -1, :
            ]

            # Temperature controls randomness.
            next_token_logits = (
                next_token_logits / temperature
            )

            # Keep only the top-k candidate tokens.
            top_values, top_indices = torch.topk(
                next_token_logits,
                min(
                    top_k,
                    next_token_logits.size(-1),
                ),
            )

            probabilities = torch.softmax(
                top_values,
                dim=-1,
            )

            # Sample from the selected candidates.
            sampled_index = torch.multinomial(
                probabilities,
                num_samples=1,
            ).item()

            next_token_id = top_indices[
                sampled_index
            ].item()

            generated_ids.append(
                next_token_id
            )

            if (
                eos_id is not None
                and next_token_id == eos_id
            ):
                break

    generated_text = tokenizer.decode(
        generated_ids
    )

    print()
    print("Generated:")
    print(generated_text)

    print()
    print("Generation test complete.")


if __name__ == "__main__":
    main()
