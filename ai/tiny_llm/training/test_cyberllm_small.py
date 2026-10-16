from pathlib import Path

import torch

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
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
    / "cyberllm_small_v1_best.pt"
)


def main():

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

    print("===== CYBERLLM SMALL TEST =====")
    print(f"Device: {device}")

    tokenizer = CyberBPETokenizer(
        TOKENIZER_FILE
    )

    checkpoint = torch.load(
        CHECKPOINT_FILE,
        map_location=device,
    )

    model = TinyLLMSmall(
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
        f"Loaded CyberLLM checkpoint from epoch "
        f"{checkpoint['epoch']}"
    )

    print(
        f"Validation loss: "
        f"{checkpoint['val_loss']:.4f}"
    )

    instruction = (
        "Analyze the following security alert and "
        "identify the likely security event, supporting "
        "evidence, and recommended severity."
    )

    input_text = (
        "Rule: 5710\n"
        "Description: sshd: Attempt to login using "
        "a non-existent user\n"
        "Source IP: 192.168.1.200\n"
        "Username: admin\n"
        "Full Log: Failed password for invalid user "
        "admin from 192.168.1.200 port 22 ssh2"
    )

    prompt = (
        "Instruction:\n"
        f"{instruction}\n\n"
        "Input:\n"
        f"{input_text}\n\n"
        "Response:\n"
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

    max_new_tokens = 80

    temperature = 0.7
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

            next_token_logits = (
                next_token_logits / temperature
            )

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
    print("CyberLLM test complete.")


if __name__ == "__main__":
    main()
