from pathlib import Path

import torch

from ai.tiny_llm.model.tiny_llm import TinyLLM
from ai.tiny_llm.tokenizer.bpe_tokenizer import BPETokenizer


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TOKENIZER_PATH = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "tokenizer"
    / "artifacts"
    / "tokenizer.json"
)

CHECKPOINT_PATH = (
    PROJECT_ROOT
    / "ai"
    / "tiny_llm"
    / "checkpoints"
    / "cyberllm_v1_1.pt"
)


def load_model():

    device = torch.device("cpu")

    tokenizer = BPETokenizer()
    tokenizer.load(TOKENIZER_PATH)

    vocab_size = len(
        tokenizer.token_to_id
    )

    model = TinyLLM(
        vocab_size=vocab_size
    ).to(device)

    checkpoint = torch.load(
        CHECKPOINT_PATH,
        map_location=device,
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.eval()

    return model, tokenizer, device


def generate(
    model,
    tokenizer,
    device,
    prompt,
    max_new_tokens=80,
):

    token_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False,
    )

    input_ids = torch.tensor(
        [token_ids],
        dtype=torch.long,
        device=device,
    )

    generated = input_ids.clone()

    with torch.no_grad():

        for _ in range(max_new_tokens):

            if generated.shape[1] >= model.max_seq_len:
                break

            logits = model(
                generated
            )

            next_token_logits = logits[
                0,
                -1,
                :
            ]

            next_token_id = torch.argmax(
                next_token_logits
            ).item()

            next_token = torch.tensor(
                [[next_token_id]],
                dtype=torch.long,
                device=device,
            )

            generated = torch.cat(
                [generated, next_token],
                dim=1,
            )

            if next_token_id == tokenizer.token_to_id["<EOS>"]:
                break

    generated_ids = generated[
        0
    ].tolist()

    return tokenizer.decode(
        generated_ids
    )


def main():

    model, tokenizer, device = load_model()

    test_cases = [

        (
            "ALERT ANALYSIS",
            """Instruction:
Analyze the supplied security alert.

Input:
Rule: SSH authentication failure
Source IP: 192.168.1.100
Username: admin
Failed login attempts: 5
Target: server01

Response:""",
        ),

        (
            "IOC ANALYSIS",
            """Instruction:
Identify the important indicators of compromise.

Input:
Source IP: 203.0.113.50
Destination IP: 10.0.0.15
File hash: 44d88612fea8a8f36de82e1278abb02f
Username: administrator

Response:""",
        ),

        (
            "MITRE MAPPING",
            """Instruction:
Map the observed security event to MITRE ATT&CK.

Input:
Multiple failed SSH login attempts were observed from
an external IP address.

Response:""",
        ),

        (
            "INCIDENT SUMMARY",
            """Instruction:
Create a concise SOC incident summary.

Input:
Host: server02
User: administrator
Source IP: 203.0.113.25
Failed logins: 6
Successful login: yes
Outbound connection: 203.0.113.90:443
Time window: 5 minutes

Response:""",
        ),

    ]

    print("\n========================================")
    print("       CyberLLM v1 Evaluation")
    print("========================================")

    for name, prompt in test_cases:

        print(f"\n===== {name} =====")
        print("\nPROMPT:")
        print(prompt)

        response = generate(
            model,
            tokenizer,
            device,
            prompt,
        )

        print("\nMODEL OUTPUT:")
        print(response)


if __name__ == "__main__":
    main()
