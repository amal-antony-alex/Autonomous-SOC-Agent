import torch
from pathlib import Path

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


CHECKPOINT = Path(
    "ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt"
)

TOKENIZER_PATH = Path(
    "ai/tiny_llm/tokenizer/artifacts/"
    "cyber_bpe/tokenizer.json"
)

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


def load_model():

    tokenizer = CyberBPETokenizer()
    tokenizer.load(TOKENIZER_PATH)

    checkpoint = torch.load(
        CHECKPOINT,
        map_location=DEVICE
    )

    model = TinyLLMSmall(
        vocab_size=checkpoint["vocab_size"],
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=checkpoint["max_seq_len"],
        dropout=0.1,
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.to(DEVICE)
    model.eval()

    return model, tokenizer


def generate(
    model,
    tokenizer,
    prompt,
    max_new_tokens=100,
    temperature=0.7,
    top_k=20,
):

    input_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False
    )

    input_ids = torch.tensor(
        [input_ids],
        dtype=torch.long,
        device=DEVICE
    )

    generated = input_ids.clone()

    with torch.no_grad():

        for _ in range(max_new_tokens):

            context = generated[
                :, -model.max_seq_len:
            ]

            logits = model(context)

            next_token_logits = logits[
                :, -1, :
            ]

            next_token_logits /= temperature

            if top_k is not None:

                values, indices = torch.topk(
                    next_token_logits,
                    min(top_k, next_token_logits.size(-1))
                )

                filtered = torch.full_like(
                    next_token_logits,
                    float("-inf")
                )

                filtered.scatter_(
                    1,
                    indices,
                    values
                )

                next_token_logits = filtered

            probabilities = torch.softmax(
                next_token_logits,
                dim=-1
            )

            next_token = torch.multinomial(
                probabilities,
                num_samples=1
            )

            generated = torch.cat(
                [generated, next_token],
                dim=1
            )

            eos_id = tokenizer.token_to_id.get(
                "<EOS>"
            )

            if eos_id is not None:
                if next_token.item() == eos_id:
                    break

    return tokenizer.decode(
        generated[0].tolist()
    )


def main():

    print(
        "===== CYBERLLM V2 GENERATION TEST ====="
    )

    print(f"Device: {DEVICE}")

    model, tokenizer = load_model()

    print(
        f"Checkpoint loaded:\n  {CHECKPOINT}"
    )

    print(
        f"Tokenizer vocabulary: "
        f"{tokenizer.vocab_size}"
    )

    prompts = [

        # ------------------------------------------------
        # 1. Wazuh SSH alert
        # ------------------------------------------------

        """Instruction:
Analyze the following security alert and identify the likely security event, supporting evidence, and recommended severity.

Input:
Rule: 5710
Description: sshd: Attempt to login using a non-existent user
Source IP: 192.168.1.200
Username: admin
Full Log: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2

Response:""",

        # ------------------------------------------------
        # 2. PowerShell
        # ------------------------------------------------

        """Instruction:
Analyze the following security alert and identify the likely security event, supporting evidence, and recommended severity.

Input:
Rule: 100501
Description: Suspicious PowerShell execution
Source IP: 10.0.0.25
Username: administrator
Full Log: powershell.exe -EncodedCommand SQBtAHAAcgBvAHQ=

Response:""",

        # ------------------------------------------------
        # 3. IOC
        # ------------------------------------------------

        """Instruction:
Analyze the following indicator of compromise and explain its significance.

Input:
IOC Type: IPv4
IOC: 203.0.113.50
Context: The address was observed in repeated outbound connections from a compromised workstation.

Response:""",

        # ------------------------------------------------
        # 4. MITRE mapping
        # ------------------------------------------------

        """Instruction:
Map the following security behavior to the most relevant MITRE ATT&CK technique.

Input:
Behavior: An attacker uses PowerShell to execute commands on a Windows host.

Response:""",

        # ------------------------------------------------
        # 5. Incident summary
        # ------------------------------------------------

        """Instruction:
Create a concise SOC incident summary for the observed authentication and network activity.

Input:
Host: server02
User: administrator
Source IP: 203.0.113.25
Failed logins: 6
Successful login: yes
Outbound connection: 203.0.113.90:443
Time window: 5 minutes

Response:""",
    ]

    for index, prompt in enumerate(
        prompts,
        start=1
    ):

        print()
        print("=" * 70)
        print(f"TEST {index}")
        print("=" * 70)

        print()
        print("PROMPT:")
        print(prompt)

        print()
        print("GENERATED RESPONSE:")

        response = generate(
            model,
            tokenizer,
            prompt,
            max_new_tokens=100,
            temperature=0.7,
            top_k=20,
        )

        # Remove the original prompt from the
        # displayed output if the model repeats it.
        if "Response:" in response:
            response = response.split(
                "Response:",
                1
            )[-1].strip()

        print(response)

    print()
    print(
        "===== GENERATION TEST COMPLETE ====="
    )


if __name__ == "__main__":
    main()
