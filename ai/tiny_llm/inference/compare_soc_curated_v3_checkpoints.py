import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import torch

from ai.tiny_llm.model.tiny_llm_small import TinyLLMSmall
from ai.tiny_llm.tokenizer.cyber_bpe_tokenizer import CyberBPETokenizer


TOKENIZER_PATH = ROOT / "ai/tiny_llm/tokenizer/artifacts/cyber_bpe/tokenizer.json"

CHECKPOINTS = {
    "base": ROOT / "ai/tiny_llm/checkpoints/cyberllm_v2_2_soc_metrics_best.pt",
    "fine_tuned": ROOT / "ai/tiny_llm/checkpoints/soc_curated_v3_splits_v2/best_validation.pt",
}

OUTPUT_PATH = (
    ROOT
    / "ai/tiny_llm/evaluations/soc_curated_v3_splits_v2/"
    / "base_vs_finetuned_generation_comparison.json"
)

MAX_NEW_TOKENS = 120

TEST_CASES = [
    {
        "id": "alert_analysis_01",
        "category": "alert_analysis",
        "instruction": (
            "Assess the alert using only the supplied evidence; "
            "separate facts from hypotheses."
        ),
        "input": (
            "Alert ID: GEN-001\n"
            "Host: DC-01\n"
            "User: j.smith\n"
            "Observed behavior: privileged account authenticated "
            "from an unusual source\n"
            "Source: 172.16.8.7\n"
            "Destination: 203.0.113.46\n"
            "Business purpose: undocumented\n"
            "Authentication outcome: successful\n"
            "MFA result: unavailable\n"
            "Post-login activity: unknown"
        ),
    },
    {
        "id": "powershell_01",
        "category": "alert_analysis",
        "instruction": (
            "Analyze the observed activity. Separate facts, "
            "hypotheses, and recommended validation steps."
        ),
        "input": (
            "Alert ID: GEN-002\n"
            "Host: WS-104\n"
            "Process: powershell.exe\n"
            "Command line: powershell.exe -EncodedCommand [REDACTED]\n"
            "Parent process: winword.exe\n"
            "User: analyst1\n"
            "Decoded command: unavailable\n"
            "Process network connections: unknown"
        ),
    },
    {
        "id": "ioc_analysis_01",
        "category": "ioc_analysis",
        "instruction": (
            "Analyze the supplied indicators. Do not claim an "
            "indicator is malicious without supporting evidence."
        ),
        "input": (
            "Alert ID: GEN-003\n"
            "Source IP: 203.0.113.50\n"
            "Destination IP: 10.0.0.15\n"
            "File hash: 44d88612fea8a8f36de82e1278abb02f\n"
            "Threat intelligence reputation: unavailable\n"
            "Connection outcome: unknown"
        ),
    },
    {
        "id": "mitre_mapping_01",
        "category": "mitre_mapping",
        "instruction": (
            "Map the observed behavior to MITRE ATT&CK only when "
            "the evidence supports a technique; explain uncertainty."
        ),
        "input": (
            "Alert ID: GEN-004\n"
            "Observed behavior: multiple failed SSH login attempts\n"
            "Source: 198.51.100.24\n"
            "Target: linux-server-02\n"
            "Successful authentication: not observed in supplied data\n"
            "Credential use after attempts: unknown"
        ),
    },
    {
        "id": "incident_summary_01",
        "category": "incident_summary",
        "instruction": (
            "Write a concise SOC incident summary that separates "
            "observed facts from unresolved questions."
        ),
        "input": (
            "Alert ID: GEN-005\n"
            "Host: server02\n"
            "User: administrator\n"
            "Source IP: 203.0.113.25\n"
            "Failed logins: 6\n"
            "Successful login: yes\n"
            "Outbound connection: 203.0.113.90:443\n"
            "Time window: 5 minutes\n"
            "Process responsible for connection: unknown\n"
            "Data transfer volume: unavailable"
        ),
    },
]


def load_checkpoint(path, tokenizer, device):
    if not path.is_file():
        raise FileNotFoundError(f"Checkpoint not found: {path}")

    checkpoint = torch.load(
        path,
        map_location=device,
        weights_only=True,
    )

    if tokenizer.vocab_size != checkpoint["vocab_size"]:
        raise ValueError(
            f"Tokenizer vocabulary ({tokenizer.vocab_size}) does not match "
            f"checkpoint vocabulary ({checkpoint['vocab_size']}) for {path}"
        )

    model = TinyLLMSmall(
        vocab_size=checkpoint["vocab_size"],
        embed_dim=128,
        num_layers=2,
        num_heads=4,
        ff_dim=512,
        max_seq_len=checkpoint["max_seq_len"],
        dropout=0.1,
    ).to(device)

    model.load_state_dict(checkpoint["model_state_dict"], strict=True)
    model.eval()

    return model, checkpoint


def generate(model, tokenizer, device, prompt):
    input_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False,
    )

    generated = torch.tensor(
        [input_ids],
        dtype=torch.long,
        device=device,
    )

    eos_id = tokenizer.token_to_id.get("<EOS>")
    generated_ids = []
    stop_reason = "max_new_tokens"

    with torch.inference_mode():
        for _ in range(MAX_NEW_TOKENS):
            # Avoid exceeding the model's maximum context length.
            context = generated[:, -model.max_seq_len:]
            logits = model(context)
            next_token_id = int(torch.argmax(logits[0, -1, :]).item())

            if eos_id is not None and next_token_id == eos_id:
                stop_reason = "eos"
                break

            generated_ids.append(next_token_id)
            next_token = torch.tensor(
                [[next_token_id]],
                dtype=torch.long,
                device=device,
            )
            generated = torch.cat([generated, next_token], dim=1)

            if generated.shape[1] >= model.max_seq_len:
                stop_reason = "context_limit"
                break

    return tokenizer.decode(generated_ids), stop_reason, len(input_ids)


def main():
    if not TOKENIZER_PATH.is_file():
        raise FileNotFoundError(f"Tokenizer not found: {TOKENIZER_PATH}")

    device = torch.device("cpu")
    tokenizer = CyberBPETokenizer(TOKENIZER_PATH)

    print("Tokenizer:", TOKENIZER_PATH)
    print("Vocabulary:", tokenizer.vocab_size)
    print("Device:", device)
    print("Decoding: greedy (argmax)")
    print("Prompts: the same five synthetic scenarios for both checkpoints")
    print("Held-out test set: not loaded or modified")

    models = {}
    metadata = {}

    for name, path in CHECKPOINTS.items():
        model, checkpoint = load_checkpoint(path, tokenizer, device)
        models[name] = model
        metadata[name] = {
            "path": str(path.relative_to(ROOT)),
            "model_type": checkpoint.get("model_type"),
            "epoch": checkpoint.get("epoch"),
            "recorded_validation_loss": checkpoint.get("val_loss"),
        }

        print(
            f"\nLoaded {name}: "
            f"type={metadata[name]['model_type']}, "
            f"epoch={metadata[name]['epoch']}, "
            f"recorded validation loss="
            f"{metadata[name]['recorded_validation_loss']}"
        )

    results = []

    for case in TEST_CASES:
        prompt = (
            "Instruction:\n"
            + case["instruction"]
            + "\n\nInput:\n"
            + case["input"]
            + "\n\nResponse:\n"
        )

        result = {
            "id": case["id"],
            "category": case["category"],
            "instruction": case["instruction"],
            "input": case["input"],
            "prompt_tokens": len(
                tokenizer.encode(prompt, add_bos=True, add_eos=False)
            ),
            "decoding": "greedy",
            "generated_tokens_limit": MAX_NEW_TOKENS,
            "outputs": {},
        }

        print(f"\n{'=' * 72}")
        print(f"CASE: {case['id']} ({case['category']})")

        for name, model in models.items():
            response, stop_reason, prompt_tokens = generate(
                model, tokenizer, device, prompt
            )

            result["outputs"][name] = {
                "response": response,
                "stop_reason": stop_reason,
                "prompt_tokens": prompt_tokens,
            }

            print(f"\n--- {name.upper()} ---")
            print(response or "[EMPTY RESPONSE]")
            print("Stop reason:", stop_reason)

        results.append(result)

    report = {
        "purpose": "Qualitative generation comparison; not a benchmark",
        "tokenizer": str(TOKENIZER_PATH.relative_to(ROOT)),
        "device": str(device),
        "decoding": "greedy",
        "max_new_tokens": MAX_NEW_TOKENS,
        "checkpoints": metadata,
        "test_set_used": False,
        "cases": results,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"\nSaved comparison report to:\n{OUTPUT_PATH}")


if __name__ == "__main__":
    main()
