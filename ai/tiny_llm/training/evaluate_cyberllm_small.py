import json
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

DATASET_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_instruction_dataset.jsonl"
)


def generate_response(
    model,
    tokenizer,
    prompt,
    checkpoint,
    device,
    max_new_tokens=80,
):

    input_ids = tokenizer.encode(
        prompt,
        add_bos=True,
        add_eos=False,
    )

    generated_ids = list(input_ids)

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

    full_text = tokenizer.decode(
        generated_ids
    )

    if "Response:" in full_text:
        response = full_text.split(
            "Response:",
            1
        )[1]
    else:
        response = full_text

    return response.strip()


def main():

    print(
        "===== CYBERLLM SMALL EVALUATION ====="
    )

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

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

    with open(
        DATASET_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        examples = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    print(
        f"Evaluation examples: {len(examples)}"
    )

    output_file = (
        PROJECT_ROOT
        / "data"
        / "processed"
        / "cyberllm_small_evaluation.jsonl"
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as output:

        for index, example in enumerate(
            examples,
            start=1,
        ):

            instruction = example[
                "instruction"
            ].strip()

            input_text = example[
                "input"
            ].strip()

            expected = example[
                "output"
            ].strip()

            prompt = (
                "Instruction:\n"
                f"{instruction}\n\n"
                "Input:\n"
                f"{input_text}\n\n"
                "Response:\n"
            )

            generated = generate_response(
                model,
                tokenizer,
                prompt,
                checkpoint,
                device,
            )

            result = {
                "example": index,
                "instruction": instruction,
                "input": input_text,
                "expected_output": expected,
                "generated_output": generated,
            }

            output.write(
                json.dumps(
                    result,
                    ensure_ascii=False,
                )
                + "\n"
            )

            print(
                f"[{index:03d}/{len(examples)}]"
            )

    print()
    print(
        "Evaluation complete."
    )

    print(
        f"Results saved to:\n{output_file}"
    )


if __name__ == "__main__":
    main()
