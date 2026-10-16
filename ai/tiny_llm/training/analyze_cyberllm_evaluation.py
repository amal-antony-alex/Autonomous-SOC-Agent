import json
import re
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

EVALUATION_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cyberllm_small_evaluation.jsonl"
)

REPORT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cyberllm_small_evaluation_report.json"
)


CYBER_TERMS = {
    "ssh",
    "authentication",
    "login",
    "brute force",
    "source ip",
    "username",
    "malware",
    "powershell",
    "process",
    "network",
    "lateral movement",
    "privilege",
    "ioc",
    "indicator",
    "mitre",
    "attack",
    "severity",
    "evidence",
    "investigation",
    "suspicious",
    "credential",
    "exfiltration",
    "firewall",
    "log",
    "host",
    "account",
    "connection",
}


TASK_KEYWORDS = {
    "alert_analysis": [
        "alert",
        "authentication",
        "security event",
        "evidence",
        "severity",
    ],
    "ioc_analysis": [
        "ioc",
        "indicator",
        "ip",
        "domain",
        "hash",
        "reputation",
    ],
    "log_analysis": [
        "log",
        "event",
        "timestamp",
        "process",
        "source",
        "destination",
    ],
    "mitre_mapping": [
        "mitre",
        "technique",
        "tactic",
        "attack",
    ],
    "incident_summary": [
        "incident",
        "summary",
        "host",
        "user",
        "source",
        "activity",
    ],
}


def normalize(text):
    return text.lower()


def get_terms(text, terms):
    text = normalize(text)

    return [
        term
        for term in terms
        if term in text
    ]


def infer_task(instruction):
    text = normalize(instruction)

    if "mitre" in text:
        return "mitre_mapping"

    if "ioc" in text or "indicator" in text:
        return "ioc_analysis"

    if "log" in text:
        return "log_analysis"

    if "incident" in text or "summary" in text:
        return "incident_summary"

    return "alert_analysis"


def main():

    print(
        "===== CYBERLLM EVALUATION ANALYSIS ====="
    )

    with open(
        EVALUATION_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        rows = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    print(
        f"Evaluation examples: {len(rows)}"
    )

    total_generated_terms = 0
    total_expected_terms = 0

    short_responses = 0

    task_stats = defaultdict(
        lambda: {
            "examples": 0,
            "generated_term_hits": 0,
            "expected_term_hits": 0,
            "short_responses": 0,
        }
    )

    results = []

    for row in rows:

        instruction = row[
            "instruction"
        ]

        expected = row[
            "expected_output"
        ]

        generated = row[
            "generated_output"
        ]

        task = infer_task(
            instruction
        )

        expected_terms = get_terms(
            expected,
            CYBER_TERMS,
        )

        generated_terms = get_terms(
            generated,
            CYBER_TERMS,
        )

        task_keywords = TASK_KEYWORDS.get(
            task,
            [],
        )

        task_expected = get_terms(
            expected,
            task_keywords,
        )

        task_generated = get_terms(
            generated,
            task_keywords,
        )

        is_short = (
            len(generated.split()) < 5
        )

        if is_short:
            short_responses += 1

        total_expected_terms += len(
            expected_terms
        )

        total_generated_terms += len(
            generated_terms
        )

        task_stats[task]["examples"] += 1
        task_stats[task][
            "generated_term_hits"
        ] += len(generated_terms)

        task_stats[task][
            "expected_term_hits"
        ] += len(expected_terms)

        if is_short:
            task_stats[task][
                "short_responses"
            ] += 1

        results.append(
            {
                "example": row["example"],
                "task": task,
                "expected_terms": expected_terms,
                "generated_terms": generated_terms,
                "task_expected_terms": task_expected,
                "task_generated_terms": task_generated,
                "generated_word_count": len(
                    generated.split()
                ),
                "short_response": is_short,
            }
        )

    print()
    print(
        "----- Overall -----"
    )

    print(
        "Total examples:",
        len(rows),
    )

    print(
        "Short responses:",
        short_responses,
    )

    print(
        "Average generated cyber-term hits:",
        round(
            total_generated_terms
            / max(len(rows), 1),
            2,
        ),
    )

    print(
        "Average expected cyber-term hits:",
        round(
            total_expected_terms
            / max(len(rows), 1),
            2,
        ),
    )

    print()
    print(
        "----- By Task -----"
    )

    for task, stats in sorted(
        task_stats.items()
    ):

        examples = stats["examples"]

        avg_generated = (
            stats["generated_term_hits"]
            / examples
        )

        avg_expected = (
            stats["expected_term_hits"]
            / examples
        )

        print(
            f"{task}: "
            f"{examples} examples | "
            f"Generated term hits: "
            f"{avg_generated:.2f} | "
            f"Expected term hits: "
            f"{avg_expected:.2f} | "
            f"Short: "
            f"{stats['short_responses']}"
        )

    report = {
        "model": "CyberLLM-Small-v1",
        "total_examples": len(rows),
        "short_responses": short_responses,
        "average_generated_cyber_term_hits": (
            total_generated_terms
            / max(len(rows), 1)
        ),
        "average_expected_cyber_term_hits": (
            total_expected_terms
            / max(len(rows), 1)
        ),
        "task_statistics": dict(task_stats),
        "example_results": results,
    }

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print(
        f"Report saved to:\n{REPORT_FILE}"
    )


if __name__ == "__main__":
    main()
