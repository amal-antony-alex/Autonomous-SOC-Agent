
import json
import re
from collections import Counter
from pathlib import Path

SOURCE = Path("data/raw/cybersecurity_instruction_dataset.jsonl")
OUT_DIR = Path("data/raw/soc_curated_v3")
OUTPUT = OUT_DIR / "soc_source_labeled_v1.jsonl"
REPORT = OUT_DIR / "soc_source_labeled_v1_report.json"

# Broad patterns are retained for secondary review only.
RULES = [
    ("mitre_mapping", r"\bMITRE\b|\bATT&CK\b|\btechnique\b|\bT\d{4}(?:\.\d{3})?\b"),
    ("incident_summary", r"\bsummary\b|\bsummarize\b|\bsummarise\b|\bincident report\b"),
    ("ioc_analysis", r"\bIOC\b|\bindicators? of compromise\b|\benrichment\b"),
    ("severity_classification", r"\bseverity\b|\bcritical severity\b"),
    ("false_positive_assessment", r"\bfalse positive\b|\bbenign\b"),
    ("uncertainty_analysis", r"\buncertain\b|\bmissing evidence\b|\binsufficient evidence\b|\bwithout inventing\b"),
    ("alert_correlation", r"\bcorrelat(?:e|ion|ed|ing)\b|\bsequence\b|\bmultiple weak indicators\b"),
    ("log_analysis", r"\blogs?\b|\bevent ID\b|\bfull log\b"),
    ("alert_analysis", r"\banaly[sz]e\b|\balert\b|\bsecurity event\b"),
]

def matches_for(text):
    return [
        category
        for category, pattern in RULES
        if re.search(pattern, text, re.IGNORECASE)
    ]

def classify(row):
    instruction = row.get("instruction", "").strip()
    input_text = row.get("input", "").strip()
    instruction_lower = instruction.lower()
    combined_text = f"{instruction} {input_text}"

    # Classify by the task explicitly requested in the instruction.
    if re.search(
        r"\b(incident summary|soc incident summary|incident report|"
        r"incident summary from|summary of the incident|summarize the incident|"
        r"summarise the incident|create a concise soc summary|"
        r"create a soc incident summary|summarize the security event)\b",
        instruction_lower,
    ):
        primary = "incident_summary"

    elif re.search(r"\b(mitre|att&ck)\b", instruction_lower) and re.search(
        r"\b(map|mapping|identify|associated|technique)\b", instruction_lower
    ):
        primary = "mitre_mapping"

    elif re.search(
        r"\b(ioc|indicators? of compromise|indicator categories|"
        r"threat intelligence enrichment|ioc reputation|enrichment findings)\b",
        instruction_lower,
    ):
        primary = "ioc_analysis"

    elif re.search(r"\b(severity|critical severity)\b", instruction_lower):
        primary = "severity_classification"

    elif re.search(r"\b(false positive)\b", instruction_lower):
        primary = "false_positive_assessment"

    elif re.search(r"\b(could be benign|evidence that could indicate a false positive)\b", instruction_lower):
        primary = "false_positive_assessment"

    elif re.search(
        r"\b(correlate|correlation|authentication sequence|"
        r"multiple weak indicators|process and network events)\b",
        instruction_lower,
    ):
        primary = "alert_correlation"

    elif re.search(r"\b(log|logs|event id|log sequence|log analysis)\b", instruction_lower):
        primary = "log_analysis"

    elif re.search(
        r"\b(uncertain|missing evidence|insufficient evidence|"
        r"without inventing evidence|should remain uncertain)\b",
        instruction_lower,
    ):
        primary = "uncertainty_analysis"

    elif re.search(
        r"\b(analy[sz]e|alert|security event|determine whether|"
        r"determine what additional evidence)\b",
        instruction_lower,
    ):
        primary = "alert_analysis"

    else:
        primary = "manual_review"

    candidates = matches_for(combined_text)

    # Multiple task indicators mean human review is still required.
    ambiguous = len(candidates) > 1 or primary == "manual_review"

    return primary, candidates, ambiguous

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with SOURCE.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    counts = Counter()
    review_counts = Counter()
    labeled_rows = []

    for i, row in enumerate(rows, 1):
        category, candidates, ambiguous = classify(row)

        item = {
            **row,
            "category": category,
            "category_candidates": candidates,
            "scenario_family": "unreviewed",
            "source": "existing_soc_source",
            "review_status": (
                "REQUIRES_MANUAL_REVIEW"
                if ambiguous
                else "PROVISIONAL_REVIEW_REQUIRED"
            ),
            "source_record_id": f"SOC-SRC-{i:03d}",
        }

        labeled_rows.append(item)
        counts[category] += 1

        if ambiguous:
            review_counts[category] += 1

    with OUTPUT.open("w", encoding="utf-8") as f:
        for item in labeled_rows:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    report = {
        "input_records": len(rows),
        "output_records": len(labeled_rows),
        "category_counts": dict(sorted(counts.items())),
        "records_requiring_manual_review": sum(review_counts.values()),
        "review_counts_by_category": dict(sorted(review_counts.items())),
        "status": "PROVISIONAL_LABELS_REQUIRING_REVIEW",
        "notes": [
            "The original source file was not modified.",
            "Primary labels are heuristic suggestions, not verified ground truth.",
            "Secondary category candidates may overlap.",
            "Ambiguous records require human review.",
            "Scenario families must be reviewed before dataset splitting.",
            "No model training was performed.",
        ],
    }

    REPORT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print(f"\nLabeled copy: {OUTPUT}")
    print(f"Report: {REPORT}")

if __name__ == "__main__":
    main()
