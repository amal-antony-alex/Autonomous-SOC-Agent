
import json
import re
from collections import Counter
from pathlib import Path

DATASET = Path(
    "data/raw/soc_curated_v3/"
    "soc_training_v4_revision_v6_4_1.jsonl"
)
OUT = Path(
    "data/raw/soc_curated_v3/"
    "v6_4_1_severity_consistency_flags.jsonl"
)

SEVERITIES = ("Critical", "High", "Medium", "Low")

def main():
    records = []
    with DATASET.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("category") == "severity_classification":
                records.append((line_no, row))

    if len(records) != 500:
        raise SystemExit(f"Expected 500 records, found {len(records)}")

    flags = []
    labels = Counter()

    for line_no, row in records:
        inp = row.get("input", "")
        out = row.get("output", "")
        match = re.search(
            r"Preliminary severity:\s*(Critical|High|Medium|Low)\b",
            out,
            re.IGNORECASE,
        )
        if not match:
            flags.append({
                "dataset_line": line_no,
                "scenario_id": row.get("scenario_id"),
                "reason": "Missing or unrecognized preliminary severity",
                "review_status": "PENDING_HUMAN_REVIEW",
            })
            continue

        severity = match.group(1).capitalize()
        labels[severity] += 1
        text = f"{inp}\n{out}".lower()
        reasons = []

        # High-impact indicators with a potentially low assigned label.
        high_impact = any(term in inp.lower() for term in (
            "confirmed ransomware",
            "business services are unavailable",
            "destructive activity",
            "sensitive records were accessed unusually",
            "privileged account and suspicious execution",
        ))
        if high_impact and severity in ("Medium", "Low"):
            reasons.append(
                "Potential high-impact evidence with Medium/Low label"
            )

        if "confidence: low" in inp.lower():
            if severity in ("Critical", "High"):
                if not any(term in out.lower() for term in (
                    "escalat", "urgently", "preserve evidence",
                    "preserve relevant", "incident commander",
                )):
                    reasons.append(
                        "Low-confidence High/Critical case lacks clear escalation/evidence language"
                    )

        if "change ticket" in inp.lower() or "change record" in inp.lower():
            if severity == "Low" and not any(term in out.lower() for term in (
                "confirm scope", "verify", "before closing",
                "before closure", "contradictory alerts",
            )):
                reasons.append(
                    "Low label with change record lacks explicit validation safeguard"
                )

        if reasons:
            flags.append({
                "dataset_line": line_no,
                "scenario_id": row.get("scenario_id"),
                "assigned_severity": severity,
                "reasons": reasons,
                "review_status": "PENDING_HUMAN_REVIEW",
                "input": inp,
                "output": out,
            })

    with OUT.open("w", encoding="utf-8") as f:
        for item in flags:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print("Severity records checked:", len(records))
    print("Severity label counts:", dict(labels))
    print("Records flagged for human review:", len(flags))
    print("Review flags saved to:", OUT)
    print("Flags are review candidates, not confirmed errors.")

if __name__ == "__main__":
    main()
