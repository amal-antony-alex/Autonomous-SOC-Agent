#!/usr/bin/env python3
"""Independent structural and targeted consistency auditor for SOC dataset v6.

Run from the project root:
    python ai/tiny_llm/training/audit_soc_training_v6.py

This is a heuristic audit, not proof of factual SOC reasoning. Human review is
still required before training.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path.cwd()
DATASET = ROOT / "data/raw/soc_curated_v3/soc_training_v4_revision_v6.jsonl"
REPORT = ROOT / "data/raw/soc_curated_v3/soc_training_v4_revision_v6_audit.json"

EXPECTED_TOTAL = 4000
EXPECTED_PER_CATEGORY = 500
EXPECTED_CATEGORIES = {
    "alert_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "severity_classification",
    "mitre_mapping",
    "incident_summary",
    "uncertainty_analysis",
}
EXPECTED_VERIFICATION_STATUS = "reference_checked_behavior_needs_human_review"


def load_records(path: Path) -> tuple[list[dict[str, Any]], list[int]]:
    records: list[dict[str, Any]] = []
    malformed_lines: list[int] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines.append(line_number)
                continue
            if not isinstance(item, dict):
                malformed_lines.append(line_number)
                continue
            records.append(item)
    return records, malformed_lines


def has_temporal_evidence(text: str) -> bool:
    t = text.lower()
    explicit = (
        "event a (", "event b (", "occurred at", "time difference:",
        "difference of ", "within five minutes", "more than five minutes apart",
    )
    if sum(phrase in t for phrase in explicit) >= 2:
        return True
    return any(phrase in t for phrase in (
        "time window", "temporal", "timestamp", "time-aligned", "time zone",
        "time zones", "clock skew", "time difference", "occurred before",
        "occurred after", "close together", "far apart", "same time",
        "within five minutes", "more than five minutes apart", "timing alone",
    ))


def audit() -> dict[str, Any]:
    if not DATASET.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET}\nRun this auditor from the project root."
        )

    records, malformed_lines = load_records(DATASET)
    category_counts = Counter(str(r.get("category", "missing")) for r in records)
    verification_counts = Counter(
        str(r.get("verification_status", "missing")) for r in records
    )

    category_balance_errors = {
        cat: {"expected": EXPECTED_PER_CATEGORY, "actual": category_counts.get(cat, 0)}
        for cat in sorted(EXPECTED_CATEGORIES)
        if category_counts.get(cat, 0) != EXPECTED_PER_CATEGORY
    }
    unexpected_categories = sorted(set(category_counts) - EXPECTED_CATEGORIES)

    duplicate_counter: Counter[tuple[str, str, str]] = Counter()
    validation_errors: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []
    required_fields = (
        "instruction", "input", "output", "source", "category",
        "scenario_family", "scenario_id", "verification_status",
        "generator_version", "metadata",
    )

    for index, record in enumerate(records, start=1):
        missing = [field for field in required_fields if field not in record]
        if missing:
            validation_errors.append({
                "record": index, "error": "missing_fields", "fields": missing
            })
        for field in ("instruction", "input", "output", "category"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                validation_errors.append({
                    "record": index, "error": "invalid_or_empty_string", "field": field
                })

        duplicate_counter[(
            str(record.get("instruction", "")),
            str(record.get("input", "")),
            str(record.get("output", "")),
        )] += 1

        if record.get("verification_status") != EXPECTED_VERIFICATION_STATUS:
            flags.append({
                "record": index, "category": record.get("category"),
                "flag": "unexpected_verification_status",
                "value": record.get("verification_status"),
            })

        category = record.get("category")
        input_text = str(record.get("input", "")).lower()
        output = str(record.get("output", "")).lower()
        combined = input_text + "\n" + output

        if category == "alert_correlation":
            if "retrieve the full process tree" in output:
                flags.append({
                    "record": index, "category": category,
                    "flag": "generic_process_tree_action",
                })
            if not has_temporal_evidence(combined):
                flags.append({
                    "record": index, "category": category,
                    "flag": "missing_temporal_caveat",
                })
            if not any(term in output for term in (
                "next step", "next action", "recommended next", "collect",
                "compare", "verify", "review", "confirm", "inspect", "check",
                "preserve", "correlate", "before linking",
            )):
                flags.append({
                    "record": index, "category": category,
                    "flag": "missing_follow_up_action",
                })

        if category == "severity_classification":
            if "workstation" in input_text and "database server" in input_text:
                flags.append({
                    "record": index, "category": category,
                    "flag": "possible_workstation_database_mismatch",
                })
            if any(term in input_text for term in (
                "critical servers", "critical assets", "business services are unavailable",
            )) and not any(term in input_text for term in (
                "critical production service", "critical server", "critical asset",
            )):
                flags.append({
                    "record": index, "category": category,
                    "flag": "critical_evidence_asset_mismatch",
                })
            if not any(term in output for term in (
                "preliminary", "provisional", "reassess", "re-evaluate",
            )):
                flags.append({
                    "record": index, "category": category,
                    "flag": "severity_not_marked_provisional",
                })

        if category == "ioc_analysis" and any(term in combined for term in (
            "url path", "url_path", "http path",
        )):
            if "process tree" in output and not any(term in output for term in (
                "http", "web", "proxy", "request", "url", "domain",
            )):
                flags.append({
                    "record": index, "category": category,
                    "flag": "url_path_generic_process_guidance",
                })

    duplicates = sum(n - 1 for n in duplicate_counter.values() if n > 1)
    verification_errors = [
        {"value": status, "actual": count, "expected": 0}
        for status, count in sorted(verification_counts.items())
        if status != EXPECTED_VERIFICATION_STATUS
    ]
    expected_count = verification_counts.get(EXPECTED_VERIFICATION_STATUS, 0)
    if expected_count != EXPECTED_TOTAL:
        verification_errors.append({
            "value": EXPECTED_VERIFICATION_STATUS,
            "actual": expected_count,
            "expected": EXPECTED_TOTAL,
        })

    report: dict[str, Any] = {
        "status": "STRUCTURAL_AND_TARGETED_CONSISTENCY_AUDIT_HUMAN_REVIEW_REQUIRED",
        "dataset": str(DATASET.relative_to(ROOT)),
        "record_count": len(records),
        "expected_record_count": EXPECTED_TOTAL,
        "category_counts": dict(sorted(category_counts.items())),
        "category_balance_errors": category_balance_errors,
        "unexpected_categories": unexpected_categories,
        "duplicate_triples": duplicates,
        "malformed_record_lines": malformed_lines,
        "validation_errors": validation_errors,
        "targeted_consistency_flags": flags,
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "verification_status_errors": verification_errors,
        "factual_verification": (
            "NOT VERIFIED. Heuristic checks cannot establish correctness of SOC reasoning or labels."
        ),
    }

    if (
        len(records) != EXPECTED_TOTAL or category_balance_errors
        or unexpected_categories or duplicates or malformed_lines
        or validation_errors or flags or verification_errors
    ):
        report["status"] = "AUDIT_FLAGS_REQUIRE_REVIEW"

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> None:
    result = audit()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nReport saved to: {REPORT}")
    if result["status"] == "AUDIT_FLAGS_REQUIRE_REVIEW":
        print("Audit flags found. Review them; do not train until resolved.")
    else:
        print("Structural and targeted checks passed; human review is still required.")


if __name__ == "__main__":
    main()
