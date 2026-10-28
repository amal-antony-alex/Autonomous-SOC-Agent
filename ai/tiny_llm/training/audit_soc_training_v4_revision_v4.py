#!/usr/bin/env python3
"""Structural and targeted consistency audit for synthetic SOC training v4.4.

This audit checks generator-specific invariants. It does not prove factual correctness;
expert review remains required before training.
"""
import json, re
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path("data/raw/soc_curated_v3")
DATA = ROOT / "soc_training_v4_revision_v4.jsonl"
ATTACK = Path("data/processed/mitre_attack/mitre_techniques.jsonl")
REPORT = ROOT / "soc_training_v4_revision_v4_audit.json"
CATEGORIES = {
    "alert_analysis", "ioc_analysis", "alert_correlation",
    "false_positive_assessment", "severity_classification",
    "mitre_mapping", "incident_summary", "uncertainty_analysis",
}
BAD_GENERIC_IOC = "For a process name, collect file path, cryptographic hash, signer, parent process"

def parse_clock(value):
    return datetime.strptime(value, "%H:%M:%S")

def main():
    if not DATA.exists():
        raise SystemExit(f"Dataset not found: {DATA}. Run build_soc_training_v4_revision_v4.py first.")
    attack = {}
    if ATTACK.exists():
        for line in ATTACK.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                attack[row["technique_id"]] = row
    rows = [json.loads(x) for x in DATA.read_text(encoding="utf-8").splitlines() if x.strip()]
    errors, malformed = [], []
    semantic_flags = []
    cats, statuses = Counter(), Counter()
    input_sets, output_counts, families = {}, {}, {}
    triples = set()
    mapping_errors = []
    for i, r in enumerate(rows, 1):
        for field in ("instruction", "input", "output", "category", "source", "scenario_family", "scenario_id", "verification_status", "metadata", "generator_version"):
            if field not in r or r[field] in ("", None):
                errors.append(f"line {i}: missing {field}")
        cat = r.get("category", "UNKNOWN")
        cats[cat] += 1
        inp, out = r.get("input", ""), r.get("output", "")
        input_sets.setdefault(cat, set()).add(" ".join(inp.lower().split()))
        output_counts.setdefault(cat, Counter())[" ".join(out.lower().split())] += 1
        families.setdefault(cat, set()).add(r.get("scenario_family", ""))
        statuses[r.get("verification_status", "MISSING")] += 1
        if len(inp.split()) < 8: errors.append(f"line {i}: input too short")
        if len(out.split()) < 20: errors.append(f"line {i}: output too short")
        if re.search(r"(?im)\b(context|evidence)\s*[:=]\s*(?:\.|[a-z]\.)\s*$", inp): malformed.append(i)
        key = tuple(" ".join(str(r.get(k, "")).lower().split()) for k in ("instruction", "input", "output"))
        if key in triples: errors.append(f"line {i}: duplicate triple")
        triples.add(key)

        if cat == "ioc_analysis":
            itype = r.get("metadata", {}).get("indicator_type")
            if BAD_GENERIC_IOC in out:
                semantic_flags.append({"line": i, "issue": "generic process-name guidance in IOC output"})
            expected_terms = {
                "domain": ("dns", "domain"), "ip_address": ("address", "protocol"),
                "process": ("parent process", "command line"), "user": ("account", "authentication"),
                "file_hash": ("hash", "signer"), "url_path": ("url path", "http method"),
            }
            terms = expected_terms.get(itype, ())
            if terms and not any(term in out.lower() for term in terms):
                semantic_flags.append({"line": i, "issue": f"IOC output lacks type-specific terms for {itype}"})

        if cat == "alert_correlation":
            match_a = re.search(r"Event A: time=(\d{2}:\d{2}:\d{2}).*?type=([^\n]+)", inp)
            match_b = re.search(r"Event B: time=(\d{2}:\d{2}:\d{2}).*?type=([^\n]+)", inp)
            if not match_a or not match_b:
                semantic_flags.append({"line": i, "issue": "could not parse correlation event pair"})
            else:
                a, b = parse_clock(match_a.group(1)), parse_clock(match_b.group(1))
                delta = abs(int((b-a).total_seconds()))
                expected = f"{delta//3600}h {(delta%3600)//60}m {delta%60}s" if delta >= 3600 else f"{delta//60}m {delta%60}s"
                if f"difference of {expected}" not in out:
                    semantic_flags.append({"line": i, "issue": "correlation output time difference does not match event timestamps"})
                if "firewall allow records near the same time" in inp.lower():
                    semantic_flags.append({"line": i, "issue": "unsupported generic firewall relationship"})

        if cat == "severity_classification":
            evidence = re.search(r"Evidence: (.*)\nAnalyst confidence:", inp)
            context = re.search(r"Additional context: (.*)\nPolicy:", inp)
            if evidence and context:
                ev, cx = evidence.group(1).lower(), context.group(1).lower()
                if "matching change record" in ev and "ticket is missing" in cx:
                    semantic_flags.append({"line": i, "issue": "contradictory change-record evidence/context"})

        if cat == "incident_summary":
            question = re.search(r"Open question: (.*)\nContext:", inp)
            if question and question.group(1) not in out:
                semantic_flags.append({"line": i, "issue": "incident output does not preserve its open question"})
        if cat == "mitre_mapping":
            meta = r.get("metadata", {})
            ref = attack.get(meta.get("candidate_technique_id")) if attack else None
            if attack and (not ref or ref.get("name") != meta.get("candidate_technique_name")):
                mapping_errors.append({"line": i, "id": meta.get("candidate_technique_id"), "name": meta.get("candidate_technique_name")})

    per_cat = {}
    for cat in sorted(CATEGORIES):
        oc = output_counts.get(cat, Counter())
        per_cat[cat] = {"records": cats[cat], "unique_inputs": len(input_sets.get(cat, set())),
                        "unique_outputs": len(oc), "most_common_output_count": oc.most_common(1)[0][1] if oc else 0,
                        "unique_scenario_families": len(families.get(cat, set()))}
    report = {
        "expected_record_count": 4000, "expected_records_per_category": 500,
        "category_balance_errors": {cat: cats[cat] for cat in sorted(CATEGORIES) if cats[cat] != 500},
        "status": "STRUCTURAL_AND_TARGETED_CONSISTENCY_AUDIT_HUMAN_REVIEW_REQUIRED",
        "record_count": len(rows), "category_counts": dict(cats), "per_category": per_cat,
        "duplicate_triples": len(rows)-len(triples), "malformed_context_count": len(malformed),
        "malformed_context_lines": malformed, "validation_errors": errors,
        "targeted_semantic_flags": semantic_flags, "mitre_reference_mismatches": mapping_errors,
        "verification_status_counts": dict(statuses),
        "factual_verification": "NOT VERIFIED. Heuristic checks cannot establish correctness of SOC reasoning or labels.",
    }
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nReport saved to: {REPORT}")
    if errors or malformed or mapping_errors or semantic_flags or report["category_balance_errors"] or len(rows) != 4000:
        raise SystemExit("AUDIT FAILED: review flagged issues before training.")
    print("Structural and targeted consistency checks passed; human review is still required.")

if __name__ == "__main__":
    main()
