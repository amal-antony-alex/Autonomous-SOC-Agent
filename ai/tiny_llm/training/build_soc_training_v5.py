#!/usr/bin/env python3
"""Create and run a patched v5 SOC dataset builder from the user's v4 builder."""
from pathlib import Path
import runpy

SOURCE = Path("ai/tiny_llm/training/build_soc_training_v4_revision_v4.py")
TARGET = Path("ai/tiny_llm/training/build_soc_training_v5_generated.py")

def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Expected exactly one match for {label}; found {count}. No v5 builder was written.")
    return text.replace(old, new, 1)

def main():
    if not SOURCE.exists():
        raise FileNotFoundError(f"Cannot find v4 source builder: {SOURCE}")
    source = SOURCE.read_text(encoding="utf-8")

    source = replace_once(
        source,
        'OUT = ROOT / "soc_training_v4_revision_v4.jsonl"\nREPORT = ROOT / "soc_training_v4_revision_v4_build_report.json"\nATTACK = Path("data/processed/mitre_attack/mitre_techniques.jsonl")\nSEED = 20261017\nPER_CATEGORY = 500\nVERSION = "soc-training-v4.4-semantic-consistency"',
        'OUT = ROOT / "soc_training_v4_revision_v5.jsonl"\nREPORT = ROOT / "soc_training_v4_revision_v5_build_report.json"\nATTACK = Path("data/processed/mitre_attack/mitre_techniques.jsonl")\nSEED = 20261022\nPER_CATEGORY = 500\nVERSION = "soc-training-v5-correlation-severity-consistency"',
        "v5 output paths and version",
    )

    old_corr = """        corr_out = (f"Event A ({type_a}) occurred at {t1}; Event B ({type_b}) occurred at {t2}, a difference of {delta_text} ({temporal_note}). "
                    f"Potential interpretation: {relation}. Context: {ctx}. Verify time zones and clock skew; the listed times alone do not prove causation. "
                    f"Do not merge the events solely because a source, host, or account field matches. Next, {action}, then document whether a shared session, process, "
                    f"connection tuple, or defensible timeline supports correlation.")"""
    new_corr = """        # Choose a correlation-specific follow-up, not the global generic ACTIONS entry.
        if type_a.startswith("login") or type_b.startswith("login"):
            corr_action = "check authentication outcomes, source/device attribution, and whether the events share an account and session"
        elif type_a == "process start" and type_b == "outbound connection":
            corr_action = "correlate process ID, parent process, command line, destination, ports, and normalized timestamps"
        elif type_a == "DNS query" or type_b == "DNS query":
            corr_action = "correlate the queried domain, DNS answer, requesting host/process, and relevant network connection identifiers"
        elif type_a == "firewall event" or type_b == "firewall event":
            corr_action = "inspect source/destination addresses, ports, protocol, rule/action, and relevant authorization or change records"
        elif type_a == "endpoint prevention" or type_b == "endpoint prevention":
            corr_action = "verify prevention status and correlate endpoint process, file or domain, and subsequent network activity"
        elif type_a == "privilege change" or type_b == "privilege change":
            corr_action = "review the identity audit trail, privilege-change details, source device, authorization, and subsequent actions"
        else:
            corr_action = "compare event identifiers and normalized timestamps, then retrieve telemetry specific to both event types"
        corr_out = (f"Event A ({type_a}) occurred at {t1}; Event B ({type_b}) occurred at {t2}, a difference of {delta_text} ({temporal_note}). "
                    f"Potential interpretation: {relation}. Context: {ctx}. Verify time zones and clock skew; the listed times alone do not prove causation. "
                    f"Do not merge the events solely because a source, host, or account field matches. Next, {corr_action}. "
                    f"Document whether a shared session, process, connection tuple, or defensible timeline supports correlation.")"""
    source = replace_once(source, old_corr, new_corr, "correlation output block")

    old_sev = """        sev, sev_evidence = IMPACTS[(i * 5 + i // 8) % len(IMPACTS)]
        asset = ["user workstation", "application server", "identity server", "database server", "critical production service"][(i // 3) % 5]
        confidence = ["low", "moderate", "high"][(i // 2) % 3]
        sev_context = ctx"""
    new_sev = """        sev, sev_evidence = IMPACTS[(i * 5 + i // 8) % len(IMPACTS)]
        # Align the asset class with the evidence scenario rather than pairing
        # unrelated asset and impact descriptions.
        if "failed login" in sev_evidence or "authentication" in sev_evidence or "accounts" in sev_evidence or "privileged account" in sev_evidence:
            asset = "identity server"
        elif "workstation" in sev_evidence:
            asset = "user workstation"
        elif "critical servers" in sev_evidence or "critical assets" in sev_evidence or "business services" in sev_evidence:
            asset = "critical production service"
        elif "sensitive records" in sev_evidence:
            asset = "database server"
        elif "administrative activity" in sev_evidence:
            asset = "application server"
        else:
            asset = ["user workstation", "application server", "identity server", "database server", "critical production service"][(i // 3) % 5]
        confidence = ["low", "moderate", "high"][(i // 2) % 3]
        sev_context = ctx"""
    source = replace_once(source, old_sev, new_sev, "severity evidence/asset selection")

    source = source.replace('"source": "synthetic_scenario_candidate_v4",',
                            '"source": "synthetic_scenario_candidate_v5",', 1)
    TARGET.write_text(source, encoding="utf-8")
    print(f"Wrote patched v5 builder: {TARGET}")
    print("Running v5 builder...")
    runpy.run_path(str(TARGET), run_name="__main__")

if __name__ == "__main__":
    main()
