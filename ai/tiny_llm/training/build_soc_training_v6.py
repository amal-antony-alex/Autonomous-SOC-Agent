#!/usr/bin/env python3
# Create and run a v6 SOC dataset builder by patching the v5 generated builder.
# Run from the project root:
#   python ai/tiny_llm/training/build_soc_training_v6.py
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / "ai/tiny_llm/training/build_soc_training_v5_generated.py"
if not SOURCE.exists():
    raise FileNotFoundError(
        f"Could not find {SOURCE}. Run this script from the project root and "
        "ensure the v5 generated builder exists."
    )

source = SOURCE.read_text(encoding="utf-8")
source = source.replace("soc_training_v4_revision_v5.jsonl", "soc_training_v4_revision_v6.jsonl")
source = source.replace("soc_training_v4_revision_v5_build_report.json", "soc_training_v4_revision_v6_build_report.json")
source = source.replace("soc-training-v5-correlation-severity-consistency",
                        "soc-training-v6-event-specific-correlation-confidence-aware-severity")
source = source.replace("20261022", "20261023")

old_corr = '''        corr_out = (f"Event A ({type_a}) occurred at {t1}; Event B ({type_b}) occurred at {t2}, a difference of {delta_text} ({temporal_note}). "
                    f"Potential interpretation: {relation}. Context: {ctx}. Verify time zones and clock skew; the listed times alone do not prove causation. "
                    f"Do not merge the events solely because a source, host, or account field matches. Next, {corr_action}. "
                    f"Document whether a shared session, process, connection tuple, or defensible timeline supports correlation.")'''
new_corr = '''        # Tailor the closing evidence requirement to the event pair.
        if type_a.startswith("login") or type_b.startswith("login"):
            corr_close = "Before linking the events, verify authentication outcome, account identity, source/device, and session or logon identifiers."
        elif type_a == "process start" and type_b == "outbound connection":
            corr_close = "Before linking the events, verify process and parent IDs, destination/port, and timestamp alignment."
        elif type_a == "DNS query" or type_b == "DNS query":
            corr_close = "Before linking the events, verify the queried name, DNS answer, requesting process/host, and a matching network event."
        elif type_a == "firewall event" or type_b == "firewall event":
            corr_close = "Before linking the events, verify the network tuple, firewall rule/action, and whether the later activity has an authorized change record."
        elif type_a == "endpoint prevention" or type_b == "endpoint prevention":
            corr_close = "Before linking the events, verify prevention outcome and matching endpoint, file/process, domain, or connection identifiers."
        elif type_a == "privilege change" or type_b == "privilege change":
            corr_close = "Before linking the events, verify the affected identity, privilege-change audit record, source device, authorization, and subsequent activity."
        else:
            corr_close = "Before linking the events, identify at least one corroborating event identifier and document remaining uncertainty."
        corr_out = (f"Event A ({type_a}) occurred at {t1}; Event B ({type_b}) occurred at {t2}, a difference of {delta_text} ({temporal_note}). "
                    f"Potential interpretation: {relation}. Context: {ctx}. Verify time zones and clock skew; the listed times alone do not prove causation. "
                    f"Do not merge the events solely because a source, host, or account field matches. Next, {corr_action}. "
                    f"{corr_close}")'''
if old_corr not in source:
    raise RuntimeError("Could not find expected v5 correlation output block; no v6 builder was written.")
source = source.replace(old_corr, new_corr, 1)

old_sev = '''        if sev == "Critical":
            severity_action = "follow the organization's critical-incident escalation procedure, preserve evidence, and assess immediate containment with the incident commander"
        elif sev == "High":
            severity_action = "escalate for prompt analyst review, validate affected scope, and preserve relevant endpoint and network evidence"
        elif sev == "Medium":
            severity_action = "validate the affected scope, confirm relevant event outcomes, and gather corroborating telemetry"
        else:
            severity_action = "compare the event with the approved baseline and verify whether related alerts or impact indicators exist"'''
new_sev = '''        # Make next steps responsive to confidence as well as provisional severity.
        if confidence == "low":
            severity_action = "validate the underlying evidence, confirm the affected asset and scope, and gather missing telemetry before finalizing severity"
        elif confidence == "moderate" and sev in {"High", "Critical"}:
            severity_action = "promptly escalate for analyst review while independently corroborating impact, scope, and the evidence supporting the proposed severity"
        elif sev == "Critical":
            severity_action = "follow the organization's critical-incident escalation procedure, preserve evidence, and assess immediate containment with the incident commander"
        elif sev == "High":
            severity_action = "escalate for prompt analyst review, validate affected scope, and preserve relevant endpoint and network evidence"
        elif sev == "Medium":
            severity_action = "validate the affected scope, confirm relevant event outcomes, and gather corroborating telemetry"
        else:
            severity_action = "compare the event with the approved baseline and verify whether related alerts or impact indicators exist"'''
if old_sev not in source:
    raise RuntimeError("Could not find expected v5 severity action block; no v6 builder was written.")
source = source.replace(old_sev, new_sev, 1)
source = source.replace('"synthetic_scenario_candidate_v5"', '"synthetic_scenario_candidate_v6"')

target = ROOT / "ai/tiny_llm/training/build_soc_training_v6_generated.py"
target.write_text(source, encoding="utf-8")
print(f"Created v6 builder: {target}")
print("v5 source and dataset remain unchanged.")
print("Running the v6 builder now...")
result = subprocess.run([sys.executable, str(target)], cwd=ROOT)
raise SystemExit(result.returncode)
