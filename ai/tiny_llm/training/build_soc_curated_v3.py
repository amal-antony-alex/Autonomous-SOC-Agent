
import json
import hashlib
from pathlib import Path
from collections import Counter

OUTPUT_DIR = Path("data/raw/soc_curated_v3")
OUTPUT_FILE = OUTPUT_DIR / "soc_seed_batch.jsonl"
REPORT_FILE = OUTPUT_DIR / "soc_seed_batch_report.json"

TARGET_PER_CATEGORY = 20
SEED_VERSION = "soc-curated-v3-seed-1"

CATEGORIES = {
    "alert_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "severity_classification",
    "mitre_mapping",
    "incident_summary",
    "uncertainty_analysis",
}


def record(category, family, instruction, input_text, output):
    return {
        "instruction": instruction,
        "input": input_text,
        "output": output,
        "source": "curated_soc_v3",
        "category": category,
        "scenario_family": family,
        "generator_version": SEED_VERSION,
    }


def build_seed_examples():
    rows = []

    # 1. Alert analysis
    for i in range(20):
        benign = i % 2 == 0
        host = f"WS-{i + 1:03d}"
        src = f"10.20.{i // 10}.{10 + i}"
        dest = f"198.51.100.{20 + i}"
        if benign:
            input_text = (
                f"Host: {host}\nProcess: browser.exe\n"
                f"Source IP: {src}\nDestination IP: {dest}\n"
                "Destination port: 443\n"
                "Known approved vendor: yes\n"
                "Proxy log: connection allowed\n"
            )
            output = (
                "The event records an outbound HTTPS connection to a "
                "destination described as an approved vendor. This context "
                "does not establish malicious activity. Verify the actual "
                "domain, destination reputation, process ancestry, and "
                "whether the connection matches expected user activity."
            )
        else:
            input_text = (
                f"Host: {host}\nProcess: powershell.exe\n"
                f"Parent process: winword.exe\nUser: analyst-test\n"
                f"Destination IP: {dest}\n"
                "Command line: encoded command present\n"
                "Script contents: not collected\n"
            )
            output = (
                "The Office-to-PowerShell process chain and encoded command "
                "are suspicious and warrant investigation. The script "
                "contents and execution outcome are unavailable, so this "
                "evidence alone does not confirm compromise. Collect the "
                "command line, script block logs, process tree, and related "
                "network events."
            )
        rows.append(record(
            "alert_analysis", "process_and_network_triage",
            "Assess the alert using only the supplied evidence.",
            input_text, output
        ))

    # 2. IOC analysis
    for i in range(20):
        host = f"SRV-{i + 1:03d}"
        ip = f"203.0.113.{10 + i}"
        digest = hashlib.sha256(f"soc-v3-file-{i}".encode()).hexdigest()
        input_text = (
            f"Host: {host}\nSource IP: 10.30.1.{i + 10}\n"
            f"Destination IP: {ip}\nFile hash (SHA-256): {digest}\n"
            "Threat-intelligence verdict: unavailable\n"
        )
        output = (
            f"Observed indicators are host {host}, source IP "
            f"10.30.1.{i + 10}, destination IP {ip}, and the supplied "
            f"SHA-256 file hash {digest}. No reputation verdict is provided, "
            "so these indicators cannot be labelled malicious from this "
            "record alone. Enrich them using trusted intelligence sources "
            "and correlate them with endpoint and network telemetry."
        )
        rows.append(record(
            "ioc_analysis", "indicator_extraction_and_enrichment",
            "Extract the observable indicators and state what remains unverified.",
            input_text, output
        ))

    # 3. Alert correlation
    for i in range(20):
        host = f"HOST-{i + 1:03d}"
        user = f"user{i + 1:02d}"
        ip = f"10.40.0.{20 + i}"
        input_text = (
            f"Event A: {host}, user={user}, time=10:00:00, "
            f"failed_login_count=1, source={ip}\n"
            f"Event B: {host}, user={user}, time=10:00:20, "
            f"failed_login_count=2, source={ip}\n"
            f"Event C: {host}, user={user}, time=10:00:45, "
            f"successful_login=no, source={ip}\n"
        )
        output = (
            f"The three events share host {host}, user {user}, and source "
            f"{ip}, with repeated failures over 45 seconds and no successful "
            "login recorded. This is consistent with repeated authentication "
            "failure but does not establish account compromise. Check the "
            "surrounding authentication history, source ownership, and "
            "whether the pattern affects other accounts or hosts."
        )
        rows.append(record(
            "alert_correlation", "authentication_event_sequence",
            "Correlate the events and distinguish observed facts from conclusions.",
            input_text, output
        ))

    # 4. False-positive assessment
    for i in range(20):
        host = f"APP-{i + 1:03d}"
        input_text = (
            f"Host: {host}\nUser: svc_maintenance\n"
            "Process: systemctl\nCommand: restart application-service\n"
            "Change ticket: approved\nMaintenance window: active\n"
            "Unexpected child process: no\n"
        )
        output = (
            f"The restart on {host} is consistent with the supplied approved "
            "maintenance context, and no unexpected child process is reported. "
            "This supports a potentially benign explanation but does not prove "
            "the event is a false positive. Verify the change ticket, command "
            "details, and relevant host logs before closing the alert."
        )
        rows.append(record(
            "false_positive_assessment", "approved_administration",
            "Assess whether the alert can be treated as a false positive.",
            input_text, output
        ))

    # 5. Severity classification
    for i in range(20):
        level = i % 4
        scenarios = [
            (
                "One failed login; no success; known internal source.",
                "Low",
                "The supplied event shows one failed login, with no successful "
                "access or additional suspicious activity. Low preliminary "
                "severity is reasonable, subject to local SOC policy."
            ),
            (
                "Repeated failures across several accounts; no success observed.",
                "Medium",
                "Repeated failures across several accounts warrant investigation "
                "for password spraying. No successful access is reported. "
                "Medium preliminary severity is reasonable, subject to context "
                "and local SOC policy."
            ),
            (
                "A privileged account logs in from an unusual source and launches "
                "an encoded script; outcome is unknown.",
                "High",
                "The unusual privileged login and encoded script create a "
                "significant risk that warrants prompt investigation. The "
                "execution outcome is unknown, so compromise is not confirmed. "
                "High preliminary severity is reasonable, subject to local policy."
            ),
            (
                "Confirmed ransomware execution; multiple critical servers "
                "are encrypted and business services are unavailable.",
                "Critical",
                "The supplied evidence describes confirmed ransomware execution "
                "with impact across critical servers and service availability. "
                "Critical preliminary severity is justified by the reported "
                "impact. Follow the organization's incident-response process."
            ),
        ]
        scenario, severity, output = scenarios[level]
        rows.append(record(
            "severity_classification", "impact_and_confidence",
            "Assign a preliminary severity and justify it using the evidence.",
            f"Case ID: SEV-{i + 1:03d}\nEvidence: {scenario}",
            f"Preliminary severity: {severity}. {output}"
        ))

    # 6. MITRE mapping
    mappings = [
        (
            "Process: cmd.exe\nCommand: cmd.exe /c whoami",
            "T1059.003 - Windows Command Shell",
            "The command shows Windows Command Shell use to execute whoami. "
            "This supports T1059.003; the command alone does not establish "
            "malicious intent."
        ),
        (
            "Observed: a user opens an email attachment; the attachment's "
            "contents and execution outcome are unknown.",
            "No definitive technique assignment",
            "The evidence confirms an attachment was opened but does not "
            "establish that it was malicious or executed. Do not assign a "
            "malicious-file execution technique without additional evidence."
        ),
        (
            "Observed: a process lists running services on a remote host.",
            "T1046 - Network Service Discovery",
            "Remote service enumeration is consistent with Network Service "
            "Discovery (T1046). Confirm the command and target context before "
            "treating the behavior as malicious."
        ),
        (
            "Observed: a user receives an email containing an attachment; "
            "no evidence that the attachment was opened.",
            "T1566.001 - Spearphishing Attachment",
            "The reported email attachment may support Spearphishing Attachment "
            "(T1566.001) if the delivery was phishing-related. User execution "
            "is not established by the supplied evidence."
        ),
    ]
    for i in range(20):
        event, expected, explanation = mappings[i % len(mappings)]
        rows.append(record(
            "mitre_mapping", "behavior_to_attack_mapping",
            "Map the observed behavior to MITRE ATT&CK only when supported.",
            f"Case ID: ATTACK-{i + 1:03d}\n{event}",
            f"Assessment: {expected}. {explanation}"
        ))

    # 7. Incident summaries
    for i in range(20):
        host = f"EDGE-{i + 1:03d}"
        ip = f"203.0.113.{80 + i}"
        input_text = (
            f"Host: {host}\nProcess: unknown.exe\n"
            f"Destination: {ip}:443\nData transferred: {100 + i * 25} MB\n"
            "Destination reputation: not checked\n"
            "Related endpoint alerts: none supplied\n"
        )
        output = (
            f"{host} transferred approximately {100 + i * 25} MB to "
            f"{ip}:443 using unknown.exe. Destination reputation and related "
            "endpoint evidence are unavailable, so the transfer cannot be "
            "classified as malicious from this information alone. Review "
            "process provenance, domain details, and network context."
        )
        rows.append(record(
            "incident_summary", "outbound_transfer_summary",
            "Write a concise, evidence-grounded incident summary.",
            input_text, output
        ))

    # 8. Uncertainty and missing evidence
    for i in range(20):
        cases = [
            (
                "Alert: suspicious.exe detected. Hash: unavailable. "
                "Execution status: unknown.",
                "The file name alone is insufficient to confirm malware. "
                "Collect the file hash, file metadata, execution history, "
                "process ancestry, and endpoint detections."
            ),
            (
                "Alert: unusual outbound connection. Domain: unavailable. "
                "Process: browser.exe. Reputation: unavailable.",
                "The connection is unusual according to the alert, but the "
                "supplied evidence does not establish malicious activity. "
                "Obtain the domain, destination reputation, process context, "
                "and baseline for expected traffic."
            ),
            (
                "Alert: authentication failures. Attempt count: unknown. "
                "Successful login: unknown.",
                "The available record does not establish the scale or outcome "
                "of the authentication activity. Retrieve the full event count, "
                "time range, source addresses, targeted accounts, and successful "
                "authentication records before assigning a conclusion."
            ),
            (
                "Alert: possible privilege escalation. Command: unavailable. "
                "User role: unknown.",
                "The alert label alone does not confirm privilege escalation. "
                "Collect the command, initiating process, account privileges, "
                "audit logs, and approved change context."
            ),
        ]
        event, output = cases[i % len(cases)]
        rows.append(record(
            "uncertainty_analysis", "missing_evidence_assessment",
            "State what can be concluded and identify the most important missing evidence.",
            f"Case ID: UNC-{i + 1:03d}\n{event}",
            output
        ))

    return rows


def validate(rows):
    errors = []
    seen = set()

    for index, row in enumerate(rows, 1):
        for field in ("instruction", "input", "output", "source", "category"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                errors.append(f"Row {index}: missing/invalid {field}")

        if row.get("category") not in CATEGORIES:
            errors.append(f"Row {index}: invalid category")

        key = (
            row.get("instruction", "").strip().lower(),
            row.get("input", "").strip().lower(),
            row.get("output", "").strip().lower(),
        )
        if key in seen:
            errors.append(f"Row {index}: exact duplicate")
        seen.add(key)

        if len(row.get("output", "").split()) < 8:
            errors.append(f"Row {index}: output too short")

    return errors


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    rows = build_seed_examples()
    errors = validate(rows)

    if errors:
        raise SystemExit(
            "Validation failed:\n" + "\n".join(errors[:30])
        )

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    report = {
        "generator_version": SEED_VERSION,
        "examples": len(rows),
        "category_counts": dict(Counter(r["category"] for r in rows)),
        "validation_errors": errors,
        "status": "STRUCTURE_VALIDATION_PASSED_REVIEW_REQUIRED",
        "note": (
            "Passing structural checks does not establish factual correctness. "
            "Review examples before using them for model training."
        ),
    }

    REPORT_FILE.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print(f"\nWrote: {OUTPUT_FILE}")
    print(f"Wrote: {REPORT_FILE}")


if __name__ == "__main__":
    main()
