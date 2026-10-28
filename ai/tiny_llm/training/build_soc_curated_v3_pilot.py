
import json
import random
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path("data/raw/soc_curated_v3")
OUTPUT = ROOT / "soc_pilot_400.jsonl"
REPORT = ROOT / "soc_pilot_400_report.json"

SEED = 20261017
PER_CATEGORY = 50
VERSION = "soc-curated-v3-pilot-1"

CATEGORIES = [
    "alert_analysis",
    "ioc_analysis",
    "alert_correlation",
    "false_positive_assessment",
    "severity_classification",
    "mitre_mapping",
    "incident_summary",
    "uncertainty_analysis",
]


def make(category, family, instruction, input_text, output, variant):
    return {
        "instruction": instruction,
        "input": input_text,
        "output": output,
        "source": "curated_soc_v3_candidate",
        "category": category,
        "scenario_family": family,
        "scenario_variant": variant,
        "generator_version": VERSION,
    }


def build_examples():
    rng = random.Random(SEED)
    rows = []

    # Scenarios are explicit and varied. The variants are identifiers for
    # scenario instances, not a claim that all instances are independent.
    alert_scenarios = [
        (
            "Office spawned PowerShell with encoded command",
            "Process chain and encoded command warrant investigation; "
            "script contents and execution outcome are unknown. Collect "
            "script-block logs, process ancestry, and related network events.",
            "Process: powershell.exe\nParent: winword.exe\n"
            "Command line: encoded command present\nScript contents: unavailable"
        ),
        (
            "Single failed SSH login",
            "One failed authentication attempt is recorded, with no successful "
            "login supplied. This alone does not establish malicious activity. "
            "Check surrounding authentication events and source context.",
            "Service: SSH\nFailed attempts: 1\nSuccessful login: no"
        ),
        (
            "Approved software update",
            "The update is consistent with the supplied approved deployment "
            "context. Verify the package source, signature, change record, "
            "and process behavior before closing the alert.",
            "Process: package-manager\nDeployment: approved\n"
            "Package signature: not supplied"
        ),
        (
            "Possible suspicious DNS activity",
            "The DNS event merits review, but the query alone does not confirm "
            "compromise. Inspect the queried domain, resolver logs, endpoint "
            "process, and any subsequent connections.",
            "Event: unusual DNS query\nDomain: telemetry-check.example\n"
            "Endpoint process: unknown"
        ),
        (
            "Unusual outbound transfer",
            "The reported transfer warrants investigation in context. The "
            "destination reputation and process provenance are unavailable, "
            "so exfiltration is not established. Review flow records and "
            "endpoint telemetry.",
            "Outbound transfer: 1.8 GB\nDestination reputation: unknown\n"
            "Process: unknown.exe"
        ),
        (
            "New privileged account",
            "A new privileged account is security-relevant, but the event "
            "does not alone prove unauthorized access. Verify the change "
            "request, creator identity, account history, and subsequent activity.",
            "Event: privileged account created\nChange ticket: unavailable\n"
            "Creator: admin-user"
        ),
        (
            "Web request with SQL injection-like syntax",
            "The request contains SQL injection-like syntax. An HTTP response "
            "code alone cannot establish successful exploitation. Correlate "
            "application, database, and response-body logs.",
            "Request: GET /item?id=1' OR '1'='1\nHTTP status: 200"
        ),
        (
            "Unsigned executable launched from temporary directory",
            "Execution of an unsigned executable from a temporary directory "
            "is suspicious but not conclusive. Verify its hash and provenance, "
            "parent process, signer information, and endpoint detections.",
            "File: C:\\Temp\\update.exe\nSignature: unsigned\n"
            "Execution: observed"
        ),
        (
            "Repeated authentication failures across accounts",
            "Failures across several accounts may indicate password spraying, "
            "but source legitimacy and the wider time window must be checked. "
            "Look for successful logins and account lockouts.",
            "Failed logins: 42\nTargeted accounts: 12\n"
            "Successful login: not determined"
        ),
        (
            "Endpoint alert with missing process telemetry",
            "The alert label is insufficient to confirm malicious execution. "
            "Collect the process tree, command line, file hash, user context, "
            "and neighboring endpoint events.",
            "Alert: suspicious execution\nProcess tree: unavailable\n"
            "File hash: unavailable"
        ),
    ]

    for i in range(PER_CATEGORY):
        name, reasoning, evidence = alert_scenarios[i % len(alert_scenarios)]
        host = f"ENDPOINT-{i + 1:03d}"
        rows.append(make(
            "alert_analysis",
            f"alert_family_{i % len(alert_scenarios):02d}",
            "Assess the security alert using only the supplied evidence.",
            f"Case: ALERT-{i + 1:03d}\nHost: {host}\n"
            f"Scenario: {name}\n{evidence}",
            reasoning,
            i,
        ))

    ioc_scenarios = [
        ("File hash", "File SHA-256: " + hashlib.sha256(b"soc-pilot-file").hexdigest(),
         "Extract the file hash exactly. Its reputation is not supplied, so do not label it malicious."),
        ("Domain", "Queried domain: login-review.example\nReputation: unavailable",
         "The observable domain is login-review.example. Its reputation is unavailable; verify it using trusted intelligence and DNS context."),
        ("Network endpoints", "Source IP: 10.5.4.20\nDestination IP: 203.0.113.42",
         "The observed network indicators are source 10.5.4.20 and destination 203.0.113.42. These addresses alone do not establish maliciousness."),
        ("Identity", "User: svc-backup\nDomain: CORP\nSource IP: 10.5.4.25",
         "The identity and context indicators are user svc-backup, domain CORP, and source IP 10.5.4.25. Verify whether this activity matches the account's expected use."),
        ("File metadata", "Filename: archive.bin\nSHA-256: unavailable\nSigner: unknown",
         "The filename archive.bin is an observable artifact, not proof of malware. Obtain its hash, file type, signature, source, and execution context."),
        ("DNS indicator", "Domain: update-check.example\nResolved IP: 192.0.2.25\nThreat verdict: unknown",
         "The observable indicators are update-check.example and 192.0.2.25. No threat verdict is supplied; enrich both and correlate DNS resolution with endpoint activity."),
        ("URL", "URL path: /account/verify\nHost: portal.example\nHTTP status: 302",
         "The observed URL host, path, and HTTP status can be recorded as investigation indicators. The redirect alone does not establish phishing or compromise."),
        ("Process", "Process: powershell.exe\nParent: winword.exe\nHash: unavailable",
         "The process names and parent-child relationship are observable indicators. Obtain the command line, executable hash, and script telemetry before drawing a verdict."),
        ("Email", "Sender: notice@example.invalid\nAttachment: invoice.zip\nSandbox result: not run",
         "The sender and attachment name are observable email indicators. A sandbox verdict is unavailable, so inspect headers, attachment hashes, and delivery context."),
        ("Certificate", "Certificate subject: portal.example\nIssuer: unknown\nValidation: failed",
         "The certificate subject and failed validation are relevant indicators. Verify certificate chain, expiry, hostname matching, and whether the failure is expected."),
    ]

    for i in range(PER_CATEGORY):
        kind, evidence, answer = ioc_scenarios[i % len(ioc_scenarios)]
        rows.append(make(
            "ioc_analysis",
            f"ioc_family_{i % len(ioc_scenarios):02d}",
            f"Extract and assess the {kind.lower()} indicators without inventing a reputation verdict.",
            f"Case: IOC-{i + 1:03d}\n{evidence}",
            answer,
            i,
        ))

    correlation_scenarios = [
        ("authentication_chain",
         "10:00 failed login; 10:01 failed login; 10:02 successful login",
         "The sequence changes from failed to successful authentication. Correlate source, user, device, MFA, and session activity to determine whether the success was legitimate."),
        ("multi_account_failures",
         "One source targets 18 accounts in 4 minutes; no success status supplied",
         "The broad targeting pattern may indicate password spraying. Successful access is unknown; check authentication outcomes, source ownership, and lockout events."),
        ("process_network_chain",
         "Word processor spawns script host; script host makes outbound connection",
         "The process chain and outbound connection are related suspicious events if timestamps and process identifiers align. Retrieve command line, destination reputation, and script telemetry."),
        ("endpoint_and_identity",
         "New privileged group membership followed by remote login",
         "The events may indicate a related privilege and remote-access sequence. Verify actor identity, change approval, timestamps, and whether the remote session used the changed privileges."),
        ("dns_then_connection",
         "Endpoint resolves a domain and connects to the returned address 3 seconds later",
         "The DNS query and subsequent connection are temporally consistent. Verify the queried domain, process ownership, destination reputation, and whether the address was actually returned by that query."),
        ("host_spread",
         "Similar alert on three hosts within 6 minutes; shared source account",
         "The shared account and timing suggest a possible common cause. Compare process hashes, source activity, and host roles before concluding that the events are part of one incident."),
        ("firewall_endpoint",
         "Firewall permits outbound connection; endpoint logs show unknown process",
         "The firewall event confirms permitted traffic, while endpoint process attribution is incomplete. Correlate timestamps, five-tuple, host telemetry, and destination context."),
        ("web_and_database",
         "Web server logs suspicious query; database error occurs seconds later",
         "The temporal relationship warrants correlation but does not prove exploitation. Review request parameters, application handling, database audit logs, and response evidence."),
        ("scheduled_task",
         "New scheduled task appears after an unusual interactive login",
         "The timing may link the login to task creation, but attribution is not established. Correlate user SID, process ancestry, task action, and logon session."),
        ("isolated_alerts",
         "Two alerts share a hostname but occur 14 days apart with no shared user or process",
         "A shared hostname alone is weak evidence of a common incident. Keep the alerts separate unless additional identifiers or a defensible timeline link them."),
    ]

    for i in range(PER_CATEGORY):
        family, events, answer = correlation_scenarios[i % len(correlation_scenarios)]
        rows.append(make(
            "alert_correlation", family,
            "Correlate the events and state both the relationship supported by evidence and its limitations.",
            f"Case: CORR-{i + 1:03d}\nEvents:\n{events}\n"
            f"Correlation window: {i % 5 + 1} minutes",
            answer,
            i,
        ))

    benign_scenarios = [
        ("approved_restart", "systemctl restart nginx; change approved; maintenance active",
         "The restart is consistent with the supplied approved maintenance context. Verify the change record and command details before closing the alert."),
        ("known_scanner", "Vulnerability scanner probes internal hosts; source matches registered scanner",
         "The activity may be expected scanning because the source matches the registered scanner. Verify its schedule, scope, and authorization before classifying it as benign."),
        ("software_update", "Signed vendor updater runs during deployment window",
         "A valid signature and deployment window support a benign explanation, but verify the signature chain, package source, and expected process behavior."),
        ("backup_activity", "Backup service transfers 800 GB to registered storage at scheduled time",
         "The volume is consistent with the stated scheduled backup, but confirm the destination, job record, and service account activity."),
        ("admin_command", "Administrator runs approved service diagnostic; ticket supplied",
         "The supplied ticket supports an authorized explanation. Confirm the command and target match the ticket and inspect for unexpected child processes."),
        ("blocked_test", "Internal security test triggers detection; test authorization recorded",
         "The alert may be attributable to the authorized test. Verify the test window, source systems, and scope before suppressing or closing it."),
        ("browser_update", "Browser updater connects to vendor domain; valid process signature",
         "The signed updater and vendor destination support a benign hypothesis. Confirm the domain, signature validity, and expected update behavior."),
        ("monitoring_probe", "Monitoring system checks service health every minute",
         "The repeated probe may be normal monitoring if its source and cadence match the inventory. Verify the monitoring configuration and target."),
        ("unexpected_context", "Admin command is outside approved window; ticket exists but scope differs",
         "The ticket does not fully explain the event because the timing or scope differs. Keep the alert open and confirm with the change owner."),
        ("unknown_origin", "Activity resembles routine administration; actor and authorization are unavailable",
         "The activity may be benign, but the missing actor and authorization prevent closure on that basis alone. Verify account, command, and change history."),
    ]

    for i in range(PER_CATEGORY):
        family, evidence, answer = benign_scenarios[i % len(benign_scenarios)]
        rows.append(make(
            "false_positive_assessment", family,
            "Evaluate the benign explanation and state whether the alert can safely be closed.",
            f"Case: FP-{i + 1:03d}\nEvidence: {evidence}",
            answer,
            i,
        ))

    severity_scenarios = [
        ("Low", "One failed login; no success; no related alerts; low-value test host.",
         "Low is a reasonable preliminary rating because the supplied evidence shows one failed attempt without successful access or related activity."),
        ("Medium", "Repeated authentication failures across several accounts; no success confirmed.",
         "Medium is reasonable pending investigation because the pattern may indicate password spraying, but no successful access is reported."),
        ("High", "Privileged login from an unusual source followed by encoded script execution; impact unknown.",
         "High is reasonable because privileged access and suspicious execution create significant risk. Determine execution outcome and affected assets promptly."),
        ("Critical", "Confirmed ransomware on critical servers; business services unavailable.",
         "Critical is justified by confirmed ransomware and material impact to critical services. Follow the organization's incident response and escalation policy."),
        ("Medium", "Malware detection on isolated test VM; file quarantined; no spread evidence.",
         "Medium may be appropriate pending validation because a detection occurred but the host is isolated and spread is not observed. Follow local severity policy."),
        ("High", "Sensitive data access by an unusual account; authorization unknown; transfer not confirmed.",
         "High may be appropriate for urgent investigation because sensitive data access is unusual, but exfiltration is not established. Confirm access justification and scope."),
        ("Low", "Blocked inbound scan from known research scanner; no host service accepted the traffic.",
         "Low may be reasonable if the source and activity are verified as expected and no service accepted the traffic. Apply local policy and confirm scope."),
        ("High", "Credential theft alert on a domain controller; evidence not yet independently validated.",
         "High is a cautious preliminary rating because the affected asset is critical, but validate the detection and scope immediately. Escalate according to local policy."),
        ("Medium", "Unusual DNS requests from one workstation; process and impact unknown.",
         "Medium may be reasonable while investigating the anomaly, subject to the asset context and local policy. The DNS pattern alone does not confirm compromise."),
        ("Low", "Expected service restart during approved maintenance; no anomalous child process.",
         "Low is reasonable if the maintenance record and command are verified. Reassess if telemetry contradicts the approved explanation."),
    ]

    for i in range(PER_CATEGORY):
        severity, evidence, answer = severity_scenarios[i % len(severity_scenarios)]
        rows.append(make(
            "severity_classification", f"severity_family_{i % len(severity_scenarios):02d}",
            "Assign a preliminary severity and justify it using impact, confidence, and available evidence.",
            f"Case: SEV-{i + 1:03d}\nEvidence: {evidence}\n"
            "Policy: organization-specific severity matrix applies",
            f"Preliminary severity: {severity}. {answer} Severity should follow the organization's defined matrix.",
            i,
        ))

    mitre_scenarios = [
        ("cmd.exe /c whoami", "T1059.003 - Windows Command Shell",
         "The command uses the Windows command shell. This supports T1059.003, but does not alone establish malicious intent."),
        ("A process enumerates services on remote hosts", "T1046 - Network Service Discovery",
         "Remote service enumeration is consistent with T1046. Validate the command and target context."),
        ("A user receives an email attachment; maliciousness unknown",
         "No definitive malicious technique assignment",
         "Receipt alone does not establish a malicious attachment or execution. More evidence is needed before mapping a malicious execution behavior."),
        ("A user opens a confirmed malicious attachment and executes its payload",
         "Potentially T1204.002 - Malicious File",
         "The described user execution of a confirmed malicious file is consistent with T1204.002. Confirm the payload and execution telemetry."),
        ("A phishing email delivers an attachment; delivery confirmed",
         "Potentially T1566.001 - Spearphishing Attachment",
         "The delivery behavior is consistent with T1566.001 if the email is confirmed as spearphishing. Do not infer user execution from delivery alone."),
        ("A process creates a scheduled task for persistence",
         "Potentially T1053.005 - Scheduled Task",
         "Scheduled-task creation can support T1053.005 when the observed action matches the technique. Creation alone does not prove malicious intent."),
        ("An account is added to a privileged group",
         "Potentially T1098.007 - Additional Local or Domain Groups",
         "Group membership modification may support a relevant account-manipulation technique, but validate the exact context and current ATT&CK mapping before assigning this sub-technique."),
        ("A host scans multiple ports on a remote network",
         "Potentially T1046 - Network Service Discovery",
         "Port scanning for service discovery may support T1046. Confirm the observed behavior and distinguish authorized scanning from adversarial activity."),
        ("A user authenticates to a remote service using valid credentials",
         "Insufficient evidence for a malicious technique",
         "Valid authentication alone is normal behavior and does not establish adversarial use. More context is needed to map malicious behavior."),
        ("A script downloads a file from an external URL",
         "Insufficient evidence for a definitive technique",
         "Downloading a file is not sufficient to determine a specific ATT&CK technique without context such as the process, delivery mechanism, and purpose."),
    ]

    for i in range(PER_CATEGORY):
        event, expected, answer = mitre_scenarios[i % len(mitre_scenarios)]
        rows.append(make(
            "mitre_mapping", f"attack_behavior_family_{i % len(mitre_scenarios):02d}",
            "Map observed behavior to MITRE ATT&CK only where the evidence supports the mapping.",
            f"Case: ATTACK-{i + 1:03d}\nObserved behavior: {event}",
            f"Assessment: {expected}. {answer}",
            i,
        ))

    summary_scenarios = [
        ("Authentication", "Server: AUTH-01; 24 failed logins across 7 accounts in 3 minutes; no successful login confirmed",
         "The server recorded repeated authentication failures across seven accounts over three minutes. No successful login is confirmed. Investigate source ownership, account targeting, and any subsequent successful access."),
        ("Ransomware", "Host: FILE-02; ransomware execution confirmed; 120 files renamed; host isolated",
         "Ransomware execution was confirmed on FILE-02, with 120 files renamed before isolation. Determine scope, recovery status, initial access, and whether other hosts are affected."),
        ("Outbound transfer", "Host: DB-03; 1.2 GB outbound; process unknown; destination reputation unavailable",
         "DB-03 transferred 1.2 GB outbound using an unidentified process. The available evidence does not establish exfiltration. Investigate process provenance, destination, and data access records."),
        ("Web attack", "Host: WEB-01; SQL injection-like request; HTTP 500; database logs unavailable",
         "WEB-01 received a request containing SQL injection-like syntax and returned HTTP 500. Exploitation is unconfirmed because database logs are unavailable. Review application and database telemetry."),
        ("Privilege", "Host: DC-01; account added to privileged group; change ticket unavailable",
         "An account was added to a privileged group on DC-01, and no change ticket is supplied. Verify the actor, authorization, affected account, and subsequent privileged activity."),
        ("Malware", "Host: WS-04; suspicious file quarantined; hash verdict unavailable",
         "A suspicious file was quarantined on WS-04. Its hash verdict is unavailable, so malware classification remains unverified. Review file metadata and endpoint execution history."),
        ("Cloud identity", "Cloud account: analyst-test; new API key created; source context unavailable",
         "A new API key was created for analyst-test, but source context and authorization are unavailable. Verify the actor, key permissions, usage history, and change approval."),
        ("DNS", "Host: WS-08; repeated queries to rare domain; process unknown; no endpoint detection supplied",
         "WS-08 repeatedly queried a rare domain, with the responsible process and endpoint verdict unavailable. Investigate domain reputation, process ownership, and subsequent connections."),
        ("Lateral movement", "Host A authenticates to Host B using admin account; source process unknown",
         "The admin account authenticated from Host A to Host B, but the initiating process and authorization are unknown. Verify the session, account activity, and related endpoint logs."),
        ("Data access", "User accessed a large number of sensitive records; approved business reason unknown",
         "A user accessed a large number of sensitive records, but the business justification is unavailable. Confirm authorization, access scope, and whether data was transferred."),
    ]

    for i in range(PER_CATEGORY):
        family, evidence, answer = summary_scenarios[i % len(summary_scenarios)]
        rows.append(make(
            "incident_summary", f"summary_family_{i % len(summary_scenarios):02d}",
            "Write a concise incident summary that separates observed facts from unresolved questions.",
            f"Case: INC-{i + 1:03d}\n{evidence}",
            answer,
            i,
        ))

    uncertainty_scenarios = [
        ("File hash unavailable; suspicious filename; execution unknown",
         "The filename alone cannot confirm malware. Obtain the hash, file metadata, execution history, process ancestry, and endpoint detections."),
        ("Connection flagged unusual; destination reputation missing",
         "The alert indicates unusual traffic, but maliciousness is unconfirmed. Obtain the domain, reputation, process owner, traffic baseline, and surrounding events."),
        ("Authentication attempt count and success status missing",
         "The scale and outcome of authentication activity cannot be determined. Retrieve event counts, timestamps, source addresses, targeted accounts, and success records."),
        ("Privilege escalation alert; command and actor missing",
         "The alert label alone does not prove privilege escalation. Collect the command, initiating process, actor identity, privileges, and change history."),
        ("Endpoint says blocked; firewall says allowed at a nearby timestamp",
         "The records may describe different stages or sessions. Align timestamps, connection identifiers, and endpoint action details before deciding whether traffic succeeded."),
        ("Threat feed flags domain; another feed reports no detections",
         "The intelligence is conflicting. Verify feed freshness, confidence, domain age, and observed behavior; neither verdict alone conclusively establishes maliciousness."),
        ("EDR alert exists; relevant endpoint logs were lost",
         "The missing logs limit confidence. Preserve available telemetry, obtain central EDR records and related network evidence, and avoid conclusions that require the missing data."),
        ("User denies activity; authentication log shows a valid session",
         "The discrepancy requires investigation but does not by itself prove account compromise or user dishonesty. Review MFA, device, session, source, and account audit records."),
        ("A detection fired during an authorized test; test scope unclear",
         "The alert may relate to the test, but the scope mismatch is unresolved. Confirm authorization, timing, source systems, and exact test actions before closing it."),
        ("Several alerts share a user but have different hosts and no clear timeline",
         "A shared username alone is insufficient to establish one incident. Compare session IDs, timestamps, source addresses, processes, and account context."),
    ]

    for i in range(PER_CATEGORY):
        evidence, answer = uncertainty_scenarios[i % len(uncertainty_scenarios)]
        rows.append(make(
            "uncertainty_analysis", f"uncertainty_family_{i % len(uncertainty_scenarios):02d}",
            "Explain what can be concluded, what remains uncertain, and what evidence is needed next.",
            f"Case: UNC-{i + 1:03d}\nEvidence: {evidence}",
            answer,
            i,
        ))

    rng.shuffle(rows)
    return rows


def validate(rows):
    errors = []
    exact = set()
    category_counts = Counter()
    family_groups = defaultdict(set)

    for index, row in enumerate(rows, 1):
        for field in ("instruction", "input", "output", "source", "category",
                      "scenario_family", "generator_version"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                errors.append(f"Row {index}: missing/invalid {field}")

        if row.get("category") not in CATEGORIES:
            errors.append(f"Row {index}: invalid category")

        key = tuple(row.get(k, "").strip().lower()
                    for k in ("instruction", "input", "output"))
        if key in exact:
            errors.append(f"Row {index}: exact duplicate")
        exact.add(key)

        if len(row.get("output", "").split()) < 8:
            errors.append(f"Row {index}: output too short")

        category_counts[row.get("category", "unknown")] += 1
        family_groups[row.get("scenario_family", "unknown")].add(
            row.get("category", "unknown")
        )

    return errors, category_counts, family_groups


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    rows = build_examples()
    errors, counts, families = validate(rows)

    if errors:
        raise SystemExit("Validation failed:\n" + "\n".join(errors[:40]))

    with OUTPUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    report = {
        "version": VERSION,
        "total": len(rows),
        "target_per_category": PER_CATEGORY,
        "category_counts": dict(counts),
        "unique_inputs": len({r["input"] for r in rows}),
        "unique_outputs": len({r["output"] for r in rows}),
        "unique_instruction_input_pairs": len({
            (r["instruction"], r["input"]) for r in rows
        }),
        "unique_scenario_families": len({r["scenario_family"] for r in rows}),
        "validation_errors": errors,
        "status": "STRUCTURE_VALIDATED_REVIEW_REQUIRED",
        "caveat": (
            "This deterministic pilot uses reusable scenario templates. "
            "Distinct inputs are not proof of independent or factually verified "
            "examples. Review labels and group scenario families before splitting."
        ),
    }
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nWrote: {OUTPUT}")
    print(f"Wrote: {REPORT}")


if __name__ == "__main__":
    main()
