
#!/usr/bin/env python3
"""Build 4,000 SOC training candidates with expanded correlation coverage and consistent provenance metadata.

Run from the repository root:
  python ai/tiny_llm/training/build_soc_training_v6_4_1_generated.py

This script validates ATT&CK ID/name consistency against the local JSONL reference.
It does NOT claim that all behavioral mappings are factually verified.
"""
import json
import hashlib
import random
import re
from collections import Counter
from pathlib import Path

ROOT = Path("data/raw/soc_curated_v3")
OUT = ROOT / "soc_training_v4_revision_v6_4_1.jsonl"
REPORT = ROOT / "soc_training_v4_revision_v6_4_1_build_report.json"
ATTACK = Path("data/processed/mitre_attack/mitre_techniques.jsonl")
SEED = 20261023
PER_CATEGORY = 500
VERSION = "soc-training-v6.4.1-provenance-metadata"
CATEGORIES = [
    "alert_analysis", "ioc_analysis", "alert_correlation",
    "false_positive_assessment", "severity_classification",
    "mitre_mapping", "incident_summary", "uncertainty_analysis",
]

# These mappings are candidates tied to explicit observed behaviors. The local
# ATT&CK reference validates the identifier/name pair, not whether the scenario
# meets every technique criterion. Every mapping remains review-required.
MAPPING_BANK = [
    ("T1059.001", "PowerShell", "A PowerShell process executes a command", "PowerShell execution is observed. This is consistent with the technique, but execution alone does not establish malicious intent."),
    ("T1059.003", "Windows Command Shell", "cmd.exe executes a command", "Windows Command Shell use is observed. This supports the technique behavior, but the command's purpose and authorization remain relevant."),
    ("T1046", "Network Service Discovery", "A host probes multiple ports on several systems to identify exposed services", "The observed probing may be consistent with network service discovery. Verify targets, command details, and authorization."),
    ("T1021.004", "SSH", "An account authenticates to a remote host over SSH", "SSH remote-service use is observed. Valid SSH use alone does not show adversarial lateral movement; review account, source, and session context."),
    ("T1110.001", "Password Guessing", "Repeated password attempts target one account", "Repeated attempts may be consistent with password guessing. Check authentication outcomes, source context, and whether the activity was authorized."),
    ("T1053.005", "Scheduled Task", "A Windows scheduled task is created with an executable action", "Scheduled-task creation is observed and may match this technique. Review task action, creator, timing, and authorization before classifying it as malicious."),
    ("T1566.001", "Spearphishing Attachment", "A confirmed phishing email delivers an attachment", "Attachment-based spearphishing delivery may fit this technique when the message is confirmed as phishing. Delivery does not prove the attachment was executed."),
    ("T1204.002", "Malicious File", "A user executes a file independently confirmed as malicious", "The supplied facts describe user execution of a confirmed malicious file. Validate the file verdict and execution telemetry."),
    ("T1003.001", "LSASS Memory", "A process attempts to access LSASS memory", "The access attempt may be consistent with LSASS memory credential dumping. Confirm process access telemetry and distinguish authorized security tooling."),
    ("T1021.002", "SMB/Windows Admin Shares", "An account accesses a remote Windows host over SMB", "SMB remote access is observed. The protocol alone is not malicious; inspect account privileges, source host, and remote actions."),
    ("T1055", "Process Injection", "Telemetry reports a process attempting to write to and execute memory in another process", "The behavior may be consistent with process injection. Validate the telemetry and target process before assigning the technique."),
    ("T1543.003", "Windows Service", "A new Windows service is installed with an executable path", "Service creation is observed and may match this technique. Determine whether it was approved and inspect the binary and creator."),
]

def load_attack():
    if not ATTACK.exists():
        raise FileNotFoundError(f"Local ATT&CK reference not found: {ATTACK}")
    records = []
    with ATTACK.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if line.strip():
                row = json.loads(line)
                if not row.get("technique_id") or not row.get("name"):
                    raise ValueError(f"ATT&CK line {line_no} missing technique_id/name")
                records.append(row)
    by_id = {}
    for row in records:
        tid = row["technique_id"]
        if tid in by_id:
            raise ValueError(f"Duplicate ATT&CK technique ID: {tid}")
        by_id[tid] = row
    if not records:
        raise ValueError("ATT&CK reference is empty")
    return by_id

HOSTS = ["WS-014", "WS-027", "SRV-APP-02", "SRV-FILE-01", "DC-01", "WEB-03", "DB-02", "LINUX-07", "JUMP-01", "CLOUD-VM-04"]
USERS = ["analyst.test", "svc-backup", "j.smith", "admin.ops", "svc-web", "build-agent", "finance.user", "helpdesk.l1", "unknown-user", "svc-monitor"]
SOURCES = ["10.14.8.23", "10.18.2.44", "192.0.2.17", "198.51.100.29", "203.0.113.46", "10.20.4.19", "172.16.8.7", "192.0.2.88"]
DOMAINS = ["login-check.example", "cdn-update.example", "fileshare.example", "telemetry.example", "portal.example", "sync-service.example", "auth-review.example", "updates.example"]
PROCESSES = ["powershell.exe", "cmd.exe", "wscript.exe", "rundll32.exe", "python.exe", "chrome.exe", "svchost.exe", "unknown.exe", "sshd", "nginx"]
TIMES = ["09:14:02", "09:17:41", "10:03:19", "11:26:54", "13:42:08", "15:05:33", "17:48:21", "22:16:07"]
CONTEXTS = [
    "approved change ticket is present and matches the host and time",
    "change ticket is missing",
    "source is listed in the asset inventory but schedule is unknown",
    "actor denies initiating the activity",
    "process ancestry is unavailable",
    "destination reputation is unavailable",
    "related endpoint telemetry shows no follow-on event in the collected window",
    "one adjacent alert exists but identifiers do not yet establish a shared incident",
    "maintenance window is active but the recorded target differs from the ticket",
    "source and destination are known but business purpose is not documented",
]
OUTCOMES = [
    "no successful authentication is recorded",
    "a successful authentication follows the failures",
    "execution outcome is not collected",
    "the endpoint reports prevention, but downstream network activity is unknown",
    "the process completed, but its payload is unavailable",
    "the event was blocked at the endpoint according to the supplied record",
    "no file hash or signer information is available",
    "the observed action completed; impact has not been assessed",
]
ACTIONS = [
    "retrieve the full process tree and command line",
    "check the authentication result and surrounding login history",
    "enrich the destination using approved threat-intelligence sources",
    "compare the event with change records and asset inventory",
    "collect endpoint and network telemetry for the same time window",
    "confirm the actor, authorization, and affected resource",
    "preserve relevant logs and record the missing evidence",
    "review the detection rule and its expected benign triggers",
]
BENIGN = [
    "a signed updater runs during a documented deployment",
    "a registered scanner probes hosts within its approved scope",
    "a backup job transfers data to its registered storage target",
    "an administrator runs a command covered by a matching change ticket",
    "a monitoring probe checks service health at its configured interval",
    "a browser process connects to its documented vendor endpoint",
]
SUSPICIOUS = [
    "a script host is spawned by an Office application",
    "repeated authentication failures target multiple accounts",
    "a privileged account authenticates from an unusual source",
    "a new service or scheduled task appears without a matching change record",
    "a process initiates outbound traffic to a destination with unknown reputation",
    "a process attempts to access credential-sensitive memory",
]
IMPACTS = [
    ("Low", "one failed login, no success recorded, and no related alerts"),
    ("Low", "expected administrative activity is supported by a matching change record"),
    ("Medium", "repeated failures affect several accounts but no successful access is confirmed"),
    ("Medium", "an unusual network event affects one workstation; impact is unknown"),
    ("High", "a privileged account and suspicious execution are involved; scope is unknown"),
    ("High", "sensitive records were accessed unusually; authorization is unresolved"),
    ("Critical", "confirmed ransomware affects critical servers and business services are unavailable"),
    ("Critical", "confirmed destructive activity affects multiple critical assets"),
]
IOC_TYPES = [
    ("domain", "Domain", lambda i: DOMAINS[i % len(DOMAINS)]),
    ("ip_address", "Destination IP", lambda i: SOURCES[i % len(SOURCES)]),
    ("process", "Process", lambda i: PROCESSES[i % len(PROCESSES)]),
    ("user", "Account", lambda i: USERS[i % len(USERS)]),
    ("file_hash", "SHA-256", lambda i: hashlib.sha256(f"soc-v4-file-{i}".encode()).hexdigest()),
    ("url_path", "URL path", lambda i: ["/account/verify", "/api/export", "/update/check", "/download/report", "/login/session"][i % 5]),
]
LOG_EVENTS = [
    ("Windows Security", "Event 4625", "failed logon", "failure status is present; source ownership is unknown"),
    ("Windows Security", "Event 4624", "successful logon", "a successful logon is recorded; legitimacy is not established"),
    ("Sysmon", "Event 1", "process creation", "process and parent fields are available; command-line completeness varies"),
    ("Sysmon", "Event 3", "network connection", "a network connection is recorded; process attribution must be checked"),
    ("Linux auth", "sshd authentication failure", "SSH authentication failure", "one or more failures are recorded; no compromise is established"),
    ("Firewall", "allow event", "connection permitted", "the firewall allowed traffic; this does not establish application-level success"),
    ("DNS resolver", "query event", "DNS query", "a query is recorded; domain reputation and process attribution are unresolved"),
    ("EDR", "prevention event", "endpoint prevention", "the product reports prevention; verify action status and follow-on behavior"),
]

def add(rows, category, family, instruction, input_text, output, idx, extra=None):
    row = {
        "instruction": instruction.strip(),
        "input": input_text.strip(),
        "output": output.strip(),
        "source": "synthetic_scenario_candidate_v6_4_1",
        "category": category,
        "scenario_family": family,
        "scenario_id": f"V4-{category}-{idx:04d}",
        "verification_status": "reference_checked_behavior_needs_human_review",
        "generator_version": VERSION,
        "metadata": {
            "synthetic": True,
            "seed": SEED,
            "requires_human_review": True,
            **(extra or {}),
        },
    }
    rows.append(row)

def build_rows(attack):
    rng = random.Random(SEED)
    rows = []
    # Each category uses deterministic combinatorial variation. Records are
    # synthetic candidates and are not represented as real incident observations.
    for i in range(PER_CATEGORY):
        host, user, src = HOSTS[i % len(HOSTS)], USERS[(i * 3) % len(USERS)], SOURCES[(i * 5) % len(SOURCES)]
        dest = SOURCES[(i * 3 + 2) % len(SOURCES)]
        domain = DOMAINS[(i * 7) % len(DOMAINS)]
        proc = PROCESSES[(i * 3 + 1) % len(PROCESSES)]
        time = TIMES[(i * 5) % len(TIMES)]
        ctx = CONTEXTS[(i * 7 + i // 9) % len(CONTEXTS)]
        outcome = OUTCOMES[(i * 3 + i // 7) % len(OUTCOMES)]
        action = ACTIONS[(i * 5 + i // 11) % len(ACTIONS)]
        case = f"{i+1:04d}"

        # Alert analysis
        behavior = (SUSPICIOUS if i % 3 else BENIGN)[(i * 3 + i // 5) % (len(SUSPICIOUS) if i % 3 else len(BENIGN))]
        severity_hint = ["low", "medium", "high", "unassigned"][(i // 2) % 4]
        alert_input = (f"Alert ID: AL-{case}\nHost: {host}\nUser: {user}\nTimestamp: {time}\n"
                       f"Observed behavior: {behavior}\nSource: {src}\nDestination: {dest}\n"
                       f"Context: {ctx}\nExisting severity label: {severity_hint}")
        if "outbound traffic" in behavior or "network" in behavior:
            alert_action = "identify the initiating process and correlate endpoint process telemetry with DNS, proxy, and firewall records for the destination"
        elif "authentication" in behavior or "login" in behavior or "account" in behavior:
            alert_action = "review authentication outcomes, source and device attribution, MFA results, and any actions after a successful session"
        elif "service" in behavior or "scheduled task" in behavior:
            alert_action = "inspect the service or task configuration, executable path and hash, creator identity, execution time, and change authorization"
        elif "credential-sensitive memory" in behavior:
            alert_action = "inspect process access telemetry, parent-child relationships, target process, signer, and whether the activity belongs to approved security tooling"
        elif "script host" in behavior:
            alert_action = "retrieve the parent process, command line, script content where available, signer, and related child-process or network activity"
        elif "scanner" in behavior or "updater" in behavior or "backup" in behavior or "monitoring" in behavior:
            alert_action = "compare the process, target, timing, and scope against the approved change or asset inventory before treating the event as benign"
        else:
            alert_action = "collect the telemetry most directly related to the observed behavior and verify the actor, scope, and outcome"
        alert_out = (f"Observed: {behavior}. The event is associated with {host} and account {user} at {time}; "
                     f"source {src} and destination {dest} are recorded. Context: {ctx}. "
                     f"The supplied event does not by itself establish malicious intent or impact. "
                     f"Do not treat the existing severity label as proof of maliciousness. "
                     f"Next step: {alert_action}.")
        add(rows, "alert_analysis", f"alert_{i%24:02d}", "Assess the alert using only the supplied evidence; separate facts from hypotheses.",
            alert_input, alert_out, i+1)

        # IOC analysis — vary evidence state and interpretation explicitly.
        # Verdict labels below are synthetic scenario assumptions, not live lookups.
        ioc_scenarios = [
            ("unavailable", "No reputation result is available; maliciousness remains unknown."),
            ("not checked", "The indicator has not been checked against a threat-intelligence source."),
            ("conflicting", "Threat-intelligence sources disagree; review source provenance and timestamps before drawing a conclusion."),
            ("no verdict supplied", "The input contains no verdict; do not infer one."),
            ("reported malicious by one source", "One source reports the indicator as malicious; verify source reliability and seek independent corroboration."),
            ("reported benign by one source", "One source reports a benign result; that result alone does not establish that the indicator is safe."),
        ]
        itype, label, value_fn = IOC_TYPES[(i * 5 + i // 6) % len(IOC_TYPES)]
        value = value_fn(i)
        verdict, interpretation = ioc_scenarios[(i * 7 + i // 5) % len(ioc_scenarios)]
        ioc_contexts = [
            "no related activity is present in the supplied telemetry",
            "the indicator appears in one endpoint event",
            "the indicator appears in endpoint and DNS records within the same time window",
            "an approved change may explain the activity but has not been fully matched",
            "the source process and actor are not yet established",
            "the available records disagree about whether the activity succeeded",
            "the indicator was observed but no impact assessment is available",
            "the time window is incomplete",
            "the indicator appears in a historical record with no current activity",
            "the same indicator appears on two hosts but shared cause is not established",
            "the event is associated with a known business application but its purpose is undocumented",
            "the relevant endpoint telemetry is unavailable for part of the event window",
        ]
        ioc_context = ioc_contexts[(i * 3 + i // 7) % len(ioc_contexts)]
        ioc_input = (
            f"Case: IOC-{case}\nHost: {host}\nIndicator type: {label}\n"
            f"Indicator: {value}\nThreat-intelligence status: {verdict}\n"
            f"Observed context: {ioc_context}"
        )
        ioc_guidance = {
            "domain": "Check DNS answers, first/last-seen times, domain ownership and reputation from approved sources; correlate the domain with the resolving host, process, and relevant network activity.",
            "ip_address": "Determine whether the address is public, private, or reserved; review protocol, port, direction, flow outcome, ownership, and sourced reputation before interpreting it.",
            "process": "Collect the executable path, cryptographic hash, signer, parent process, command line, user, and execution context; a process name alone is not unique.",
            "user": "Resolve the account to the identity source and review authentication results, MFA/session details, device or source attribution, privileges, and nearby account changes.",
            "file_hash": "Preserve the exact hash and identify the associated file, path, signer, acquisition source, and scan provenance; verify any reputation result against approved sources.",
            "url_path": "A URL path alone is not globally unique. Obtain the full URL and host when available, HTTP method/status, proxy or application records, request time, and requesting identity or process.",
        }
        ioc_out = (
            f"Observed indicator: {label} `{value}` on {host}. Evidence interpretation: {interpretation} "
            f"Observed context: {ioc_context}. Observation alone does not prove compromise. "
            f"Type-specific validation: {ioc_guidance[itype]} "
            f"Record the source, timestamp, and confidence of any enrichment result. Correlate only relevant endpoint, DNS, identity, or network records. "
            f"If evidence remains insufficient or conflicting, leave the verdict unresolved."
        )
        add(rows, "ioc_analysis", f"ioc_{itype}",
            "Extract the indicator exactly and distinguish observation, reputation evidence, and conclusions.",
            ioc_input, ioc_out, i+1,
            {"indicator_type": itype, "threat_intelligence_status": verdict})

        # Alert correlation: pair actual event types with explicit time delta; do not invent a relationship.
        t1 = TIMES[(i * 2) % len(TIMES)]
        t2 = TIMES[(i * 2 + 1) % len(TIMES)]
        # v6.3/v6.4: broaden correlation coverage with 16 curated event pairs.
        # Pair selection is deterministic and does not assert that events are related.
        correlation_pairs = [
            ("login failure", "login success"),
            ("process start", "outbound connection"),
            ("DNS query", "endpoint prevention"),
            ("firewall event", "privilege change"),
            ("process start", "endpoint prevention"),
            ("DNS query", "outbound connection"),
            ("login success", "privilege change"),
            ("firewall event", "outbound connection"),
            ("login failure", "privilege change"),
            ("process start", "DNS query"),
            ("endpoint prevention", "outbound connection"),
            ("firewall event", "endpoint prevention"),
            ("DNS query", "firewall event"),
            ("login success", "outbound connection"),
            ("process start", "privilege change"),
            ("login failure", "endpoint prevention"),
        ]
        type_a, type_b = correlation_pairs[i % len(correlation_pairs)]
        # Vary continuity so some pairs share a host/account and others do not.
        host_b = host if (i // len(correlation_pairs)) % 2 == 0 else HOSTS[(i+3)%len(HOSTS)]
        user_b = user if (i // 3) % 2 == 0 else USERS[(i+2)%len(USERS)]
        # v6.4: retain shared-source cases, but deliberately include distinct-source cases.
        source_b = src if (i // len(correlation_pairs)) % 2 == 0 else SOURCES[(i + 1) % len(SOURCES)]

        def _seconds(clock):
            hh, mm, ss = (int(part) for part in clock.split(':'))
            return hh*3600 + mm*60 + ss

        delta = abs(_seconds(t2) - _seconds(t1))
        delta_text = f"{delta//3600}h {(delta%3600)//60}m {delta%60}s" if delta >= 3600 else f"{delta//60}m {delta%60}s"
        temporal_note = "within five minutes" if delta <= 300 else "more than five minutes apart"
        if type_a == 'login failure' and type_b == 'login success' and user == user_b:
            relation = "a login failure and a later successful login for the same account; confirm source and session continuity"
        elif type_a == 'DNS query' and type_b == 'endpoint prevention':
            relation = "no direct causal link is established by these event types alone; verify process, domain, and endpoint identifiers"
        elif host != host_b:
            relation = "events on different hosts; shared source alone does not establish a common incident"
        elif user != user_b:
            relation = "events associated with different accounts; a shared source field alone is insufficient to link them"
        else:
            relation = "a possible relationship that requires a shared session, process, connection tuple, or other corroborating identifier"
        corr_input = (f"Case: COR-{case}\nEvent A: time={t1}; host={host}; user={user}; source={src}; type={type_a}\n"
                      f"Event B: time={t2}; host={host_b}; user={user_b}; source={source_b}; type={type_b}\n"
                      f"Time difference: {delta_text}\nPotential relationship to evaluate: {relation}\nMissing/contextual evidence: {ctx}")

        # Choose a correlation-specific follow-up, not the global generic ACTIONS entry.
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

        # Tailor the closing evidence requirement to the event pair.
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
                    f"{corr_close}")
        add(rows, "alert_correlation", f"correlation_{i%32:02d}", "Correlate the supplied events, state the strongest supported relationship, and identify limits.",
            corr_input, corr_out, i+1)

        # False positive assessment
        ben = BENIGN[(i * 3 + i // 4) % len(BENIGN)]
        fp_state = ["matching authorization", "authorization absent", "ticket present but scope differs", "source is allowlisted but behavior is unusual", "test is authorized but time window is unclear"][(i // 2) % 5]
        follow_on = ["none observed in collected window", "present", "not collected"][i % 3]
        fp_input = f"Case: FP-{case}\nHost: {host}\nAccount: {user}\nActivity: {ben}\nAuthorization state: {fp_state}\nAdditional context: {ctx}\nUnexpected follow-on behavior: {follow_on}"
        if fp_state == "matching authorization" and i % 3 == 0:
            fp_conclusion = "The evidence supports a benign explanation, but closure still requires confirming the activity matches the approved scope."
        elif fp_state == "authorization absent" or fp_state == "ticket present but scope differs":
            fp_conclusion = "Do not close as a false positive yet; the authorization gap or scope mismatch remains unresolved."
        else:
            fp_conclusion = "The benign explanation is plausible but incomplete; allowlisting or expected timing alone is insufficient to suppress the alert."
        if follow_on == "present":
            fp_next = "investigate the follow-on behavior and correlate its process, identity, destination, and timestamps with the authorized activity"
        elif follow_on == "not collected":
            fp_next = "collect endpoint and network telemetry for the relevant time window before deciding whether the activity is benign"
        else:
            fp_next = "verify that the observed activity matches the approved actor, command, target, and time window"
        fp_out = (f"Assessment: {fp_conclusion} The stated activity is: {ben}. Authorization state: {fp_state}. "
                  f"Context: {ctx}. Follow-on behavior: {follow_on}. Next step: {fp_next}. "
                  "Do not close the alert while unexplained behavior or a scope mismatch remains.")
        add(rows, "false_positive_assessment", f"fp_{i%25:02d}", "Assess whether the supplied evidence supports closing the alert as a false positive.",
            fp_input, fp_out, i+1)

        # Severity classification
        sev, sev_evidence = IMPACTS[(i * 5 + i // 8) % len(IMPACTS)]
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
        sev_context = ctx
        if "matching change record" in sev_evidence:
            sev_context = "the supplied change record matches the activity, host, and time; confirm scope before closure"
        elif "change ticket is missing" in ctx and "expected administrative activity" in sev_evidence:
            sev_context = "the activity is described as expected, but the supporting change ticket is missing; authorization remains unverified"
        sev_input = f"Case: SEV-{case}\nAsset class: {asset}\nEvidence: {sev_evidence}\nAnalyst confidence: {confidence}\nAdditional context: {sev_context}\nPolicy: local severity matrix governs final assignment"

        # v6.1: prioritize potential impact, then tailor validation to confidence.
        # Low confidence must not suppress urgent handling of High/Critical cases.
        matching_change = "matching change record" in sev_evidence
        if sev == "Critical":
            severity_action = (
                "follow the organization's critical-incident escalation procedure, "
                "preserve evidence, and assess immediate containment with the incident commander; "
                "independently verify impact, scope, and supporting telemetry"
            )
        elif sev == "High":
            if confidence == "low":
                severity_action = (
                    "escalate for prompt analyst review, preserve relevant endpoint and network "
                    "evidence, and urgently validate affected scope and supporting telemetry "
                    "before finalizing severity"
                )
            else:
                severity_action = (
                    "escalate for prompt analyst review, validate affected scope, and preserve "
                    "relevant endpoint and network evidence"
                )
        elif sev == "Medium":
            if confidence == "low":
                severity_action = (
                    "validate the underlying evidence, confirm affected assets and scope, and gather "
                    "corroborating telemetry before finalizing severity"
                )
            else:
                severity_action = (
                    "validate the affected scope, confirm relevant event outcomes, and gather "
                    "corroborating telemetry"
                )
        elif matching_change:
            severity_action = (
                "verify that the change record covers the exact activity, host, and time; check for "
                "contradictory alerts or impact indicators, and consider closure only if the evidence "
                "supports expected activity"
            )
        elif confidence == "low":
            severity_action = (
                "validate the evidence and approved baseline, check for related alerts or impact "
                "indicators, and gather missing telemetry before closing the case"
            )
        else:
            severity_action = (
                "compare the event with the approved baseline and verify whether related alerts "
                "or impact indicators exist before considering closure"
            )
        sev_out = (f"Preliminary severity: {sev}. Rationale: {sev_evidence}. Asset class: {asset}; analyst confidence: {confidence}. "
                   f"Context: {sev_context}. This is a provisional assessment, not a substitute for the organization's severity matrix. "
                   f"Reassess if impact, scope, or confidence changes. Recommended next step: {severity_action}.")
        add(rows, "severity_classification", f"severity_{sev.lower()}_{i%12:02d}", "Assign a preliminary severity using impact and confidence; state what could change it.",
            sev_input, sev_out, i+1)

        # MITRE mapping; use exact local ID/name where candidate is proposed.
        tid, expected_name, behavior_desc, mapping_reason = MAPPING_BANK[i % len(MAPPING_BANK)]
        local = attack.get(tid)
        assert local is not None, f"Candidate ATT&CK ID missing from local reference: {tid}"
        if local["name"] != expected_name:
            raise ValueError(f"ATT&CK name mismatch for {tid}: bank={expected_name!r}, local={local['name']!r}")
        evidence_quality = ["single event", "corroborated endpoint telemetry", "partial log record"][(i // len(MAPPING_BANK)) % 3]
        map_context = ["authorization unknown", "activity is confirmed in endpoint telemetry", "related events are incomplete", "change record is absent"][(i // (len(MAPPING_BANK) * 3)) % 4]
        if tid in {"T1059.001", "T1059.003", "T1055", "T1003.001"}:
            mapping_action = "inspect process ancestry, command line, target process, and supporting endpoint telemetry; verify whether the behavior was authorized"
        elif tid == "T1543.003":
            mapping_action = "inspect service name, executable path and hash, service creator, start configuration, and change authorization"
        elif tid == "T1053.005":
            mapping_action = "inspect task name, executable action, creator, trigger, persistence behavior, and change authorization"
        elif tid in {"T1021.004", "T1021.002"}:
            mapping_action = "correlate the account, source host, destination host, session, authentication result, and subsequent remote actions"
        elif tid == "T1110.001":
            mapping_action = "review authentication outcomes, source attribution, targeted accounts, rate, and any subsequent successful session"
        elif tid == "T1566.001":
            mapping_action = "review message headers, sender authentication, attachment hash, delivery evidence, and whether the attachment was opened or executed"
        elif tid == "T1204.002":
            mapping_action = "validate the file verdict and hash, confirm process execution, and inspect parent-child processes and follow-on behavior"
        else:
            mapping_action = "validate the observed behavior against the technique criteria and collect the most relevant supporting telemetry"
        map_input = f"Case: ATTACK-{case}\nObserved behavior: {behavior_desc}\nEvidence quality: {evidence_quality}\nContext: {map_context}\nAnalyst follow-up available: {mapping_action}"
        map_out = f"Candidate mapping: {tid} — {local['name']}. Reasoning: {mapping_reason} Evidence quality: {evidence_quality}. Observed behavior: {behavior_desc}. Context: {map_context}. Next validation step: {mapping_action}. The local reference confirms that the ID and name match; it does not independently validate the behavioral mapping. Human review required."
        add(rows, "mitre_mapping", f"mitre_{tid}", "Suggest an ATT&CK mapping only where supported and distinguish reference validation from behavioral confidence.",
            map_input, map_out, i+1, {"candidate_technique_id": tid, "candidate_technique_name": local["name"], "reference_id_name_match": True})

        # Incident summary — broaden incident types and evidence/impact combinations.
        incident_types = [
            "authentication anomaly", "possible malware execution", "unusual outbound transfer",
            "privileged group change", "web request anomaly", "DNS anomaly", "remote service access",
            "endpoint prevention", "repeated account lockout", "unexpected scheduled task",
            "suspicious service installation", "unusual database query", "cloud role change",
            "multiple failed VPN logins", "unexpected archive creation", "possible data staging",
            "new local administrator", "unusual scripting activity", "certificate validation failure",
            "unexpected external connection", "suspicious file write", "EDR tamper alert",
            "unexpected mailbox rule", "sensitive file access",
        ]
        incident_type = incident_types[(i * 7 + i // 5) % len(incident_types)]
        count = 1 + (i * 7) % 67
        duration = 1 + (i * 11) % 90
        impact_states = [
            "impact not assessed",
            "one host affected in current telemetry",
            "host isolated by response tooling; containment requires confirmation",
            "scope may include additional assets",
            "no data access evidence is included in the supplied record",
            "service degradation is reported but not independently measured",
            "account access is observed; downstream actions are unknown",
            "no confirmed business impact is documented",
        ]
        impact = impact_states[(i * 3 + i // 4) % len(impact_states)]
        incident_question_by_type = {
            "authentication anomaly": "whether the account activity was authorized and whether any authentication succeeded",
            "possible malware execution": "whether the file verdict is supported and what process or network activity followed execution",
            "unusual outbound transfer": "whether the destination, transferred volume, and data sensitivity match an approved business workflow",
            "privileged group change": "who initiated the privilege change, whether it was approved, and which identities or systems were affected",
            "web request anomaly": "whether the request reached the application and whether it accessed or changed data",
            "DNS anomaly": "whether the queried domain was resolved by the affected host and which process initiated the query",
            "remote service access": "whether the remote session was authorized and what commands or file transfers followed",
            "endpoint prevention": "whether prevention completed and whether related execution or follow-on activity occurred",
            "repeated account lockout": "whether the lockouts and authentication attempts share a source, account, or session",
            "unexpected scheduled task": "whether the task action, creator, trigger, and persistence behavior are approved",
            "suspicious service installation": "whether the service binary, creator, start configuration, and installation are authorized",
            "unusual database query": "whether the query accessed or modified sensitive records and whether the access was authorized",
            "cloud role change": "whether the cloud role change was approved and whether the role was subsequently used",
            "multiple failed VPN logins": "whether any VPN login succeeded and whether the attempts share a source or session",
            "unexpected archive creation": "whether the archive contains sensitive data and whether it was transferred off the host",
            "possible data staging": "whether file and network evidence supports staging and what data or destinations were involved",
            "new local administrator": "which actor created the account or privilege and whether the change was approved",
            "unusual scripting activity": "what script content and parent process were involved and whether execution was authorized",
            "certificate validation failure": "which certificate chain or validation check failed and whether the connection proceeded",
            "unexpected external connection": "which process initiated the connection and whether destination, protocol, and data flow are expected",
            "suspicious file write": "which process wrote the file, what the file contains, and whether it was executed or persisted",
            "EDR tamper alert": "which actor or process attempted to alter security controls and whether monitoring remains effective",
            "unexpected mailbox rule": "who created the rule, what messages it targets, and whether forwarding or deletion occurred",
            "sensitive file access": "which identity accessed the files, whether access was authorized, and whether data was copied or transferred",
        }
        open_question = incident_question_by_type[incident_type]
        inc_input = (
            f"Case: INC-{case}\nType: {incident_type}\nHost: {host}\nAccount: {user}\nSource: {src}\n"
            f"Observed events: {count} within {duration} minutes\n"
            f"Impact: {impact}\nOpen question: {open_question}\nContext: {ctx}"
        )
        inc_out = (
            f"Summary: {count} {incident_type} event(s) were recorded for {host} over {duration} minute(s), "
            f"associated with account {user} and source {src}. Reported impact: {impact}. "
            f"Unresolved question: {open_question}. Context: {ctx}. "
            f"Next investigation step: collect the audit, endpoint, network, or application records needed to answer this question: {open_question}. "
            f"Distinguish recorded events from inferred impact; "
            f"do not state confirmed compromise or exfiltration unless corroborating evidence supports it."
        )
        add(rows, "incident_summary", f"incident_{incident_type.replace(' ','_')}",
            "Write a concise incident summary separating observed facts, impact, and unresolved questions.",
            inc_input, inc_out, i+1,
            {"incident_type": incident_type, "impact_state": impact})

        # Uncertainty analysis v2 — distinct competing hypotheses and discriminating evidence.
        # These are synthetic candidate scenarios and require expert review.
        uncertainty_cases = [
            {
                "conflict": "endpoint reports prevention while a network log records an allowed connection",
                "missing": "connection tuple, process-to-connection linkage, timestamps, and prevention status",
                "supporting": "the prevention event may indicate that a related execution or file action was blocked",
                "alternative": "the allowed connection may be unrelated, may have occurred before prevention, or may be legitimate traffic",
                "discriminator": "match host, process identifier, destination, ports, and normalized timestamps; then verify whether the connection belongs to the prevented activity",
                "step": "correlate endpoint process telemetry with firewall or network-flow records using the same host, process, tuple, and time window",
            },
            {
                "conflict": "one intelligence source flags the domain while another has no detections",
                "missing": "source provenance, verdict rationale, first-seen time, domain resolution history, and observation timestamps",
                "supporting": "a sourced malicious verdict may justify prioritizing review if it is credible and relevant to the observed time",
                "alternative": "a clean or empty result may reflect limited coverage, stale data, shared hosting, or a false positive in the first source",
                "discriminator": "compare source quality and timestamps, validate the exact domain and subdomain, and correlate DNS answers with the affected host and process",
                "step": "record each source and timestamp, inspect the domain's observed resolution and ownership context, and correlate the host's actual activity before assigning a verdict",
            },
            {
                "conflict": "user denies the activity while a valid session is recorded",
                "missing": "session identifier, MFA result, source device, authentication method, token details, and post-login actions",
                "supporting": "a valid session could indicate account use that requires investigation, especially if device or location differs from baseline",
                "alternative": "the session may be legitimate, delegated, stale, or associated with a shared or misattributed identity",
                "discriminator": "match the session to the device, authentication factors, source, and actions, and independently confirm the user's account of events",
                "step": "preserve identity-provider audit records and review MFA, device, source, session lifetime, and subsequent actions without treating denial alone as proof of compromise",
            },
            {
                "conflict": "the alert is high confidence but the process tree is missing",
                "missing": "parent and child process identifiers, full command line, signer or hash, user context, and event coverage status",
                "supporting": "the alert's underlying detection evidence may still be meaningful if the rule matched specific behaviors",
                "alternative": "the score may depend on incomplete fields, a noisy rule, or a legitimate administrative tool",
                "discriminator": "inspect the detection rule's matched fields and retrieve endpoint process telemetry for the same event before relying on the confidence label",
                "step": "collect process ancestry and command-line evidence, inspect the rule's trigger conditions, and compare the executable and account with approved baseline activity",
            },
            {
                "conflict": "a change ticket exists but its target or timing differs from the event",
                "missing": "approved scope, exact change window, operator identity, target list, command history, and ticket approval trail",
                "supporting": "the ticket may explain the activity if the actual target and execution details fall within its approved scope",
                "alternative": "the ticket may be unrelated, mistimed, or insufficient to authorize the observed target or action",
                "discriminator": "compare the ticket's approved assets, operator, command, and time window with the event rather than relying on ticket existence alone",
                "step": "verify approval and exact scope with the change owner, then compare the execution record against the approved target, operator, command, and time",
            },
            {
                "conflict": "two records share a username but not a session identifier",
                "missing": "host identifiers, source addresses, session or logon IDs, process IDs, and normalized event times",
                "supporting": "the events may be related if independent identifiers and chronology connect them",
                "alternative": "the username may be reused across hosts or sessions, making the apparent link coincidental",
                "discriminator": "require corroboration from host, source, session, process, or a defensible timeline before treating the records as one incident",
                "step": "build a timeline and compare unique identifiers across both records; keep them separate if no reliable linkage is established",
            },
            {
                "conflict": "the event says success while the downstream action is not logged",
                "missing": "application audit events, downstream service logs, request or transaction ID, and logging coverage for the time window",
                "supporting": "the success status may show that an initial request or authentication step completed",
                "alternative": "the intended operation may have failed later, been rejected by another control, or not been logged by the downstream system",
                "discriminator": "distinguish request acceptance from completed business action by tracing the request or transaction across application and downstream logs",
                "step": "retrieve application and downstream audit records for the same request ID and time window, and verify whether logs were enabled and complete before inferring impact",
            },
            {
                "conflict": "timestamps are close but systems may use different time zones",
                "missing": "time-zone configuration, timestamp format, clock synchronization status, and measured clock skew",
                "supporting": "the events may be sequential if their timestamps can be reliably normalized",
                "alternative": "apparent ordering may be caused by time-zone differences, clock drift, buffering, or delayed ingestion",
                "discriminator": "normalize timestamps to a common reference and account for known clock skew before using event order to infer causality",
                "step": "check time-zone and NTP settings, normalize event times, document ingestion delays, and only then reconstruct the event sequence",
            },
            {
                "conflict": "an endpoint reports a file blocked but a separate log records a process start",
                "missing": "file hash, file path, process ID, event timestamps, prevention outcome, and file-instance linkage",
                "supporting": "the process start may indicate that execution was attempted or began before the block completed",
                "alternative": "the process event may refer to another file instance, a different host, or activity unrelated to the blocked file",
                "discriminator": "match hash, path, host, process ID, and chronology, and confirm whether the block prevented execution or only a later action",
                "step": "retrieve endpoint prevention details and process telemetry, verify the exact file identity, and check for child processes or follow-on activity",
            },
            {
                "conflict": "an account has repeated failures followed by one success",
                "missing": "source attribution, MFA result, successful-session details, device identity, and post-authentication activity",
                "supporting": "the success after repeated failures may warrant review for password guessing or account misuse",
                "alternative": "the sequence may reflect a user mistyping a password, a stale client, or an authorized retry from a known device",
                "discriminator": "compare source and device continuity, MFA, baseline behavior, and actions after the successful login rather than treating the sequence alone as compromise",
                "step": "review authentication outcomes, source reputation, device and MFA context, then inspect the successful session for unexpected actions",
            },
            {
                "conflict": "a cloud role change is recorded but the initiating identity is unclear",
                "missing": "complete cloud audit event, principal and session identifiers, assumed-role chain, source, and API request context",
                "supporting": "the role change may be security-relevant if it grants new privileges or departs from approved activity",
                "alternative": "the change may be automated or approved, with the apparent identity gap caused by role assumption or incomplete event fields",
                "discriminator": "trace the principal and session chain through cloud audit logs and compare the change with approved automation and access policy",
                "step": "retrieve the full audit event, resolve the initiating principal and assumed-role chain, and verify approval and subsequent use of the changed role",
            },
            {
                "conflict": "a large outbound transfer is observed but its business purpose is undocumented",
                "missing": "destination ownership, byte counts, transfer contents or classification, process identity, and approved workflow records",
                "supporting": "unusual volume or a sensitive destination may justify investigation when it deviates from a known baseline",
                "alternative": "the transfer may be a legitimate backup, synchronization, software update, or business workflow",
                "discriminator": "compare destination, volume, timing, process, data sensitivity, and change records against a verified baseline",
                "step": "preserve flow and endpoint records, identify the process and destination, consult the data owner, and assess content and authorization before concluding exfiltration",
            },
        ]
        case = uncertainty_cases[(i * 5 + i // 4) % len(uncertainty_cases)]
        uncertainty_contexts = [
            "no corroborating event is available in the current collection window",
            "the asset is production-critical and the business owner is not yet confirmed",
            "the activity overlaps a maintenance window but authorization is not established",
            "the available records come from different logging systems",
            "the actor's explanation has not been independently verified",
            "the collection window may omit events before or after the alert",
            "the observed activity may have a legitimate explanation, but scope is unconfirmed",
            "the supplied evidence does not establish intent or business impact",
        ]
        uncertainty_context = uncertainty_contexts[(i * 3 + i // 7) % len(uncertainty_contexts)]
        unc_input = (
            f"Case: UNC-{i + 1:04d}\nEvidence conflict: {case['conflict']}\n"
            f"Host: {host}\nAccount: {user}\nContext: {uncertainty_context}\n"
            f"Evidence gap: {case['missing']}"
        )
        unc_out = (
            f"Assessment for host {host}, account {user}: unresolved. Observed conflict: {case['conflict']}. "
            f"Evidence that could support concern: {case['supporting']}. "
            f"Alternative explanation to test: {case['alternative']}. "
            f"Current evidence gap: {case['missing']}. Operational context: {uncertainty_context}. "
            f"Discriminating check: {case['discriminator']}. Recommended next step: {case['step']}. "
            f"Do not label the case a confirmed true positive or false positive until the relevant records are checked. "
            f"Preserve original logs, note sources and time range, and record both supporting and contradictory evidence."
        )
        add(
            rows,
            "uncertainty_analysis",
            f"uncertainty_{i % len(uncertainty_cases):02d}",
            "State what is known, what remains uncertain, and the evidence needed to resolve it.",
            unc_input,
            unc_out,
            i + 1,
            {
                "uncertainty_scenario": case["conflict"],
                "missing_evidence": case["missing"],
                "targeted_investigation": case["step"],
                "supporting_hypothesis": case["supporting"],
                "alternative_hypothesis": case["alternative"],
                "discriminating_check": case["discriminator"],
            },
        )
    rng.shuffle(rows)
    return rows

def audit_rows(rows, attack):
    errors = []
    exact = set()
    category_counts = Counter()
    outputs = {}
    inputs = {}
    families = {}
    malformed_contexts = []
    bad_mapping_refs = []
    for n, r in enumerate(rows, 1):
        for field in ("instruction","input","output","category","source","scenario_family","scenario_id","verification_status","metadata","generator_version"):
            if field not in r or r[field] in ("", None):
                errors.append(f"row {n}: missing {field}")
        if r.get("category") not in CATEGORIES:
            errors.append(f"row {n}: invalid category {r.get('category')}")
        if len(r.get("input","").split()) < 8:
            errors.append(f"row {n}: input too short")
        if len(r.get("output","").split()) < 20:
            errors.append(f"row {n}: output too short")
        if re.search(r"(?im)\b(context|evidence)\s*[:=]\s*(?:\.|[a-z]\.)\s*$", r.get("input","")):
            malformed_contexts.append(n)
        key = tuple(" ".join(str(r.get(k,"")).lower().split()) for k in ("instruction","input","output"))
        if key in exact:
            errors.append(f"row {n}: duplicate instruction/input/output triple")
        exact.add(key)
        cat = r.get("category","UNKNOWN")
        category_counts[cat] += 1
        outputs.setdefault(cat, Counter())[" ".join(r.get("output","").lower().split())] += 1
        inputs.setdefault(cat, set()).add(" ".join(r.get("input","").lower().split()))
        families.setdefault(cat, set()).add(r.get("scenario_family",""))
        if cat == "mitre_mapping":
            tid = r.get("metadata",{}).get("candidate_technique_id")
            name = r.get("metadata",{}).get("candidate_technique_name")
            ref = attack.get(tid)
            if not ref or ref.get("name") != name:
                bad_mapping_refs.append({"row":n,"id":tid,"name":name})
    per_cat = {}
    for cat in CATEGORIES:
        c = outputs.get(cat, Counter())
        per_cat[cat] = {
            "records": category_counts[cat],
            "unique_inputs": len(inputs.get(cat,set())),
            "unique_outputs": len(c),
            "most_common_output_count": c.most_common(1)[0][1] if c else 0,
            "unique_scenario_families": len(families.get(cat,set())),
        }
    return {
        "status": "STRUCTURAL_AUDIT_ONLY_HUMAN_REVIEW_REQUIRED",
        "record_count": len(rows),
        "expected_record_count": PER_CATEGORY * len(CATEGORIES),
        "category_counts": dict(category_counts),
        "per_category": per_cat,
        "exact_duplicate_triples": len(rows)-len(exact),
        "malformed_context_count": len(malformed_contexts),
        "malformed_context_row_numbers": malformed_contexts,
        "validation_errors": errors,
        "mitre_reference_mismatches": bad_mapping_refs,
        "mitre_mapping_reference_check": "ID/name pairs checked against local reference; behavioral mapping not certified",
        "factual_verification": "NOT VERIFIED; synthetic candidate data requires expert review",
    }

def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    attack = load_attack()
    rows = build_rows(attack)
    report = audit_rows(rows, attack)
    if report["record_count"] != PER_CATEGORY * len(CATEGORIES):
        raise SystemExit(f"Wrong record count: {report['record_count']}")
    if report["validation_errors"] or report["malformed_context_count"] or report["mitre_reference_mismatches"]:
        print(json.dumps(report, indent=2))
        raise SystemExit("Quality gate failed; dataset not written.")
    if any(v["records"] != PER_CATEGORY for v in report["per_category"].values()):
        raise SystemExit("Category balance gate failed; dataset not written.")
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nWrote candidate dataset: {OUT}")
    print(f"Wrote build audit: {REPORT}")
    print("NOTICE: this is synthetic candidate data, not factually verified training data.")

if __name__ == "__main__":
    main()
