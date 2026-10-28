#!/usr/bin/env python3
"""Build 4,000 SOC training candidates with controlled variation and explicit review status.

Run from the repository root:
  python ai/tiny_llm/training/build_soc_training_v4.py

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
OUT = ROOT / "soc_training_v4.jsonl"
REPORT = ROOT / "soc_training_v4_build_report.json"
ATTACK = Path("data/processed/mitre_attack/mitre_techniques.jsonl")
SEED = 20261017
PER_CATEGORY = 500
VERSION = "soc-training-v4.0"
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
        "source": "synthetic_scenario_candidate_v4",
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
                       f"Context: {ctx}\nOutcome: {outcome}\nExisting severity label: {severity_hint}")
        alert_out = (f"Observed: {behavior}. The event is associated with {host} and account {user} at {time}; "
                     f"source {src} and destination {dest} are recorded. Context: {ctx}. "
                     f"Outcome: {outcome}. Do not treat the existing severity label as proof of maliciousness. "
                     f"Next step: {action}.")
        add(rows, "alert_analysis", f"alert_{i%24:02d}", "Assess the alert using only the supplied evidence; separate facts from hypotheses.",
            alert_input, alert_out, i+1)

        # IOC analysis
        itype, label, value_fn = IOC_TYPES[(i * 5 + i // 6) % len(IOC_TYPES)]
        value = value_fn(i)
        verdict = ["unavailable", "not checked", "conflicting", "no verdict supplied"][(i // 3) % 4]
        ioc_input = f"Case: IOC-{case}\nHost: {host}\nIndicator type: {label}\nIndicator: {value}\nSource context: {ctx}\nThreat-intelligence verdict: {verdict}"
        ioc_out = (f"Record {label.lower()} `{value}` as an observed indicator associated with {host}. "
                   f"The supplied intelligence status is '{verdict}', so a malicious verdict is not established. "
                   f"Context note: {ctx}. Recommended validation: {action}. Correlate the indicator with time-bounded "
                   f"endpoint, DNS, authentication, or network telemetry appropriate to its type.")
        add(rows, "ioc_analysis", f"ioc_{itype}", "Extract the indicator exactly and explain what its current evidence does and does not establish.",
            ioc_input, ioc_out, i+1, {"indicator_type": itype})

        # Alert correlation
        t1 = TIMES[(i * 2) % len(TIMES)]
        t2 = TIMES[(i * 2 + 1) % len(TIMES)]
        relation = [
            "same host and account",
            "same source address but different destination hosts",
            "same process identifier and overlapping timestamps",
            "same hostname but no shared user or process identifier",
            "same account with a successful login after failures",
            "DNS query followed by a connection to the resolved address",
            "endpoint prevention and firewall allow records near the same time",
            "similar alerts on separate hosts with a shared source account",
        ][i % 8]
        corr_input = (f"Case: COR-{case}\nEvent A: time={t1}; host={host}; user={user}; source={src}; type={['login failure','process start','DNS query','firewall event'][i%4]}\n"
                      f"Event B: time={t2}; host={HOSTS[(i+3)%len(HOSTS)] if i%4==3 else host}; user={user if i%3 else USERS[(i+2)%len(USERS)]}; source={src}; type={['login success','outbound connection','endpoint prevention','privilege change'][i%4]}\n"
                      f"Potential relationship: {relation}\nMissing/contextual evidence: {ctx}")
        corr_out = (f"The records may be related through {relation}, but that relationship is a hypothesis until identifiers and timestamps are aligned. "
                    f"Event times are {t1} and {t2}; verify time zone and clock skew. Context: {ctx}. "
                    f"Do not merge the events solely because one field matches. Next, {action}, then document whether a shared session, process, "
                    f"connection tuple, or defensible timeline supports correlation.")
        add(rows, "alert_correlation", f"correlation_{i%32:02d}", "Correlate the supplied events, state the strongest supported relationship, and identify limits.",
            corr_input, corr_out, i+1)

        # False positive assessment
        ben = BENIGN[(i * 3 + i // 4) % len(BENIGN)]
        fp_state = ["matching authorization", "authorization absent", "ticket present but scope differs", "source is allowlisted but behavior is unusual", "test is authorized but time window is unclear"][(i // 2) % 5]
        fp_input = f"Case: FP-{case}\nHost: {host}\nAccount: {user}\nActivity: {ben}\nAuthorization state: {fp_state}\nAdditional context: {ctx}\nUnexpected follow-on behavior: {['none observed in collected window','present','not collected'][i%3]}"
        if fp_state == "matching authorization" and i % 3 == 0:
            fp_conclusion = "The evidence supports a benign explanation, but closure still requires confirming the activity matches the approved scope."
        elif fp_state == "authorization absent" or fp_state == "ticket present but scope differs":
            fp_conclusion = "Do not close as a false positive yet; the authorization gap or scope mismatch remains unresolved."
        else:
            fp_conclusion = "The benign explanation is plausible but incomplete; allowlisting or expected timing alone is insufficient to suppress the alert."
        fp_out = f"Assessment: {fp_conclusion} The stated activity is: {ben}. Authorization state: {fp_state}. Context: {ctx}. Follow-on behavior: {['none observed in collected window','present','not collected'][i%3]}. Verify the actor, exact command or process, target, time window, and {action} before disposition."
        add(rows, "false_positive_assessment", f"fp_{i%25:02d}", "Assess whether the supplied evidence supports closing the alert as a false positive.",
            fp_input, fp_out, i+1)

        # Severity classification
        sev, sev_evidence = IMPACTS[(i * 5 + i // 8) % len(IMPACTS)]
        asset = ["user workstation", "application server", "identity server", "database server", "critical production service"][(i // 3) % 5]
        confidence = ["low", "moderate", "high"][(i // 2) % 3]
        sev_input = f"Case: SEV-{case}\nAsset class: {asset}\nEvidence: {sev_evidence}\nAnalyst confidence: {confidence}\nAdditional context: {ctx}\nPolicy: local severity matrix governs final assignment"
        sev_out = f"Preliminary severity: {sev}. Rationale: {sev_evidence}. Asset class: {asset}; analyst confidence: {confidence}. Context: {ctx}. This is a provisional assessment, not a substitute for the organization's severity matrix. Reassess if impact, scope, or confidence changes; next step: {action}."
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
        mapping_action = ACTIONS[(i // (len(MAPPING_BANK) * 12)) % len(ACTIONS)]
        map_input = f"Case: ATTACK-{case}\\nObserved behavior: {behavior_desc}\\nEvidence quality: {evidence_quality}\\nContext: {map_context}\\nAnalyst follow-up available: {mapping_action}"
        map_out = f"Candidate mapping: {tid} — {local['name']}. Reasoning: {mapping_reason} Evidence quality: {evidence_quality}. Observed behavior: {behavior_desc}. Context: {map_context}. Next validation step: {mapping_action}. The local reference confirms that the ID and name match; it does not independently validate the behavioral mapping. Human review required."
        add(rows, "mitre_mapping", f"mitre_{tid}", "Suggest an ATT&CK mapping only where supported and distinguish reference validation from behavioral confidence.",
            map_input, map_out, i+1, {"candidate_technique_id": tid, "candidate_technique_name": local["name"], "reference_id_name_match": True})

        # Incident summary
        incident_type = ["authentication anomaly", "possible malware execution", "unusual outbound transfer", "privileged group change", "web request anomaly", "DNS anomaly", "remote service access", "endpoint prevention"][i%8]
        count = 1 + (i*7)%67
        duration = 1 + (i*11)%90
        impact = ["impact not assessed", "one host affected in current telemetry", "host isolated by response tooling", "scope may include additional assets"][i%4]
        inc_input = f"Case: INC-{case}\nType: {incident_type}\nHost: {host}\nAccount: {user}\nSource: {src}\nObserved events: {count} within {duration} minutes\nOutcome: {outcome}\nImpact: {impact}\nOpen question: {ctx}"
        inc_out = (f"Summary: {count} {incident_type} event(s) were recorded for {host} over {duration} minute(s), associated with account {user} and source {src}. "
                   f"Reported outcome: {outcome}. Current impact statement: {impact}. The available record does not resolve: {ctx}. "
                   f"Next investigation step: {action}. Do not state confirmed compromise or exfiltration unless corroborating evidence supports it.")
        add(rows, "incident_summary", f"incident_{incident_type.replace(' ','_')}", "Write a concise incident summary separating observed facts, impact, and unresolved questions.",
            inc_input, inc_out, i+1)

        # Uncertainty analysis
        conflict = [
            "endpoint reports prevention while a network log records an allowed connection",
            "one intelligence source flags the domain while another has no detections",
            "user denies the activity while a valid session is recorded",
            "the alert is high confidence but the process tree is missing",
            "a change ticket exists but its target or timing differs from the event",
            "two records share a username but not a session identifier",
            "the event says success while the downstream action is not logged",
            "timestamps are close but systems may use different time zones",
        ][i%8]
        missing = ["process ancestry", "session identifier", "destination reputation", "change approval", "data access audit", "full command line", "host isolation result", "source ownership"][(i*3)%8]
        unc_input = f"Case: UNC-{case}\nEvidence conflict: {conflict}\nMissing evidence: {missing}\nHost: {host}\nAccount: {user}\nContext: {ctx}"
        unc_out = (f"Conclusion: unresolved. The conflict is: {conflict}. The missing {missing} prevents a confident determination of the event's meaning. "
                   f"Context: {ctx}. Do not force a true-positive or false-positive verdict yet. Obtain {missing}, then {action}. "
                   f"Record what evidence would support each competing explanation and preserve the original logs.")
        add(rows, "uncertainty_analysis", f"uncertainty_{i%28:02d}", "State what is known, what remains uncertain, and the evidence needed to resolve it.",
            unc_input, unc_out, i+1)

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
