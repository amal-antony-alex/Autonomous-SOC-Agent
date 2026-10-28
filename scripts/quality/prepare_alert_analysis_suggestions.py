import csv
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_alert_analysis_human_review.csv"
)
OUTPUT = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_alert_analysis_review_suggestions.csv"
)

def make_note(row):
    text = " ".join([
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]).lower()

    checks = [
        "Validate that the conclusion is supported by the supplied alert evidence.",
        "Check whether the response distinguishes observed facts from assumptions.",
        "Verify that the stated severity and impact are justified by the evidence.",
        "Check whether relevant context, affected assets, and uncertainty are handled accurately.",
        "Ensure the recommended investigation steps are proportionate and authorized.",
    ]

    if any(term in text for term in [
        "failed login", "authentication failure", "login failure",
        "brute force", "password spray",
    ]):
        checks.append(
            "Authentication failures alone do not prove a successful compromise; "
            "check counts, source, target account, time window, and any successful logins."
        )

    if any(term in text for term in [
        "powershell", "cmd.exe", "command line", "process execution",
    ]):
        checks.append(
            "Validate the exact command line, process ancestry, user, host, "
            "and surrounding activity before inferring malicious execution."
        )

    if any(term in text for term in [
        "malware", "ransomware", "payload", "trojan",
    ]):
        checks.append(
            "Confirm what evidence identifies malware; do not infer infection "
            "from a filename or an alert label alone."
        )

    if any(term in text for term in [
        "lateral movement", "remote service", "smb", "ssh", "rdp",
    ]):
        checks.append(
            "A remote connection alone does not establish malicious lateral movement; "
            "validate account, source, destination, authorization, and session activity."
        )

    return " ".join(checks)

if not SOURCE.is_file():
    raise FileNotFoundError(f"Missing worksheet: {SOURCE}")

with SOURCE.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

if len(rows) != 500:
    raise ValueError(f"Expected 500 rows, found {len(rows)}")

required = {"scenario_id", "category", "input", "output"}
if rows and not required.issubset(rows[0]):
    raise ValueError(
        f"Worksheet missing required columns: {required - set(rows[0])}"
    )

fields = list(rows[0].keys())
if "behavior_supported" not in fields:
    fields.append("behavior_supported")
if "review_notes" not in fields:
    fields.append("review_notes")

for row in rows:
    # Suggestions only. A human must make the final determination.
    row["behavior_supported"] = "PENDING_HUMAN_ASSESSMENT"
    row["review_notes"] = make_note(row)

with OUTPUT.open("w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)

with OUTPUT.open("r", encoding="utf-8-sig", newline="") as f:
    verified = list(csv.DictReader(f))

if len(verified) != 500:
    raise RuntimeError(f"Output verification failed: {len(verified)} rows")

print(f"Input rows: {len(rows)}")
print(f"Output rows verified: {len(verified)}")
print(f"Output: {OUTPUT}")
print("All records remain pending human assessment.")
print("Source worksheet and original dataset were not modified.")
print("\nSample review note:")
print(verified[0]["review_notes"])
