import csv
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_incident_summary_human_review.csv"
)
OUTPUT = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_incident_summary_review_suggestions.csv"
)

def make_note(row):
    text = " ".join([
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]).lower()

    checks = [
        "Verify that the summary is faithful to the supplied evidence and does not introduce unsupported facts.",
        "Check that observed events, analyst interpretations, and unconfirmed hypotheses are clearly distinguished.",
        "Validate the timeline, event ordering, timestamps, and time zones where supplied.",
        "Check affected assets, identities, indicators, and incident scope against the source evidence.",
        "Ensure severity, impact, and confidence are justified rather than assumed.",
        "Confirm that response actions are described accurately and are not presented as completed unless the evidence says so.",
        "Identify material gaps, conflicting evidence, and outstanding investigation questions.",
    ]

    if any(term in text for term in [
        "data exfiltration", "exfiltration", "data theft", "data loss",
    ]):
        checks.append(
            "Do not claim successful data exfiltration without evidence of transfer, "
            "destination, and relevant volume or content where available."
        )

    if any(term in text for term in [
        "ransomware", "encryption", "encrypted files",
    ]):
        checks.append(
            "Distinguish observed file changes or encryption alerts from confirmed "
            "ransomware impact; validate affected systems and recovery evidence."
        )

    if any(term in text for term in [
        "credential", "password", "lsass", "token theft",
    ]):
        checks.append(
            "Separate suspected credential access from confirmed credential exposure "
            "or misuse, and identify the evidence supporting each claim."
        )

    if any(term in text for term in [
        "containment", "isolated", "blocked", "quarantined",
    ]):
        checks.append(
            "Verify the action, target, and outcome; do not equate a recommendation "
            "or attempted action with successful containment."
        )

    if any(term in text for term in [
        "mitre", "attack technique", "tactic",
    ]):
        checks.append(
            "Check that any MITRE ATT&CK mapping reflects the observed behavior "
            "and does not imply a technique solely from an alert label."
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
    raise ValueError(f"Missing columns: {required - set(rows[0])}")

fields = list(rows[0].keys())
for field in ["behavior_supported", "review_notes"]:
    if field not in fields:
        fields.append(field)

for row in rows:
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
