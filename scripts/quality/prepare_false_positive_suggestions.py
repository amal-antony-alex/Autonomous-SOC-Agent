import csv
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_false_positive_assessment_human_review.csv"
)
OUTPUT = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_false_positive_assessment_review_suggestions.csv"
)

def make_note(row):
    text = " ".join([
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]).lower()

    checks = [
        "Verify that the benign or false-positive conclusion is supported by evidence.",
        "Distinguish a false positive from a true detection of activity that is authorized or benign.",
        "Check asset ownership, account identity, expected behavior, and business context where available.",
        "Validate the detection rule, triggering fields, thresholds, and relevant event details.",
        "Check for contradictory evidence and avoid treating missing evidence as proof of benign activity.",
        "Ensure the confidence level and recommended disposition reflect the available evidence.",
    ]

    if any(term in text for term in [
        "administrator", "admin", "authorized", "legitimate", "maintenance",
    ]):
        checks.append(
            "Privileged or maintenance activity is not automatically benign; "
            "verify authorization, timing, account, target, and expected actions."
        )

    if any(term in text for term in [
        "allowlist", "whitelist", "exception", "suppression",
    ]):
        checks.append(
            "Check that any allowlist or suppression is narrowly scoped, justified, "
            "approved, and does not hide unrelated malicious activity."
        )

    if any(term in text for term in [
        "antivirus", "edr", "malware", "quarantine",
    ]):
        checks.append(
            "Validate the detection evidence and endpoint response; "
            "a blocked or quarantined item does not by itself establish the full incident outcome."
        )

    if any(term in text for term in [
        "failed login", "authentication", "brute force", "password spray",
    ]):
        checks.append(
            "Check authentication patterns, source, target accounts, time window, "
            "and successful logins before classifying the activity as benign."
        )

    if any(term in text for term in [
        "scanner", "vulnerability scan", "penetration test", "pentest",
    ]):
        checks.append(
            "Verify the testing scope, authorization, source, and scheduled window "
            "before treating scanning or exploitation-like activity as expected."
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
