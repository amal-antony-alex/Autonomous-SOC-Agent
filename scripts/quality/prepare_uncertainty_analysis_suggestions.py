import csv
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_uncertainty_analysis_human_review.csv"
)
OUTPUT = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_uncertainty_analysis_review_suggestions.csv"
)

def make_note(row):
    text = " ".join([
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]).lower()

    checks = [
        "Verify that the response separates directly observed facts from inferences and hypotheses.",
        "Check whether missing evidence and material limitations are explicitly identified.",
        "Confirm that confidence is proportionate to evidence quality, completeness, and consistency.",
        "Check that alternative explanations are considered where the evidence permits them.",
        "Ensure the response does not invent telemetry, threat-intelligence results, or investigation outcomes.",
        "Verify that conclusions avoid unsupported attribution and distinguish suspicion from confirmation.",
        "Check whether the recommended next steps would meaningfully reduce uncertainty and are authorized.",
    ]

    if any(term in text for term in [
        "false positive", "benign", "legitimate activity",
    ]):
        checks.append(
            "Check that uncertainty is not resolved in favor of a benign explanation "
            "without sufficient supporting evidence."
        )

    if any(term in text for term in [
        "malicious", "compromise", "attack", "threat actor",
    ]):
        checks.append(
            "Check whether the evidence supports the maliciousness or compromise claim "
            "and whether competing explanations remain plausible."
        )

    if any(term in text for term in [
        "confidence", "probability", "likely", "unlikely",
    ]):
        checks.append(
            "Verify that confidence language is calibrated and explained; "
            "avoid presenting an unsupported numerical probability as measured fact."
        )

    if any(term in text for term in [
        "missing logs", "no logs", "insufficient logs", "telemetry gap",
    ]):
        checks.append(
            "Confirm that missing telemetry is treated as a visibility limitation, "
            "not as proof that the event did or did not occur."
        )

    if any(term in text for term in [
        "attribution", "threat actor", "apt", "campaign",
    ]):
        checks.append(
            "Require specific corroborating evidence before assigning an actor, "
            "campaign, or source; similarities alone may be insufficient."
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
