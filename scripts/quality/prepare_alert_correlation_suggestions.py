import csv
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_alert_correlation_human_review.csv"
)
OUTPUT = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_alert_correlation_review_suggestions.csv"
)

def make_note(row):
    text = " ".join([
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]).lower()

    checks = [
        "Verify that the proposed relationship between alerts is supported by shared evidence.",
        "Check timestamps, time zones, ordering, and the time window used for correlation.",
        "Validate shared entities such as host, account, process, IP address, or indicator.",
        "Distinguish a plausible hypothesis from a confirmed common incident.",
        "Check whether contradictory evidence, alternative explanations, and uncertainty are acknowledged.",
        "Verify that the incident scope and recommended response are proportionate to the evidence.",
    ]

    if any(term in text for term in [
        "same host", "endpoint", "hostname", "device",
    ]):
        checks.append(
            "Confirm asset identity and whether the events occurred on the same "
            "asset during the relevant time period."
        )

    if any(term in text for term in [
        "user", "account", "login", "authentication",
    ]):
        checks.append(
            "Validate account identity, authentication outcomes, and session context; "
            "a shared username alone may not prove a common attack."
        )

    if any(term in text for term in [
        "process", "parent process", "process tree", "command line",
    ]):
        checks.append(
            "Check process identifiers, parent-child relationships, execution times, "
            "and host context before inferring a causal sequence."
        )

    if any(term in text for term in [
        "ip address", "source ip", "destination ip", "network connection",
    ]):
        checks.append(
            "Validate source and destination roles and network context; "
            "a shared or NAT-translated IP may not uniquely identify an actor."
        )

    if any(term in text for term in [
        "attack chain", "lateral movement", "mitre", "technique",
    ]):
        checks.append(
            "Ensure the proposed attack sequence and technique mapping are "
            "supported by the observed behavior rather than inferred from alert names alone."
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
