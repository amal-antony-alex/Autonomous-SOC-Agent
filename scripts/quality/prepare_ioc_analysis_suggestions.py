import csv
from pathlib import Path

ROOT = Path.cwd()
SOURCE = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_ioc_analysis_human_review.csv"
)
OUTPUT = ROOT / (
    "data/raw/soc_curated_v3/"
    "v6_4_1_ioc_analysis_review_suggestions.csv"
)

def make_note(row):
    text = " ".join([
        row.get("instruction", ""),
        row.get("input", ""),
        row.get("output", ""),
    ]).lower()

    checks = [
        "Verify the indicator is extracted accurately and its type is identified correctly.",
        "Check the indicator against the supplied evidence and context; do not invent reputation or threat-intelligence results.",
        "Distinguish an indicator match from proof of malicious activity or a confirmed compromise.",
        "Check confidence and uncertainty, including whether the evidence is sufficient for attribution.",
        "Ensure recommended investigation or containment actions are proportionate and authorized.",
    ]

    if any(term in text for term in [
        "ip address", "ipv4", "ipv6", "destination ip", "source ip",
    ]):
        checks.append(
            "For IP indicators, validate source/destination role, time, "
            "network context, and whether the address may be shared or legitimate."
        )

    if any(term in text for term in [
        "domain", "dns", "hostname", "url", "uri",
    ]):
        checks.append(
            "For domain or URL indicators, validate the exact value, "
            "lookalike spelling, resolution or redirect context, and observation time."
        )

    if any(term in text for term in [
        "hash", "sha256", "sha-256", "md5", "sha1", "sha-1",
    ]):
        checks.append(
            "For file hashes, validate the hash type and exact value, "
            "and distinguish a hash match from proof that the file executed."
        )

    if any(term in text for term in [
        "false positive", "benign", "allowlist", "whitelist",
    ]):
        checks.append(
            "Validate benign explanations against asset ownership, business purpose, "
            "and supporting evidence rather than assuming an indicator is safe."
        )

    if any(term in text for term in [
        "threat intelligence", "reputation", "known malicious", "blacklist",
    ]):
        checks.append(
            "Check the source, freshness, and reliability of any reputation claim; "
            "do not imply an external lookup occurred unless evidence is provided."
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
