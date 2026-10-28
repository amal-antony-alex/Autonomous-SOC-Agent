import csv
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = Path.cwd()
SOURCE = ROOT / "data/raw/soc_curated_v3/soc_training_v4_revision_v6_4_1.jsonl"
REVIEW_DIR = ROOT / "data/reviewed_v6_4_1/reviewed_csvs"
REPORT_DIR = ROOT / "data/reviewed_v6_4_1/reports"
OUTPUT_DIR = ROOT / "data/processed/soc_curated_v3"

COMBINED = REVIEW_DIR / "v6_4_1_all_record_ai_review_decisions.csv"
SEVERITY = REVIEW_DIR / "v6_4_1_severity_ai_assessed.csv"
CORRECTIONS = REVIEW_DIR / "v6_4_1_corrections_required.csv"
PENDING = REVIEW_DIR / "v6_4_1_records_remaining_pending.csv"

OUTPUT = OUTPUT_DIR / "soc_training_v4_revision_v6_4_1_reviewed.jsonl"
MAPPING_REPORT = REPORT_DIR / "v6_4_1_consolidation_mapping.csv"
AUDIT_REPORT = REPORT_DIR / "v6_4_1_consolidation_audit.json"

def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def read_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSON at {path}, line {line_number}: {exc}"
                )
            if not isinstance(row, dict):
                raise RuntimeError(f"Non-object JSON at line {line_number}")
            rows.append(row)
    return rows

def nonblank(value):
    return str(value or "").strip()

# Refuse to overwrite previous outputs.
for path in (OUTPUT, MAPPING_REPORT, AUDIT_REPORT):
    if path.exists():
        raise SystemExit(
            f"STOP: output already exists: {path}\n"
            "Move it aside or choose a new versioned output name before rerunning."
        )

required = [SOURCE, COMBINED, SEVERITY, CORRECTIONS, PENDING]
missing = [str(p) for p in required if not p.is_file()]
if missing:
    raise SystemExit("Missing required files:\n" + "\n".join(missing))

source_rows = read_jsonl(SOURCE)
review_rows = read_csv(COMBINED)
severity_rows = read_csv(SEVERITY)
correction_rows = read_csv(CORRECTIONS)
pending_rows = read_csv(PENDING)

source_by_id = {}
source_by_content = defaultdict(list)

for row in source_rows:
    sid = nonblank(row.get("scenario_id"))
    if not sid:
        raise SystemExit("STOP: source contains a blank scenario_id.")
    if sid in source_by_id:
        raise SystemExit(f"STOP: duplicate source scenario_id: {sid}")
    source_by_id[sid] = row
    source_by_content[
        (nonblank(row.get("category")), nonblank(row.get("input")))
    ].append(row)

severity_by_id = {}
for row in severity_rows:
    sid = nonblank(row.get("scenario_id"))
    if not sid or sid in severity_by_id:
        raise SystemExit(
            f"STOP: blank or duplicate severity scenario_id: {sid!r}"
        )
    severity_by_id[sid] = row

if len(source_rows) != 4000:
    raise SystemExit(f"STOP: expected 4000 source records, got {len(source_rows)}")
if len(review_rows) != 4000:
    raise SystemExit(f"STOP: expected 4000 combined review rows, got {len(review_rows)}")
if len(severity_by_id) != 500:
    raise SystemExit(f"STOP: expected 500 severity assessments, got {len(severity_by_id)}")

# Index all combined reviews, mapping nonstandard MITRE keys only when
# category + input uniquely identifies a source record.
review_by_id = {}
mapping_rows = []
mapping_methods = Counter()

for review in review_rows:
    key = nonblank(review.get("record_key"))
    category = nonblank(review.get("category"))
    input_text = nonblank(review.get("input"))

    if key in source_by_id:
        sid = key
        method = "exact_scenario_id"
        source = source_by_id[sid]

        if nonblank(source.get("category")) != category:
            raise SystemExit(
                f"STOP: category mismatch for exact ID {sid}: "
                f"{source.get('category')} vs {category}"
            )
    elif category == "mitre_mapping":
        matches = source_by_content.get((category, input_text), [])
        if len(matches) != 1:
            raise SystemExit(
                f"STOP: MITRE key {key} has {len(matches)} exact "
                "category+input matches; cannot map safely."
            )
        source = matches[0]
        sid = nonblank(source.get("scenario_id"))
        method = "unique_category_input_match"
    elif category == "severity_classification":
        # The supplied combined row is a blank placeholder. The recovered,
        # assessed severity worksheet is the authoritative review artifact.
        # It is merged below by its actual scenario_id.
        mapping_rows.append({
            "review_record_key": key,
            "scenario_id": "",
            "category": category,
            "mapping_method": "replaced_by_recovered_severity_assessment",
            "status": "placeholder_not_used",
        })
        continue
    else:
        raise SystemExit(
            f"STOP: cannot map review key {key!r}, category={category!r}"
        )

    if sid in review_by_id:
        raise SystemExit(f"STOP: multiple combined review rows map to {sid}")

    review_by_id[sid] = review
    mapping_methods[method] += 1
    mapping_rows.append({
        "review_record_key": key,
        "scenario_id": sid,
        "category": category,
        "mapping_method": method,
        "status": "mapped",
    })

# Require all non-severity reviews to map to their original source record.
nonseverity_ids = {
    sid for sid, row in source_by_id.items()
    if nonblank(row.get("category")) != "severity_classification"
}
mapped_nonseverity = nonseverity_ids.intersection(review_by_id)

if mapped_nonseverity != nonseverity_ids:
    missing_ids = sorted(nonseverity_ids - mapped_nonseverity)
    raise SystemExit(
        f"STOP: {len(missing_ids)} non-severity source records are unmapped. "
        f"Examples: {missing_ids[:10]}"
    )

# Every severity source ID must have one recovered assessment with matching
# source category, input and output. Never rely on row order.
severity_source_ids = {
    sid for sid, row in source_by_id.items()
    if nonblank(row.get("category")) == "severity_classification"
}

if set(severity_by_id) != severity_source_ids:
    missing_ids = sorted(severity_source_ids - set(severity_by_id))
    extra_ids = sorted(set(severity_by_id) - severity_source_ids)
    raise SystemExit(
        "STOP: severity IDs do not match the original severity category. "
        f"Missing={missing_ids[:10]}, extra={extra_ids[:10]}"
    )

for sid, assessment in severity_by_id.items():
    source = source_by_id[sid]
    for field in ("category", "input", "output"):
        if nonblank(assessment.get(field)) != nonblank(source.get(field)):
            raise SystemExit(
                f"STOP: severity {field} mismatch for {sid}; "
                "source and assessment are not identical."
            )

# Create a fresh dataset from the immutable original rows, adding review
# metadata. The original input/output are never replaced by suggestions.
consolidated = []
for source in source_rows:
    sid = nonblank(source["scenario_id"])
    category = nonblank(source.get("category"))

    result = dict(source)
    result["review_record_key"] = ""
    result["reviewer_type"] = "AI_ASSISTED"
    result["reviewer_decision"] = "PENDING"
    result["behavior_supported"] = "NOT_ASSESSED"
    result["reviewer_notes"] = ""
    result["suggested_correction"] = ""
    result["reference_url"] = ""
    result["review_mapping_method"] = ""
    result["assigned_severity"] = ""
    result["proposed_severity"] = ""
    result["impact_assessment"] = ""
    result["scope_assessment"] = ""
    result["confidence_assessment"] = ""
    result["urgency_assessment"] = ""
    result["review_method"] = ""

    if category == "severity_classification":
        review = severity_by_id[sid]
        method = "recovered_severity_scenario_id"

        result["review_record_key"] = sid
        for field in (
            "reviewer_decision", "behavior_supported", "reviewer_notes",
            "assigned_severity", "proposed_severity", "impact_assessment",
            "scope_assessment", "confidence_assessment", "urgency_assessment",
            "review_method",
        ):
            if field in review:
                result[field] = review[field]
    else:
        review = review_by_id[sid]
        method = (
            "unique_category_input_match"
            if nonblank(review.get("record_key")) != sid
            else "exact_scenario_id"
        )

        result["review_record_key"] = nonblank(review.get("record_key"))
        for field in (
            "reviewer_type", "reviewer_decision", "behavior_supported",
            "reviewer_notes", "suggested_correction", "reference_url",
        ):
            if field in review and nonblank(review.get(field)):
                result[field] = review[field]

    result["review_mapping_method"] = method
    consolidated.append(result)

# Verify complete one-to-one coverage and preserved original content.
output_ids = [nonblank(r.get("scenario_id")) for r in consolidated]
if len(consolidated) != 4000 or len(set(output_ids)) != 4000:
    raise SystemExit("STOP: consolidated output does not have 4000 unique IDs.")

for original, merged in zip(source_rows, consolidated):
    for field in ("scenario_id", "category", "input", "output"):
        if original.get(field) != merged.get(field):
            raise SystemExit(
                f"STOP: original source field changed: "
                f"{original.get('scenario_id')} / {field}"
            )

decisions = Counter(nonblank(r.get("reviewer_decision")) for r in consolidated)
categories = Counter(nonblank(r.get("category")) for r in consolidated)
methods = Counter(nonblank(r.get("review_mapping_method")) for r in consolidated)

# Record corrections and pending items as audit references, not applied edits.
correction_ids = [
    nonblank(r.get("record_key")) for r in correction_rows
]
pending_ids = [
    nonblank(r.get("record_key")) for r in pending_rows
]

# Write only after all pre-write validations pass.
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("x", encoding="utf-8") as f:
    for row in consolidated:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

with MAPPING_REPORT.open("x", encoding="utf-8", newline="") as f:
    fields = ["review_record_key", "scenario_id", "category",
              "mapping_method", "status"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(mapping_rows)

audit = {
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "source_file": str(SOURCE.relative_to(ROOT)),
    "output_file": str(OUTPUT.relative_to(ROOT)),
    "source_records": len(source_rows),
    "consolidated_records": len(consolidated),
    "unique_scenario_ids": len(set(output_ids)),
    "source_content_preserved": True,
    "original_jsonl_modified": False,
    "decision_counts": dict(decisions),
    "category_counts": dict(categories),
    "mapping_method_counts": dict(methods),
    "nonseverity_review_mappings": dict(mapping_methods),
    "severity_assessments_mapped_by_scenario_id": len(severity_by_id),
    "correction_suggestion_rows_preserved_separately": len(correction_rows),
    "pending_review_rows_in_original_combined_file": len(pending_rows),
    "correction_record_keys": correction_ids,
    "pending_record_keys": pending_ids,
    "limitations": [
        "AI-assisted decisions are not independent human validation.",
        "Suggested corrections were not applied to original outputs.",
        "Severity assessments are preliminary and depend on the evidence supplied.",
        "Unmatched generic severity placeholder rows were not used as evidence.",
    ],
}
with AUDIT_REPORT.open("x", encoding="utf-8") as f:
    json.dump(audit, f, indent=2, ensure_ascii=False)

print("CONSOLIDATION SUCCESSFUL")
print("Output:", OUTPUT)
print("Mapping report:", MAPPING_REPORT)
print("Audit report:", AUDIT_REPORT)
print("Records:", len(consolidated))
print("Unique scenario IDs:", len(set(output_ids)))
print("Decision counts:", dict(decisions))
print("Mapping methods:", dict(methods))
print("Original JSONL modified: No")
print("Suggested corrections applied: No")
