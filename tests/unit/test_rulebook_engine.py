
import pytest

from backend.app.services.rulebook_engine import rulebook_engine


@pytest.mark.parametrize(
    ("rule_id", "description", "full_log", "expected_rule"),
    [
        (
            "5710",
            "Failed password for invalid user",
            "Failed password for invalid user admin from 198.51.100.25",
            "BRUTE_FORCE",
        ),
        (
            "9001",
            "Malware detected",
            "A ransomware sample was detected on the endpoint",
            "MALWARE",
        ),
        (
            "9002",
            "PowerShell activity",
            "powershell -EncodedCommand SQBFAFgA",
            "SUSPICIOUS_POWERSHELL",
        ),
        (
            "9003",
            "Network reconnaissance",
            "Nmap scan detected across multiple destination ports",
            "PORT_SCANNING",
        ),
        (
            "9004",
            "Directory authentication",
            "Kerberos authentication request for a domain account",
            "ACTIVE_DIRECTORY",
        ),
    ],
)
def test_expected_rule_matches(
    rule_id, description, full_log, expected_rule
):
    alert = {
        "rule": {
            "id": rule_id,
            "level": 7,
            "description": description,
        },
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "198.51.100.25"},
        "full_log": full_log,
    }

    matches = rulebook_engine.evaluate(alert)
    matched_ids = {match["rule_id"] for match in matches}

    assert expected_rule in matched_ids


def test_unrelated_alert_does_not_match_rules():
    alert = {
        "rule": {
            "id": "9999",
            "level": 2,
            "description": "Routine system status",
        },
        "agent": {"id": "001", "name": "test-host"},
        "data": {},
        "full_log": "Routine CPU utilization report: 23 percent",
    }

    matches = rulebook_engine.evaluate(alert)

    assert matches == []


def test_matches_include_severity_and_mitre():
    alert = {
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "Failed password",
        },
        "agent": {"id": "001", "name": "test-host"},
        "data": {"srcip": "198.51.100.25"},
        "full_log": "Failed password for invalid user test",
    }

    matches = rulebook_engine.evaluate(alert)
    brute_force = next(
        match for match in matches
        if match["rule_id"] == "BRUTE_FORCE"
    )

    assert brute_force["severity"] == "High"
    assert "T1110" in brute_force["mitre"]["techniques"]
