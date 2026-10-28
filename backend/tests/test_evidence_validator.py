
from app.services.evidence_validator import EvidenceDecisionValidator


validator = EvidenceDecisionValidator()


def brute_force_rule():
    return {
        "rule_id": "BRUTE_FORCE",
        "name": "Brute Force Authentication",
        "severity": "High",
        "mitre": {
            "techniques": ["T1110"],
            "subtechniques": ["T1110.001"],
        },
    }


def failed_login_alert():
    return {
        "rule_id": "5710",
        "rule_description": "Failed SSH authentication",
        "rule_level": 5,
        "source_ip": "192.168.1.200",
        "source_user": "admin",
        "destination_port": 22,
        "full_log": (
            "Failed password for invalid user admin "
            "from 192.168.1.200 port 22 ssh2"
        ),
        "mitre": {},
    }


def test_unsupported_mitre_technique_is_rejected():
    result = validator.validate(
        failed_login_alert(),
        [brute_force_rule()],
        "The activity maps to MITRE technique T103.",
    )

    assert result["decision"] == "Uncertain"
    assert any(
        "Unsupported MITRE technique" in claim
        for claim in result["unsupported_claims"]
    )


def test_unsubstantiated_repeated_attempts_remain_uncertain():
    result = validator.validate(
        failed_login_alert(),
        [brute_force_rule()],
        "This is a brute-force attack involving repeated failed attempts.",
    )

    assert result["decision"] == "Uncertain"
    assert result["correlation_supported"] is False


def test_multiple_failed_attempts_in_alert_support_brute_force():
    alert = failed_login_alert()
    alert["full_log"] = (
        "5 failed authentication attempts for user admin "
        "from 192.168.1.200"
    )

    result = validator.validate(
        alert,
        [brute_force_rule()],
        "The alert records 5 failed authentication attempts.",
    )

    assert result["decision"] == "True Positive"
    assert result["severity"] == "High"
    assert result["unsupported_claims"] == []


def test_unmatched_rulebook_event_remains_uncertain():
    result = validator.validate(
        failed_login_alert(),
        [],
        "The event requires further investigation.",
    )

    assert result["decision"] == "Uncertain"


def test_severity_uses_rulebook_severity():
    result = validator.validate(
        failed_login_alert(),
        [{
            "rule_id": "MALWARE",
            "severity": "Critical",
            "mitre": {},
        }],
        "The alert requires further investigation.",
    )

    assert result["severity"] == "Critical"


def test_informational_startup_event_is_false_positive():
    alert = {
        "rule_id": "502",
        "rule_description": "Service started",
        "rule_level": 3,
        "full_log": "Service started successfully",
    }

    result = validator.validate(
        alert,
        [],
        "The service started successfully.",
    )

    assert result["decision"] == "False Positive"

def test_correlation_requires_multiple_failed_login_alerts():
    correlation_result = {
        "correlated": True,
        "alert_count": 2,
        "related_alerts": [
            {
                "alert_id": "alert-1",
                "rule_id": "5710",
                "rule_description": "Failed SSH authentication",
                "full_log": (
                    "Failed password for admin from 192.168.1.200"
                ),
            },
            {
                "alert_id": "alert-2",
                "rule_id": "5710",
                "rule_description": "Failed SSH authentication",
                "full_log": (
                    "Failed password for admin from 192.168.1.200"
                ),
            },
        ],
    }

    assert (
        validator._correlation_supports_repeated_attempts(
            correlation_result
        )
        is True
    )
def test_unrelated_alerts_do_not_support_repeated_failed_logins():
    correlation_result = {
        "correlated": True,
        "alert_count": 2,
        "related_alerts": [
            {
                "alert_id": "alert-1",
                "rule_id": "5710",
                "rule_description": "Failed SSH authentication",
                "full_log": "Failed password for admin from 192.168.1.200",
            },
            {
                "alert_id": "alert-2",
                "rule_id": "100001",
                "rule_description": "Application service started",
                "full_log": "Application service started successfully",
            },
        ],
    }

    assert (
        validator._correlation_supports_repeated_attempts(correlation_result)
        is False
    )
