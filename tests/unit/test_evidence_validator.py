
import pytest

from backend.app.services.evidence_validator import (
    EvidenceDecisionValidator,
)


@pytest.fixture
def validator():
    return EvidenceDecisionValidator()


@pytest.fixture
def single_failed_login():
    return {
        "rule_id": "5710",
        "rule_level": 5,
        "rule_description": (
            "sshd: Attempt to login using a non-existent user"
        ),
        "source_ip": "198.51.100.26",
        "source_user": "socagent_test",
        "full_log": (
            "Failed password for invalid user socagent_test "
            "from 198.51.100.26 port 48222 ssh2"
        ),
    }


@pytest.fixture
def brute_force_match():
    return [
        {
            "rule_id": "BRUTE_FORCE",
            "name": "Brute Force Authentication",
            "severity": "High",
        }
    ]


def test_single_failed_login_is_uncertain(
    validator, single_failed_login, brute_force_match
):
    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "One failed login was observed.",
        correlation_result={"correlated": False, "alert_count": 1},
    )

    assert result["decision"] == "Uncertain"
    assert result["severity"] == "High"


def test_correlated_repeated_failures_can_be_true_positive(
    validator, single_failed_login, brute_force_match
):
    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "Repeated failed attempts were observed.",
        correlation_result={"correlated": True, "alert_count": 3},
    )

    assert result["decision"] == "True Positive"
    assert result["correlation_supported"] is True


def test_unsupported_repeated_attempt_claim_is_uncertain(
    validator, single_failed_login, brute_force_match
):
    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "The source made repeated attempts.",
        correlation_result={"correlated": False, "alert_count": 1},
    )

    assert result["decision"] == "Uncertain"
    assert result["evidence_grounded"] is False
    assert result["unsupported_claims"]


def test_negated_claim_is_not_flagged_as_affirmed(
    validator, single_failed_login, brute_force_match
):
    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "Repeated attempts are not supported by the available evidence.",
        correlation_result={"correlated": False, "alert_count": 1},
    )

    assert not any(
        "repeated attempts" in claim
        for claim in result["unsupported_claims"]
    )


@pytest.mark.parametrize(
    ("rule_level", "expected"),
    [
        (12, "Critical"),
        (7, "High"),
        (4, "Medium"),
        (2, "Low"),
    ],
)
def test_severity_fallback(
    validator, rule_level, expected
):
    result = validator.validate(
        alert={
            "rule_id": "9999",
            "rule_level": rule_level,
            "rule_description": "Unclassified event",
            "full_log": "Test event",
        },
        rulebook_matches=[],
        qwen_analysis="No conclusions can be confirmed.",
    )

    assert result["severity"] == expected


def test_unsupported_compromise_claim_is_detected(
    validator, single_failed_login, brute_force_match
):
    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "The account was compromised.",
        correlation_result={"correlated": False, "alert_count": 1},
    )

    assert result["decision"] == "Uncertain"
    assert result["evidence_grounded"] is False
    assert any(
        "compromised" in claim
        for claim in result["unsupported_claims"]
    )


def test_unmatched_alert_is_uncertain(validator):
    result = validator.validate(
        alert={
            "rule_id": "9999",
            "rule_level": 2,
            "rule_description": "Unknown event",
            "full_log": "Unclassified test event",
        },
        rulebook_matches=[],
        qwen_analysis="Insufficient evidence to classify this event.",
    )

    assert result["decision"] == "Uncertain"


def test_no_evidence_does_not_produce_true_positive(validator):
    result = validator.validate(
        alert={},
        rulebook_matches=[
            {
                "rule_id": "BRUTE_FORCE",
                "severity": "High",
            }
        ],
        qwen_analysis="Repeated failed attempts were observed.",
        correlation_result={"correlated": True, "alert_count": 3},
    )

    assert result["decision"] == "Uncertain"
