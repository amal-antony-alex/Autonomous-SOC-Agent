
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
    correlation_result = {
        "correlated": True,
        "alert_count": 3,
        "window_minutes": 10,
        "related_alerts": [
            {
                "alert_id": "1001",
                "rule_id": "5710",
                "rule_description": "Failed password for invalid user",
            },
            {
                "alert_id": "1002",
                "rule_id": "5710",
                "rule_description": "Failed password for invalid user",
            },
            {
                "alert_id": "1003",
                "rule_id": "502",
                "rule_description": "Wazuh manager started",
            },
        ],
    }

    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "Repeated failed attempts were observed.",
        correlation_result=correlation_result,
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

def test_mixed_claims_preserve_affirmative_repeated_attempts():
    text = (
        "Repeated attempts were observed, "
        "but compromise was not confirmed."
    )

    assert EvidenceDecisionValidator._phrase_is_affirmed(
        text, "repeated attempts"
    ) is True


def test_repeated_attempts_negated_after_no():
    text = (
        "No. The correlation evidence shows 0 related alerts. "
        "No multiple/repeated attempts."
    )

    assert EvidenceDecisionValidator._phrase_is_affirmed(
        text, "repeated attempts"
    ) is False

def test_repeated_attempts_heading_does_not_override_negation():
    text = (
        "5. **Multiple/Repeated Attempts**:\n"
        "   - No correlation to repeated attempts "
        "(alert count 0)."
    )

    assert EvidenceDecisionValidator._phrase_is_affirmed(
        text, "repeated attempts"
    ) is False

def test_unrelated_negation_does_not_hide_activity_claim():
    text = (
        "PowerShell activity was detected, "
        "but compromise was not confirmed."
    )

    assert EvidenceDecisionValidator._phrase_is_affirmed(
        text, "powershell"
    ) is True

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

def test_unrelated_correlated_alerts_do_not_confirm_brute_force(
    validator, single_failed_login, brute_force_match
):
    correlation_result = {
        "correlated": True,
        "alert_count": 3,
        "window_minutes": 10,
        "related_alerts": [
            {
                "alert_id": "1001",
                "rule_id": "5710",
                "rule_description": "Failed password for user",
                "source_user": "socagent_test",
            },
            {
                "alert_id": "1002",
                "rule_id": "502",
                "rule_description": "Wazuh manager started",
                "source_user": None,
            },
            {
                "alert_id": "1003",
                "rule_id": "9003",
                "rule_description": "Network reconnaissance",
                "source_user": None,
            },
        ],
    }

    result = validator.validate(
        single_failed_login,
        brute_force_match,
        "Repeated failed attempts were observed.",
        correlation_result=correlation_result,
    )

    assert result["decision"] == "Uncertain"
    assert result["correlation_supported"] is False


def test_unsupported_powershell_claim_is_detected(validator):
    result = validator.validate(
        alert={
            "rule_id": "502",
            "rule_level": 3,
            "rule_description": "Benign service startup",
            "full_log": "Synthetic benign service startup event",
        },
        rulebook_matches=[],
        qwen_analysis="The event contains PowerShell execution.",
    )

    assert result["decision"] == "Uncertain"
    assert result["evidence_grounded"] is False
    assert any(
        "powershell" in claim.lower()
        for claim in result["unsupported_claims"]
    )


def test_unsupported_network_scanning_claim_is_detected(validator):
    result = validator.validate(
        alert={
            "rule_id": "502",
            "rule_level": 3,
            "rule_description": "Benign service startup",
            "full_log": "Synthetic benign service startup event",
        },
        rulebook_matches=[],
        qwen_analysis="The event indicates network scanning.",
    )

    assert result["decision"] == "Uncertain"
    assert result["evidence_grounded"] is False
    assert any(
        "network scanning" in claim.lower()
        for claim in result["unsupported_claims"]
    )
def test_known_startup_is_false_positive_despite_irrelevant_model_claims(
    validator,
):
    result = validator.validate(
        alert={
            "rule_id": "502",
            "rule_level": 3,
            "rule_description": "Wazuh server started.",
            "full_log": "ossec: Manager started.",
        },
        rulebook_matches=[],
        qwen_analysis=(
            "The event contains PowerShell execution and repeated attempts."
        ),
    )

    assert result["decision"] == "False Positive"
    assert result["severity"] == "Low"
    assert result["evidence_grounded"] is False
    assert result["unsupported_claims"]


def test_startup_exception_does_not_apply_to_other_rule_ids(validator):
    result = validator.validate(
        alert={
            "rule_id": "5710",
            "rule_level": 5,
            "rule_description": "sshd: Attempt to login using a non-existent user",
            "full_log": "Failed password for invalid user test from 198.51.100.26",
        },
        rulebook_matches=[],
        qwen_analysis="The event contains PowerShell execution.",
    )

    assert result["decision"] == "Uncertain"

def test_question_heading_does_not_override_negated_body_claim():
    text = (
        "5. Whether multiple/repeated attempts are supported:\n"
        "The correlation evidence contains zero related alerts, "
        "meaning no repeated or multiple attempts are confirmed."
    )

    assert EvidenceDecisionValidator._phrase_is_affirmed(
        text, "repeated attempts"
    ) is False


def test_highest_valid_rulebook_severity_takes_precedence(validator):
    result = validator.validate(
        alert={
            "rule_id": "9999",
            "rule_level": 3,
            "rule_description": "Multiple rule matches",
            "full_log": "Test event",
        },
        rulebook_matches=[
            {"rule_id": "RULE_A", "severity": "Medium"},
            {"rule_id": "RULE_B", "severity": "Critical"},
            {"rule_id": "RULE_C", "severity": "High"},
        ],
        qwen_analysis="Insufficient evidence to classify this event.",
    )

    assert result["severity"] == "Critical"
    assert result["decision"] == "Uncertain"


def test_invalid_rulebook_severity_uses_wazuh_fallback(validator):
    result = validator.validate(
        alert={
            "rule_id": "9999",
            "rule_level": 8,
            "rule_description": "Unclassified event",
            "full_log": "Test event",
        },
        rulebook_matches=[
            {"rule_id": "RULE_A", "severity": "Severe"}
        ],
        qwen_analysis="Insufficient evidence to classify this event.",
    )

    assert result["severity"] == "High"
    assert result["decision"] == "Uncertain"


def test_non_brute_force_rule_does_not_become_true_positive(
    validator, single_failed_login
):
    result = validator.validate(
        alert=single_failed_login,
        rulebook_matches=[
            {"rule_id": "SUSPICIOUS_ACTIVITY", "severity": "High"}
        ],
        qwen_analysis="Repeated failed attempts were observed.",
        correlation_result={
            "correlated": True,
            "alert_count": 3,
            "related_alerts": [
                {
                    "alert_id": "1001",
                    "rule_id": "5710",
                    "rule_description": "Failed password for user",
                },
                {
                    "alert_id": "1002",
                    "rule_id": "5710",
                    "rule_description": "Failed password for user",
                },
            ],
        },
    )

    assert result["decision"] == "Uncertain"


def test_startup_exception_requires_started_in_description(validator):
    result = validator.validate(
        alert={
            "rule_id": "502",
            "rule_level": 3,
            "rule_description": "Service startup event",
            "full_log": "Synthetic service startup event",
        },
        rulebook_matches=[],
        qwen_analysis="No confirmed malicious activity.",
    )

    assert result["decision"] == "Uncertain"

@pytest.mark.parametrize(
    "qwen_analysis",
    [
        "The event indicates unusual LDAP activity.",
        "The system may be undergoing unusual LDAP queries.",
        "The alert indicates LDAP activity and potential unauthorized access.",
        "The event indicates network service scanning.",
    ],
)
def test_unsupported_ldap_and_service_scanning_claims_are_detected(
    validator, qwen_analysis
):
    alert = {
        "rule_id": "100001",
        "rule_level": 3,
        "rule_description": "Controlled synthetic benchmark event",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "destination_port": "443",
        "full_log": "Synthetic benchmark event; unique marker abc123",
    }

    result = validator.validate(
        alert=alert,
        rulebook_matches=[],
        qwen_analysis=qwen_analysis,
        correlation_result={
            "correlated": False,
            "alert_count": 1,
            "related_alerts": [],
        },
    )

    assert result["decision"] == "Uncertain"
    assert result["evidence_grounded"] is False
    assert result["unsupported_claims"]


def test_explicit_ldap_log_is_not_flagged_as_unsupported(
    validator,
):
    alert = {
        "rule_id": "100001",
        "rule_level": 3,
        "rule_description": "LDAP query observed",
        "full_log": "LDAP activity recorded by the application",
    }

    result = validator.validate(
        alert=alert,
        rulebook_matches=[],
        qwen_analysis="The log records LDAP activity.",
    )

    assert not any(
        "ldap" in claim.lower()
        for claim in result["unsupported_claims"]
    )


def test_port_443_alone_does_not_establish_ldap(
    validator,
):
    alert = {
        "rule_id": "100001",
        "rule_level": 3,
        "rule_description": "Controlled synthetic benchmark event",
        "destination_port": "443",
        "full_log": "Synthetic benchmark event",
    }

    result = validator.validate(
        alert=alert,
        rulebook_matches=[],
        qwen_analysis=(
            "Port 443 proves that unusual LDAP activity occurred."
        ),
    )

    assert result["evidence_grounded"] is False
    assert result["unsupported_claims"]
def test_untrusted_mitre_technique_is_rejected(validator):
    alert = {
        "rule_id": "100001",
        "rule_level": 3,
        "rule_description": "Controlled synthetic benchmark event",
        "full_log": "Synthetic benchmark event; unique marker abc123",
        "mitre": {},
    }

    result = validator.validate(
        alert=alert,
        rulebook_matches=[],
        qwen_analysis=(
            "Unusual LDAP activity maps to MITRE ATT&CK T103."
        ),
    )

    assert result["decision"] == "Uncertain"
    assert result["evidence_grounded"] is False
    assert any(
        "T103" in claim
        for claim in result["unsupported_claims"]
    )


def test_rulebook_mitre_technique_is_accepted(validator):
    alert = {
        "rule_id": "5710",
        "rule_level": 10,
        "rule_description": "Failed password",
        "full_log": "Failed password for test user",
        "mitre": {},
    }

    rulebook_matches = [
        {
            "rule_id": "BRUTE_FORCE",
            "severity": "High",
            "mitre": {
                "techniques": ["T1110"],
                "subtechniques": ["T1110.001"],
            },
        }
    ]

    result = validator.validate(
        alert=alert,
        rulebook_matches=rulebook_matches,
        qwen_analysis=(
            "The event may relate to MITRE ATT&CK T1110."
        ),
    )

    assert not any(
        "T1110" in claim
        for claim in result["unsupported_claims"]
    )
