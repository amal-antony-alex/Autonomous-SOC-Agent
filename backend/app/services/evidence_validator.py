import re


class EvidenceDecisionValidator:
    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
    VALID_DECISIONS = {"True Positive", "False Positive", "Uncertain"}

    SEVERITY_PRIORITY = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    REPEATED_TERMS = [
        "multiple failed attempts",
        "multiple attempts",
        "repeated failed attempts",
        "repeated attempts",
        "several failed attempts",
        "numerous failed attempts",
        "repeated authentication attempts",
    ]

    COMPROMISE_TERMS = [
        "successful login",
        "successful authentication",
        "account compromised",
        "account was compromised",
        "system compromised",
        "system was compromised",
        "attacker gained access",
        "attacker has gained access",
        "unauthorized access was obtained",
    ]

    NEGATION_TERMS = [
        "not supported",
        "unsupported",
        "no evidence",
        "cannot confirm",
        "can't confirm",
        "not confirmed",
        "not observed",
        "not established",
        "does not establish",
        "does not indicate",
        "not enough evidence",
        "insufficient evidence",
        "not demonstrated",
        "not proven",
    ]

    @staticmethod
    def _text(value):
        if value is None:
            return ""
        return str(value).lower()

    @staticmethod
    def _build_alert_evidence(alert):
        evidence = []

        fields = [
            ("rule_id", "Wazuh rule ID"),
            ("rule_description", "Rule description"),
            ("rule_level", "Wazuh rule level"),
            ("source_ip", "Source IP"),
            ("source_user", "Source user"),
            ("destination_ip", "Destination IP"),
            ("destination_port", "Destination port"),
            ("full_log", "Log"),
        ]

        for field, label in fields:
            value = alert.get(field)
            if value is not None and str(value).strip():
                evidence.append(f"{label}: {value}")

        return evidence

    @staticmethod
    def _extract_failed_attempt_count(alert):
        text = " ".join([
            EvidenceDecisionValidator._text(
                alert.get("rule_description")
            ),
            EvidenceDecisionValidator._text(
                alert.get("full_log")
            ),
        ])

        patterns = [
            r"(\d+)\s+(?:failed|unsuccessful)\s+"
            r"(?:login|logins|authentication|"
            r"authentications|attempts)",

            r"(?:failed|unsuccessful)\s+"
            r"(?:login|logins|authentication|"
            r"authentications|attempts)"
            r"\s*[:=]?\s*(\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))

        return None

    @staticmethod
    def _correlation_supports_repeated_attempts(correlation_result):
        if not correlation_result:
            return False

        try:
            return int(correlation_result.get("alert_count", 0)) > 1
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _phrase_is_affirmed(text, phrase):
        """
        Check whether a phrase appears in a sentence without
        an obvious negation or uncertainty qualifier.
        This is a lightweight guard, not a full NLP model.
        """
        sentences = re.split(r"(?<=[.!?])\s+|[\r\n]+", text)

        for sentence in sentences:
            if phrase not in sentence:
                continue

            if any(
                negation in sentence
                for negation in EvidenceDecisionValidator.NEGATION_TERMS
            ):
                continue

            return True

        return False

    @staticmethod
    def _validate_qwen_claims(
        alert,
        qwen_analysis,
        correlation_result=None,
    ):
        unsupported_claims = []
        text = EvidenceDecisionValidator._text(qwen_analysis)

        failed_attempt_count = (
            EvidenceDecisionValidator._extract_failed_attempt_count(alert)
        )

        correlation_supports_repeated = (
            EvidenceDecisionValidator
            ._correlation_supports_repeated_attempts(
                correlation_result
            )
        )

        if (
            failed_attempt_count is None
            and not correlation_supports_repeated
        ):
            for term in EvidenceDecisionValidator.REPEATED_TERMS:
                if EvidenceDecisionValidator._phrase_is_affirmed(text, term):
                    unsupported_claims.append(
                        f"Unsupported claim: '{term}'"
                    )

        alert_text = " ".join([
            EvidenceDecisionValidator._text(
                alert.get("rule_description")
            ),
            EvidenceDecisionValidator._text(
                alert.get("full_log")
            ),
        ])

        for term in EvidenceDecisionValidator.COMPROMISE_TERMS:
            if (
                EvidenceDecisionValidator._phrase_is_affirmed(text, term)
                and term not in alert_text
            ):
                unsupported_claims.append(
                    f"Unsupported claim: '{term}'"
                )

        return unsupported_claims

    @staticmethod
    def _determine_severity(alert, rulebook_matches):
        severities = []

        for match in rulebook_matches or []:
            severity = match.get("severity")
            if severity in EvidenceDecisionValidator.VALID_SEVERITIES:
                severities.append(severity)

        if severities:
            return max(
                severities,
                key=lambda value:
                EvidenceDecisionValidator.SEVERITY_PRIORITY[value],
            )

        rule_level = alert.get("rule_level")

        try:
            rule_level = int(rule_level)
        except (TypeError, ValueError):
            return "Low"

        if rule_level >= 12:
            return "Critical"
        if rule_level >= 7:
            return "High"
        if rule_level >= 4:
            return "Medium"
        return "Low"

    @staticmethod
    def _is_known_informational_startup(alert, rulebook_matches):
        """
        Recognize the specific Wazuh manager-startup event observed
        in this project. Do not generalize this exception to all
        unmatched low-severity alerts.
        """
        rule_id = str(alert.get("rule_id", "")).strip()
        description = EvidenceDecisionValidator._text(
            alert.get("rule_description")
        )

        return (
            rule_id == "502"
            and "started" in description
            and not rulebook_matches
        )

    @staticmethod
    def _is_brute_force_match(rulebook_matches):
        return any(
            str(match.get("rule_id", "")).upper() == "BRUTE_FORCE"
            for match in (rulebook_matches or [])
        )

    @staticmethod
    def _determine_decision(
        alert,
        rulebook_matches,
        unsupported_claims,
        correlation_result=None,
    ):
        if unsupported_claims:
            return "Uncertain"

        if EvidenceDecisionValidator._is_known_informational_startup(
            alert, rulebook_matches
        ):
            return "False Positive"

        if not rulebook_matches:
            return "Uncertain"

        evidence = EvidenceDecisionValidator._build_alert_evidence(alert)
        if not evidence:
            return "Uncertain"

        if EvidenceDecisionValidator._is_brute_force_match(
            rulebook_matches
        ):
            count = EvidenceDecisionValidator._extract_failed_attempt_count(
                alert
            )
            repeated = (
                count is not None and count > 1
            ) or EvidenceDecisionValidator._correlation_supports_repeated_attempts(
                correlation_result
            )

            return "True Positive" if repeated else "Uncertain"

        # Keyword-only matches such as "powershell" are not enough
        # to confirm malicious activity.
        return "Uncertain"

    def validate(
        self,
        alert,
        rulebook_matches,
        qwen_analysis,
        correlation_result=None,
    ):
        alert_evidence = self._build_alert_evidence(alert)

        unsupported_claims = self._validate_qwen_claims(
            alert,
            qwen_analysis,
            correlation_result,
        )

        severity = self._determine_severity(
            alert,
            rulebook_matches,
        )

        decision = self._determine_decision(
            alert,
            rulebook_matches,
            unsupported_claims,
            correlation_result,
        )

        correlation_supported = (
            self._correlation_supports_repeated_attempts(
                correlation_result
            )
        )

        return {
            "decision": decision,
            "severity": severity,
            "evidence": alert_evidence,
            "unsupported_claims": unsupported_claims,
            "evidence_grounded": not unsupported_claims,
            "correlation_supported": correlation_supported,
        }


evidence_validator = EvidenceDecisionValidator()
