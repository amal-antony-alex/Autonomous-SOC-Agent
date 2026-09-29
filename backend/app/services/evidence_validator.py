import re


class EvidenceDecisionValidator:

    VALID_SEVERITIES = {
        "Critical",
        "High",
        "Medium",
        "Low",
    }

    VALID_DECISIONS = {
        "True Positive",
        "False Positive",
        "Uncertain",
    }

    @staticmethod
    def _text(value):
        if value is None:
            return ""
        return str(value).lower()

    @staticmethod
    def _build_alert_evidence(alert):
        evidence = []

        if alert.get("rule_id"):
            evidence.append(
                f"Wazuh rule ID: {alert['rule_id']}"
            )

        if alert.get("rule_description"):
            evidence.append(
                f"Rule description: "
                f"{alert['rule_description']}"
            )

        if alert.get("rule_level") is not None:
            evidence.append(
                f"Wazuh rule level: "
                f"{alert['rule_level']}"
            )

        if alert.get("source_ip"):
            evidence.append(
                f"Source IP: {alert['source_ip']}"
            )

        if alert.get("source_user"):
            evidence.append(
                f"Source user: {alert['source_user']}"
            )

        if alert.get("destination_ip"):
            evidence.append(
                f"Destination IP: "
                f"{alert['destination_ip']}"
            )

        if alert.get("destination_port"):
            evidence.append(
                f"Destination port: "
                f"{alert['destination_port']}"
            )

        if alert.get("full_log"):
            evidence.append(
                f"Log: {alert['full_log']}"
            )

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

            match = re.search(
                pattern,
                text
            )

            if match:
                return int(
                    match.group(1)
                )

        return None

    @staticmethod
    def _correlation_supports_repeated_attempts(
        correlation_result
    ):

        if not correlation_result:
            return False

        alert_count = correlation_result.get(
            "alert_count",
            0
        )

        return alert_count > 1

    @staticmethod
    def _validate_qwen_claims(
        alert,
        qwen_analysis,
        correlation_result=None
    ):

        unsupported_claims = []

        text = EvidenceDecisionValidator._text(
            qwen_analysis
        )

        failed_attempt_count = (
            EvidenceDecisionValidator
            ._extract_failed_attempt_count(
                alert
            )
        )

        correlation_supports_repeated = (
            EvidenceDecisionValidator
            ._correlation_supports_repeated_attempts(
                correlation_result
            )
        )

        repeated_terms = [
            "multiple failed attempts",
            "multiple attempts",
            "repeated failed attempts",
            "repeated attempts",
            "several failed attempts",
            "numerous failed attempts",
            "repeated authentication attempts",
        ]

        if (
            failed_attempt_count is None
            and not correlation_supports_repeated
        ):

            for term in repeated_terms:

                if term in text:

                    unsupported_claims.append(
                        f"Unsupported claim: '{term}'"
                    )

        compromise_terms = [
            "successful login",
            "successful authentication",
            "account compromised",
            "system compromised",
            "attacker gained access",
        ]

        alert_text = " ".join([
            EvidenceDecisionValidator._text(
                alert.get("rule_description")
            ),
            EvidenceDecisionValidator._text(
                alert.get("full_log")
            ),
        ])

        for term in compromise_terms:

            if (
                term in text
                and term not in alert_text
            ):

                unsupported_claims.append(
                    f"Unsupported claim: '{term}'"
                )

        return unsupported_claims

    @staticmethod
    def _determine_severity(
        alert,
        rulebook_matches
    ):

        if rulebook_matches:

            severities = []

            for match in rulebook_matches:

                severity = match.get(
                    "severity"
                )

                if (
                    severity
                    in EvidenceDecisionValidator
                    .VALID_SEVERITIES
                ):

                    severities.append(
                        severity
                    )

            priority = {
                "Critical": 4,
                "High": 3,
                "Medium": 2,
                "Low": 1,
            }

            if severities:

                return max(
                    severities,
                    key=lambda value:
                    priority[value]
                )

        rule_level = alert.get(
            "rule_level"
        )

        if isinstance(
            rule_level,
            int
        ):

            if rule_level >= 12:
                return "Critical"

            if rule_level >= 7:
                return "High"

            if rule_level >= 4:
                return "Medium"

            return "Low"

        return "Low"

    @staticmethod
    def _determine_decision(
        alert,
        rulebook_matches,
        unsupported_claims
    ):

        if unsupported_claims:
            return "Uncertain"

        if not rulebook_matches:
            return "Uncertain"

        evidence = (
            EvidenceDecisionValidator
            ._build_alert_evidence(
                alert
            )
        )

        if evidence:
            return "True Positive"

        return "Uncertain"

    def validate(
        self,
        alert,
        rulebook_matches,
        qwen_analysis,
        correlation_result=None
    ):

        alert_evidence = (
            self._build_alert_evidence(
                alert
            )
        )

        unsupported_claims = (
            self._validate_qwen_claims(
                alert,
                qwen_analysis,
                correlation_result
            )
        )

        severity = (
            self._determine_severity(
                alert,
                rulebook_matches
            )
        )

        decision = (
            self._determine_decision(
                alert,
                rulebook_matches,
                unsupported_claims
            )
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
            "evidence_grounded": (
                len(unsupported_claims) == 0
            ),
            "correlation_supported": (
                correlation_supported
            ),
        }


evidence_validator = EvidenceDecisionValidator()
