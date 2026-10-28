import re


class EvidenceDecisionValidator:
    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
    VALID_DECISIONS = {"True Positive", "False Positive", "Uncertain"}

    SEVERITY_PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    REPEATED_TERMS = [
        "multiple failed attempts", "multiple attempts",
        "repeated failed attempts", "repeated attempts",
        "several failed attempts", "numerous failed attempts",
        "repeated authentication attempts",
    ]

    COMPROMISE_TERMS = [
        "successful login", "successful authentication",
        "account compromised", "account was compromised",
        "system compromised", "system was compromised",
        "attacker gained access", "attacker has gained access",
        "unauthorized access was obtained",
    ]

    UNSUPPORTED_ACTIVITY_TERMS = [
        "powershell", "command injection", "network scanning",
        "port scanning", "nmap activity", "ldap",
        "network service scanning", "service scanning",
    ]

    NEGATION_TERMS = [
        "not supported", "unsupported", "no evidence",
        "cannot confirm", "can't confirm", "not confirmed",
        "not observed", "not established", "does not establish",
        "does not indicate", "not enough evidence",
        "insufficient evidence", "not demonstrated", "not proven",
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
            EvidenceDecisionValidator._text(alert.get("rule_description")),
            EvidenceDecisionValidator._text(alert.get("full_log")),
        ])
        patterns = [
            r"(\d+)\s+(?:failed|unsuccessful)\s+"
            r"(?:login|logins|authentication|authentications|attempts)",
            r"(?:failed|unsuccessful)\s+"
            r"(?:login|logins|authentication|authentications|attempts)"
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
        related_alerts = correlation_result.get("related_alerts") or []
        if related_alerts:
            failed_login_alerts = []
            for alert in related_alerts:
                if not isinstance(alert, dict):
                    continue
                rule_id = str(alert.get("rule_id", "")).strip()
                description = " ".join([
                    EvidenceDecisionValidator._text(alert.get("rule_description")),
                    EvidenceDecisionValidator._text(alert.get("full_log")),
                ])
                is_failed_login = (
                    rule_id == "5710"
                    or ("failed password" in description and "password" in description)
                )
                if is_failed_login:
                    failed_login_alerts.append(alert)
            return len(failed_login_alerts) > 1
        try:
            return (
                bool(correlation_result.get("correlated"))
                and int(correlation_result.get("alert_count", 0)) > 1
            )
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _phrase_is_affirmed(text, phrase):
        """Check whether a phrase is asserted affirmatively."""
        text = EvidenceDecisionValidator._text(text)
        phrase = EvidenceDecisionValidator._text(phrase).strip()
        if not text or not phrase:
            return False

        negation_pattern = (
            r"\b(?:no|not|never|without|neither|nor|cannot|can't|isn't|aren't|"
            r"wasn't|weren't|doesn't|don't|didn't|hasn't|haven't|hadn't|"
            r"won't|wouldn't|unsupported|unconfirmed)\b"
        )

        for match in re.finditer(re.escape(phrase), text):
            start, end = match.span()
            left = max(
                text.rfind(".", 0, start), text.rfind("!", 0, start),
                text.rfind("?", 0, start), text.rfind(";", 0, start),
                text.rfind("\n", 0, start),
            ) + 1
            right_positions = [
                pos for marker in (".", "!", "?", ";", "\n")
                if (pos := text.find(marker, end)) != -1
            ]
            right = min(right_positions) if right_positions else len(text)
            sentence = text[left:right].strip()
            clean_sentence = re.sub(r"[*_`#]", "", sentence).strip()
            if clean_sentence.endswith((":", "?")):
                continue

            clauses = re.split(r"\b(?:but|however|although|whereas)\b", sentence)
            target_clause = next(
                (clause for clause in clauses if re.search(re.escape(phrase), clause)),
                "",
            ).strip()
            if not target_clause:
                continue

            phrase_match = re.search(re.escape(phrase), target_clause)
            prefix = target_clause[:phrase_match.start()]
            suffix = target_clause[phrase_match.end():]
            if re.search(negation_pattern + r"(?:\W+\w+){0,4}\W*$", prefix):
                continue
            if re.match(
                r"^\W*(?:(?:are|were|was|is|have been|has been)\W*)?"
                r"(?:not|never|unsupported|unconfirmed)\b",
                suffix,
            ):
                continue
            if any(term in target_clause for term in EvidenceDecisionValidator.NEGATION_TERMS):
                continue
            return True
        return False

    @staticmethod
    def _trusted_mitre_techniques(alert, rulebook_matches):
        """Collect technique IDs from trusted alert and rulebook metadata."""
        trusted = set()

        def collect(mapping):
            if not isinstance(mapping, dict):
                return
            for field in ("techniques", "subtechniques"):
                values = mapping.get(field, [])
                if isinstance(values, str):
                    values = [values]
                if not isinstance(values, (list, tuple, set)):
                    continue
                for value in values:
                    if isinstance(value, str):
                        technique = value.strip().upper()
                        if re.fullmatch(r"T\d{3,5}(?:\.\d{3})?", technique):
                            trusted.add(technique)

        collect(alert.get("mitre"))
        for match in rulebook_matches or []:
            if isinstance(match, dict):
                collect(match.get("mitre"))
        return trusted

    @staticmethod
    def _validate_qwen_claims(
        alert, qwen_analysis, correlation_result=None, rulebook_matches=None
    ):
        unsupported_claims = []
        text = EvidenceDecisionValidator._text(qwen_analysis)

        trusted_techniques = EvidenceDecisionValidator._trusted_mitre_techniques(
            alert, rulebook_matches
        )
        asserted_techniques = set(
            re.findall(r"\bT\d{3,5}(?:\.\d{3})?\b", text.upper())
        )
        for technique in sorted(asserted_techniques - trusted_techniques):
            if EvidenceDecisionValidator._phrase_is_affirmed(text, technique):
                unsupported_claims.append(
                    f"Unsupported MITRE technique: '{technique}'"
                )

        failed_attempt_count = EvidenceDecisionValidator._extract_failed_attempt_count(alert)
        correlation_supports_repeated = (
            EvidenceDecisionValidator._correlation_supports_repeated_attempts(
                correlation_result
            )
        )
        if failed_attempt_count is None and not correlation_supports_repeated:
            for term in EvidenceDecisionValidator.REPEATED_TERMS:
                if EvidenceDecisionValidator._phrase_is_affirmed(text, term):
                    unsupported_claims.append(f"Unsupported claim: '{term}'")

        alert_text = " ".join([
            EvidenceDecisionValidator._text(alert.get("rule_description")),
            EvidenceDecisionValidator._text(alert.get("full_log")),
        ])
        for term in EvidenceDecisionValidator.UNSUPPORTED_ACTIVITY_TERMS:
            if (
                EvidenceDecisionValidator._phrase_is_affirmed(text, term)
                and term not in alert_text
            ):
                unsupported_claims.append(f"Unsupported claim: '{term}'")

        for term in EvidenceDecisionValidator.COMPROMISE_TERMS:
            if (
                EvidenceDecisionValidator._phrase_is_affirmed(text, term)
                and term not in alert_text
            ):
                unsupported_claims.append(f"Unsupported claim: '{term}'")

        return list(dict.fromkeys(unsupported_claims))

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
                key=lambda value: EvidenceDecisionValidator.SEVERITY_PRIORITY[value],
            )
        try:
            rule_level = int(alert.get("rule_level"))
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
        """Narrow exception for a known informational Wazuh startup event."""
        rule_id = str(alert.get("rule_id", "")).strip()
        description = EvidenceDecisionValidator._text(alert.get("rule_description"))
        return rule_id == "502" and "started" in description and not rulebook_matches

    @staticmethod
    def _is_brute_force_match(rulebook_matches):
        return any(
            str(match.get("rule_id", "")).upper() == "BRUTE_FORCE"
            for match in (rulebook_matches or [])
        )

    @staticmethod
    def _determine_decision(
        alert, rulebook_matches, unsupported_claims, correlation_result=None
    ):
        # This exception must precede the unsupported-claims check.
        if EvidenceDecisionValidator._is_known_informational_startup(alert, rulebook_matches):
            return "False Positive"
        if unsupported_claims:
            return "Uncertain"
        if not rulebook_matches:
            return "Uncertain"
        evidence = EvidenceDecisionValidator._build_alert_evidence(alert)
        if not evidence:
            return "Uncertain"
        if EvidenceDecisionValidator._is_brute_force_match(rulebook_matches):
            count = EvidenceDecisionValidator._extract_failed_attempt_count(alert)
            repeated = (
                count is not None and count > 1
            ) or EvidenceDecisionValidator._correlation_supports_repeated_attempts(
                correlation_result
            )
            return "True Positive" if repeated else "Uncertain"
        return "Uncertain"

    def validate(self, alert, rulebook_matches, qwen_analysis, correlation_result=None):
        alert_evidence = self._build_alert_evidence(alert)
        unsupported_claims = self._validate_qwen_claims(
            alert,
            qwen_analysis,
            correlation_result,
            rulebook_matches,
        )
        severity = self._determine_severity(alert, rulebook_matches)
        decision = self._determine_decision(
            alert, rulebook_matches, unsupported_claims, correlation_result
        )
        correlation_supported = self._correlation_supports_repeated_attempts(
            correlation_result
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
