from pathlib import Path

import yaml


class RulebookEngine:

    def __init__(self, rulebook_path=None):

        if rulebook_path is None:
            possible_paths = [
                Path(__file__).resolve().parents[3]
                / "configs"
                / "soc_rulebook.yaml",

                Path(__file__).resolve().parents[2]
                / "configs"
                / "soc_rulebook.yaml",
            ]

            for path in possible_paths:
                if path.exists():
                    rulebook_path = path
                    break

            if rulebook_path is None:
                raise FileNotFoundError(
                    "soc_rulebook.yaml could not be found."
                )

        self.rulebook_path = Path(rulebook_path)

        self.rules = []

        self._load_rulebook()

    def _load_rulebook(self):

        with open(
            self.rulebook_path,
            "r",
            encoding="utf-8"
        ) as file:

            data = yaml.safe_load(file)

        self.rules = data["rulebook"]["rules"]

    @staticmethod
    def _build_search_text(alert):
        """
        Convert important Wazuh alert fields
        into searchable text.
        """

        rule = alert.get("rule", {})
        data = alert.get("data", {})

        fields = [
            rule.get("id"),
            rule.get("description"),
            alert.get("full_log"),
            data.get("srcip"),
            data.get("srcuser"),
            data.get("dstip"),
            data.get("dstport"),
        ]

        return " ".join(
            str(value)
            for value in fields
            if value is not None
        ).lower()

    def evaluate(self, alert):

        search_text = self._build_search_text(alert)

        matches = []

        for rule in self.rules:

            indicators = rule.get(
                "indicators",
                {}
            )

            rule_ids = indicators.get(
                "rule_ids",
                []
            )

            keywords = indicators.get(
                "keywords",
                []
            )

            rule_id = str(
                alert.get(
                    "rule",
                    {}
                ).get("id", "")
            )

            rule_id_match = (
                rule_id in rule_ids
            )

            keyword_matches = [
                keyword
                for keyword in keywords
                if keyword.lower()
                in search_text
            ]

            if rule_id_match or keyword_matches:

                matches.append(
                    {
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "mitre": rule.get(
                            "mitre",
                            {}
                        ),
                        "matched_rule_id": (
                            rule_id
                            if rule_id_match
                            else None
                        ),
                        "matched_keywords": (
                            keyword_matches
                        ),
                        "investigation": rule.get(
                            "investigation",
                            {}
                        ),
                    }
                )

        return matches


rulebook_engine = RulebookEngine()
