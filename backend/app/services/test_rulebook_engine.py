from backend.app.services.rulebook_engine import (
    rulebook_engine
)


def main():

    test_alert = {
        "rule": {
            "id": "5710",
            "level": 5,
            "description": (
                "sshd: Attempt to login "
                "using a non-existent user"
            )
        },
        "agent": {
            "id": "000",
            "name": "wazuh.manager"
        },
        "data": {
            "srcip": "192.168.1.200",
            "srcuser": "admin"
        },
        "full_log": (
            "Failed password for invalid user "
            "admin from 192.168.1.200 "
            "port 22 ssh2"
        )
    }

    matches = rulebook_engine.evaluate(
        test_alert
    )

    print("===== RULEBOOK TEST =====")
    print(f"Matched rules: {len(matches)}")

    for match in matches:

        print(
            f"\nRule: {match['rule_id']}"
        )

        print(
            f"Name: {match['name']}"
        )

        print(
            f"Severity: {match['severity']}"
        )

        print(
            f"Matched Wazuh Rule: "
            f"{match['matched_rule_id']}"
        )

        print(
            f"Matched Keywords: "
            f"{match['matched_keywords']}"
        )

        print(
            f"MITRE: {match['mitre']}"
        )


if __name__ == "__main__":
    main()
