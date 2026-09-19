#!/var/ossec/framework/python/bin/python3

import json
import sys
import requests

BACKEND_URL = "http://socagent-backend:8000/api/v1/wazuh/alert"


def main():
    if len(sys.argv) < 2:
        print("Usage: autonomous-soc.py <alert_json_file>")
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)

        response = requests.post(
            BACKEND_URL,
            json=alert,
            timeout=10
        )

        print(
            f"Autonomous SOC backend response: "
            f"{response.status_code} {response.text}"
        )

        response.raise_for_status()

    except Exception as e:
        print(f"Autonomous SOC integration error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
