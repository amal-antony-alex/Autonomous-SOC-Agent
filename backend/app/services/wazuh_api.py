import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPI:
    def __init__(self):
        self.base_url = os.getenv(
            "WAZUH_API_URL",
            "https://172.18.0.2:55000"
        )
        self.username = os.getenv("WAZUH_API_USERNAME")
        self.password = os.getenv("WAZUH_API_PASSWORD")

        self.token = None

    def authenticate(self):
        response = requests.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.username, self.password),
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        self.token = response.json()["data"]["token"]
        return self.token

    def get_alerts(self):
        raise NotImplementedError(
            "Wazuh alerts are received through the Wazuh integration webhook."
        )


wazuh_api = WazuhAPI()
