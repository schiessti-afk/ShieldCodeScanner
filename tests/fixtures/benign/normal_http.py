"""Ordinary HTTP API call with no secrets and no execution."""

import requests

response = requests.get("https://example.com/api/health")
print(response.status_code)
