"""Suspicious pattern: decode a payload and execute it."""

import base64
import os

payload = base64.b64decode("ZWNobyBoYWNrZWQ=")
os.system(payload)
