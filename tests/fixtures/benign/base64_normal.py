"""Ordinary Base64 encoding for a data format, without execution."""

import base64
import json

payload = {"user": "alice", "role": "reader"}
encoded = base64.b64encode(json.dumps(payload).encode("utf-8"))
print(encoded.decode("ascii"))
