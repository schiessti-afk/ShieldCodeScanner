"""Ordinary environment-variable usage, including an unused secret read."""

import os

home = os.environ["HOME"]
path = os.environ.get("PATH", "")
api_key = os.environ.get("API_KEY")
print(home, path, "configured" if api_key else "missing")
